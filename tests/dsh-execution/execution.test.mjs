import test from 'node:test';
import assert from 'node:assert/strict';
import { sdkModule } from './paths.mjs';
const { ScheduleRuntime } = await sdkModule('lib/types/runtime.js');
const { decodeScheduleRecord } = await sdkModule('lib/types/domain.js');
const { resolveScheduleUpdate } = await sdkModule('lib/types/update.js');
const { appendDelivery, deliveryHistoryPage } = await sdkModule('lib/types/delivery-history.js');
const { scheduleTaskSchema } = await sdkModule('lib/types/storage.js');
const { ScheduleService } = await sdkModule('lib/index.js');

const retention = { days: 30, records: 2 };
const origin = 'origin-session';
const execution = { kind: 'external', executor: 'home-network' };
const record = (extra={}) => ({ id: 'task-1', kind: 'every', title:'Audit', prompt:'Inspect devices', everySeconds:60, scheduledAt:'2026-11-01T00:00:00.000Z', execution, ...extra });
const receipt = (id, extra={}) => ({ kind:'execution', executionId:id, scheduledAt:'2026-11-01T00:00:00.000Z', deliveredAt:'2026-11-01T00:00:01.000Z', status:'started', ...extra });
function fixture(rec = record(), options={}) {
  const store = new Map([[rec.id, { sessionId:origin, record:rec, status:'active', deliveryHistory:{ records:[], earlierRecordsUnavailable:false }, ...options.task }]]);
  const writes=[]; const warnings=[]; const seen=[]; const effects=[];
  const ctx={ logger:{warn:x=>warnings.push(x)}, agents:{withoutInitiator:fn=>fn(), get:()=>undefined}, sessionController:{resolveAgent:async()=>{seen.push('resolve'); return {agent:{session:{id:origin}, followup:m=>{effects.push(m)}}}}}, sessions:{flush:async()=>{seen.push('flush'); return true}} };
  const table={entries:()=>store.entries(),get:id=>store.get(id),put:async(id,value)=>{const parsed=scheduleTaskSchema.parse(value);store.set(id,parsed);writes.push(structuredClone(parsed))},delete:async id=>store.delete(id)};
  const domain={table:()=>table};
  const executors=new Map();
  const runtime=new ScheduleRuntime(ctx,()=>[...store.values()],fn=>fn(),task=>table.put(task.record.id,task),retention,name=>executors.get(name));
  const service=Object.assign(Object.create(ScheduleService.prototype),{ctx,retention,executors,chain:Promise.resolve(),stopping:false,ready:Promise.resolve(domain),initialized:Promise.resolve(),runtime});
  ctx.emit=()=>seen.push('changed');
  return {store,writes,warnings,seen,effects,executors,runtime,service};
}

// Catches origin-session delivery leaking through external dispatch and lost cadence/coalescing.
test('external recurrence calls executor with durable pending id and never resolves/enqueues/flushes origin',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:03:10.000Z'));
  const f=fixture(); let observed;
  f.executors.set('home-network',async args=>{observed=args; assert.equal(f.store.get('task-1').lastDelivery.status,'pending'); assert.equal(f.store.get('task-1').pendingExecution.executionId,args.executionId); return {status:'started',summary:'Worker admitted',executionSessionId:'fresh-1'} });
  await f.runtime.drive(); await f.runtime.dispose();
  assert.equal(observed.occurrenceAt,'2026-11-01T00:03:00.000Z');
  assert.match(observed.executionId,/^[a-f0-9]{32}$/);
  assert.equal(observed.task.sessionId,origin); assert.equal(observed.task.record.prompt,'Inspect devices');
  assert.ok(Object.isFrozen(observed.task.record)); assert.ok(observed.signal instanceof AbortSignal);
  assert.deepEqual(f.seen,[]); assert.deepEqual(f.effects,[]);
  const saved=f.store.get('task-1');
  assert.equal(saved.record.scheduledAt,'2026-11-01T00:04:00.000Z');
  assert.equal(saved.lastDelivery.kind,'execution'); assert.equal(saved.lastDelivery.status,'started');
  assert.equal(saved.lastDelivery.executionSessionId,'fresh-1'); assert.equal(saved.pendingExecution,undefined);
  assert.ok(!('messageId' in saved.lastDelivery)); assert.ok(!('prompt' in saved.deliveryHistory.records[0]));
});

// Catches fallback, missing-executor hot loops, and dropped/reidentified dispatch across restart.
test('missing executor fails closed with one durable pending receipt and replays same id after register',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:03:10.000Z'));
  const f=fixture(record({kind:'at'})); delete f.store.get('task-1').record.everySeconds;
  await f.runtime.drive(); await f.runtime.drive();
  assert.deepEqual(f.seen,[]); assert.deepEqual(f.effects,[]);
  const saved=structuredClone(f.store.get('task-1'));
  assert.equal(saved.deliveryHistory.records.length,1); assert.equal(saved.lastDelivery.status,'pending');
  assert.equal(saved.status,'inactive'); assert.equal(f.runtime.timer,undefined);
  const restarted=fixture(saved.record,{task:saved}); let received;
  const dispose=restarted.service.registerExecutor('home-network',async ({executionId})=>{received=executionId;return {status:'skipped',summary:'No AI: unchanged devices'}});
  await restarted.runtime.running; await restarted.runtime.dispose(); dispose(); await f.runtime.dispose();
  assert.equal(received,saved.lastDelivery.executionId); assert.equal(restarted.store.get('task-1').lastDelivery.status,'skipped');
  assert.equal(restarted.store.get('task-1').deliveryHistory.records.length,1);
});

// Catches unsafe completion rewriting cadence, missing non-latest reconciliation, and wrong-session access.
test('configure preserves identity/history; complete reconciles retained receipt and emits changed only after persistence',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:00:30.000Z'));
  const normal=record({scheduledAt:'2026-11-02T00:00:00.000Z'}); delete normal.execution;
  const first=receipt('first'); const latest=receipt('last');
  const f=fixture(normal,{task:{lastDelivery:latest,deliveryHistory:{records:[first,latest],earlierRecordsUnavailable:false}}});
  const before=structuredClone(f.store.get('task-1'));
  const configured=await f.service.configureExecution({sessionId:origin,id:'task-1',execution});
  assert.deepEqual(configured,{...before.record,execution});
  assert.deepEqual(f.store.get('task-1').deliveryHistory,before.deliveryHistory);
  const result=await f.service.completeExecution({sessionId:origin,id:'task-1',executionId:'first',status:'completed',summary:'Audit done',executionSessionId:'fresh-9'});
  assert.equal(result.updated,true); assert.equal(f.store.get('task-1').deliveryHistory.records[0].status,'completed');
  assert.deepEqual(f.store.get('task-1').lastDelivery,latest); assert.equal(f.store.get('task-1').record.scheduledAt,before.record.scheduledAt);
  const mismatch=await f.service.completeExecution({sessionId:'wrong',id:'task-1',executionId:'last',status:'completed'});
  assert.equal(mismatch.code,'schedule_not_found');
  assert.ok(f.seen.includes('changed'));
  await f.runtime.dispose();
});

// Catches storage/optimistic-update decoder losing external metadata on timing replacement.
test('all native timing edits and durable round trips retain external execution metadata',()=>{
  const current=record({scheduledAt:'2026-11-02T00:00:00.000Z'});
  assert.deepEqual(decodeScheduleRecord(current),current);
  for(const change of [{kind:'at',at:'2026-11-03T00:00:00.000Z'},{kind:'every',every_seconds:120},{kind:'daily',daily:{time:'08:00:00',time_zone:'UTC'}},{kind:'weekly',weekly:{time:'08:00:00',time_zone:'UTC',weekdays:[1,4]}},{kind:'cron',cron:{expression:'0 8 * * *',time_zone:'UTC'}}]) {
    const result=resolveScheduleUpdate(current,current,change,Date.parse('2026-11-01T00:00:00.000Z'),{title:'New title',prompt:'New prompt'});
    assert.equal(result.record?.id,'task-1'); assert.deepEqual(result.record?.execution,execution); assert.equal(result.record?.prompt,'New prompt');
    assert.deepEqual(scheduleTaskSchema.parse({sessionId:origin,record:result.record,status:'active'}).record,result.record);
  }
  assert.throws(()=>decodeScheduleRecord({...current,execution:{kind:'external',executor:''}}));
  assert.throws(()=>decodeScheduleRecord({...current,execution:{kind:'external',executor:'home-network',surprise:true}}));
});

// Catches fake-message receipts, history caps bypassed by external rows, and broken mixed pagination.
test('mixed ordinary/external history stays bounded, uses delivery cursor and reads unchanged legacy task',()=>{
  const normal={scheduledAt:'2026-10-31T00:00:00.000Z',deliveredAt:'2026-10-31T00:00:01.000Z',messageId:'legacy-message'};
  const task={sessionId:origin,record:record(),status:'active',lastDelivery:normal};
  assert.equal(scheduleTaskSchema.parse(task).lastDelivery.messageId,'legacy-message');
  let saved={...task,...appendDelivery(task,receipt('first'),retention)};
  saved={...saved,...appendDelivery(saved,receipt('second'),retention)};
  assert.equal(saved.deliveryHistory.records.length,2); assert.equal(saved.deliveryHistory.earlierRecordsPruned,true);
  assert.ok(saved.deliveryHistory.records.every(r=>!('messageId' in r)&&!('prompt' in r)));
  const page=deliveryHistoryPage(saved,{sessionId:origin,id:'task-1',limit:1},retention);
  assert.equal(page.nextBeforeDeliveryId,'second');
  assert.equal(deliveryHistoryPage(saved,{sessionId:origin,id:'task-1',limit:1,beforeDeliveryId:page.nextBeforeDeliveryId},retention).records[0].executionId,'first');
  assert.equal(deliveryHistoryPage(task,{sessionId:origin,id:'task-1',limit:1,beforeMessageId:'legacy-message'},retention).records.length,0);
  assert.ok(scheduleTaskSchema.safeParse(saved).success);
});

// Catches recurrence batching accidentally swallowing ordinary tasks when external work shares origin.
test('ordinary reminders still coalesce into one durable origin message beside a waiting external task',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:03:10.000Z'));
  const f=fixture(); const r=record({id:'ordinary-1'}); delete r.execution;
  f.store.set(r.id,{sessionId:origin,record:r,status:'active'});
  f.store.set('ordinary-2',{sessionId:origin,record:{...r,id:'ordinary-2'},status:'active'});
  await f.runtime.drive(); await f.runtime.dispose();
  assert.equal(f.effects.length,1); assert.deepEqual(f.seen,['resolve','flush']);
  assert.equal(f.store.get('ordinary-1').lastDelivery.messageId,f.store.get('ordinary-2').lastDelivery.messageId);
  assert.equal(f.store.get('task-1').lastDelivery.status,'pending');
});

// Catches protocol decoders rejecting external receipts or stripping metadata/cursors before UI sees them.
test('host and remote generated protocol codecs retain external metadata, mixed receipts and cursors',async()=>{
  const {TYPERT}=await sdkModule('lib/typert.host.js');
  const {TYPERT_REMOTE}=await sdkModule('lib/typert.remote-client.js');
  for(const methods of [Object.fromEntries(TYPERT.invocations.map(x=>[`schedule/${x.method}`,x])),TYPERT_REMOTE.methods]) {
    const entry={...record(),sessionId:origin,status:'active',lastDelivery:receipt('run-1',{status:'pending'})};
    const catalog=methods['schedule/catalog'].result.spec.create().parse([entry]);
    assert.deepEqual(catalog,[entry]);
    const result={id:'task-1',records:[receipt('run-1')],earlierRecordsUnavailable:false,earlierRecordsPruned:false,retention,nextBefore:'run-1',nextBeforeDeliveryId:'run-1'};
    assert.deepEqual(methods['schedule/history'].result.spec.create().parse(result),result);
    const input=methods['schedule/history'].parameters[0];
    const request={sessionId:origin,id:'task-1',limit:1,beforeDeliveryId:'run-1'};
    assert.deepEqual(input.codec.create().parse(request),request);
    if(input.strictCodec) assert.deepEqual(input.strictCodec.create().parse(request),request);
    const update=methods['schedule/update'].parameters[0];
    const edited={sessionId:origin,id:'task-1',expected:record(),prompt:'Edited'};
    assert.deepEqual(update.codec.create().parse(edited),edited);
    assert.deepEqual(methods['schedule/update'].result.spec.create().parse({id:'task-1',updated:true,record:record()}),{id:'task-1',updated:true,record:record()});
    assert.equal(methods['schedule/create'],undefined);
    assert.equal(methods['schedule/configureExecution'],undefined);
    assert.equal(methods['schedule/completeExecution'],undefined);
  }
});

// Catches retained pending work losing its original callback identity after a settle-write crash.
test('restart after accepted callback and failed acknowledgement replays same pending execution identity',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:03:10.000Z'));
  const f=fixture(); const ids=[];
  f.executors.set('home-network',async({executionId})=>{ids.push(executionId);return {status:'started',executionSessionId:'fresh-stable'}});
  const commit=f.runtime.commit; let writes=0;
  f.runtime.commit=async task=>{if(++writes===2)throw Error('disk unavailable');return commit(task)};
  await f.runtime.drive(); await f.runtime.dispose();
  const durable=structuredClone(f.store.get('task-1'));
  assert.equal(durable.lastDelivery.status,'pending');
  const restart=fixture(durable.record,{task:durable});
  restart.executors.set('home-network',async({executionId})=>{ids.push(executionId);return {status:'started',executionSessionId:'fresh-stable'}});
  await restart.runtime.drive(); await restart.runtime.dispose();
  assert.equal(ids.length,2); assert.equal(ids[0],ids[1]);
  assert.equal(restart.store.get('task-1').deliveryHistory.records.length,1);
  assert.equal(restart.store.get('task-1').lastDelivery.executionSessionId,'fresh-stable');
});

// Catches callbacks leaking native mutation lock indefinitely or invalid replies being called successful.
test('executor exception and malformed result persist failed outcomes without source fallback',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:03:10.000Z'));
  for(const executor of [async()=>{throw Error('broker offline')},async()=>({status:'invented',messageId:'fake'})]) {
    const f=fixture(); f.executors.set('home-network',executor);
    await f.runtime.drive(); await f.runtime.dispose();
    assert.equal(f.store.get('task-1').lastDelivery.status,'failed');
    assert.equal(f.store.get('task-1').pendingExecution,undefined); assert.deepEqual(f.seen,[]);
  }
});

// Catches new rule branches bypassing isolated dispatch or losing native calendar cadence.
test('external after/at/every/daily/weekly/cron retain native one-shot and coalesced cadence',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:03:10.000Z'));
  const base={id:'task-1',title:'Audit',prompt:'Inspect devices',scheduledAt:'2026-11-01T00:00:00.000Z',execution};
  const cases=[
    [{...base,kind:'after',afterSeconds:1},'2026-11-01T00:00:00.000Z',undefined],
    [{...base,kind:'at'},'2026-11-01T00:00:00.000Z',undefined],
    [{...base,kind:'every',everySeconds:60},'2026-11-01T00:03:00.000Z','2026-11-01T00:04:00.000Z'],
    [{...base,kind:'daily',time:'00:00:00.000',timeZone:'UTC'},'2026-11-01T00:00:00.000Z','2026-11-02T00:00:00.000Z'],
    [{...base,kind:'weekly',time:'00:00:00.000',timeZone:'UTC',weekdays:[7]},'2026-11-01T00:00:00.000Z','2026-11-08T00:00:00.000Z'],
    [{...base,kind:'cron',expression:'0 0 * * *',timeZone:'UTC'},'2026-11-01T00:00:00.000Z','2026-11-02T00:00:00.000Z'],
  ];
  for(const [rec,occurrence,next] of cases) {
    const f=fixture(rec); f.executors.set('home-network',async({occurrenceAt})=>{assert.equal(occurrenceAt,occurrence);return {status:'skipped',summary:'No AI needed'}});
    await f.runtime.drive(); await f.runtime.dispose();
    assert.equal(f.store.get('task-1').record.scheduledAt,next??occurrence);
    assert.equal(f.store.get('task-1').status,next===undefined?'inactive':'active'); assert.deepEqual(f.seen,[]);
  }
});

// Catches protocol receipt persistence inventing unbounded summaries or accepting forged ordinary identities.
test('strict storage rejects external fake message identities, duplicate ids, and inconsistent pending markers',()=>{
  const r=receipt('run-1'); const task={sessionId:origin,record:record(),status:'active',lastDelivery:r,deliveryHistory:{records:[r],earlierRecordsUnavailable:false}};
  assert.ok(scheduleTaskSchema.safeParse(task).success);
  assert.equal(scheduleTaskSchema.safeParse({...task,lastDelivery:{...r,messageId:'fake'}}).success,false);
  assert.equal(scheduleTaskSchema.safeParse({...task,lastDelivery:{...r,summary:'x'.repeat(4001)}}).success,false);
  assert.equal(scheduleTaskSchema.safeParse({...task,deliveryHistory:{...task.deliveryHistory,records:[r,r]}}).success,false);
  assert.equal(scheduleTaskSchema.safeParse({...task,pendingExecution:{executionId:'unknown',occurrenceAt:r.scheduledAt,record:task.record}}).success,false);
});

// Catches an unbounded callback holding the native mutation chain, and missing abort propagation.
test('hanging callback is aborted after 15 seconds and late success cannot turn timeout into completion',async t=>{
  t.mock.timers.enable({apis:['setTimeout']});
  const {invokeExecutor}=await sdkModule('lib/types/execution.js');
  let signal,finish;
  const pending=invokeExecutor(async args=>{signal=args.signal;return new Promise(resolve=>{finish=resolve})},{task:{record:record(),sessionId:origin},executionId:'run-1',occurrenceAt:'2026-11-01T00:00:00.000Z'});
  await Promise.resolve(); await Promise.resolve();
  const rejected=assert.rejects(pending,/timed out/);
  assert.equal(signal.aborted,false); t.mock.timers.tick(14999); assert.equal(signal.aborted,false);
  t.mock.timers.tick(1); await rejected; assert.equal(signal.aborted,true);
  finish({status:'completed',summary:'late'}); await Promise.resolve();
});

// Catches invoking a worker before the replay identity and pending evidence reach durable storage.
test('failed first pending write never calls executor and keeps native obligation available',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:03:10.000Z'));
  const f=fixture(); let calls=0;
  f.executors.set('home-network',async()=>{calls++;return {status:'started'}});
  f.runtime.commit=async()=>{throw Error('disk full')};
  await f.runtime.drive(); await f.runtime.dispose();
  assert.equal(calls,0); assert.equal(f.store.get('task-1').lastDelivery,undefined);
  assert.equal(f.store.get('task-1').record.scheduledAt,'2026-11-01T00:00:00.000Z');
});

// Catches duplicate response ids fabricating a second execution row for one occurrence.
test('executor may reconcile the existing execution id for duplicate occurrence without duplicate history',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:00:10.000Z'));
  const prior=receipt('existing');
  const f=fixture(record(),{task:{lastDelivery:prior,deliveryHistory:{records:[prior],earlierRecordsUnavailable:false}}});
  f.executors.set('home-network',async()=>({executionId:'existing',status:'started',summary:'Existing worker'}));
  await f.runtime.drive(); await f.runtime.dispose();
  assert.equal(f.store.get('task-1').deliveryHistory.records.length,1);
  assert.equal(f.store.get('task-1').lastDelivery.executionId,'existing');
});

// Catches pruning/lookup failures recreating evidence or overwriting a different Session's task.
test('completion ignores pruned receipts and updates latest receipt without rearming one-shots',async t=>{
  t.mock.method(Date,'now',()=>Date.parse('2026-11-01T00:00:10.000Z'));
  const r=receipt('latest');
  const f=fixture(record({scheduledAt:'2026-11-02T00:00:00.000Z'}),{task:{status:'inactive',lastDelivery:r,deliveryHistory:{records:[r],earlierRecordsUnavailable:true}}});
  const unknown=await f.service.completeExecution({sessionId:origin,id:'task-1',executionId:'pruned',status:'completed'});
  assert.equal(unknown.code,'execution_not_found'); assert.equal(f.writes.length,0);
  await f.service.completeExecution({sessionId:origin,id:'task-1',executionId:'latest',status:'completed',summary:'Successful exit',executionSessionId:'fresh-completed'});
  assert.equal(f.store.get('task-1').lastDelivery.status,'completed'); assert.equal(f.store.get('task-1').status,'inactive');
  const count=f.writes.length;
  await f.service.completeExecution({sessionId:origin,id:'task-1',executionId:'latest',status:'completed',summary:'Successful exit',executionSessionId:'fresh-completed'});
  assert.equal(f.writes.length,count); await f.runtime.dispose();
});

// Catches divergence between the package's bundled storage decoder and shipped per-module decoder.
test('bundled and per-module durable schemas agree on legacy, pending and settled external rows',async()=>{
  const {scheduleDomain}=await sdkModule('lib/index.js');
  const bundled=scheduleDomain.tables.tasks.valueSchema;
  const pending=receipt('waiting',{status:'pending'});
  const fixtures=[
    {sessionId:origin,record:record(),status:'active',lastDelivery:pending,deliveryHistory:{records:[pending],earlierRecordsUnavailable:false},pendingExecution:{executionId:'waiting',occurrenceAt:pending.scheduledAt,record:record()}},
    {sessionId:origin,record:record(),status:'inactive',lastDelivery:receipt('done',{status:'completed'}),deliveryHistory:{records:[receipt('done',{status:'completed'})],earlierRecordsUnavailable:false}},
    {sessionId:origin,record:{id:'legacy',kind:'after',title:'Legacy',prompt:'Legacy reminder',afterSeconds:60,scheduledAt:'2026-11-01T00:00:00.000Z'}},
  ];
  for(const task of fixtures)assert.deepEqual(bundled.parse(task),scheduleTaskSchema.parse(task));
  const invalid={...fixtures[0],pendingExecution:{...fixtures[0].pendingExecution,executionId:'missing'}};
  assert.equal(bundled.safeParse(invalid).success,false); assert.equal(scheduleTaskSchema.safeParse(invalid).success,false);
});

// Catches external receipts bypassing native age retention while completion must not reconstruct missing rows.
test('external append prunes by native day window as well as record cap',()=>{
  const old=receipt('old',{scheduledAt:'2026-09-01T00:00:00.000Z',deliveredAt:'2026-09-01T00:00:00.000Z'});
  const task={sessionId:origin,record:record(),status:'active',lastDelivery:old,deliveryHistory:{records:[old],earlierRecordsUnavailable:false}};
  const saved=appendDelivery(task,receipt('new'),{days:30,records:200});
  assert.deepEqual(saved.deliveryHistory.records.map(x=>x.executionId),['new']);
  assert.equal(saved.deliveryHistory.earlierRecordsPruned,true);
});
