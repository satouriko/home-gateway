import test from 'node:test';
import assert from 'node:assert/strict';
import { sdkModule } from './paths.mjs';
const { ScheduleRuntime }=await sdkModule('lib/types/runtime.js');
const { ScheduleService }=await sdkModule('lib/index.js');
const { scheduleTaskSchema }=await sdkModule('lib/types/storage.js');
const origin='origin-session',id='task-retry',executionId='skipped-execution';
const occurrenceAt='2026-11-01T00:00:00.000Z',retryAt='2026-11-01T00:30:00.000Z';
const expected={id,kind:'every',title:'User audit',prompt:'User instructions',everySeconds:14400,
 scheduledAt:'2026-11-01T04:00:00.000Z',execution:{kind:'external',executor:'home-network'}};
const request={sessionId:origin,id,executionId,expected};
function fixture(extra={}){
 const record=structuredClone(expected);
 const old={kind:'execution',executionId,scheduledAt:occurrenceAt,deliveredAt:'2026-11-01T00:00:00.123Z',status:'skipped',summary:'No due audit'};
 const task={sessionId:origin,record,status:'active',lastDelivery:old,deliveryHistory:{records:[old],earlierRecordsUnavailable:false},...extra};
 const store=new Map([[id,task]]),writes=[],warnings=[];
 const table={get:key=>store.get(key),entries:()=>store.entries(),put:async(key,value)=>{
  const parsed=scheduleTaskSchema.parse(structuredClone(value));store.set(key,parsed);writes.push(parsed);
 }};
 const ctx={logger:{warn:x=>warnings.push(x)},emit(){},agents:{withoutInitiator:fn=>fn()},
  sessionController:{resolveAgent:async()=>{throw Error('Retry reached source model')}},sessions:{flush:async()=>{throw Error('Retry touched source inbox')}}};
 const executors=new Map();let service;
 const runtime=new ScheduleRuntime(ctx,()=>[...store.values()],fn=>service.serialize(fn),task=>table.put(task.record.id,task),{days:30,records:200},name=>executors.get(name));
 service=Object.assign(Object.create(ScheduleService.prototype),{ctx,executors,chain:Promise.resolve(),stopping:false,
  ready:Promise.resolve({table:()=>table}),initialized:Promise.resolve(),runtime});
 return{store,writes,warnings,runtime,service,executors,old,record};
}

test('native retry keeps task cadence and the skipped identity while recording one real retry',async t=>{
 t.mock.method(Date,'now',()=>Date.parse(retryAt));
 const f=fixture();t.after(()=>f.runtime.dispose());let calls=0;
 f.executors.set('home-network',async args=>{calls++;assert.equal(args.executionId,executionId);assert.equal(args.occurrenceAt,occurrenceAt);
  assert.equal(args.task.record.prompt,'User instructions');assert.equal(f.store.get(id).lastDelivery.status,'pending');
  return{status:'started',executionSessionId:'new-headless-session',summary:'Worker started'};
 });
 const results=await Promise.all([f.service.retryExecution(request),f.service.retryExecution(request)]);
 await f.runtime.running;await f.service.chain;
 assert.equal(results.filter(r=>r.updated).length,1);assert.equal(calls,1);
 const saved=f.store.get(id);assert.deepEqual(saved.record,f.record);assert.equal(saved.deliveryHistory.records.length,1);
 assert.equal(saved.lastDelivery.executionId,executionId);assert.equal(saved.lastDelivery.status,'started');
 assert.deepEqual(saved.lastDelivery.retry,{at:retryAt,previousStatus:'skipped',previousDeliveredAt:f.old.deliveredAt,previousSummary:'No due audit'});
 assert.equal(saved.lastDelivery.executionSessionId,'new-headless-session');
 await f.service.completeExecution({...request,status:'completed',executionSessionId:'new-headless-session',summary:'Verified audit'});
 assert.equal(f.store.get(id).lastDelivery.status,'completed');assert.deepEqual(f.store.get(id).lastDelivery.retry,saved.lastDelivery.retry);
 assert.equal((await f.service.retryExecution(request)).updated,false);assert.deepEqual(f.warnings,[]);
});

test('a user edit queued before native retry preserves the skipped receipt and retry opportunity',async t=>{
 t.mock.method(Date,'now',()=>Date.parse(retryAt));
 for(const edit of [{prompt:'Changed by user'},{title:'New title'},{change:{kind:'every',every_seconds:21600}}]){
  const f=fixture();let calls=0;
  f.executors.set('home-network',async()=>{calls++;return{status:'started'}});
  const updated=f.service.update({sessionId:origin,id,expected,...edit});
  const retry=f.service.retryExecution(request);
  assert.equal((await updated).updated,true);
  assert.deepEqual(await retry,{id,updated:false,code:'schedule_conflict'});
  await f.runtime.running;await f.service.chain;
  assert.equal(calls,0);assert.equal(f.store.get(id).lastDelivery.status,'skipped');
  assert.equal(f.store.get(id).lastDelivery.retry,undefined);assert.equal(f.writes.length,1);
  await f.runtime.dispose();
 }
});

test('native retry requires the complete observed task definition before consuming a retry',async t=>{
 t.mock.method(Date,'now',()=>Date.parse(retryAt));
 for(const invalid of [undefined,{id},{...expected,unexpected:true}]){
  const f=fixture();const result=await f.service.retryExecution({...request,expected:invalid});
  assert.equal(result.updated,false);assert.equal(f.writes.length,0);await f.runtime.dispose();
 }
});

test('native retry fails closed for future expired running foreign and already retried work',async t=>{
 t.mock.method(Date,'now',()=>Date.parse(retryAt));
 const cases=[
  f=>({...request,sessionId:'foreign'}),f=>({...request,executionId:'old'}),
  f=>{f.store.get(id).status='inactive';return request},
  f=>{delete f.store.get(id).record.execution;return request},
  f=>{f.store.get(id).record.scheduledAt=retryAt;return request},
  f=>{f.store.get(id).lastDelivery.scheduledAt='2026-11-01T01:00:00.000Z';return request},
  f=>{f.store.get(id).lastDelivery.status='started';return request},
  f=>{f.store.get(id).lastDelivery.retry={at:retryAt,previousStatus:'skipped',previousDeliveredAt:f.old.deliveredAt};return request},
  f=>{f.store.get(id).pendingExecution={executionId,occurrenceAt,record:f.record};return request},
  f=>{f.store.get(id).deliveryHistory.records.unshift({...f.old,executionId:'still-running',status:'started'});return request},
 ];
 for(const change of cases){const f=fixture();const result=await f.service.retryExecution(change(f));
  assert.equal(result.updated,false);assert.equal(f.writes.length,0);await f.runtime.dispose();}
});

test('a persisted native retry replays after restart with the same identity and no additional retry',async t=>{
 t.mock.method(Date,'now',()=>Date.parse(retryAt));const first=fixture();
 await first.service.retryExecution(request);await first.runtime.running;await first.runtime.dispose();
 const pending=structuredClone(first.store.get(id));assert.equal(pending.lastDelivery.status,'pending');
 const cold=fixture(pending);t.after(()=>cold.runtime.dispose());let calls=0;
 cold.service.registerExecutor('home-network',async args=>{calls++;assert.equal(args.executionId,executionId);return{status:'skipped',summary:'Budget changed'}});
 await cold.runtime.running;await cold.service.chain;
 assert.equal(calls,1);assert.equal(cold.store.get(id).lastDelivery.retry.at,retryAt);
 assert.equal((await cold.service.retryExecution(request)).updated,false);assert.equal(cold.store.get(id).deliveryHistory.records.length,1);
});

test('native catalog and history expose retry evidence through both protocol codecs without a remote retry method',async()=>{
 const {TYPERT}=await sdkModule('lib/typert.host.js'),{TYPERT_REMOTE}=await sdkModule('lib/typert.remote-client.js');
 const f=fixture(),receipt={...f.old,retry:{at:retryAt,previousStatus:'skipped',previousDeliveredAt:f.old.deliveredAt,previousSummary:f.old.summary}};
 const entry={...f.record,sessionId:origin,status:'active',lastDelivery:receipt};
 const history={id,records:[receipt],earlierRecordsUnavailable:false,earlierRecordsPruned:false,retention:{days:30,records:200}};
 for(const methods of [Object.fromEntries(TYPERT.invocations.map(x=>[`schedule/${x.method}`,x])),TYPERT_REMOTE.methods]){
  assert.deepEqual(methods['schedule/catalog'].result.spec.create().parse([entry]),[entry]);
  assert.deepEqual(methods['schedule/history'].result.spec.create().parse(history),history);
  assert.equal(methods['schedule/retryExecution'],undefined);
 }
 await f.runtime.dispose();
});
