import test from 'node:test';
import assert from 'node:assert/strict';
import { sdkModule, sdkDependency } from './paths.mjs';
const { Context, Service } = await sdkDependency('@deepseek-ai/cordis');
const { ScheduleService } = await sdkModule('lib/index.js');
const { scheduleTaskSchema } = await sdkModule('lib/types/storage.js');

// Real Cordis registration/lifecycle and real shipped Schedule service; only storage medium and origin are test boundaries.
test('real Cordis service migrates in place, isolates dispatch and completes through native changed notifications',async t=>{
  let clock=Date.parse('2026-11-01T00:00:00.000Z'); t.mock.method(Date,'now',()=>clock);
  const ctx=new Context(),store=new Map(),events=[]; let originReads=0,closed=false;
  const table={entries:()=>store.entries(),get:id=>store.get(id),put:async(id,task)=>{store.set(id,scheduleTaskSchema.parse(structuredClone(task)))},delete:async id=>{store.delete(id)}};
  const services={
    agents:{withoutInitiator:fn=>fn(),get:()=>{originReads++;return undefined}},
    sessions:{flush:async()=>{throw Error('External dispatch must not flush origin')}},
    storageDomain:{open:async()=>({table:()=>table,close:async()=>{closed=true}})},
    sessionController:{resolveAgent:async()=>{throw Error('External dispatch must not resolve origin')}},
    sessionPersistence:{},logger:{warn:message=>{throw Error(message)},error:message=>{throw Error(message)}},
  };
  for(const [name,value] of Object.entries(services))ctx.provide(name,value);
  ctx.on('schedule/changed',()=>events.push(structuredClone([...store.values()])));
  const service=new ScheduleService(ctx,{deliveryHistoryRecords:2});
  await service[Service.init]();
  const original=await service.create('origin-session',{title:'Core audit',prompt:'Inspect devices',every_seconds:60});
  const configured=await service.configureExecution({sessionId:'origin-session',id:original.id,execution:{kind:'external',executor:'home-network'}});
  assert.equal(configured.id,original.id); assert.equal(configured.scheduledAt,original.scheduledAt);
  const count=originReads; let args;
  const dispose=service.registerExecutor('home-network',async request=>{args=request;return {status:'started',summary:'Worker admitted'}});
  assert.throws(()=>service.registerExecutor('home-network',async()=>({status:'started'})),/already registered/);
  clock=Date.parse('2026-11-01T00:03:10.000Z'); service.runtime.requestDrive();
  await service.runtime.running; await service.chain;
  assert.equal(originReads,count); assert.equal(args.task.record.id,original.id);
  let catalog=await service.catalog(); assert.equal(catalog.length,1); assert.equal(catalog[0].lastDelivery.status,'started');
  await service.completeExecution({sessionId:'origin-session',id:original.id,executionId:args.executionId,status:'completed',summary:'Worker exited zero',executionSessionId:'fresh-result'});
  catalog=await service.catalog(); assert.equal(catalog[0].lastDelivery.status,'completed');
  assert.equal((await service.history({sessionId:'origin-session',id:original.id,limit:10})).records[0].executionSessionId,'fresh-result');
  const updated=await service.update({sessionId:'origin-session',id:original.id,expected:store.get(original.id).record,title:'Edited audit',change:{kind:'every',every_seconds:120}});
  assert.equal(updated.updated,true); assert.deepEqual(updated.record.execution,configured.execution); assert.equal(originReads,count);
  assert.ok(events.length>=6); assert.equal(events.at(-1)[0].record.title,'Edited audit');
  await service.delete({sessionId:'origin-session',id:original.id}); assert.deepEqual(await service.catalog(),[]);
  dispose();dispose(); await ctx.fiber.dispose(); assert.equal(closed,true);
});

// Catches a bind crash leaving a newly created native task untagged, and dispatch racing host reconciliation.
test('real service atomically creates external task before first due and cold catalog discovers its policy',async t=>{
  let clock=Date.parse('2026-11-01T00:00:00.000Z');t.mock.method(Date,'now',()=>clock);
  const store=new Map(),writes=[],warnings=[];let sourceReads=0,sourceResolves=0,sourceFlushes=0;
  const table={entries:()=>store.entries(),get:id=>store.get(id),put:async(id,task)=>{
    const parsed=scheduleTaskSchema.parse(structuredClone(task));store.set(id,parsed);writes.push(structuredClone(parsed));
    // Persistence can cross the first due time before create returns or a host binds the returned id.
    if(writes.length===1)clock=Date.parse('2026-11-01T00:02:10.000Z');
  },delete:async id=>{store.delete(id)}};
  const makeContext=()=>{
    const ctx=new Context();
    const services={agents:{withoutInitiator:fn=>fn(),get:()=>{sourceReads++;return undefined}},
      sessionController:{resolveAgent:async()=>{sourceResolves++;throw Error('External task reached source model')}},
      sessions:{flush:async()=>{sourceFlushes++;throw Error('External task flushed source Session')}},
      storageDomain:{open:async()=>({table:()=>table,close:async()=>{}})},sessionPersistence:{},
      logger:{warn:message=>warnings.push(message),error:message=>warnings.push(String(message))}};
    for(const [name,value] of Object.entries(services))ctx.provide(name,value);
    return ctx;
  };
  const firstContext=makeContext();t.after(()=>firstContext.fiber.dispose());
  const first=new ScheduleService(firstContext,{});await first[Service.init]();
  const execution={kind:'external',executor:'home-network'};
  const created=await first.create('origin-session',{title:'Atomic audit',prompt:'Inspect devices',every_seconds:60,execution});
  assert.deepEqual(created.execution,execution);
  assert.deepEqual(writes[0].record.execution,execution);
  await first.runtime.running;await first.chain;
  assert.equal(sourceReads,0);assert.equal(sourceResolves,0);assert.equal(sourceFlushes,0);
  const durable=structuredClone(store.get(created.id));
  assert.equal(durable.lastDelivery.status,'pending');
  assert.equal(durable.pendingExecution.executionId,durable.lastDelivery.executionId);
  assert.ok(writes.every(task=>task.record.execution?.executor==='home-network'));
  // No configureExecution or external bind happened. Reopen the same persisted native task.
  await firstContext.fiber.dispose();
  const coldContext=makeContext();t.after(()=>coldContext.fiber.dispose());
  const cold=new ScheduleService(coldContext,{});await cold[Service.init]();
  const discovered=(await cold.catalog()).find(task=>task.id===created.id);
  assert.deepEqual(discovered.execution,execution);assert.equal(discovered.lastDelivery.status,'pending');
  let received;
  cold.registerExecutor('home-network',async args=>{received=args;return {status:'skipped',summary:'No AI needed'}});
  await cold.runtime.running;await cold.chain;
  assert.equal(received.executionId,durable.pendingExecution.executionId);
  assert.equal((await cold.catalog())[0].lastDelivery.status,'skipped');
  const before=store.size;
  await assert.rejects(cold.create('origin-session',{title:'Invalid policy',prompt:'Inspect',after_seconds:60,execution:{kind:'external',executor:''}}),error=>error.code==='invalid_rule');
  assert.equal(store.size,before);assert.equal(sourceReads,0);assert.equal(sourceResolves,0);assert.equal(sourceFlushes,0);
  assert.deepEqual(warnings,[]);
});
