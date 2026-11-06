import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deliverSyncNotice, deliverOperationNotice, formatSyncNotice, installSyncNotices } from '../src/dsh/sync-notices.mjs';

const sid='session-12345678-1234-4234-8234-123456789abc';
const receipt=(extra={})=>({id:'a'.repeat(32),revision:2,notice_id:'gateway-source-sync-'+ 'a'.repeat(32)+'-2',session_id:sid,
  reason:'program_publish',version:'b'.repeat(16),status:'success',remote_commit:'c'.repeat(40),repository_url:'https://github.com/example/project',branch:'main',...extra});

function harness({cold=false,busy=false,held=false,durability=true,ackFails=false}={}) {
  const events=[],calls=[];
  let active=false,leased=false;
  const append=(type,data,opts)=>{const event={type,data,...opts,seq:events.length,time:Date.now()};events.push(event);calls.push('append');return event;};
  const agent={id:sid,status:busy?'running':'idle',session:{id:sid,append},runMaintenance:async fn=>{
    if(busy||active)throw Error('active work');active=true;try{return await fn(new AbortController().signal);}finally{active=false;}
  }};
  const ctx={agents:{get:()=>cold?undefined:agent},sessions:{get:()=>cold?undefined:agent.session,flush:async()=>{calls.push('flush');return durability;}},
    sessionController:{inspect:async()=>({events}),resolveAgent(){throw Error('cold agent activation is forbidden');}},
    sessionPersistence:{open:async(id,access)=>{assert.equal(id,sid);assert.equal(access,'write');if(held||leased)throw Error('writer held');leased=true;calls.push('open');return{
      read:async()=>({events}),append:async batch=>{events.push(...batch);calls.push('append');},flush:async()=>{calls.push('flush');if(!durability)throw Error('disk full');},close:async()=>{leased=false;calls.push('close');}
    };}}};
  const broker=async req=>{calls.push(req);if(req.operation==='source_sync_notice_ack'&&ackFails)throw Error('broker restarted');return{ok:true,result:{acknowledged:true}};};
  return{ctx,broker,calls,events,agent};
}

test('deterministic native notice is durable before broker acknowledgment and never wakes a model',async()=>{
  const h=harness(),r=receipt();
  assert.equal(await deliverSyncNotice(h.ctx,r,h.broker),true);
  assert.deepEqual(h.calls.slice(0,2),['append','flush']);
  assert.equal(h.calls[2].operation,'source_sync_notice_ack');
  const e=h.events[0];
  assert.equal(e.type,'user/message');assert.equal(e.surfaceOp,'append');
  assert.equal(e.data.source.kind,'home-gateway-source-sync');assert.equal(e.data.source.form,'notice');
  assert.equal(e.data.id,r.notice_id);assert.match(e.data.content[0].text,/GitHub.*main/);
  assert.match(e.data.content[0].text,/https:\/\/github.com\/example\/project\/commit\/c{40}/);
  assert.match(e.data.source.summary,/已同步/);
});

test('crash after durable append before ack is recovered once after restart',async()=>{
  const h=harness({ackFails:true}),r=receipt();
  assert.equal(await deliverSyncNotice(h.ctx,r,h.broker),false);
  assert.equal(h.events.length,1);
  const ack=async req=>({ok:true,result:{acknowledged:req.message_id===r.notice_id}});
  assert.equal(await deliverSyncNotice(h.ctx,r,ack),true);
  assert.equal(h.events.length,1);
  assert.equal(h.calls.filter(x=>x==='flush').length,2);
});

test('busy agents, absent flush listeners and external writer leases defer delivery without ack',async()=>{
  for(const options of [{busy:true},{durability:false},{cold:true,held:true}]){
    const h=harness(options);assert.equal(await deliverSyncNotice(h.ctx,receipt(),h.broker),false);
    assert(!h.calls.some(c=>c.operation==='source_sync_notice_ack'));
    if(options.busy||options.held)assert.equal(h.events.length,0);
  }
});

test('cold native write handle releases its lease after durability and deduplicates retry',async()=>{
  const h=harness({cold:true}),r=receipt();
  assert.equal(await deliverSyncNotice(h.ctx,r,h.broker),true);
  assert.equal(await deliverSyncNotice(h.ctx,r,h.broker),true);
  assert.equal(h.events.length,1);
  assert.equal(h.calls.filter(x=>x==='close').length,2);
  assert(h.calls.indexOf('flush')<h.calls.findIndex(c=>c.operation==='source_sync_notice_ack'));
  const failed=harness({cold:true,durability:false});
  assert.equal(await deliverSyncNotice(failed.ctx,r,failed.broker),false);assert(failed.calls.includes('close'));
});

test('cold native operations carry a deadline and cancellation still closes the lease without acknowledgment',async()=>{
  const h=harness({cold:true}),controller=new AbortController(),seen=[];
  h.ctx.sessionPersistence.open=async(_id,_access,options)=>{
    assert(options.signal instanceof AbortSignal);seen.push('open');
    return{
      read:async(_offset,_length,options)=>{assert(options.signal instanceof AbortSignal);seen.push('read');controller.abort();return{events:[]};},
      append:async()=>{seen.push('append');},flush:async()=>{seen.push('flush');},close:async()=>{seen.push('close');}
    };
  };
  assert.equal(await deliverSyncNotice(h.ctx,receipt(),h.broker,{signal:controller.signal}),false);
  assert.deepEqual(seen,['open','read','close']);
  assert(!h.calls.some(c=>c.operation==='source_sync_notice_ack'));
});

test('cooperative native reads expire within the notice deadline and release their lease',async()=>{
  const h=harness({cold:true}),seen=[];
  h.ctx.sessionPersistence.open=async()=>({
    read:async(_offset,_length,{signal})=>new Promise((_resolve,reject)=>{
      signal.addEventListener('abort',()=>reject(signal.reason),{once:true});
    }),
    close:async()=>seen.push('close')
  });
  const attempted=deliverSyncNotice(h.ctx,receipt(),h.broker,{timeoutMs:50});
  // Native AbortSignal deadlines are unref'ed; represent the service's live
  // timer while this isolated test waits for cancellation.
  await new Promise(resolve=>setTimeout(resolve,75));
  assert.equal(await attempted,false);assert.deepEqual(seen,['close']);
  assert(!h.calls.some(c=>c.operation==='source_sync_notice_ack'));
});

test('held failed pending and superseded messages never claim remote confirmation',()=>{
  for(const status of ['pending','held','failed','superseded']){
    const text=formatSyncNotice(receipt({status,error_code:'push_rejected'}));
    assert(!text.summary.includes('已同步'));assert(!text.text.includes('/commit/'));
    assert.match(text.text,/尚未|未确认|未保存/);
  }
  const unsafe=formatSyncNotice(receipt({repository_url:'https://github.com.evil.invalid/user/repo',remote_commit:'../credentials'}));
  assert(!unsafe.text.includes('evil'));assert(!unsafe.text.includes('credentials'));assert(!unsafe.summary.includes('已同步'));
});

test('invalid session and malformed broker fields never reach native storage',async()=>{
  for(const extra of [{session_id:'../../private'},{id:'secret'},{revision:-1},{notice_id:'arbitrary'},
    {session_id:sid+'\n'},{version:'b'.repeat(16)+'\n'},
    {reason:'untrusted private error'},{version:'secret'},{status:'unknown'}]){
    const h=harness();assert.equal(await deliverSyncNotice(h.ctx,receipt(extra),h.broker),false);assert.equal(h.events.length,0);
  }
});

test('timer drains deterministic pending notices without a model turn and guards overlapping ticks',async()=>{
  const h=harness(),effects=[],callbacks=[];
  const ctx={...h.ctx,effect(fn){effects.push(fn());},on(){},logger:{warn(){}},get(name){return h.ctx[name];}};
  let lists=0;
  const broker=async req=>{
    if(req.operation==='source_sync_notices'){lists++;return{ok:true,result:{notices:[receipt()]}};}
    return h.broker(req);
  };
  const controls=installSyncNotices(ctx,{},broker,{setInterval(fn){callbacks.push(fn);return{unref(){}};},clearInterval(){}});
  await controls.drain();await controls.drain();
  assert(lists>=1);assert.equal(h.events.length,1);assert.equal(callbacks.length,1);
  effects.forEach(fn=>fn?.());
});

test('installed native JSONL backend persists notice and releases writer across service restart',
  {skip:!process.env.DSH_NATIVE_PACKAGE},async t=>{
  const require=createRequire(process.env.DSH_NATIVE_PACKAGE);
  const {Context}=await import(require.resolve('@deepseek-ai/cordis'));
  const {SessionStore,SESSION_FORMAT_VERSION}=await import(require.resolve('@deepseek-ai/dsh-session'));
  const backend=await import(require.resolve('@deepseek-ai/dsh-session-persistence-jsonl'));
  const root=await mkdtemp(join(tmpdir(),'gateway-native-notice-test-'));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const start=async()=>{
    const ctx=new Context();new SessionStore(ctx);
    await backend.apply(ctx,{root,compression:'none',listConcurrency:3});
    return ctx;
  };
  const first=await start();
  let second;
  try {
    const seed=await first.sessionPersistence.create({id:sid,version:SESSION_FORMAT_VERSION,createdAt:Date.now(),isSeeded:false,cwd:root});
    await seed.flush();await seed.close();
    const boundary=ctx=>({agents:{get:()=>undefined},sessions:ctx.sessions,sessionPersistence:ctx.sessionPersistence});
    let acks=0;
    const ack=async()=>{acks++;return{ok:true,result:{acknowledged:true}};};
    assert.equal(await deliverSyncNotice(boundary(first),receipt(),ack),true);
    const held=await first.sessionPersistence.open(sid,'write');
    assert.equal(await deliverSyncNotice(boundary(first),receipt({revision:3,notice_id:`gateway-source-sync-${'a'.repeat(32)}-3`}),ack),false);
    await held.close();
    await first.fiber.dispose();
    second=await start();
    assert.equal(await deliverSyncNotice(boundary(second),receipt(),ack),true);
    const operation={session_id:sid,revision:7,notice_id:'gateway-operations-'+sid.slice(8).replaceAll('-','')+'-7',
      records:[{operation:'recheck_nodes',status:'pending_rollback'},{operation:'restore_gateway',status:'rolled_back',gateway_restarted:true}]};
    assert.equal(await deliverOperationNotice(boundary(second),operation,ack),true);
    assert.equal(await deliverOperationNotice(boundary(second),operation,ack),true);
    const reader=await second.sessionPersistence.open(sid,'read');
    const {events}=await reader.read();await reader.close();
    assert.equal(events.length,2);assert.equal(events[0].data.id,receipt().notice_id);
    assert.equal(events[0].data.source.form,'notice');assert.equal(acks,4);
    assert.equal(events[1].data.source.kind,'home-gateway-operation-audit');
  } finally {await second?.fiber.dispose();await first.fiber.dispose();}
});
