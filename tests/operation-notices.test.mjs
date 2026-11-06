import assert from 'node:assert/strict';
import test from 'node:test';
import {deliverOperationNotice,formatOperationNotice,installSyncNotices} from '../src/dsh/sync-notices.mjs';
const sid='session-12345678-1234-1234-1234-123456789abc';
const receipt=()=>({session_id:sid,revision:3,notice_id:'gateway-operations-'+sid.slice(8).replaceAll('-','')+'-3',records:[
  {operation:'recheck_nodes',status:'pending_rollback'},
  {operation:'refresh_subscription',status:'rejected'},
  {operation:'restore_gateway',status:'rolled_back',gateway_restarted:true}]});

test('independent repair facts name rejected work and rollback without claiming application recovery',()=>{
 const m=formatOperationNotice(receipt());
 assert.match(m.text,/节点复检.*等待保护回退/);assert.match(m.text,/订阅刷新.*被拒绝/);
 assert.match(m.text,/重启网关/);assert.match(m.text,/业务.*实际复测/);assert.match(m.text,/未调用模型/);
});

test('operation notice persists in the original native chat once before acknowledgment without running a model',async()=>{
 const events=[],calls=[];
 const ctx={agents:{get:()=>undefined},sessions:{get:()=>undefined},sessionPersistence:{open:async(id,mode)=>{
  assert.equal(id,sid);assert.equal(mode,'write');return{
   read:async()=>({events}),append:async rows=>events.push(...rows),flush:async()=>calls.push('flush'),close:async()=>calls.push('close')};
 }}};
 const broker=async request=>{calls.push(request);return {ok:true,result:{acknowledged:true}};};
 assert.equal(await deliverOperationNotice(ctx,receipt(),broker),true);
 assert.equal(await deliverOperationNotice(ctx,receipt(),broker),true);
 assert.equal(events.length,1);assert.equal(events[0].data.source.kind,'home-gateway-operation-audit');
 assert.equal(calls[2].operation,'operation_notice_ack');
});

test('malformed or private operation payloads cannot be rendered into a native notice',async()=>{
 const ctx={agents:{get(){throw Error('must not touch native storage');}}};
 for(const extra of [{session_id:'private'}, {revision:-1}, {records:[{operation:'private error text',status:'failed'}]}])
  assert.equal(await deliverOperationNotice(ctx,{...receipt(),...extra},async()=>{}),false);
});

test('a broken publication stream does not prevent operation facts reaching the chat',async()=>{
 const events=[],cleanup=[];
 const ctx={effect(fn){cleanup.push(fn());},agents:{get:()=>undefined},sessions:{get:()=>undefined},sessionPersistence:{open:async()=>({
  read:async()=>({events}),append:async rows=>events.push(...rows),flush:async()=>{},close:async()=>{}})}};
 const broker=async request=>{
  if(request.operation==='source_sync_notices')throw Error('publication registry unavailable');
  return {ok:true,result:request.operation==='operation_notices'?{notices:[receipt()]}:{acknowledged:true}};
 };
 const controls=installSyncNotices(ctx,{},broker,{setInterval(){return{unref(){}};},clearInterval(){}});
 await new Promise(resolve=>setImmediate(resolve));await controls.drain();
 assert.equal(events.length,1);assert.equal(events[0].data.source.kind,'home-gateway-operation-audit');
 cleanup.forEach(fn=>fn?.());
});
