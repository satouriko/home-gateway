import assert from 'node:assert/strict';
import test from 'node:test';
import { installNativeMaintenance,scheduledDelivery } from '../src/dsh/native-maintenance.mjs';
const id='schedule-owned';
const item=(schedule_id=id)=>({schedule_id,occurrence_at:'2026-11-01T04:00:00Z',reminder_prompt:'用户修改后的真实任务内容'});
const message=items=>({source:{kind:'schedule'},content:[{type:'text',text:'[SCHEDULE REMINDER BATCH]\nreminders_json: '+JSON.stringify(items)}]});
function hookHarness(config={},identity={}){
 const hooks={},calls=[];
 const ctx={on:(name,fn)=>hooks[name]=fn,inject(){},get:()=>({catalog:async()=>[{id,sessionId:'s'}]}),logger:{warn(){}}};
 installNativeMaintenance(ctx,config,async payload=>{calls.push(payload);return{ok:true,result:payload.operation==='native_status'?{session_id:'s',schedule_id:id,enabled:true,retired_schedule_ids:identity.retired_schedule_ids||[]}:{dispatched:true}}},()=>identity);
 return{hooks,calls};
}
test('legacy owned delivery never enters the scheduler model or dispatches a duplicate worker',async()=>{
 const h=hookHarness(),m=message([item()]);
 const decision=await h.hooks['agent/pre-step']({agent:{id:'s'}},async()=>({kind:'enter',messages:[m]}));
 assert.equal(decision.kind,'reject');assert.equal(h.calls.filter(p=>p.operation==='native_admit').length,0);
});
test('mixed batches preserve unrelated reminders and real user input',async()=>{
 const h=hookHarness(),user={source:{kind:'user'},content:[{type:'text',text:'帮我处理当前问题'}]};
 const decision=await h.hooks['agent/pre-step']({agent:{id:'s'}},async()=>({kind:'enter',messages:[message([item(),item('schedule-other')]),user]}));
 assert.equal(decision.kind,'enter');assert.equal(decision.messages[1],user);
 assert.deepEqual(scheduledDelivery(decision.messages[0]).items.map(x=>x.schedule_id),['schedule-other']);
});
test('read-only tests never dispatch workers and malformed owned markers fail closed',async()=>{
 const h=hookHarness({readOnly:true}),m=message([item()]);
 assert.equal((await h.hooks['agent/pre-step']({agent:{id:'s'}},async()=>({kind:'enter',messages:[m]}))).kind,'reject');
 assert(!h.calls.some(p=>p.operation==='native_admit'));
 const malformed={source:{kind:'schedule'},content:[{type:'text',text:'[home-gateway-native-audit] malformed'}]};
 assert.equal((await h.hooks['agent/pre-step']({agent:{id:'s'}},async()=>({kind:'enter',messages:[malformed]}))).kind,'reject');
});
function setupHarness(current,catalog){
 const effects=[],calls=[],hooks={};
 const workspace={id:'w',path:'/var/lib/dsh/workspace',attachSession:async id=>calls.push(['attach',id])};
 const controller={list:async()=>({items:[{sessionId:'past',cwd:workspace.path}]}),create:async args=>{assert.equal(args.workspaceId,'w');return{sessionId:'new'}},projections:async()=>({values:{workingDirectory:workspace.path}})};
 const scoped={schedule:{registerExecutor:(name,fn)=>{calls.push(['executor',name,fn]);return()=>{};},configureExecution:async args=>{const task=catalog.find(t=>t.id===args.id);task.execution=args.execution;return task;},completeExecution:async()=>({updated:true}),catalog:async()=>catalog,create:async(sid,args)=>{calls.push(['create',sid,args]);return{id:'new-task',...args}}},sessionController:controller,workspaceRegistry:{resolveByPath:async()=>workspace},get:()=>undefined,effect(fn){effects.push(fn());},on(){}};
 const ctx={on:(n,f)=>hooks[n]=f,inject(names,fn){if(names.includes('schedule'))fn(scoped);},logger:{warn(){}}};
 installNativeMaintenance(ctx,{},async req=>{calls.push(req);return{ok:true,result:req.operation==='native_status'?current:{}}});
 return{calls,controller,cleanup(){for(const f of effects.reverse())f?.();}};
}
test('a deleted or disabled task stays deleted; an existing task retains all user edits',async()=>{
 for(const [current,catalog] of [[{session_id:'s',schedule_id:id,enabled:true},[]],[{session_id:'s',schedule_id:id,enabled:false},[]],[{session_id:'s',schedule_id:id,enabled:true},[{id,title:'自己改的名字',everySeconds:21600,status:'active'}]]]){
  const h=setupHarness(current,catalog);await new Promise(r=>setImmediate(r));
  assert(!h.calls.some(c=>c[0]==='create'));h.cleanup();
 }
});
test('fresh installation provisions one durable task; external worker reports join its workspace',async()=>{
 const h=setupHarness({preferences:{interval_hours:4}},[]);await new Promise(r=>setImmediate(r));
 assert.equal(h.calls.filter(c=>c[0]==='create').length,1);
 assert.equal(h.calls.find(c=>c[0]==='create')[2].every_seconds,14400);
 await h.controller.projections({sessionId:'external'});assert(h.calls.some(c=>c[0]==='attach'&&c[1]==='external'));
 h.cleanup();
});

test('cold broker outage rejects owned custom prompts using protected persisted identity',async()=>{
 const hooks={};const ctx={on:(n,f)=>hooks[n]=f,inject(){},logger:{warn(){}}};
 installNativeMaintenance(ctx,{},async()=>{throw new Error('broker offline')},()=>({session_id:'s',schedule_id:id}));
 const own=message([item()]);assert.equal((await hooks['agent/pre-step']({agent:{id:'s'}},async()=>({kind:'enter',messages:[own]}))).kind,'reject');
 const foreign=message([item('other')]);assert.equal((await hooks['agent/pre-step']({agent:{id:'foreign'}},async()=>({kind:'enter',messages:[foreign]}))).kind,'enter');
});
test('queued reminders of a deleted/recovered task are consumed while unrelated reminders survive',async()=>{
 const h=hookHarness({}, {retired_schedule_ids:['deleted-task']});
 const decision=await h.hooks['agent/pre-step']({agent:{id:'s'}},async()=>({kind:'enter',messages:[message([item('deleted-task'),item('other')])]}));
 assert.deepEqual(scheduledDelivery(decision.messages[0]).items.map(x=>x.schedule_id),['other']);
 assert(!h.calls.some(p=>p.operation==='native_admit'));
});
