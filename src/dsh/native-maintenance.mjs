import { readFileSync } from 'node:fs';
import { callBroker as brokerCall } from './broker-client.mjs';

export const name='home-gateway-native-maintenance';
export const inject=['schedule','sessionController','workspaceRegistry'];
export function apply(ctx,config={}) { installNativeMaintenance(ctx,config,brokerCall); }

const MARKER='[home-gateway-native-audit]';
const DEFAULT_PROMPT='按当前用户策略复核家庭网络。对照实际连通性、DNS、节点质量和巡检程序覆盖，主动处理有证据的问题并复测；必要时维护工具和分析程序，保留已验证的经验。';

/** Decode pinned DSH schedule framing; edits to a task prompt retain its identity. */
export function scheduledDelivery(message) {
  if(message.source?.kind!=='schedule')return null;
  const text=message.content.filter(b=>b.type==='text').map(b=>b.text).join('\n');
  try {
    const batch=text.match(/^reminders_json: (.+)$/m);
    if(batch)return {items:JSON.parse(batch[1]),text,batch:true};
    const id=text.match(/^schedule_id_json: (.+)$/m),prompt=text.match(/^reminder_prompt_json: (.+)$/m),at=text.match(/^occurrence_at: (.+)$/m);
    if(id&&prompt)return {items:[{schedule_id:JSON.parse(id[1]),reminder_prompt:JSON.parse(prompt[1]),occurrence_at:at?.[1]}],text,batch:false};
  } catch {}
  return null;
}

function createRequest(definition,preferences) {
  const def=definition||{};
  const request={title:def.title||'AI 网络复核',prompt:def.prompt||DEFAULT_PROMPT};
  if(def.kind==='daily')request.daily={time:def.time,time_zone:def.timeZone};
  else if(def.kind==='weekly')request.weekly={time:def.time,time_zone:def.timeZone,weekdays:def.weekdays};
  else if(def.kind==='cron')request.cron={expression:def.expression,time_zone:def.timeZone};
  else if(def.kind==='after')request.after_seconds=def.afterSeconds;
  else if(def.kind==='at')request.at=def.scheduledAt;
  else request.every_seconds=def.everySeconds||(preferences.interval_hours||4)*3600;
  return request;
}

function readIdentity(){try{return JSON.parse(readFileSync('/var/lib/dsh/native-task-identity/identity.json','utf8'));}catch{return {};}}

export function installNativeMaintenance(ctx,config,callBroker,loadIdentity=readIdentity) {
  const request=async payload=>{
    const reply=await callBroker(payload,undefined,10000);
    if(!reply.ok)throw new Error(reply.message||'native maintenance control unavailable');
    return reply.result;
  };
  let current=loadIdentity(),ensure=async()=>{};
  ctx.on('agent/pre-step',async({agent},next)=>{
    const decision=await next();
    if(decision.kind!=='enter')return decision;
    const messages=decision.messages||[];
    if(!messages.some(m=>m.source?.kind==='schedule'))return decision;
    try{current={...loadIdentity(),...current,...await request({operation:'native_status'})};}catch{
      return messages.some(m=>m.content?.some(b=>b.type==='text'&&b.text.includes(MARKER)))||agent.id===current.session_id?{kind:'reject'}:decision;
    }
    const remaining=[];
    let handled=false;
    for(const message of messages) {
      const delivery=scheduledDelivery(message);
      if(!delivery){
        if(message.source?.kind==='schedule'&&message.content?.some(b=>b.type==='text'&&b.text.includes(MARKER))){handled=true;continue;}
        remaining.push(message);continue;
      }
      const protectedIds=[current.schedule_id,...(current.retired_schedule_ids||[])];
      const own=delivery.items.filter(item=>protectedIds.includes(item.schedule_id));
      if(!own.length){remaining.push(message);continue;}
      // Legacy inbox deliveries can survive task deletion or an upgrade. They
      // must never fall through to the originating conversation's model.
      handled=true;
      const other=delivery.items.filter(item=>![current.schedule_id,...(current.retired_schedule_ids||[])].includes(item.schedule_id));
      if(other.length)remaining.push({...message,content:[{type:'text',text:delivery.text.replace(/^reminders_json: .+$/m,'reminders_json: '+JSON.stringify(other))}]});
    }
    if(!handled)return decision;
    return remaining.length?{...decision,messages:remaining}:{kind:'reject'};
  });
  if(config.readOnly)return;
  ctx.inject(['schedule','sessionController','workspaceRegistry'],scoped=>{
    let checking=false,disposed=false;
    const completed=new Map();
    scoped.effect(()=>scoped.schedule.registerExecutor('home-network',async({task,occurrenceAt,executionId,signal})=>{
      const record=task.record||task;
      const meta=await request({operation:'native_status'});
      if(record.id!==meta.schedule_id||meta.enabled===false)return{executionId,status:'skipped',summary:'该任务已删除、停用或由明确恢复的新任务替代，本次未调用模型。'};
      await request({operation:'native_observe',task:{...record,sessionId:task.sessionId,status:task.status||'active'}});
      const reply=await callBroker({operation:'native_admit',session_id:task.sessionId||meta.session_id,
        occurrence:record.id+':'+occurrenceAt,execution_id:executionId,task_prompt:record.prompt},signal,12000);
      if(!reply.ok)throw new Error(reply.message||'isolated execution admission failed');
      const result=reply.result;
      if(result.existing_job){
        const job=result.existing_job;
        return{executionId:job.id,status:job.state==='running'?'started':job.state,summary:job.summary,executionSessionId:job.execution_session_id};
      }
      const reasons={'minimum audit spacing':'上次 AI 复核距现在过近，本次按费用保护跳过。','waiting for off-peak budget':'等待谷价，本次未调用模型；基础巡检继续运行。','storage reserve is protected':'存储预留不足，本次未调用模型。','waiting for fresh program observations':'尚无新鲜程序观测，本次不作健康判断。','emergency recovery takes priority':'故障处理优先，本次不再重复启动常规 AI 复核。','audit already running':'已有维护任务运行，本次避免重复调用模型。','no due audit or new improvement evidence':'没有到期复核或新的改进证据，本次未调用模型。'};
      return{executionId:result.id||executionId,status:result.dispatched?'started':'skipped',
        summary:result.dispatched?'已启动独立的 DSH 复核会话，完成后在这里关联真实结果。':reasons[result.reason]||'本次未启动新的模型执行。'};
    }));
    // A cold report from an external worker joins the one Web-owned registry.
    scoped.effect(()=>{
      const controller=scoped.sessionController,original=controller.projections;
      if(typeof original!=='function')return()=>{};
      const wrapped=async function(request,...args){
        const result=await original.call(this,request,...args);
        if(result?.values?.workingDirectory==='/var/lib/dsh/workspace'){
          try{const workspace=await scoped.workspaceRegistry.resolveByPath('/var/lib/dsh/workspace');if(workspace)await workspace.attachSession(request.sessionId);}
          catch{ctx.logger.warn('background session accounting deferred');}
        }
        return result;
      };
      controller.projections=wrapped;
      return()=>{if(controller.projections===wrapped)controller.projections=original;};
    });
    ensure=async()=>{
      if(checking||disposed)return;checking=true;
      try {
        const workspace=await scoped.workspaceRegistry.resolveByPath('/var/lib/dsh/workspace')||await scoped.workspaceRegistry.create('/var/lib/dsh/workspace','家庭网络');
        const sessions=await scoped.sessionController.list({});
        for(const item of sessions.items)if(item.cwd===workspace.path)await workspace.attachSession(item.sessionId);
        current={...loadIdentity(),...await request({operation:'native_status'})};
        if(current.enabled===false)return;
        const catalog=await scoped.schedule.catalog();
        let task=catalog.find(t=>t.id===current.schedule_id);
        if(!current.schedule_id){
          const existing=catalog.filter(t=>t.execution?.kind==='external'&&t.execution.executor==='home-network');
          if(existing.length>1)throw new Error('multiple household tasks require review');
          if(existing.length===1){task=existing[0];current={...current,session_id:task.sessionId,schedule_id:task.id};}
        }
        if(task){
          if(task.execution?.kind!=='external'||task.execution.executor!=='home-network')await scoped.schedule.configureExecution({sessionId:current.session_id,id:task.id,execution:{kind:'external',executor:'home-network'}});
          await request({operation:'native_bind',session_id:current.session_id,schedule_id:task.id});
          const actual=(await scoped.schedule.catalog()).find(t=>t.id===task.id);
          await request({operation:'native_observe',task:actual});
          for(const job of current.runs||[]){
            if(!job.schedule_id||job.schedule_id!==task.id||job.state==='running')continue;
            const signature=JSON.stringify([job.state,job.summary,job.execution_session_id]);
            if(completed.get(job.id)===signature)continue;
            const result=await scoped.schedule.completeExecution({sessionId:current.session_id,id:task.id,executionId:job.id,
              status:job.state==='preempted'?'interrupted':job.state,summary:job.summary,executionSessionId:job.execution_session_id});
            if(result?.updated)completed.set(job.id,signature);
          }
          // A corrected due gate can recover the latest rejected occurrence
          // through native durable delivery, without moving the user's task.
          const retry=(await request({operation:'native_status'})).retry_execution;
          if(retry?.session_id===current.session_id&&retry.schedule_id===task.id&&
             actual?.lastDelivery?.executionId===retry.execution_id&&actual.lastDelivery.scheduledAt===retry.occurrence_at){
            const {sessionId,status,lastDelivery,...expected}=actual;
            await scoped.schedule.retryExecution({sessionId:retry.session_id,id:retry.schedule_id,executionId:retry.execution_id,expected});
          }
          return;
        }
        if(current.schedule_id&&!current.provision_requested){await request({operation:'native_observe',task:null});return;}
        if(current.runs?.at(-1)?.state==='running'&&current.runs.at(-1).deadline>Date.now()/1000)return;
        const sid=current.session_id||(await scoped.sessionController.create({workspaceId:workspace.id})).sessionId;
        const session=scoped.get('sessions')?.get(sid);
        if(session&&!current.session_id)scoped.get('sessionTitle')?.rename(session,'网络巡检记录');
        const preferences=current.preferences||{};
        const created=await scoped.schedule.create(sid,{...createRequest(preferences.schedule,preferences),execution:{kind:'external',executor:'home-network'}});
        await request({operation:'native_bind',session_id:sid,schedule_id:created.id});
        current={...current,session_id:sid,schedule_id:created.id};
        await request({operation:'native_observe',task:{...created,sessionId:sid,status:'active'}});
      } catch {ctx.logger.warn('native task observation deferred; local fault supervision continues');}
      finally{checking=false;}
    };
    scoped.effect(()=>{
      void ensure();const timer=setInterval(()=>void ensure(),60000);timer.unref?.();
      return()=>{disposed=true;clearInterval(timer);};
    });
    scoped.on?.('schedule/changed',()=>{void ensure();});
  });
  ctx.inject(['webServer','connection'],scoped=>{
    scoped.effect(()=>scoped.webServer.register({kind:'exact',path:'/api/home-network/inspection',handler:async(req,res)=>{
      const respond=(status,value)=>{const body=JSON.stringify(value);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Content-Length':Buffer.byteLength(body)});res.end(body);};
      const admission=scoped.connection.admit(req);
      if('rejection' in admission)return respond(admission.rejection,{error:'access denied'});
      if(req.method!=='GET')return respond(405,{error:'GET required'});
      try{if(req.headers.origin&&new URL(req.headers.origin).host!==req.headers.host)return respond(403,{error:'cross origin'});}catch{return respond(403,{error:'invalid origin'});}
      const sid=new URL(req.url,'http://local').searchParams.get('sessionId');
      if(!/^session-[a-f0-9-]{36}$/.test(sid||''))return respond(400,{error:'invalid session'});
      try{respond(200,await request({operation:'native_inspection',session_id:sid}));}catch{respond(503,{error:'inspection unavailable'});}
    }}));
  });
}
