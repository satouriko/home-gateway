import { callBroker as brokerCall } from './broker-client.mjs';

export const name='home-gateway-source-sync-notices';
export const inject=['agents','sessions','sessionController','sessionPersistence'];
export function apply(ctx,config={}) { installSyncNotices(ctx,config,brokerCall); }

const SESSION=/^session-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const IDENT=/^[a-f0-9]{32}$/;
const VERSION=/^[a-f0-9]{16,64}$/;
const COMMIT=/^[a-f0-9]{40,64}$/;
const REPOSITORY=/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const LABELS={program_publish:'巡检程序',tool_publish:'运维工具',skill_publish:'运维方法',policy_apply:'网络偏好',
  workflow_publish:'运维策略',route_apply:'定向分流规则',audit_plan_set:'审计计划',audit_plan_enable:'审计计划',native_observe:'任务设置'};
const STATUSES=new Set(['pending','held','failed','success','superseded']);

function validReceipt(r) {
  return r&&SESSION.test(r.session_id||'')&&IDENT.test(r.id||'')&&Number.isSafeInteger(r.revision)&&r.revision>0&&
    r.notice_id===`gateway-source-sync-${r.id}-${r.revision}`&&Object.hasOwn(LABELS,r.reason)&&
    (r.version===null||r.version===undefined||VERSION.test(r.version))&&STATUSES.has(r.status);
}

export function formatSyncNotice(receipt) {
  const label=LABELS[receipt.reason]||'发布内容';
  const version=VERSION.test(receipt.version||'')?`（版本 ${receipt.version}）`:'';
  const success=receipt.status==='success'&&receipt.branch==='main'&&REPOSITORY.test(receipt.repository_url||'')&&COMMIT.test(receipt.remote_commit||'');
  if(success) {
    return{summary:`${label}已同步到 GitHub main`,text:`${label}${version}已在本机发布，并已同步到 GitHub main。\n提交：${receipt.repository_url}/commit/${receipt.remote_commit}\n这是程序核对后的远端回执，未调用模型。`};
  }
  const descriptions={pending:['等待同步到 GitHub','已在本机发布；GitHub main 尚未确认保存。后台会继续同步，完成后自动回执。'],
    held:['GitHub 同步暂缓','已在本机发布；部署集成期间同步暂缓，GitHub main 尚未确认保存。解除暂缓后后台会自动重试并回执。'],
    failed:['GitHub 同步失败，等待重试','已在本机发布；本次 GitHub 同步失败，远端尚未确认保存。后台会自动重试，完成后自动回执。'],
    superseded:['该版本已被后续发布替代','本机发布后已被同一内容的更新版本替代；此版本未确认单独保存到 GitHub。后续发布会收到它自己的回执。']};
  const [summary,text]=descriptions[receipt.status]||['GitHub 回执待核验','本机发布完成，GitHub main 尚未确认保存；后台将继续核验。'];
  return{summary:`${label}${summary}`,text:`${label}${version}${text}`};
}

function messageFor(receipt) {
  const notice=formatSyncNotice(receipt);
  return{id:receipt.notice_id,role:'user',content:[{type:'text',text:notice.text}],
    source:{kind:'home-gateway-source-sync',form:'notice',summary:notice.summary}};
}

function alreadyPresent(events,id) {
  return events.some(event=>event.type==='user/message'&&event.data?.id===id&&event.data.source?.kind==='home-gateway-source-sync');
}

/** One native context notice, never an Inbox delivery or a fabricated model response. */
export async function deliverSyncNotice(ctx,receipt,callBroker=brokerCall,options={}) {
  if(!validReceipt(receipt))return false;
  const sid=receipt.session_id;
  const timeoutMs=Number.isFinite(options.timeoutMs)?Math.max(50,Math.min(5000,options.timeoutMs)):5000;
  const deadline=AbortSignal.timeout(timeoutMs);
  const signal=options.signal?AbortSignal.any([deadline,options.signal]):deadline;
  try {
    signal.throwIfAborted();
    const agent=ctx.agents.get(sid);
    if(agent) {
      // runMaintenance atomically owns the true idle phase; incoming user input
      // waits behind this bounded append/flush, and an active turn rejects it.
      await agent.runMaintenance(async maintenanceSignal=>{
        const activeSignal=AbortSignal.any([signal,maintenanceSignal]);
        const observed=await ctx.sessionController.inspect(sid,activeSignal);
        activeSignal.throwIfAborted();
        if(!alreadyPresent(observed.events,receipt.notice_id))agent.session.append('user/message',messageFor(receipt),{surfaceOp:'append'});
        if(await ctx.sessions.flush(agent.session)!==true)throw Error('notice persistence unavailable');
        activeSignal.throwIfAborted();
      });
    } else {
      // Do not resume an Agent merely to display a notice. The native write
      // handle takes the cross-process writer lease and releases it on close.
      if(ctx.sessions.get(sid))return false;
      const handle=await ctx.sessionPersistence.open(sid,'write',{signal});
      try {
        signal.throwIfAborted();
        const {events}=await handle.read(undefined,undefined,{signal});
        signal.throwIfAborted();
        if(!alreadyPresent(events,receipt.notice_id)) {
          const seq=events.length?events.at(-1).seq+1:0;
          await handle.append([{type:'user/message',seq,time:Date.now(),surfaceOp:'append',data:messageFor(receipt)}],{signal});
        }
        signal.throwIfAborted();
        await handle.flush({signal});
      } finally {await handle.close();}
    }
    signal.throwIfAborted();
    const reply=await callBroker({operation:'source_sync_notice_ack',request_id:receipt.id,revision:receipt.revision,
      session_id:sid,message_id:receipt.notice_id},signal,5000);
    return reply.ok===true&&reply.result?.acknowledged===true;
  } catch {return false;}
}

/** Root-owned registry survives process restart; timers spend no model tokens. */
export function installSyncNotices(ctx,config={},callBroker=brokerCall,timers=globalThis) {
  let running=false,disposed=false;
  const lifetime=new AbortController();
  const drain=async()=>{
    if(running||disposed||config.readOnly)return;
    running=true;
    try {
      const reply=await callBroker({operation:'source_sync_notices'},lifetime.signal,5000);
      if(reply.ok!==true||!Array.isArray(reply.result?.notices))return;
      for(const receipt of reply.result.notices.slice(0,32)) {
        if(disposed)break;
        await deliverSyncNotice(ctx,receipt,callBroker,{signal:lifetime.signal});
      }
    } catch { /* Durable registry remains pending across broker/Web restarts. */ }
    finally {running=false;}
  };
  if(!config.readOnly)ctx.effect(()=>{
    void drain();
    const interval=Number.isFinite(config.intervalMs)?Math.max(1000,Math.min(60000,config.intervalMs)):10000;
    const timer=timers.setInterval(()=>void drain(),interval);timer.unref?.();
    return()=>{disposed=true;lifetime.abort();timers.clearInterval(timer);};
  });
  return{drain};
}
