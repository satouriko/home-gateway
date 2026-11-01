/** Runs before the client shell mounts; serialized into the served index. */
export function installMobileViewport() {
  const root = document.documentElement;
  const media = window.matchMedia('(max-width: 1023px) and (pointer: coarse)');
  let original = null;
  const restore = () => {
    if (original === null) return;
    if (original.value) root.style.setProperty('touch-action', original.value, original.priority);
    else root.style.removeProperty('touch-action');
    original = null;
  };
  const update = () => {
    if (!media.matches) return restore();
    if (original === null) {
      original = { value: root.style.getPropertyValue('touch-action'), priority: root.style.getPropertyPriority('touch-action') };
    }
    // Permit scrolling within code/table surfaces while stopping whole-page pinch.
    root.style.setProperty('touch-action', 'pan-y', 'important');
  };
  const preventPageGesture = event => { if (media.matches) event.preventDefault(); };
  const gestures = ['gesturestart', 'gesturechange'];
  const gestureOptions = { capture: true, passive: false };
  for (const type of gestures) document.addEventListener(type, preventPageGesture, gestureOptions);
  // Safari may claim an edge drag before pointermove. Reserve the narrow
  // non-interactive page edge; buttons and editable/scrollable surfaces keep
  // their own native touch handling. The browser's chrome is outside our reach.
  const edgeStart = event => {
    if (!media.matches || event.touches?.length !== 1) return;
    const x = event.touches[0].clientX;
    if (x >= 24 && x <= window.innerWidth - 24) return;
    if (event.target?.closest?.('button,a,input,textarea,[contenteditable="true"],pre,[role="menu"],[role="dialog"]')) return;
    event.preventDefault();
  };
  document.addEventListener('touchstart', edgeStart, gestureOptions);
  media.addEventListener('change', update);
  update();
  return () => {
    document.removeEventListener('touchstart', edgeStart, gestureOptions);
    media.removeEventListener('change', update);
    for (const type of gestures) document.removeEventListener(type, preventPageGesture, gestureOptions);
    restore();
  };
}

// Keep overflow controls inside their own surfaces; never clip the whole chat.
export const MOBILE_LAYOUT_CSS = `
@media (max-width:1023px) and (pointer:coarse) {
  html, body { -webkit-text-size-adjust:100%; text-size-adjust:100%; }
  [data-mobile-nav="frame"] [contenteditable="true"],
  [data-mobile-nav="frame"] textarea,
  [data-mobile-nav="frame"] input:not([type="checkbox"]):not([type="radio"]) { font-size:16px !important; }
  [data-mobile-nav="frame"] [class*="_tabs"]:has(> [class*="_viewTabs"]) {
    display:flex !important; align-items:center !important; flex-wrap:nowrap !important;
    min-width:0; width:100%; gap:8px;
  }
  [data-mobile-nav="frame"] [class*="_viewTabs"] { flex:1 1 auto; min-width:0; }
  [data-mobile-nav="frame"] [class*="_viewsMoreAnchor"] {
    display:inline-flex !important; flex:0 0 auto; align-self:center !important;
    margin:0 8px 0 auto !important;
  }
}`;


/** Merge output-free scheduler turns into a factual program inspection record. */
export function installInspectionRecords() {
  const mark='data-home-gateway-empty-turn',record='data-home-network-record';
  const style=document.createElement('style');
  style.textContent=`[${mark}]{display:none!important}[${record}]{box-sizing:border-box;max-width:calc(100% - 32px);margin:12px 16px;padding:12px 14px;border:1px solid var(--dsw-alias-border-l2,#ddd);border-radius:12px;background:var(--dsw-alias-bg-layer-2,#f7f8fa);color:var(--dsw-alias-label-primary,#222);font-size:14px;line-height:1.65;white-space:pre-line;overflow-wrap:anywhere}[${record}] strong{display:block;font-size:15px;margin-bottom:5px}`;
  document.head.appendChild(style);
  const cache=new Map();let frame=0,disposed=false;
  const date=at=>at?new Date(typeof at==='number'?at*1000:at).toLocaleString('zh-CN',{hour12:false}):'尚无记录';
  const reasons={
    'minimum audit spacing':'刚完成过 AI 复核，本次不重复调用模型。',
    'no due audit or new improvement evidence':'尚未到复核时间，也没有新的改进证据，本次未启动 AI。',
    'waiting for off-peak budget':'常规 AI 复核等待谷价；新故障仍会立即处理。',
    'storage reserve is protected':'存储接近预留线，已暂停常规 AI 复核，本地保护继续运行。',
    'waiting for fresh program observations':'程序观测尚未更新，本次不作健康判断，等待新采样。',
    'emergency recovery takes priority':'优先处理故障，本次没有再启动常规复核。',
    'audit already running':'已有 AI 任务进行中，本次避免重复启动。',
    'automation task is disabled or deleted':'AI 定时复核已停用，本地巡检和故障保护继续运行。',
    'this occurrence was already handled':'这次任务投递已处理，本次未重复调用模型。',
  };
  const schedule=()=>{if(!disposed&&!frame)frame=requestAnimationFrame(reconcile);};
  const getData=sid=>{
    if(!/^session-[a-f0-9-]{36}$/.test(sid||''))return null;
    let value=cache.get(sid);
    if(!value){value={at:0};cache.set(sid,value);}
    if(!value.pending&&Date.now()-value.at>=30000){
      value.at=Date.now();value.pending=true;
      fetch('/api/home-network/inspection?sessionId='+encodeURIComponent(sid),{credentials:'same-origin',cache:'no-store'})
        .then(response=>{if(!response.ok)throw new Error('unavailable');return response.json();})
        .then(data=>{value.data=data;value.error=false;}).catch(()=>{value.error=true;})
        .finally(()=>{value.pending=false;schedule();});
    }
    return value;
  };
  const textFor=value=>{
    if(value?.error)return '暂时无法读取最新巡检状态，不能据此确认网络健康。稍后会自动重试。';
    const data=value?.data;
    if(!data)return '正在读取程序的实际检查结果；这条状态记录本身不调用模型。';
    if(!data.managed)return '这轮没有产生可展示的回复或工具操作；执行状态不代表问题已修复。';
    const lines=[];
    if(data.checked_at){
      lines.push('程序观测：'+date(data.checked_at));
      const passed=data.checks.filter(c=>c.ok).map(c=>c.label),failed=data.checks.filter(c=>!c.ok).map(c=>c.label);
      if(Date.now()/1000-data.checked_at>600)lines.push('观测已超过10分钟，暂不能确认当前健康状态。');
      if(passed.length)lines.push('已通过：'+passed.join('、')+'。');
      if(failed.length)lines.push('异常项：'+failed.join('、')+'。是否恢复以实际复测为准。');
    }else lines.push('还没有足够的新鲜观测，暂不宣称网络正常。');
    if(data.enabled===false)lines.push('AI 定时任务已删除或停用；不会自动重建。');
    const gate=data.last_gate;
    if(gate?.admitted===false)lines.push('最近一次任务检查：'+(reasons[gate.reason]||'本次没有启动新的 AI 复核。'));
    const job=data.last_execution;
    if(job){
      const states={running:'进行中',completed:'已完成',failed:'未完成',expired:'已超时',preempted:'已让位给故障处理',interrupted:'已中断'};
      lines.push((job.kind==='deployment_validation'?'部署验收：':'最近 AI 复核：')+(states[job.state]||job.state)+'，'+date(job.finished_at||job.at)+'。');
      if(job.summary)lines.push((job.execution_session_id?'AI 复核结论：':'程序说明：')+job.summary.slice(0,700));
      if(job.execution_session_id)lines.push('详细过程保存在同一工作区的独立“网络AI复核”会话中。');
    }
    if(data.next_at&&data.task_status!=='inactive'&&data.enabled!==false)lines.push('下次任务计划：'+date(data.next_at)+'；常规调用仍遵循谷价和费用预算。');
    else if(data.task_status==='inactive')lines.push('这个一次性任务已结束，没有下一次投递。');
    return lines.join('\n');
  };
  function reconcile() {
    frame=0;const groups=new Map();
    for(const row of document.querySelectorAll('[data-chat-flow-kind][data-chat-turn]')){
      const column=row.parentElement;
      if(!groups.has(column))groups.set(column,new Map());
      const turns=groups.get(column),turn=row.getAttribute('data-chat-turn');
      if(!turns.has(turn))turns.set(turn,[]);turns.get(turn).push(row);
    }
    const active=new Set();
    for(const [column,turns] of groups){
      let anchor=null;
      for(const rows of turns.values()){
        const process=rows.find(row=>row.getAttribute('data-chat-flow-kind')==='turn-process');
        const counter=process?.querySelector('[data-turn-process]');
        const empty=counter&&['messages','tool-calls','subagents'].every(key=>counter.getAttribute('data-turn-process-'+key)==='0')&&rows.every(row=>{
          const kind=row.getAttribute('data-chat-flow-kind');
          return kind==='turn-process'||(kind==='turn-tail'&&!row.textContent.trim()&&!row.querySelector('button,a,input,[role="alert"]'));
        });
        for(const row of rows){
          if(empty){if(!row.hasAttribute(mark))row.setAttribute(mark,'');}
          else if(row.hasAttribute(mark))row.removeAttribute(mark);
        }
        if(empty)anchor=process;
      }
      let card=[...column.children].find(e=>e.hasAttribute(record));
      if(!anchor){card?.remove();continue;}
      if(!card){card=document.createElement('aside');card.setAttribute(record,'');const title=document.createElement('strong');title.textContent='程序巡检记录';card.appendChild(title);card.appendChild(document.createElement('div'));}
      active.add(card);
      if(card.nextSibling!==anchor)column.insertBefore(card,anchor);
      const sid=column.closest('[data-conversation-session]')?.getAttribute('data-conversation-session');
      const body=textFor(getData(sid));if(card.lastElementChild.textContent!==body)card.lastElementChild.textContent=body;
    }
    for(const card of document.querySelectorAll(`[${record}]`))if(!active.has(card))card.remove();
  }
  const observer=new MutationObserver(schedule);
  observer.observe(document.documentElement,{subtree:true,childList:true,characterData:true,attributes:true,
    attributeFilter:['data-chat-flow-kind','data-chat-turn','data-conversation-session','data-turn-process-messages','data-turn-process-tool-calls','data-turn-process-subagents']});
  const timer=setInterval(()=>{if(document.visibilityState!=='hidden')schedule();},30000);schedule();
  return()=>{
    disposed=true;observer.disconnect();clearInterval(timer);if(frame)cancelAnimationFrame(frame);
    for(const row of document.querySelectorAll(`[${mark}]`))row.removeAttribute(mark);
    for(const card of document.querySelectorAll(`[${record}]`))card.remove();style.remove();
  };
}
