window.__ModuleLoader__.load({
  id: 'home-network-overview',
  factory: require => {
    const React = require('react');
    const {createElement:h, useEffect, useRef, useState} = React;
    const PANEL = 'home-network-overview';
    const NS = 'home-network.overview';
    const styles = `
      [data-network-overview] { --nvo-bg:var(--dsw-alias-bg-base,light-dark(#fff,#191b20)); --nvo-page:light-dark(#f6f7fa,#12151a); --nvo-text:var(--dsw-alias-label-primary,light-dark(#20283a,#edf0f6)); --nvo-muted:var(--dsw-alias-label-secondary,light-dark(#687386,#a8b0c0)); --nvo-line:var(--dsw-alias-border-l3,light-dark(#e8ecf2,#333a47)); --nvo-good:light-dark(#227f61,#82d5b1); --nvo-good-bg:light-dark(#eaf6f0,#213b31); --nvo-warn:light-dark(#946014,#ebc180); --nvo-warn-bg:light-dark(#fff4e3,#403324); --nvo-bad:light-dark(#b54e50,#f3aaaa); --nvo-bad-bg:light-dark(#fff0ee,#432b2e); height:100%; min-height:0; min-width:0; overflow:auto; background:var(--nvo-page); color:var(--nvo-text); font-family:inherit; font-size:14px; line-height:1.6; }
      [data-network-overview] * {box-sizing:border-box;min-width:0;}
      [data-network-overview] .nvo-header {display:flex;align-items:center;gap:8px;padding:12px 16px;background:var(--nvo-bg);border-bottom:1px solid var(--nvo-line);position:sticky;top:0;z-index:2;}
      [data-mobile-nav="frame"] [data-network-overview] .nvo-header {padding-left:56px;}
      body:has([data-mobile-nav="fab"]) [data-mobile-nav="frame"] [data-network-overview] .nvo-back {display:none;}
      [data-network-overview] .nvo-header h1 {font-size:17px;font-weight:500;margin:0;flex:1;}
      [data-network-overview] button {font:inherit;display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:42px;min-width:44px;padding:7px 8px;border:0;border-radius:9px;background:transparent;color:var(--nvo-muted);cursor:pointer;}
      [data-network-overview] button:hover {background:var(--nvo-page);}
      [data-network-overview] button:disabled {opacity:.55;cursor:wait;}
      [data-network-overview] button:focus-visible {outline:2px solid var(--nvo-muted);outline-offset:2px;}
      [data-network-overview] .nvo-body {max-width:720px;margin:0 auto;padding:18px 16px 22px;display:flex;flex-direction:column;gap:12px;}
      [data-network-overview] .nvo-card {padding:19px 18px;border-radius:16px;background:var(--nvo-bg);}
      [data-network-overview] .nvo-label {font-size:13px;color:var(--nvo-muted);}
      [data-network-overview] .nvo-row {display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:7px 12px;}
      [data-network-overview] .nvo-node-name {font-size:25px;font-weight:500;line-height:1.4;margin:12px 0 11px;overflow-wrap:anywhere;white-space:normal;}
      [data-network-overview] .nvo-meta {display:flex;align-items:center;flex-wrap:wrap;gap:6px 14px;color:var(--nvo-muted);font-size:12px;}
      [data-network-overview] .nvo-chip {display:inline-flex;align-items:center;gap:5px;padding:4px 8px;border-radius:7px;font-size:12px;color:var(--nvo-warn);background:var(--nvo-warn-bg);}
      [data-network-overview] .nvo-chip[data-state=healthy] {color:var(--nvo-good);background:var(--nvo-good-bg);}
      [data-network-overview] .nvo-chip[data-state=unhealthy] {color:var(--nvo-bad);background:var(--nvo-bad-bg);}
      [data-network-overview] .nvo-chip[data-state=not_used] {color:var(--nvo-muted);background:var(--nvo-page);}
      [data-network-overview] .nvo-dot {width:6px;height:6px;border-radius:50%;background:currentColor;display:inline-block;flex:0 0 auto;}
      [data-network-overview] .nvo-checks {display:flex;flex-wrap:wrap;gap:10px 19px;margin-top:12px;}
      [data-network-overview] .nvo-check {display:flex;align-items:center;gap:7px;}
      [data-network-overview] .nvo-check-value {display:inline-flex;align-items:center;gap:5px;color:var(--nvo-warn);}
      [data-network-overview] .nvo-check[data-state=healthy] .nvo-check-value {color:var(--nvo-good);}
      [data-network-overview] .nvo-check[data-state=unhealthy] .nvo-check-value {color:var(--nvo-bad);}
      [data-network-overview] .nvo-check[data-state=not_used] .nvo-check-value {color:var(--nvo-muted);}
      [data-network-overview] .nvo-summary {margin:8px 0 0;font-size:15px;overflow-wrap:anywhere;}
      [data-network-overview] .nvo-sub {margin:6px 0 0;font-size:12px;color:var(--nvo-muted);overflow-wrap:anywhere;}
      [data-network-overview] .nvo-event {display:flex;align-items:baseline;gap:10px;margin-top:9px;}
      [data-network-overview] .nvo-event time {flex:0 0 auto;color:var(--nvo-muted);font-size:12px;}
      [data-network-overview] .nvo-event p {margin:0;overflow-wrap:anywhere;}
      [data-network-overview] .nvo-device {display:flex;justify-content:center;flex-wrap:wrap;gap:6px 14px;color:var(--nvo-muted);font-size:12px;padding:3px 0;}
      [data-network-overview] .nvo-alert {padding:12px 16px;border-radius:12px;background:var(--nvo-warn-bg);color:var(--nvo-warn);font-size:13px;}
      @media(max-width:360px){[data-network-overview] .nvo-body{padding:14px 12px 20px;}[data-network-overview] .nvo-card{padding:17px 16px;}[data-network-overview] .nvo-node-name{font-size:24px;}[data-network-overview] .nvo-checks{gap:9px 13px;}}
    `;
    const valid = value => typeof value === 'number' && Number.isFinite(value);
    const isFresh = (at, now) => valid(at) && now-at <= 600 && now-at >= -60;
    const timeLabel = at => {
      if (!valid(at) || at <= 0) return '暂无记录';
      const value = new Date(at*1000);
      const today = new Date();
      const options = {timeZone:'Asia/Shanghai'};
      const sameDay = value.toLocaleDateString('en-CA',options) === today.toLocaleDateString('en-CA',options);
      return value.toLocaleString('zh-CN',{...options,...(sameDay?{}:{month:'numeric',day:'numeric'}),hour:'2-digit',minute:'2-digit',hour12:false});
    };
    const stateText = {healthy:'正常',unhealthy:'异常',unknown:'待更新',not_used:'未使用'};
    const icon = kind => h('svg',{width:18,height:18,viewBox:'0 0 24 24',fill:'none',stroke:'currentColor',strokeWidth:1.7,strokeLinecap:'round',strokeLinejoin:'round','aria-hidden':true},
      kind==='back'?h('path',{d:'M19 12H5m6-6-6 6 6 6'}):kind==='refresh'?h('path',{d:'M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 2M18 18A8 8 0 0 1 5 16'}):
        [h('circle',{key:'circle',cx:12,cy:12,r:9}),h('path',{key:'lines',d:'M3 12h18M12 3c5 5 5 13 0 18-5-5-5-13 0-18'})]);

    function Overview({onBack}) {
      const [view,setView] = useState({data:null,error:false,loading:true});
      const refresh = useRef(()=>{});
      useEffect(()=>{
        let disposed=false, current=null, timer=null;
        const stop = () => {if(timer!==null)clearInterval(timer);timer=null;current?.abort();current=null;};
        const read = async () => {
          if(disposed || document.visibilityState==='hidden' || current)return;
          const controller=new AbortController();current=controller;
          const timeout=setTimeout(()=>controller.abort(),8000);
          setView(previous=>({...previous,loading:true}));
          try{
            const response=await fetch('/api/home-network/overview',{method:'GET',credentials:'same-origin',cache:'no-store',signal:controller.signal});
            if(!response.ok)throw Error('unavailable');
            const data=await response.json();
            if(!data || !valid(data.observed_at) || typeof data.node!=='object' || !data.node || !data.health)throw Error('invalid snapshot');
            if(!disposed && current===controller)setView({data,error:false,loading:false});
          }catch{
            if(!disposed && current===controller)setView(previous=>({...previous,error:true,loading:false}));
          }finally{
            clearTimeout(timeout);
            if(current===controller){current=null;if(!disposed)setView(previous=>({...previous,loading:false}));}
          }
        };
        const start=()=>{stop();if(document.visibilityState!=='hidden'){void read();timer=setInterval(()=>void read(),30000);}};
        refresh.current=read;start();document.addEventListener('visibilitychange',start);
        return()=>{disposed=true;stop();refresh.current=()=>{};document.removeEventListener('visibilitychange',start);};
      },[]);
      const data=view.data||{};
      const node=data.node||{}, health=data.health||{}, routing=data.routing||{}, activity=data.activity||{}, device=data.device||{}, subscription=data.subscription||{};
      const now=Date.now()/1000;
      const current=!view.error && isFresh(data.observed_at,now);
      const nodeState=node.kind==='direct'?'not_used':current&&isFresh(node.checked_at,now)&&['healthy','unhealthy'].includes(node.state)?node.state:'unknown';
      const nodeText=nodeState==='healthy'?'可用':nodeState==='unhealthy'?'检测异常':nodeState==='not_used'?'直连':'待更新';
      const name=node.kind==='direct'?'当前直连':node.kind==='blocked'?'代理连接被拒绝':node.name||'当前节点待更新';
      const checks=Array.isArray(health.checks)?health.checks:[{id:'domestic',label:'国内',state:'unknown'},{id:'proxy',label:'代理',state:'unknown'},{id:'dns',label:'DNS',state:'unknown'}];
      const interval=valid(subscription.interval_seconds)?subscription.interval_seconds:null;
      const cadence=interval===null?'订阅更新周期待确认':interval>=3600?'订阅每 '+Number((interval/3600).toFixed(1))+' 小时更新':interval>=60?'订阅每 '+Number((interval/60).toFixed(1))+' 分钟更新':'订阅每 '+interval+' 秒更新';
      const section=(key,label,children)=>h('section',{key,className:'nvo-card','aria-label':label},children);
      return h('div',{'data-network-overview':true},
        h('header',{className:'nvo-header'},
          h('button',{type:'button',className:'nvo-back',onClick:onBack,'aria-label':'返回聊天'},icon('back'),'返回'),
          h('h1',null,'网络概览'),
          h('button',{type:'button',disabled:view.loading,onClick:()=>refresh.current(),'aria-label':'刷新概览'},icon('refresh'),view.loading?'读取中':'刷新')),
        h('main',{className:'nvo-body'},
          view.error?h('div',{role:'alert',className:'nvo-alert'},view.data?'暂时无法更新概览，下面是上次读取的数据。':'暂时无法读取概览，请稍后刷新。'):null,
          section('node','当前代理节点',[
            h('div',{key:'label',className:'nvo-row'},h('span',{className:'nvo-label'},view.data&&!current?'上次记录的代理节点':'当前代理节点'),h('span',{className:'nvo-chip','data-state':nodeState},h('span',{className:'nvo-dot'}),nodeText)),
            h('h2',{key:'name',className:'nvo-node-name','data-overview-node-name':true},name),
            h('div',{key:'meta',className:'nvo-meta'},h('span',null,nodeState==='healthy'&&valid(node.delay_ms)?'健康探测 '+node.delay_ms+' ms':node.kind==='direct'?'不使用代理节点':'最近探测待确认'),h('span',null,valid(node.checked_at)?timeLabel(node.checked_at)+' 探测':'暂无探测时间')),
          ]),
          section('health','最近检测',[
            h('div',{key:'label',className:'nvo-row'},h('span',{className:'nvo-label'},'最近检测'),h('span',{className:'nvo-label'},valid(health.checked_at)?timeLabel(health.checked_at)+' 检查':'尚无检测结果')),
            h('div',{key:'checks',className:'nvo-checks'},checks.map(check=>{
              const state=check.state==='not_used'?'not_used':current&&isFresh(health.checked_at,now)&&['healthy','unhealthy'].includes(check.state)?check.state:'unknown';
              return h('div',{key:check.id,className:'nvo-check','data-overview-check':check.id,'data-state':state},h('span',null,check.label),h('span',{className:'nvo-check-value'},h('span',{className:'nvo-dot'}),stateText[state]));
            })),
          ]),
          section('routing','分流方式',[
            h('div',{key:'label',className:'nvo-label'},'分流方式'),
            h('p',{key:'summary',className:'nvo-summary'},routing.summary||'分流状态待更新'),
            h('p',{key:'detail',className:'nvo-sub'},routing.detail||'暂时无法读取实际运行规则。'),
          ]),
          section('activity','最近处理',[
            h('div',{key:'label',className:'nvo-label'},'最近处理'),
            h('div',{key:'event',className:'nvo-event'},h('time',null,timeLabel(activity.at)),h('p',null,activity.summary||'暂无自动处理记录。')),
            h('p',{key:'subscription',className:'nvo-sub'},cadence+(valid(subscription.updated_at)?' · '+timeLabel(subscription.updated_at)+' 更新':'')),
          ]),
          h('footer',{className:'nvo-device'},valid(device.temperature_celsius)?h('span',null,'树莓派 '+Number(device.temperature_celsius.toFixed(1))+'℃'):null,
            valid(device.free_disk_bytes)?h('span',null,'可用空间 '+Number((device.free_disk_bytes/1024**3).toFixed(1))+' GB'):null)));
    }

    function apply(ctx){
      ctx.effect(()=>{const style=document.createElement('style');style.textContent=styles;document.head.appendChild(style);return()=>style.remove();});
      ctx.effect(()=>ctx.locale.register(NS,{zh:{title:'网络概览'},en:{title:'Network overview'}}));
      const t=ctx.locale.bind(NS);
      ctx.slots.inject('main',()=>ctx.slots.register({name:'main',key:PANEL,locale:NS,inject:()=>({onBack:()=>ctx.layout.selectPanel(null)})},Overview));
      ctx.slots.inject('sidebar.panellist',()=>ctx.slots.register({name:'sidebar.panellist',id:PANEL,order:11,locale:NS,label:()=>t('title')},()=>icon('network')));
    }
    return {apply,inject:['slots','locale','layout']};
  },
});
