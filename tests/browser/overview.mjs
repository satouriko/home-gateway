import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, resolve, join } from 'node:path';
import { tmpdir } from 'node:os';
import { chromium, webkit } from 'playwright';

const here=dirname(fileURLToPath(import.meta.url));
const client=resolve(here,'../../src/dsh/network-overview/client.js');
assert(await access(client).then(()=>true,()=>false),'the actual overview client must exist');
const resources={
  '/client.js':await readFile(client),
  '/react.js':await readFile(join(here,'node_modules/react/umd/react.development.js')),
  '/react-dom.js':await readFile(join(here,'node_modules/react-dom/umd/react-dom.development.js')),
};
const html=`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body,#app,#mobile-shell{margin:0;width:100%;height:100%;font-family:system-ui}*{box-sizing:border-box}#mobile-shell{position:relative}#native-navigation{position:absolute;left:10px;top:10px;width:40px;height:40px;z-index:5}@media(min-width:1024px){#native-navigation{display:none}}</style><div id="mobile-shell"><button id="native-navigation" data-mobile-nav="fab" aria-label="返回会话">‹</button><div id="app"></div></div><script src="/react.js"></script><script src="/react-dom.js"></script><script>
if(innerWidth<1024)document.getElementById('mobile-shell').dataset.mobileNav='frame';
window.__ModuleLoader__={load({factory}){window.overviewPlugin=factory(name=>{if(name==='react')return React;throw Error(name);});}};
const root=ReactDOM.createRoot(document.getElementById('app'));
window.start=()=>{const ctx={effect:fn=>fn(),locale:{register(){return()=>{};},bind:()=>key=>key},layout:{selectPanel(){root.unmount();document.getElementById('app').textContent='原聊天页面';}},slots:{inject:(_name,fn)=>fn(),register(options,Component){if(options.name==='main'){window.Component=Component;window.componentProps=options.inject?.()||{};}return()=>{};}}};overviewPlugin.apply(ctx);document.getElementById('native-navigation').onclick=()=>ctx.layout.selectPanel(null);root.render(React.createElement(window.Component,window.componentProps));};
</script><script src="/client.js"></script><script>start();</script>`;
const server=createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/'?'text/html; charset=utf-8':'text/javascript; charset=utf-8');res.end(req.url==='/'?html:resources[req.url]||'');});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const url='http://127.0.0.1:'+server.address().port;
const env=Object.fromEntries(Object.entries(process.env).filter(([k])=>!k.toLowerCase().endsWith('_proxy')));
const fixture=()=>{
  const now=Date.now()/1000;
  return {observed_at:now,node:{name:'California (美国) G03',kind:'proxy',state:'healthy',checked_at:now-20,delay_ms:168},
    routing:{mode:'rule',consistent:true,summary:'中国大陆直连，其余走代理',detail:'美国节点均不可用时，才启用其他地区。'},
    health:{checked_at:now-30,state:'healthy',checks:[{id:'domestic',label:'国内',state:'healthy'},{id:'proxy',label:'代理',state:'healthy'},{id:'dns',label:'DNS',state:'healthy'}]},
    activity:{at:now-60,state:'completed',summary:'节点订阅已更新。'},subscription:{updated_at:now-60,interval_seconds:21600},device:{temperature_celsius:46,free_disk_bytes:18*1024**3}};
};
try{
for(const [name,type] of Object.entries({chromium,webkit})){
  const browser=await type.launch({headless:true,env});
  for(const width of [320,375,390,430,1280]){
    const page=await browser.newPage({viewport:{width,height:900}});const errors=[];let data=fixture(),calls=0,fail=false;
    page.on('pageerror',e=>errors.push(e.message));
    await page.addInitScript(()=>{
      const intervals=new Map();let serial=-1;const clear=window.clearInterval;
      window.setInterval=(fn,ms)=>{if(ms!==30000)throw Error('unexpected polling cadence');const id=serial--;intervals.set(id,fn);return id;};
      window.clearInterval=id=>{if(id<0)intervals.delete(id);else clear(id);};
      window.tickOverview=()=>{for(const fn of intervals.values())fn();};
      window.overviewIntervals=()=>intervals.size;
      Object.defineProperty(document,'visibilityState',{configurable:true,get:()=>window.hiddenForTest?'hidden':'visible'});
    });
    await page.route('**/api/home-network/overview',route=>{
      assert.equal(route.request().method(),'GET');calls++;
      return route.fulfill({status:fail?503:200,json:fail?{error:'overview_unavailable'}:data});
    });
    await page.goto(url);await page.getByRole('heading',{name:data.node.name,exact:true}).waitFor();
    if(width<1024){
      assert.equal(await page.getByRole('button',{name:'返回聊天',exact:true}).isVisible(),false,'reuse the native mobile back action');
      const separate=await page.evaluate(()=>{const a=document.getElementById('native-navigation').getBoundingClientRect(),b=document.querySelector('[data-network-overview] h1').getBoundingClientRect();return a.right<=b.left||b.right<=a.left||a.bottom<=b.top||b.bottom<=a.top;});
      assert(separate,'overview navigation must leave room for native mobile navigation');
    }
    assert.equal(await page.locator('table').count(),0);
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'no whole-page overflow');
    const longName='California (美国) G03 — '+('West coast ').repeat(17);data.node.name=longName;
    await page.getByRole('button',{name:'刷新概览',exact:true}).click();await page.getByRole('heading',{name:longName,exact:true}).waitFor();
    assert(await page.locator('[data-overview-node-name]').evaluate(e=>e.scrollWidth<=e.clientWidth+1),'full long name wraps');
    data.health.checked_at=Date.now()/1000-700;
    await page.getByRole('button',{name:'刷新概览',exact:true}).click();await page.waitForFunction(()=>[...document.querySelectorAll('[data-overview-check]')].every(e=>e.dataset.state==='unknown'));
    data=fixture();await page.getByRole('button',{name:'刷新概览',exact:true}).click();await page.waitForFunction(()=>document.querySelector('[data-overview-check]')?.dataset.state==='healthy');
    fail=true;await page.getByRole('button',{name:'刷新概览',exact:true}).click();await page.getByRole('alert').waitFor();
    assert.equal(await page.locator('[data-overview-check][data-state="healthy"]').count(),0);
    assert(await page.getByText('上次记录的代理节点',{exact:true}).isVisible());
    fail=false;
    await page.evaluate(()=>{window.hiddenForTest=true;document.dispatchEvent(new Event('visibilitychange'));});
    const hiddenCalls=calls;await page.evaluate(()=>window.tickOverview());await page.waitForTimeout(60);assert.equal(calls,hiddenCalls);
    assert.equal(await page.evaluate(()=>window.overviewIntervals()),0);
    await page.evaluate(()=>{window.hiddenForTest=false;document.dispatchEvent(new Event('visibilitychange'));});
    await page.waitForFunction(()=>!document.querySelector('[role="alert"]'));
    assert.equal(await page.evaluate(()=>window.overviewIntervals()),1);
    const before=calls;await page.evaluate(()=>{for(let i=0;i<5;i++)window.tickOverview();});
    await page.waitForTimeout(100);assert.equal(calls,before+1,'in-flight reads coalesce');
    if(width===390)await page.screenshot({path:join(tmpdir(),`home-gateway-overview-${name}.png`)});
    await page.getByRole('button',{name:width<1024?'返回会话':'返回聊天',exact:true}).click();await page.getByText('原聊天页面',{exact:true}).waitFor();
    const leftCalls=calls;await page.evaluate(()=>window.tickOverview());await page.waitForTimeout(60);assert.equal(calls,leftCalls);assert.equal(await page.evaluate(()=>window.overviewIntervals()),0);
    assert.deepEqual(errors,[]);await page.close();console.log(name,width,'exact node, long name, stale/offline states and polling lifecycle OK');
  }
  await browser.close();
}
}finally{await new Promise(r=>server.close(r));}
