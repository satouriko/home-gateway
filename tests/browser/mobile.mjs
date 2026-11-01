import { mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { chromium, webkit } from 'playwright';
const env=Object.fromEntries(Object.entries(process.env).filter(([k])=>!k.toLowerCase().endsWith('_proxy')));
const output=process.env.BROWSER_ARTIFACTS||join(tmpdir(),'home-gateway-browser');
await mkdir(output,{recursive:true});
const ua='Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1';
for(const [name,type] of Object.entries({chromium,webkit})) {
 const b=await type.launch({headless:true,env}); const errors=[];
 for(const width of [375,390,430,768]) {
  const p=await b.newPage({viewport:{width,height:844},isMobile:true,hasTouch:true,userAgent:ua});p.on('pageerror',e=>errors.push(e.message));
  await p.goto(process.env.MOBILE_URL||'http://127.0.0.1:5080');await p.waitForSelector('[data-mobile-nav="frame"]');await p.waitForTimeout(1000);
  const title=process.env.MOBILE_TEST_CONVERSATION;
  if(title){
    await p.getByRole('button',{name:'打开目录',exact:true}).click();
    const group=p.getByRole('treeitem').filter({hasText:'未分组'}).first();
    if(await group.count()&&await group.getAttribute('aria-expanded')==='false')await group.click();
    const workspace=p.getByRole('treeitem').first();
    if(await workspace.getAttribute('aria-expanded')==='false')await workspace.click();
    await p.getByText(title,{exact:true}).click();await p.waitForTimeout(600);
    const tabs=await p.getByRole('tab',{name:'对话',exact:true}).boundingBox();
    const more=await p.getByRole('button',{name:'更多会话视图',exact:true}).boundingBox();
    assert(Math.abs(tabs.y-more.y)<12,'view menu must share the tabs row');
    const editor=p.locator('[contenteditable="true"]').first();
    const box=await editor.boundingBox();assert(box.x>=0&&box.x+box.width<=width);
    const send=await p.getByRole('button',{name:'发送消息',exact:true}).boundingBox();
    assert(send.x>=0&&send.x+send.width<=width,'send button is visible');
    const bubbles=await p.locator('pre,[class*="_bubble"]').evaluateAll(es=>es.map(e=>{const r=e.getBoundingClientRect();return{x:r.x,right:r.right,width:r.width}}));
    assert(bubbles.every(r=>r.x>=0&&r.right<=width),'message/code surfaces fit screen');
  }
  const measure=()=>p.evaluate(()=>{const f=document.querySelector('[data-mobile-nav="frame"]'),r=f.children[1].getBoundingClientRect(),s=f.children[0].getBoundingClientRect();return{main:r.width,x:r.x,sidebarRight:s.right,overflow:document.documentElement.scrollWidth>innerWidth,scale:visualViewport.scale}});
  const closed=await measure();assert.equal(closed.main,width);assert(closed.sidebarRight<=0);assert(!closed.overflow);
  await p.getByRole('button',{name:'打开目录',exact:true}).click();await p.waitForTimeout(400);
  const open=await measure();assert.equal(open.main,width);assert.equal(open.x,0);assert(open.sidebarRight>200);
  if(width===390)await p.screenshot({path:join(output,`${name}-drawer.png`)});
  await p.mouse.click(width-10,220);await p.waitForTimeout(400);assert((await measure()).sidebarRight<=0);
  const editor=p.locator('[contenteditable="true"]').first();if(await editor.count()){await editor.focus();assert(parseFloat(await editor.evaluate(e=>getComputedStyle(e).fontSize))>=16);}
  if(name==='chromium'&&width===390){const cdp=await p.context().newCDPSession(p);await cdp.send('Input.synthesizePinchGesture',{x:200,y:600,scaleFactor:2,gestureSourceType:'touch'});assert.equal((await measure()).scale,1);}
  assert.equal((await measure()).scale,1);
  console.log(name,width,'full-width, drawer, backdrop, focus and scale OK');await p.close();
 }
 const p=await b.newPage({viewport:{width:1280,height:900}});await p.goto(process.env.MOBILE_URL||'http://127.0.0.1:5080');await p.locator('[data-slot="root"] > div').first().waitFor();
 assert.equal(await p.evaluate(()=>getComputedStyle(document.documentElement).touchAction),'auto');
 assert.notEqual(await p.locator('[data-slot="root"] > div').first().evaluate(e=>getComputedStyle(e.firstElementChild).position),'absolute');
 assert.deepEqual(errors,[]);console.log(name,'desktop OK; no page errors');await b.close();
}
