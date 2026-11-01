import assert from 'node:assert/strict';
import { chromium, webkit } from 'playwright';
import { installInspectionRecords } from '../../src/dsh/mobile-layout.mjs';
const env=Object.fromEntries(Object.entries(process.env).filter(([k])=>!k.toLowerCase().endsWith('_proxy')));
const processRow=(turn,tools=0)=>`<div data-chat-flow-kind="turn-process" data-chat-turn="${turn}"><button data-turn-process="${turn}" data-turn-process-messages="0" data-turn-process-tool-calls="${tools}" data-turn-process-subagents="0">执行状态</button></div>`;
for(const [name,type] of Object.entries({chromium,webkit})){
  const browser=await type.launch({headless:true,env});const page=await browser.newPage();
  await page.route('**/api/home-network/inspection?*',route=>route.fulfill({json:{managed:true,checked_at:Date.now()/1000,checks:[{label:'国内 DNS',ok:true},{label:'代理连通',ok:true}],last_gate:{admitted:false,reason:'minimum audit spacing'},next_at:'2026-11-02T08:00:00Z',enabled:true}}));
  await page.route('http://gateway.invalid/',route=>route.fulfill({contentType:'text/html',body:'<!doctype html><html><head></head><body></body></html>'}));
  await page.goto('http://gateway.invalid/');
  await page.setContent(`<section data-conversation-session="session-11111111-1111-1111-1111-111111111111"><div id="flow">${processRow(1)}<div data-chat-flow-kind="turn-tail" data-chat-turn="1"><div></div></div><div data-chat-flow-kind="user" data-chat-turn="2">用户求助</div>${processRow(2)}${processRow(3,1)}<div data-chat-flow-kind="assistant-step" data-chat-turn="4">实际回复</div>${processRow(4)}</div></section>`);
  assert(await page.locator('[data-turn-process="1"]').isVisible());
  await page.evaluate(`void(window.cleanup=(${installInspectionRecords.toString()})())`);await page.waitForTimeout(100);
  assert.equal(await page.locator('[data-turn-process="1"]').isVisible(),false);
  for(const turn of [2,3,4])assert(await page.locator(`[data-turn-process="${turn}"]`).isVisible());
  assert(await page.getByText('实际回复',{exact:true}).isVisible());
  assert.equal(await page.locator('[data-home-network-record]').count(),1);
  await page.waitForFunction(()=>document.querySelector('[data-home-network-record]')?.textContent.includes('国内 DNS'));
  const record=await page.locator('[data-home-network-record]').innerText();assert(record.includes('本次不重复调用模型'));assert(record.includes('下次任务计划'));
  await page.evaluate(()=>{
    const row=document.createElement('div');row.dataset.chatFlowKind='assistant-step';row.dataset.chatTurn='1';row.textContent='迟到的真实回复';document.getElementById('flow').appendChild(row);
  });await page.waitForTimeout(100);assert(await page.locator('[data-turn-process="1"]').isVisible());
  await page.evaluate(()=>window.cleanup());assert.equal(await page.locator('[data-home-gateway-empty-turn]').count(),0);
  console.log(name,'program record explains checks, AI deferral and next plan; actual chat and tools preserved');await browser.close();
}
