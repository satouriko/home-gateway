import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const evidence = process.env.BROWSER_ARTIFACTS ?? resolve(tmpdir(), 'home-gateway-schedule-browser');
const bundlePath = process.env.SCHEDULE_UI_BUNDLE ?? resolve(here, '../../../runtime/dsh/node_modules/@deepseek-ai/dsh-client-ui-schedule/lib/client.js');
const bundle = (await readFile(bundlePath, 'utf8')).replace('return module.exports;', 'module.exports.__fixture = { DeliveryHistory, TaskDetail, TaskManagerPage, ScheduleCatalogAction, en, zh, catalogEn: en$1, catalogZh: zh$1 }; return module.exports;');
const files = {
  '/react.js': await readFile(resolve(here, 'node_modules/react/umd/react.development.js')),
  '/react-dom.js': await readFile(resolve(here, 'node_modules/react-dom/umd/react-dom.development.js')),
  '/fixture.js': await readFile(resolve(here, 'fixture.js')),
  '/bundle.js': bundle,
};
const server = createServer((req, res) => {
  res.setHeader('Content-Type', req.url === '/' ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8');
  res.end(req.url === '/' ? '<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><style>html,body,#app{height:100%;margin:0}*{box-sizing:border-box}:root{--dsw-alias-label-primary:#222;--dsw-alias-label-secondary:#444;--dsw-alias-label-tertiary:#555;--dsw-alias-bg-base:white;--dsw-alias-border-l3:#ddd}</style><div id="app"></div><script src="/react.js"></script><script src="/react-dom.js"></script><script src="/fixture.js"></script><script src="/bundle.js"></script>' : files[req.url] ?? '');
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const browser = await chromium.launch({ headless: true });
let count = 0;
const results = [];
const timestamp = '2026-11-01T00:00:00Z';
const receipt = (status, id, extras = {}) => ({ kind: 'execution', executionId: id, scheduledAt: timestamp, deliveredAt: timestamp, status, ...extras });
const legacy = { messageId: 'old-message', scheduledAt: timestamp, deliveredAt: timestamp, prompt: 'Original reminder text' };
async function test(name, body) {
  const page = await browser.newPage({ viewport: { width: 1100, height: 820 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  try {
    await page.goto(`http://127.0.0.1:${server.address().port}/`);
    await body(page);
    assert.deepEqual(errors, [], 'browser runtime errors');
    results.push({ name, status: 'passed' });
    console.log(`PASS ${++count}: ${name}`);
  } finally { await page.close(); }
}
try {
  await test('mixed native history shows every truthful execution state and only independent-session navigation', async (page) => {
    await page.evaluate(({ receipts, legacy }) => mountHistory({ records: [...receipts, legacy] }), { receipts: ['pending', 'started', 'completed', 'skipped', 'failed', 'interrupted', 'expired'].map((status, index) => receipt(status, `run-${index}`, { summary: `Summary ${status}`, ...(status === 'completed' ? { executionSessionId: 'run-session' } : {}) })), legacy });
    await page.getByText('Summary expired', { exact: true }).waitFor();
    assert.equal(await page.locator('section').count(), 8);
    for (const state of ['Waiting for executor', 'Started', 'Completed', 'Skipped — no AI run', 'Failed', 'Interrupted', 'Expired']) assert.equal(await page.getByText(state, { exact: true }).count(), 1, state + ' in ' + await page.locator('#app').innerText());
    assert.equal(await page.getByText(legacy.prompt, { exact: true }).count(), 1);
    assert.equal(await page.getByRole('button', { name: 'Open execution session' }).count(), 1);
    await page.getByRole('button', { name: 'Open execution session' }).click();
    assert.deepEqual(await page.evaluate(() => fixture.opened), ['run-session']);
    assert.equal(await page.getByText('origin-session', { exact: true }).count(), 0);
  });
  await test('mixed pagination deduplicates by executionId and sends the independent receipt cursor', async (page) => {
    await page.evaluate(({ first, more }) => mountHistory({ records: first, more, nextBefore: 'run-b', nextBeforeDeliveryId: 'run-b' }), { first: [receipt('completed', 'run-a', { summary: 'First' }), receipt('skipped', 'run-b', { summary: 'Second' })], more: [receipt('skipped', 'run-b', { summary: 'Second' }), receipt('failed', 'run-c', { summary: 'Third' }), legacy] });
    await page.getByRole('button', { name: 'Load more', exact: true }).click();
    await page.getByText('Third', { exact: true }).waitFor();
    assert.equal(await page.locator('section').count(), 4);
    assert.deepEqual(await page.evaluate(() => fixture.requests[1]), { id: 'stable-task', sessionId: 'origin-session', limit: 20, beforeDeliveryId: 'run-b' });
  });
  await test('legacy message cursor pagination remains compatible', async (page) => {
    await page.evaluate(({ legacy }) => mountHistory({ records: [legacy], nextBefore: legacy.messageId, more: [{ ...legacy, messageId: 'older-message', prompt: 'Earlier reminder' }] }), { legacy });
    await page.getByRole('button', { name: 'Load more', exact: true }).click();
    await page.getByText('Earlier reminder', { exact: true }).waitFor();
    assert.equal(await page.locator('section').count(), 2);
    assert.equal(await page.evaluate(() => fixture.requests[1].beforeDeliveryId), 'old-message');
  });
  await test('same execution identity refreshes when started becomes completed', async (page) => {
    const started = receipt('started', 'stable-run', { summary: 'Work started' });
    const completed = { ...started, status: 'completed', summary: 'Actual completion', executionSessionId: 'run-session' };
    await page.evaluate((record) => { fixture.task.lastDelivery = record; fixture.stableLoad = async (request) => { fixture.requests.push(request); return { ok: true, value: { records: [fixture.task.lastDelivery], retention: { days: 30, records: 200 } } }; }; mountDetail({ tab: 'records', task: { ...fixture.task }, loadHistory: fixture.stableLoad }); }, started);
    await page.getByText('Work started', { exact: true }).waitFor();
    const previous = await page.evaluate(() => fixture.requests.length);
    await page.evaluate((record) => { fixture.task.lastDelivery = record; mountDetail({ tab: 'records', task: { ...fixture.task }, loadHistory: fixture.stableLoad }); }, completed);
    await page.getByText('Actual completion', { exact: true }).waitFor();
    assert.ok(await page.evaluate(() => fixture.requests.length) > previous);
    assert.equal(await page.getByText('Started', { exact: true }).count(), 0);
    await page.getByRole('button', { name: 'Open execution session' }).click();
    assert.deepEqual(await page.evaluate(() => fixture.opened), ['run-session']);
  });
  await test('catalog revision refreshes an older receipt when a newer lastDelivery is unchanged', async (page) => {
    const older = receipt('started', 'older-run', { summary: 'Older run started' });
    const newer = receipt('skipped', 'newer-run', { summary: 'Newer occurrence skipped' });
    await page.evaluate(({ older, newer }) => {
      fixture.task.lastDelivery = newer;
      fixture.historyRecords = [newer, older]; fixture.revision = 1;
      fixture.loadHistory = async (request) => { fixture.requests.push(request); return { ok: true, value: { records: fixture.historyRecords, retention: { days: 30, records: 200 } } }; };
      mountCatalog();
    }, { older, newer });
    await page.getByRole('button', { name: 'House task', exact: true }).click();
    await page.getByRole('tab', { name: 'Records', exact: true }).click();
    await page.getByText('Older run started', { exact: true }).waitFor();
    await page.evaluate(() => {
      fixture.historyRecords[1] = { ...fixture.historyRecords[1], status: 'completed', summary: 'Older run actually completed', executionSessionId: 'run-session' };
      fixture.revision = 2; mountCatalog();
    });
    await page.getByText('Older run actually completed', { exact: true }).waitFor();
    assert.equal(await page.getByText('Newer occurrence skipped', { exact: true }).count(), 1);
    assert.equal(await page.getByText('Older run started', { exact: true }).count(), 0);
  });
  await test('native task/catalog labels and content/timing edits retain execution metadata and stable task ID', async (page) => {
    await page.evaluate(() => mountCatalog());
    await page.getByRole('button', { name: 'House task', exact: true }).waitFor();
    assert.equal(await page.getByText('Independent execution', { exact: true }).count(), 1);
    await page.getByRole('button', { name: 'House task', exact: true }).click();
    await page.getByRole('textbox', { name: 'Automation task name', exact: true }).fill('Renamed house task');
    await page.getByRole('spinbutton', { name: 'Repeat every', exact: true }).fill('2');
    await page.getByRole('button', { name: 'Save changes', exact: true }).click();
    await page.waitForFunction(() => fixture.updates.length === 1);
    const update = await page.evaluate(() => fixture.updates[0]);
    assert.equal(update.id, 'stable-task');
    assert.equal(update.sessionId, 'origin-session');
    assert.equal(update.title, 'Renamed house task');
    assert.equal(update.change.every_seconds, 7200);
    assert.deepEqual(update.expected.execution, { kind: 'external', executor: 'home-network' });
    assert.deepEqual(await page.evaluate(() => fixture.task.execution), { kind: 'external', executor: 'home-network' });
    await page.evaluate(() => mountDetail({ confirmId: 'stable-task' }));
    await page.getByRole('button', { name: 'Confirm deletion', exact: true }).click();
    assert.deepEqual(await page.evaluate(() => fixture.deletes), ['stable-task']);
  });
  await test('session reminder catalog marks only independent task rows', async (page) => {
    await page.evaluate(() => mountSessionCatalog());
    await page.getByRole('button', { name: '2 reminders', exact: true }).click();
    await page.getByRole('list', { name: 'Active reminders' }).waitFor();
    assert.equal(await page.getByText('Independent execution', { exact: true }).count(), 1);
  });
  await test('mobile Chinese history fits and keeps summaries and execution actions readable', async (page) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.evaluate((records) => mountHistory({ records, locale: 'zh' }), [receipt('started', 'mobile-a', { summary: '正在执行独立会话' }), receipt('skipped', 'mobile-b', { summary: '程序探测已跳过，没有调用 AI。'.repeat(15) }), receipt('completed', 'mobile-c', { summary: '执行结果已保存', executionSessionId: 'run-session' })]);
    await page.getByText('执行结果已保存', { exact: true }).waitFor();
    assert.equal(await page.getByText('已跳过，未运行 AI', { exact: true }).count(), 1);
    assert.equal(await page.getByRole('button', { name: '打开执行会话', exact: true }).count(), 1);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await mkdir(evidence, { recursive: true });
    await page.screenshot({ path: resolve(evidence, 'mobile-history.png'), fullPage: true });
  });
  await mkdir(evidence, { recursive: true });
  await import('node:fs/promises').then(({ writeFile }) => writeFile(resolve(evidence, 'results.json'), JSON.stringify({ bundle: 'patched/dsh-client-ui-schedule/lib/client.js', tests: results }, null, 2) + '\n'));
  console.log(`${count} browser fixtures passed`);
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
