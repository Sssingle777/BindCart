import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { chromium } from 'playwright-core';

// Explicit UI-only HTTP/SSE fixture. This never loads a running application's
// runtime metadata, starts its backend, executes cryptography or calls payment.
const appRoot = fileURLToPath(new URL('../', import.meta.url));
const output = fileURLToPath(new URL('../../evidence/store-observer-regression.json', import.meta.url));
const fixtureKey = 'f'.repeat(43), streams = new Set(), requests = [], pageErrors = [], externalRequests = [], snapshots = [];
const began = performance.now();
const report = { startedAt: new Date().toISOString(), scope: 'isolated storefront observer reconciliation; mocked HTTP and SSE only', actualPayments: 0, cryptographicVerification: false, checks: [] };
const product = { id: 'headphones', name: 'Headphones', title: '测试耳机', description: '明确的界面回归测试商品', image: '/store/images/headphones.png', unitAmountMinor: 50000000, currency: 'TEST_USDC' };
const state = (revision, quantity, message, busy = false) => ({ revision, phase: 'cart', busy, cart: quantity ? [{ ...product, quantity, amountMinor: product.unitAmountMinor * quantity }] : [], totalMinor: product.unitAmountMinor * quantity, currency: 'TEST_USDC', order: null, receipt: null, verification: null, error: null, backend: { ledger: { accounts: [{ id: 'demo:alice', balanceMinor: 1000000000 }] } }, message });
let authoritative = state(0, 0, 'fixture：初始空购物车'), reads = 0, nextReads = [], heldCart = null, browser, page, baseUrl, seq = 0, deadline;
let streamReady;
const connected = new Promise(resolveReady => { streamReady = resolveReady; });
let cartReady;
const cartReceived = new Promise(resolveReady => { cartReady = resolveReady; });
const assets = new Map([
  ['/store/', ['store/index.html', 'text/html']], ['/store/app.js', ['store/app.js', 'text/javascript']],
  ['/live-feed.js', ['live-feed.js', 'text/javascript']], ['/store/adyen-application.css', ['store/adyen-application.css', 'text/css']],
  ['/store/integration.css', ['store/integration.css', 'text/css']],
  ...['mystore-logo.svg', 'headphones.png', 'sunglasses.png', 'success.svg', 'thank-you.svg'].map(name => [`/store/images/${name}`, [`store/images/${name}`, name.endsWith('.svg') ? 'image/svg+xml' : 'image/png']]),
]);
function json(res, status, value) { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); }
function sendSnapshot(store) {
  const snapshot = { instanceId: 'explicit-regression-fixture', sequence: ++seq, store };
  snapshots.push({ sequence: seq, revision: store.revision, busy: store.busy });
  for (const stream of streams) stream.write(`event: snapshot\ndata: ${JSON.stringify(snapshot)}\n\n`);
}
const server = http.createServer(async (req, res) => {
  try {
    const path = new URL(req.url, baseUrl || 'http://127.0.0.1').pathname;
    requests.push({ method: req.method, path, authenticated: req.headers['x-demo-ui-key'] === fixtureKey });
    if (assets.has(path) && req.method === 'GET') {
      const [file, type] = assets.get(path); res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-store' });
      return res.end(await readFile(resolve(appRoot, 'public', file)));
    }
    if (!path.startsWith('/api/')) { res.writeHead(404); return res.end(); }
    if (req.headers['x-demo-ui-key'] !== fixtureKey) return json(res, 401, { error: { message: 'fixture access key required' } });
    if (path === '/api/store/state' && req.method === 'GET') { reads++; return json(res, 200, nextReads.length ? nextReads.shift() : authoritative); }
    if (path === '/api/store/catalog' && req.method === 'GET') return json(res, 200, { products: [product] });
    if (path === '/api/live/events' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
      res.flushHeaders(); res.write(': explicit isolated fixture\n\n'); streams.add(res); res.once('close', () => streams.delete(res)); streamReady(); return;
    }
    if (path === '/api/store/cart' && req.method === 'POST') {
      let raw = ''; for await (const chunk of req) raw += chunk;
      const body = JSON.parse(raw); assert.deepEqual(body, { productId: 'headphones', quantity: 1, revision: 0 });
      assert.equal(heldCart, null, 'only one simulated cart request is allowed'); heldCart = res; cartReady(); return;
    }
    return json(res, 405, { error: { message: 'fixture does not implement checkout, Owner approval or payment' } });
  } catch (error) { json(res, 500, { error: { message: error.message } }); }
});
const pass = (name, evidence = {}) => report.checks.push({ name, passed: true, ...evidence });
const waitIdle = () => page.waitForFunction(() => !document.body.classList.contains('busy') && !document.querySelector('#checkout').disabled);

async function run() {
  await new Promise(resolveReady => server.listen(0, '127.0.0.1', resolveReady));
  const port = server.address().port; assert.notEqual(port, 4382, 'fixture must never use the real app port'); baseUrl = `http://127.0.0.1:${port}`;
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext({ viewport: { width: 900, height: 900 }, locale: 'zh-CN' });
  await context.route('**/*', route => { if (new URL(route.request().url()).origin !== baseUrl) { externalRequests.push(new URL(route.request().url()).origin); return route.abort(); } return route.continue(); });
  page = await context.newPage(); page.setDefaultTimeout(2500);
  page.on('pageerror', error => pageErrors.push(error.message));
  await page.goto(`${baseUrl}/store/#key=${fixtureKey}`); await connected;
  await page.locator('[data-add="headphones"]').waitFor();
  await page.locator('[data-add="headphones"]').click(); await cartReceived;
  await page.waitForFunction(() => document.body.classList.contains('busy'));
  const readsBeforeOperation = reads;
  sendSnapshot(state(1, 1, 'fixture：购物车处理中', true));
  await page.waitForTimeout(40);
  // The real observer receives this final update while local run() is busy.
  // No further snapshot is sent; reconciliation must read authoritative state.
  authoritative = state(2, 2, '软件 eSIM 已锁定，再次结算会被拒绝。');
  sendSnapshot(authoritative); await page.waitForTimeout(60);
  json(heldCart, 200, state(1, 1, 'fixture：普通购物车响应')); heldCart = null;
  await page.waitForFunction(() => document.querySelector('#cart-count').textContent === '2' && document.querySelector('#feedback').textContent.includes('已锁定'));
  await waitIdle(); assert(reads > readsBeforeOperation, 'an authenticated reconciliation read must occur');
  pass('updates observed during a local cart request reconcile after its normal response', { latestCartQuantity: 2, latestMessage: '已锁定', checkoutEnabled: true, authoritativeRead: true });

  await page.evaluate(() => {
    window.__cartCountsAfterReconcile = [];
    new MutationObserver(() => window.__cartCountsAfterReconcile.push(document.querySelector('#cart-count').textContent)).observe(document.querySelector('#cart-count'), { childList: true, subtree: true, characterData: true });
  });
  // A stale busy=true update arrives after the final state. The final idle
  // snapshot is absent, so this must recover through the authenticated GET.
  const readsBeforeRemote = reads;
  authoritative = state(2, 2, '软件 eSIM 已解锁，可以继续结算。');
  sendSnapshot(state(2, 2, 'fixture：迟到的设备操作处理中', true));
  await page.waitForFunction(() => document.body.classList.contains('busy') && document.querySelector('#checkout').disabled);
  await page.waitForFunction(() => document.querySelector('#feedback').textContent.includes('已解锁'));
  await waitIdle(); assert(reads > readsBeforeRemote);
  pass('a delayed remote busy snapshot recovers when its final SSE update is missing', { checkoutEnabled: true, latestMessage: '已解锁', authoritativeRead: true });

  // Higher event sequence deliberately carries an older cart revision: the
  // revision guard must reject it independently of the event sequence guard.
  sendSnapshot(state(1, 1, 'fixture：过期 SSE 不应覆盖较新的购物车'));
  await page.waitForTimeout(100);
  assert.equal(await page.locator('#cart-count').innerText(), '2'); assert((await page.locator('#feedback').innerText()).includes('已解锁'));
  pass('a newer SSE sequence cannot overwrite the cart with a lower revision');

  const readsBeforeStaleRead = reads;
  nextReads = [state(1, 1, 'fixture：过期 GET 不应覆盖较新的购物车'), authoritative];
  sendSnapshot(state(2, 2, 'fixture：等待状态核对', true));
  await page.waitForFunction(() => document.body.classList.contains('busy'));
  await page.waitForFunction(() => document.querySelector('#feedback').textContent.includes('已解锁'));
  await waitIdle(); assert(reads >= readsBeforeStaleRead + 2);
  const observedCounts = await page.evaluate(() => window.__cartCountsAfterReconcile);
  assert(observedCounts.every(value => value === '2'), `the cart must never regress: ${JSON.stringify(observedCounts)}`);
  pass('a lower-revision authenticated read is ignored and retried while remote busy remains', { stateReads: reads - readsBeforeStaleRead, cartNeverRegressed: true });
  assert.deepEqual(pageErrors, []); assert.deepEqual(externalRequests, []);
  const posts = requests.filter(request => request.method === 'POST');
  assert.deepEqual(posts.map(request => request.path), ['/api/store/cart']);
  assert(requests.filter(request => request.path.startsWith('/api/')).every(request => request.authenticated));
  pass('the isolated check uses one mocked cart mutation and no checkout, authorization or payment', { apiRequestsAuthenticated: true, scriptErrors: 0, externalRequests: 0 });
}

try {
  await Promise.race([run(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('isolated regression exceeded its 16 second deadline')), 16000); })]);
  report.status = 'passed';
} catch (error) { report.status = 'failed'; report.error = error.message; process.exitCode = 1; }
finally {
  clearTimeout(deadline);
  if (heldCart && !heldCart.destroyed) heldCart.destroy();
  for (const stream of streams) stream.end();
  await browser?.close().catch(() => {});
  server.closeAllConnections(); await new Promise(resolveClosed => server.close(resolveClosed));
  report.durationMs = Math.round(performance.now() - began); report.finishedAt = new Date().toISOString(); report.snapshots = snapshots; report.pageErrors = pageErrors;
  report.apiRequestCounts = Object.fromEntries([...new Set(requests.filter(request => request.path.startsWith('/api/')).map(request => `${request.method} ${request.path}`))].map(name => [name, requests.filter(request => `${request.method} ${request.path}` === name).length]));
  await mkdir(resolve(output, '..'), { recursive: true }); await writeFile(output, JSON.stringify(report, null, 2));
  console.log(JSON.stringify({ status: report.status, checks: report.checks.length, durationMs: report.durationMs, report: output, ...(report.error ? { error: report.error } : {}) }));
}
