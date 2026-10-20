import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { chromium } from 'playwright-core';

const runtime = JSON.parse(await readFile(new URL('../var/dual-runtime.json', import.meta.url)));
const keys = new URLSearchParams(new URL(runtime.url).hash.slice(1));
const output = resolve('../evidence/dual-live'); await mkdir(output, { recursive: true });
const report = { startedAt: new Date().toISOString(), checks: [], pageErrors: [], externalRequests: [], requests: [], screenshots: [] };
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, locale: 'zh-CN' });
await context.route('**/*', route => { if (new URL(route.request().url()).origin !== runtime.baseUrl) { report.externalRequests.push(route.request().url()); return route.abort(); } return route.continue(); });
const page = await context.newPage(); page.setDefaultTimeout(90000);
page.on('pageerror', error => report.pageErrors.push(error.message));
page.on('request', request => { const path = new URL(request.url()).pathname; if (path.startsWith('/api/') || path.startsWith('/owner/')) report.requests.push({ path, method: request.method() }); });
let mall, mechanism, streamStopped = false;
const wireEvents = [], wireSnapshots = [], streamAbort = new AbortController();
const pass = (name, evidence = {}) => { report.checks.push({ name, passed: true, ...evidence }); writeFileSync(resolve(output, 'progress.json'), JSON.stringify({ ...report, status: 'running' }, null, 2)); console.log(`PASS ${name}`); };
const watchdog = setTimeout(() => { console.error('UI suite exceeded its 100s wall-clock limit.'); process.exitCode = 1; void browser.close(); setTimeout(() => process.exit(1), 5000).unref(); }, 100000);
watchdog.unref();
const balances = state => Object.fromEntries(state.backend.ledger.accounts.map(account => [account.id, account.balanceMinor]));
async function api(path, body, authenticated = true) {
  const response = await fetch(`${runtime.baseUrl}${path}`, { method: body === undefined ? 'GET' : 'POST', headers: { ...(authenticated ? { 'X-Demo-UI-Key': keys.get('key') } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(90000) });
  return { status: response.status, data: await response.json() };
}
async function frames() {
  await page.locator('#store-frame').waitFor();
  mall = await (await page.$('#store-frame')).contentFrame(); mechanism = await (await page.$('#mechanism-frame')).contentFrame();
  await mall.locator('[data-add="headphones"]').waitFor({ state: 'attached' });
  await mechanism.locator('#live-connection[data-state="connected"]').waitFor();
}
async function click(frame, selector, path, expected = 200) {
  console.log(`ACTION ${selector}`);
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === path && response.request().method() === 'POST', { timeout: 15000 });
  const action = (async () => { await frame.locator(selector).click({ noWaitAfter: true, timeout: 15000 }); return pending; })();
  let timer;
  const response = await Promise.race([action, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`UI action exceeded 20s: ${selector}`)), 20000); })]).finally(() => clearTimeout(timer));
  const receivedAt = performance.now();
  const data = await Promise.race([response.json(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`Response body exceeded 15s: ${selector}`)), 15000); })]).finally(() => clearTimeout(timer));
  assert.equal(response.status(), expected, JSON.stringify(data.error));
  await mall.waitForFunction(() => !document.body.classList.contains('busy'), undefined, { polling: 100, timeout: 15000 });
  return { data, receivedAt };
}
async function shot(name) {
  await page.waitForTimeout(350); const path = resolve(output, name); await page.screenshot({ path, fullPage: true }); report.screenshots.push(path);
}
let readyStream;
const streamReady = new Promise(resolve => { readyStream = resolve; });
const streamTask = (async () => {
  try {
    const response = await fetch(`${runtime.baseUrl}/api/live/events`, { headers: { 'X-Demo-UI-Key': keys.get('key') }, signal: streamAbort.signal });
    assert.equal(response.status, 200); readyStream();
    const reader = response.body.getReader(), decoder = new TextDecoder(); let buffer = '';
    while (!streamStopped) {
      const { value, done } = await reader.read(); if (done) break; buffer += decoder.decode(value, { stream: true });
      let boundary;
      while ((boundary = buffer.indexOf('\n\n')) !== -1) {
        const packet = buffer.slice(0, boundary); buffer = buffer.slice(boundary + 2);
        const type = packet.split('\n').find(line => line.startsWith('event:'))?.slice(6).trim();
        const text = packet.split('\n').find(line => line.startsWith('data:'))?.slice(5).trim(); if (!text) continue;
        const data = JSON.parse(text), item = { ...data, receivedAt: performance.now() };
        if (type === 'system') wireEvents.push(item); else if (type === 'snapshot') wireSnapshots.push(item);
      }
    }
  } catch (error) { if (!streamStopped) { report.streamError = error.message; readyStream(); } }
})();

try {
  await streamReady;
  for (const path of ['/api/live/state', '/api/live/events', '/api/live/orders/urn%3Auuid%3A00000000-0000-0000-0000-000000000000']) {
    const denied = await api(path, undefined, false); assert.equal(denied.status, 401); assert.equal(denied.data.state, undefined);
  }
  pass('live snapshot, stream and history require the local access capability');
  let initial = (await api('/api/store/state')).data;
  if (initial.phase !== 'cart' || initial.cart.length) { const reset = await api('/api/store/new', { revision: initial.revision }); assert.equal(reset.status, 200); }
  assert.equal((await api('/api/store/security', { action: 'unlock' })).status, 200);
  await page.goto(runtime.url); await frames();
  const originalStyle = await mall.evaluate(() => [...document.styleSheets].map(sheet => new URL(sheet.href).pathname));
  const mechanismStyle = await mechanism.evaluate(() => [...document.styleSheets].map(sheet => new URL(sheet.href).pathname));
  assert(originalStyle.includes('/store/adyen-application.css')); assert(mechanismStyle.includes('/tokens.css')); assert(!mechanismStyle.includes('/store/adyen-application.css'));
  assert.equal(await mall.locator('#details-dialog').count(), 0); assert.equal(await mechanism.locator('.scene-node').count(), 6);
  pass('shopping and original mechanism pages are simultaneously visible with independent styles');
  await shot('01-two-independent-apps.png');
  let cart = (await click(mall, '[data-add="headphones"]', '/api/store/cart')).data;
  cart = (await click(mall, '[data-add="sunglasses"]', '/api/store/cart')).data;
  assert.equal(cart.totalMinor, 100000000);
  await mechanism.waitForFunction(() => document.querySelector('#live-amount').textContent.includes('100'), undefined, { polling: 100, timeout: 15000 });
  await mall.locator('header [data-route="cart"]').click();
  await shot('02-cart-synchronizes.png');
  pass('cart and amount appear on the independent mechanism page without a refresh');

  const checkoutResult = await click(mall, '#checkout', '/api/store/checkout'); const checkout = checkoutResult.data;
  assert.equal(checkout.phase, 'checkout'); assert.equal(checkout.backend.proposal.status, 'PENDING');
  const orderId = checkout.order.orderId;
  await mechanism.waitForFunction(id => document.querySelector('#live-order').textContent === id, orderId, { polling: 100, timeout: 15000 });
  const proposalEvents = wireEvents.filter(event => event.orderId === orderId && event.type === 'protocol' && event.phase === 'proposal');
  assert(proposalEvents.some(event => event.action === 'device-sign' && event.status === 'start' && event.receivedAt < checkoutResult.receivedAt));
  assert(proposalEvents.some(event => event.action === 'verify' && event.status === 'complete'));
  const completes = proposalEvents.filter(event => event.status === 'complete').map(event => event.action);
  assert.deepEqual(completes, ['begin-proposal', 'derive-vc', 'device-sign', 'prove', 'verify', 'submit-owner']);
  const liveCheckout = (await api('/api/live/state')).data;
  assert.equal(liveCheckout.core.manual.stage, 'OWNER_SUBMITTED'); assert.equal(liveCheckout.core.manual.challenge.paymentOrderId, orderId);
  assert.equal(liveCheckout.core.manual.verificationResult.verificationTrace.outcome, 'pass');
  assert.equal(liveCheckout.core.authorization, null);
  await shot('03-qualified-awaiting-owner.png');
  pass('actual original protocol steps stream before checkout returns and only then open payment', { orderId, completedActions: completes, eventsBeforeResponse: proposalEvents.filter(event => event.receivedAt < checkoutResult.receivedAt).length });

  const payload = { orderId, revision: checkout.revision }, before = balances(checkout);
  const noOwner = await api('/api/store/pay', payload); assert.equal(noOwner.status, 403); assert.equal(noOwner.data.error.code, 'OWNER_CONFIRMATION_REQUIRED'); assert.deepEqual(balances(noOwner.data.state), before);
  const wrongOrder = await api('/api/store/pay', { ...payload, orderId: 'urn:uuid:00000000-0000-0000-0000-000000000000' }); assert.equal(wrongOrder.status, 409);
  pass('missing Owner approval and substituted order cannot reach wallet payment');
  const paid = (await click(mall, '#confirm-pay', '/api/store/pay')).data;
  assert.equal(paid.phase, 'paid'); assert.equal(paid.receipt.transactionStatus, 'success');
  assert.equal(before['demo:alice'] - balances(paid)['demo:alice'], 100000000);
  assert.equal(balances(paid)['merchant:keyboard'] - before['merchant:keyboard'], 100000000);
  await mechanism.waitForFunction(() => document.querySelector('#live-phase-code').textContent.startsWith('paid'), undefined, { polling: 100, timeout: 15000 });
  const livePaid = (await api('/api/live/state')).data;
  assert.equal(livePaid.core.manual.stage, 'SETTLED'); assert.equal(livePaid.store.receipt.transactionHash, paid.receipt.transactionHash);
  assert(livePaid.inventory.devices.find(device => device.id === 'default').signCount >= 4);
  assert(wireEvents.some(event => event.action === 'wallet-sign' && event.status === 'complete' && event.orderId === orderId));
  assert(wireEvents.some(event => event.action === 'verify' && event.phase === 'settle' && event.status === 'complete' && event.orderId === orderId));
  const tracePhases = [...new Set(livePaid.events.filter(event => event.orderId === orderId && event.action === 'verify' && event.status === 'complete' && event.data?.verificationTrace).map(event => event.phase))];
  assert.deepEqual(tracePhases, ['proposal', 'authorize', 'settle']);
  await mechanism.waitForFunction(() => { const labels = [...document.querySelector('#live-trace-select').options].map(option => option.textContent).join(' '); return ['资格认证', '付款前复核', '结算验证'].every(label => labels.includes(label)); }, undefined, { polling: 100, timeout: 15000 });
  await shot('04-both-payment-completed.png');
  pass('explicit shopping confirmation drives Owner and original local transfer; both views share receipt', { receipt: paid.receipt, balancesBefore: before, balancesAfter: balances(paid), signCount: livePaid.inventory.devices.find(device => device.id === 'default').signCount });
  const duplicate = await api('/api/store/pay', payload); assert.equal(duplicate.status, 200); assert.equal(duplicate.data.receipt.transactionHash, paid.receipt.transactionHash); assert.deepEqual(balances(duplicate.data), balances(paid));
  pass('repeated payment returns the same receipt without another wallet transfer');
  await page.reload(); await frames(); await mall.locator('#receipt-view').waitFor();
  assert.equal(await mall.locator('#receipt-tx').innerText(), paid.receipt.transactionHash);
  await mechanism.waitForFunction(id => document.querySelector('#live-order').textContent === id, orderId, { polling: 100, timeout: 15000 });
  pass('reloading both applications restores the same actual order and receipt');

  await click(mall, '#new-order', '/api/store/new');
  await click(mall, '[data-add="headphones"]', '/api/store/cart'); await mall.locator('header [data-route="cart"]').click();
  await mechanism.locator('#live-security-details > summary').click();
  await click(mechanism, '[data-security="lock"]', '/api/store/security');
  await mechanism.waitForFunction(() => document.querySelector('#live-device').textContent.includes('已锁定'), undefined, { polling: 100, timeout: 15000 });
  const locked = (await click(mall, '#checkout', '/api/store/checkout', 403)).data;
  assert.equal(locked.error.code, 'DBAC_DEVICE_LOCKED'); assert.equal(await mall.locator('#checkout-view').isVisible(), false); assert.deepEqual(balances(locked.state), balances(paid));
  await mechanism.waitForFunction(() => document.querySelector('#live-phase').textContent.includes('DBAC_DEVICE_LOCKED'), undefined, { polling: 100, timeout: 15000 });
  await shot('05-backend-lock-blocks-store.png');
  pass('locking the actual device on the backend page blocks store checkout and preserves balances');
  await click(mechanism, '[data-security="unlock"]', '/api/store/security');
  await click(mechanism, '[data-security="revoke"]', '/api/store/security');
  const revoked = (await click(mall, '#checkout', '/api/store/checkout', 403)).data;
  assert.equal(revoked.error.code, 'W3C_CREDENTIAL_REVOKED'); assert.equal(await mall.locator('#checkout-view').isVisible(), false); assert.deepEqual(balances(revoked.state), balances(paid));
  await mechanism.waitForFunction(() => document.querySelector('#live-phase').textContent.includes('W3C_CREDENTIAL_REVOKED'), undefined, { polling: 100, timeout: 15000 });
  await shot('06-revocation-blocks-store.png');
  pass('issuer revocation on the backend page produces an actual verifier failure in the store');
  const currentBeforeHistory = (await api('/api/store/state')).data;
  const postsBefore = report.requests.filter(request => request.method === 'POST').length;
  await mechanism.locator('#live-history').selectOption(orderId);
  await mechanism.waitForFunction(hash => document.querySelector('#live-receipt').textContent.includes(hash), paid.receipt.transactionHash, { polling: 100, timeout: 15000 });
  await mechanism.waitForFunction(() => { const labels = [...document.querySelector('#live-trace-select').options].map(option => option.textContent).join(' '); return ['资格认证', '付款前复核', '结算验证'].every(label => labels.includes(label)); }, undefined, { polling: 100, timeout: 15000 });
  const currentAfterHistory = (await api('/api/store/state')).data;
  assert.equal(currentAfterHistory.order.orderId, currentBeforeHistory.order.orderId); assert.deepEqual(balances(currentAfterHistory), balances(paid));
  assert.equal(report.requests.filter(request => request.method === 'POST').length, postsBefore);
  await mechanism.locator('#live-history').scrollIntoViewIfNeeded(); await shot('07-read-only-order-evidence.png');
  pass('past paid evidence stays separate from the current rejected order and does not execute anything');

  for (let count = 0; count < 18; count++) {
    const abort = new AbortController();
    const response = await fetch(`${runtime.baseUrl}/api/live/events?after=${livePaid.sequence}`, { headers: { 'X-Demo-UI-Key': keys.get('key') }, signal: abort.signal });
    assert.equal(response.status, 200); abort.abort(); await new Promise(resolve => setTimeout(resolve, 15));
  }
  assert.equal((await api('/api/live/state')).status, 200);
  pass('early observer disconnects release stream slots and the service stays available');
  assert.equal(await page.locator('body').evaluate(element => element.scrollWidth <= innerWidth), true);
  for (const frame of [mall, mechanism]) assert.equal(await frame.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.setViewportSize({ width: 1440, height: 1000 }); await shot('08-laptop-side-by-side.png');
  for (const frame of [mall, mechanism]) assert.equal(await frame.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.locator('button[data-layout="stack"]').click(); assert.equal(await page.locator('body').getAttribute('data-layout'), 'stack');
  await page.locator('button[data-layout="side"]').click();
  const bodyText = (await page.locator('body').innerText()) + (await mall.locator('body').innerText()) + (await mechanism.locator('body').innerText());
  assert(!bodyText.includes(keys.get('key'))); assert(!bodyText.includes(keys.get('ownerKey')));
  const publicSnapshot = JSON.stringify((await api('/api/live/state')).data);
  assert(!publicSnapshot.includes(keys.get('key'))); assert(!publicSnapshot.includes(keys.get('ownerKey'))); assert(!publicSnapshot.includes('"token":'));
  assert.deepEqual(report.pageErrors, []); assert.deepEqual(report.externalRequests, []); assert.equal(report.streamError, undefined);
  pass('separate desktop layouts operate without external networking, access-key display or script errors');
  report.status = 'passed';
} catch (error) { report.status = 'failed'; report.error = error.stack; console.error(error.stack); process.exitCode = 1; await shot('failure.png').catch(() => {}); }
finally {
  clearTimeout(watchdog);
  streamStopped = true; streamAbort.abort(); await streamTask;
  report.protocolEvents = wireEvents.map(({ receivedAt, ...event }) => event); report.snapshotCount = wireSnapshots.length;
  report.finishedAt = new Date().toISOString(); await writeFile(resolve(output, 'verification.json'), JSON.stringify(report, null, 2));
  await writeFile(resolve(output, 'progress.json'), JSON.stringify(report, null, 2));
  await browser.close();
}
