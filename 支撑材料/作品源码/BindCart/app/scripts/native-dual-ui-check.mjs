import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';

const runtime = JSON.parse(await readFile(process.env.NATIVE_RUNTIME_PATH ?? new URL('../var/dual-runtime.json', import.meta.url)));
const caps = new URLSearchParams(new URL(runtime.url).hash.slice(1));
const output = resolve('../evidence/native-integration'); await mkdir(output, { recursive: true });
const report = { startedAt: new Date().toISOString(), source: 'real launch-dual + original MyStore templates + original cryptographic services and local x402 chain', checks: [], errors: [], externalRequests: [], screenshots: [] };
const save = async () => writeFile(resolve(output, 'verification.json'), JSON.stringify(report, null, 2));
const pass = async (name, details = {}) => { report.checks.push({ name, passed: true, ...details }); console.log(`PASS ${name}`); await save(); };
async function api(path, body, authenticated = true) {
  const response = await fetch(runtime.baseUrl + path, { method: body === undefined ? 'GET' : 'POST', headers: { ...(authenticated ? { 'X-Demo-UI-Key': caps.get('key') } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(90000) });
  return { status: response.status, data: await response.json() };
}
const ledger = state => ({ executions: state.backend.ledger.executionCount, balances: state.backend.ledger.accounts.map(({ id, balanceMinor }) => ({ id, balanceMinor })) });
const deviceSignatures = state => state.inventory.devices.find(device => device.id === 'default').signCount;
const browser = await launchAcceptanceBrowser({ headless: true });
const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, locale: 'zh-CN' });
await context.route('**/*', route => {
  if (new URL(route.request().url()).origin !== runtime.baseUrl) { report.externalRequests.push(new URL(route.request().url()).origin); return route.abort(); }
  return route.continue();
});
const page = await context.newPage(); page.setDefaultTimeout(30000);
page.on('pageerror', error => report.errors.push(error.message));
let store, mechanism;
async function frames() {
  await page.locator('#store-frame').waitFor();
  store = await (await page.$('#store-frame')).contentFrame();
  mechanism = await (await page.$('#mechanism-frame')).contentFrame();
  await mechanism.locator('#live-connection[data-state="connected"]').waitFor();
}
async function shot(name) {
  const file = resolve(output, name); await page.screenshot({ path: file, fullPage: true }); report.screenshots.push(name);
}
async function cart() {
  await store.locator('.cart-footer-amount').waitFor();
  await store.waitForFunction(() => document.body.dataset.phase === 'cart' && document.body.dataset.revision);
  let value;
  for (let tries = 0; tries < 50; tries++) {
    value = (await api('/api/store/state')).data;
    if (!value.busy && value.cart.length === 2 && value.totalMinor === 100000000) return value;
    await page.waitForTimeout(100);
  }
  throw new Error('Original fixed cart did not synchronize with backend');
}
async function click(frame, selector, path, expected = 200) {
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === path && response.request().method() === 'POST', { timeout: 60000 });
  await frame.locator(selector).click({ noWaitAfter: true });
  const response = await pending, value = await response.json();
  assert.equal(response.status(), expected, JSON.stringify(value.error)); return value;
}
async function checkout() {
  const state = await click(store, 'a[href^="/store/checkout"]', '/api/store/checkout');
  await store.locator('#local-payment-confirm').waitFor();
  assert.equal(state.phase, 'checkout'); assert.equal(state.backend.proposal.status, 'PENDING');
  await mechanism.waitForFunction(id => document.querySelector('#live-order').textContent === id, state.order.orderId);
  return state;
}
async function pay() { return click(store, '#local-payment-confirm', '/api/store/pay'); }
async function returnHome() {
  await click(store, 'a.button[href="/store/"]', '/api/store/new'); return cart();
}
try {
  const denied = await api('/api/store/query', { orderId: 'urn:uuid:00000000-0000-0000-0000-000000000000', revision: 0 }, false);
  assert.equal(denied.status, 401);
  const prior = (await api('/api/store/state')).data;
  if (prior.phase === 'paid') assert.equal((await api('/api/store/new', { revision: prior.revision })).status, 200);
  await page.goto(runtime.url); await frames(); const initial = await cart();
  const storeText = await store.locator('body').innerText();
  for (const word of ['Cart', 'Sunglasses', 'Headphones', 'Continue to checkout']) assert(storeText.includes(word));
  assert(!/[\u3400-\u9fff]/u.test(storeText));
  const sheets = await store.evaluate(() => [...document.styleSheets].map(sheet => new URL(sheet.href).pathname));
  assert.deepEqual(sheets, ['/store/bootstrap-4.3.1.min.css', '/store/adyen-application.css']);
  assert.equal(await mechanism.locator('.scene-node').count(), 6);
  await shot('01-native-cart-and-controller.png');
  await pass('Original English Cart and upstream styles load beside the existing six-role interaction graph; fixed goods match backend');

  const qualified = await checkout();
  assert.equal(qualified.merchant.status, 'created'); assert.equal(qualified.order.merchantOrder.snapshot.items.length, 2);
  assert.equal(qualified.verification.steps.find(step => step.id === 'merchant_order')?.status, 'pass');
  assert.equal(qualified.order.merchantOrder.snapshotHash, qualified.backend.proposal.payment.merchantOrder.snapshotHash);
  assert.deepEqual(ledger(qualified), ledger(initial));
  const withoutOwner = await api('/api/store/pay', { orderId: qualified.order.orderId, revision: qualified.revision });
  assert.equal(withoutOwner.status, 403);
  await shot('02-native-checkout-qualified.png');
  await pass('Checkout opens only after real signed merchant/credential/holder/device verification and still waits for Owner');

  const paid = await pay();
  assert.equal(paid.phase, 'paid'); assert.equal(paid.merchant.status, 'confirmed'); assert.equal(paid.receipt.transactionStatus, 'success');
  assert.equal(ledger(paid).executions - ledger(initial).executions, 1);
  await store.waitForFunction(() => document.querySelector('.status-message')?.textContent.includes('Your order has been successfully placed.'));
  await mechanism.waitForFunction(() => document.querySelector('#live-phase-code').textContent.startsWith('paid'));
  await mechanism.waitForFunction(() => ['资格认证', '付款前复核', '结算验证'].every(label => [...document.querySelector('#live-trace-select').options].some(option => option.textContent.includes(label))));
  const paidSnapshot = (await api('/api/live/state')).data;
  await writeFile(resolve(output, 'paid-snapshot.json'), JSON.stringify(paidSnapshot, null, 2));
  await shot('03-native-success-and-controller.png');
  await pass('Native Pay performs explicit Owner approval, original x402 payment and independent merchant confirmation before official success');
  const duplicate = await api('/api/store/pay', { orderId: paid.order.orderId, revision: paid.revision });
  assert.equal(duplicate.status, 200); assert.equal(duplicate.data.receipt.transactionHash, paid.receipt.transactionHash); assert.deepEqual(ledger(duplicate.data), ledger(paid));
  await page.reload(); await frames();
  await store.locator('.status-message').waitFor();
  assert((await store.locator('.status-message').innerText()).includes('Your order has been successfully placed.'));
  await pass('Duplicate submission and reload retain original confirmed payment without another transfer');

  await returnHome();
  await mechanism.locator('#live-fault-details').evaluate(element => { element.open = true; });
  await click(mechanism, '[data-fault="delay-merchant-once"]', '/api/store/fault');
  await checkout(); const pending = await pay();
  assert.equal(pending.phase, 'confirming'); assert.equal(pending.merchant.status, 'payment-confirmed'); assert(pending.receipt.transactionHash);
  await store.waitForFunction(() => document.querySelector('.status-message')?.textContent.includes('Payment completion pending.'));
  await mechanism.locator('#live-query-payment').waitFor({ state: 'visible' });
  const waitingSnapshot = (await api('/api/live/state')).data, signaturesBeforeQuery = deviceSignatures(waitingSnapshot);
  const ledgerBeforeQuery = ledger(waitingSnapshot.store);
  const blocked = await api('/api/store/new', { revision: pending.revision }); assert.equal(blocked.status, 409);
  await shot('04-payment-confirmed-merchant-pending.png');
  const confirmed = await click(mechanism, '#live-query-payment', '/api/store/query');
  assert.equal(confirmed.phase, 'paid'); assert.equal(confirmed.receipt.transactionHash, pending.receipt.transactionHash);
  const recoveredSnapshot = (await api('/api/live/state')).data;
  assert.equal(deviceSignatures(recoveredSnapshot), signaturesBeforeQuery); assert.deepEqual(ledger(recoveredSnapshot.store), ledgerBeforeQuery);
  await store.waitForFunction(() => document.querySelector('.status-message')?.textContent.includes('Your order has been successfully placed.'));
  await shot('05-original-receipt-recovery.png');
  await pass('Paid-but-unconfirmed merchant uses official pending; backend query recovers same receipt without signing or another transfer');

  await returnHome();
  await mechanism.locator('#live-experiment-details').evaluate(element => { element.open = true; });
  const beforeExperiments = (await api('/api/store/state')).data;
  for (const scenario of ['copied-vc', 'revoked']) {
    const result = await click(mechanism, `[data-experiment="${scenario}"]`, '/api/store/experiment');
    assert.equal(result.experiment.control.accepted, true); assert.equal(result.experiment.expectationMet, true);
    assert.equal(result.experiment.requestRejected, true); assert.equal(result.experiment.sideEffects.paymentExecutionDelta, 0);
    assert.equal(result.experiment.sideEffects.balancesUnchanged, true);
    assert.equal(result.backend.currentCredentialId, beforeExperiments.backend.currentCredentialId);
    assert.deepEqual(ledger(result), ledger(beforeExperiments));
    await mechanism.waitForFunction(code => document.querySelector('#live-experiment-result')?.textContent.includes(code), result.experiment.actual);
    await pass(`Actual ${scenario} control/attack experiment stays separate from normal credential and never pays`, { actual: result.experiment.actual });
  }
  await shot('06-real-verification-experiment.png');

  await mechanism.locator('#live-security-details').evaluate(element => { element.open = true; });
  await click(mechanism, '[data-security="lock"]', '/api/store/security');
  const locked = await click(store, 'a[href^="/store/checkout"]', '/api/store/checkout', 403);
  assert.equal(locked.error.code, 'DBAC_DEVICE_LOCKED'); assert.deepEqual(ledger(locked.state), ledger(beforeExperiments));
  await store.waitForFunction(() => document.querySelector('.status-message')?.textContent.includes('The payment was refused.'));
  await returnHome();
  await click(mechanism, '[data-security="unlock"]', '/api/store/security');
  await pass('Actual locked device blocks qualification and native checkout; official failure cannot be mistaken for a paid order');

  const postCount = [];
  const track = request => { if (request.method() === 'POST') postCount.push(new URL(request.url()).pathname); };
  page.on('request', track);
  await mechanism.locator('#live-history').selectOption(paid.order.orderId);
  await mechanism.waitForFunction(hash => document.querySelector('#live-receipt')?.textContent.includes(hash), paid.receipt.transactionHash);
  assert((await mechanism.locator('#live-merchant').innerText()).includes(paid.order.merchantOrder.snapshotHash));
  assert((await mechanism.locator('#live-merchant-status').innerText()).includes('商户已确认'));
  assert.equal(postCount.length, 0);
  assert.deepEqual(ledger((await api('/api/store/state')).data), ledger(beforeExperiments));
  await mechanism.locator('#live-history').selectOption(''); page.off('request', track);
  await pass('History exposes the original signed goods and merchant confirmation as read-only evidence');

  for (const viewport of [{ width: 1920, height: 1080 }, { width: 1440, height: 1000 }]) {
    await page.setViewportSize(viewport);
    for (const frame of [store, mechanism]) assert(await frame.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  }
  assert.deepEqual(report.errors, []); assert.deepEqual(report.externalRequests, []);
  await page.locator('button[data-layout="stack"]').click(); assert.equal(await page.locator('body').getAttribute('data-layout'), 'stack');
  await page.locator('button[data-layout="side"]').click();
  await pass('Both layouts retain independent styling, no horizontal overflow, no external network requests and no page script errors');
  report.status = 'passed';
} catch (error) {
  report.status = 'failed'; report.error = error.stack; process.exitCode = 1; console.error(error.stack);
  await shot('failure.png').catch(() => {});
} finally { report.finishedAt = new Date().toISOString(); await save(); await browser.close(); }
