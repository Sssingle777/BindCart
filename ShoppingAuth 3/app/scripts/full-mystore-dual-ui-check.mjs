import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';

// Real services only. This test intentionally executes two local test payments.
// It never starts/stops services or erases their ledger, orders or evidence.
const runtime = JSON.parse(await readFile(process.env.NATIVE_RUNTIME_PATH ?? new URL('../var/dual-runtime.json', import.meta.url)));
const caps = new URLSearchParams(new URL(runtime.url).hash.slice(1));
const redact = value => { let text = String(value); for (const token of [caps.get('key'), caps.get('ownerKey')]) if (token) text = text.replaceAll(token, '[redacted]'); return text; };
const output = resolve('../evidence/full-mystore-integration'); await mkdir(output, { recursive: true });
const report = { startedAt: new Date().toISOString(), source: 'complete official public MyStore build + actual credential, possession, device, Owner, x402 and merchant services',
  realCryptoAndChain: true, simulatedFiatOrPSP: false, localTestOnly: true, checks: [], errors: [], externalRequests: [], failedResources: [], screenshots: [], timingPairs: [] };
const save = async () => writeFile(resolve(output, 'verification.json'), JSON.stringify(report, null, 2));
const pass = async (name, details = {}) => { report.checks.push({ name, passed: true, ...details }); console.log(`PASS ${name}`); await save(); };
async function api(path, body, authenticated = true) {
  const response = await fetch(runtime.baseUrl + path, { method: body === undefined ? 'GET' : 'POST',
    headers: { ...(authenticated ? { 'X-Demo-UI-Key': caps.get('key') } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(120000) });
  return { status: response.status, data: await response.json() };
}
const state = async () => (await api('/api/store/state')).data;
const live = async () => (await api('/api/live/state')).data;
const ledger = value => ({ executions: value.backend.ledger.executionCount, balances: value.backend.ledger.accounts.map(({ id, balanceMinor }) => ({ id, balanceMinor })) });
const signatures = value => value.inventory.devices.find(device => device.id === 'default').signCount;
const browser = await launchAcceptanceBrowser({ headless: true });
const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, locale: 'zh-CN' });
await context.route('**/*', route => {
  if (new URL(route.request().url()).origin !== runtime.baseUrl) { report.externalRequests.push(new URL(route.request().url()).origin); return route.abort(); }
  return route.continue();
});
const page = await context.newPage(); page.setDefaultTimeout(120000); page.setDefaultNavigationTimeout(120000);
page.on('pageerror', error => report.errors.push(redact(error.message)));
page.on('response', response => {
  if (response.status() >= 400 && /\.(?:js|css|png|svg|woff2)(?:\?|$)/.test(new URL(response.url()).pathname)) report.failedResources.push({ path: new URL(response.url()).pathname, status: response.status() });
});
const posted = []; page.on('request', request => { if (request.method() === 'POST') posted.push(new URL(request.url()).pathname); });
let store, mechanism;
async function frames() {
  store = await (await page.locator('#store-frame').elementHandle()).contentFrame();
  mechanism = await (await page.locator('#mechanism-frame').elementHandle()).contentFrame();
  await mechanism.locator('#live-connection[data-state="connected"]').waitFor();
}
async function shot(name) { await page.screenshot({ path: resolve(output, name), fullPage: true }); report.screenshots.push(name); }
async function settledCart(count) {
  await store.waitForFunction(() => document.body.dataset.phase === 'cart' && document.body.dataset.busy === 'false');
  let result;
  for (let tries = 0; tries < 100; tries++) { result = await state(); if (!result.busy && result.phase === 'cart' && (count === undefined || result.cart.length === count)) return result; await page.waitForTimeout(100); }
  throw new Error(`Cart did not settle at expected item count ${count}`);
}
async function click(frame, selector, path, expected = 200) {
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === path && response.request().method() === 'POST', { timeout: 120000 });
  await frame.locator(selector).click({ noWaitAfter: true });
  const response = await pending, value = await response.json(); assert.equal(response.status(), expected, JSON.stringify(value.error)); return value;
}
async function home() { await store.locator('.header__link').click(); await store.locator('.products__list__list-item').nth(8).waitFor(); }
async function detail(id) { await home(); await store.locator(`a[href="#/product/${id}"]`).first().click(); await store.locator('.product-detail__title').waitFor(); }
async function add(id) { await detail(id); const value = await click(store, '.product-detail__button', '/api/store/cart'); await settledCart(value.cart.length); return value; }
async function openCart() { await store.locator('.shopping-cart__link').click(); await store.locator('.cart__title').waitFor(); }
async function checkout(expected = 200) {
  await openCart();
  assert.equal(await store.locator('#local-payment-confirm').count(), 0);
  const before = await live(), started = Date.now();
  const value = await click(store, '.cart_checkout-button', '/api/store/checkout', expected);
  const durationMs = Date.now() - started;
  if (expected === 200) {
    await store.locator('#local-payment-confirm').waitFor(); await store.waitForFunction(() => document.body.dataset.busy === 'false');
    assert.equal(value.phase, 'checkout'); assert.equal(value.backend.proposal.status, 'PENDING');
    assert.equal(value.verification.steps.find(step => step.id === 'merchant_order')?.status, 'pass');
    assert.equal(value.order.merchantOrder.snapshotHash, value.backend.proposal.payment.merchantOrder.snapshotHash);
    assert.deepEqual(ledger(value), ledger(before.store));
    assert(signatures(await live()) > signatures(before), 'Qualification did not use the real device');
    await mechanism.waitForFunction(id => document.querySelector('#live-order').textContent === id, value.order.orderId);
  }
  return { value, durationMs, before };
}
async function payWithDoubleClick() {
  const before = await state(), beforePosts = posted.filter(path => path === '/api/store/pay').length;
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/store/pay' && response.request().method() === 'POST', { timeout: 120000 });
  const started = Date.now();
  await store.locator('#local-payment-confirm').evaluate(button => { button.dispatchEvent(new MouseEvent('click', { bubbles: true })); button.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
  let paying;
  for (let tries = 0; tries < 100; tries++) { const current = await state(); if (current.busy && current.phase === 'paying') { paying = current; break; } await page.waitForTimeout(100); }
  assert(paying, 'The genuine payment operation did not begin');
  const blocked = await api('/api/store/pay', { orderId: before.order.orderId, revision: before.revision });
  assert.equal(blocked.status, 409, 'Concurrent payment was not blocked');
  const response = await pending, value = await response.json(); assert.equal(response.status(), 200, JSON.stringify(value.error));
  assert.equal(posted.filter(path => path === '/api/store/pay').length - beforePosts, 1, 'Repeated click created another payment request');
  await store.waitForFunction(() => document.body.dataset.busy === 'false');
  return { value, durationMs: Date.now() - started };
}
async function returnHome() {
  await click(store, '.status a.button', '/api/store/new'); await store.locator('.products__list__list-item').nth(8).waitFor(); return settledCart(0);
}
function checkStageIntervals(events, orderId) {
  const paced = action => action.startsWith('begin-') || ['issue', 'device-sign', 'prove', 'verify', 'submit-owner', 'sync-owner', 'wallet-sign'].includes(action);
  const rows = events.filter(event => event.source === 'original-controller' && event.orderId === orderId);
  const pairs = [];
  for (const event of rows.filter(row => row.status === 'complete' && paced(row.action))) {
    const next = rows.find(row => row.seq > event.seq && row.status === 'start' && row.operationId === event.operationId);
    if (!next) continue;
    const gapMs = Date.parse(next.at) - Date.parse(event.at);
    assert(gapMs >= 1590, `Real server stage ${event.action}→${next.action} advanced after only ${gapMs}ms`);
    pairs.push({ action: event.action, nextAction: next.action, phase: event.phase, completedAt: event.at, nextStartedAt: next.at, gapMs });
  }
  assert(pairs.length >= 12, `Too few comparable real protocol-stage intervals: ${pairs.length}`); return pairs;
}
async function checkDiagramSource() {
  const original = process.env.BASELINE_APP_PATH
    ? pathToFileURL(resolve(process.env.BASELINE_APP_PATH, 'public') + '/')
    : new URL('../../phase3-dual-live/a2a-jcardsim-x402/public/', new URL('../', import.meta.url));
  const current = new URL('../public/', import.meta.url);
  const baselineJs = await readFile(new URL('mechanism.js', original), 'utf8'), candidateJs = await readFile(new URL('mechanism.js', current), 'utf8');
  for (const [start, end] of [['function renderScene()', 'function renderSummary()'], ['function openRole(', "$('live-history').addEventListener"]]) {
    const extract = text => { const left = text.indexOf(start), right = text.indexOf(end, left + start.length); assert(left >= 0 && right > left); return text.slice(left, right); };
    assert.equal(extract(candidateJs), extract(baselineJs));
  }
  const css = await readFile(new URL('mechanism.css', original)), candidateCss = await readFile(new URL('mechanism.css', current));
  assert(candidateCss.subarray(0, css.length).equals(css));
  // The preserved diagram now repairs its <=620px layout instead of switching
  // to the broken mobile list. Runtime geometry is checked separately by
  // backend-restoration-layout-check.mjs; original CSS and helpers stay frozen.
  for (const file of ['guide-scene.js', 'guide-stage.css', 'guide.css', 'tokens.css', 'platform.css']) assert((await readFile(new URL(file, original))).equals(await readFile(new URL(file, current))));
}
try {
  await checkDiagramSource();
  assert.equal((await api('/api/store/query', { orderId: 'urn:uuid:00000000-0000-0000-0000-000000000000', revision: 0 }, false)).status, 401);
  const prior = await state(); assert(['cart', 'paid'].includes(prior.phase), 'Preserve unresolved order; resolve it before starting this test');
  if (prior.phase === 'paid' || prior.cart.length) assert.equal((await api('/api/store/new', { revision: prior.revision })).status, 200);
  await page.goto(runtime.url); await frames(); const initial = await settledCart(0);
  const catalog = (await api('/api/store/catalog')).data.products; assert.equal(catalog.length, 9);
  await store.locator('.products__list__list-item').nth(8).waitFor(); assert.equal(await store.locator('.products__list__list-item').count(), 9);
  assert.equal(await mechanism.locator('.scene-node').count(), 6);
  const sheets = await store.evaluate(() => [...document.styleSheets].map(sheet => new URL(sheet.href).pathname));
  assert.deepEqual(sheets, ['/store/mystore/fonts/inter.css', '/store/mystore/vendors.css', '/store/mystore/main.css']);
  for (const product of catalog) {
    await detail(product.id);
    assert.equal((await store.locator('.product-detail__title').innerText()).replace(/\s/g, ''), (product.title || product.name).replace(/\s/g, ''));
    assert((await store.locator('.product-detail__price').innerText()).includes((product.unitAmountMinor / 1000000).toFixed(2)));
    const description = await store.locator('.product-detail__description').innerText(); assert(/[\u3400-\u9fff]/.test(description)); assert(!/[A-Za-z]{3,}(?:[ ,.!—’'-]+[A-Za-z]{2,}){7}/.test(description));
    await store.locator('.product-detail__product').scrollIntoViewIfNeeded();
    await store.waitForFunction(() => { const image = document.querySelector('.product-detail__product'); return image?.complete && image.naturalWidth > 0; });
    assert.equal(await store.locator('.recommendations .products__list__list-item').count(), 4);
  }
  await home(); await shot('01-complete-official-store-chinese.png');
  await add('01'); await openCart(); await click(store, '.order-summary__list__list-item__remove-product', '/api/store/cart'); await settledCart(0); await store.locator('.cart--empty').waitFor();
  await add('02'); const selected = await add('03'); assert.equal(selected.totalMinor, 34980000); await openCart();
  assert((await store.locator('.cart__price-amount').innerText()).includes('34.98'));
  await pass('All nine original products, translated details/recommendations/images and authoritative add/remove/cart work beside the preserved six-role graph');

  const { value: qualified, durationMs: qualificationMs } = await checkout(); assert.equal(qualified.order.merchantOrder.snapshot.items.length, 2);
  const withoutOwner = await api('/api/store/pay', { orderId: qualified.order.orderId, revision: qualified.revision }); assert.equal(withoutOwner.status, 403);
  assert.deepEqual(ledger(await state()), ledger(initial)); await shot('02-qualified-original-checkout.png');
  await pass('Real signed goods, credential, holder and device checks finish before payment appears; pending Owner blocks payment', { qualificationMs });
  const { value: paid, durationMs: paymentMs } = await payWithDoubleClick();
  assert.equal(paid.phase, 'paid'); assert.equal(paid.merchant.status, 'confirmed'); assert.equal(paid.receipt.transactionStatus, 'success');
  assert.equal(ledger(paid).executions - ledger(initial).executions, 1);
  await store.waitForFunction(() => document.querySelector('.status__message')?.textContent === '订单已成功提交。');
  await mechanism.waitForFunction(() => document.querySelector('#live-phase-code').textContent.startsWith('paid'));
  await mechanism.waitForFunction(() => ['资格认证', '付款前复核', '结算验证'].every(label => [...document.querySelector('#live-trace-select').options].some(option => option.textContent.includes(label))));
  const paidSnapshot = await live(); await writeFile(resolve(output, 'paid-snapshot.json'), JSON.stringify(paidSnapshot, null, 2));
  report.timingPairs = checkStageIntervals(paidSnapshot.events, paid.order.orderId);
  await shot('03-real-payment-and-merchant-confirmed.png');
  await pass('Explicit Owner approval, paced original x402 payment and independent merchant confirmation execute once despite repeated clicks', { paymentMs, executionDelta: 1, comparableStages: report.timingPairs.length, minimumStageGapMs: Math.min(...report.timingPairs.map(pair => pair.gapMs)) });
  const duplicate = await api('/api/store/pay', { orderId: paid.order.orderId, revision: paid.revision }); assert.equal(duplicate.status, 200);
  assert.equal(duplicate.data.receipt.transactionHash, paid.receipt.transactionHash); assert.deepEqual(ledger(duplicate.data), ledger(paid));
  await page.reload(); await frames(); await store.locator('.status__message').waitFor();
  assert.equal((await state()).receipt.transactionHash, paid.receipt.transactionHash); assert.deepEqual(ledger(await state()), ledger(paid));
  await returnHome(); await pass('Duplicate submission and refresh retain original receipt; explicit Return Home alone starts a fresh empty official store');

  await mechanism.locator('#live-fault-details').evaluate(element => { element.open = true; });
  await click(mechanism, '[data-fault="delay-merchant-once"]', '/api/store/fault');
  await add('02'); await add('03'); await checkout(); const { value: pending } = await payWithDoubleClick();
  assert.equal(pending.phase, 'confirming'); assert.equal(pending.merchant.status, 'payment-confirmed'); assert(pending.receipt.transactionHash);
  assert.equal(await store.locator('.status__message').count(), 0); assert.equal(await store.locator('#local-payment-confirm').innerText(), '查询支付结果');
  await mechanism.locator('#live-merchant-details').evaluate(element => { element.open = true; });
  await mechanism.locator('#live-query-payment').waitFor({ state: 'visible' });
  const pendingSnapshot = await live(), signaturesBefore = signatures(pendingSnapshot), beforeQueryLedger = ledger(pendingSnapshot.store);
  assert.equal((await api('/api/store/new', { revision: pending.revision })).status, 409);
  await page.reload(); await frames(); await store.locator('#local-payment-confirm').waitFor(); assert.equal((await state()).phase, 'confirming');
  await mechanism.locator('#live-merchant-details').evaluate(element => { element.open = true; });
  await shot('04-real-paid-merchant-pending.png');
  const recovered = await click(mechanism, '#live-query-payment', '/api/store/query'); assert.equal(recovered.phase, 'paid');
  assert.equal(recovered.receipt.transactionHash, pending.receipt.transactionHash); const recoveredSnapshot = await live();
  assert.equal(signatures(recoveredSnapshot), signaturesBefore); assert.deepEqual(ledger(recoveredSnapshot.store), beforeQueryLedger);
  await store.waitForFunction(() => document.querySelector('.status__message')?.textContent === '订单已成功提交。'); await shot('05-original-receipt-recovered.png');
  await pass('Merchant delay stays pending through refresh; right-side recovery confirms the identical receipt without signing or transferring again');

  await returnHome(); await mechanism.locator('#live-experiment-details').evaluate(element => { element.open = true; });
  const beforeExperiments = await state();
  for (const scenario of ['copied-vc', 'revoked']) {
    const result = await click(mechanism, `[data-experiment="${scenario}"]`, '/api/store/experiment');
    assert.equal(result.experiment.control.accepted, true); assert.equal(result.experiment.expectationMet, true); assert.equal(result.experiment.requestRejected, true);
    assert.equal(result.experiment.sideEffects.paymentExecutionDelta, 0); assert.equal(result.experiment.sideEffects.balancesUnchanged, true);
    assert.equal(result.backend.currentCredentialId, beforeExperiments.backend.currentCredentialId); assert.deepEqual(ledger(result), ledger(beforeExperiments));
    await mechanism.waitForFunction(code => document.querySelector('#live-experiment-result')?.textContent.includes(code), result.experiment.actual);
    await pass(`Actual ${scenario} control passes, attack is rejected, normal credential and balances remain unchanged`, { actual: result.experiment.actual });
  }
  await shot('06-real-credential-attack-experiments.png');
  await add('02'); await mechanism.locator('#live-security-details').evaluate(element => { element.open = true; });
  await click(mechanism, '[data-security="lock"]', '/api/store/security');
  const { value: locked } = await checkout(403); assert.equal(locked.error.code, 'DBAC_DEVICE_LOCKED'); assert.deepEqual(ledger(locked.state), ledger(beforeExperiments));
  await store.waitForFunction(() => document.querySelector('.status__message')?.textContent === '操作未成功，请重试。');
  assert.equal(await store.locator('#local-payment-confirm').count(), 0); await returnHome();
  await click(mechanism, '[data-security="unlock"]', '/api/store/security');
  await pass('Actual locked device denies qualification; original failure page appears without a payment window or transfer');

  const current = await live(), postCount = posted.length;
  await mechanism.locator('#live-history').selectOption(paid.order.orderId);
  await mechanism.waitForFunction(hash => document.querySelector('#live-receipt')?.textContent.includes(hash), paid.receipt.transactionHash);
  assert((await mechanism.locator('#live-merchant').innerText()).includes(paid.order.merchantOrder.snapshotHash)); assert((await mechanism.locator('#live-merchant-status').innerText()).includes('商户已确认'));
  let legacyOrder = null;
  for (const entry of current.history) {
    if (entry.orderId === paid.order.orderId) continue;
    const record = (await api('/api/live/orders/' + encodeURIComponent(entry.orderId))).data;
    if (record.cart?.some(item => ['headphones', 'sunglasses'].includes(item.id))) { legacyOrder = record; break; }
  }
  if (legacyOrder) {
    await mechanism.locator('#live-history').selectOption(legacyOrder.order.orderId);
    await mechanism.waitForFunction(id => document.querySelector('#live-history').value === id && document.querySelector('#live-evidence-summary').textContent.includes(id), legacyOrder.order.orderId);
    assert.equal(legacyOrder.readOnly, true); assert(legacyOrder.cart.some(item => ['headphones', 'sunglasses'].includes(item.id)));
  }
  assert.equal(posted.length, postCount); assert.deepEqual(ledger(await state()), ledger(current.store));
  await mechanism.locator('#live-history').selectOption('');
  await pass('Current signed order history and available legacy SKU history remain read-only', { legacyOrderChecked: Boolean(legacyOrder) });

  for (const viewport of [{ width: 1920, height: 1080 }, { width: 1440, height: 1000 }]) {
    await page.setViewportSize(viewport);
    for (const frame of [store, mechanism]) assert(await frame.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Horizontal overflow');
  }
  await page.locator('button[data-layout="stack"]').click(); assert.equal(await page.locator('body').getAttribute('data-layout'), 'stack');
  for (const frame of [store, mechanism]) assert(await frame.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  await page.locator('button[data-layout="side"]').click();
  assert.equal((await state()).phase, 'cart'); assert.equal((await state()).cart.length, 0);
  assert.deepEqual(report.errors, []); assert.deepEqual(report.externalRequests, []); assert.deepEqual(report.failedResources, []);
  await pass('Independent storefront/controller styles, both layouts and both window widths retain no overflow, no external requests and no page errors');
  report.status = 'passed';
} catch (error) {
  report.status = 'failed'; report.error = redact(error.stack); process.exitCode = 1; console.error(report.error); await shot('failure.png').catch(() => {});
} finally { report.finishedAt = new Date().toISOString(); await save(); await browser.close(); }
