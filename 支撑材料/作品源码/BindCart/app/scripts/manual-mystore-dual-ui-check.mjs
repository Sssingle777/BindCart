import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';

// Operates a fresh test instance only, using real services and browser clicks.
// One deliberate TEST_USDC payment. No mutation is triggered by a timer.
const runtime = JSON.parse(await readFile(process.env.NATIVE_RUNTIME_PATH ?? new URL('../var/dual-runtime.json', import.meta.url)));
const caps = new URLSearchParams(new URL(runtime.url).hash.slice(1));
const output = resolve(process.env.MANUAL_UI_OUTPUT_PATH ?? '../evidence/manual-mystore-integration');
await mkdir(output, { recursive: true });
const report = { startedAt: new Date().toISOString(), realCryptoAndChain: true, localTestOnly: true,
  checks: [], manualClicks: [], idleChecks: [], errors: [], externalRequests: [], failedResources: [], screenshots: [] };
const redact = value => { let text = String(value); for (const token of [caps.get('key'), caps.get('ownerKey')]) if (token) text = text.replaceAll(token, '[redacted]'); return text; };
const save = () => writeFile(resolve(output, 'verification.json'), JSON.stringify(report, null, 2));
const pass = async (name, details = {}) => { report.checks.push({ name, passed: true, ...details }); console.log(`PASS ${name}`); await save(); };
async function api(path, body, authenticated = true) {
  const response = await fetch(runtime.baseUrl + path, { method: body === undefined ? 'GET' : 'POST',
    headers: { ...(authenticated ? { 'X-Demo-UI-Key': caps.get('key') } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(120000) });
  return { status: response.status, data: await response.json() };
}
const live = async () => (await api('/api/live/state')).data;
const state = async () => (await api('/api/store/state')).data;
const ledger = snapshot => ({ executions: snapshot.core.ledger.executionCount, accounts: snapshot.core.ledger.accounts.map(({ id, balanceMinor }) => ({ id, balanceMinor })) });
const signatures = snapshot => snapshot.inventory.devices.find(device => device.id === 'default').signCount;
const fixed = snapshot => ({ token: snapshot.store.manualControl?.token, revision: snapshot.store.revision, phase: snapshot.store.phase,
  attemptId: snapshot.core.manual.attemptId, stage: snapshot.core.manual.stage, log: snapshot.core.manual.log.length,
  deviceSigns: signatures(snapshot), ledger: ledger(snapshot), ownerStatus: snapshot.core.proposal?.status, walletSigned: snapshot.core.manual.walletSigned });
const browser = await launchAcceptanceBrowser({ headless: true });
const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, locale: 'zh-CN' });
await context.route('**/*', route => { const origin = new URL(route.request().url()).origin; if (origin !== runtime.baseUrl) { report.externalRequests.push(origin); return route.abort(); } return route.continue(); });
const page = await context.newPage(); page.setDefaultTimeout(120000);
page.on('pageerror', error => report.errors.push(redact(error.message)));
page.on('response', response => { if (response.status() >= 400 && /\.(?:js|css|png|svg|woff2)(?:\?|$)/.test(new URL(response.url()).pathname)) report.failedResources.push({ path: new URL(response.url()).pathname, status: response.status() }); });
const posts = []; page.on('request', request => { if (request.method() === 'POST') posts.push(new URL(request.url()).pathname); });
let store, mechanism;
async function shot(name) { await page.screenshot({ path: resolve(output, name), fullPage: true }); report.screenshots.push(name); }
async function click(frame, selector, path, double = false) {
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === path && response.request().method() === 'POST');
  if (double) await frame.locator(selector).evaluate(button => { button.click(); button.click(); });
  else await frame.locator(selector).click({ noWaitAfter: true });
  const response = await pending, value = await response.json(); assert.equal(response.status(), 200, JSON.stringify(value.error)); return value;
}
async function idle(name, milliseconds = 1100) {
  const before = await live(), count = posts.length; await delay(milliseconds); const after = await live();
  assert.deepEqual(fixed(after), fixed(before), `${name}: idle reads advanced a protocol step`); assert.equal(posts.length, count, `${name}: browser sent an unsolicited mutation`);
  report.idleChecks.push({ name, milliseconds, phase: before.store.phase, stage: before.core.manual.stage, noAdditionalPosts: true, noAdditionalSignatures: true, noTransfer: true }); await save(); return after;
}
const bodyFor = (snapshot, action) => ({ action, orderId: snapshot.store.order.orderId, revision: snapshot.store.revision,
  attemptId: snapshot.core.manual.attemptId, controlToken: snapshot.store.manualControl.token });
async function step(action, options = {}) {
  const before = await live(); assert.equal(before.store.manualControl.nextAction, action, JSON.stringify(before.store.manualControl));
  await mechanism.waitForFunction(expected => { const button = document.querySelector('#live-manual-next'); return button?.dataset.action === expected && !button.disabled; }, action);
  const count = posts.filter(path => path === '/api/store/manual').length;
  const returned = await click(mechanism, '#live-manual-next', '/api/store/manual', options.double);
  const after = await live();
  assert.equal(posts.filter(path => path === '/api/store/manual').length - count, 1, 'A click must issue exactly one manual request');
  assert.notEqual(after.store.manualControl.token, before.store.manualControl.token, 'Each attempted step consumes the console token');
  // Event sequence is global; compare a stable prior event boundary instead.
  const newEvents = after.events.filter(event => !before.events.some(old => old.id === event.id && old.seq === event.seq));
  const operations = newEvents.filter(event => event.source === 'original-controller' && event.status === 'start');
  assert(operations.length <= 1, `One console click started ${operations.length} core operations`);
  if (action !== 'verify' || before.core.manual.phase !== 'settle') assert.deepEqual(ledger(after), ledger(before), `${action} transferred before final settlement`);
  report.manualClicks.push({ action, phase: after.core.manual.phase, stage: after.core.manual.stage, coreOperationsStarted: operations.length,
    deviceSignatureDelta: signatures(after) - signatures(before), executionDelta: after.core.ledger.executionCount - before.core.ledger.executionCount });
  await save(); if (options.idle !== false) await idle(`after ${action}/${after.core.manual.phase ?? 'none'}`); return { before, after, returned };
}
async function detail(id) { await store.locator('.header__link').click(); await store.locator(`a[href="#/product/${id}"]`).first().click(); await store.locator('.product-detail__title').waitFor(); }
async function add(id) { await detail(id); return click(store, '.product-detail__button', '/api/store/cart'); }
async function sourceGuards() {
  // Historical visual comparisons are optional; delivery checks need no external checkout.
  if (!process.env.BASELINE_APP_PATH) return;
  const original = pathToFileURL(resolve(process.env.BASELINE_APP_PATH, 'public') + '/');
  const current = new URL('../public/', import.meta.url), baselineJs = await readFile(new URL('mechanism.js', original), 'utf8'), candidateJs = await readFile(new URL('mechanism.js', current), 'utf8');
  for (const [start, end] of [['function renderScene()', 'function renderSummary()'], ['function openRole(', "$('live-role-dialog').showModal();\n}"]]) {
    const extract = text => { const left = text.indexOf(start), right = text.indexOf(end, left + start.length); assert(left >= 0 && right > left); return text.slice(left, right + (start.startsWith('function openRole') ? end.length : 0)); }; assert.equal(extract(candidateJs.replaceAll('\r\n', '\n')), extract(baselineJs.replaceAll('\r\n', '\n')));
  }
  const css = await readFile(new URL('mechanism.css', original)), candidateCss = await readFile(new URL('mechanism.css', current)); assert(candidateCss.subarray(0, css.length).equals(css));
  // 2026-10-18: the six-role diagram was intentionally re-laid out as a hub
  // (A at the centre). Role ids, message directions and click evidence remain
  // covered by test/guide-scene.test.mjs; only the non-diagram shared assets
  // stay byte-frozen here.
  for (const file of ['guide.css', 'tokens.css', 'platform.css']) assert((await readFile(new URL(file, original))).equals(await readFile(new URL(file, current))));
}
try {
  await sourceGuards(); const initial = await live(); assert.equal(initial.store.phase, 'cart'); assert.equal(initial.store.cart.length, 0); assert.equal(initial.core.ledger.executionCount, 0, 'Use a fresh isolated acceptance instance');
  assert.equal((await api('/api/store/manual', { action: 'issue' }, false)).status, 401);
  const introduction = new URL(runtime.url); introduction.pathname = '/intro/';
  await page.goto(introduction.href);
  await page.waitForFunction(() => !location.hash && sessionStorage.getItem('storefront-key') && sessionStorage.getItem('storefront-ownerKey'));
  assert.equal(posts.length, 0, 'Introduction must not advance any business step');
  await page.locator('.hero [data-demo]').click();
  await page.waitForURL(`${runtime.baseUrl}/demo/`);
  store = await (await page.locator('#store-frame').elementHandle()).contentFrame(); mechanism = await (await page.locator('#mechanism-frame').elementHandle()).contentFrame();
  await mechanism.locator('#live-connection[data-state="connected"]').waitFor(); await store.locator('.products__list__list-item').nth(8).waitFor();
  assert.equal(await mechanism.locator('.scene-node').count(), 6); assert.equal(await store.locator('.products__list__list-item').count(), 9);
  const sheets = await store.evaluate(() => [...document.styleSheets].map(sheet => new URL(sheet.href).pathname)); assert.deepEqual(sheets, ['/store/mystore/fonts/inter.css', '/store/mystore/vendors.css', '/store/mystore/main.css']);
  const catalog = (await api('/api/store/catalog')).data.products;
  for (const product of catalog) { await detail(product.id); assert.equal((await store.locator('.product-detail__title').innerText()).replace(/\s/g, ''), (product.title || product.name).replace(/\s/g, ''));
    assert((await store.locator('.product-detail__price').innerText()).includes((product.unitAmountMinor / 1000000).toFixed(2))); assert(/[\u3400-\u9fff]/.test(await store.locator('.product-detail__description').innerText()));
    await store.locator('.product-detail__product').scrollIntoViewIfNeeded(); await store.waitForFunction(() => { const image = document.querySelector('.product-detail__product'); return image?.complete && image.naturalWidth > 0; });
    assert.equal(await store.locator('.recommendations .products__list__list-item').count(), 4); }
  await store.locator('.header__link').click(); await shot('01-complete-official-store.png');
  await pass('Complete nine-product Chinese official storefront and six-role hub scene are present');
  await add('02'); const selected = await add('03'); assert.equal(selected.totalMinor, 34980000); await store.locator('.shopping-cart__link').click();
  const beforeCheckout = await live(); const created = await click(store, '.cart_checkout-button', '/api/store/checkout');
  assert.equal(created.phase, 'verifying'); let current = await live(); assert.equal(signatures(current), signatures(beforeCheckout)); assert.equal(current.core.manual.stage, 'IDLE'); assert.equal(current.core.credential, null);
  assert.equal(await store.locator('#local-payment-confirm').count(), 0); await idle('checkout creates only the signed order', 4000); await shot('02-await-manual-qualification.png');
  await pass('Checkout stops before credential, device, proof and Owner; four seconds of inactivity makes no mutation');
  const bad = await api('/api/store/manual', bodyFor(await live(), 'begin-authorize')); assert.equal(bad.status, 409); current = await live(); assert.deepEqual(ledger(current), ledger(initial));
  const stale = await api('/api/store/manual', { ...bodyFor(current, 'issue'), controlToken: 'old-console-token' }); assert.equal(stale.status, 409);
  await step('issue', { double: true }); await step('begin-proposal');
  if (process.env.MANUAL_EXPIRY_CHECK !== '0') {
    const before = await live(), count = posts.length; console.log('Checking that a real 60-second challenge expires without automatic renewal.');
    const waitMs = Math.max(0, before.core.manual.expiresAtUnix * 1000 - Date.now() + 1100); await delay(Math.min(31000, waitMs)); await delay(Math.max(0, waitMs - 31000));
    const expired = await live(); assert.equal(expired.core.manual.expired, true); assert.equal(expired.core.manual.attemptId, before.core.manual.attemptId);
    assert.equal(signatures(expired), signatures(before)); assert.deepEqual(ledger(expired), ledger(before)); assert.equal(posts.length, count); assert.equal(expired.store.manualControl.nextAction, 'begin-proposal');
    const restarted = await step('begin-proposal'); assert.notEqual(restarted.after.core.manual.attemptId, before.core.manual.attemptId); assert.equal(signatures(restarted.after), signatures(before));
    const oldAttempt = await api('/api/store/manual', { ...bodyFor(restarted.after, 'derive-vc'), attemptId: before.core.manual.attemptId }); assert.equal(oldAttempt.status, 409);
    await pass('Real challenge expiry stays stopped; explicit fresh challenge does not call the device and stale attempts are rejected', { waitedMs: waitMs });
  }
  for (const action of ['derive-vc', 'device-sign', 'prove', 'verify']) await step(action);
  current = await live(); assert.equal(current.core.manual.verificationResult.verificationTrace.outcome, 'pass'); assert.equal(current.store.phase, 'verifying'); assert.equal(await store.locator('#local-payment-confirm').count(), 0);
  await shot('03-qualification-before-owner-submission.png'); await step('submit-owner'); await store.locator('#local-payment-confirm').waitFor();
  current = await idle('Owner proposal waits for the shopper', 2500); assert.equal(current.core.proposal.status, 'PENDING'); assert.equal(current.core.authorization, null);
  await pass('Every credential/challenge/derived-VC/device/proof/verification/submission step needs its own click; payment opens only after qualification');
  const beforePay = await live(), payCount = posts.filter(path => path === '/api/store/pay').length;
  const approved = await click(store, '#local-payment-confirm', '/api/store/pay', true); assert.equal(approved.phase, 'paying');
  assert.equal(posts.filter(path => path === '/api/store/pay').length - payCount, 1); current = await idle('Shopper approval does not start payment verification', 2500);
  assert.equal(current.core.authorization, null); assert.equal(current.core.manual.walletSigned, false); assert.equal(current.core.manual.phase, 'proposal'); assert.deepEqual(ledger(current), ledger(beforePay));
  await shot('04-shopper-approved-await-console.png');
  await pass('Shopper approval queues payment only; approval does not synchronize, prove, sign or transfer automatically');
  await step('sync-owner'); assert.equal((await live()).core.proposal.status, 'APPROVED');
  for (const action of ['begin-authorize', 'derive-vc', 'device-sign', 'prove', 'verify']) await step(action);
  await step('wallet-sign'); current = await idle('Signed wallet payload waits for a separate settlement challenge', 2000); assert.equal(current.core.manual.walletSigned, true); assert.deepEqual(ledger(current), ledger(initial));
  const blockedReset = await api('/api/store/new', { revision: current.store.revision }); assert.equal(blockedReset.status, 409);
  await shot('05-wallet-signed-no-transfer.png');
  for (const action of ['begin-settle', 'derive-vc', 'device-sign', 'prove']) await step(action);
  current = await live(); assert.deepEqual(ledger(current), ledger(initial)); await step('verify');
  current = await live(); assert.equal(current.store.phase, 'confirming'); assert.equal(current.core.manual.settled, true); assert.equal(current.core.ledger.executionCount, 1); assert.equal(current.store.receipt.transactionStatus, 'success');
  await idle('Real receipt still waits for explicit merchant confirmation', 2500); await shot('06-settled-await-merchant.png');
  await pass('Authorization, wallet signing and settlement are individual operations; only final settle verify transfers once and preserves the original order');
  await step('confirm-merchant'); current = await live(); assert.equal(current.store.phase, 'paid'); assert.equal(current.store.merchant.status, 'confirmed'); assert.equal(current.core.ledger.executionCount, 1);
  await store.waitForFunction(() => document.body.dataset.phase === 'paid'); await store.locator('.status__message').waitFor(); await shot('07-manual-payment-complete.png');
  await writeFile(resolve(output, 'paid-snapshot.json'), JSON.stringify(current, null, 2));
  const paid = current.store; const queried = await api('/api/store/query', { orderId: paid.order.orderId, revision: paid.revision }); assert.equal(queried.status, 200); assert.equal((await live()).core.ledger.executionCount, 1);
  const verifyEvents = current.events.filter(event => event.source === 'original-controller' && event.orderId === paid.order.orderId && event.action === 'verify' && event.status === 'complete' && event.data?.verificationTrace);
  assert.deepEqual(verifyEvents.map(event => event.phase), ['proposal', 'authorize', 'settle']); assert.equal(new Set(verifyEvents.map(event => event.data.challengeId)).size, 3);
  for (const event of verifyEvents) for (const id of ['merchant_order', 'w3c_bbs', 'device_pairing', 'holder_signature', 'credential_status']) assert.equal(event.data.verificationTrace.steps.find(step => step.id === id)?.status, 'pass');
  await pass('Explicit merchant confirmation completes the purchase, all three actual proof traces pass, and querying cannot pay again', { transactionHash: paid.receipt.transactionHash, executionCount: current.core.ledger.executionCount });
  await page.setViewportSize({ width: 1280, height: 900 }); await page.locator('button[data-layout="stack"]').click();
  for (const frame of [store, mechanism]) assert(await frame.evaluate(() => document.documentElement.scrollWidth <= innerWidth)); await page.locator('button[data-layout="side"]').click();
  assert.deepEqual(report.errors, []); assert.deepEqual(report.externalRequests, []); assert.deepEqual(report.failedResources, []);
  await pass('Both layouts remain operable without horizontal overflow, external requests or browser errors'); report.status = 'passed';
} catch (error) { report.status = 'failed'; report.error = redact(error.stack); process.exitCode = 1; console.error(report.error); await shot('failure.png').catch(() => {}); }
finally { report.finishedAt = new Date().toISOString(); await save(); await browser.close(); }
