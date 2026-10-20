import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

// Runs one explicitly requested sandbox purchase, including real rejection paths.
// Start launch-adyen.mjs first. No keys or session credentials enter this report.
const runtime = JSON.parse(await readFile(new URL('../var/adyen-runtime.json', import.meta.url)));
const fragment = new URLSearchParams(new URL(runtime.url).hash.slice(1));
const key = fragment.get('key'), ownerKey = fragment.get('ownerKey');
const evidence = new URL('../../evidence/', import.meta.url);
await mkdir(evidence, { recursive: true });
const report = { startedAt: new Date().toISOString(), checks: [], screenshots: [], errors: [] };
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1050 }, locale: 'zh-CN' });
page.setDefaultTimeout(90000);
page.on('pageerror', error => report.errors.push(error.message));
const record = (name, extra = {}) => { report.checks.push({ name, passed: true, ...extra }); console.log(`PASS ${name}`); };
async function shot(name) {
  const path = fileURLToPath(new URL(name, evidence));
  await page.screenshot({ path, fullPage: true });
  report.screenshots.push(path);
}
async function click(id, path, expectedStatus = 200) {
  const pending = page.waitForResponse(r => r.url() === `${runtime.baseUrl}${path}` && r.request().method() === 'POST');
  await page.locator(id).click();
  const response = await pending;
  const result = await response.json();
  assert.equal(response.status(), expectedStatus, JSON.stringify(result.error));
  await page.waitForFunction(() => !document.body.classList.contains('is-busy'));
  return result;
}
async function api(path, { method = 'POST', owner = false, body = {}, authenticated = true } = {}) {
  const response = await fetch(`${runtime.baseUrl}${path}`, {
    method, headers: { ...(authenticated ? { 'X-Demo-UI-Key': key } : {}), ...(owner ? { 'X-Owner-UI-Key': ownerKey } : {}), 'Content-Type': 'application/json' },
    ...(method !== 'GET' ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(90000),
  });
  return { status: response.status, data: await response.json() };
}
try {
  const unauthorised = await api('/api/adyen/state', { method: 'GET', authenticated: false });
  assert.equal(unauthorised.status, 401); record('unauthenticated local access rejected');
  await page.goto(runtime.url);
  await page.waitForFunction(() => document.getElementById('status').textContent.includes('连接官方演示商城'));
  await shot('integrated-01-home.png');
  const cart = await click('#main-action', '/api/adyen/connect');
  assert.equal(cart.phase, 'cart'); assert.equal(cart.order.productName, 'Headphones');
  assert.equal(cart.order.quantity, 1); assert.equal(cart.order.currency, 'EUR');
  assert(cart.order.amountMinor > 0); assert.equal(cart.order.providerReference, null);
  assert.equal(await page.locator('#price').innerText(), `€${(cart.order.amountMinor / 100).toFixed(2)}`);
  await page.waitForFunction(() => document.getElementById('product-image').complete && document.getElementById('product-image').naturalWidth > 0);
  record('official product and live cart loaded', { orderId: cart.order.id, amountMinor: cart.order.amountMinor });
  await shot('integrated-02-cart.png');
  const injection = await api('/api/adyen/checkout', { body: { amountMinor: 1 } });
  assert.equal(injection.status, 400); assert.equal(injection.data.error.code, 'SHOP_INPUT_INVALID');
  record('client supplied payment amount rejected');
  await page.locator('#details-toggle').click();
  const missingDevice = await click('#attack', '/api/adyen/attack');
  assert.equal(missingDevice.phase, 'cart'); assert.equal(missingDevice.verification.accepted, false);
  assert.equal(missingDevice.verification.error, 'W3C_DEVICE_PROOF_REQUIRED');
  assert.equal(missingDevice.providerSession, undefined);
  record('missing device proof blocks checkout', { steps: missingDevice.verification.steps });
  await shot('integrated-03-device-rejected.png');
  await click('#revoke', '/api/adyen/revoke');
  const revoked = await click('#main-action', '/api/adyen/checkout', 403);
  assert.equal(revoked.error.code, 'W3C_CREDENTIAL_REVOKED'); assert.equal(revoked.state.phase, 'cart');
  assert.equal(revoked.state.providerSession, undefined);
  record('revoked credential blocks checkout', { code: revoked.error.code });
  await click('#reissue', '/api/adyen/reissue');
  await page.locator('#details-close').click();
  const checkout = await click('#main-action', '/api/adyen/checkout');
  assert.equal(checkout.phase, 'checkout'); assert.equal(checkout.verification.accepted, true);
  assert(checkout.verification.steps.length >= 6);
  assert(checkout.order.providerReference); assert.equal(checkout.providerSession.amount.value, cart.order.amountMinor);
  await page.locator('#payment-dialog[open]').waitFor();
  await page.locator('#checkout-preview:not([hidden])').waitFor();
  await shot('integrated-04-checkout.png');
  record('valid VC, holder and device proofs open official checkout', { steps: checkout.verification.steps, providerSession: checkout.providerSession });
  const unconfirmed = await api('/api/adyen/pay');
  assert.equal(unconfirmed.status, 403); assert.equal(unconfirmed.data.error.code, 'OWNER_CONFIRMATION_REQUIRED');
  assert.equal(unconfirmed.data.state.phase, 'checkout'); assert.equal(unconfirmed.data.state.result, null);
  record('missing owner confirmation blocks payment');
  const paid = await click('#pay', '/api/adyen/pay');
  assert.equal(paid.phase, 'paid'); assert.equal(paid.result.resultCode, 'Authorised');
  assert.equal(paid.result.testOnly, true); assert.equal(paid.result.providerReference, checkout.order.providerReference);
  assert.equal(paid.result.sessionId, checkout.providerSession.id);
  assert.equal(paid.result.amountMinor, cart.order.amountMinor);
  assert.equal(paid.result.source, 'checkoutshopper-test.adyen.com network response');
  assert.notEqual(paid.verification.orderHash, checkout.verification.orderHash);
  await page.locator('#payment-dialog').waitFor({ state: 'hidden' });
  await page.locator('#receipt:not([hidden])').waitFor();
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
  await shot('integrated-05-paid.png');
  record('official sandbox payment authorised with reference-bound fresh proof', { result: paid.result, verification: paid.verification });
  const duplicate = await api('/api/adyen/pay', { owner: true });
  assert.equal(duplicate.status, 409); assert.equal(duplicate.data.state.phase, 'paid');
  assert.deepEqual(duplicate.data.state.result, paid.result);
  record('duplicate payment rejected without changing provider result');
  await page.setViewportSize({ width: 390, height: 844 });
  await shot('integrated-06-mobile.png');
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  record('mobile layout has no horizontal overflow');
  assert.deepEqual(report.errors, []); record('local UI has no uncaught browser errors');
  report.status = 'passed';
} catch (error) {
  report.status = 'failed'; report.failure = error.stack;
  await shot('integrated-failure.png').catch(() => {});
  console.error(error.stack); process.exitCode = 1;
} finally {
  report.finishedAt = new Date().toISOString();
  await writeFile(new URL('integrated-check.json', evidence), JSON.stringify(report, null, 2));
  await browser.close();
}
