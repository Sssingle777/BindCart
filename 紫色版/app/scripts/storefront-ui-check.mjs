import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import http from 'node:http';

const runtime = JSON.parse(await readFile(new URL('../var/storefront-runtime.json', import.meta.url)));
const keys = new URLSearchParams(new URL(runtime.url).hash.slice(1));
const output = new URL('../../evidence/storefront/', import.meta.url);
await mkdir(output, { recursive: true });
const report = { startedAt: new Date().toISOString(), checks: [], uiErrors: [], apiRequests: [], externalRequests: [], screenshots: [] };
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: 'zh-CN' });
await context.route('**/*', route => {
  if (new URL(route.request().url()).origin !== runtime.baseUrl) { report.externalRequests.push(route.request().url()); return route.abort(); }
  return route.continue();
});
const page = await context.newPage(); page.setDefaultTimeout(90000);
page.on('pageerror', error => report.uiErrors.push(error.message));
page.on('response', response => {
  const url = new URL(response.url());
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/owner/api/')) report.apiRequests.push({ method: response.request().method(), path: url.pathname, status: response.status() });
});
const pass = (name, evidence = {}) => { report.checks.push({ name, passed: true, ...evidence }); console.log(`PASS ${name}`); };
async function shot(name) { const path = fileURLToPath(new URL(name, output)); await page.waitForTimeout(350); await page.screenshot({ path, fullPage: true }); report.screenshots.push(path); }
async function click(selector, path, status = 200) {
  const pending = page.waitForResponse(r => new URL(r.url()).pathname === path && r.request().method() === 'POST');
  await page.locator(selector).click();
  const response = await pending, result = await response.json();
  assert.equal(response.status(), status, JSON.stringify(result.error));
  await page.waitForFunction(() => !document.body.classList.contains('busy'));
  return result;
}
async function api(path, body, { owner = false, authenticated = true } = {}) {
  const response = await fetch(`${runtime.baseUrl}${path}`, { method: body === undefined ? 'GET' : 'POST', headers: { ...(authenticated ? { [owner ? 'X-Owner-UI-Key' : 'X-Demo-UI-Key']: keys.get(owner ? 'ownerKey' : 'key') } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(90000) });
  return { status: response.status, data: await response.json() };
}
const balances = state => Object.fromEntries(state.backend.ledger.accounts.map(a => [a.id, a.balanceMinor]));
try {
  const unauthenticated = await api('/api/store/state', undefined, { authenticated: false });
  assert.equal(unauthenticated.status, 401); assert.equal(unauthenticated.data.state, undefined);
  const foreignOrigin = await fetch(`${runtime.baseUrl}/api/store/state`, { headers: { 'X-Demo-UI-Key': keys.get('key'), Origin: 'https://example.org' } });
  assert.equal(foreignOrigin.status, 403); assert.equal((await foreignOrigin.json()).state, undefined);
  pass('unauthenticated and foreign-origin requests are denied without disclosing order state');
  let initial = (await api('/api/store/state')).data;
  if (process.argv.includes('--after-restart')) {
    const previous = JSON.parse(await readFile(new URL('ui-verification.json', output)));
    const payment = previous.checks.find(check => check.receipt);
    assert.equal(initial.phase, 'paid'); assert.deepEqual(initial.receipt, payment.receipt);
    assert.deepEqual(balances(initial), payment.balancesAfter);
    const repeated = await api('/api/store/pay', { orderId: initial.order.orderId, revision: initial.revision });
    assert.equal(repeated.status, 200); assert.deepEqual(repeated.data.receipt, initial.receipt);
    assert.deepEqual(balances(repeated.data), payment.balancesAfter);
    pass('service restart preserves receipt and balances; repeating old payment does not transfer again', { previousTransaction: initial.receipt.transactionHash, balances: balances(initial) });
  }
  if (initial.phase !== 'cart' || initial.cart.length) initial = (await api('/api/store/new', { revision: initial.revision })).data;
  let slowRequest;
  const slowResult = new Promise((resolve, reject) => {
    slowRequest = http.request(`${runtime.baseUrl}/api/store/cart`, { method: 'POST', headers: { 'X-Demo-UI-Key': keys.get('key'), 'Content-Type': 'application/json' } }, response => { response.resume(); response.on('end', () => resolve(response.statusCode)); });
    slowRequest.on('error', reject); slowRequest.write('{');
  });
  try {
    for (let attempt = 0; attempt < 30; attempt++) { if ((await api('/api/store/state')).data.busy) break; await new Promise(resolve => setTimeout(resolve, 10)); }
    assert.equal((await api('/api/store/state')).data.busy, true);
    const concurrent = await api('/api/store/new', { revision: initial.revision });
    assert.equal(concurrent.status, 409); assert.equal(concurrent.data.error.code, 'STORE_BUSY');
  } finally { slowRequest.end('}'); }
  assert.equal(await slowResult, 400);
  pass('controller mutations cannot overlap while another request body is arriving');
  await api('/api/store/security', { action: 'unlock' });
  await page.goto(runtime.url);
  await page.locator('[data-add="headphones"]').waitFor();
  await page.waitForFunction(() => [...document.images].every(img => img.complete && img.naturalWidth > 0));
  await shot('01-official-frontend.png');
  let cart = await click('[data-add="headphones"]', '/api/store/cart');
  cart = await click('[data-add="sunglasses"]', '/api/store/cart');
  assert.equal(cart.cart.length, 2); assert.equal(cart.totalMinor, 100_000_000);
  await page.locator('header [data-route="cart"]').click();
  await shot('02-cart.png');
  pass('official frontend updates cart through original-controller adapter', { totalMinor: cart.totalMinor });
  const tamper = await api('/api/store/cart', { productId: 'headphones', quantity: 1, revision: cart.revision, amountMinor: 1 });
  assert.equal(tamper.status, 400); assert.equal(tamper.data.error.code, 'STORE_INPUT_INVALID');
  const stale = await api('/api/store/cart', { productId: 'headphones', quantity: 2, revision: cart.revision - 1 });
  assert.equal(stale.status, 409); assert.equal(stale.data.error.code, 'STORE_STALE_CART');
  pass('backend rejects injected prices and stale cart edits');
  await page.locator('#details-open').click();
  await click('[data-security="issue"]', '/api/store/security');
  await click('[data-security="lock"]', '/api/store/security');
  await page.locator('#details-close').click();
  const locked = await click('#checkout', '/api/store/checkout', 403);
  assert.equal(locked.error.code, 'DBAC_DEVICE_LOCKED'); assert.equal(locked.state.phase, 'cart');
  assert.equal(await page.locator('#checkout-view').isVisible(), false);
  pass('real locked software eSIM blocks checkout');
  await page.locator('#details-open').click();
  await click('[data-security="unlock"]', '/api/store/security');
  await click('[data-security="revoke"]', '/api/store/security');
  await page.locator('#details-close').click();
  const revoked = await click('#checkout', '/api/store/checkout', 403);
  assert.equal(revoked.error.code, 'W3C_CREDENTIAL_REVOKED'); assert.equal(revoked.state.phase, 'cart');
  await page.locator('#details-open').click(); await shot('03-credential-rejected.png');
  pass('real issuer revocation blocks checkout', { verification: revoked.state.verification });
  await click('[data-security="issue"]', '/api/store/security');
  await page.locator('#details-close').click();
  const checkout = await click('#checkout', '/api/store/checkout');
  assert.equal(checkout.phase, 'checkout'); assert.equal(checkout.backend.proposal.status, 'PENDING');
  assert.equal(checkout.verification.outcome, 'pass');
  assert.equal(checkout.order.amountMinor, checkout.totalMinor);
  await page.locator('#checkout-view').waitFor(); await shot('04-payment-window.png');
  pass('original B verifier opens payment page only after actual proof verification', { orderId: checkout.order.orderId, verification: checkout.verification });
  const payload = { orderId: checkout.order.orderId, revision: checkout.revision };
  const before = balances(checkout);
  const noOwner = await api('/api/store/pay', payload);
  assert.equal(noOwner.status, 403); assert.equal(noOwner.data.error.code, 'OWNER_CONFIRMATION_REQUIRED');
  assert.deepEqual(balances(noOwner.data.state), before);
  const changedOrder = await api('/api/store/pay', { ...payload, orderId: 'urn:uuid:00000000-0000-0000-0000-000000000000' });
  assert.equal(changedOrder.status, 409);
  pass('missing owner confirmation and substituted order cannot pay');
  const paid = await click('#confirm-pay', '/api/store/pay');
  assert.equal(paid.phase, 'paid'); assert.equal(paid.receipt.orderId, checkout.order.orderId);
  assert.equal(paid.receipt.transactionStatus, 'success'); assert.equal(paid.receipt.amountMinor, 100_000_000);
  assert.match(paid.receipt.transactionHash, /^0x[0-9a-f]{64}$/);
  assert.equal(before['demo:alice'] - balances(paid)['demo:alice'], paid.totalMinor);
  assert.equal(balances(paid)['merchant:keyboard'] - before['merchant:keyboard'], paid.totalMinor);
  await page.locator('#receipt-view').waitFor(); await shot('05-paid-receipt.png');
  pass('explicit frontend confirmation executes original Owner and x402 payment', { receipt: paid.receipt, balancesBefore: before, balancesAfter: balances(paid) });
  const duplicate = await api('/api/store/pay', payload);
  assert.equal(duplicate.status, 200); assert.equal(duplicate.data.receipt.transactionHash, paid.receipt.transactionHash);
  assert.deepEqual(balances(duplicate.data), balances(paid));
  pass('repeated request returns same receipt without another transfer');
  await page.reload(); await page.locator('#receipt-view').waitFor();
  assert.equal(await page.locator('#receipt-tx').innerText(), paid.receipt.transactionHash);
  pass('browser refresh restores receipt from backend');
  await page.locator('#details-open').click(); await shot('06-backend-evidence.png'); await page.locator('#details-close').click();
  await page.setViewportSize({ width: 390, height: 844 }); await shot('07-mobile.png');
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  assert.deepEqual(report.externalRequests, []); assert.deepEqual(report.uiErrors, []);
  pass('desktop and mobile frontend work with external networking blocked');
  report.status = 'passed';
} catch (error) { report.status = 'failed'; report.error = error.stack; console.error(error.stack); await shot('failure.png').catch(() => {}); process.exitCode = 1; }
finally { report.finishedAt = new Date().toISOString(); await writeFile(new URL('ui-verification.json', output), JSON.stringify(report, null, 2)); await browser.close(); }
