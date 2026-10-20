import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';

// A separate real-service instance: no existing demo or order is read/mutated.
// The test intentionally locks the device, then recovers without any payment.
const app = resolve(import.meta.dirname, '..');
const output = resolve(process.env.MANUAL_RECOVERY_OUTPUT_PATH ?? resolve(app, '../evidence/manual-recovery-ui'));
const run = resolve(output, 'runs', `${Date.now()}-${randomUUID().slice(0, 8)}`);
const runtimePath = resolve(run, 'runtime.json'), statePath = resolve(run, 'state');
await mkdir(run, { recursive: true });
const report = { startedAt: new Date().toISOString(), isolatedInstance: true, realCryptoAndChain: true,
  localTestOnly: true, paymentAttempted: false, checks: [], manualClicks: [], screenshots: [], pageErrors: [], externalRequests: [], resourceFailures: [] };
let runtime, browser, page, store, mechanism, childOutput = '';
const capabilities = new Map();
const redact = value => { let text = String(value); for (const value of capabilities.values()) if (value) text = text.replaceAll(value, '[redacted]'); return text; };
const save = () => writeFile(resolve(output, 'verification.json'), JSON.stringify(report, null, 2));
const pass = async (name, details = {}) => { report.checks.push({ name, passed: true, ...details }); console.log(`PASS ${name}`); await save(); };
const child = spawn(process.execPath, [resolve(app, 'launch-dual.mjs')], { cwd: app, windowsHide: true,
  env: { ...process.env, DUAL_PORT: '0', DUAL_STATE_DIR: statePath, DUAL_RUNTIME_PATH: runtimePath, DUAL_STAGE_DELAY_MS: '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
for (const stream of [child.stdout, child.stderr]) stream.on('data', value => { childOutput = (childOutput + value).slice(-24000); });
const childExit = new Promise(ready => { child.once('exit', (code, signal) => ready({ code, signal })); child.once('error', error => ready({ error: error.message })); });
async function api(path, body) {
  const response = await fetch(runtime.baseUrl + path, { method: body === undefined ? 'GET' : 'POST',
    headers: { 'X-Demo-UI-Key': capabilities.get('key'), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(120000) });
  return { status: response.status, data: await response.json() };
}
const live = async () => (await api('/api/live/state')).data;
const ledger = snapshot => ({ executions: snapshot.core.ledger.executionCount,
  accounts: snapshot.core.ledger.accounts.map(({ id, balanceMinor }) => ({ id, balanceMinor })) });
const posts = [];
async function shot(name) { await page.screenshot({ path: resolve(output, name), fullPage: true }); report.screenshots.push(name); }
async function click(frame, selector, path) {
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === path && response.request().method() === 'POST');
  await frame.locator(selector).click({ noWaitAfter: true });
  const response = await pending; return { status: response.status(), data: await response.json() };
}
async function manual() {
  const before = await live(), action = before.store.manualControl.nextAction;
  assert(action, 'The real controller must recommend an explicit next action');
  await mechanism.waitForFunction(action => { const button = document.querySelector('#live-manual-next'); return button?.dataset.action === action && !button.disabled; }, action);
  const count = posts.filter(path => path === '/api/store/manual').length;
  const returned = await click(mechanism, '#live-manual-next', '/api/store/manual');
  const after = await live();
  assert.equal(posts.filter(path => path === '/api/store/manual').length - count, 1);
  assert.deepEqual(ledger(after), ledger(before), 'Recovery operations must not transfer tokens');
  report.manualClicks.push({ action, status: returned.status, error: returned.data.error?.code ?? null,
    phase: after.store.phase, stage: after.core.manual.stage, executionCount: after.core.ledger.executionCount });
  await save(); return { ...returned, after };
}
async function addAndCheckout() {
  await store.locator('.header__link').click();
  await store.locator('a[href="#/product/02"]').first().click(); await store.locator('.product-detail__title').waitFor();
  const added = await click(store, '.product-detail__button', '/api/store/cart'); assert.equal(added.status, 200);
  await store.locator('.shopping-cart__link').click();
  const created = await click(store, '.cart_checkout-button', '/api/store/checkout'); assert.equal(created.status, 200); assert.equal(created.data.phase, 'verifying');
  return created.data;
}
async function cancel() {
  await mechanism.waitForFunction(() => { const button = document.querySelector('#live-manual-cancel'); return button && !button.hidden && !button.disabled; });
  const result = await click(mechanism, '#live-manual-cancel', '/api/store/new'); assert.equal(result.status, 200); assert.equal(result.data.phase, 'cart');
  await mechanism.waitForFunction(() => document.querySelector('#live-phase')?.dataset.phase === 'cart');
  return live();
}
try {
  const deadline = Date.now() + 120000;
  while (!runtime && Date.now() < deadline) {
    try { runtime = JSON.parse(await readFile(runtimePath, 'utf8')); } catch { if (child.exitCode !== null) throw new Error('Isolated launcher stopped before readiness'); await delay(250); }
  }
  assert(runtime, 'Isolated launcher did not become ready'); assert.equal(runtime.pid, child.pid); assert.equal(runtime.stateDirectory, statePath);
  const parsed = new URLSearchParams(new URL(runtime.url).hash.slice(1));
  for (const name of ['key', 'ownerKey']) capabilities.set(name, parsed.get(name));
  report.instance = { supervisorPid: runtime.pid, baseUrl: runtime.baseUrl, stateDirectory: statePath, stageDelayMs: runtime.stageDelayMs };
  browser = await launchAcceptanceBrowser({ headless: true });
  const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, locale: 'zh-CN' });
  await context.route('**/*', route => { if (new URL(route.request().url()).origin !== runtime.baseUrl) { report.externalRequests.push(new URL(route.request().url()).origin); return route.abort(); } return route.continue(); });
  page = await context.newPage(); page.setDefaultTimeout(120000);
  page.on('pageerror', error => report.pageErrors.push(redact(error.message)));
  page.on('request', request => { if (request.method() === 'POST') posts.push(new URL(request.url()).pathname); });
  page.on('response', response => { const path = new URL(response.url()).pathname; if (response.status() >= 400 && /\.(?:js|css|png|svg|woff2)$/.test(path)) report.resourceFailures.push({ path, status: response.status() }); });
  await page.goto(runtime.url);
  store = await (await page.locator('#store-frame').elementHandle()).contentFrame(); mechanism = await (await page.locator('#mechanism-frame').elementHandle()).contentFrame();
  await mechanism.locator('#live-connection[data-state="connected"]').waitFor(); await store.locator('.products__list__list-item').nth(8).waitFor();
  const initial = await live(); assert.equal(initial.store.phase, 'cart'); assert.equal(initial.core.ledger.executionCount, 0);
  await mechanism.locator('#live-security-details').evaluate(detail => { detail.open = true; });
  const locked = await click(mechanism, '[data-security="lock"]', '/api/store/security'); assert.equal(locked.status, 200);
  await addAndCheckout();
  let failure;
  for (let count = 0; count < 8; count++) {
    const result = await manual();
    if (result.status >= 400) { failure = result; break; }
    assert.equal(result.status, 200);
  }
  assert(failure, 'Locked real device must reject credential enrollment or device signing');
  assert.equal(failure.status, 403); assert.equal(failure.data.error.code, 'DBAC_DEVICE_LOCKED');
  assert.deepEqual(ledger(failure.after), ledger(initial));
  const postCount = posts.length; await delay(1500); assert.equal(posts.length, postCount, 'Failure must not retry automatically');
  await mechanism.locator('#live-manual-status').filter({ hasText: '未完成' }).waitFor();
  await shot('01-locked-device-rejected.png');
  await pass('Locked software eSIM rejects an explicit step and stays stopped without a transfer', { code: failure.data.error.code, failedAction: report.manualClicks.at(-1).action });
  const cancelled = await cancel(); assert.deepEqual(ledger(cancelled), ledger(initial)); assert.equal(cancelled.core.manual.active, false);
  await shot('02-explicitly-cancelled-to-cart.png');
  await pass('Explicit console cancel returns safely to the cart and releases management controls');
  await mechanism.waitForFunction(() => !document.querySelector('[data-security="unlock"]').disabled);
  const unlocked = await click(mechanism, '[data-security="unlock"]', '/api/store/security'); assert.equal(unlocked.status, 200);
  await addAndCheckout();
  let recovered;
  for (let count = 0; count < 8; count++) {
    const result = await manual(); assert.equal(result.status, 200, JSON.stringify(result.data.error));
    if (result.after.core.manual.stage === 'VERIFIED') { recovered = result.after; break; }
  }
  assert(recovered, 'Unlocked device must support complete real qualification');
  assert.equal(recovered.core.manual.phase, 'proposal'); assert.equal(recovered.core.manual.verificationResult.verificationTrace.outcome, 'pass');
  assert.equal(recovered.store.phase, 'verifying'); assert.equal(recovered.core.proposal, null); assert.deepEqual(ledger(recovered), ledger(initial));
  await shot('03-unlocked-and-qualification-restored.png');
  await pass('After unlocking, a new order reaches actual B qualification through individual manual clicks', { outcome: 'pass', stage: recovered.core.manual.stage });
  const final = await cancel(); assert.deepEqual(ledger(final), ledger(initial)); assert.equal(final.store.phase, 'cart');
  assert(posts.every(path => path !== '/api/store/pay' && !path.startsWith('/owner/')), 'Recovery test must never request Owner approval or payment');
  assert.deepEqual(report.pageErrors, []); assert.deepEqual(report.externalRequests, []); assert.deepEqual(report.resourceFailures, []);
  await pass('Final safe cancel leaves zero payments, no Owner approvals, no automatic retries and no browser errors');
  report.status = 'passed';
} catch (error) {
  report.status = 'failed'; report.error = redact(error.stack); process.exitCode = 1;
  console.error(report.error); if (page) await shot('failure.png').catch(() => {});
} finally {
  await browser?.close();
  try {
    if (runtime) { const result = await api('/api/shutdown', {}); report.shutdownRequested = result.status === 200; }
    else child.kill('SIGTERM');
    let ended = await Promise.race([childExit, delay(15000).then(() => null)]);
    if (!ended) { child.kill('SIGTERM'); ended = await Promise.race([childExit, delay(10000).then(() => null)]); }
    report.isolatedInstanceStopped = Boolean(ended); report.supervisorExit = ended;
    if (runtime) { let reachable = false; try { reachable = (await fetch(runtime.baseUrl + '/api/health', { signal: AbortSignal.timeout(2000) })).ok; } catch { /* stopped */ } report.isolatedPortClosed = !reachable; }
  } catch (error) { report.shutdownError = redact(error.message); child.kill('SIGTERM'); }
  if (!report.isolatedInstanceStopped || report.isolatedPortClosed === false) { report.status = 'failed'; process.exitCode = 1; }
  if (report.status !== 'passed') report.launcherDiagnostics = redact(childOutput);
  report.finishedAt = new Date().toISOString(); await save();
}
