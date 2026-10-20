// Isolated, real-service acceptance. No fixtures or fallback success data.
//   node scripts/scenario-stage-acceptance.mjs --serve
//   SCENARIO_PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
//     node scripts/scenario-stage-acceptance.mjs --browser
//   node scripts/scenario-stage-acceptance.mjs --open --access <private access.json>
// Launcher capabilities are kept only in an ignored 0600 file. Never print them.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, writeFile, chmod } from 'node:fs/promises';
import { join, resolve, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { planPayment } from '../public/guide-model.js';
import { guidePaymentReceipt } from '../public/guide-progress.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const args = new Set(process.argv.slice(2));
const option = name => {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
};
const inProject = path => {
  const result = resolve(root, path);
  assert.ok(!relative(root, result).startsWith('..'), 'acceptance artifacts must remain in the project');
  return result;
};
const outputDirectory = inProject(option('--output') || 'docs/scenario-stage-acceptance');
let server, browser, access, stopped = false;
let secrets = [];
const report = { source: 'real isolated local services; no fixture state', screenshots: [], actions: [], experiments: [], layouts: [], checks: [], errors: [], consoleErrors: [], resourceFailures: [] };
const redact = value => {
  let result = String(value ?? '');
  for (const secret of secrets) result = result.split(secret).join('[private capability omitted]');
  return result.replace(/(?:ownerKey|key)=[A-Za-z0-9_-]{43}/g, 'private-capability=omitted');
};
async function saveReport() {
  await mkdir(outputDirectory, { recursive: true });
  await writeFile(join(outputDirectory, args.has('--cross-scene') ? 'cross-scene-results.json' : 'browser-results.json'), redact(JSON.stringify(report, null, 2)) + '\n');
}
async function launch() {
  await mkdir(join(root, '.runtime'), { recursive: true });
  const directory = await mkdtemp(join(root, '.runtime', 'scenario-stage-'));
  await chmod(directory, 0o700);
  server = spawn(process.execPath, ['launch.mjs'], {
    cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PORT: '0', AGENT_B_PORT: '0', ESIM_PORT: '0', OWNER_PORT: '0', PAYMENT_DB: join(directory, 'payment.sqlite'), X402_STATE_DIR: join(directory, 'x402') },
  });
  let buffer = '', startupFailure = false;
  server.stdout.on('data', data => { buffer = (buffer + data).slice(-100000); });
  // Upstream stderr can include sensitive command context. Never persist it.
  server.stderr.on('data', () => {});
  server.on('error', () => { startupFailure = true; });
  for (let i = 0; i < 1800; i++) {
    assert.ok(!startupFailure && server.exitCode === null, 'isolated launcher exited before readiness');
    const match = buffer.match(/(http:\/\/127\.0\.0\.1:\d+)\/#key=([A-Za-z0-9_-]{43})&ownerKey=([A-Za-z0-9_-]{43})/);
    if (match) {
      const [, baseUrl, uiKey, ownerKey] = match;
      access = { baseUrl, uiKey, ownerKey, launcherPid: server.pid, stateDirectory: directory };
      secrets = [uiKey, ownerKey];
      buffer = ''; server.stdout.removeAllListeners('data'); server.stdout.on('data', () => {});
      const path = join(directory, 'access.json');
      await writeFile(path, JSON.stringify(access), { mode: 0o600 });
      console.log(`Isolated service ready: ${baseUrl}/#view=guide&scenario=normal`);
      console.log(`Private access artifact (never publish): ${path}`);
      return access;
    }
    await delay(100);
  }
  throw new Error('isolated service did not become ready within 180 seconds');
}
async function shutdown() {
  if (stopped) return;
  stopped = true;
  await browser?.close().catch(() => {});
  if (server?.pid) {
    try { process.kill(-server.pid, 'SIGTERM'); } catch {}
    await Promise.race([new Promise(resolve => server.once('exit', resolve)), delay(4000)]);
    if (server.exitCode === null) try { process.kill(-server.pid, 'SIGKILL'); } catch {}
  }
}
async function api(path) {
  const response = await fetch(`${access.baseUrl}${path}`, { headers: { 'X-Demo-UI-Key': access.uiKey }, signal: AbortSignal.timeout(15000), cache: 'no-store' });
  const value = await response.json();
  assert.equal(response.status, 200, `read-only API status ${response.status} at ${path.split('?')[0]}`);
  return value;
}
async function waitUntil(check, description, timeout = 60000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) { const value = await check(); if (value) return value; await delay(100); }
  throw new Error(`Timed out: ${description}`);
}
async function crossSceneAcceptance() {
  const modulePath = process.env.SCENARIO_PLAYWRIGHT_MODULE;
  const { chromium } = await import(modulePath ? pathToFileURL(resolve(modulePath)).href : 'playwright');
  browser = await chromium.launch({ headless: true, channel: 'chrome' });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
  await context.addInitScript(({ origin, uiKey, ownerKey }) => {
    if (location.origin !== origin) return;
    sessionStorage.setItem('a2a-did-vc-ui-key', uiKey);
    sessionStorage.setItem('a2a-owner-ui-key', ownerKey);
  }, { origin: access.baseUrl, uiKey: access.uiKey, ownerKey: access.ownerKey });
  const page = await context.newPage(), writes = [];
  page.on('pageerror', error => report.errors.push(redact(error.message)));
  page.on('request', request => { if (request.method() === 'POST') writes.push(new URL(request.url()).pathname); });
  await page.goto(`${access.baseUrl}/#view=guide&scenario=normal`);
  const frame = page.frameLocator('#frame-guide');
  const idle = async () => { await frame.locator('#guide-normal[aria-busy="false"]').waitFor(); await page.waitForTimeout(80); };
  await idle();
  for (const expected of ['issue', 'begin-proposal']) {
    const value = await api('/api/dbac/payment/state?mode=bbs-bls');
    assert.equal(planPayment(value, { ownerAvailable: true }).id, expected);
    await frame.locator('#guide-main').click(); await idle();
  }
  const original = await api('/api/dbac/payment/state?mode=bbs-bls');
  assert.equal(original.manual.stage, 'VC_DERIVED');
  assert.ok(original.manual.expiresAtUnix * 1000 > Date.now());
  const before = writes.length;
  await page.locator('#scenario-copied-vc').click();
  await frame.locator('#guide-experiment').waitFor({ state: 'visible' });
  const progress = await frame.locator('#guide-progress').innerText();
  assert.match(progress, /合法控制组/); assert.match(progress, /复制公开 VC/);
  console.log('Waiting for the original 60-second server challenge to expire naturally; no renewal or time override.');
  while (Date.now() < original.manual.expiresAtUnix * 1000 + 1600) await delay(Math.min(1000, original.manual.expiresAtUnix * 1000 + 1600 - Date.now()));
  assert.equal(await frame.locator('#guide-progress').innerText(), progress, 'retained normal challenge tick cannot overwrite experiment progress');
  await frame.locator('#guide-main').evaluate(node => node.click());
  await page.waitForTimeout(120);
  assert.equal(writes.length, before, 'stale hidden normal action cannot write in an experiment');
  await frame.locator('#guide-refresh').click();
  await page.waitForTimeout(180);
  assert.equal(await frame.locator('#guide-progress').innerText(), progress);
  await page.locator('#scenario-revoked').click();
  await waitUntil(async () => (await frame.locator('#guide-progress').innerText()).includes('撤销实验凭证'), 'revoked progress');
  await frame.locator('#guide-refresh').click(); await page.waitForTimeout(180);
  assert.match(await frame.locator('#guide-progress').innerText(), /撤销实验凭证/);
  await page.reload();
  await waitUntil(async () => (await frame.locator('#guide-progress').innerText().catch(() => '')).includes('撤销实验凭证'), 'revoked refresh progress');
  assert.equal(writes.length, before, 'scene changes, refresh and page reload never renew expired normal challenge or start experiments');
  await page.locator('#scenario-normal').click(); await idle();
  const recovered = await api('/api/dbac/payment/state?mode=bbs-bls');
  assert.equal(recovered.order.orderId, original.order.orderId);
  assert.equal(recovered.manual.challenge.challengeId, original.manual.challenge.challengeId);
  assert.equal(recovered.manual.expired, true);
  assert.match(await frame.locator('#guide-clock').innerText(), /已过期 0 秒/);
  const resumedPlan = planPayment(recovered, { ownerAvailable: true });
  assert.equal(resumedPlan.id, 'begin-proposal');
  assert.equal(resumedPlan.enabled, true);
  assert.equal(await frame.locator('#guide-main').isEnabled(), true, 'only an explicit click may request new material after expiration');
  assert.equal(writes.length, before, 'returning normal observes original expiration with no new order or challenge');
  assert.deepEqual(report.errors, []);
  report.checks.push({ check: 'natural challenge expiry preserves B/C progress and blocks a stale hidden normal action', passed: true, orderId: original.order.orderId, challengeId: original.manual.challenge.challengeId, expiresAtUnix: original.manual.expiresAtUnix, expiredObserved: recovered.manual.expired, readOnlyWrites: writes.length - before, scenarios: ['copied-vc', 'revoked'], normalReturnedPlan: resumedPlan.id, normalReturnedAction: await frame.locator('#guide-main').innerText() });
  report.passed = true; await saveReport();
  console.log('Cross-scene natural-expiration browser acceptance passed.');
}
async function browserAcceptance() {
  const modulePath = process.env.SCENARIO_PLAYWRIGHT_MODULE;
  const { chromium } = await import(modulePath ? pathToFileURL(resolve(modulePath)).href : 'playwright');
  browser = await chromium.launch({ headless: true, channel: 'chrome' });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
  // Load the real launch capabilities without putting them in the visible URL.
  await context.addInitScript(({ origin, uiKey, ownerKey }) => {
    if (location.origin !== origin) return;
    sessionStorage.setItem('a2a-did-vc-ui-key', uiKey);
    sessionStorage.setItem('a2a-owner-ui-key', ownerKey);
  }, { origin: access.baseUrl, uiKey: access.uiKey, ownerKey: access.ownerKey });
  const page = await context.newPage();
  const writes = [];
  page.on('pageerror', error => report.errors.push(redact(error.message)));
  page.on('console', message => { if (message.type() === 'error') report.consoleErrors.push(redact(message.text())); });
  page.on('response', response => { if (response.status() >= 400) report.resourceFailures.push({ path: new URL(response.url()).pathname, status: response.status() }); });
  page.on('request', request => {
    if (request.method() !== 'POST') return;
    const path = new URL(request.url()).pathname;
    let body; try { body = request.postDataJSON(); } catch {}
    writes.push({ path, ...(path === '/api/dbac/payment/manual' ? { action: body?.action, mode: body?.mode } : {}), ...(path === '/api/dbac/payment/experiment-runs' ? { runId: body?.runId, scenarioId: body?.scenarioId, mode: body?.mode } : {}) });
  });
  await page.goto(`${access.baseUrl}/#view=guide&scenario=normal`);
  const frame = page.frameLocator('#frame-guide');
  const idle = async () => {
    await frame.locator('#guide-normal[aria-busy="false"]').waitFor({ timeout: 60000 });
    await page.waitForTimeout(50);
  };
  const read = mode => api(`/api/dbac/payment/state?mode=${mode}`);
  const screenshot = async (label, { width = 1440, height = 900 } = {}) => {
    await page.setViewportSize({ width, height });
    await page.evaluate(() => scrollTo(0, 0));
    await frame.locator('body').evaluate(() => scrollTo(0, 0));
    await page.waitForTimeout(120);
    for (const current of page.frames()) {
      const text = await current.locator('body').textContent().catch(() => '');
      assert.ok(!secrets.some(secret => text.includes(secret)), 'no private capability in rendered page text');
    }
    const outer = await page.evaluate(() => ({ width: innerWidth, scroll: document.documentElement.scrollWidth }));
    const inner = await frame.locator('body').evaluate(() => ({ width: innerWidth, scroll: document.documentElement.scrollWidth,
      visiblePanels: [...document.querySelectorAll('.guide-step-panel')].filter(node => node.getClientRects().length).length,
      nodes: [...document.querySelectorAll('.scene-node')].map(node => { const box=node.getBoundingClientRect(); return { id:node.dataset.node, left:box.left, top:box.top, right:box.right, bottom:box.bottom }; }),
      messages: [...document.querySelectorAll('.scene-message')].filter(node=>node.getClientRects().length).map(node=>{const box=node.getBoundingClientRect();return{left:box.left,top:box.top,right:box.right,bottom:box.bottom};}),
      mainButton: (() => { const node = [...document.querySelectorAll('#guide-main, [data-experiment-action="run"], [data-experiment-action="evidence"], #guide-show-receipt')].find(node => node.getClientRects().length); const box = node?.getBoundingClientRect(); return box ? { top: box.top, bottom: box.bottom, left: box.left, right: box.right } : null; })(),
    }));
    report.layouts.push({ label, width, height, outer, inner });
    assert.ok(outer.scroll <= outer.width + 1 && inner.scroll <= inner.width + 1, `no horizontal overflow at ${label}/${width}`);
    assert.equal(inner.visiblePanels, 1, 'one current-step panel');
    const frameBox = await page.locator('#frame-guide').boundingBox();
    if (width >= 1300 && inner.mainButton) assert.ok(inner.mainButton.bottom + frameBox.y <= height + 1, `current primary action fits ${width}x${height} first view`);
    for (const [index, node] of inner.nodes.entries()) {
      assert.ok(node.left >= -1 && node.right <= inner.width + 1, `role ${node.id} stays inside ${width}px view`);
      for (const other of inner.nodes.slice(index + 1)) assert.ok(Math.min(node.right, other.right) - Math.max(node.left, other.left) <= 1 || Math.min(node.bottom, other.bottom) - Math.max(node.top, other.top) <= 1, `roles ${node.id}/${other.id} do not overlap at ${width}px`);
      for (const message of inner.messages) assert.ok(Math.min(node.right, message.right) - Math.max(node.left, message.left) <= 1 || Math.min(node.bottom, message.bottom) - Math.max(node.top, message.top) <= 1, `message labels do not overlap role ${node.id} at ${width}px`);
    }
    const path = join(outputDirectory, `${label}-${width}x${height}.png`);
    await page.screenshot({ path, fullPage: true });
    report.screenshots.push({ file: relative(root, path), label, width, height, source: report.source });
    if (width < 900) {
      const primary = frame.locator('.guide-step-panel .guide-panel-actions .primary:visible').first();
      await primary.scrollIntoViewIfNeeded();
      const bounds = await primary.boundingBox();
      assert.ok(bounds && bounds.x >= -1 && bounds.x + bounds.width <= width + 1 && bounds.y >= -1 && bounds.y + bounds.height <= height + 1, 'narrow view keeps current operation reachable by natural scrolling');
      const actionPath = join(outputDirectory, `${label}-${width}x${height}-action.png`);
      await page.screenshot({ path: actionPath });
      report.screenshots.push({ file: relative(root, actionPath), label: `${label} current action after natural scrolling`, width, height, source: report.source });
    }
  };
  const captureSizes = async label => {
    for (const [width, height] of [[1920, 1080], [1440, 900], [1366, 768], [390, 844]]) await screenshot(label, { width, height });
    await page.setViewportSize({ width: 1440, height: 900 });
  };
  await idle();
  assert.equal(await frame.locator('#guide-pace').inputValue(), 'guided', 'default keeps existing preparation grouping');
  const initial = await read('bbs-bls');
  assert.equal(Boolean(initial.credential), false);
  assert.doesNotMatch(await frame.locator('#guide-result-title').innerText(), /已完成|验证通过/);
  await screenshot('initial');
  const unprivilegedContext = await browser.newContext();
  const unprivilegedPage = await unprivilegedContext.newPage();
  await unprivilegedPage.goto(`${access.baseUrl}/#view=guide&scenario=normal`);
  const unprivilegedFrame = unprivilegedPage.frameLocator('#frame-guide');
  await waitUntil(async () => (await unprivilegedFrame.locator('#guide-environment').innerText().catch(() => '')).includes('权限'), 'missing capability clearly reported');
  assert.equal(await unprivilegedFrame.locator('#guide-main').isDisabled(), true);
  assert.doesNotMatch(await unprivilegedFrame.locator('#guide-result-title').innerText(), /已完成|验证通过/);
  await unprivilegedContext.close();
  await page.route('**/api/dbac/payment/state*', route => route.abort('failed'), { times: 1 });
  await frame.locator('#guide-refresh').click(); await idle();
  assert.equal(await frame.locator('#guide-main').isDisabled(), true, 'unconfirmed service state disables writes');
  assert.match(await frame.locator('#guide-result-title').innerText(), /未确认|需核对/);
  await frame.locator('#guide-refresh').click(); await idle();
  assert.equal(writes.length, 0, 'initial reads, missing permission and network recovery issue no writes');
  report.checks.push({ check: 'initial missing credential, missing permissions and failed state query cannot show success', passed: true });

  async function act(mode, expected, { doubleClick = false, loseResponse = false } = {}) {
    const before = await read(mode), plan = planPayment(before, { ownerAvailable: true });
    assert.equal(plan.id, expected); assert.equal(plan.enabled, true, plan.reason);
    const index = writes.length;
    const manualPattern = '**/api/dbac/payment/manual';
    if (loseResponse) await page.route(manualPattern, async route => {
      // Forward the real operation once, then lose only its browser response.
      await route.fetch(); await route.abort('failed');
    }, { times: 1 });
    if (doubleClick) await frame.locator('#guide-main').evaluate(node => { node.click(); node.click(); });
    else await frame.locator('#guide-main').click();
    await idle();
    const after = await read(mode);
    assert.ok(!after.manual?.lastError, `real action ${expected} has no backend error`);
    const actions = writes.slice(index).filter(row => row.path === '/api/dbac/payment/manual').map(row => row.action);
    const expectedActions = expected.startsWith('begin-') ? [expected, 'derive-vc'] : expected === 'issue' ? [] : [expected];
    assert.deepEqual(actions, expectedActions, 'only authorized current action and existing preparation grouping');
    if (doubleClick || loseResponse) report.checks.push({ check: doubleClick ? 'rapid repeat click sends one write' : 'lost mutation response recovers original server result by GET', mode, action: expected, writes: actions.length, passed: true });
    report.actions.push({ mode, action: expected, phase: after.manual?.phase, stage: after.manual?.stage, orderId: after.order?.orderId, result: await frame.locator('#guide-result-title').innerText() });
    return after;
  }
  async function completeMode(mode, screenshots) {
    const original = await read(mode), executions = original.ledger.executionCount;
    const challenges = [];
    await act(mode, 'issue');
    for (const phase of ['proposal', 'authorize', 'settle']) {
      let current = await act(mode, `begin-${phase}`);
      challenges.push(current.manual.challenge.challengeId);
      assert.equal(current.manual.verificationResult, null, 'new proof phase does not inherit old result');
      assert.equal(await frame.locator('.scene-node[data-node="holder"]').getAttribute('data-state'), 'material', 'scene shows current derived material');
      assert.equal(await frame.locator('.scene-node[data-node="verifier"]').getAttribute('data-state'), 'pending', 'scene never carries B pass into a new phase');
      if (mode === 'bbs-blind-bls') {
        assert.equal(typeof current.manual.deviceRequest.blindedPoint, 'string');
        assert.equal(Object.hasOwn(current.manual.deviceRequest, 'context'), false, 'blind device input carries no plaintext context');
        assert.match(await frame.locator('.scene-caption').innerText(), /A 本地/);
      } else assert.equal(current.manual.deviceRequest.context.challengeId, current.manual.challenge.challengeId);
      if (phase === 'proposal' && screenshots) await captureSizes('normal-device-request');
      current = await act(mode, 'device-sign', { doubleClick: phase === 'proposal' && screenshots, loseResponse: phase === 'authorize' && screenshots });
      assert.ok(current.manual.deviceResponse); assert.equal(current.manual.verificationResult, null);
      assert.equal(await frame.locator('.scene-node[data-node="device"]').getAttribute('data-state'), 'material', 'returned contribution is material, not B verification');
      if (phase === 'proposal') {
        for (const [width, height] of [[1920, 1080], [1440, 900], [1366, 768]]) await screenshot(mode === 'bbs-bls' ? 'normal-device-returned' : 'blind-device-returned', { width, height });
        await page.setViewportSize({ width: 1440, height: 900 });
      }
      await act(mode, 'prove');
      assert.equal(await frame.locator('.scene-node[data-node="holder"]').getAttribute('data-state'), 'material');
      const beforeVerify = await read(mode);
      assert.equal(beforeVerify.ledger.executionCount, executions, 'material preparation does not pay');
      if (phase === 'settle') {
        assert.equal(beforeVerify.manual.walletSigned, true);
        assert.equal(await frame.locator('#guide-restart').isDisabled(), true, 'pending signed order cannot reset');
      }
      current = await act(mode, 'verify');
      assert.equal(await frame.locator('.scene-node[data-node="verifier"]').getAttribute('data-state'), 'pass', 'scene uses real current B trace');
      if (phase === 'proposal') {
        assert.equal(current.manual.verificationResult.accepted, true);
        assert.equal(current.ledger.executionCount, executions);
        await act(mode, 'submit-owner');
        const before = writes.length;
        await frame.locator('#guide-main').click();
        await frame.locator('#guide-owner-approve:enabled').waitFor();
        assert.equal(writes.length, before, 'opening Owner terms is read only');
        assert.equal(await frame.locator('#guide-owner-reject').isEnabled(), true);
        if (screenshots) {
          await page.locator('#scenario-copied-vc').click();
          await frame.locator('#guide-experiment').waitFor({ state: 'visible' });
          assert.equal(await frame.locator('#guide-owner-dialog').isVisible(), false, 'Owner dialog cannot remain actionable in attack scene');
          assert.equal(writes.length, before, 'changing scene closes Owner dialog without a decision');
          await page.locator('#scenario-normal').click(); await idle();
          assert.equal((await read(mode)).proposal.status, 'PENDING');
          await frame.locator('#guide-main').click();
          await frame.locator('#guide-owner-approve:enabled').waitFor();
          report.checks.push({ check: 'cross-scene navigation closes Owner review and preserves undecided proposal', passed: true, writes: 0 });
        }
        await frame.locator('#guide-owner-approve').click();
        await frame.locator('#guide-owner-dialog').waitFor({ state: 'hidden' }); await idle();
        current = await read(mode);
        assert.equal(current.proposal.status, 'APPROVED');
        assert.equal(current.ledger.executionCount, executions, 'Owner approval does not pay');
      } else if (phase === 'authorize') {
        assert.equal(current.manual.walletSigned, false);
        current = await act(mode, 'wallet-sign');
        assert.equal(current.manual.walletSigned, true);
        assert.equal(current.ledger.executionCount, executions, 'wallet signature does not pay');
      }
    }
    assert.equal(new Set(challenges).size, 3, 'three independently issued challenges');
    const settled = await read(mode), receipt = guidePaymentReceipt(settled);
    assert.ok(receipt, 'only matching successful receipt completes payment');
    assert.equal(settled.ledger.executionCount, executions + 1);
    if (screenshots) await captureSizes('payment-complete');
    const count = writes.length;
    await frame.locator('#guide-refresh').click(); await idle();
    assert.equal(writes.length, count, 'receipt refresh is read only');
    assert.equal((await read(mode)).ledger.executionCount, executions + 1, 'receipt refresh does not pay twice');
    report.checks.push({ check: 'complete payment', mode, orderId: settled.order.orderId, amountMinor: settled.order.amountMinor, outcome: receipt.outcome, executionDelta: 1, distinctChallenges: 3 });
    return settled;
  }
  const settledPlain = await completeMode('bbs-bls', true);
  // Public evidence, role selection and closing the dialog are view operations.
  let evidenceWrites = writes.length;
  const roleButton = frame.locator('.scene-node[data-node="holder"]');
  await roleButton.click();
  await frame.locator('#guide-evidence-dialog').waitFor({ state: 'visible' });
  await frame.locator('#guide-evidence-dialog form button').click();
  await frame.locator('#guide-evidence-dialog').waitFor({ state: 'hidden' });
  assert.equal(writes.length, evidenceWrites, 'canvas node and evidence dialog are read only');
  assert.equal(await roleButton.evaluate(node => node === document.activeElement), true, 'evidence close restores invoking keyboard focus');
  report.checks.push({ check: 'node evidence read only and restores focus', passed: true });
  // Display preference is independent of route/frame and never sends a write.
  let count = writes.length;
  const guideFrame = page.frames().find(item => item.url().includes('/guide/'));
  await page.locator('#presentation-toggle').click(); await page.locator('#presentation-toggle').click();
  assert.equal(page.frames().find(item => item.url().includes('/guide/')), guideFrame, 'layout changes preserve iframe');
  assert.equal(writes.length, count, 'display preference is read only');
  report.checks.push({ check: 'presentation preference preserves frame and sends no writes', passed: true });

  for (const scenario of ['copied-vc', 'revoked']) {
    count = writes.length;
    await page.locator(`#scenario-${scenario}`).click();
    await frame.locator('#guide-experiment').waitFor({ state: 'visible' });
    assert.equal(writes.length, count, 'scene selection does not start experiment');
    const run = frame.locator('[data-experiment-action="run"]');
    await run.click();
    const request = await waitUntil(() => writes.slice(count).find(row => row.runId), 'recorded real experiment run');
    const completed = await waitUntil(async () => { const value = await api(`/api/dbac/payment/experiment-runs?runId=${request.runId}`); return value.status === 'completed' ? value : false; }, 'experiment completion');
    const result = completed.result;
    assert.equal(result.control?.accepted, true); assert.equal(result.requestRejected, true);
    assert.equal(result.expectationMet, true); assert.equal(result.authenticationIssued, false);
    assert.equal(result.sideEffects.paymentExecutionDelta, 0); assert.equal(result.sideEffects.balancesUnchanged, true);
    assert.equal(result.sideEffects.ownerApprovalRequested, false); assert.equal(result.sideEffects.walletSignatureRequested, false);
    assert.notEqual(result.control.challengeId, result.request.challengeId);
    await waitUntil(async () => (await frame.locator('#guide-experiment').innerText()).includes(result.actual), 'actual experiment result rendered');
    const evidenceBefore = writes.length;
    const holderCheck = frame.locator('#guide-experiment [data-scene-evidence="check:holder_signature"]');
    await holderCheck.click();
    await frame.locator('#guide-evidence-dialog').waitFor({ state: 'visible' });
    const requestCheck = frame.locator('[data-experiment-request-checks] [data-check-id="holder_signature"]');
    const expectedCheck = result.verificationTrace.steps.find(row => row.id === 'holder_signature');
    assert.equal(await requestCheck.getAttribute('data-state'), expectedCheck.status, 'evidence link selects attack trace, never the successful control');
    if (scenario === 'copied-vc') assert.equal(expectedCheck.status, 'skipped', 'actual later holder check was not executed');
    await frame.locator('#guide-evidence-dialog form button').click();
    assert.equal(writes.length, evidenceBefore, 'experiment check details send no business writes');
    report.checks.push({ check: 'experiment check link selects current request trace', scenario, checkId: 'holder_signature', state: expectedCheck.status, passed: true });
    await captureSizes(scenario === 'copied-vc' ? 'copied-result' : 'revoked-result');
    count = writes.length;
    await page.reload();
    await waitUntil(async () => (await frame.locator('#guide-experiment').innerText().catch(() => '')).includes(result.actual), 'original run restored after refresh');
    assert.equal(writes.length, count, 'refresh restores run through GET only');
    const recovered = await api(`/api/dbac/payment/experiment-runs?runId=${request.runId}`);
    assert.equal(recovered.result.id, result.id, 'same original run, no rerun');
    report.experiments.push({ scenario, mode: completed.mode, runId: request.runId, resultId: result.id, actual: result.actual, rejectionStage: result.rejectionStage,
      controlAccepted: result.control.accepted, requestRejected: result.requestRejected, expectationMet: result.expectationMet, authenticationIssued: result.authenticationIssued,
      skippedChecks: result.verificationTrace.steps.filter(row => row.status === 'skipped').map(row => row.id), sideEffects: result.sideEffects, refreshWrites: writes.length - count });
  }
  count = writes.length;
  await page.goBack();
  await waitUntil(async () => (await frame.locator('#guide-experiment').innerText().catch(() => '')).includes('W3C_DEVICE_PROOF_REQUIRED'), 'back navigation restores copied run');
  await page.goForward();
  await waitUntil(async () => (await frame.locator('#guide-experiment').innerText().catch(() => '')).includes('W3C_CREDENTIAL_REVOKED'), 'forward navigation restores revoked run');
  assert.equal(writes.length, count, 'history navigation restores existing runs without writes');
  report.checks.push({ check: 'Back/Forward restores original scene records with no writes', passed: true });
  await page.locator('#scenario-normal').click(); await idle();
  assert.equal((await read('bbs-bls')).order.orderId, settledPlain.order.orderId, 'experiments preserve normal order');
  const settings = frame.locator('#guide-mode');
  await frame.locator('#guide-settings-open').click();
  await frame.locator('#guide-settings-dialog').waitFor({ state: 'visible' });
  count = writes.length;
  await settings.selectOption('bbs-blind-bls'); await idle();
  assert.equal(writes.length, count, 'mode switching is read only');
  await frame.locator('#guide-settings-dialog form button').click();
  const settledBlind = await completeMode('bbs-blind-bls', false);
  assert.notEqual(settledPlain.order.orderId, settledBlind.order.orderId, 'modes retain independent orders');
  assert.equal((await read('bbs-bls')).order.orderId, settledPlain.order.orderId);
  count = writes.length;
  for (const view of ['manage', 'attacks', 'owner', 'identity', 'diagnostic']) {
    if (await page.locator('#platform-navigation').isHidden()) await page.locator('#platform-tools-toggle').click();
    if (['identity', 'diagnostic'].includes(view)) {
      const tools = page.locator('.platform-tools');
      if ((await tools.getAttribute('open')) === null) await tools.locator('summary').click();
    }
    await page.locator(`[data-view="${view}"]`).first().click();
    await page.locator(`#panel-${view}`).waitFor({ state: 'visible' });
    await page.waitForTimeout(160);
    if (await page.locator('#platform-navigation').isHidden()) await page.locator('#platform-tools-toggle').click();
    await page.locator('#tab-guide').click(); await idle();
  }
  assert.equal(writes.length, count, 'all preserved module navigation remains read only');
  for (const path of ['/manual-demo.html', '/payment-detail.html']) {
    const response = await fetch(access.baseUrl + path, { redirect: 'manual', signal: AbortSignal.timeout(10000) });
    assert.equal(response.status, 302); assert.equal(response.headers.get('location'), '/');
  }
  report.checks.push({ check: 'preserved module entrypoints and retired URL redirects', passed: true, writes: 0 });
  assert.deepEqual(report.errors, [], 'no browser execution errors');
  report.passed = true;
  await saveReport();
  console.log(`Browser acceptance passed. Public artifacts: ${outputDirectory}`);
}

try {
  await mkdir(outputDirectory, { recursive: true });
  if (option('--access')) {
    access = JSON.parse(await readFile(inProject(option('--access')), 'utf8'));
    secrets = [access.uiKey, access.ownerKey];
  } else await launch();
  if (args.has('--open')) {
    const url = `${access.baseUrl}/#key=${access.uiKey}&ownerKey=${access.ownerKey}&view=guide`;
    const child = spawn('open', ['-a', 'Google Chrome', url], { stdio: 'ignore' });
    await new Promise((resolve, reject) => { child.once('exit', code => code === 0 ? resolve() : reject(new Error('could not open isolated browser'))); child.once('error', reject); });
    console.log(`Opened isolated browser at ${access.baseUrl}/ (capabilities removed by application).`);
  } else if (args.has('--cross-scene')) await crossSceneAcceptance();
  else if (args.has('--browser')) await browserAcceptance();
  else {
    console.log('Read-only initial service retained for manual browser acceptance; stop this process to close only its isolated services.');
    await new Promise(resolve => { process.once('SIGINT', resolve); process.once('SIGTERM', resolve); });
  }
} catch (error) {
  report.passed = false; report.failure = redact(error.stack || error.message);
  await saveReport();
  console.error(redact(error.message)); process.exitCode = 1;
} finally { await shutdown(); }
