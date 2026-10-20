import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { startDbacDemo } from '../lib/dbac/runtime.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

// Capability-bearing startup output stays in memory and is never included in
// assertion messages. All payment state and listener ports are isolated.
async function startUnified(t) {
  const directory = await mkdtemp(join(tmpdir(), 'unified-ui-'));
  const child = spawn(process.execPath, ['launch.mjs'], {
    cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PORT: '0', AGENT_B_PORT: '0', ESIM_PORT: '0', OWNER_PORT: '0', PAYMENT_DB: join(directory, 'ledger.sqlite'), X402_STATE_DIR: join(directory, 'x402') },
  });
  let stdout = '', stderr = '', stopped = false;
  const exited = new Promise(resolve => {
    child.once('exit', () => { stopped = true; resolve(); });
    child.once('error', () => { stopped = true; resolve(); });
  });
  child.stdout.on('data', chunk => { stdout = (stdout + chunk).slice(-100000); });
  child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-10000); });
  t.after(async () => {
    try { process.kill(-child.pid, 'SIGTERM'); } catch {}
    await Promise.race([exited, delay(5000, undefined, { ref: false })]);
    // Include subordinate JVM/chain/device processes if the launcher failed.
    try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    await exited;
    stdout = ''; stderr = '';
    await rm(directory, { recursive: true, force: true });
    const groupExists = () => { try { process.kill(-child.pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; } };
    for (let attempt = 0; attempt < 40 && groupExists(); attempt++) await delay(25);
    assert.equal(groupExists(), false, 'isolated launcher and all subordinate processes exit');
  });
  for (let attempt = 0; attempt < 900; attempt++) {
    if (stopped) throw new Error(/EPERM|EACCES/.test(stderr) ? 'Unified launcher listener permission denied.' : 'Unified launcher exited before readiness.');
    const a = stdout.match(/Agent A:\s*(http:\/\/127\.0\.0\.1:\d+)\s*\(PID \d+\)/)?.[1];
    const owner = stdout.match(/Owner:\s*(http:\/\/127\.0\.0\.1:\d+)\s*\(PID \d+\)/)?.[1];
    const oldA = stdout.match(/控制台链接:\s*http:\/\/127\.0\.0\.1:\d+\/#key=([A-Za-z0-9_-]{43})/);
    const oldOwner = stdout.match(/Owner 确认链接:\s*http:\/\/127\.0\.0\.1:\d+\/#key=([A-Za-z0-9_-]{43})/);
    const unified = stdout.match(/(http:\/\/127\.0\.0\.1:\d+\/#key=([A-Za-z0-9_-]{43})&ownerKey=([A-Za-z0-9_-]{43}))/);
    if (a && owner && oldA && oldOwner && unified) {
      assert.ok(unified[2] === oldA[1], 'unified entry retains the existing Agent console capability');
      assert.ok(unified[3] === oldOwner[1], 'unified entry retains the independent Owner capability');
      assert.ok(unified[2] !== unified[3], 'Agent and Owner capabilities remain independent');
      assert.ok(new URL(unified[1]).origin === a, 'unified entry uses the Agent A origin');
      return { baseUrl: a, ownerUrl: owner, uiKey: oldA[1], ownerKey: oldOwner[1] };
    }
    await delay(50, undefined, { signal: t.signal });
  }
  throw new Error('Unified launcher did not publish all required entry links.');
}

async function request(baseUrl, path, { body, headers = {}, method = body === undefined ? 'GET' : 'POST' } = {}) {
  const response = await fetch(new URL(path, baseUrl), {
    method, redirect: 'error', signal: AbortSignal.timeout(30000),
    headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  const data = response.headers.get('content-type')?.includes('application/json') ? JSON.parse(text) : null;
  return { status: response.status, headers: response.headers, text, data };
}
function success(result, label) { assert.equal(result.status, 200, label); return result.data; }
function error(result, code, status) { assert.equal(result.status, status, `${code}: status`); assert.equal(result.data?.error?.code, code); }
function traceOf(data) { return data.verificationTrace ?? data.error?.verificationTrace; }
function assertVerified(trace, profile, ids) {
  assert.ok(trace, 'the API returns the backend verification trace');
  assert.equal(trace.profile, profile); assert.equal(trace.source, 'agent-b'); assert.equal(trace.outcome, 'pass');
  for (const id of ids) assert.equal(trace.steps.find(step => step.id === id)?.status, 'pass', `backend verification completed ${id}`);
}

async function wrongHost(baseUrl, path, headers, body) {
  return new Promise((resolve, reject) => {
    const req = httpRequest(new URL(path, baseUrl), { method: 'POST', headers: { ...headers, Host: 'untrusted.example', 'Content-Type': 'application/json' } }, res => {
      let text = ''; res.setEncoding('utf8'); res.on('data', chunk => { text += chunk; });
      res.once('end', () => { try { resolve({ status: res.statusCode, data: JSON.parse(text) }); } catch (err) { reject(err); } });
    });
    req.once('error', reject); req.setTimeout(5000, () => req.destroy(new Error('Wrong-Host request timed out.')));
    req.end(JSON.stringify(body));
  });
}

test('one Agent A origin serves all demo pages while retaining independent Owner approval', { timeout: 120000 }, async t => {
  const f = await startUnified(t);
  const api = (path, body, headers = {}) => request(f.baseUrl, path, { body, headers: { 'X-Demo-UI-Key': f.uiKey, ...headers } });
  const owner = (path, body, headers = {}) => request(f.baseUrl, `/owner${path}`, { body, headers: { 'X-Owner-UI-Key': f.ownerKey, Origin: f.baseUrl, ...headers } });
  let proposal, initial;

  await t.test('active pages and their scripts/styles load from the same origin with embedding restricted to self', async () => {
    const health = success(await request(f.baseUrl, '/api/health'), 'public health');
    assert.equal(health.namedAvailable, true); assert.equal(health.ownerAvailable, true); assert.equal(health.dbacAvailable, true);
    for (const path of ['/', '/console.html', '/dbac.html', '/guide.html', '/guide/normal.html', '/guide/copied-vc.html', '/guide/revoked.html', '/owner/']) {
      const page = await request(f.baseUrl, path);
      assert.equal(page.status, 200, `${path} loads`); assert.match(page.headers.get('content-type'), /^text\/html/);
      assert.match(page.headers.get('content-security-policy'), path === '/' ? /frame-ancestors 'none'/ : /frame-ancestors 'self'/, `${path} retains its framing boundary`);
      const assets = [...page.text.matchAll(/(?:src|href)=["']([^"']+\.(?:js|css))["']/g)].map(match => new URL(match[1], new URL(path, f.baseUrl)));
      assert.ok(assets.length >= 2, `${path} includes its UI assets`);
      for (const asset of assets) {
        assert.equal(asset.origin, f.baseUrl, 'page assets retain the unified origin');
        assert.equal((await request(f.baseUrl, asset.pathname)).status, 200, `${path} asset ${asset.pathname}`);
      }
      assert.ok(!page.text.includes(f.uiKey) && !page.text.includes(f.ownerKey), 'public pages do not inject access capabilities');
    }
    for (const path of ['/manual-demo.html','/payment-detail.html']) {
      const retired = await fetch(new URL(path, f.baseUrl), {redirect:'manual'});
      assert.equal(retired.status, 302,`${path} redirects without loading a retired controller`);
      assert.equal(retired.headers.get('location'), '/', 'retain browser access fragments while returning to the main platform');
    }
    for (const path of ['/credential-flow.js', '/credential-flow.css', '/credential-flow-model.js', '/credential-flow-history.js', '/manual-demo.js', '/manual-demo.css', '/manual-crypto.js', '/manual-crypto.css']) assert.equal((await request(f.baseUrl,path)).status,404,`${path} is retired`);
    for (const path of ['/tokens.css', '/platform.css']) assert.equal((await request(f.ownerUrl,path)).status,200,`standalone Owner ${path} loads`);
    for (const path of ['/verification.js', '/verification.css', '/embed.js', '/embed.css', '/navigation-model.js', '/platform.css', '/guide-model.js', '/guide-experiments.js', '/guide-progress.js', '/guide-evidence.js', '/guide-step-detail.js']) assert.equal((await request(f.baseUrl, path)).status, 200, `${path} loads`);
  });

  await t.test('actual identified invocation returns completed backend checks', async () => {
    success(await api('/api/issue', {}), 'issue a device-bound credential');
    const result = success(await api('/api/invoke', { text: 'Unified UI verification integration' }), 'identified invocation');
    assert.equal(result.ok, true);
    assertVerified(traceOf(result), 'identity', ['holder_signature', 'credential', 'device', 'consume', 'execution']);
    initial = success(await api('/api/payment'), 'initial payment state');
    assert.equal(initial.ledger.executionCount, 0);
    const resultProposal = success(await api('/api/payment/propose', { payment: initial.order }), 'submit proposal');
    assert.equal(resultProposal.authorization, null);
    proposal = success(await owner('/api/state'), 'Owner state through the unified origin').proposals.find(item => item.id === resultProposal.proposal.id);
    assert.ok(proposal); assert.equal(proposal.status, 'PENDING'); assert.equal(proposal.authorization, undefined);
  });

  await t.test('visiting the Owner panel and using only Agent access never approve or sign', async () => {
    const confirmation = { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash };
    const path = `/owner/api/proposals/${proposal.id}/approve`;
    for (const [headers, status] of [[{}, 401], [{ 'X-Demo-UI-Key': f.uiKey }, 401], [{ 'X-Owner-UI-Key': f.uiKey }, 403], [{ 'X-Owner-UI-Key': f.ownerKey.slice(1) }, 401]]) {
      error(await request(f.baseUrl, '/owner/api/state', { headers }), 'OWNER_UI_ACCESS_DENIED', status);
      error(await request(f.baseUrl, path, { body: confirmation, headers }), 'OWNER_UI_ACCESS_DENIED', status);
    }
    success(await owner('/api/state'), 'viewing Owner state');
    assert.equal(success(await api('/api/payment/sync', {}), 'sync pending proposal').authorization, null);
    error(await api('/api/payment/pay', {}), 'OWNER_APPROVAL_PENDING', 403);
    assert.equal(success(await owner('/api/state'), 'still pending').proposals.find(item => item.id === proposal.id).status, 'PENDING');
    assert.deepEqual(success(await api('/api/payment'), 'no payment from visiting Owner').ledger, initial.ledger);
    error(await request(f.baseUrl, '/owner/proposals', { body: {}, headers: { 'X-Owner-UI-Key': f.ownerKey } }), 'NOT_FOUND', 404);
  });

  await t.test('same-origin proxy preserves request guards and exact payment confirmation', async () => {
    const path = `/api/proposals/${proposal.id}/approve`;
    const confirmation = { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash };
    error(await owner(path, confirmation, { Origin: 'https://untrusted.example' }), 'CROSS_ORIGIN_DENIED', 403);
    error(await wrongHost(f.baseUrl, `/owner${path}`, { 'X-Owner-UI-Key': f.ownerKey }, confirmation), 'INVALID_HOST', 403);
    error(await owner(path, confirmation, { 'Content-Type': 'text/plain' }), 'JSON_REQUIRED', 415);
    error(await owner(path, { ...confirmation, payment: { ...proposal.payment, amountMinor: 1 } }), 'OWNER_CONFIRMATION_MISMATCH', 409);
    assert.equal(success(await owner('/api/state'), 'guarded proposal').proposals.find(item => item.id === proposal.id).status, 'PENDING');
    const approved = success(await owner(path, confirmation), 'exact Owner confirmation from unified origin');
    assert.equal(approved.status, 'APPROVED'); assert.equal(typeof approved.authorization?.token, 'string');
    const synced = success(await api('/api/payment/sync', {}), 'sync actual Owner authorization');
    assert.equal(typeof synced.authorization?.token, 'string');
    assert.deepEqual(synced.ledger, initial.ledger, 'approval is not execution');
    error(await owner(path, confirmation), 'OWNER_PROPOSAL_NOT_PENDING', 409);
  });

  await t.test('approved local-chain payment executes once and retry keeps the original receipt', async () => {
    const paid = success(await api('/api/payment/pay', {}), 'approved payment');
    assert.equal(paid.paymentResult.outcome, 'EXECUTED');
    assert.match(paid.paymentResult.receipt.transactionHash, /^0x[0-9a-fA-F]{64}$/);
    assert.equal(paid.paymentResult.receipt.settlementResponse.success, true);
    assertVerified(traceOf(paid), 'identity', ['holder_signature', 'credential', 'device', 'execution']);
    const retried = success(await api('/api/payment/retry', {}), 'idempotent payment retry');
    assert.equal(retried.paymentResult.outcome, 'ALREADY_PROCESSED');
    assert.deepEqual(retried.paymentResult.receipt, paid.paymentResult.receipt);
    assert.equal(success(await api('/api/payment'), 'one ledger execution').ledger.executionCount, 1);
  });

  await t.test('Owner rejection forwards through the same origin and cannot be converted to approval', async () => {
    const next = success(await api('/api/payment/new', {}), 'create another local test order');
    const pending = success(await api('/api/payment/propose', { payment: next.order }), 'submit another proposal').proposal;
    const rejected = success(await owner(`/api/proposals/${pending.id}/reject`, { rejected: true }), 'explicit Owner rejection');
    assert.equal(rejected.status, 'REJECTED'); assert.equal(rejected.authorization, undefined);
    error(await owner(`/api/proposals/${pending.id}/approve`, { confirmed: true, payment: pending.payment, credentialHash: pending.credentialHash }), 'OWNER_PROPOSAL_NOT_PENDING', 409);
    assert.equal(success(await api('/api/payment/sync', {}), 'sync rejected proposal').authorization, null);
    assert.equal(success(await api('/api/payment'), 'rejection does not execute').ledger.executionCount, 1);
  });
});

test('DBAC-only launch keeps the unified entry and exposes only available backend capabilities', { timeout: 60000 }, async t => {
  const runtime = await startDbacDemo();
  t.after(() => runtime.close());
  const api = (path, body) => request(runtime.a.baseUrl, path, { body, headers: { 'X-Demo-UI-Key': runtime.uiToken } });
  const page = await request(runtime.a.baseUrl, '/');
  assert.equal(page.status, 200); assert.match(page.text, /demo\.js/);
  const health = success(await request(runtime.a.baseUrl, '/api/health'), 'DBAC-only capabilities');
  assert.equal(health.dbacAvailable, true); assert.equal(health.namedAvailable, false); assert.equal(health.ownerAvailable, false);
  assert.equal(health.paymentProtocol, null);
  error(await api('/api/payment/pay', {}), 'DBAC_ONLY', 404);
  const ownerUnavailable = await request(runtime.a.baseUrl, '/owner/api/state');
  assert.ok(ownerUnavailable.status === 404 || ownerUnavailable.status === 503, 'DBAC-only has no usable Owner proxy');
  success(await api('/api/dbac/issue', { mode: 'bbs-bls' }), 'DBAC credential');
  const invoked = success(await api('/api/dbac/invoke', { mode: 'bbs-bls', text: 'Unified entry anonymous invocation' }), 'anonymous backend invocation');
  assert.equal(invoked.accepted, true);
  assertVerified(traceOf(invoked), 'dbac', ['knowledge', 'credential_pairing', 'device_pairing', 'consume', 'execution']);
  success(await api('/api/dbac/device/lock', { mode: 'bbs-bls', locked: true }), 'lock software device');
  const denied = await api('/api/dbac/invoke', { mode: 'bbs-bls' });
  error(denied, 'DBAC_DEVICE_LOCKED', 403);
  const trace = traceOf(denied.data);
  assert.ok(trace); assert.equal(trace.source, 'agent-a'); assert.equal(trace.outcome, 'fail');
  assert.equal(trace.steps.find(step => step.id === 'preparation')?.status, 'fail');
  assert.ok(trace.steps.filter(step => step.actor === 'agent-b').every(step => step.status === 'skipped'), 'device failure never claims that B verified the request');
});
