import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { mkdtemp, readFile, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

// This run owns its ports, ledger, credentials and local chain. It never reads
// or mutates the presenter instance. Startup capability values stay in memory.
const directory = await mkdtemp(resolve(tmpdir(), 'mystore-stage-pacing-'));
const metadataPath = resolve(directory, 'runtime.json');
const output = resolve('../evidence/demo-stage-pacing');
const report = { startedAt: new Date().toISOString(), source: 'isolated launch-dual, real original cryptographic and x402 services', checks: [], status: 'running' };
await mkdir(output, { recursive: true });
const environment = { ...process.env, DUAL_PORT: '0', DUAL_STATE_DIR: resolve(directory, 'state'), DUAL_RUNTIME_PATH: metadataPath };
delete environment.DUAL_STAGE_DELAY_MS; // Verify the normal launcher default.
const child = fork(new URL('../launch-dual.mjs', import.meta.url), [], { env: environment, stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
let stderr = '', runtime, caps, stopped = false;
child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-4000); });
const exited = new Promise(resolve => child.once('exit', () => { stopped = true; resolve(); }));
const save = () => writeFile(resolve(output, 'verification.json'), JSON.stringify(report, null, 2));
const pass = (name, detail = {}) => { report.checks.push({ name, passed: true, ...detail }); console.log(`PASS ${name}`); };
async function request(path, body, headers = {}) {
  const response = await fetch(runtime.baseUrl + path, { method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(90000),
    headers: { 'X-Demo-UI-Key': caps.get('key'), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { status: response.status, data: await response.json() };
}
async function success(path, body, headers) {
  const result = await request(path, body, headers);
  assert.equal(result.status, 200, `${path}: ${result.data.error?.code ?? 'unexpected HTTP status'}`);
  return result.data;
}
async function waitForComplete(action, after = 0) {
  for (let attempt = 0; attempt < 500; attempt++) {
    const state = await success('/api/live/state');
    if (state.events.some(event => event.seq > after && event.source === 'original-controller' && event.action === action && event.status === 'complete')) return state;
    await delay(40);
  }
  throw new Error(`Real completed ${action} step was not observed`);
}
try {
  for (let attempt = 0; attempt < 600; attempt++) {
    if (stopped) throw new Error(`Isolated launcher stopped before readiness: ${stderr}`);
    try { runtime = JSON.parse(await readFile(metadataPath)); break; } catch (error) { if (error.code !== 'ENOENT') throw error; }
    await delay(100);
  }
  assert.ok(runtime, 'launcher must become ready');
  assert.equal(runtime.stageDelayMs, 1600);
  caps = new URLSearchParams(new URL(runtime.url).hash.slice(1));
  pass('normal launcher enables a 1600 ms server-side presentation hold');
  let state = await success('/api/store/state');
  state = await success('/api/store/cart', { productId: '02', quantity: 1, revision: state.revision });
  state = await success('/api/store/cart', { productId: '03', quantity: 1, revision: state.revision });
  const expectedAmountMinor = 34_980_000;
  assert.deepEqual(state.cart.map(item => item.id).sort(), ['02', '03']);
  assert.equal(state.totalMinor, expectedAmountMinor);
  const before = await success('/api/live/state');
  const qualificationStarted = performance.now();
  const checking = success('/api/store/checkout', { revision: state.revision });
  const heldCheckout = await waitForComplete('begin-proposal', before.sequence);
  assert.equal(heldCheckout.store.busy, true);
  const blockedNew = await request('/api/store/new', { revision: state.revision });
  assert.equal(blockedNew.status, 409); assert.equal(blockedNew.data.error.code, 'STORE_BUSY');
  state = await checking;
  const qualificationMs = performance.now() - qualificationStarted;
  assert.equal(state.phase, 'checkout'); assert.equal(state.backend.proposal.status, 'PENDING');
  assert.equal(state.order.amountMinor, expectedAmountMinor);
  assert.deepEqual(state.order.merchantOrder.snapshot.items.map(item => item.productId).sort(), ['02', '03']);
  assert.equal(state.verification.steps.find(step => step.id === 'merchant_order').status, 'pass');
  assert.ok(qualificationMs >= 9500);
  assert.equal(state.backend.ledger.executionCount, before.store.backend.ledger.executionCount);
  pass('real qualification remains readable during held results, blocks a new order and waits for Owner', { durationMs: Math.round(qualificationMs) });
  const proposal = state.backend.proposal;
  await success(`/owner/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }, { 'X-Owner-UI-Key': caps.get('ownerKey') });
  const paymentBefore = await success('/api/live/state');
  const paymentStarted = performance.now();
  const paying = success('/api/store/pay', { orderId: state.order.orderId, revision: state.revision });
  const heldOwner = await waitForComplete('sync-owner', paymentBefore.sequence);
  assert.equal(heldOwner.store.busy, true);
  const duplicate = await request('/api/store/pay', { orderId: state.order.orderId, revision: state.revision });
  assert.equal(duplicate.status, 409); assert.equal(duplicate.data.error.code, 'STORE_BUSY');
  state = await paying;
  const paymentMs = performance.now() - paymentStarted;
  assert.equal(state.phase, 'paid'); assert.equal(state.merchant.status, 'confirmed');
  assert.equal(state.receipt.transactionStatus, 'success');
  assert.equal(state.receipt.amountMinor, expectedAmountMinor);
  assert.equal(state.backend.ledger.executionCount, before.store.backend.ledger.executionCount + 1);
  assert.equal(before.store.backend.ledger.accounts.find(account => account.id === 'demo:alice').balanceMinor - state.backend.ledger.accounts.find(account => account.id === 'demo:alice').balanceMinor, expectedAmountMinor);
  assert.ok(paymentMs >= 19000);
  pass('Owner, authorization, wallet, settlement and independent merchant confirmation complete one real payment with no duplicate', { durationMs: Math.round(paymentMs), totalProcessMs: Math.round(qualificationMs + paymentMs) });
  const final = await success('/api/live/state');
  const protocol = final.events.filter(event => event.seq > before.sequence && event.source === 'original-controller');
  const paced = new Set(['issue', 'device-sign', 'prove', 'verify', 'submit-owner', 'sync-owner', 'wallet-sign']);
  const intervals = [];
  for (let index = 0; index < protocol.length - 1; index++) {
    const completed = protocol[index], next = protocol[index + 1];
    if (completed.status !== 'complete' || next.status !== 'start' || !(completed.action.startsWith('begin-') || paced.has(completed.action))) continue;
    const elapsedMs = Date.parse(next.at) - Date.parse(completed.at);
    intervals.push({ action: completed.action, phase: completed.phase, nextAction: next.action, elapsedMs });
    assert.ok(elapsedMs >= 1500, `${completed.action} result must stay observable before ${next.action}`);
  }
  assert.ok(intervals.length >= 15);
  const verified = protocol.filter(event => event.action === 'verify' && event.status === 'complete');
  assert.deepEqual(verified.map(event => event.phase), ['proposal', 'authorize', 'settle']);
  assert.ok(verified.every(event => event.data.verificationTrace?.outcome === 'pass'));
  assert.equal(new Set(verified.map(event => event.data.challengeId)).size, 3);
  assert.equal(protocol.filter(event => event.action === 'wallet-sign' && event.status === 'complete').length, 1);
  pass('journal timestamps prove actual stages are separated and three fresh challenges pass original verification', { observedIntervals: intervals });
  const count = state.backend.ledger.executionCount, hash = state.receipt.transactionHash;
  const replay = await success('/api/store/pay', { orderId: state.order.orderId, revision: state.revision });
  assert.equal(replay.receipt.transactionHash, hash); assert.equal(replay.backend.ledger.executionCount, count);
  pass('completed duplicate returns the original receipt with no second signature or transfer');
  report.status = 'passed';
} catch (error) {
  report.status = 'failed'; report.error = { message: error.message, stack: error.stack }; process.exitCode = 1; console.error(error.message);
} finally {
  if (runtime && caps) await request('/api/shutdown', {}).catch(() => {});
  await Promise.race([exited, delay(8000)]);
  if (!stopped) { child.kill(); await Promise.race([exited, delay(3000)]); }
  report.finishedAt = new Date().toISOString(); report.isolatedLauncherStopped = stopped;
  await save();
}
