// Runs the actual npm start integration with disposable state and dynamic ports.
// Startup output contains console capabilities: retain it only in memory and
// never print it, save it, or include assertion payloads in the public report.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { DBAC_EXTENSION, DBAC_MODES } from '../lib/dbac/policy.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const destination = resolve(process.argv[2] ?? join(root, 'docs', 'DBAC-LAUNCHER-VERIFICATION.json'));
const directory = await mkdtemp(join(tmpdir(), 'dbac-default-launch-'));
const started = performance.now();
const report = { recordedAt: new Date().toISOString(), command: 'npm start', environment: { node: process.version, platform: process.platform, arch: process.arch }, isolatedState: true, dynamicPorts: true, checks: [], evidenceScope: 'Fresh default-launcher API integration; no real funds, no Owner approval or payment execution; no browser UI claim.' };
let child, output = '', startupErrors = '', tracked = [], closing;
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const groupMembers = () => execFileSync('ps', ['-axo', 'pid=,ppid=,pgid='], { encoding: 'utf8' }).trim().split('\n').map(line => line.trim().split(/\s+/).map(Number)).filter(row => row[2] === child.pid).map(row => row[0]);
async function cleanup() {
  if (closing) return closing;
  closing = (async () => {
    if (child?.pid) {
      tracked = [...new Set([...tracked, ...groupMembers()])];
      try { process.kill(-child.pid, 'SIGTERM'); } catch {}
      for (let attempt = 0; attempt < 40 && tracked.some(alive); attempt++) await delay(100);
      if (tracked.some(alive)) { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }
      for (let attempt = 0; attempt < 30 && tracked.some(alive); attempt++) await delay(100);
      report.cleanup = { allObservedProcessesExited: tracked.every(pid => !alive(pid)), observedProcessCount: tracked.length };
    }
    await rm(directory, { recursive: true, force: true });
    report.cleanup ??= { allObservedProcessesExited: true, observedProcessCount: 0 };
    report.cleanup.temporaryStateRemoved = true;
  })();
  return closing;
}
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { cleanup().finally(() => process.exit(1)); });
function check(name, evidence = {}) { report.checks.push({ name, passed: true, ...evidence }); }
async function request(url, { token, body, headers = {} } = {}) {
  const response = await fetch(url, { method: body === undefined ? 'GET' : 'POST', headers: { ...(token ? { 'X-Demo-UI-Key': token } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(30000), redirect: 'error' });
  const data = await response.json();
  return { status: response.status, data };
}
function successful(result, label) { assert.equal(result.status, 200, `${label}: HTTP status`); return result.data; }

let failure;
try {
  const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
  assert.equal(manifest.scripts.start, 'node launch.mjs');
  child = spawn('npm', ['start'], { cwd: root, detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, PORT: '0', AGENT_B_PORT: '0', ESIM_PORT: '0', OWNER_PORT: '0', PAYMENT_DB: join(directory, 'payment.sqlite'), X402_STATE_DIR: join(directory, 'x402') } });
  const exited = new Promise(resolve => { child.once('exit', (code, signal) => resolve({ code, signal })); child.once('error', () => resolve({ code: 'SPAWN_ERROR' })); });
  child.stdout.on('data', data => { output = (output + data).slice(-100000); });
  child.stderr.on('data', data => { startupErrors = (startupErrors + data).slice(-10000); });
  const ready = (async () => {
    for (let attempt = 0; attempt < 450; attempt++) {
      const a = /演示页面 \/ Agent A: (http:\/\/127\.0\.0\.1:\d+)/.exec(output)?.[1];
      const b = /验证服务 \/ Agent B: (http:\/\/127\.0\.0\.1:\d+)\/a2a/.exec(output)?.[1];
      const ui = /控制台链接: http:\/\/127\.0\.0\.1:\d+\/#key=([A-Za-z0-9_-]{43})/.exec(output)?.[1];
      if (a && b && ui) return { a, b, ui };
      await delay(100);
    }
    throw new Error('DEFAULT_LAUNCHER_READINESS_TIMEOUT');
  })();
  const addresses = await Promise.race([ready, exited.then(() => { throw new Error('DEFAULT_LAUNCHER_EXITED_BEFORE_READY'); })]);
  tracked = groupMembers();
  assert.ok(tracked.length >= 8, 'default launcher should supervise all roles and JVM');
  const api = (path, body, token = addresses.ui) => request(`${addresses.a}${path}`, { body, token });
  const [aHealthResult, bHealthResult, cardResult, anonCardResult] = await Promise.all([
    request(`${addresses.a}/api/health`), request(`${addresses.b}/health`),
    request(`${addresses.b}/.well-known/agent-card.json`), request(`${addresses.b}/dbac/agent-card.json`),
  ]);
  const aHealth = successful(aHealthResult, 'A health'), bHealth = successful(bHealthResult, 'B health');
  const card = successful(cardResult, 'main Agent Card'), anonCard = successful(anonCardResult, 'anonymous Agent Card');
  assert.equal(aHealth.dbacAvailable, true); assert.equal(aHealth.independentOwner, true); assert.equal(aHealth.deviceRuntime, 'jCardSim');
  assert.equal(aHealth.paymentProtocol, 'x402-v2'); assert.equal(bHealth.paymentProtocol, 'x402-v2'); assert.equal(bHealth.paymentReady, true);
  check('default npm start boots both DBAC and legacy payment/device profiles', { observedProcessCount: tracked.length, paymentProtocol: 'x402-v2', paymentReady: true });
  const dbacExtension = card.capabilities.extensions.find(value => value.uri === DBAC_EXTENSION);
  assert.ok(dbacExtension); assert.equal(dbacExtension.required, false);
  assert.equal(dbacExtension.params.endpoint, `${addresses.b}/dbac/a2a`);
  assert.equal(dbacExtension.params.agentCardUrl, `${addresses.b}/dbac/agent-card.json`);
  assert.ok(card.skills.some(value => value.id === 'payments:pay'));
  assert.ok(card.capabilities.extensions.some(value => value.uri.includes('a2a-x402')));
  assert.equal(anonCard.url, `${addresses.b}/dbac/a2a`);
  assert.deepEqual(anonCard.skills.map(value => value.id), ['demo:echo']);
  assert.equal(anonCard.capabilities.extensions[0].params.paymentSupported, false);
  assert.equal(anonCard.security, undefined);
  check('main and anonymous Agent Cards advertise distinct payment and anonymous capabilities', { mainPaymentSkill: true, anonymousPaymentSupported: false, anonymousEndpoint: '/dbac/a2a' });

  const device = successful(await api('/api/device'), 'jCardSim health');
  assert.equal(device.backend, 'jcardsim'); assert.equal(device.algorithm, 'ES256'); assert.ok(Number.isInteger(device.javaPid));
  successful(await api('/api/issue', {}), 'legacy credential issuance');
  const legacy = successful(await api('/api/invoke', { text: 'Default launcher: retained jCardSim echo verification' }), 'legacy echo');
  assert.equal(legacy.ok, true); assert.equal(legacy.task.status.state, 'completed');
  const audit = successful(await api('/api/audit'), 'legacy audit');
  assert.ok(audit.events.some(event => event.event === 'authenticated' && event.dualSignature === true));
  check('legacy jCardSim ES256 and holder dual-signature echo remains operational', { backend: device.backend, algorithm: device.algorithm, javaProcessObserved: tracked.includes(device.javaPid), state: legacy.task.status.state, dualSignatureAudit: true });
  const noOwner = await api('/api/payment/pay', {});
  assert.ok(noOwner.status >= 400); assert.equal(noOwner.data.error.code, 'OWNER_CONFIRMATION_REQUIRED');
  const before = successful(await api('/api/payment'), 'payment snapshot');
  assert.equal(before.ledger.executionCount, 0); assert.equal(before.order.currency, 'TEST_USDC'); assert.equal(before.owner.available, true);
  check('existing payment stays behind independent Owner confirmation', { rejection: noOwner.data.error.code, executionCount: 0, currency: 'TEST_USDC' });

  let previousDevicePublicKey;
  for (const mode of DBAC_MODES) {
    const issued = successful(await api('/api/dbac/issue', { mode }), `${mode}: issue`);
    assert.equal(issued.device.backend, 'node-bls12-381'); assert.equal(issued.device.hardware, false);
    assert.equal(issued.credential.attributes[3].value, mode);
    assert.ok(tracked.includes(issued.device.pid));
    if (previousDevicePublicKey) assert.notEqual(previousDevicePublicKey, issued.device.publicKey);
    previousDevicePublicKey = issued.device.publicKey;
    const result = successful(await api('/api/dbac/invoke', { mode, text: `Default launcher anonymous ${mode}` }), `${mode}: invoke`);
    assert.equal(result.accepted, true); assert.equal(result.task.status.state, 'completed');
    assert.equal(result.verification.responseSignature, true); assert.equal(result.verification.deviceContribution, true);
    assert.equal(result.wire.body.jsonrpc, '2.0'); assert.equal(result.wire.body.method, 'message/send');
    assert.equal(result.wire.headers['X-A2A-Extensions'], DBAC_EXTENSION);
    assert.equal(typeof result.wire.headers['X-A2A-DBAC-Proof'], 'string');
    assert.equal(typeof result.wire.headers['X-A2A-DBAC-Challenge'], 'string');
    assert.equal(result.wire.headers.Authorization, undefined);
    assert.equal(JSON.stringify(result.wire).includes(issued.device.publicKey), false);
    assert.doesNotMatch(JSON.stringify(result.wire), /Alice \/ Agent A|Competition team|privateKey|secretKey|accessToken/);
    const replay = await request(`${addresses.b}/dbac/a2a`, { body: result.wire.body, headers: result.wire.headers });
    assert.equal(replay.data.error.code, 'DBAC_REPLAY');
    check(`${mode}: default-launcher issuance and signed anonymous A2A execution`, { state: result.task.status.state, backend: issued.device.backend, hardware: false, disclosedIndices: result.presentation.disclosed.map(value => value.index), hiddenFieldCount: result.hiddenFields.length, responseSignature: true, stableDeviceKeyAbsent: true, replayRejected: true, ordinaryJsonRpcBody: true });
  }
  const after = successful(await api('/api/payment'), 'post-DBAC payment snapshot');
  assert.equal(after.ledger.executionCount, 0); assert.deepEqual(after.ledger.accounts, before.ledger.accounts);
  check('anonymous flows did not alter payment execution count or balances', { executionCount: 0, accountBalancesUnchanged: true });
  report.result = 'PASS';
} catch (error) {
  // Assertion messages are deliberately labels only; never serialize actual
  // values, responses, capabilities, or the private startup log.
  failure = error;
  report.result = 'FAIL';
  report.failure = { name: error.name, code: error.code ?? null, message: String(error.message).split('\n')[0].slice(0, 180) };
  if (report.failure.message === 'DEFAULT_LAUNCHER_EXITED_BEFORE_READY') {
    report.failure.localListenPermissionDenied = /EPERM|EACCES/.test(startupErrors);
    report.failure.javaMissing = /JCARD_JAVA_REQUIRED|缺少局部 JDK/.test(startupErrors);
  }
} finally {
  await cleanup();
  output = ''; startupErrors = '';
}
if (!report.cleanup.allObservedProcessesExited) { report.result = 'FAIL'; report.failure = { message: 'CLEANUP_PROCESS_STILL_RUNNING' }; failure ??= new Error('CLEANUP_PROCESS_STILL_RUNNING'); }
report.durationMs = +(performance.now() - started).toFixed(2);
const saved = JSON.stringify(report, null, 2) + '\n';
assert.doesNotMatch(saved, /#key=|privateKey|secretKey|accessToken|X-Demo-UI-Key/);
await writeFile(destination, saved, { mode: 0o600 });
console.log(JSON.stringify({ result: report.result, checksPassed: report.checks.length, cleanup: report.cleanup, report: destination, durationMs: report.durationMs, ...(failure ? { failure: report.failure } : {}) }));
process.exitCode = failure ? 1 : 0;
