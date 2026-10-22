import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import { mkdtemp, rm, writeFile, appendFile } from 'node:fs/promises';
import { tmpdir, cpus, totalmem, platform, release, arch } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateIdentity } from '../../作品源码/BindCart/app/lib/identity.mjs';
import { serializeIdentity } from '../../作品源码/BindCart/app/lib/protocol.mjs';
import { createLocalX402Environment, createX402Backend, createX402Payer } from '../../作品源码/BindCart/app/lib/x402-payment.mjs';
import { createDbacPaymentSession } from '../../作品源码/BindCart/app/lib/dbac/payment-session.mjs';
import { DBAC_PAYMENT_PROFILE } from '../../作品源码/BindCart/app/lib/dbac/payment-policy.mjs';

// Dedicated test services and local TEST_USDC only. Never read app/var or log capabilities.
const output = fileURLToPath(new URL('./', import.meta.url));
const root = new URL('../../作品源码/BindCart/app/', import.meta.url);
const kind = process.argv[2] ?? 'smoke';
const modes = ['bbs-bls', 'bbs-blind-bls'];
const directory = await mkdtemp(join(tmpdir(), 'shoppingauth-figure-audit-'));
const children = [], tokens = [];
const token = () => { const value = randomBytes(32).toString('base64url'); tokens.push(value); return value; };
const clean = value => { let s = String(value); for (const t of tokens) s = s.replaceAll(t, '[redacted]'); return s; };
let environment, closing = false;
async function close() {
  if (closing) return; closing = true;
  await Promise.all(children.map(child => new Promise(done => {
    if (child.exitCode !== null || child.signalCode !== null) return done();
    child.once('exit', done); child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000); timer.unref();
  })));
  await environment?.close();
  await rm(directory, { recursive: true, force: true });
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => close().then(() => process.exit(130)));
async function launch(file, config) {
  return new Promise((resolve, reject) => {
    const child = fork(new URL(file, root), [], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    children.push(child); let diagnostics = '';
    child.stderr.on('data', v => { diagnostics = (diagnostics + v).slice(-2500); });
    const timer = setTimeout(() => reject(new Error(`${file}: startup timeout`)), 30000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); if (!closing) reject(new Error(clean(`${file}: ${code}: ${diagnostics}`))); });
    child.once('message', value => { clearTimeout(timer); value.error ? reject(new Error(clean(value.error))) : resolve({ ...value, child }); });
    child.send(config);
  });
}
const timing = new AsyncLocalStorage(), originalFetch = globalThis.fetch;
globalThis.fetch = async (...args) => {
  const ctx = timing.getStore(), start = performance.now();
  const response = await originalFetch(...args);
  if (ctx) {
    const row = { path: new URL(typeof args[0] === 'string' ? args[0] : args[0].url ?? args[0]).pathname, ms: performance.now() - start };
    ctx.push(row);
    for (const method of ['text', 'json', 'arrayBuffer']) {
      const original = response[method].bind(response);
      response[method] = async (...values) => { try { return await original(...values); } finally { row.ms = performance.now() - start; } };
    }
  }
  return response;
};
async function json(url, body, headers) {
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(90000) });
  const value = await response.json();
  if (!response.ok) throw Object.assign(new Error(value.error?.message ?? 'HTTP error'), { code: value.error?.code, status: response.status });
  return value;
}
const save = (name, data) => writeFile(join(output, name), JSON.stringify(data, null, 2));
try {
  const deviceToken = token(), issuerToken = token(), statusToken = token(), proposalToken = token(), ownerKey = token();
  const device = await launch('dbac-role.mjs', { role: 'device', accessToken: deviceToken, port: 0 });
  const issuer = await launch('dbac-role.mjs', { role: 'issuer', w3c: true, requireHolderProof: true, accessToken: issuerToken, statusToken, statePath: join(directory, 'status.json'), devicePublicKeys: device.publicKeys, port: 0 });
  const legacyIssuer = generateIdentity('test legacy issuer'), holder = generateIdentity('test holder policy'), inactiveDevice = generateIdentity('inactive device policy'), verifierIdentity = generateIdentity('test Agent B');
  const owner = await launch('owner.mjs', { holderDid: holder.did, verifierDid: verifierIdentity.did, trustedIssuers: [legacyIssuer.did], dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer, proposalToken, uiToken: ownerKey, port: 0 });
  const verifier = await launch('agent-b.mjs', { identity: serializeIdentity(verifierIdentity), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], adminToken: token(), ledgerPath: join(directory, 'verifier.sqlite'), port: 0, dbac: { issuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c, requireHolderProof: true, statusSource: { baseUrl: issuer.baseUrl, accessToken: statusToken } } });
  environment = await createLocalX402Environment({ stateDir: join(directory, 'chain'), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], holderDid: holder.did, deviceDid: inactiveDevice.did, verifierDid: verifierIdentity.did, dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer, isCredentialRevoked: async () => true,
    async isDbacCredentialRevoked(bindingId) {
      const state = await json(`${issuer.baseUrl}/credential/status`, { bindingId }, { 'X-DBAC-Access': statusToken });
      if (state.bindingId !== bindingId || !['valid', 'revoked'].includes(state.status)) throw new Error('Unconfirmed credential status');
      return state.status === 'revoked';
    },
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('x402 configure timeout')), 10000);
    verifier.child.once('message', value => { clearTimeout(timer); value.stage === 'x402-ready' ? resolve() : reject(new Error(value.error)); });
    verifier.child.send({ stage: 'configure-x402', backendConfig: environment.backendConfig });
  });
  const backend = createX402Backend(environment.backendConfig), payer = createX402Payer(environment.payerConfig);
  const session = () => createDbacPaymentSession({ baseUrl: verifier.baseUrl, verifierDid: verifierIdentity.did,
    issuer: { publicKey: issuer.publicKey, w3c: issuer.w3c, baseUrl: issuer.baseUrl, accessToken: issuerToken },
    device: { publicKeys: device.publicKeys, baseUrl: device.baseUrl, accessToken: deviceToken },
    owner: { did: owner.did, baseUrl: owner.baseUrl, proposalToken }, x402Payer: payer, paymentInfo: environment.publicInfo, getLedger: () => backend.snapshot() });
  const metadata = { startedAt: new Date().toISOString(), node: process.version, platform: platform(), release: release(), arch: arch(), cpu: cpus()[0]?.model, logicalCpus: cpus().length, memoryGiB: totalmem() / 1024 ** 3,
    kind, localTestOnly: true, runtime: 'independent Node software eSIM, issuer, Owner and production Agent B; shared local Ganache; real W3C BBS and holder proof',
    boundaries: 'Core protocol via production prepare/transmit. No browser render, human wait, merchant order signature or merchant confirmation timing. Concurrent independent A sessions share one Node test driver, device and B. Not the singleton storefront HTTP capacity.',
    measurement: 'performance.now wall clock; 1 warm-up order per mode excluded; 10 sequential measured orders per mode. Each order unique; 0.01 TEST_USDC each. Failures retained, never retried.',
    decomposition: 'A = prepare wall minus device/sign HTTP; device = complete sign HTTP round trip; B = complete a2a HTTP round trip including local settlement in settle; receipt = local response checks after HTTP. These are client-observed wall times, not pure CPU timings. Owner and wallet measured separately.' };
  await save(`${kind}-environment.json`, metadata);
  if (kind === 'security') {
    const rows = [], s = session();
    for (const mode of modes) for (const item of s.experimentScenarios()) {
      const result = await s.experiments({ mode, scenarioId: item.id });
      rows.push(result); await save('security-experiments.json', rows);
      console.log(`${mode} ${item.id}: ${result.actual}; expected=${result.expectationMet}; delta=${result.sideEffects?.paymentExecutionDelta}`);
    }
    assert(rows.every(row => row.expectationMet));
  } else {
    const samples = [], orders = [];
    const round = (value) => Math.round(value * 1000) / 1000;
    async function measure(s, mode, phase, options, group, index) {
      const requests = [], start = performance.now(); let prepareMs, transmitMs, prepared, result;
      const row = { group, index, mode, phase, startedAt: new Date().toISOString() };
      try {
        await timing.run(requests, async () => {
          const a = performance.now(); prepared = await s.prepare({ mode, phase, ...options }); prepareMs = performance.now() - a;
          const b = performance.now(); result = await s.transmit(prepared); transmitMs = performance.now() - b;
        });
        assert.equal(result.accepted, true); assert.equal(result.verificationTrace.outcome, 'pass');
        const deviceMs = requests.filter(v => v.path === '/sign').reduce((sum, v) => sum + v.ms, 0);
        const bMs = requests.filter(v => v.path === '/dbac/payment/a2a').reduce((sum, v) => sum + v.ms, 0);
        Object.assign(row, { success: true, totalMs: round(prepareMs + transmitMs), aMs: round(prepareMs - deviceMs), deviceMs: round(deviceMs), bHttpMs: round(bMs), receiptMs: round(transmitMs - bMs), orderId: prepared.payment.orderId, challengeId: prepared.context.challengeId,
          transactionHash: result.paymentResult?.receipt?.transactionHash, outcome: result.paymentResult?.outcome, verificationTrace: result.verificationTrace });
      } catch (error) { Object.assign(row, { success: false, totalMs: round(performance.now() - start), error: { code: error.code ?? error.name, message: clean(error.message) }, verificationTrace: error.verificationTrace }); throw error; }
      finally { samples.push(row); await appendFile(join(output, `${kind}-samples.jsonl`), JSON.stringify(row) + '\n'); }
      return result;
    }
    async function order(s, mode, group, index) {
      const state = await s.newOrder({ mode, amountMinor: 10000 });
      const record = { group, index, mode, orderId: state.order.orderId, success: false };
      const start = performance.now();
      try {
        const proposed = await measure(s, mode, 'proposal', {}, group, index);
        const approveStart = performance.now();
        const proposal = await json(`${owner.baseUrl}/proposals`, { profile: DBAC_PAYMENT_PROFILE, payment: state.order, dbacEvidence: proposed.responseEvidence }, { 'X-Owner-Proposal': proposalToken });
        const approved = await json(`${owner.baseUrl}/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }, { 'X-Owner-UI-Key': ownerKey });
        record.ownerMs = round(performance.now() - approveStart);
        const authorization = approved.authorization.token;
        const authorized = await measure(s, mode, 'authorize', { authorization }, group, index);
        const walletStart = performance.now();
        const payload = await payer.createPayload({ profile: DBAC_PAYMENT_PROFILE, payment: state.order, authorization, paymentRequired: authorized.task.status.message.metadata['x402.payment.required'], responseEvidence: authorized.responseEvidence });
        record.walletMs = round(performance.now() - walletStart);
        const settled = await measure(s, mode, 'settle', { authorization, payload, continuation: authorized.task }, group, index);
        assert.equal(settled.paymentResult.outcome, 'EXECUTED'); assert.equal(settled.paymentResult.receipt.orderId, state.order.orderId);
        assert.equal(settled.paymentResult.receipt.transactionStatus, 'success');
        Object.assign(record, { success: true, transactionHash: settled.paymentResult.receipt.transactionHash });
      } catch (error) { record.error = { code: error.code ?? error.name, message: clean(error.message) }; }
      record.totalMs = round(performance.now() - start); orders.push(record);
      await appendFile(join(output, `${kind}-orders.jsonl`), JSON.stringify(record) + '\n');
      return record;
    }
    const before = await backend.snapshot();
    for (const mode of modes) {
      const s = session(); await s.issue({ mode });
      const warmup = await order(s, mode, 'warmup', 1); assert.equal(warmup.success, true, JSON.stringify(warmup.error));
      if (kind === 'smoke') continue;
      for (let i = 1; i <= 10; i++) { const row = await order(s, mode, 'sequential', i); console.log(`${mode} sequential ${i}: ${row.success} ${row.totalMs}ms`); }

    }
    const after = await backend.snapshot();
    await save(`${kind}-ledger.json`, { before, after, executionDelta: after.executionCount - before.executionCount, recordedSuccesses: orders.filter(row => row.success).length });
    await save(`${kind}-results.json`, { metadata, orders, samples });
    console.log(`Completed ${orders.length} orders; success=${orders.filter(row => row.success).length}; ledger delta=${after.executionCount - before.executionCount}`);
  }
} catch (error) {
  await save(`${kind}-fatal.json`, { code: error.code ?? error.name, message: clean(error.message), stack: clean(error.stack) });
  console.error(clean(error.stack)); process.exitCode = 1;
} finally { await close(); globalThis.fetch = originalFetch; }
