import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { startDbacDemo } from '../lib/dbac/runtime.mjs';
import { createW3cBbsVerifier } from '../lib/w3c-bbs.mjs';
import { W3C_PAYMENT_PROFILE, presentationHeader, w3cPresentationHash } from '../lib/dbac/w3c-profile.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const modes = ['bbs-bls', 'bbs-blind-bls'];

// Every chain, ledger and listening port belongs to this test. Startup capability
// links are parsed in memory and never printed, saved or included in assertions.
async function startIsolatedLauncher(t) {
  const directory = await mkdtemp(join(tmpdir(), 'dbac-payment-flow-'));
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
    try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    await exited;
    stdout = ''; stderr = '';
    await rm(directory, { recursive: true, force: true });
    const groupExists = () => { try { process.kill(-child.pid, 0); return true; } catch (error) { if (error.code === 'ESRCH') return false; throw error; } };
    for (let attempt = 0; attempt < 40 && groupExists(); attempt++) await delay(25);
    assert.equal(groupExists(), false, 'all isolated launcher children must exit');
  });
  for (let attempt = 0; attempt < 1000; attempt++) {
    if (stopped) throw new Error(/EPERM|EACCES/.test(stderr) ? 'Isolated launcher listener permission denied.' : 'Isolated launcher stopped before readiness.');
    const match = stdout.match(/(http:\/\/127\.0\.0\.1:\d+)\/#key=([A-Za-z0-9_-]{43})&ownerKey=([A-Za-z0-9_-]{43})/);
    if (match) return { baseUrl: match[1], uiKey: match[2], ownerKey: match[3] };
    await delay(50, undefined, { signal: t.signal });
  }
  throw new Error('Isolated launcher did not publish its unified entry.');
}

async function request(baseUrl, path, { body, headers = {} } = {}) {
  const response = await fetch(new URL(path, baseUrl), {
    method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(90000),
    headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  return { status: response.status, data: response.headers.get('content-type')?.includes('application/json') ? JSON.parse(text) : null, text };
}
function success(response, label) {
  assert.equal(response.status, 200, `${label}: HTTP status (${response.data?.error?.code ?? 'no server error code'})`);
  return response.data;
}
function traceOf(value) { return value?.verificationTrace ?? value?.error?.verificationTrace; }
function verified(trace, ids) {
  assert.ok(trace, 'actual verifier trace is present');
  assert.equal(trace.profile, 'dbac-payment'); assert.equal(trace.source, 'agent-b'); assert.equal(trace.outcome, 'pass');
  for (const id of ids) assert.equal(trace.steps.find(step => step.id === id)?.status, 'pass', `actual verifier ran ${id}`);
}
function entries(value, result = []) {
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) { result.push({ key, value: child }); entries(child, result); }
  return result;
}
async function privateWire(wire, localState, deviceState) {
  assert.ok(wire?.proof && wire.body && wire.context, 'server returns the actual payment wire');
  assert.ok(wire.endpoint.endsWith('/dbac/payment/a2a'), 'payment used the DBAC verifier endpoint');
  assert.equal(wire.context.credentialProfile, W3C_PAYMENT_PROFILE);
  assert.equal(localState.w3c?.enabled, true, 'real launcher requires W3C BBS credentials');
  const base = localState.w3c.originalCredential, derived = wire.proof.verifiableCredential;
  assert.ok(base?.proof && derived?.proof, 'local base VC and actually transmitted derived VC are both available');
  assert.deepEqual(JSON.parse(Buffer.from(wire.headers['X-A2A-DBAC-Proof'], 'base64url').toString('utf8')), wire.proof, 'inspected proof is exactly the encoded HTTP proof');
  assert.equal(derived['@context'][0], 'https://www.w3.org/ns/credentials/v2');
  assert.equal(derived.proof.type, 'DataIntegrityProof');
  assert.equal(derived.proof.cryptosuite, 'bbs-2023');
  assert.equal(derived.proof.proofPurpose, 'assertionMethod');
  assert.deepEqual(Object.keys(derived.credentialSubject).sort(), ['bindingId', 'epoch', 'holderDid', 'mode', 'role', 'scope']);
  for (const name of ['role', 'scope', 'epoch', 'mode', 'bindingId', 'holderDid']) assert.equal(derived.credentialSubject[name], base.credentialSubject[name], `derived VC carries the signed ${name}`);
  assert.equal(derived.issuer, localState.w3c.issuerProfile.issuer);
  assert.notEqual(derived.proof.proofValue, base.proof.proofValue, 'the base issuer signature is not transmitted as a presentation');
  assert.equal(await createW3cBbsVerifier(localState.w3c.issuerProfile).verifyDerived({ credential: derived, presentationHeader: presentationHeader(wire.context) }), true, 'actual transmitted VC verifies under the pinned issuer and current payment challenge');
  assert.equal(wire.proof.disclosed.find(attribute => attribute.index === 6)?.value, derived.credentialSubject.bindingId, 'VC and device-bound proof disclose the same signed binding ID');
  const fields = entries(wire);
  for (const field of ['credential', 'rawCredential', 'originalCredential', 'devicePublicKey', 'longTermDevicePublicKey', 'deviceDid', 'subjectDid', 'organization', 'holderLabel']) {
    assert.equal(fields.some(entry => entry.key === field), false, `wire does not contain raw private field ${field}`);
  }
  assert.equal(fields.filter(entry => entry.key === 'verifiableCredential').length, 1, 'wire contains one selective-disclosure VC');
  assert.equal(fields.some(entry => entry.value === base.proof.proofValue), false, 'original base proof is not disclosed anywhere in the wire');
  const longTermKey = deviceState.device?.publicKey;
  assert.equal(typeof longTermKey, 'string');
  assert.equal(fields.some(entry => entry.value === longTermKey), false, 'wire does not contain the long-term device public key');
  for (const attribute of localState.credential.attributes.filter(item => item.disclosed === false)) {
    assert.equal(fields.some(entry => entry.value === attribute.value), false, `hidden attribute ${attribute.name} is not disclosed`);
  }
  assert.equal(wire.headers.Authorization, undefined); assert.equal(wire.headers.authorization, undefined);
  assert.equal(wire.headers['X-A2A-Device-Proof'], undefined);
  assert.equal(wire.proof.disclosed?.find(attribute => attribute.index === 1)?.value, 'payments:pay', 'payment proof discloses payment scope');
}

// The named profile remains completely unprovisioned and its device is locked.
// A successful real transfer therefore exercises DBAC as the payment gate.
test('W3C BBS VC and paper eSIM binding jointly gate real Owner-approved x402 payments, with independent modes and idempotent receipts', { timeout: 300000 }, async t => {
  const fixture = await startIsolatedLauncher(t);
  const api = (path, body) => request(fixture.baseUrl, path, { body, headers: { 'X-Demo-UI-Key': fixture.uiKey } });
  const payment = (mode, action, body = {}) => api(`/api/dbac/payment/${action}`, { mode, ...body });
  const state = async mode => success(await api(`/api/dbac/payment/state?mode=${mode}`), 'read payment state');
  const owner = (path, body) => request(fixture.baseUrl, `/owner${path}`, { body, headers: { 'X-Owner-UI-Key': fixture.ownerKey, Origin: fixture.baseUrl } });
  const observed = new Map();
  assert.equal(success(await api('/api/state'), 'named profile before DBAC').credential, null);
  success(await api('/api/device/lock', { locked: true }), 'lock the named jCardSim device');
  assert.equal(success(await api('/api/device'), 'named device lock is effective').locked, true);

  for (const mode of modes) {
    await t.test(`${mode}: DBAC credential, explicit Owner approval, real transfer, retry and attacks`, async () => {
      const initial = await state(mode);
      assert.equal(initial.available, true); assert.equal(initial.mode, mode); assert.equal(initial.credential, null);
      assert.equal(initial.authorization, null); assert.equal(initial.proposal, null);
      const startCount = initial.ledger.executionCount;
      const issued = success(await payment(mode, 'issue'), 'issue payment credential');
      assert.ok(issued.credential);
      assert.equal(issued.credential.attributes.find(item => item.name === 'scope')?.value, 'payments:pay');
      assert.equal(issued.credential.attributes.find(item => item.name === 'mode')?.value, mode);
      assert.equal(issued.credential.attributes.find(item => item.name === 'organization')?.disclosed, false);
      assert.equal(issued.w3c?.profile, W3C_PAYMENT_PROFILE);
      assert.equal(issued.w3c.originalCredential.proof.cryptosuite, 'bbs-2023');
      assert.equal(issued.credential.attributes.find(item => item.name === 'bindingId')?.value, issued.w3c.originalCredential.credentialSubject.bindingId);
      const localDevice = success(await api(`/api/dbac/state?mode=${mode}`), 'read local software-device key');

      success(await api('/api/dbac/device/lock', { mode, locked: true }), 'lock the selected DBAC software device');
      const lockedProposal = await payment(mode, 'propose');
      assert.equal(lockedProposal.status, 403); assert.equal(lockedProposal.data.error.code, 'DBAC_DEVICE_LOCKED');
      assert.equal(traceOf(lockedProposal.data)?.source, 'agent-a');
      assert.equal(traceOf(lockedProposal.data)?.outcome, 'fail');
      assert.ok(traceOf(lockedProposal.data).steps.filter(step => step.actor === 'agent-b').every(step => step.status === 'skipped'), 'no verifier pass is invented when device preparation fails');
      assert.equal((await state(mode)).ledger.executionCount, startCount);
      success(await api('/api/dbac/device/lock', { mode, locked: false }), 'unlock selected DBAC device');

      const proposed = success(await payment(mode, 'propose'), 'submit DBAC payment proposal');
      const proposal = proposed.proposal;
      assert.ok(proposal); assert.equal(proposal.profile, 'dbac-payment'); assert.equal(proposal.mode, mode); assert.equal(proposal.status, 'PENDING');
      assert.equal(proposed.authorization, null);
      verified(traceOf(proposed), ['scope', 'w3c_bbs', 'vc_device_binding', 'disclosure', 'knowledge', 'credential_pairing', 'device_pairing', 'consume']);
      await privateWire(proposed.wire, issued, localDevice);
      const beforeApproval = await payment(mode, 'pay');
      assert.equal(beforeApproval.status, 403); assert.equal(beforeApproval.data.error.code, 'OWNER_CONFIRMATION_REQUIRED');
      assert.equal((await state(mode)).ledger.executionCount, startCount, 'proposal and pending Owner state never debit');

      const ownerState = success(await owner('/api/state'), 'inspect independent Owner proposals');
      const displayedProposal = ownerState.proposals.find(item => item.id === proposal.id);
      assert.ok(displayedProposal); assert.equal(displayedProposal.profile, 'dbac-payment'); assert.equal(displayedProposal.mode, mode);
      const approved = success(await owner(`/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: displayedProposal.payment, credentialHash: displayedProposal.credentialHash }), 'Owner explicitly approves exact payment terms');
      assert.equal(approved.status, 'APPROVED');
      const synced = success(await payment(mode, 'sync'), 'sync Owner authorization');
      assert.equal(synced.proposal.status, 'APPROVED'); assert.equal(typeof synced.authorization?.token, 'string');
      assert.equal(synced.authorization.document.credentialProfile, W3C_PAYMENT_PROFILE);
      assert.equal(synced.authorization.document.w3cIssuer, issued.w3c.issuerProfile.issuer);
      assert.equal(synced.authorization.document.vcBindingId, issued.w3c.originalCredential.credentialSubject.bindingId, 'Owner approves the exact W3C credential binding');
      assert.equal(synced.ledger.executionCount, startCount, 'approval is not payment');

      success(await api('/api/dbac/device/lock', { mode, locked: true }), 'lock DBAC device after approval');
      const blockedPayment = await payment(mode, 'pay');
      assert.equal(blockedPayment.status, 403); assert.equal(blockedPayment.data.error.code, 'DBAC_DEVICE_LOCKED');
      assert.equal((await state(mode)).ledger.executionCount, startCount, 'Owner authorization alone cannot bypass a fresh DBAC contribution');
      success(await api('/api/dbac/device/lock', { mode, locked: false }), 'unlock for payment');

      const paid = success(await payment(mode, 'pay'), 'execute real DBAC payment');
      assert.equal(paid.accepted, true); assert.equal(paid.mode, mode); assert.equal(paid.paymentResult.outcome, 'EXECUTED');
      assert.equal(paid.paymentResult.receipt.settlementResponse.success, true);
      assert.match(paid.paymentResult.receipt.transactionHash, /^0x[0-9a-fA-F]{64}$/);
      assert.deepEqual(paid.paymentFlow, ['dbac-verified', 'input-required', 'payment-submitted', 'completed']);
      verified(traceOf(paid), ['scope', 'w3c_bbs', 'vc_device_binding', 'disclosure', 'knowledge', 'credential_pairing', 'device_pairing', 'owner_authorization', 'task_binding', 'consume', 'settlement_gate', 'execution']);
      assert.ok(paid.verificationTraces?.length >= 2, 'authorization and settlement each have actual verifier traces');
      for (const trace of paid.verificationTraces) verified(trace, ['w3c_bbs', 'vc_device_binding', 'knowledge', 'credential_pairing', 'device_pairing', 'owner_authorization', 'consume']);
      await privateWire(paid.wire, issued, localDevice);
      assert.equal(paid.gate.w3cPresentationHash, w3cPresentationHash(paid.wire.proof.verifiableCredential), 'B signs the hash of the precise standard presentation it verified');
      assert.equal(paid.gate.vcBindingId, synced.authorization.document.vcBindingId);
      const afterPaid = await state(mode);
      assert.equal(afterPaid.ledger.executionCount, startCount + 1);
      const tokenBalance = (snapshot, id) => snapshot.ledger.accounts.find(account => account.id === id)?.balanceMinor;
      assert.equal(tokenBalance(afterPaid, proposed.order.payerAccount), tokenBalance(initial, proposed.order.payerAccount) - proposed.order.amountMinor, 'chain payer balance reflects one transfer');
      assert.equal(tokenBalance(afterPaid, proposed.order.payeeAccount), tokenBalance(initial, proposed.order.payeeAccount) + proposed.order.amountMinor, 'chain merchant balance reflects one transfer');

      const retried = success(await payment(mode, 'retry'), 'retry same authorized order with fresh DBAC proof');
      assert.equal(retried.paymentResult.outcome, 'ALREADY_PROCESSED');
      assert.equal(retried.paymentResult.receipt.transactionHash, paid.paymentResult.receipt.transactionHash);
      assert.deepEqual(retried.paymentResult.receipt, paid.paymentResult.receipt);
      assert.notEqual(retried.wire.context.challengeId, paid.wire.context.challengeId, 'retry obtains a fresh device proof challenge');
      assert.notDeepEqual(retried.wire.proof, paid.wire.proof, 'retry proof binds the fresh payment request');
      assert.equal(retried.wire.proof.randomizedDevicePublicKey, paid.wire.proof.randomizedDevicePublicKey, 'one order retains the Owner-bound pseudonym');
      assert.equal((await state(mode)).ledger.executionCount, startCount + 1, 'retry never transfers twice');

      const demo = success(await payment(mode, 'demo'), 'run payment adversarial cases');
      assert.ok(Array.isArray(demo.results) && demo.results.length > 0);
      assert.equal(demo.total, 17, 'the complete payment attack suite runs'); assert.equal(demo.total, demo.results.length); assert.equal(demo.passed, demo.total);
      assert.ok(demo.results.every(result => result.pass === true), 'every reported payment attack has the expected result');
      assert.ok(demo.results.some(result => traceOf(result)?.outcome === 'fail'), 'attack demo includes an actual rejected verifier request');
      assert.equal((await state(mode)).ledger.executionCount, startCount + 1, 'payment attacks and retries retain a single debit');
      assert.equal(success(await api('/api/state'), 'named VC still unused').credential, null);
      assert.equal(success(await api('/api/device'), 'named device remains locked').locked, true);
      observed.set(mode, { orderId: proposed.order.orderId, orderKey: proposed.orderKey, bindingId: issued.w3c.originalCredential.credentialSubject.bindingId, transactionHash: paid.paymentResult.receipt.transactionHash });
      if (mode === modes[0]) {
        const other = await state(modes[1]);
        assert.equal(other.credential, null); assert.equal(other.proposal, null); assert.equal(other.authorization, null);
        assert.notEqual(other.order.orderId, proposed.order.orderId, 'modes have separate orders');
      }
    });
  }
  assert.equal(observed.size, 2);
  assert.notEqual(observed.get(modes[0]).transactionHash, observed.get(modes[1]).transactionHash, 'both modes produced their own real transfers');
  assert.notEqual(observed.get(modes[0]).orderKey, observed.get(modes[1]).orderKey, 'schemes do not share the order pseudonym');
  const beforeNew = await state(modes[0]);
  const next = success(await payment(modes[0], 'new'), 'create next order');
  assert.notEqual(next.order.orderId, beforeNew.order.orderId); assert.equal(next.proposal, null); assert.equal(next.authorization, null);
  assert.equal(next.ledger.executionCount, beforeNew.ledger.executionCount, 'new order retains settlement records');
  const reproposed = success(await payment(modes[0], 'propose'), 'propose the next order using the existing payment credential');
  assert.notEqual(reproposed.orderKey, beforeNew.orderKey, 'a new order randomizes the device pseudonym again');
  assert.equal(reproposed.wire.proof.verifiableCredential.credentialSubject.bindingId, observed.get(modes[0]).bindingId, 'reusing one VC keeps its disclosed binding ID linkable across orders');
  assert.equal((await state(modes[1])).order.orderId, observed.get(modes[1]).orderId, 'new order in one mode does not replace the other mode');
});

test('DBAC-only startup explicitly reports payment unavailable and never simulates a payment', { timeout: 60000 }, async t => {
  const runtime = await startDbacDemo();
  t.after(() => runtime.close());
  const api = (path, body) => request(runtime.a.baseUrl, path, { body, headers: { 'X-Demo-UI-Key': runtime.uiToken } });
  for (const mode of modes) {
    const state = success(await api(`/api/dbac/payment/state?mode=${mode}`), 'DBAC-only payment availability');
    assert.equal(state.available, false);
    const denied = await api('/api/dbac/payment/pay', { mode });
    assert.equal(denied.status, 503); assert.equal(typeof denied.data.error?.code, 'string');
    assert.equal(denied.data.paymentResult, undefined, 'unavailable service never returns a fake payment receipt');
  }
  assert.equal((await request(runtime.a.baseUrl, '/dbac-payment.js')).status, 200, 'DBAC-only still serves the payment UI and its unavailable state');
});
