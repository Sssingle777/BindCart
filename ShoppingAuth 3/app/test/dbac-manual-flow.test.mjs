import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { presentationHeader, w3cPresentationHash } from '../lib/dbac/w3c-profile.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const modes = ['bbs-bls', 'bbs-blind-bls'];

// Same isolated process/chain setup as dbac-payment-flow.test.mjs. Startup
// capability URLs stay only in memory; failures never print the captured log.
async function startIsolatedLauncher(t) {
  const directory = await mkdtemp(join(tmpdir(), 'dbac-manual-flow-'));
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
    assert.equal(groupExists(), false, 'all manual-flow launcher children exit');
  });
  for (let attempt = 0; attempt < 1000; attempt++) {
    if (stopped) throw new Error(/EPERM|EACCES/.test(stderr) ? 'Manual-flow listener permission denied.' : 'Manual-flow launcher stopped before readiness.');
    const match = stdout.match(/(http:\/\/127\.0\.0\.1:\d+)\/#key=([A-Za-z0-9_-]{43})&ownerKey=([A-Za-z0-9_-]{43})/);
    if (match) return { baseUrl: match[1], uiKey: match[2], ownerKey: match[3] };
    await delay(50, undefined, { signal: t.signal });
  }
  throw new Error('Manual-flow launcher did not publish its unified entry.');
}
async function request(baseUrl, path, { body, headers = {} } = {}) {
  const response = await fetch(new URL(path, baseUrl), {
    method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(90000),
    headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return { status: response.status, data: await response.json() };
}
function success(response, label) {
  assert.equal(response.status, 200, `${label}: HTTP ${response.status} (${response.data?.error?.code ?? 'no error code'})`);
  return response.data;
}
function denied(response, code) {
  assert.ok(response.status >= 400 && response.status < 500, `manual action must be rejected, got ${response.status}`);
  if (code) assert.equal(response.data?.error?.code, code);
  return response.data;
}
const balances = state => Object.fromEntries(state.ledger.accounts.map(account => [account.id, account.balanceMinor]));
const signatureCount = (state, mode) => state.manual.device.modes[mode].signatures;
function entries(value, result = []) {
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) { result.push({ key, value: child }); entries(child, result); }
  return result;
}
function publicOnly(state) {
  assert.ok(state.manual && Array.isArray(state.manual.log) && Array.isArray(state.manual.availableActions), 'manual state exposes public progress');
  const exposed = entries(state.manual);
  for (const key of ['privateKey', 'secretKey', 'accessToken', 'uiToken', 'proposalToken', 'ownerUiKey', 'deviceSecretKey', 'issuerSecretKey', 'credential', 'rawCredential', 'originalCredential', 'paymentBinding', 'preparedState', 'opaqueState']) {
    assert.equal(exposed.some(entry => entry.key === key), false, `manual snapshot never serializes ${key}`);
  }
  for (const key of ['state', 'binding', 'k', 'blind', 'credential']) assert.equal(Object.hasOwn(state.manual, key), false, `manual public view excludes internal ${key}`);
  for (const event of state.manual.log) {
    for (const key of ['id', 'time', 'from', 'to', 'action', 'status', 'summary']) assert.equal(typeof event[key], 'string', `event provides public ${key}`);
  }
}
function checkpoint(state) {
  return { attemptId: state.manual.attemptId, phase: state.manual.phase, stage: state.manual.stage, deviceRequest: state.manual.deviceRequest, deviceResponse: state.manual.deviceResponse,
    verifiableCredential: state.manual.verifiableCredential, sentCredential: state.manual.sentCredential, cryptography: state.manual.cryptography,
    presentation: state.manual.presentation, verificationResult: state.manual.verificationResult, ownerSubmitted: state.manual.ownerSubmitted, walletSigned: state.manual.walletSigned,
    log: state.manual.log, availableActions: state.manual.availableActions, executionCount: state.ledger.executionCount, balances: balances(state) };
}

// Real launcher processes, BLS device signatures, BBS verifier, explicit Owner
// decisions and local EVM. No fixture replaces a signature or settlement here.
test('manual multiparty DBAC flow advances only on each explicit message and settles once per mode', { timeout: 240000 }, async t => {
  const fixture = await startIsolatedLauncher(t);
  const api = (path, body) => request(fixture.baseUrl, path, { body, headers: { 'X-Demo-UI-Key': fixture.uiKey } });
  const state = async mode => success(await api(`/api/dbac/payment/state?mode=${mode}`), 'read manual payment state');
  const rawManual = (mode, action, attemptId, extra = {}) => api('/api/dbac/payment/manual', { mode, action, ...(attemptId === undefined ? {} : { attemptId }), ...extra });
  const attemptIds = new Map();
  const step = async (mode, action) => {
    const result = success(await rawManual(mode, action, attemptIds.get(mode)), `manual ${mode}/${action}`);
    if (result.manual.attemptId) attemptIds.set(mode, result.manual.attemptId);
    publicOnly(result);
    return result;
  };
  const owner = (path, body) => request(fixture.baseUrl, `/owner${path}`, { body, headers: { 'X-Owner-UI-Key': fixture.ownerKey, Origin: fixture.baseUrl } });
  const stableRefresh = async (mode, expected) => {
    const first = await state(mode), second = await state(mode);
    publicOnly(first); publicOnly(second);
    assert.deepEqual(checkpoint(first), checkpoint(expected), 'GET state does not advance the current manual operation');
    assert.deepEqual(checkpoint(second), checkpoint(first), 'repeated GET state does not send another message');
    assert.equal(signatureCount(second, mode), signatureCount(expected, mode), 'refresh never asks the device to sign');
    return second;
  };
  const unchangedLedger = (current, reference) => {
    assert.equal(current.ledger.executionCount, reference.ledger.executionCount, 'no transfer before explicit settlement verification');
    assert.deepEqual(balances(current), balances(reference), 'no balance changes before explicit settlement verification');
  };
  const verifyPass = result => {
    assert.equal(result.manual.verificationResult?.accepted, true);
    const trace = result.manual.verificationResult.verificationTrace;
    assert.equal(trace?.source, 'agent-b'); assert.equal(trace?.outcome, 'pass');
    for (const id of ['w3c_bbs', 'vc_device_binding', 'knowledge', 'credential_pairing', 'device_pairing', 'consume']) assert.equal(trace.steps.find(item => item.id === id)?.status, 'pass', `B performed ${id}`);
    assert.deepEqual(result.manual.sentCredential, result.manual.verifiableCredential, 'B receives the exact displayed selective-disclosure VC');
  };
  const attack = async (mode, action, expected, reference) => {
    const result = await step(mode, action);
    assert.equal(result.manual.lastAttack?.expected, expected);
    assert.equal(result.manual.lastAttack?.actual, expected);
    assert.equal(result.manual.lastAttack?.pass, true, 'the requested single attack was actually rejected');
    assert.equal(result.manual.stage, reference.manual.stage, 'an attack never advances the normal flow');
    assert.equal(result.manual.attemptId, reference.manual.attemptId);
    assert.equal(signatureCount(result, mode), signatureCount(reference, mode), 'the attack does not borrow a legitimate device contribution');
    assert.deepEqual(result.manual.presentation, reference.manual.presentation, 'attack does not overwrite the original proof');
    assert.deepEqual(result.manual.deviceResponse, reference.manual.deviceResponse, 'attack does not replace the legitimate response');
    assert.equal(result.ledger.executionCount, reference.ledger.executionCount);
    assert.deepEqual(balances(result), balances(reference));
    return result;
  };

  denied(await request(fixture.baseUrl, '/api/dbac/payment/manual', { body: { mode: modes[0], action: 'begin-proposal' } }), 'UI_ACCESS_DENIED');
  denied(await rawManual(modes[0], 'begin-proposal', undefined, { automatic: true }), 'DBAC_PAYMENT_INVALID_INPUT');
  denied(await rawManual(modes[0], 'begin-proposal', 1), 'DBAC_PAYMENT_INVALID_INPUT');
  assert.equal(success(await api('/api/state'), 'named profile unused').credential, null);
  success(await api('/api/device/lock', { locked: true }), 'lock original jCardSim comparison device');
  const observed = new Map();
  for (const mode of modes) {
    await t.test(`${mode}: challenge → simulated eSIM → proof → verifier → Owner → wallet → chain`, async () => {
      const initial = await state(mode);
      assert.equal(initial.manual.active, false); unchangedLedger(initial, initial); publicOnly(initial);
      const issued = success(await api('/api/dbac/payment/issue', { mode }), 'issue BBS payment credential');
      const afterIssue = await state(mode);
      const startSignatures = signatureCount(afterIssue, mode);
      assert.equal(issued.credential.attributes.find(attribute => attribute.name === 'scope').value, 'payments:pay');
      assert.equal(afterIssue.w3c.enabled, true);
      const originalVc = afterIssue.w3c.originalCredential;
      assert.equal(originalVc['@context'][0], 'https://www.w3.org/ns/credentials/v2');
      assert.equal(originalVc.proof.type, 'DataIntegrityProof'); assert.equal(originalVc.proof.cryptosuite, 'bbs-2023');
      assert.deepEqual(Object.keys(originalVc.credentialSubject).sort(), ['role', 'scope', 'epoch', 'mode', 'bindingId', 'holderDid', 'organization', 'holderLabel'].sort());
      assert.equal(originalVc.credentialSubject.mode, mode);
      assert.equal(originalVc.credentialSubject.bindingId, issued.credential.attributes.find(attribute => attribute.name === 'bindingId').value, 'standard VC and eSIM-bound credential share the signed binding identifier');
      denied(await rawManual(mode, 'begin-authorize'), 'DBAC_MANUAL_STAGE');
      unchangedLedger(await state(mode), initial);

      let prepared = await step(mode, 'begin-proposal');
      assert.equal(prepared.manual.phase, 'proposal'); assert.equal(prepared.manual.stage, 'CHALLENGE_READY');
      assert.equal(prepared.manual.active, true); assert.equal(prepared.manual.expired, false);
      assert.ok(prepared.manual.challenge, 'challenge is reviewable before deriving the VC');
      assert.equal(prepared.manual.cryptography, null, 'no derived cryptographic diagnostics before derivation');
      assert.ok(!prepared.manual.deviceRequest && !prepared.manual.verifiableCredential && !prepared.manual.sentCredential, 'requesting a challenge does not derive a VC or prepare an eSIM request');
      assert.ok(!prepared.manual.deviceResponse && !prepared.manual.presentation && !prepared.manual.verificationResult);
      assert.equal(signatureCount(prepared, mode), startSignatures, 'preparation obtains a challenge without invoking the simulated eSIM');
      assert.equal(prepared.proposal, null); unchangedLedger(prepared, initial);
      await stableRefresh(mode, prepared);
      denied(await rawManual(mode, 'device-sign'), 'DBAC_MANUAL_ATTEMPT_MISMATCH');
      denied(await rawManual(mode, 'device-sign', randomUUID()), 'DBAC_MANUAL_ATTEMPT_MISMATCH');
      denied(await rawManual(mode, 'begin-proposal'), 'DBAC_MANUAL_ATTEMPT_MISMATCH');
      denied(await rawManual(mode, 'discard'), 'DBAC_MANUAL_ATTEMPT_MISMATCH');
      denied(await rawManual(mode, 'prove', attemptIds.get(mode)), 'DBAC_MANUAL_STAGE');
      denied(await rawManual(mode, 'device-sign', attemptIds.get(mode)), 'DBAC_MANUAL_STAGE');
      denied(await rawManual(mode, 'wallet-sign', attemptIds.get(mode)), 'DBAC_MANUAL_STAGE');
      denied(await api('/api/dbac/payment/pay', { mode }), 'DBAC_MANUAL_ACTIVE');
      const otherMode = modes.find(value => value !== mode);
      const otherBefore = await state(otherMode);
      denied(await rawManual(otherMode, 'device-sign', attemptIds.get(mode)));
      // Recording a rejected action is allowed, but it cannot change any
      // protocol stage, prepared message, device contribution or balance.
      assert.deepEqual({ ...checkpoint(await state(otherMode)), log: null }, { ...checkpoint(otherBefore), log: null }, 'another mode cannot use this attempt');

      prepared = await step(mode, 'derive-vc');
      assert.equal(prepared.manual.stage, 'VC_DERIVED');
      assert.ok(prepared.manual.deviceRequest && prepared.manual.verifiableCredential, 'explicit holder derivation prepares the VC-bound eSIM request');
      assert.ok(!prepared.manual.sentCredential, 'deriving locally does not send the credential to B');
      assert.deepEqual(Object.keys(prepared.manual.verifiableCredential.credentialSubject).sort(), ['role', 'scope', 'epoch', 'mode', 'bindingId', 'holderDid'].sort());
      assert.equal(prepared.manual.verifiableCredential.proof.cryptosuite, 'bbs-2023');
      assert.deepEqual(prepared.manual.cryptography, {
        presentationHeader: Buffer.from(presentationHeader(prepared.manual.challenge)).toString('hex'),
        w3cPresentationHash: w3cPresentationHash(prepared.manual.verifiableCredential),
      }, 'public diagnostics are the actual derivation header and exact VC digest');
      assert.deepEqual(prepared.manual.log.findLast(item => item.action === 'derive-vc').data.cryptography, prepared.manual.cryptography, 'historical derivation preserves its own public hashes');
      assert.equal(prepared.manual.verifiableCredential.credentialSubject.bindingId, originalVc.credentialSubject.bindingId);
      assert.equal(JSON.stringify(prepared.manual.verifiableCredential).includes(originalVc.credentialSubject.organization), false);
      assert.equal(JSON.stringify(prepared.manual.verifiableCredential).includes(originalVc.credentialSubject.holderLabel), false);
      assert.equal(signatureCount(prepared, mode), startSignatures, 'derivation uses public issuer material without invoking eSIM');
      unchangedLedger(prepared, initial); await stableRefresh(mode, prepared);
      denied(await rawManual(mode, 'derive-vc', attemptIds.get(mode)), 'DBAC_MANUAL_STAGE');

      prepared = await attack(mode, 'test-no-device', 'W3C_DEVICE_PROOF_REQUIRED', prepared);
      assert.equal(prepared.manual.lastAttack.verificationTrace?.steps?.find(item => item.id === 'w3c_bbs')?.status, 'pass', 'a copied standard VC is cryptographically valid');
      assert.equal(prepared.manual.lastAttack.verificationTrace?.steps?.find(item => item.id === 'vc_device_binding')?.status, 'fail', 'B separately refuses use without the bound eSIM proof');
      prepared = await attack(mode, 'test-wrong-device', 'DBAC_DEVICE_SIGNATURE_INVALID', prepared);
      assert.equal(prepared.manual.stage, 'VC_DERIVED');
      assert.ok(!prepared.manual.presentation && !prepared.manual.verificationResult);

      success(await api('/api/dbac/device/lock', { mode, locked: true }), 'lock paper software eSIM');
      denied(await rawManual(mode, 'device-sign', attemptIds.get(mode)), 'DBAC_DEVICE_LOCKED');
      const locked = await state(mode);
      assert.equal(locked.manual.stage, 'VC_DERIVED'); assert.equal(locked.manual.attemptId, prepared.manual.attemptId);
      assert.equal(signatureCount(locked, mode), startSignatures); assert.ok(!locked.manual.deviceResponse && !locked.manual.presentation);
      unchangedLedger(locked, initial);
      success(await api('/api/dbac/device/lock', { mode, locked: false }), 'unlock paper software eSIM');
      const signed = await step(mode, 'device-sign');
      assert.equal(signed.manual.stage, 'DEVICE_SIGNED'); assert.equal(signatureCount(signed, mode), startSignatures + 1);
      assert.equal(typeof signed.manual.deviceResponse?.signature, 'string'); assert.ok(!signed.manual.presentation && !signed.manual.verificationResult);
      await stableRefresh(mode, signed);
      denied(await rawManual(mode, 'verify', attemptIds.get(mode)), 'DBAC_MANUAL_STAGE');
      denied(await rawManual(mode, 'device-sign', attemptIds.get(mode)), 'DBAC_MANUAL_STAGE');
      const proved = await step(mode, 'prove');
      assert.equal(proved.manual.stage, 'PROOF_READY'); assert.ok(proved.manual.presentation?.proof);
      assert.equal(signatureCount(proved, mode), startSignatures + 1, 'proof construction does not ask the device to sign again');
      assert.ok(!proved.manual.verificationResult); assert.equal(proved.proposal, null); unchangedLedger(proved, initial);
      await stableRefresh(mode, proved);
      await attack(mode, 'test-tamper', 'DBAC_BODY_MISMATCH', proved);
      const proposalVerified = await step(mode, 'verify');
      assert.equal(proposalVerified.manual.stage, 'VERIFIED'); verifyPass(proposalVerified);
      assert.equal(proposalVerified.proposal, null, 'B verification does not submit an Owner proposal automatically');
      unchangedLedger(proposalVerified, initial);
      const submitted = await step(mode, 'submit-owner');
      assert.equal(submitted.manual.stage, 'OWNER_SUBMITTED'); assert.equal(submitted.proposal.status, 'PENDING');
      assert.equal(submitted.authorization, null); unchangedLedger(submitted, initial);
      await stableRefresh(mode, submitted);
      const ownerState = success(await owner('/api/state'), 'read explicit Owner proposals');
      const proposal = ownerState.proposals.find(item => item.id === submitted.proposal.id);
      assert.equal(proposal.mode, mode); assert.equal(proposal.profile, 'dbac-payment');
      const approved = success(await owner(`/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }), 'explicitly approve exact order');
      assert.equal(approved.status, 'APPROVED');
      // GET can refresh public Owner information, but never advances a message stage.
      const approvedView = await state(mode);
      assert.equal(approvedView.manual.stage, 'OWNER_SUBMITTED'); unchangedLedger(approvedView, initial);
      const synchronized = await step(mode, 'sync-owner');
      assert.equal(synchronized.manual.stage, 'OWNER_SUBMITTED');
      assert.equal(synchronized.proposal.status, 'APPROVED'); assert.ok(synchronized.authorization?.token);
      const ownerAuthorization = JSON.parse(Buffer.from(synchronized.authorization.token.split('.')[1], 'base64url').toString('utf8'));
      assert.equal(ownerAuthorization.credentialProfile, afterIssue.w3c.profile);
      assert.equal(ownerAuthorization.w3cIssuer, originalVc.issuer);
      assert.equal(ownerAuthorization.vcBindingId, originalVc.credentialSubject.bindingId, 'Owner authorization fixes the same W3C VC binding identifier');
      unchangedLedger(synchronized, initial);

      prepared = await step(mode, 'begin-authorize');
      assert.equal(prepared.manual.phase, 'authorize'); assert.equal(prepared.manual.stage, 'CHALLENGE_READY');
      assert.notEqual(prepared.manual.attemptId, proposalVerified.manual.attemptId);
      denied(await rawManual(mode, 'device-sign', proposalVerified.manual.attemptId), 'DBAC_MANUAL_ATTEMPT_MISMATCH');
      denied(await rawManual(mode, 'discard', proposalVerified.manual.attemptId), 'DBAC_MANUAL_ATTEMPT_MISMATCH');
      assert.equal(signatureCount(prepared, mode), startSignatures + 1); assert.ok(!prepared.manual.deviceResponse && !prepared.manual.presentation);
      assert.ok(!prepared.manual.verifiableCredential && !prepared.manual.deviceRequest && !prepared.manual.sentCredential);
      unchangedLedger(prepared, initial);
      const authVc = await step(mode, 'derive-vc');
      assert.equal(authVc.manual.stage, 'VC_DERIVED');
      assert.equal(signatureCount(authVc, mode), startSignatures + 1);
      assert.notEqual(authVc.manual.verifiableCredential.proof.proofValue, proposalVerified.manual.verifiableCredential.proof.proofValue, 'authorization uses a newly derived proof bound to its own challenge');
      assert.equal(authVc.manual.verifiableCredential.credentialSubject.bindingId, originalVc.credentialSubject.bindingId);
      await stableRefresh(mode, authVc);
      const authSigned = await step(mode, 'device-sign');
      assert.equal(signatureCount(authSigned, mode), startSignatures + 2);
      const authProved = await step(mode, 'prove');
      assert.equal(authProved.manual.presentation.randomizedDevicePublicKey, proved.manual.presentation.randomizedDevicePublicKey, 'the same order retains its approved device pseudonym');
      assert.notEqual(authProved.manual.presentation.deviceSignature, proved.manual.presentation.deviceSignature);
      assert.notDeepEqual(authProved.manual.presentation.proof, proved.manual.presentation.proof);
      const authVerified = await step(mode, 'verify');
      assert.equal(authVerified.manual.stage, 'VERIFIED'); verifyPass(authVerified);
      assert.equal(authVerified.manual.walletSigned, false); unchangedLedger(authVerified, initial);
      await stableRefresh(mode, authVerified);
      const walletSigned = await step(mode, 'wallet-sign');
      assert.equal(walletSigned.manual.stage, 'WALLET_SIGNED'); assert.equal(walletSigned.manual.walletSigned, true);
      assert.equal(signatureCount(walletSigned, mode), startSignatures + 2); unchangedLedger(walletSigned, initial);
      await stableRefresh(mode, walletSigned);

      const settlementPrepared = await step(mode, 'begin-settle');
      assert.equal(settlementPrepared.manual.phase, 'settle'); assert.equal(settlementPrepared.manual.stage, 'CHALLENGE_READY');
      assert.equal(signatureCount(settlementPrepared, mode), startSignatures + 2); unchangedLedger(settlementPrepared, initial);
      assert.ok(!settlementPrepared.manual.verifiableCredential && !settlementPrepared.manual.deviceRequest && !settlementPrepared.manual.sentCredential);
      const settleVc = await step(mode, 'derive-vc');
      assert.equal(settleVc.manual.stage, 'VC_DERIVED');
      assert.equal(signatureCount(settleVc, mode), startSignatures + 2);
      assert.notEqual(settleVc.manual.verifiableCredential.proof.proofValue, authVc.manual.verifiableCredential.proof.proofValue, 'settlement derives a fresh challenge-bound W3C proof');
      assert.equal(settleVc.manual.verifiableCredential.credentialSubject.bindingId, originalVc.credentialSubject.bindingId);
      await stableRefresh(mode, settleVc);
      const settleSigned = await step(mode, 'device-sign');
      assert.equal(signatureCount(settleSigned, mode), startSignatures + 3); unchangedLedger(settleSigned, initial);
      const settleProved = await step(mode, 'prove');
      assert.equal(settleProved.manual.presentation.randomizedDevicePublicKey, proved.manual.presentation.randomizedDevicePublicKey);
      assert.notDeepEqual(settleProved.manual.presentation.proof, authProved.manual.presentation.proof);
      unchangedLedger(settleProved, initial); await stableRefresh(mode, settleProved);
      const settled = await step(mode, 'verify');
      assert.equal(settled.manual.stage, 'SETTLED'); verifyPass(settled);
      const paymentResult = settled.manual.verificationResult.paymentResult;
      assert.equal(paymentResult.outcome, 'EXECUTED'); assert.equal(paymentResult.receipt.transactionStatus, 'success');
      assert.match(paymentResult.receipt.transactionHash, /^0x[0-9a-f]{64}$/);
      assert.equal(settled.ledger.executionCount, initial.ledger.executionCount + 1);
      assert.equal(balances(settled)[settled.order.payerAccount], balances(initial)[settled.order.payerAccount] - settled.order.amountMinor);
      assert.equal(balances(settled)[settled.order.payeeAccount], balances(initial)[settled.order.payeeAccount] + settled.order.amountMinor);
      assert.equal(signatureCount(settled, mode), startSignatures + 3, 'exactly one simulated eSIM contribution per payment phase');
      await stableRefresh(mode, settled);
      const replayed = await attack(mode, 'replay', 'DBAC_REPLAY', settled);
      assert.equal(replayed.manual.verificationResult.paymentResult.receipt.transactionHash, paymentResult.receipt.transactionHash);
      const attackEvents = replayed.manual.log.filter(event => ['test-no-device', 'test-wrong-device', 'test-tamper', 'replay'].includes(event.action));
      assert.equal(attackEvents.length, 4, 'exactly four single attack actions were requested; no automatic batch ran');
      t.diagnostic(`${mode}: payer ${balances(initial)[settled.order.payerAccount]} → ${balances(settled)[settled.order.payerAccount]}; merchant ${balances(initial)[settled.order.payeeAccount]} → ${balances(settled)[settled.order.payeeAccount]}; executions ${initial.ledger.executionCount} → ${settled.ledger.executionCount}; device contributions +${signatureCount(settled, mode) - startSignatures}`);
      observed.set(mode, { initial, settled, orderKey: proved.manual.presentation.randomizedDevicePublicKey, transactionHash: paymentResult.receipt.transactionHash });
    });
  }
  assert.equal(observed.size, 2); assert.notEqual(observed.get(modes[0]).orderKey, observed.get(modes[1]).orderKey);
  assert.notEqual(observed.get(modes[0]).transactionHash, observed.get(modes[1]).transactionHash);
  assert.equal(success(await api('/api/state'), 'named profile remains unused').credential, null);
  assert.equal(success(await api('/api/device'), 'named jCardSim remains locked').locked, true);
});
