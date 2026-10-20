import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { mkdtemp, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { generateIdentity } from '../lib/identity.mjs';
import { serializeIdentity } from '../lib/protocol.mjs';
import { createLocalX402Environment, createX402Payer } from '../lib/x402-payment.mjs';
import { createDbacPaymentSession } from '../lib/dbac/payment-session.mjs';
import { createLivePaymentSession } from '../lib/storefront/live-payment-session.mjs';
import { createStorefrontController } from '../lib/storefront/controller.mjs';
import { loadMerchantIdentity } from '../lib/storefront/merchant.mjs';

const directory = await mkdtemp(resolve(tmpdir(), 'manual-shopping-'));
const report = { startedAt: new Date().toISOString(), checks: [], status: 'running' }, children = [];
let environment, closing = false;
const token = () => randomBytes(32).toString('base64url');
const check = name => { report.checks.push({ name, passed: true }); console.log(`PASS ${name}`); };
async function launch(path, config) {
  return new Promise((ready, reject) => {
    const child = fork(new URL(`../${path}`, import.meta.url), [], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] }); children.push(child);
    let errors = ''; child.stderr.on('data', v => { errors = (errors + v).slice(-4000); });
    const timer = setTimeout(() => reject(new Error(`${path} startup timeout`)), 30000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', () => { clearTimeout(timer); if (!closing) reject(new Error(`${path} stopped ${errors}`)); });
    child.once('message', data => { clearTimeout(timer); data.error ? reject(new Error(data.error)) : ready({ ...data, child }); }); child.send(config);
  });
}
async function post(url, body, headers = {}) {
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) });
  return { status: response.status, data: await response.json() };
}
try {
  const merchantDirectory = resolve(directory, 'merchant'), merchantIdentity = await loadMerchantIdentity(merchantDirectory);
  const trusted = { did: merchantIdentity.did, merchantId: 'mystore', payeeAccount: 'merchant:keyboard' };
  const legacyIssuer = generateIdentity('unused legacy issuer'), holder = generateIdentity('holder policy'), inactiveDevice = generateIdentity('unused named device'), b = generateIdentity('Agent B');
  const deviceToken = token(), issuerToken = token(), statusToken = token(), adminToken = token(), proposalToken = token(), ownerKey = token();
  const device = await launch('dbac-role.mjs', { role: 'device', accessToken: deviceToken, port: 0 });
  const issuer = await launch('dbac-role.mjs', { role: 'issuer', w3c: true, requireHolderProof: true, accessToken: issuerToken, statusToken, statePath: resolve(directory, 'credential-status.json'), devicePublicKeys: device.publicKeys, port: 0 });
  const owner = await launch('owner.mjs', { holderDid: holder.did, verifierDid: b.did, trustedIssuers: [legacyIssuer.did], dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer, proposalToken, uiToken: ownerKey, port: 0 });
  const verifier = await launch('agent-b.mjs', { identity: serializeIdentity(b), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], adminToken, ledgerPath: resolve(directory, 'verifier.sqlite'), port: 0, dbac: { trustedMerchant: trusted, issuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c, requireHolderProof: true, statusSource: { baseUrl: issuer.baseUrl, accessToken: statusToken } } });
  environment = await createLocalX402Environment({ stateDir: resolve(directory, 'x402'), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], holderDid: holder.did, deviceDid: inactiveDevice.did, verifierDid: b.did, dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer, isCredentialRevoked: async () => true, async isDbacCredentialRevoked(bindingId) { const result = await post(`${issuer.baseUrl}/credential/status`, { bindingId }, { 'X-DBAC-Access': statusToken }); assert.equal(result.status, 200); return result.data.status === 'revoked'; } });
  await new Promise((ready, reject) => { verifier.child.once('message', m => m.stage === 'x402-ready' ? ready() : reject(new Error(m.error))); verifier.child.send({ stage: 'configure-x402', backendConfig: environment.backendConfig }); });
  const events = [], options = { baseUrl: verifier.baseUrl, verifierDid: b.did, issuer: { publicKey: issuer.publicKey, w3c: issuer.w3c, baseUrl: issuer.baseUrl, accessToken: issuerToken }, device: { publicKeys: device.publicKeys, baseUrl: device.baseUrl, accessToken: deviceToken }, owner: { baseUrl: owner.baseUrl, did: owner.did, proposalToken }, x402Payer: createX402Payer(environment.payerConfig), paymentInfo: environment.publicInfo, getLedger: () => environment.snapshot() };
  let raw = createDbacPaymentSession(options), payments = createLivePaymentSession({ paymentSession: raw, stageDelayMs: 1600, emit: e => events.push(e) });
  const controllerOptions = { paymentSession: payments, directory: resolve(directory, 'orders'), merchant: { directory: merchantDirectory, trusted }, paymentInfo: environment.publicInfo };
  let controller = await createStorefrontController(controllerOptions);
  let state = await controller.state();
  state = await controller.changeCart({ productId: '02', quantity: 1, revision: state.revision });
  state = await controller.changeCart({ productId: '03', quantity: 1, revision: state.revision });
  const initial = await environment.snapshot();
  state = await controller.checkout({ revision: state.revision });
  assert.equal(state.phase, 'verifying'); assert.equal(state.manualControl.nextAction, 'issue');
  assert.equal(state.backend.proposal, null); assert.equal(state.backend.currentCredentialId, null);
  assert.equal(state.backend.manual.stage, 'IDLE'); assert.equal(state.order.merchantOrder.snapshot.items.length, 2);
  check('checkout only creates the complete signed goods order; no credential/challenge/device/Owner action');
  const writes = () => events.filter(e => e.type === 'protocol' && e.status === 'complete').length;
  const signatures = async () => (await payments.inventory()).devices.find(d => d.id === 'default').signCount;
  const beforeReads = { writes: writes(), signatures: await signatures(), token: state.manualControl.token };
  for (let i = 0; i < 5; i++) state = await controller.state();
  assert.deepEqual({ writes: writes(), signatures: await signatures(), token: state.manualControl.token }, beforeReads);
  check('repeated reads leave protocol stage, signatures, replay token and wallet unchanged');
  async function act(action) {
    state = await controller.state();
    assert.equal(state.manualControl.nextAction, action, JSON.stringify(state.manualControl));
    const body = { action, orderId: state.order.orderId, revision: state.revision, attemptId: state.manualControl.attemptId, controlToken: state.manualControl.token };
    const before = writes();
    state = await controller.manual(body);
    assert.notEqual(state.manualControl.token, body.controlToken);
    assert.equal(writes() - before, action === 'issue' || action === 'confirm-merchant' ? 0 : 1, 'one click produces exactly one protocol effect');
    await assert.rejects(controller.manual(body), { code: 'STORE_STALE_CONTROL' });
    return state;
  }
  await act('issue');
  const validBody = { action: 'begin-proposal', orderId: state.order.orderId, revision: state.revision, attemptId: null, controlToken: state.manualControl.token };
  await assert.rejects(controller.manual({ ...validBody, action: 'wallet-sign' }), { code: 'STORE_MANUAL_STAGE' });
  await assert.rejects(controller.manual({ ...validBody, orderId: 'urn:uuid:00000000-0000-0000-0000-000000000000' }), { code: 'STORE_ORDER_CHANGED' });
  await assert.rejects(controller.manual({ ...validBody, attemptId: 'old-attempt' }), { code: 'DBAC_MANUAL_ATTEMPT_MISMATCH' });
  check('wrong order, stale click, illegal wallet step and stale attempt fail closed');
  async function proof(phase) { for (const action of [`begin-${phase}`, 'derive-vc', 'device-sign', 'prove', 'verify']) await act(action); }
  await proof('proposal');
  assert.equal(state.phase, 'verifying'); assert.equal(state.backend.proposal, null);
  assert.equal(state.verification.steps.find(s => s.id === 'merchant_order').status, 'pass');
  await act('submit-owner'); assert.equal(state.phase, 'checkout'); assert.equal(state.manualControl.nextAction, null);
  await assert.rejects(controller.pay({ orderId: state.order.orderId, revision: state.revision }), { code: 'OWNER_CONFIRMATION_REQUIRED' });
  check('qualification and Owner submission are separate; unpaid checkout only appears after actual verification');
  const proposal = state.backend.proposal;
  const approval = await post(`${owner.baseUrl}/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }, { 'X-Owner-UI-Key': ownerKey });
  assert.equal(approval.status, 200); await controller.observeOwnerDecision(approval.data);
  const beforePay = writes(), beforeSignatures = await signatures();
  state = await controller.pay({ orderId: state.order.orderId, revision: state.revision });
  assert.equal(state.phase, 'paying'); assert.equal(state.manualControl.nextAction, 'sync-owner');
  assert.equal(state.backend.proposal.status, 'PENDING'); assert.equal(state.backend.authorization, null);
  assert.equal(writes(), beforePay); assert.equal(await signatures(), beforeSignatures);
  assert.equal((await environment.snapshot()).executionCount, initial.executionCount);
  check('Owner approval and storefront Pay only arm the console; neither synchronizes, signs nor pays');
  await act('sync-owner'); assert.equal(state.backend.proposal.status, 'APPROVED');
  await proof('authorize');
  assert.equal(state.backend.manual.walletSigned, false); assert.equal((await environment.snapshot()).executionCount, initial.executionCount);
  await act('wallet-sign'); assert.equal(state.backend.manual.walletSigned, true);
  assert.equal((await environment.snapshot()).executionCount, initial.executionCount);
  await assert.rejects(controller.reset({ revision: state.revision }), { code: 'STORE_PAYMENT_UNRESOLVED' });
  check('explicit authorization proof and wallet signature remain separate, with no settlement and no reset');
  await proof('settle');
  assert.equal(state.phase, 'confirming'); assert.equal(state.receipt.transactionStatus, 'success');
  const paidLedger = await environment.snapshot(); assert.equal(paidLedger.executionCount, initial.executionCount + 1);
  assert.notEqual(state.merchant.status, 'confirmed'); const receiptHash = state.receipt.transactionHash;
  const afterSettlementSignatures = await signatures(), afterSettlementWrites = writes();
  state = await controller.queryPayment({ orderId: state.order.orderId, revision: state.revision });
  assert.equal(state.phase, 'confirming'); assert.notEqual(state.merchant.status, 'confirmed');
  assert.equal(state.receipt.transactionHash, receiptHash); assert.equal(await signatures(), afterSettlementSignatures);
  check('final settle Verify executes once; querying original receipt does not perform merchant confirmation');
  raw = createDbacPaymentSession(options); payments = createLivePaymentSession({ paymentSession: raw, emit: e => events.push(e) });
  controller = await createStorefrontController({ ...controllerOptions, paymentSession: payments });
  assert.notEqual((await raw.state()).order.orderId, state.order.orderId);
  state = await controller.queryPayment({ orderId: state.order.orderId, revision: state.revision });
  assert.equal(state.phase, 'confirming'); assert.equal(state.receipt.transactionHash, receiptHash);
  assert.equal(await signatures(), afterSettlementSignatures);
  check('fresh controller and Agent A with a different default order recover only the original full-bound receipt');
  await act('confirm-merchant'); assert.equal(state.phase, 'paid'); assert.equal(state.merchant.status, 'confirmed');
  state = await controller.queryPayment({ orderId: state.order.orderId, revision: state.revision });
  assert.equal(state.phase, 'paid'); assert.equal(state.merchant.status, 'confirmed');
  assert.equal(state.receipt.transactionHash, receiptHash); assert.equal(writes(), afterSettlementWrites);
  assert.equal((await environment.snapshot()).executionCount, paidLedger.executionCount);
  const reloaded = await createStorefrontController({ ...controllerOptions, paymentSession: payments }), restored = await reloaded.state();
  assert.equal(restored.phase, 'paid'); assert.equal(restored.receipt.transactionHash, receiptHash);
  check('merchant confirmation requires its own click; paid query and journal reload are idempotent');
  report.status = 'passed'; report.payment = { orderId: state.order.orderId, transactionHash: receiptHash, amountMinor: state.totalMinor, executionDelta: paidLedger.executionCount - initial.executionCount };
  report.actions = events.filter(e => e.type === 'protocol' && e.status === 'complete').map(({ action, phase }) => ({ action, phase }));
} catch (error) { report.status = 'failed'; report.error = { code: error.code, message: error.message, stack: error.stack }; console.error(error.stack); process.exitCode = 1; }
finally {
  closing = true;
  await Promise.all(children.map(async child => { if (child.exitCode !== null || child.signalCode !== null) return; const done = new Promise(r => child.once('exit', r)); child.disconnect(); await done; }));
  await environment?.close(); report.finishedAt = new Date().toISOString();
  const output = new URL('../../evidence/manual-console-integration.json', import.meta.url); await mkdir(new URL('.', output), { recursive: true }); await writeFile(output, JSON.stringify(report, null, 2));
}
