import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { mkdtemp, readFile, writeFile, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateIdentity, verifyJws, signJws } from '../lib/identity.mjs';
import { serializeIdentity, digest } from '../lib/protocol.mjs';
import { createLocalX402Environment, createX402Payer } from '../lib/x402-payment.mjs';
import { createDbacPaymentSession } from '../lib/dbac/payment-session.mjs';
import { createLivePaymentSession } from '../lib/storefront/live-payment-session.mjs';
import { createStorefrontController, CATALOG } from '../lib/storefront/controller.mjs';
import { loadMerchantIdentity, createLocalMerchant } from '../lib/storefront/merchant.mjs';
import { merchantOrderHash, MERCHANT_ORDER_TYP } from '../lib/storefront/merchant-protocol.mjs';
import { DBAC_EXTENSION } from '../lib/dbac/policy.mjs';
import { DBAC_PAYMENT_CHALLENGE_TYP } from '../lib/dbac/payment-policy.mjs';

const directory = await mkdtemp(resolve(tmpdir(), 'mystore-merchant-'));
const report = { startedAt: new Date().toISOString(), directory, checks: [], status: 'running' }, children = [];
let environment, closing = false;
const token = () => randomBytes(32).toString('base64url');
const check = (name, detail = {}) => { report.checks.push({ name, passed: true, ...detail }); console.log(`PASS ${name}`); };
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
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body), signal: AbortSignal.timeout(60000) });
  return { status: response.status, data: await response.json() };
}
try {
  const merchantDirectory = resolve(directory, 'merchant'), merchantIdentity = await loadMerchantIdentity(merchantDirectory);
  const trusted = { did: merchantIdentity.did, merchantId: 'mystore', payeeAccount: 'merchant:keyboard' };
  const legacyIssuer = generateIdentity('unused legacy issuer'), holder = generateIdentity('local holder policy'), inactiveDevice = generateIdentity('unused named device'), b = generateIdentity('Agent B');
  const deviceToken = token(), issuerToken = token(), statusToken = token(), adminToken = token(), proposalToken = token(), ownerKey = token();
  const device = await launch('dbac-role.mjs', { role: 'device', accessToken: deviceToken, port: 0 });
  const issuer = await launch('dbac-role.mjs', { role: 'issuer', w3c: true, requireHolderProof: true, accessToken: issuerToken, statusToken, statePath: resolve(directory, 'credential-status.json'), devicePublicKeys: device.publicKeys, port: 0 });
  const owner = await launch('owner.mjs', { holderDid: holder.did, verifierDid: b.did, trustedIssuers: [legacyIssuer.did], dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer, proposalToken, uiToken: ownerKey, port: 0 });
  const verifier = await launch('agent-b.mjs', { identity: serializeIdentity(b), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], adminToken, ledgerPath: resolve(directory, 'verifier.sqlite'), port: 0, dbac: { trustedMerchant: trusted, issuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c, requireHolderProof: true, statusSource: { baseUrl: issuer.baseUrl, accessToken: statusToken } } });
  environment = await createLocalX402Environment({ stateDir: resolve(directory, 'x402'), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], holderDid: holder.did, deviceDid: inactiveDevice.did, verifierDid: b.did, dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer, isCredentialRevoked: async () => true, async isDbacCredentialRevoked(bindingId) { const result = await post(`${issuer.baseUrl}/credential/status`, { bindingId }, { 'X-DBAC-Access': statusToken }); assert.equal(result.status, 200); return result.data.status === 'revoked'; } });
  await new Promise((ready, reject) => { verifier.child.once('message', m => m.stage === 'x402-ready' ? ready() : reject(new Error(m.error))); verifier.child.send({ stage: 'configure-x402', backendConfig: environment.backendConfig }); });
  const events = [];
  const options = { baseUrl: verifier.baseUrl, verifierDid: b.did, issuer: { publicKey: issuer.publicKey, w3c: issuer.w3c, baseUrl: issuer.baseUrl, accessToken: issuerToken }, device: { publicKeys: device.publicKeys, baseUrl: device.baseUrl, accessToken: deviceToken }, owner: { baseUrl: owner.baseUrl, did: owner.did, proposalToken }, x402Payer: createX402Payer(environment.payerConfig), paymentInfo: environment.publicInfo, getLedger: () => environment.snapshot() };
  let raw = createDbacPaymentSession(options), payments = createLivePaymentSession({ paymentSession: raw, emit: e => events.push(e) });
  const controllerOptions = { paymentSession: payments, directory: resolve(directory, 'orders'), merchant: { directory: merchantDirectory, trusted }, paymentInfo: environment.publicInfo, emit: e => events.push(e) };
  let controller = await createStorefrontController(controllerOptions), state = await controller.state();
  state = await controller.changeCart({ productId: '02', quantity: 1, revision: state.revision });
  state = await controller.changeCart({ productId: '03', quantity: 1, revision: state.revision });
  state = await controller.fault({ action: 'delay-merchant-once' });
  state = await controller.checkout({ revision: state.revision });
  assert.equal(state.phase, 'checkout'); assert.equal(state.order.amountMinor, 34_980_000); assert.equal(state.order.merchantOrder.snapshot.items.length, 2);
  assert.equal(state.verification.steps.find(s => s.id === 'merchant_order')?.status, 'pass');
  check('full MyStore cart is merchant-signed and independently verified by B', { snapshotHash: state.order.merchantOrder.snapshotHash });
  await assert.rejects(controller.pay({ orderId: state.order.orderId, revision: state.revision }), e => e.code === 'OWNER_CONFIRMATION_REQUIRED');
  const proposal = state.backend.proposal;
  const changed = structuredClone(proposal.payment); changed.merchantOrder.snapshot.items[0].quantity = 2;
  const deniedApproval = await post(`${owner.baseUrl}/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: changed, credentialHash: proposal.credentialHash }, { 'X-Owner-UI-Key': ownerKey });
  assert.equal(deniedApproval.status, 409);
  const approved = await post(`${owner.baseUrl}/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }, { 'X-Owner-UI-Key': ownerKey }); assert.equal(approved.status, 200);
  check('Owner confirmation rejects changed product snapshot and requires explicit exact-order approval');
  const before = await environment.snapshot();
  state = await controller.pay({ orderId: state.order.orderId, revision: state.revision });
  assert.equal(state.phase, 'confirming'); assert.equal(state.receipt.transactionStatus, 'success'); assert.equal(state.merchant.status, 'payment-confirmed');
  const transactionHash = state.receipt.transactionHash, orderId = state.order.orderId, signatures = (await payments.inventory()).devices.find(d => d.id === 'default').signCount;
  const paidLedger = await environment.snapshot(); assert.equal(paidLedger.executionCount, before.executionCount + 1);
  assert.equal(before.accounts.find(a => a.id === 'demo:alice').balanceMinor - paidLedger.accounts.find(a => a.id === 'demo:alice').balanceMinor, 34_980_000);
  await assert.rejects(controller.pay({ orderId, revision: state.revision }), e => e.code === 'STORE_PAYMENT_UNRESOLVED');
  await assert.rejects(controller.reset({ revision: state.revision }), e => e.code === 'STORE_PAYMENT_UNRESOLVED');
  check('actual original x402 transfer survives injected merchant-confirmation failure and blocks new payment/order', { orderId, transactionHash });
  // Reload persisted storefront and merchant records, keeping payment services alive.
  raw = createDbacPaymentSession(options); payments = createLivePaymentSession({ paymentSession: raw, emit: e => events.push(e) });
  controller = await createStorefrontController({ ...controllerOptions, paymentSession: payments });
  state = await controller.state(); assert.equal(state.phase, 'confirming');
  state = await controller.queryPayment({ orderId, revision: state.revision }); assert.equal(state.phase, 'paid'); assert.equal(state.merchant.status, 'confirmed'); assert.equal(state.receipt.transactionHash, transactionHash);
  assert.equal((await payments.inventory()).devices.find(d => d.id === 'default').signCount, signatures);
  assert.equal((await environment.snapshot()).executionCount, paidLedger.executionCount);
  check('restart of storefront recovers merchant confirmation by querying original receipt without signing or transfer');
  const duplicate = await controller.pay({ orderId, revision: state.revision }); assert.equal(duplicate.receipt.transactionHash, transactionHash);
  state = await controller.reset({ revision: state.revision });
  await payments.issue();
  const originalCredentialId = (await payments.state()).currentCredentialId;
  for (const scenario of ['copied-vc', 'revoked']) {
    state = await controller.experiment({ scenario });
    assert.equal(state.experiment.completion, 'completed'); assert.equal(state.experiment.expectationMet, true, JSON.stringify(state.experiment)); assert.equal(state.experiment.control.accepted, true); assert.equal(state.experiment.sideEffects.paymentExecutionDelta, 0); assert.equal(state.experiment.sideEffects.balancesUnchanged, true);
    assert.equal((await payments.state()).currentCredentialId, originalCredentialId);
    check(`real legal control and ${scenario} attack use separate credentials, reject at verifier, and leave balances unchanged`, { actual: state.experiment.actual });
  }
  // Send independently acquired challenge with modified JSON directly to B.
  // The verifier must reject the signed merchant mismatch even though a client
  // bypasses controller validation and possesses an otherwise real public proof.
  const merchant = await createLocalMerchant({ directory: merchantDirectory, trusted, paymentInfo: environment.publicInfo, queryPayment: o => payments.queryPayment(o) });
  const created = await merchant.create([{ ...CATALOG[0], quantity: 1, amountMinor: CATALOG[0].unitAmountMinor }], 1);
  await raw.newOrder(created.payment);
  const prepared = await raw.prepare({ phase: 'proposal' });
  for (const mutation of ['goods', 'payee']) {
    const body = JSON.parse(prepared.rawBody), payment = body.params.message.parts[0].data.payment;
    if (mutation === 'goods') { const item = payment.merchantOrder.snapshot.items[0]; item.productId = '03'; item.name = 'Sunglasses'; }
    else payment.settlement.payTo = payment.settlement.payerAddress;
    const rawBody = JSON.stringify(body), challenge = await post(`${verifier.baseUrl}/dbac/payment/challenge`, { mode: 'bbs-bls', bodyHash: digest(rawBody), paymentOrderId: payment.orderId }); assert.equal(challenge.status, 200);
    const context = verifyJws(challenge.data.challenge, { typ: DBAC_PAYMENT_CHALLENGE_TYP, expectedDid: b.did }).payload.context;
    const result = await post(`${verifier.baseUrl}/dbac/payment/a2a`, rawBody, { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Challenge': context.challengeId, 'X-A2A-DBAC-Proof': Buffer.from(JSON.stringify({ ...prepared.presentation, verifiableCredential: prepared.verifiableCredential, holderProof: prepared.holderProof })).toString('base64url') });
    assert.equal(result.status, 403); assert(['MERCHANT_SIGNATURE_INVALID', 'MERCHANT_ORDER_INVALID', 'MERCHANT_PAYMENT_MISMATCH'].includes(result.data.error.code), JSON.stringify(result.data.error));
    check(`direct HTTP ${mutation} substitution is rejected by verifier`, { code: result.data.error.code });
  }
  const forgedMerchant = generateIdentity('untrusted copied merchant'), forgedPayment = structuredClone(created.payment);
  forgedPayment.merchantOrder.snapshot.merchantDid = forgedMerchant.did;
  const forged = forgedPayment.merchantOrder;
  forged.snapshotHash = merchantOrderHash(forged.snapshot);
  forged.signature = signJws({ type: 'SignedMyStoreOrder', version: 1, iss: forgedMerchant.did, snapshotHash: forged.snapshotHash, snapshot: forged.snapshot }, forgedMerchant, MERCHANT_ORDER_TYP);
  await assert.rejects(raw.transmit(await raw.prepare({ phase: 'proposal', payment: forgedPayment })), e => e.code === 'MERCHANT_UNTRUSTED' && e.verificationTrace?.steps.some(s => s.id === 'merchant_order' && s.status === 'fail'));
  check('a cryptographically signed but untrusted merchant order is independently rejected by B');
  const missingMerchant = structuredClone(created.payment); delete missingMerchant.merchantOrder;
  await assert.rejects(raw.transmit(await raw.prepare({ phase: 'proposal', payment: missingMerchant })), e => e.code === 'MERCHANT_ORDER_INVALID' && e.verificationTrace?.steps.some(s => s.id === 'merchant_order' && s.status === 'fail'));
  check('omitting the complete merchant snapshot cannot bypass configured business verification');
  assert.equal((await environment.snapshot()).executionCount, paidLedger.executionCount);
  const identityAgain = await loadMerchantIdentity(merchantDirectory); assert.equal(identityAgain.did, trusted.did);
  const persistedMerchant = await merchant.state(orderId); assert.equal(persistedMerchant.status, 'confirmed'); assert.equal(persistedMerchant.receiptHash, transactionHash);
  check('durable merchant identity and confirmed complete order retain original receipt');
  state = await controller.changeCart({ productId: '02', quantity: 1, revision: state.revision });
  state = await controller.checkout({ revision: state.revision });
  const unknownOrderId = state.order.orderId, unknownSignatures = (await payments.inventory()).devices.find(d => d.id === 'default').signCount;
  const currentPath = resolve(directory, 'orders', 'current.json'), checkpoint = JSON.parse(await readFile(currentPath, 'utf8'));
  checkpoint.phase = 'paying'; await writeFile(currentPath, JSON.stringify(checkpoint));
  controller = await createStorefrontController({ ...controllerOptions, paymentSession: payments });
  state = await controller.queryPayment({ orderId: unknownOrderId, revision: state.revision });
  assert.equal(state.phase, 'unknown');
  await assert.rejects(controller.reset({ revision: state.revision }), e => e.code === 'STORE_PAYMENT_UNRESOLVED');
  await assert.rejects(controller.pay({ orderId: unknownOrderId, revision: state.revision }), e => e.code === 'STORE_PAYMENT_UNRESOLVED');
  assert.equal((await payments.inventory()).devices.find(d => d.id === 'default').signCount, unknownSignatures);
  assert.equal((await environment.snapshot()).executionCount, paidLedger.executionCount);
  check('an interrupted payment checkpoint with unknown chain result remains blocked; query never signs or pays');
  report.status = 'passed'; report.events = events.map(({ source, action, status, orderId, phase }) => ({ source, action, status, orderId, phase }));
} catch (error) { report.status = 'failed'; report.error = { code: error.code, message: error.message, stack: error.stack }; console.error(error.stack); process.exitCode = 1; }
finally {
  closing = true;
  await Promise.all(children.map(async child => { if (child.exitCode !== null || child.signalCode !== null) return; const done = new Promise(r => child.once('exit', r)); child.disconnect(); await done; }));
  await environment?.close(); report.finishedAt = new Date().toISOString();
  const output = new URL('../../evidence/merchant-integration.json', import.meta.url); await mkdir(new URL('.', output), { recursive: true }); await writeFile(output, JSON.stringify(report, null, 2));
}
