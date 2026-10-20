import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateIdentity, signJws, verifyJws } from '../lib/identity.mjs';
import { digest, sendJson } from '../lib/protocol.mjs';
import { generateIssuerKey, generateDeviceKey, issueCredential, createPaymentBinding, preparePresentation, finalizePresentation, signDeviceRequest, verifyPresentation } from '../lib/dbac/crypto.mjs';
import { DBAC_EXTENSION, DBAC_MODES, paymentAttributes, paymentDisclosures, demoAttributes } from '../lib/dbac/policy.mjs';
import { createDbacPaymentVerifier } from '../lib/dbac/payment-verifier.mjs';
import { createDbacIssuer, createDbacDevice } from '../lib/dbac/services.mjs';
import { DBAC_PAYMENT_CHALLENGE_TYP, DBAC_PAYMENT_RESPONSE_TYP, issueDbacPaymentAuthorization, verifyDbacPaymentAuthorization, verifyDbacPaymentEvidence } from '../lib/dbac/payment-policy.mjs';

const order = () => ({ orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 29900, currency: 'CNY' });
const now = () => Math.floor(Date.now() / 1000);
const rpc = data => ({ jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: { message: { kind: 'message', role: 'user', messageId: randomUUID(), parts: [{ kind: 'data', data: { scope: 'payments:pay', ...data } }] } } });
const failure = code => error => error.code === code;

async function fixture(t, mode) {
  const issuer = generateIssuerKey(), device = generateDeviceKey(), owner = generateIdentity('Owner'), b = generateIdentity('B');
  const credential = issueCredential({ issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes: paymentAttributes(mode) });
  const payments = new Map();
  let executions = 0, lastSettlementEvidence;
  const backend = {
    requirements: payment => ({ x402Version: 2, accepts: [{ amount: String(payment.amountMinor), network: 'test-fixture', asset: 'fixture', payTo: payment.payeeAccount }] }),
    async execute(input) {
      lastSettlementEvidence = input.responseEvidence;
      const verified = verifyDbacPaymentEvidence(input.responseEvidence, { verifierDid: b.did, issuerPublicKey: issuer.publicKey, phase: 'settle', payment: input.payment, authorization: input.authorization, payload: input.payload });
      verifyDbacPaymentAuthorization(input.authorization, { trustedAuthorizers: [owner.did], verifierDid: b.did, issuerPublicKey: issuer.publicKey, payment: input.payment, mode: verified.gate.mode, orderKey: verified.gate.orderKey });
      let saved = payments.get(input.payment.orderId);
      if (saved) return { outcome: 'ALREADY_PROCESSED', receipt: saved };
      saved = { ...input.payment, receiptId: randomUUID(), transactionHash: `0x${'a'.repeat(64)}` }; payments.set(input.payment.orderId, saved); executions++;
      return { outcome: 'EXECUTED', receipt: saved };
    },
  };
  const verifier = createDbacPaymentVerifier({ identity: b, issuerPublicKey: issuer.publicKey, trustedAuthorizers: [owner.did], getBackend: () => backend });
  let baseUrl;
  const server = http.createServer({ maxHeaderSize: 24 * 1024 }, async (req, res) => {
    try { if (!await verifier.handle(req, res, baseUrl)) sendJson(res, 404, {}); }
    catch (error) { sendJson(res, error.status ?? 400, { error: { code: error.code, message: error.message }, verificationTrace: error.verificationTrace }); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  async function post(path, body, headers = {}) {
    const response = await fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });
    const rawResponse = await response.text(), result = JSON.parse(rawResponse);
    if (!response.ok) throw Object.assign(new Error(result.error.message), result.error, { verificationTrace: result.verificationTrace });
    return { result, rawResponse, response };
  }
  async function prepare(request, binding, suppliedCredential = credential) {
    const rawRequest = JSON.stringify(request), payment = request.params.message.parts[0].data.payment;
    const { result } = await post('/dbac/payment/challenge', { mode, bodyHash: digest(rawRequest), paymentOrderId: payment.orderId });
    const context = verifyJws(result.challenge, { typ: DBAC_PAYMENT_CHALLENGE_TYP, expectedDid: b.did }).payload.context;
    const initial = preparePresentation({ credential: suppliedCredential, context, disclosedIndices: [0, 1, 2, 3], mode, ...(binding ? { paymentBinding: binding } : {}) });
    const response = signDeviceRequest({ deviceSecretKey: device.secretKey, request: initial.request });
    const presentation = finalizePresentation({ state: initial.state, response });
    return { rawRequest, context, presentation };
  }
  async function transmit(prepared) {
    const received = await post('/dbac/payment/a2a', prepared.rawRequest, { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Challenge': prepared.context.challengeId, 'X-A2A-DBAC-Proof': Buffer.from(JSON.stringify(prepared.presentation)).toString('base64url') });
    return { task: received.result.result, evidence: { proof: received.response.headers.get('x-a2a-dbac-payment-response'), rawRequest: prepared.rawRequest, rawResponse: received.rawResponse, context: prepared.context } };
  }
  const invoke = async (request, binding, suppliedCredential) => transmit(await prepare(request, binding, suppliedCredential));
  return { issuer, device, owner, b, credential, backend, prepare, transmit, invoke, post, executions: () => executions, lastSettlementEvidence: () => lastSettlementEvidence };
}

for (const mode of DBAC_MODES) {
  test(`${mode}: one-order binding keeps only the pseudonym stable and binds every fresh proof`, () => {
    const issuer = generateIssuerKey(), device = generateDeviceKey(), payment = order();
    const credential = issueCredential({ issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes: paymentAttributes(mode) });
    const paymentBinding = createPaymentBinding({ credential, mode, orderId: payment.orderId });
    assert.deepEqual(paymentBinding, {});
    const context = { purpose: 'dbac-payment-v1', scope: 'payments:pay', paymentOrderId: payment.orderId, bodyHash: digest('first') };
    const show = (ctx, binding = paymentBinding) => {
      const initial = preparePresentation({ credential, context: ctx, disclosedIndices: [0, 1, 2, 3], mode, paymentBinding: binding });
      return finalizePresentation({ state: initial.state, response: signDeviceRequest({ deviceSecretKey: device.secretKey, request: initial.request }) });
    };
    const first = show(context), nextContext = { ...context, bodyHash: digest('second') }, second = show(nextContext);
    assert.equal(first.randomizedDevicePublicKey, second.randomizedDevicePublicKey);
    assert.notEqual(first.deviceSignature, second.deviceSignature);
    assert.notEqual(first.Abar, second.Abar);
    assert.notDeepEqual(first.proof, second.proof);
    verifyPresentation({ presentation: first, issuerPublicKey: issuer.publicKey, context, requiredDisclosures: paymentDisclosures(mode) });
    verifyPresentation({ presentation: second, issuerPublicKey: issuer.publicKey, context: nextContext, requiredDisclosures: paymentDisclosures(mode) });
    assert.throws(() => verifyPresentation({ presentation: first, issuerPublicKey: issuer.publicKey, context: nextContext, requiredDisclosures: paymentDisclosures(mode) }), failure('DBAC_PROOF_INVALID'));
    assert.throws(() => show({ ...context, paymentOrderId: 'other-order' }), failure('DBAC_PAYMENT_BINDING_MISMATCH'));
    assert.throws(() => show({ ...context, bodyHash: undefined }), failure('DBAC_INVALID_INPUT'));
    assert.throws(() => show(context, {}), failure('DBAC_PAYMENT_BINDING_MISMATCH'));
    const otherPayment = order(), otherBinding = createPaymentBinding({ credential, mode, orderId: otherPayment.orderId });
    assert.notEqual(show({ ...context, paymentOrderId: otherPayment.orderId }, otherBinding).randomizedDevicePublicKey, first.randomizedDevicePublicKey);
    const anotherCredential = issueCredential({ issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes: paymentAttributes(mode) });
    assert.throws(() => preparePresentation({ credential: anotherCredential, context, mode, paymentBinding }), failure('DBAC_PAYMENT_BINDING_MISMATCH'));
  });

  test(`${mode}: DBAC proposal, explicit Owner grant, wallet gate and fresh settlement proof form one payment flow`, { timeout: 60000 }, async t => {
    const f = await fixture(t, mode), payment = order();
    const binding = createPaymentBinding({ credential: f.credential, mode, orderId: payment.orderId });
    const proposalRequest = rpc({ phase: 'proposal', payment });
    const preparedProposal = await f.prepare(proposalRequest, binding), proposal = await f.transmit(preparedProposal);
    const proposalVerified = verifyDbacPaymentEvidence(proposal.evidence, { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'proposal', payment });
    assert.equal(f.executions(), 0, 'qualification is not authorization to transfer');
    const orderKey = proposalVerified.gate.orderKey;
    assert.doesNotMatch(proposal.evidence.rawRequest + proposal.evidence.rawResponse, /holderDid|deviceDid|credentialHash|Alice \/ Agent A|Competition team/);
    assert.ok(!(proposal.evidence.rawRequest + proposal.evidence.rawResponse).includes(f.device.publicKey));
    const authorization = issueDbacPaymentAuthorization(f.owner, { verifierDid: f.b.did, mode, issuerPublicKey: f.issuer.publicKey, orderKey, payment });
    const document = verifyDbacPaymentAuthorization(authorization, { trustedAuthorizers: [f.owner.did], verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, payment, mode, orderKey });
    assert.equal(document.maxExecutions, 1);
    await assert.rejects(f.transmit(preparedProposal), failure('DBAC_REPLAY'));
    const forgedBody = { ...await f.prepare(proposalRequest, binding), rawRequest: JSON.stringify(rpc({ phase: 'proposal', payment: { ...payment, amountMinor: 1 } })) };
    await assert.rejects(f.transmit(forgedBody), failure('DBAC_BODY_MISMATCH'));
    await assert.rejects(f.invoke(rpc({ phase: 'authorize', payment }), binding), failure('PAYMENT_AUTHORIZATION_REQUIRED'));
    await assert.rejects(f.invoke(rpc({ phase: 'authorize', payment: { ...payment, amountMinor: 1 }, authorization }), binding), failure('PAYMENT_TERMS_MISMATCH'));
    const freshBinding = createPaymentBinding({ credential: f.credential, mode, orderId: payment.orderId });
    await assert.rejects(f.invoke(rpc({ phase: 'authorize', payment, authorization }), freshBinding), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
    const fakeAuthorization = issueDbacPaymentAuthorization(generateIdentity('Fake owner'), { verifierDid: f.b.did, mode, issuerPublicKey: f.issuer.publicKey, orderKey, payment });
    await assert.rejects(f.invoke(rpc({ phase: 'authorize', payment, authorization: fakeAuthorization }), binding), failure('PAYMENT_AUTHORIZER_UNTRUSTED'));
    const echoCredential = issueCredential({ issuerSecretKey: f.issuer.secretKey, devicePublicKey: f.device.publicKey, attributes: demoAttributes(mode) });
    await assert.rejects(f.invoke(rpc({ phase: 'proposal', payment }), undefined, echoCredential), failure('DBAC_POLICY_REJECTED'));
    const authorize = await f.invoke(rpc({ phase: 'authorize', payment, authorization }), binding);
    const paymentRequired = authorize.task.status.message.metadata['x402.payment.required'];
    const options = { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'authorize', payment, authorization, paymentRequired };
    verifyDbacPaymentEvidence(authorize.evidence, options);
    assert.throws(() => verifyDbacPaymentEvidence(proposal.evidence, options), failure('DBAC_PAYMENT_EVIDENCE_INVALID'));
    assert.throws(() => verifyDbacPaymentEvidence(authorize.evidence, { ...options, paymentRequired: { ...paymentRequired, accepts: [] } }), failure('DBAC_PAYMENT_EVIDENCE_MISMATCH'));
    assert.throws(() => verifyDbacPaymentEvidence({ ...authorize.evidence, rawResponse: authorize.evidence.rawResponse + ' ' }, options), failure('DBAC_PAYMENT_EVIDENCE_INVALID'));
    const payload = { x402Version: 2, accepted: paymentRequired.accepts[0], payload: { authorization: { nonce: randomUUID() }, signature: 'fixture' } };
    const settlement = rpc({ phase: 'settle', payment, authorization, payload });
    settlement.params.message.taskId = authorize.task.id;
    settlement.params.message.contextId = authorize.task.contextId;
    const wrongTask = structuredClone(settlement); wrongTask.params.message.taskId = randomUUID();
    await assert.rejects(f.invoke(wrongTask, binding), failure('DBAC_PAYMENT_TASK_MISMATCH'));
    assert.equal(f.executions(), 0);
    const preparedSettlement = await f.prepare(settlement, binding), settled = await f.transmit(preparedSettlement);
    verifyDbacPaymentEvidence(settled.evidence, { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'settle', payment, authorization, payload });
    verifyDbacPaymentEvidence(f.lastSettlementEvidence(), { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'settle', payment, authorization, payload });
    assert.equal(settled.task.artifacts[0].parts[0].data.paymentResult.outcome, 'EXECUTED');
    assert.equal(f.executions(), 1);
    await assert.rejects(f.transmit(preparedSettlement), failure('DBAC_REPLAY'));
    const retry = await f.invoke(settlement, binding);
    assert.equal(retry.task.artifacts[0].parts[0].data.paymentResult.outcome, 'ALREADY_PROCESSED');
    assert.equal(f.executions(), 1);
    const trace = verifyJws(settled.evidence.proof, { typ: DBAC_PAYMENT_RESPONSE_TYP, expectedDid: f.b.did }).payload.verificationTrace;
    for (const id of ['knowledge', 'credential_pairing', 'device_pairing', 'owner_authorization', 'task_binding', 'consume', 'settlement_gate', 'execution']) assert.equal(trace.steps.find(step => step.id === id).status, 'pass');
  });
}

test('proposal evidence can outlive its consumed challenge, but not its 300-second signed limit', async t => {
  const f = await fixture(t, 'bbs-bls'), payment = order(), mode = 'bbs-bls';
  const binding = createPaymentBinding({ credential: f.credential, mode, orderId: payment.orderId });
  const proposal = await f.invoke(rpc({ phase: 'proposal', payment }), binding);
  const payload = verifyJws(proposal.evidence.proof, { typ: DBAC_PAYMENT_RESPONSE_TYP, expectedDid: f.b.did }).payload;
  const referenceTime = now();
  const oldContext = { ...proposal.evidence.context, iat: referenceTime - 100, exp: referenceTime - 40 };
  const signed = { ...payload, contextHash: digest(JSON.stringify(oldContext)), iat: referenceTime - 80, exp: referenceTime + 220 };
  const evidence = { ...proposal.evidence, context: oldContext, proof: signJws(signed, f.b, DBAC_PAYMENT_RESPONSE_TYP) };
  verifyDbacPaymentEvidence(evidence, { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'proposal', payment });
  assert.throws(() => verifyDbacPaymentEvidence({ ...evidence, proof: signJws({ ...signed, exp: referenceTime + 221 }, f.b, DBAC_PAYMENT_RESPONSE_TYP) }, { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'proposal', payment }), failure('DBAC_PAYMENT_EVIDENCE_INVALID'));
  assert.throws(() => verifyDbacPaymentEvidence({ ...evidence, proof: signJws({ ...signed, exp: referenceTime - 1 }, f.b, DBAC_PAYMENT_RESPONSE_TYP) }, { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'proposal', payment }), failure('DBAC_PAYMENT_EVIDENCE_INVALID'));
});

test('issuer separately enrolls payment credentials with device possession while preserving default echo scope', async t => {
  const accessToken = randomBytes(32).toString('base64url');
  const device = createDbacDevice({ accessToken }), deviceUrl = await device.listen();
  const issuer = createDbacIssuer({ accessToken, devicePublicKeys: device.publicInfo().publicKeys }), issuerUrl = await issuer.listen();
  t.after(async () => { await issuer.close(); await device.close(); });
  async function call(url, body) {
    const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-DBAC-Access': accessToken }, body: JSON.stringify(body) });
    const result = await response.json();
    if (!response.ok) throw Object.assign(new Error(result.error.message), result.error);
    return result;
  }
  for (const mode of DBAC_MODES) {
    for (const scope of [undefined, 'payments:pay']) {
      const enrollment = await call(`${issuerUrl}/enroll/challenge`, { mode, ...(scope ? { scope } : {}) });
      await assert.rejects(call(`${issuerUrl}/issue`, { registrationId: enrollment.registrationId, response: {} }));
      const signed = await call(`${deviceUrl}/enroll/sign`, { mode, request: enrollment.request });
      const { credential } = await call(`${issuerUrl}/issue`, { registrationId: enrollment.registrationId, response: signed });
      assert.equal(credential.attributes[1], scope ?? 'demo:echo');
      assert.equal(credential.attributes[3], mode);
      await assert.rejects(call(`${issuerUrl}/issue`, { registrationId: enrollment.registrationId, response: signed }), failure('DBAC_REGISTRATION_EXPIRED'));
    }
  }
  await assert.rejects(call(`${issuerUrl}/enroll/challenge`, { mode: 'bbs-bls', scope: 'payments:admin' }), failure('DBAC_ISSUANCE_POLICY'));
});
