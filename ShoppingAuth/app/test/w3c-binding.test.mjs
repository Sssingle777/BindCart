import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateIdentity, verifyJws } from '../lib/identity.mjs';
import { digest, sendJson } from '../lib/protocol.mjs';
import { createW3cBbsIssuer, createW3cBbsVerifier, deriveCredential } from '../lib/w3c-bbs.mjs';
import { generateIssuerKey, generateDeviceKey, issueCredential, verifyCredential, preparePresentation, finalizePresentation, signDeviceRequest, verifyPresentation } from '../lib/dbac/crypto.mjs';
import { DBAC_EXTENSION, DBAC_MODES, DBAC_SCHEMA, paymentAttributes, paymentDisclosures } from '../lib/dbac/policy.mjs';
import { createDbacIssuer } from '../lib/dbac/services.mjs';
import { createDbacPaymentVerifier } from '../lib/dbac/payment-verifier.mjs';
import { DBAC_PAYMENT_CHALLENGE_TYP, DBAC_PAYMENT_RESPONSE_TYP, verifyDbacPaymentEvidence, issueDbacPaymentAuthorization, verifyDbacPaymentAuthorization, credentialBindingOf } from '../lib/dbac/payment-policy.mjs';
import { W3C_PAYMENT_PROFILE, W3C_PAYMENT_SCHEMA, W3C_DISCLOSED_INDICES, presentationHeader, bindingContext, w3cPresentationHash } from '../lib/dbac/w3c-profile.mjs';

const rejected = code => error => error?.code === code;
const payment = () => ({ orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 29900, currency: 'CNY' });
const rpc = terms => ({ jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: { message: { kind: 'message', role: 'user', messageId: randomUUID(), parts: [{ kind: 'data', data: { scope: 'payments:pay', phase: 'proposal', payment: terms } }] } } });

async function fixture(t, mode) {
  const b = generateIdentity('W3C payment verifier'), owner = generateIdentity('Owner');
  const issuer = generateIssuerKey(), w3cIssuer = await createW3cBbsIssuer(), issuerProfile = w3cIssuer.publicInfo();
  const w3cVerifier = createW3cBbsVerifier(issuerProfile);
  async function pair() {
    const device = generateDeviceKey(), bindingId = `urn:uuid:${randomUUID()}`, attributes = [...paymentAttributes(mode), bindingId];
    const [role, scope, epoch, claimMode, organization, holderLabel] = attributes;
    const credential = issueCredential({ issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes });
    const verifiableCredential = await w3cIssuer.issue({ credentialSubject: { role, scope, epoch, mode: claimMode, bindingId, organization, holderLabel } });
    return { device, credential, verifiableCredential, bindingId };
  }
  const first = await pair(), second = await pair();
  const verifier = createDbacPaymentVerifier({ identity: b, issuerPublicKey: issuer.publicKey, trustedAuthorizers: [owner.did], w3cIssuer: issuerProfile, getBackend: () => null });
  let baseUrl;
  const server = http.createServer({ maxHeaderSize: 24 * 1024 }, async (req, res) => {
    try { if (!await verifier.handle(req, res, baseUrl)) sendJson(res, 404, {}); }
    catch (error) { sendJson(res, error.status ?? 400, { error: { code: error.code, message: error.message }, verificationTrace: error.verificationTrace }); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  async function post(path, body, headers = {}) {
    const response = await fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });
    const rawResponse = await response.text(), result = JSON.parse(rawResponse);
    if (!response.ok) throw Object.assign(new Error(result.error.message), result.error, { verificationTrace: result.verificationTrace });
    return { result, response, rawResponse };
  }
  async function challenge(rawRequest, terms) {
    const { result } = await post('/dbac/payment/challenge', { mode, bodyHash: digest(rawRequest), paymentOrderId: terms.orderId });
    return verifyJws(result.challenge, { typ: DBAC_PAYMENT_CHALLENGE_TYP, expectedDid: b.did }).payload.context;
  }
  async function prepare({ dbacPair = first, vcPair = dbacPair, terms = payment(), rawRequest = JSON.stringify(rpc(terms)), context, credential } = {}) {
    context ??= await challenge(rawRequest, terms);
    const vc = await deriveCredential({ credential: credential ?? vcPair.verifiableCredential, issuerProfile, presentationHeader: presentationHeader(context) });
    const boundContext = bindingContext(context, vc);
    const initial = preparePresentation({ credential: dbacPair.credential, context: boundContext, mode, disclosedIndices: W3C_DISCLOSED_INDICES });
    const presentation = finalizePresentation({ state: initial.state, response: signDeviceRequest({ deviceSecretKey: dbacPair.device.secretKey, request: initial.request }) });
    return { rawRequest, terms, context, presentation: { ...presentation, verifiableCredential: vc } };
  }
  async function transmit(prepared) {
    const received = await post('/dbac/payment/a2a', prepared.rawRequest, { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Challenge': prepared.context.challengeId, 'X-A2A-DBAC-Proof': Buffer.from(JSON.stringify(prepared.presentation)).toString('base64url') });
    const evidence = { proof: received.response.headers.get('x-a2a-dbac-payment-response'), rawRequest: prepared.rawRequest, rawResponse: received.rawResponse, context: prepared.context };
    return { ...received, evidence, signed: verifyJws(evidence.proof, { typ: DBAC_PAYMENT_RESPONSE_TYP, expectedDid: b.did }).payload };
  }
  return { issuer, issuerProfile, w3cIssuer, w3cVerifier, first, second, b, owner, prepare, transmit, challenge, post, verifier };
}

test('W3C profile hashes are domain separated, canonical and bind the exact derived proof', () => {
  const a = { nonce: 'one', request: { b: 2, a: 1 } }, b = { request: { a: 1, b: 2 }, nonce: 'one' };
  assert.deepEqual(presentationHeader(a), presentationHeader(b));
  assert.notDeepEqual(presentationHeader(a), presentationHeader({ ...a, nonce: 'two' }));
  assert.equal(w3cPresentationHash(a), w3cPresentationHash(b));
  assert.notEqual(Buffer.from(presentationHeader(a)).toString('base64url'), w3cPresentationHash(a));
  assert.equal(bindingContext(a, b).w3cPresentationHash, w3cPresentationHash(b));
  assert.equal(Object.hasOwn(a, 'w3cPresentationHash'), false);
  assert.throws(() => presentationHeader({ bad: undefined }), rejected('W3C_BINDING_INVALID'));
  assert.deepEqual(DBAC_SCHEMA, ['role', 'scope', 'epoch', 'mode', 'organization', 'holderLabel']);
});

for (const mode of DBAC_MODES) {
  test(`${mode}: standard BBS VC and its eSIM binding proof jointly gate payment qualification`, { timeout: 60000 }, async t => {
    const f = await fixture(t, mode), prepared = await f.prepare();
    assert.equal(prepared.context.credentialProfile, W3C_PAYMENT_PROFILE);
    assert.deepEqual(prepared.context.schema, W3C_PAYMENT_SCHEMA);
    assert.deepEqual(Object.keys(prepared.presentation.verifiableCredential.credentialSubject).sort(), ['bindingId', 'epoch', 'mode', 'role', 'scope']);
    assert.doesNotMatch(JSON.stringify(prepared.presentation), /Alice \/ Agent A|Competition team/);
    assert.ok(!JSON.stringify(prepared.presentation).includes(f.first.device.publicKey));
    const received = await f.transmit(prepared), gate = received.signed.paymentGate;
    assert.equal(gate.credentialProfile, W3C_PAYMENT_PROFILE);
    assert.equal(gate.w3cIssuer, f.issuerProfile.issuer);
    assert.equal(gate.vcBindingId, f.first.bindingId);
    assert.equal(gate.w3cPresentationHash, w3cPresentationHash(prepared.presentation.verifiableCredential));
    for (const id of ['w3c_bbs', 'vc_device_binding', 'knowledge', 'credential_pairing', 'device_pairing', 'consume']) assert.equal(received.signed.verificationTrace.steps.find(step => step.id === id).status, 'pass');
    verifyDbacPaymentEvidence(received.evidence, { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'proposal', payment: prepared.terms, w3cIssuer: f.issuerProfile.issuer });
    await assert.rejects(f.transmit(prepared), rejected('DBAC_REPLAY'));
  });

  test(`${mode}: two independently valid credentials cannot be mixed in either direction`, { timeout: 60000 }, async t => {
    const f = await fixture(t, mode);
    for (const [dbacPair, vcPair] of [[f.first, f.second], [f.second, f.first]]) {
      const prepared = await f.prepare({ dbacPair, vcPair }), { verifiableCredential, ...dbacProof } = prepared.presentation;
      assert.equal(await f.w3cVerifier.verifyDerived({ credential: verifiableCredential, presentationHeader: presentationHeader(prepared.context) }), true);
      assert.equal(verifyPresentation({ presentation: dbacProof, issuerPublicKey: f.issuer.publicKey, context: bindingContext(prepared.context, verifiableCredential), requiredDisclosures: { ...paymentDisclosures(mode), 6: dbacPair.bindingId } }).valid, true);
      await assert.rejects(f.transmit(prepared), error => error.code === 'W3C_DEVICE_BINDING_MISMATCH' && error.verificationTrace.steps.find(step => step.id === 'vc_device_binding').status === 'fail');
    }
  });

  test(`${mode}: missing VC, changed claims, swapped proof and challenge transplantation are rejected`, { timeout: 60000 }, async t => {
    const f = await fixture(t, mode), prepared = await f.prepare();
    const missing = structuredClone(prepared); delete missing.presentation.verifiableCredential;
    await assert.rejects(f.transmit(missing), rejected('W3C_BBS_CREDENTIAL_INVALID'));
    const vcOnly = { ...prepared, presentation: { verifiableCredential: prepared.presentation.verifiableCredential } };
    await assert.rejects(f.transmit(vcOnly), error => error.code === 'W3C_DEVICE_PROOF_REQUIRED' &&
      error.verificationTrace.steps.find(step => step.id === 'w3c_bbs').status === 'pass' &&
      error.verificationTrace.steps.find(step => step.id === 'vc_device_binding').status === 'fail');
    const tampered = structuredClone(prepared); tampered.presentation.verifiableCredential.credentialSubject.scope = 'payments:admin';
    await assert.rejects(f.transmit(tampered), rejected('W3C_BBS_INVALID_PROOF'));
    const replacement = await deriveCredential({ credential: f.first.verifiableCredential, issuerProfile: f.issuerProfile, presentationHeader: presentationHeader(prepared.context) });
    assert.notEqual(replacement.proof.proofValue, prepared.presentation.verifiableCredential.proof.proofValue);
    await assert.rejects(f.transmit({ ...prepared, presentation: { ...prepared.presentation, verifiableCredential: replacement } }), rejected('DBAC_PROOF_INVALID'));
    const newContext = await f.challenge(prepared.rawRequest, prepared.terms);
    await assert.rejects(f.transmit({ ...prepared, context: newContext }), rejected('W3C_BBS_INVALID_PROOF'));
    const wrongBody = structuredClone(prepared), body = JSON.parse(wrongBody.rawRequest); body.params.message.parts[0].data.payment.amountMinor++;
    wrongBody.rawRequest = JSON.stringify(body);
    await assert.rejects(f.transmit(wrongBody), rejected('DBAC_BODY_MISMATCH'));
    // Invalid attempts leave the correct one usable; no downgrade to DBAC-only.
    await f.transmit(prepared);
  });

  test(`${mode}: async W3C verification consumes a concurrent challenge exactly once`, { timeout: 60000 }, async t => {
    const f = await fixture(t, mode), prepared = await f.prepare();
    const results = await Promise.allSettled([f.transmit(prepared), f.transmit(prepared)]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    assert.equal(results.filter(result => result.status === 'rejected' && result.reason.code === 'DBAC_REPLAY').length, 1);
  });
}

test('the BBS verifier pins the configured key even when an impostor copies the issuer identifier', { timeout: 60000 }, async t => {
  const f = await fixture(t, 'bbs-bls'), prepared = await f.prepare();
  for (const id of [f.issuerProfile.issuer, 'did:example:untrusted-payment-issuer']) {
    const impostor = await createW3cBbsIssuer({ id });
    const credential = await impostor.issue({ credentialSubject: f.first.verifiableCredential.credentialSubject });
    const derived = await deriveCredential({ credential, issuerProfile: impostor.publicInfo(), presentationHeader: presentationHeader(prepared.context) });
    const forged = { ...prepared, presentation: { ...prepared.presentation, verifiableCredential: derived } };
    await assert.rejects(f.transmit(forged), rejected(id === f.issuerProfile.issuer ? 'W3C_BBS_INVALID_PROOF' : 'W3C_BBS_UNTRUSTED_ISSUER'));
  }
  await f.transmit(prepared);
});

test('Owner approval and signed verification evidence cannot drop or replace the W3C credential binding', { timeout: 60000 }, async t => {
  const f = await fixture(t, 'bbs-bls'), prepared = await f.prepare(), result = await f.transmit(prepared);
  const gate = result.signed.paymentGate, credentialBinding = credentialBindingOf(gate);
  const issueOptions = { verifierDid: f.b.did, mode: 'bbs-bls', issuerPublicKey: f.issuer.publicKey, orderKey: gate.orderKey, payment: prepared.terms };
  const authorization = issueDbacPaymentAuthorization(f.owner, { ...issueOptions, credentialBinding });
  const verifyOptions = { trustedAuthorizers: [f.owner.did], ...issueOptions, credentialBinding, w3cIssuer: f.issuerProfile.issuer };
  assert.equal(verifyDbacPaymentAuthorization(authorization, verifyOptions).vcBindingId, f.first.bindingId);
  assert.throws(() => verifyDbacPaymentAuthorization(authorization, { ...verifyOptions, credentialBinding: { ...credentialBinding, vcBindingId: f.second.bindingId } }), rejected('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
  const legacyApproval = issueDbacPaymentAuthorization(f.owner, issueOptions);
  assert.throws(() => verifyDbacPaymentAuthorization(legacyApproval, verifyOptions), rejected('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
  assert.throws(() => verifyDbacPaymentEvidence(result.evidence, { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'proposal', payment: prepared.terms, w3cIssuer: 'did:example:other-issuer' }), rejected('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
});

test('the issuer jointly signs a device-bound W3C payment VC while ordinary echo stays at six attributes', { timeout: 60000 }, async t => {
  const accessToken = randomBytes(32).toString('base64url');
  const devices = Object.fromEntries(DBAC_MODES.map(mode => [mode, generateDeviceKey()]));
  const issuer = createDbacIssuer({ accessToken, devicePublicKeys: Object.fromEntries(DBAC_MODES.map(mode => [mode, devices[mode].publicKey])), w3c: true });
  const url = await issuer.listen(); t.after(() => issuer.close());
  const publicInfo = issuer.publicInfo(), verifier = createW3cBbsVerifier(publicInfo.w3c);
  assert.doesNotMatch(JSON.stringify(publicInfo), /secretKey|privateKey/);
  async function call(path, body) {
    const response = await fetch(`${url}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-DBAC-Access': accessToken }, body: JSON.stringify(body) });
    const value = await response.json();
    if (!response.ok) throw Object.assign(new Error(value.error.message), value.error);
    return value;
  }
  for (const mode of DBAC_MODES) {
    const enrollment = await call('/enroll/challenge', { mode, scope: 'payments:pay' });
    assert.match(enrollment.bindingId, /^urn:uuid:/);
    assert.equal(enrollment.request.context.attributeHash, digest(JSON.stringify([...paymentAttributes(mode), enrollment.bindingId])));
    const response = signDeviceRequest({ deviceSecretKey: devices[mode].secretKey, request: enrollment.request });
    const issued = await call('/issue', { registrationId: enrollment.registrationId, response });
    assert.equal(verifyCredential(issued.credential, { issuerPublicKey: publicInfo.publicKey }), true);
    assert.equal(await verifier.verifyBase({ credential: issued.verifiableCredential }), true);
    assert.equal(issued.credential.attributes[6], issued.verifiableCredential.credentialSubject.bindingId);
    assert.equal(issued.credential.devicePublicKey, devices[mode].publicKey);
    assert.equal(issued.verifiableCredential.proof.cryptosuite, 'bbs-2023');
    await assert.rejects(call('/issue', { registrationId: enrollment.registrationId, response }), rejected('DBAC_REGISTRATION_EXPIRED'));
    const echoEnrollment = await call('/enroll/challenge', { mode });
    assert.equal(echoEnrollment.bindingId, undefined);
    const echoResponse = signDeviceRequest({ deviceSecretKey: devices[mode].secretKey, request: echoEnrollment.request });
    const echo = await call('/issue', { registrationId: echoEnrollment.registrationId, response: echoResponse });
    assert.equal(echo.credential.attributes.length, 6);
    assert.equal(echo.verifiableCredential, undefined);
  }
});
