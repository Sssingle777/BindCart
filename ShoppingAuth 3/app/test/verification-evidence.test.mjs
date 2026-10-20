import assert from 'node:assert/strict';
import test from 'node:test';
import {randomUUID} from 'node:crypto';
import {Readable} from 'node:stream';
import {generateIdentity, verifyJws} from '../lib/identity.mjs';
import {digest} from '../lib/protocol.mjs';
import {createVerificationTrace} from '../lib/verification-trace.mjs';
import {createW3cBbsIssuer, deriveCredential} from '../lib/w3c-bbs.mjs';
import {
  generateIssuerKey, generateDeviceKey, issueCredential, createPaymentBinding,
  preparePresentation, finalizePresentation, signDeviceRequest, verifyPresentation,
} from '../lib/dbac/crypto.mjs';
import {DBAC_EXTENSION, paymentAttributes} from '../lib/dbac/policy.mjs';
import {createDbacPaymentVerifier} from '../lib/dbac/payment-verifier.mjs';
import {DBAC_PAYMENT_CHALLENGE_TYP, DBAC_PAYMENT_RESPONSE_TYP, issueDbacPaymentAuthorization, credentialBindingOf} from '../lib/dbac/payment-policy.mjs';
import {W3C_DISCLOSED_INDICES, presentationHeader, bindingContext, w3cPresentationHash} from '../lib/dbac/w3c-profile.mjs';

const step = (trace, id) => trace.steps.find(value => value.id === id);
const row = (trace, id, label) => step(trace, id).evidence?.find(value => value.label === label);
const copy = value => structuredClone(value);

async function fixture(mode = 'bbs-bls') {
  const identity = generateIdentity('Evidence verifier'), owner = generateIdentity('Evidence Owner');
  const issuer = generateIssuerKey(), device = generateDeviceKey(), standardIssuer = await createW3cBbsIssuer();
  const issuerProfile = standardIssuer.publicInfo();
  const bindingId = `urn:uuid:${randomUUID()}`;
  const attributes = [...paymentAttributes(mode), bindingId];
  attributes[4] = `hidden-organization-${randomUUID()}`; attributes[5] = `hidden-holder-${randomUUID()}`;
  const [role, scope, epoch, claimMode, organization, holderLabel] = attributes;
  const originalCredential = await standardIssuer.issue({credentialSubject: {role, scope, epoch, mode: claimMode, organization, holderLabel, bindingId}});
  const credential = issueCredential({issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes});
  const payment = {orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 299, currency: 'CNY'};
  const paymentBinding = createPaymentBinding({credential, mode, orderId: payment.orderId});
  // Only the business backend is a fixture. All signatures, standard VC
  // verification, device proofs, Owner grants, and trace production run live.
  const backend = {
    requirements: () => ({x402Version: 2, accepts: [{amount: '299', network: 'test-fixture', asset: 'fixture', payTo: payment.payeeAccount}]}),
    execute: async input => ({outcome: 'EXECUTED', receipt: {...input.payment, transactionHash: `0x${'7'.repeat(64)}`}}),
  };
  const verifier = createDbacPaymentVerifier({identity, issuerPublicKey: issuer.publicKey, trustedAuthorizers: [owner.did], getBackend: () => backend, w3cIssuer: issuerProfile});
  const baseUrl = 'http://127.0.0.1:12345';
  async function call(path, raw, headers = {}) {
    const req = Readable.from([Buffer.from(typeof raw === 'string' ? raw : JSON.stringify(raw))]);
    Object.assign(req, {method: 'POST', url: path, headers});
    const captured = {};
    const res = {writeHead(status, headers) {Object.assign(captured, {status, headers});}, end(body) {captured.body = JSON.parse(body);}};
    assert.equal(await verifier.handle(req, res, baseUrl), true);
    return captured;
  }
  async function prepare({phase = 'proposal', authorization, payload, continuation} = {}) {
    const request = {jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: {message: {
      kind: 'message', role: 'user', messageId: randomUUID(),
      ...(continuation ? {taskId: continuation.id, contextId: continuation.contextId} : {}),
      parts: [{kind: 'data', data: {scope: 'payments:pay', phase, payment,
        ...(authorization ? {authorization} : {}), ...(payload ? {payload} : {}),
      }}],
    }}};
    const rawRequest = JSON.stringify(request);
    const challenge = await call('/dbac/payment/challenge', {mode, bodyHash: digest(rawRequest), paymentOrderId: payment.orderId});
    const context = verifyJws(challenge.body.challenge, {typ: DBAC_PAYMENT_CHALLENGE_TYP, expectedDid: identity.did}).payload.context;
    const verifiableCredential = await deriveCredential({credential: originalCredential, issuerProfile, presentationHeader: presentationHeader(context)});
    const prepared = preparePresentation({credential, mode, paymentBinding, context: bindingContext(context, verifiableCredential), disclosedIndices: W3C_DISCLOSED_INDICES});
    const presentation = finalizePresentation({state: prepared.state, response: signDeviceRequest({deviceSecretKey: device.secretKey, request: prepared.request})});
    return {rawRequest, context, presentation: {...presentation, verifiableCredential}};
  }
  async function transmit(prepared) {
    const result = await call('/dbac/payment/a2a', prepared.rawRequest, {
      'x-a2a-extensions': DBAC_EXTENSION, 'x-a2a-dbac-challenge': prepared.context.challengeId,
      'x-a2a-dbac-proof': Buffer.from(JSON.stringify(prepared.presentation)).toString('base64url'),
    });
    const token = result.headers['X-A2A-DBAC-Payment-Response'];
    const signed = verifyJws(token, {typ: DBAC_PAYMENT_RESPONSE_TYP, expectedDid: identity.did}).payload;
    return {...result, token, signed, trace: signed.verificationTrace};
  }
  return {prepare, transmit, owner, issuer, identity, credential, originalCredential, device, payment, bindingId, mode,
    secrets: [issuer.secretKey, device.secretKey, device.publicKey, attributes[4], attributes[5], originalCredential.proof.proofValue, credential.signature.A, credential.signature.e],
  };
}

function noSecrets(trace, forbidden) {
  const encoded = JSON.stringify(trace);
  for (const secret of forbidden) assert.equal(encoded.includes(secret), false, 'trace excludes original credential, keys, hidden attributes and private state');
  assert.doesNotMatch(encoded, /"(?:secretKey|privateKey|accessToken|originalCredential|responses|inverseR1|keyRandomizer|blind)"\s*:/);
  for (const item of trace.steps.filter(value => value.status === 'skipped')) assert.equal(item.evidence, undefined, 'an unexecuted check has no invented evidence');
}

test('evidence is attached only to an executing check, stays bounded, and survives a failure snapshot', () => {
  const trace = createVerificationTrace('dbac-payment');
  assert.throws(() => trace.record('request_binding', {label: 'digest', observed: 'before execution'}), /active verification stage/);
  trace.start('request_binding');
  assert.throws(() => trace.record('request_binding', {label: 'whole document', observed: {secretKey: 'never serialize'}}), /public scalar/);
  const observed = ['expected hash', 'actual hash'];
  trace.record('request_binding', {label: 'digest comparison', expected: observed[0], observed: observed[1], match: false});
  trace.fail(Object.assign(new Error('Mismatch'), {code: 'DBAC_BODY_MISMATCH'}));
  const first = trace.snapshot();
  assert.equal(row(first, 'request_binding', 'digest comparison').match, false);
  first.steps[0].evidence[0].observed = 'mutated';
  assert.equal(row(trace.snapshot(), 'request_binding', 'digest comparison').observed, 'actual hash');
  assert.equal(step(trace.snapshot(), 'knowledge').evidence, undefined);
  assert.throws(() => trace.record('request_binding', {label: 'late', observed: 'after stop'}), /active verification stage/);
});

for (const mode of ['bbs-bls', 'bbs-blind-bls']) {
  test(`${mode}: signed public evidence exposes actual checks without original credentials or secret state`, async t => {
    const f = await fixture(mode), prepared = await f.prepare();
    const result = await f.transmit(prepared), trace = result.trace;
    assert.equal(row(trace, 'request_binding', 'raw body SHA-256').observed, digest(prepared.rawRequest));
    assert.equal(row(trace, 'request_binding', 'raw body SHA-256').match, true);
    assert.equal(row(trace, 'w3c_bbs', 'expected presentationHeader (hex)').observed, Buffer.from(presentationHeader(prepared.context)).toString('hex'));
    assert.equal(row(trace, 'vc_device_binding', 'hVC: derived credential hash').observed, w3cPresentationHash(prepared.presentation.verifiableCredential));
    assert.deepEqual(row(trace, 'vc_device_binding', 'bindingId / mode / device contribution').observed, [f.bindingId, mode, true]);
    assert.equal(row(trace, 'knowledge', 'Fiat-Shamir challenge').observed, prepared.presentation.proof.challenge);
    assert.equal(row(trace, 'knowledge', 'Fiat-Shamir challenge').match, true);
    assert.equal(row(trace, 'credential_pairing', 'e(Abar,W) = e(Bbar,G2)').observed, true);
    assert.equal(row(trace, 'device_pairing', 'e(H0,pi_se) = e(randomizedKey,Q)').observed, true);
    assert.match(row(trace, 'device_pairing', 'hash-to-curve point Q (G2)').observed, /^[0-9a-f]{192}$/);
    assert.equal(row(trace, 'consume', 'before consume: used / now / expires').observed[0], false);
    assert.equal(row(trace, 'consume', 'after synchronous consume: used').observed, true);
    noSecrets(trace, [...f.secrets, prepared.presentation.verifiableCredential.proof.proofValue]);
    assert.ok(Buffer.byteLength(result.token) < 14336, `proposal trace response header remains bounded (${Buffer.byteLength(result.token)} bytes)`);
    t.diagnostic(`${mode} signed response header: ${Buffer.byteLength(result.token)} bytes`);
    await assert.rejects(f.transmit(prepared), error => {
      assert.equal(error.code, 'DBAC_REPLAY');
      assert.equal(row(error.verificationTrace, 'replay', 'challenge already used').observed, true);
      assert.equal(step(error.verificationTrace, 'w3c_bbs').evidence, undefined);
      noSecrets(error.verificationTrace, f.secrets); return true;
    });
  });
}

test('body mismatch and missing eSIM preserve the actual failed comparison, not subsequent checks', async () => {
  const f = await fixture(), prepared = await f.prepare();
  const changed = copy(prepared), body = JSON.parse(changed.rawRequest); body.params.message.parts[0].data.payment.amountMinor++;
  changed.rawRequest = JSON.stringify(body);
  await assert.rejects(f.transmit(changed), error => {
    const evidence = row(error.verificationTrace, 'request_binding', 'raw body SHA-256');
    assert.equal(error.code, 'DBAC_BODY_MISMATCH');
    assert.equal(evidence.expected, digest(prepared.rawRequest)); assert.equal(evidence.observed, digest(changed.rawRequest));
    assert.equal(evidence.match, false); assert.equal(step(error.verificationTrace, 'knowledge').evidence, undefined); return true;
  });
  const vcOnly = {...prepared, presentation: {verifiableCredential: prepared.presentation.verifiableCredential}};
  await assert.rejects(f.transmit(vcOnly), error => {
    assert.equal(error.code, 'W3C_DEVICE_PROOF_REQUIRED');
    assert.equal(step(error.verificationTrace, 'w3c_bbs').status, 'pass');
    assert.deepEqual(row(error.verificationTrace, 'vc_device_binding', 'bindingId / mode / device contribution').observed, [null, null, false]);
    noSecrets(error.verificationTrace, f.secrets); return true;
  });
  await f.transmit(prepared);
});

test('failed knowledge comparison reveals only its public reconstructed challenge', async () => {
  const f = await fixture(), prepared = await f.prepare();
  const {verifiableCredential, ...presentation} = copy(prepared.presentation);
  const scalar = presentation.proof.responses.inverseR1;
  presentation.proof.responses.inverseR1 = scalar.slice(0, -1) + (scalar.at(-1) === '0' ? '1' : '0');
  const trace = createVerificationTrace('dbac-payment');
  assert.throws(() => {
    try {verifyPresentation({presentation, issuerPublicKey: f.issuer.publicKey, context: bindingContext(prepared.context, verifiableCredential), trace});}
    catch (error) {trace.fail(error); throw error;}
  }, error => error.code === 'DBAC_PROOF_INVALID');
  const recorded = trace.snapshot(), comparison = row(recorded, 'knowledge', 'Fiat-Shamir challenge');
  assert.equal(comparison.match, false); assert.notEqual(comparison.expected, comparison.observed);
  assert.equal(step(recorded, 'credential_pairing').evidence, undefined);
  noSecrets(recorded, [...f.secrets, presentation.proof.responses.inverseR1, presentation.proof.responses.keyRandomizer]);
});

test('invalid attribute count stops at schema without publishing an unfinished VC binding comparison', async () => {
  const f = await fixture(), prepared = await f.prepare();
  const changed = copy(prepared); changed.presentation.attributeCount++;
  await assert.rejects(f.transmit(changed), error => {
    assert.equal(error.code, 'DBAC_SCHEMA_MISMATCH');
    const trace = error.verificationTrace;
    assert.equal(step(trace, 'w3c_bbs').status, 'pass');
    assert.equal(step(trace, 'schema').status, 'fail');
    assert.deepEqual(row(trace, 'schema', 'signed attribute count'), {label: 'signed attribute count', expected: 7, observed: 8, match: false});
    assert.equal(step(trace, 'vc_device_binding').status, 'skipped');
    assert.equal(step(trace, 'vc_device_binding').evidence, undefined);
    noSecrets(trace, f.secrets); return true;
  });
  const wrongMode = copy(changed); wrongMode.presentation.mode = 'bbs-blind-bls';
  await assert.rejects(f.transmit(wrongMode), error => {
    assert.equal(error.code, 'DBAC_MODE_MISMATCH', 'the existing earlier mode rejection retains priority');
    assert.equal(step(error.verificationTrace, 'vc_device_binding').status, 'fail');
    assert.equal(row(error.verificationTrace, 'vc_device_binding', 'bindingId / mode / device contribution').observed[1], 'bbs-blind-bls');
    assert.equal(step(error.verificationTrace, 'schema').evidence, undefined); return true;
  });
  await f.transmit(prepared);
});

test('challenge expiry records the actual clock and expiry without claiming W3C verification ran', async t => {
  const f = await fixture(), prepared = await f.prepare();
  t.mock.method(Date, 'now', () => (prepared.context.exp + 1) * 1000);
  await assert.rejects(f.transmit(prepared), error => {
    assert.equal(error.code, 'DBAC_CHALLENGE_EXPIRED');
    assert.deepEqual(row(error.verificationTrace, 'challenge', 'challenge found / now / expiry (s)').observed, [true, prepared.context.exp + 1, prepared.context.exp]);
    assert.equal(step(error.verificationTrace, 'w3c_bbs').evidence, undefined); return true;
  });
});

test('Owner and settlement evidence stays public and within transport size limits', async t => {
  const f = await fixture(), proposal = await f.transmit(await f.prepare());
  const gate = proposal.signed.paymentGate;
  const authorization = issueDbacPaymentAuthorization(f.owner, {verifierDid: f.identity.did, issuerPublicKey: f.issuer.publicKey, mode: f.mode,
    orderKey: gate.orderKey, payment: f.payment, credentialBinding: credentialBindingOf(gate),
  });
  const authorized = await f.transmit(await f.prepare({phase: 'authorize', authorization}));
  const ownerRow = row(authorized.trace, 'owner_authorization', 'Owner / VC binding / issued / expires');
  assert.equal(ownerRow.observed[0], f.owner.did); assert.equal(ownerRow.observed[1], f.bindingId);
  assert.match(ownerRow.note, /untrusted until/);
  const payload = {x402Version: 2, payload: {signature: 'test business backend only', authorization: {nonce: randomUUID()}}};
  const settled = await f.transmit(await f.prepare({phase: 'settle', authorization, payload, continuation: authorized.body.result}));
  assert.equal(row(settled.trace, 'execution', 'settlement outcome / transaction').observed[0], 'EXECUTED');
  for (const result of [authorized, settled]) {
    noSecrets(result.trace, [...f.secrets, authorization]);
    assert.ok(Buffer.byteLength(result.token) <= 14336, `signed trace leaves at least 2 KiB of the default header budget (${Buffer.byteLength(result.token)} bytes)`);
  }
  t.diagnostic(`authorize header ${Buffer.byteLength(authorized.token)} bytes; settlement header ${Buffer.byteLength(settled.token)} bytes`);
});
