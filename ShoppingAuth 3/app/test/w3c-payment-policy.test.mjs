import assert from 'node:assert/strict';
import test from 'node:test';
import {randomBytes, randomUUID} from 'node:crypto';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateIdentity, signJws} from '../lib/identity.mjs';
import {digest, unix} from '../lib/protocol.mjs';
import {PAYMENT_SCOPE} from '../lib/payment.mjs';
import {generateDeviceKey, generateIssuerKey} from '../lib/dbac/crypto.mjs';
import {DBAC_EXTENSION, DBAC_SCHEMA, paymentDisclosures} from '../lib/dbac/policy.mjs';
import {W3C_PAYMENT_PROFILE, W3C_PAYMENT_SCHEMA} from '../lib/dbac/w3c-profile.mjs';
import {
  DBAC_PAYMENT_PROFILE, DBAC_PAYMENT_RESPONSE_TYP, credentialBindingOf,
  dbacPaymentHash, issueDbacPaymentAuthorization, verifyDbacPaymentAuthorization,
  verifyDbacPaymentEvidence,
} from '../lib/dbac/payment-policy.mjs';
import {createLocalX402Environment, createX402Backend, createX402Payer, paymentSettlement} from '../lib/x402-payment.mjs';
import {createOwner} from '../lib/owner.mjs';

const owner = generateIdentity('Policy test Owner');
const verifier = generateIdentity('Policy test verifier');
const issuer = generateIssuerKey();
const orderKey = generateDeviceKey().publicKey;
const mode = 'bbs-bls';
const binding = Object.freeze({credentialProfile: W3C_PAYMENT_PROFILE, w3cIssuer: 'did:example:w3c-policy-issuer', vcBindingId: `urn:uuid:${randomUUID()}`});
const payment = Object.freeze({orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 299, currency: 'CNY'});
const issueOptions = (p = payment) => ({verifierDid: verifier.did, issuerPublicKey: issuer.publicKey, mode, orderKey, payment: p});
const verifyOptions = (p = payment) => ({...issueOptions(p), trustedAuthorizers: [owner.did]});
const failure = code => error => {assert.equal(error.code, code, error.message); return true;};

// Boundary fixture: authentic signatures by a trusted B, without claiming a
// synthetic trace is a cryptographic BBS/eSIM test. Those run in separate tests.
function signedEvidence({phase = 'proposal', terms = payment, vcBinding = binding, authorization, paymentRequired, payload, steps, mutateSigned} = {}) {
  const time = unix();
  const taskId = randomUUID(), contextId = randomUUID();
  const request = {jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: {message: {
    kind: 'message', role: 'user', messageId: randomUUID(),
    ...(phase === 'settle' ? {taskId, contextId} : {}),
    parts: [{kind: 'data', data: {scope: PAYMENT_SCOPE, phase, payment: terms,
      ...(phase === 'proposal' ? {} : {authorization}), ...(phase === 'settle' ? {payload} : {}),
    }}],
  }}};
  const rawRequest = JSON.stringify(request);
  const context = {
    profile: DBAC_EXTENSION, purpose: 'dbac-payment-v1', scope: PAYMENT_SCOPE, mode,
    verifier: verifier.did, target: 'http://127.0.0.1:12345/dbac/payment/a2a', method: 'POST',
    bodyHash: digest(rawRequest), paymentOrderId: terms.orderId, challengeId: randomUUID(),
    nonce: randomBytes(32).toString('base64url'), iat: time, exp: time + 60,
    schema: vcBinding ? W3C_PAYMENT_SCHEMA : DBAC_SCHEMA, requiredDisclosures: paymentDisclosures(mode),
    ...(vcBinding ? {credentialProfile: W3C_PAYMENT_PROFILE} : {}),
  };
  const rawResponse = JSON.stringify({jsonrpc: '2.0', id: request.id, result: {
    kind: 'task', id: taskId, contextId, status: {
      state: phase === 'proposal' ? 'completed' : phase === 'authorize' ? 'input-required' : 'working',
      ...(phase === 'proposal' ? {} : {message: {metadata: phase === 'authorize'
        ? {'x402.payment.status': 'payment-required', 'x402.payment.required': paymentRequired}
        : {'dbac.payment.status': 'settlement-authorized'}}}),
    },
  }});
  const signed = {
    iss: verifier.did, requestHash: digest(rawRequest), responseHash: digest(rawResponse), contextHash: digest(JSON.stringify(context)),
    iat: time, exp: time + (phase === 'proposal' ? 300 : 60),
    paymentGate: {
      profile: DBAC_PAYMENT_PROFILE, phase, mode, issuerPublicKey: issuer.publicKey, orderKey,
      paymentHash: dbacPaymentHash(terms),
      ...(vcBinding ? {...vcBinding, w3cPresentationHash: digest('synthetic standard VC for policy-only fixture')} : {}),
      ...(phase === 'proposal' ? {} : {authorizationHash: digest(authorization)}),
      ...(phase === 'settle' ? {payloadHash: dbacPaymentHash(payload)} : {}),
    },
    verificationTrace: {profile: DBAC_PAYMENT_PROFILE, source: 'agent-b', outcome: 'pass',
      steps: steps ?? (vcBinding ? ['w3c_bbs', 'vc_device_binding'].map(id => ({id, status: 'pass'})) : []),
    },
  };
  mutateSigned?.(signed);
  return {proof: signJws(signed, verifier, DBAC_PAYMENT_RESPONSE_TYP), rawRequest, rawResponse, context};
}

test('credentialBindingOf returns only the three signed binding fields and rejects incomplete profiles', () => {
  const extracted = credentialBindingOf({...binding, mode, secretUnrelatedValue: 'must not propagate'});
  assert.deepEqual(extracted, binding); assert.notEqual(extracted, binding);
  assert.equal(credentialBindingOf({mode}), undefined);
  for (const changed of [
    {...binding, credentialProfile: 'identified'}, {...binding, w3cIssuer: ''},
    {...binding, w3cIssuer: 'relative-id'}, {...binding, vcBindingId: ''},
    {...binding, vcBindingId: 'line\nbreak'}, {credentialProfile: W3C_PAYMENT_PROFILE},
  ]) assert.throws(() => credentialBindingOf(changed), failure('W3C_CREDENTIAL_BINDING_INVALID'));
});

test('W3C policy refuses an otherwise valid legacy Owner authorization', () => {
  const legacy = issueDbacPaymentAuthorization(owner, issueOptions());
  assert.equal(verifyDbacPaymentAuthorization(legacy, verifyOptions()).profile, DBAC_PAYMENT_PROFILE);
  assert.throws(() => verifyDbacPaymentAuthorization(legacy, {...verifyOptions(), w3cIssuer: binding.w3cIssuer}), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
  assert.throws(() => verifyDbacPaymentAuthorization(legacy, {...verifyOptions(), credentialBinding: binding}), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
});

test('Owner authorization pins the exact W3C issuer, profile and credential identifier', () => {
  const token = issueDbacPaymentAuthorization(owner, {...issueOptions(), credentialBinding: binding});
  const document = verifyDbacPaymentAuthorization(token, {...verifyOptions(), credentialBinding: binding, w3cIssuer: binding.w3cIssuer});
  assert.deepEqual(credentialBindingOf(document), binding);
  for (const changed of [
    {...binding, vcBindingId: `urn:uuid:${randomUUID()}`},
    {...binding, w3cIssuer: 'did:example:other-issuer'},
  ]) assert.throws(() => verifyDbacPaymentAuthorization(token, {...verifyOptions(), credentialBinding: changed}), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
  assert.throws(() => verifyDbacPaymentAuthorization(token, {...verifyOptions(), credentialBinding: {...binding, credentialProfile: 'legacy-dbac'}}), failure('W3C_CREDENTIAL_BINDING_INVALID'));
  assert.throws(() => verifyDbacPaymentAuthorization(token, {...verifyOptions(), w3cIssuer: 'did:example:other-issuer'}), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
  assert.throws(() => issueDbacPaymentAuthorization(owner, {...issueOptions(), credentialBinding: {...binding, unexpected: true}}), failure('W3C_CREDENTIAL_BINDING_INVALID'));
});

test('pinned W3C evidence policy rejects old B gates even with authentic signatures', () => {
  const options = {verifierDid: verifier.did, issuerPublicKey: issuer.publicKey, phase: 'proposal', payment};
  const legacy = signedEvidence({vcBinding: null});
  assert.equal(verifyDbacPaymentEvidence(legacy, options).gate.profile, DBAC_PAYMENT_PROFILE);
  assert.throws(() => verifyDbacPaymentEvidence(legacy, {...options, w3cIssuer: binding.w3cIssuer}), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
  assert.throws(() => verifyDbacPaymentEvidence(legacy, {...options, credentialBinding: binding}), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
  assert.deepEqual(credentialBindingOf(verifyDbacPaymentEvidence(signedEvidence(), {...options, credentialBinding: binding, w3cIssuer: binding.w3cIssuer}).gate), binding);
});

test('B evidence requires both W3C and device-binding checks and a signed derived-VC digest', () => {
  const options = {verifierDid: verifier.did, issuerPublicKey: issuer.publicKey, phase: 'proposal', payment, credentialBinding: binding};
  for (const steps of [[], [{id: 'w3c_bbs', status: 'pass'}], [{id: 'vc_device_binding', status: 'pass'}], [{id: 'w3c_bbs', status: 'pass'}, {id: 'vc_device_binding', status: 'fail'}]]) {
    assert.throws(() => verifyDbacPaymentEvidence(signedEvidence({steps}), options), failure('DBAC_PAYMENT_EVIDENCE_MISMATCH'));
  }
  assert.throws(() => verifyDbacPaymentEvidence(signedEvidence({mutateSigned: signed => {signed.paymentGate.w3cPresentationHash = 'invalid';}}), options), failure('DBAC_PAYMENT_EVIDENCE_MISMATCH'));
  assert.throws(() => verifyDbacPaymentEvidence(signedEvidence({vcBinding: {...binding, vcBindingId: `urn:uuid:${randomUUID()}`}}), options), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
});

test('explicit empty or malformed W3C policy options cannot silently select legacy mode', () => {
  const token = issueDbacPaymentAuthorization(owner, issueOptions());
  const evidence = signedEvidence({vcBinding: null});
  const evidenceOptions = {verifierDid: verifier.did, issuerPublicKey: issuer.publicKey, phase: 'proposal', payment};
  for (const invalid of [null, false, '', 'relative-id', 'did:example:issuer with spaces']) {
    assert.throws(() => verifyDbacPaymentAuthorization(token, {...verifyOptions(), w3cIssuer: invalid}), failure('W3C_CREDENTIAL_BINDING_INVALID'));
    assert.throws(() => verifyDbacPaymentEvidence(evidence, {...evidenceOptions, w3cIssuer: invalid}), failure('W3C_CREDENTIAL_BINDING_INVALID'));
  }
  for (const invalid of [null, false, {}, {w3cIssuer: binding.w3cIssuer}, {...binding, unexpected: true}]) {
    assert.throws(() => verifyDbacPaymentAuthorization(token, {...verifyOptions(), credentialBinding: invalid}), failure('W3C_CREDENTIAL_BINDING_INVALID'));
    assert.throws(() => verifyDbacPaymentEvidence(evidence, {...evidenceOptions, credentialBinding: invalid}), failure('W3C_CREDENTIAL_BINDING_INVALID'));
  }
});

test('Owner and wallet configurations reject an explicitly invalid W3C issuer before starting services', async () => {
  const holder = generateIdentity('configuration holder'), device = generateIdentity('configuration device'), namedIssuer = generateIdentity('configuration issuer');
  const base = {holderDid: holder.did, verifierDid: verifier.did, trustedIssuers: [namedIssuer.did], dbacIssuerPublicKey: issuer.publicKey};
  for (const w3cIssuer of [null, false, '', 'relative-id', 'did:example:issuer with spaces']) {
    assert.throws(() => createOwner({...base, proposalToken: randomBytes(32).toString('base64url'), uiToken: randomBytes(32).toString('base64url'), w3cIssuer}), failure('OWNER_INVALID_CONFIG'));
    await assert.rejects(createLocalX402Environment({...base, trustedAuthorizers: [owner.did], deviceDid: device.did, isCredentialRevoked: async () => false, w3cIssuer}), failure('INVALID_X402_CONFIGURATION'));
  }
});

test('wallet refuses W3C downgrade and cannot reuse one VC payment payload with another VC binding', {timeout: 60000}, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'w3c-policy-wallet-'));
  const namedIssuer = generateIdentity('legacy issuer'), holder = generateIdentity('holder'), device = generateIdentity('legacy device');
  let environment;
  t.after(async () => {await environment?.close(); await rm(directory, {recursive: true, force: true});});
  environment = await createLocalX402Environment({stateDir: directory, trustedIssuers: [namedIssuer.did], trustedAuthorizers: [owner.did],
    holderDid: holder.did, deviceDid: device.did, verifierDid: verifier.did, isCredentialRevoked: async () => false,
    dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: binding.w3cIssuer, isDbacCredentialRevoked: async () => false,
  });
  const payer = createX402Payer(environment.payerConfig), backend = createX402Backend(environment.backendConfig);
  const terms = {...payment, orderId: `urn:uuid:${randomUUID()}`, currency: 'TEST_USDC', settlement: paymentSettlement(environment.publicInfo)};
  const paymentRequired = backend.requirements(terms);
  const snapshot = await backend.snapshot();
  const legacy = issueDbacPaymentAuthorization(owner, issueOptions(terms));
  await assert.rejects(payer.createPayload({profile: DBAC_PAYMENT_PROFILE, payment: terms, paymentRequired, authorization: legacy,
    responseEvidence: signedEvidence({terms, phase: 'authorize', vcBinding: null, authorization: legacy, paymentRequired}),
  }), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
  const authorization = issueDbacPaymentAuthorization(owner, {...issueOptions(terms), credentialBinding: binding});
  const input = {profile: DBAC_PAYMENT_PROFILE, payment: terms, paymentRequired, authorization,
    responseEvidence: signedEvidence({terms, phase: 'authorize', authorization, paymentRequired}),
  };
  await assert.rejects(payer.createPayload({...input, responseEvidence: signedEvidence({terms, phase: 'authorize', vcBinding: null, authorization, paymentRequired})}), failure('PAYMENT_AUTHORIZATION_BINDING_MISMATCH'));
  const payload = await payer.createPayload(input);
  assert.match(payload.payload.signature, /^0x[0-9a-f]+$/i);
  const otherBinding = {...binding, vcBindingId: `urn:uuid:${randomUUID()}`};
  const otherAuthorization = issueDbacPaymentAuthorization(owner, {...issueOptions(terms), credentialBinding: otherBinding});
  const other = {...input, authorization: otherAuthorization,
    responseEvidence: signedEvidence({terms, phase: 'authorize', vcBinding: otherBinding, authorization: otherAuthorization, paymentRequired}),
  };
  await assert.rejects(payer.createPayload(other), failure('X402_ORDER_BINDING_MISMATCH'));
  await assert.rejects(backend.execute({profile: DBAC_PAYMENT_PROFILE, payment: terms, payload, authorization: otherAuthorization,
    responseEvidence: signedEvidence({terms, phase: 'settle', vcBinding: otherBinding, authorization: otherAuthorization, payload}),
  }), failure('X402_ORDER_BINDING_MISMATCH'));
  assert.deepEqual(await payer.createPayload(input), payload, 'the original VC still recovers exactly its original signed payload');
  assert.equal((await backend.snapshot()).executionCount, snapshot.executionCount, 'policy rejection never transfers test tokens');
});

test('a W3C-bound wallet cannot silently omit its current issuer status callback', { timeout: 60000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'w3c-policy-missing-status-'));
  const namedIssuer = generateIdentity('legacy issuer'), holder = generateIdentity('holder'), device = generateIdentity('legacy device');
  let environment;
  t.after(async () => { await environment?.close(); await rm(directory, { recursive: true, force: true }); });
  environment = await createLocalX402Environment({ stateDir: directory, trustedIssuers: [namedIssuer.did], trustedAuthorizers: [owner.did],
    holderDid: holder.did, deviceDid: device.did, verifierDid: verifier.did, isCredentialRevoked: async () => false,
    dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: binding.w3cIssuer,
    // Intentionally absent isDbacCredentialRevoked: this is a configuration
    // fault test, using the policy-only signed B fixture defined above.
  });
  const payer = createX402Payer(environment.payerConfig), backend = createX402Backend(environment.backendConfig);
  const terms = { ...payment, orderId: `urn:uuid:${randomUUID()}`, currency: 'TEST_USDC', settlement: paymentSettlement(environment.publicInfo) };
  const paymentRequired = backend.requirements(terms), before = await backend.snapshot();
  const authorization = issueDbacPaymentAuthorization(owner, { ...issueOptions(terms), credentialBinding: binding });
  const input = { profile: DBAC_PAYMENT_PROFILE, payment: terms, paymentRequired, authorization,
    responseEvidence: signedEvidence({ terms, phase: 'authorize', authorization, paymentRequired }) };
  await assert.rejects(payer.createPayload(input), failure('W3C_STATUS_UNAVAILABLE'));
  const after = await backend.snapshot();
  assert.equal(after.executionCount, before.executionCount);
  assert.deepEqual(after.accounts, before.accounts);
  assert.equal(after.receipts.length, before.receipts.length);
});
