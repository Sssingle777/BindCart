import test from 'node:test';
import assert from 'node:assert/strict';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import {
  DBAC_SUITE, DBAC_VERSION, DbacError, generateIssuerKey, generateDeviceKey,
  issueCredential, verifyCredential, preparePresentation, signDeviceRequest,
  finalizePresentation, verifyPresentation, verifyDeviceResponse,
} from '../lib/dbac/crypto.mjs';

const issuer = generateIssuerKey();
const device = generateDeviceKey();
const attributes = ['payment:execute', 'customer-private-42', 'region:CN'];
const context = { nonce: 'fresh-session-challenge', audience: 'merchant:B', requestDigest: 'order:123' };
function credential() {
  return issueCredential({ issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes });
}
function present(options = {}) {
  const source = options.credential ?? credential();
  const input = { credential: source, context, disclosedIndices: [0], ...options };
  const { state, request } = preparePresentation(input);
  const response = signDeviceRequest({ deviceSecretKey: device.secretKey, request });
  return { credential: source, request, response, presentation: finalizePresentation({ state, response }) };
}
function verify(presentation, options = {}) {
  return verifyPresentation({ presentation, issuerPublicKey: issuer.publicKey, context, requiredDisclosures: { 0: attributes[0] }, ...options });
}
function rejects(fn, code) {
  assert.throws(fn, error => error instanceof DbacError && (!code || error.code === code));
}

test('paper BBS credential binds both device key and every attribute', () => {
  const original = credential();
  assert.equal(verifyCredential(original, { issuerPublicKey: issuer.publicKey }), true);
  const alteredAttribute = structuredClone(original);
  alteredAttribute.attributes[1] = 'another-customer';
  rejects(() => verifyCredential(alteredAttribute, { issuerPublicKey: issuer.publicKey }), 'DBAC_INVALID_CREDENTIAL');
  const substitutedDevice = { ...original, devicePublicKey: generateDeviceKey().publicKey };
  rejects(() => verifyCredential(substitutedDevice, { issuerPublicKey: issuer.publicKey }), 'DBAC_INVALID_CREDENTIAL');
  rejects(() => verifyCredential(original, { issuerPublicKey: generateIssuerKey().publicKey }), 'DBAC_UNTRUSTED_ISSUER');
});

test('BBS-BLS reproduces selective disclosure with device participation', () => {
  const { presentation } = present();
  assert.deepEqual(verify(presentation), {
    valid: true, mode: 'bbs-bls', attributeCount: 3, disclosed: [{ index: 0, value: attributes[0] }],
  });
  assert.equal(presentation.suite, DBAC_SUITE);
  assert.equal(presentation.version, DBAC_VERSION);
});

test('a separate device response check supports enrollment proof of possession', () => {
  const enrollmentContext = { purpose: 'dbac-enrollment', nonce: 'issuer-fresh-nonce', attributeDigest: 'approved-claims-digest' };
  const { request } = preparePresentation({ credential: credential(), context: enrollmentContext });
  const response = signDeviceRequest({ deviceSecretKey: device.secretKey, request });
  assert.equal(verifyDeviceResponse({ devicePublicKey: device.publicKey, request, response }), true);
  rejects(() => verifyDeviceResponse({ devicePublicKey: generateDeviceKey().publicKey, request, response }), 'DBAC_DEVICE_SIGNATURE_INVALID');
  const altered = structuredClone(request);
  altered.context.nonce = 'other-enrollment';
  rejects(() => verifyDeviceResponse({ devicePublicKey: device.publicKey, request: altered, response }), 'DBAC_DEVICE_SIGNATURE_INVALID');
});

test('BlindBLS blinds device input and uses the same verification equations', () => {
  const { request, presentation } = present({ mode: 'bbs-blind-bls' });
  assert.deepEqual(Object.keys(request).sort(), ['blindedPoint', 'mode', 'suite', 'version']);
  assert.equal(request.blindedPoint.length, 192);
  assert.ok(!JSON.stringify(request).includes(context.nonce));
  assert.ok(!JSON.stringify(request).includes(context.audience));
  assert.equal(verify(presentation).mode, 'bbs-blind-bls');
});

test('both variants support all-hidden and all-disclosed predicates', () => {
  for (const mode of ['bbs-bls', 'bbs-blind-bls']) {
    const hidden = present({ mode, disclosedIndices: [] }).presentation;
    assert.deepEqual(verify(hidden, { requiredDisclosures: {} }).disclosed, []);
    const publicProof = present({ mode, disclosedIndices: [0, 1, 2] }).presentation;
    assert.equal(verify(publicProof).disclosed.length, 3);
    assert.deepEqual(publicProof.proof.responses.hidden, []);
  }
});

test('presentation does not serialize original key, signature, or hidden attributes', () => {
  const { credential: source, presentation } = present();
  const serialized = JSON.stringify(presentation);
  for (const privateValue of [device.secretKey, device.publicKey, source.signature.A, source.signature.e, attributes[1], attributes[2]]) {
    assert.ok(!serialized.includes(privateValue));
  }
  assert.ok(!Object.hasOwn(presentation, 'credential'));
  assert.ok(!Object.hasOwn(presentation, 'context'));
});

test('fresh showings rerandomize public device key, credential, and proof', () => {
  const source = credential();
  const first = present({ credential: source }).presentation;
  const second = present({ credential: source }).presentation;
  for (const field of ['randomizedDevicePublicKey', 'deviceSignature', 'Abar', 'Bbar', 'Cbar']) {
    assert.notEqual(first[field], second[field]);
  }
  assert.notEqual(first.proof.challenge, second.proof.challenge);
  assert.equal(verify(first).valid, true);
  assert.equal(verify(second).valid, true);
});

test('a copied credential plus a different device cannot complete a showing', () => {
  const { state, request } = preparePresentation({ credential: credential(), context, disclosedIndices: [0] });
  const wrongResponse = signDeviceRequest({ deviceSecretKey: generateDeviceKey().secretKey, request });
  rejects(() => finalizePresentation({ state, response: wrongResponse }), 'DBAC_DEVICE_SIGNATURE_INVALID');
});

test('presentation state is one-use even after an invalid device response', () => {
  const { state, request } = preparePresentation({ credential: credential(), context });
  const response = signDeviceRequest({ deviceSecretKey: device.secretKey, request });
  finalizePresentation({ state, response });
  rejects(() => finalizePresentation({ state, response }), 'DBAC_INVALID_STATE');
  const another = preparePresentation({ credential: credential(), context });
  rejects(() => finalizePresentation({ state: another.state, response: {} }));
  rejects(() => finalizePresentation({ state: another.state, response }), 'DBAC_INVALID_STATE');
});

test('context binding rejects changed nonce, merchant, and request digest', () => {
  const { presentation } = present();
  for (const field of Object.keys(context)) {
    rejects(() => verify(presentation, { context: { ...context, [field]: 'different' } }), 'DBAC_PROOF_INVALID');
  }
  assert.equal(verify(presentation, { context: {
    requestDigest: context.requestDigest, nonce: context.nonce, audience: context.audience,
  } }).valid, true);
});

test('changing the device request context is detected before final proof creation', () => {
  const { state, request } = preparePresentation({ credential: credential(), context });
  request.context.nonce = 'changed-by-transport';
  const response = signDeviceRequest({ deviceSecretKey: device.secretKey, request });
  rejects(() => finalizePresentation({ state, response }), 'DBAC_DEVICE_SIGNATURE_INVALID');
});

test('required disclosure is enforced independently of proof validity', () => {
  const { presentation } = present();
  rejects(() => verify(presentation, { requiredDisclosures: { 1: attributes[1] } }), 'DBAC_POLICY_REJECTED');
  rejects(() => verify(presentation, { requiredDisclosures: { 0: 'payment:admin' } }), 'DBAC_POLICY_REJECTED');
});

test('disclosure tampering, response tampering, issuer substitution, and mode swap fail', () => {
  const { presentation } = present();
  const disclosed = structuredClone(presentation);
  disclosed.disclosed[0].value = 'payment:admin';
  rejects(() => verify(disclosed, { requiredDisclosures: {} }), 'DBAC_PROOF_INVALID');
  const response = structuredClone(presentation);
  response.proof.responses.hidden[0].response = '00'.repeat(32);
  rejects(() => verify(response), 'DBAC_PROOF_INVALID');
  rejects(() => verify(presentation, { issuerPublicKey: generateIssuerKey().publicKey }), 'DBAC_PROOF_INVALID');
  rejects(() => verify({ ...presentation, mode: 'bbs-blind-bls' }), 'DBAC_PROOF_INVALID');
});

test('strict schemas reject unrecognized fields and malformed disclosure indices', () => {
  const { presentation } = present();
  rejects(() => verify({ ...presentation, devicePublicKey: device.publicKey }), 'DBAC_INVALID_INPUT');
  rejects(() => verify({ ...presentation, attributeCount: 65 }), 'DBAC_INVALID_INPUT');
  rejects(() => preparePresentation({ credential: credential(), context, disclosedIndices: [1, 0] }));
  rejects(() => preparePresentation({ credential: credential(), context, disclosedIndices: [0, 0] }));
  rejects(() => preparePresentation({ credential: credential(), context, disclosedIndices: [3] }));
});

test('malformed/identity points and noncanonical scalars are rejected', () => {
  const { presentation } = present();
  const infinity = bls.G1.ProjectivePoint.ZERO.toHex(true);
  rejects(() => verify({ ...presentation, Abar: infinity }), 'DBAC_INVALID_INPUT');
  rejects(() => verify({ ...presentation, randomizedDevicePublicKey: '00'.repeat(48) }), 'DBAC_INVALID_INPUT');
  rejects(() => verify({ ...presentation, deviceSignature: presentation.deviceSignature.toUpperCase() }), 'DBAC_INVALID_INPUT');
  const tooLarge = structuredClone(presentation);
  tooLarge.proof.challenge = bls.fields.Fr.ORDER.toString(16).padStart(64, '0');
  rejects(() => verify(tooLarge), 'DBAC_INVALID_INPUT');
  const negative = structuredClone(presentation);
  negative.proof.responses.r2 = '-1';
  rejects(() => verify(negative), 'DBAC_INVALID_INPUT');
});

test('blind response from another session fails the user-side device verification', () => {
  const first = preparePresentation({ credential: credential(), context, mode: 'bbs-blind-bls' });
  const second = preparePresentation({ credential: credential(), context, mode: 'bbs-blind-bls' });
  const response = signDeviceRequest({ deviceSecretKey: device.secretKey, request: first.request });
  rejects(() => finalizePresentation({ state: second.state, response }), 'DBAC_DEVICE_SIGNATURE_INVALID');
});

test('invalid JSON types, surrogate strings, and noninteger context values are rejected', () => {
  const source = credential();
  for (const invalid of [{ nonce: undefined }, { nonce: 1.1 }, { nonce: -0 }, { nonce: '\ud800' }, { nonce: 1n }]) {
    rejects(() => preparePresentation({ credential: source, context: invalid }), 'DBAC_INVALID_INPUT');
  }
});
