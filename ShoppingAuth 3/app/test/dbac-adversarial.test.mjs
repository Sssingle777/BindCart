// Independent paper-relation audit. This file does not import implementation
// helpers or any payment/runtime state. Fixed scalars below are public fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bls12_381 as curve } from '@noble/curves/bls12-381';
import {
  generateIssuerKey, generateDeviceKey, issueCredential, verifyCredential,
  preparePresentation, signDeviceRequest, finalizePresentation, verifyPresentation,
} from '../lib/dbac/crypto.mjs';

const SUITE = 'DBAC-BBS-BLS12381-SHA512-v1';
const P = curve.G1.ProjectivePoint, Q = curve.G2.ProjectivePoint;
const R = curve.fields.Fr.ORDER;
const utf8 = value => new TextEncoder().encode(value);
const normalize = value => Array.isArray(value) ? value.map(normalize)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, normalize(value[key])])) : value;
const encode = value => JSON.stringify(normalize(value));
const field = n => ((n % R) + R) % R;
const scalarHex = n => field(n).toString(16).padStart(64, '0');
const scalar = h => BigInt(`0x${h}`);
const hash = (purpose, value) => BigInt(`0x${createHash('sha512').update(`${SUITE}:${purpose}\0${encode(value)}`).digest('hex')}`) % R;
const generator = i => curve.G1.hashToCurve(utf8(`${SUITE}:H:${i}`), { DST: 'DBAC_BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_GENERATOR_V1_' });
const H = Array.from({ length: 8 }, (_, i) => generator(i));
const mScalar = (value, index) => hash('ATTRIBUTE', { index, value });
const scale = (point, n) => field(n) === 0n ? point.constructor.ZERO : point.multiply(field(n));
const linear = (bases, coefficients) => bases.reduce((sum, point, i) => sum.add(scale(point, coefficients[i])), P.ZERO);
const pairEquals = (p1, p2, p3, p4) => curve.fields.Fp12.eql(curve.pairing(p1, p2), curve.pairing(p3, p4));
const messagePoint = (pk, ctx) => curve.G2.hashToCurve(utf8(encode({ version: 1, suite: SUITE, randomizedDevicePublicKey: pk, context: ctx })), {
  DST: 'DBAC_BBS_BLS12381G2_XMD:SHA-256_SSWU_RO_DEVICE_V1_',
});
const transcript = (p, issuerPublicKey, context, t1, t2) => ({
  version: 1, suite: SUITE, mode: p.mode, issuerPublicKey, attributeCount: p.attributeCount,
  disclosed: p.disclosed, context, randomizedDevicePublicKey: p.randomizedDevicePublicKey,
  deviceSignature: p.deviceSignature, Abar: p.Abar, Bbar: p.Bbar, Cbar: p.Cbar,
  T1: t1.toHex(true), T2: t2.toHex(true),
});

function referenceAudit(p, issuerPublicKey, context) {
  const a = P.fromHex(p.Abar), b = P.fromHex(p.Bbar), cbar = P.fromHex(p.Cbar);
  const publicDevice = P.fromHex(p.randomizedDevicePublicKey);
  assert.ok(!a.equals(P.ZERO), 'Fig. 5 requires a nonzero randomized credential');
  assert.ok(pairEquals(a, Q.fromHex(issuerPublicKey), b, Q.BASE), 'independent randomized BBS pairing');
  assert.ok(pairEquals(H[0], Q.fromHex(p.deviceSignature), publicDevice, messagePoint(p.randomizedDevicePublicKey, context)), 'independent adapted BLS pairing');
  const disclosed = new Map(p.disclosed.map(({ index, value }) => [index, value]));
  const hidden = Array.from({ length: p.attributeCount }, (_, i) => i).filter(i => !disclosed.has(i));
  const y = linear([P.BASE, publicDevice, ...p.disclosed.map(({ index }) => H[index + 1])], [1n, 1n, ...p.disclosed.map(({ index, value }) => mScalar(value, index))]);
  const z = p.proof.responses;
  const responses = [scalar(z.inverseR1), scalar(z.keyRandomizer), ...z.hidden.map(item => scalar(item.response)), scalar(z.r2), scalar(z.e)];
  // Appendix F.1 matrix: [Cbar,H0,-Hj...,0,0]; [0,0,0...,Cbar,-Abar].
  const row1 = [cbar, H[0], ...hidden.map(i => H[i + 1].negate()), P.ZERO, P.ZERO];
  const row2 = [P.ZERO, P.ZERO, ...hidden.map(() => P.ZERO), cbar, a.negate()];
  const challenge = scalar(p.proof.challenge);
  const reconstructed = [linear(row1, responses).subtract(scale(y, challenge)), linear(row2, responses).subtract(scale(b, challenge))];
  assert.equal(scalarHex(hash('NIZK', transcript(p, issuerPublicKey, context, ...reconstructed))), p.proof.challenge, 'independent matrix commitments and Fiat-Shamir transcript');
}

const context = { audience: 'merchant:library', nonce: 'fresh-challenge-0001', order: { currency: 'demo', amount: 299 } };
const values = ['membership:student', 'private:alice@example.invalid', 'private:birthdate:2001-07-09'];
function fixture(mode = 'bbs-bls', attributes = values) {
  const issuer = generateIssuerKey(), device = generateDeviceKey();
  const credential = issueCredential({ issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes });
  const prepared = preparePresentation({ credential, context, disclosedIndices: [0], mode });
  const response = signDeviceRequest({ deviceSecretKey: device.secretKey, request: prepared.request });
  const presentation = finalizePresentation({ state: prepared.state, response });
  return { issuer, device, credential, prepared, response, presentation };
}
function verify(presentation, issuerPublicKey, ctx = context, requiredDisclosures = { 0: values[0] }) {
  return verifyPresentation({ presentation, issuerPublicKey, context: ctx, requiredDisclosures });
}
function denied(action, label) {
  assert.throws(action, error => typeof error.code === 'string' && error.code.startsWith('DBAC_'), label);
}

test('DBAC independent fixture: issuance, BLS adaptation and both NIZK rows agree with paper equations', () => {
  const x = 11n, d = 13n, e = 17n, k = 19n, r1 = 23n, r2 = 29n;
  const dpk = scale(H[0], d), ipk = scale(Q.BASE, x);
  const C = linear([P.BASE, dpk, ...values.map((_, i) => H[i + 1])], [1n, 1n, ...values.map(mScalar)]);
  const A = scale(C, curve.fields.Fr.inv(x + e));
  const credential = { version: 1, suite: SUITE, issuerPublicKey: ipk.toHex(true), devicePublicKey: dpk.toHex(true), attributes: values,
    signature: { A: A.toHex(true), e: scalarHex(e) } };
  assert.equal(verifyCredential(credential, { issuerPublicKey: ipk.toHex(true) }), true);
  assert.ok(pairEquals(A, ipk.add(scale(Q.BASE, e)), C, Q.BASE));
  const randomized = dpk.add(scale(H[0], k));
  const Cbar = scale(C, r1), Abar = scale(A, r1 * r2), Bbar = scale(Cbar, r2).subtract(scale(Abar, e));
  const p = { version: 1, suite: SUITE, mode: 'bbs-bls', attributeCount: 3, disclosed: [{ index: 0, value: values[0] }],
    randomizedDevicePublicKey: randomized.toHex(true), deviceSignature: scale(messagePoint(randomized.toHex(true), context), d + k).toHex(true),
    Abar: Abar.toHex(true), Bbar: Bbar.toHex(true), Cbar: Cbar.toHex(true) };
  const witness = [curve.fields.Fr.inv(r1), k, mScalar(values[1], 1), mScalar(values[2], 2), r2, e];
  const masks = [31n, 37n, 41n, 43n, 47n, 53n];
  const row1 = [Cbar, H[0], H[2].negate(), H[3].negate(), P.ZERO, P.ZERO];
  const row2 = [P.ZERO, P.ZERO, P.ZERO, P.ZERO, Cbar, Abar.negate()];
  assert.ok(linear(row1, witness).equals(P.BASE.add(randomized).add(scale(H[1], mScalar(values[0], 0)))));
  assert.ok(linear(row2, witness).equals(Bbar));
  const c = hash('NIZK', transcript(p, ipk.toHex(true), context, linear(row1, masks), linear(row2, masks)));
  const z = masks.map((mask, i) => scalarHex(mask + c * witness[i]));
  p.proof = { challenge: scalarHex(c), responses: { inverseR1: z[0], keyRandomizer: z[1], hidden: [{ index: 1, response: z[2] }, { index: 2, response: z[3] }], r2: z[4], e: z[5] } };
  referenceAudit(p, ipk.toHex(true), context);
  assert.equal(verify(p, ipk.toHex(true)).valid, true, 'production verifier accepts a separately constructed proof');
});

for (const mode of ['bbs-bls', 'bbs-blind-bls']) {
  test(`DBAC ${mode}: independent matrix and pairing verification of generated presentations`, () => {
    const f = fixture(mode);
    referenceAudit(f.presentation, f.issuer.publicKey, context);
    assert.equal(verify(f.presentation, f.issuer.publicKey).valid, true);
    if (mode === 'bbs-blind-bls') {
      assert.deepEqual(Object.keys(f.prepared.request).sort(), ['version', 'suite', 'mode', 'blindedPoint'].sort());
      assert.ok(pairEquals(H[0], Q.fromHex(f.response.signature), P.fromHex(f.device.publicKey), Q.fromHex(f.prepared.request.blindedPoint)), 'blind SE response satisfies the independent BLS pairing');
    }
  });

  test(`DBAC ${mode}: all public transcript fields and every response reject mutation`, () => {
    const f = fixture(mode), p = f.presentation;
    const mutations = {
      suite: q => { q.suite += '-other'; },
      version: q => { q.version++; },
      mode: q => { q.mode = mode === 'bbs-bls' ? 'bbs-blind-bls' : 'bbs-bls'; },
      attributeCount: q => { q.attributeCount++; },
      disclosedValue: q => { q.disclosed[0].value += ':forged'; },
      disclosedIndex: q => { q.disclosed[0].index = 1; },
      randomizedDevicePublicKey: q => { q.randomizedDevicePublicKey = P.fromHex(q.randomizedDevicePublicKey).add(H[0]).toHex(true); },
      deviceSignature: q => { q.deviceSignature = Q.fromHex(q.deviceSignature).add(Q.BASE).toHex(true); },
      Abar: q => { q.Abar = P.fromHex(q.Abar).add(P.BASE).toHex(true); },
      Bbar: q => { q.Bbar = P.fromHex(q.Bbar).add(P.BASE).toHex(true); },
      Cbar: q => { q.Cbar = P.fromHex(q.Cbar).add(P.BASE).toHex(true); },
      challenge: q => { q.proof.challenge = scalarHex(scalar(q.proof.challenge) + 1n); },
      inverseR1: q => { q.proof.responses.inverseR1 = scalarHex(scalar(q.proof.responses.inverseR1) + 1n); },
      keyRandomizer: q => { q.proof.responses.keyRandomizer = scalarHex(scalar(q.proof.responses.keyRandomizer) + 1n); },
      hiddenResponse: q => { q.proof.responses.hidden[0].response = scalarHex(scalar(q.proof.responses.hidden[0].response) + 1n); },
      r2: q => { q.proof.responses.r2 = scalarHex(scalar(q.proof.responses.r2) + 1n); },
      e: q => { q.proof.responses.e = scalarHex(scalar(q.proof.responses.e) + 1n); },
    };
    for (const [name, mutate] of Object.entries(mutations)) {
      const q = structuredClone(p); mutate(q);
      denied(() => verify(q, f.issuer.publicKey, context, {}), name);
    }
    denied(() => verify(p, generateIssuerKey().publicKey), 'trusted issuer replacement');
    for (const changed of [{ ...context, nonce: 'other-challenge' }, { ...context, audience: 'other-verifier' }, { ...context, order: { ...context.order, amount: 300 } }]) {
      denied(() => verify(p, f.issuer.publicKey, changed), 'external context mutation');
    }
    denied(() => verify(p, f.issuer.publicKey, context, { 1: values[1] }), 'hidden attribute is not a satisfied disclosure');
  });

  test(`DBAC ${mode}: a wrong device or malicious SE response fails before a presentation is released`, () => {
    const f = fixture(mode), other = generateDeviceKey();
    const fresh = () => preparePresentation({ credential: f.credential, context, disclosedIndices: [0], mode });
    const wrong = fresh();
    const response = signDeviceRequest({ deviceSecretKey: other.secretKey, request: wrong.request });
    denied(() => finalizePresentation({ state: wrong.state, response }), 'different device signed');
    denied(() => finalizePresentation({ state: wrong.state, response }), 'failed session cannot be reused');
    const altered = fresh();
    const honest = signDeviceRequest({ deviceSecretKey: f.device.secretKey, request: altered.request });
    honest.signature = Q.fromHex(honest.signature).add(Q.BASE).toHex(true);
    denied(() => finalizePresentation({ state: altered.state, response: honest }), 'SE appended a tag in group output');
    const credential = structuredClone(f.credential); credential.devicePublicKey = other.publicKey;
    denied(() => preparePresentation({ credential, context, mode }), 'credential device swap');
    credential.devicePublicKey = f.device.publicKey; credential.attributes[1] += ':changed';
    denied(() => preparePresentation({ credential, context, mode }), 'credential hidden attribute swap');
    const first = fresh(), second = fresh();
    const previousResponse = signDeviceRequest({ deviceSecretKey: f.device.secretKey, request: first.request });
    denied(() => finalizePresentation({ state: second.state, response: previousResponse }), 'replayed SE response in a new user session');
  });
}

test('DBAC malformed G1/G2 encodings, torsion points and infinity are rejected at each public boundary', () => {
  const f = fixture('bbs-blind-bls');
  const torsionG1 = `80${'00'.repeat(47)}`; // (0,2): on y^2=x^3+4, order 3, outside r-subgroup.
  const torsionG2 = `a0${'00'.repeat(94)}02`; // x=(2,0), curve point outside r-subgroup.
  assert.equal(P.fromAffine({ x: 0n, y: 2n }).isTorsionFree(), false);
  const x2 = { c0: 2n, c1: 0n }, y2 = curve.fields.Fp2.sqrt(curve.fields.Fp2.add(curve.fields.Fp2.pow(x2, 3n), curve.params.G2b));
  assert.equal(Q.fromAffine({ x: x2, y: y2 }).isTorsionFree(), false);
  const badG1 = [P.ZERO.toHex(true), torsionG1, f.device.publicKey.toUpperCase(), P.BASE.toHex(false), '00'.repeat(48), 'ff'.repeat(48), `${f.device.publicKey}00`];
  // This x.c0+p encoding decodes to the same field element in permissive
  // parsers. Canonical round-trip checking must reject it nevertheless.
  const canonicalG2 = Q.BASE.toHex(true);
  const aliasG2 = canonicalG2.slice(0, 96) + (BigInt(`0x${canonicalG2.slice(96)}`) + curve.fields.Fp.ORDER).toString(16).padStart(96, '0');
  const badG2 = [Q.ZERO.toHex(true), torsionG2, aliasG2, f.issuer.publicKey.toUpperCase(), Q.BASE.toHex(false), '00'.repeat(96), 'ff'.repeat(96), `${f.issuer.publicKey}00`];
  for (const point of badG1) {
    denied(() => issueCredential({ issuerSecretKey: f.issuer.secretKey, devicePublicKey: point, attributes: values }), 'invalid enrollment device point');
    for (const key of ['Abar', 'Bbar', 'Cbar', 'randomizedDevicePublicKey']) {
      const p = structuredClone(f.presentation); p[key] = point;
      denied(() => verify(p, f.issuer.publicKey), `invalid ${key}`);
    }
  }
  for (const point of badG2) {
    denied(() => verify(f.presentation, point), 'invalid trusted issuer point');
    const p = structuredClone(f.presentation); p.deviceSignature = point;
    denied(() => verify(p, f.issuer.publicKey), 'invalid presentation signature point');
    const request = { ...f.prepared.request, blindedPoint: point };
    denied(() => signDeviceRequest({ deviceSecretKey: f.device.secretKey, request }), 'invalid blind input point');
  }
});

test('DBAC noncanonical/out-of-range scalars and malformed disclosure/response schemas are rejected', () => {
  const f = fixture();
  const invalid = [R.toString(16).padStart(64, '0'), 'f'.repeat(64), '-1', '01', 'g'.repeat(64), 'A'.repeat(64), `00${f.issuer.secretKey}`];
  for (const item of invalid) {
    denied(() => issueCredential({ issuerSecretKey: item, devicePublicKey: f.device.publicKey, attributes: values }));
    denied(() => signDeviceRequest({ deviceSecretKey: item, request: f.prepared.request }));
    for (const key of ['inverseR1', 'keyRandomizer', 'r2', 'e']) {
      const p = structuredClone(f.presentation); p.proof.responses[key] = item;
      denied(() => verify(p, f.issuer.publicKey), key);
    }
    const p = structuredClone(f.presentation); p.proof.challenge = item;
    denied(() => verify(p, f.issuer.publicKey));
  }
  denied(() => issueCredential({ issuerSecretKey: '0'.repeat(64), devicePublicKey: f.device.publicKey, attributes: values }));
  denied(() => signDeviceRequest({ deviceSecretKey: '0'.repeat(64), request: f.prepared.request }));
  const malformed = [
    p => { p.disclosed.push({ ...p.disclosed[0] }); },
    p => { p.proof.responses.hidden.reverse(); },
    p => { p.proof.responses.hidden.pop(); },
    p => { p.proof.responses.hidden[0].index = 0; },
    p => { p.proof.responses.hidden[0].response = R.toString(16); },
    p => { p.devicePublicKey = f.device.publicKey; },
    p => { p.proof.stableTag = 'do-not-forward'; },
    p => { p.disclosed[0].hiddenValue = values[1]; },
  ];
  for (const mutate of malformed) { const p = structuredClone(f.presentation); mutate(p); denied(() => verify(p, f.issuer.publicKey)); }
});

test('DBAC multiple devices and repeated presentations disclose no original device key, credential or hidden values', () => {
  const issuer = generateIssuerKey();
  const keysSeen = new Set(), credentialPoints = new Set(), signatures = new Set();
  for (let user = 0; user < 3; user++) {
    const device = generateDeviceKey();
    const attributes = [values[0], `private:account:${user}:extra-long-opaque-id`, `private:address:${user}:hidden`];
    const credential = issueCredential({ issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes });
    for (const mode of ['bbs-bls', 'bbs-blind-bls']) for (let show = 0; show < 2; show++) {
      const prepared = preparePresentation({ credential, context, mode, disclosedIndices: [0] });
      const response = signDeviceRequest({ deviceSecretKey: device.secretKey, request: prepared.request });
      const p = finalizePresentation({ state: prepared.state, response });
      assert.equal(verify(p, issuer.publicKey).valid, true);
      const text = JSON.stringify(p);
      for (const forbidden of [device.publicKey, device.secretKey, issuer.secretKey, credential.signature.A, credential.signature.e, ...attributes.slice(1)]) {
        assert.equal(text.includes(forbidden), false, 'public presentation must not serialize a stable secret/original credential field');
      }
      if (mode === 'bbs-blind-bls') {
        const requestText = JSON.stringify(prepared.request);
        for (const forbidden of [device.publicKey, p.randomizedDevicePublicKey, context.nonce, context.audience, ...attributes]) assert.equal(requestText.includes(forbidden), false);
      }
      keysSeen.add(p.randomizedDevicePublicKey); credentialPoints.add(p.Abar); signatures.add(p.deviceSignature);
    }
  }
  assert.equal(keysSeen.size, 12); assert.equal(credentialPoints.size, 12); assert.equal(signatures.size, 12);
  // Different points and absence of serialized secrets are regression evidence,
  // not a proof of statistical unlinkability or side-channel resistance.
});

test('DBAC disclosure extremes and Unicode context canonicalization preserve the intended relation', () => {
  const f = fixture();
  for (const disclosedIndices of [[], [0, 1, 2]]) {
    const prepared = preparePresentation({ credential: f.credential, context, disclosedIndices });
    const p = finalizePresentation({ state: prepared.state, response: signDeviceRequest({ deviceSecretKey: f.device.secretKey, request: prepared.request }) });
    referenceAudit(p, f.issuer.publicKey, context);
    assert.equal(verify(p, f.issuer.publicKey, context, {}).valid, true);
  }
  for (const invalid of [{ nonce: '\ud800' }, { nonce: NaN }, { nested: undefined }, { nonce: -0 }, { nonce: 2 ** 54 }]) {
    denied(() => preparePresentation({ credential: f.credential, context: invalid }));
  }
  const reordered = { order: { amount: 299, currency: 'demo' }, nonce: context.nonce, audience: context.audience };
  assert.equal(verify(f.presentation, f.issuer.publicKey, reordered).valid, true);
});

test('DBAC boundary: one key exposed as a blind oracle cannot attest that the device observed normal-mode context', () => {
  const f = fixture();
  const prepared = preparePresentation({ credential: f.credential, context, disclosedIndices: [0], mode: 'bbs-bls' });
  // A malicious holder can submit H2(dpkBar,ctx) through an unrestricted blind
  // oracle instead of sending (dpkBar,ctx) to the normal device endpoint.
  const blindResponse = signDeviceRequest({ deviceSecretKey: f.device.secretKey, request: {
    version: 1, suite: SUITE, mode: 'bbs-blind-bls',
    blindedPoint: messagePoint(prepared.request.randomizedDevicePublicKey, context).toHex(true),
  } });
  const p = finalizePresentation({ state: prepared.state, response: { ...blindResponse, mode: 'bbs-bls' } });
  assert.equal(verify(p, f.issuer.publicKey).valid, true);
  // This is the paper's compatible mathematical construction, not a failed
  // cryptographic check. Deployment must not infer SE context approval from the
  // holder's mode label when the same device key has a blind-signing oracle.
});
