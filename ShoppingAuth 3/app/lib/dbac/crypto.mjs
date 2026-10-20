/**
 * Research implementation of Fig. 5 / Sections 6.3 and 6.4 of
 * Device-Bound Anonymous Credentials With(out) Trusted Hardware.
 *
 * This is a paper-specific BBS protocol, NOT the W3C bbs-2023 wire format.
 * BLS12-381 instantiates the paper's abstract type-3 pairing groups. Device
 * public keys are in G1; device signatures and issuer public keys are in G2.
 * This JavaScript module does not provide hardware isolation or attestation.
 */
import { createHash, randomBytes } from 'node:crypto';
import { bls12_381 as bls } from '@noble/curves/bls12-381';

export const DBAC_VERSION = 1;
export const DBAC_SUITE = 'DBAC-BBS-BLS12381-SHA512-v1';
const MODULUS = bls.fields.Fr.ORDER;
const G1 = bls.G1.ProjectivePoint;
const G2 = bls.G2.ProjectivePoint;
const MAX_ATTRIBUTES = 64;
const MODES = new Set(['bbs-bls', 'bbs-blind-bls']);
const GENERATOR_DST = 'DBAC_BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_GENERATOR_V1_';
const SIGNATURE_DST = 'DBAC_BBS_BLS12381G2_XMD:SHA-256_SSWU_RO_DEVICE_V1_';
const encoder = new TextEncoder();
const generatorCache = new Map();
const states = new WeakMap();
const paymentBindings = new WeakMap();
const publicTraceValue = value => value === null || ['string', 'boolean', 'undefined'].includes(typeof value) || typeof value === 'number' && Number.isFinite(value) ? value : `[invalid ${Array.isArray(value) ? 'array' : typeof value}]`;

export class DbacError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'DbacError';
    this.code = code;
  }
}

function fail(message, code = 'DBAC_INVALID_INPUT') {
  throw new DbacError(code, message);
}
function requireThat(condition, message, code) {
  if (!condition) fail(message, code);
}
function object(value, label) {
  requireThat(value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value)), `${label} must be a plain object`);
}
function shape(value, keys, label) {
  object(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  requireThat(actual.length === expected.length && actual.every((k, i) => k === expected[i]), `${label} has unexpected or missing fields`);
}

// JSON is canonicalized locally for this protocol; it is not RDF canonicalization.
function canonical(value, depth = 0) {
  requireThat(depth <= 16, 'JSON nesting exceeds the protocol limit');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    requireThat(value.length <= 32768, 'JSON string exceeds the protocol limit');
    // Reject isolated UTF-16 surrogates; otherwise UTF-8 conversion is not injective.
    requireThat(value.isWellFormed(), 'JSON strings must be well-formed Unicode');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    requireThat(Number.isSafeInteger(value) && !Object.is(value, -0), 'JSON numbers must be safe integers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    requireThat(value.length <= 256, 'JSON array exceeds the protocol limit');
    return `[${Array.from(value, entry => canonical(entry, depth + 1)).join(',')}]`;
  }
  object(value, 'JSON value');
  const keys = Object.keys(value).sort();
  requireThat(keys.length <= 128, 'JSON object exceeds the protocol limit');
  return `{${keys.map(key => `${canonical(key, depth + 1)}:${canonical(value[key], depth + 1)}`).join(',')}}`;
}
function contextCopy(context) {
  object(context, 'context');
  const text = canonical(context);
  requireThat(Buffer.byteLength(text, 'utf8') <= 65536, 'context exceeds 64 KiB');
  return JSON.parse(text);
}
function mod(value) { return ((value % MODULUS) + MODULUS) % MODULUS; }
function scalarHex(value) { return mod(value).toString(16).padStart(64, '0'); }
function scalar(value, label, nonzero = false) {
  requireThat(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), `${label} must be canonical 32-byte scalar hex`);
  const number = BigInt(`0x${value}`);
  requireThat(number < MODULUS && (!nonzero || number !== 0n), `${label} is outside the allowed scalar range`);
  return number;
}
function randomScalar(nonzero = false) {
  while (true) {
    const result = BigInt(`0x${randomBytes(32).toString('hex')}`);
    if (result < MODULUS && (!nonzero || result !== 0n)) return result;
  }
}
function hashScalar(domain, value) {
  return BigInt(`0x${createHash('sha512').update(domain).update('\0').update(canonical(value)).digest('hex')}`) % MODULUS;
}
function mul(point, number) {
  const reduced = mod(number);
  return reduced === 0n ? point.constructor.ZERO : point.multiply(reduced);
}
function pointHex(point) { return point.toHex(true); }
function parsePoint(encoded, group, label, allowZero = false) {
  const length = group === G1 ? 96 : 192;
  requireThat(typeof encoded === 'string' && new RegExp(`^[0-9a-f]{${length}}$`).test(encoded), `${label} must be canonical compressed point hex`);
  let result;
  try {
    result = group.fromHex(encoded);
    result.assertValidity(); // Includes subgroup membership, not merely curve membership.
  } catch {
    fail(`${label} is not a valid prime-order subgroup point`);
  }
  requireThat(pointHex(result) === encoded, `${label} uses a noncanonical point encoding`);
  requireThat(allowZero || !result.equals(group.ZERO), `${label} must not be the identity`);
  return result;
}
function generator(index) {
  if (!generatorCache.has(index)) {
    // Hash-to-curve avoids publicly known discrete-log relations between bases.
    generatorCache.set(index, bls.G1.hashToCurve(encoder.encode(`${DBAC_SUITE}:H:${index}`), { DST: GENERATOR_DST }));
  }
  return generatorCache.get(index);
}
const H0 = generator(0);
function attributeScalar(value, index) {
  return hashScalar(`${DBAC_SUITE}:ATTRIBUTE`, { index, value });
}
function attributesCopy(attributes) {
  requireThat(Array.isArray(attributes) && attributes.length >= 1 && attributes.length <= MAX_ATTRIBUTES,
    'attributes must contain between 1 and 64 strings');
  for (const value of attributes) {
    requireThat(typeof value === 'string' && value.length <= 8192 && value.isWellFormed(), 'attribute must be a well-formed string of at most 8192 code units');
  }
  return [...attributes];
}
function header(value) {
  requireThat(value.version === DBAC_VERSION && value.suite === DBAC_SUITE, 'unsupported DBAC version or suite');
}
function modeCheck(mode) { requireThat(MODES.has(mode), 'unsupported DBAC mode'); }
function pairingEqual(p, q, r, s) {
  return bls.fields.Fp12.eql(bls.pairingBatch([{ g1: p, g2: q }, { g1: r.negate(), g2: s }]), bls.fields.Fp12.ONE);
}
function deviceMessagePoint(randomizedDevicePublicKey, context) {
  return bls.G2.hashToCurve(encoder.encode(canonical({
    version: DBAC_VERSION, suite: DBAC_SUITE, randomizedDevicePublicKey, context,
  })), { DST: SIGNATURE_DST });
}
function indicesCopy(indices, count) {
  requireThat(Array.isArray(indices) && indices.length <= count, 'disclosedIndices must be an array');
  let previous = -1;
  for (const index of indices) {
    requireThat(Number.isSafeInteger(index) && index >= 0 && index < count && index > previous,
      'disclosed indices must be unique, sorted, and in range');
    previous = index;
  }
  return [...indices];
}
function credentialParts(credential) {
  shape(credential, ['version', 'suite', 'issuerPublicKey', 'devicePublicKey', 'attributes', 'signature'], 'credential');
  header(credential);
  shape(credential.signature, ['A', 'e'], 'credential signature');
  const attributes = attributesCopy(credential.attributes);
  const W = parsePoint(credential.issuerPublicKey, G2, 'issuer public key');
  const dpk = parsePoint(credential.devicePublicKey, G1, 'device public key');
  const A = parsePoint(credential.signature.A, G1, 'credential signature A');
  const e = scalar(credential.signature.e, 'credential signature e');
  let C = G1.BASE.add(dpk);
  for (let i = 0; i < attributes.length; i++) C = C.add(mul(generator(i + 1), attributeScalar(attributes[i], i)));
  requireThat(!C.equals(G1.ZERO), 'credential commitment must not be the identity');
  return { W, dpk, A, e, C, attributes };
}

export function generateIssuerKey() {
  const secret = randomScalar(true);
  return { secretKey: scalarHex(secret), publicKey: pointHex(mul(G2.BASE, secret)) };
}
export function generateDeviceKey() {
  const secret = randomScalar(true);
  return { secretKey: scalarHex(secret), publicKey: pointHex(mul(H0, secret)) };
}

/** Enrollment must separately authenticate the device and check key possession. */
export function issueCredential({ issuerSecretKey, devicePublicKey, attributes }) {
  const x = scalar(issuerSecretKey, 'issuer secret key', true);
  const dpk = parsePoint(devicePublicKey, G1, 'device public key');
  const values = attributesCopy(attributes);
  let C = G1.BASE.add(dpk);
  for (let i = 0; i < values.length; i++) C = C.add(mul(generator(i + 1), attributeScalar(values[i], i)));
  requireThat(!C.equals(G1.ZERO), 'credential commitment must not be the identity');
  let e;
  do { e = randomScalar(); } while (mod(x + e) === 0n);
  const A = mul(C, bls.fields.Fr.inv(mod(x + e)));
  return {
    version: DBAC_VERSION, suite: DBAC_SUITE,
    issuerPublicKey: pointHex(mul(G2.BASE, x)), devicePublicKey,
    attributes: values, signature: { A: pointHex(A), e: scalarHex(e) },
  };
}

export function verifyCredential(credential, { issuerPublicKey } = {}) {
  const { W, A, e, C } = credentialParts(credential);
  parsePoint(issuerPublicKey, G2, 'trusted issuer public key');
  requireThat(credential.issuerPublicKey === issuerPublicKey, 'credential issuer is not trusted', 'DBAC_UNTRUSTED_ISSUER');
  const verificationKey = W.add(mul(G2.BASE, e));
  requireThat(!verificationKey.equals(G2.ZERO) && pairingEqual(A, verificationKey, C, G2.BASE),
    'BBS credential signature is invalid', 'DBAC_INVALID_CREDENTIAL');
  return true;
}

// Reuse only the randomized device pseudonym for one payment's three phases.
// Every device request, blinding factor and NIZK commitment remains fresh.
// The private randomizer is never placed in the handle or serialized output.
export function createPaymentBinding({ credential, mode, orderId }) {
  modeCheck(mode);
  requireThat(typeof orderId === 'string' && orderId.length > 0 && orderId.length <= 256 && orderId.trim() === orderId, 'payment orderId is invalid', 'DBAC_PAYMENT_BINDING_INVALID');
  verifyCredential(credential, { issuerPublicKey: credential.issuerPublicKey });
  requireThat(credential.attributes[1] === 'payments:pay' && credential.attributes[3] === mode, 'payment binding requires a credential for this payment mode', 'DBAC_PAYMENT_BINDING_INVALID');
  const { dpk } = credentialParts(credential);
  let k, randomized;
  do { k = randomScalar(); randomized = dpk.add(mul(H0, k)); } while (randomized.equals(G1.ZERO));
  const handle = Object.freeze({});
  paymentBindings.set(handle, { credential: canonical(credential), mode, orderId, k, randomizedDevicePublicKey: pointHex(randomized) });
  return handle;
}

export function preparePresentation({ credential, context, disclosedIndices = [], mode = 'bbs-bls', paymentBinding }) {
  modeCheck(mode);
  object(credential, 'credential');
  verifyCredential(credential, { issuerPublicKey: credential.issuerPublicKey });
  const { dpk, A, e, C, attributes } = credentialParts(credential);
  const safeContext = contextCopy(context);
  const disclosed = indicesCopy(disclosedIndices, attributes.length);
  let k, randomizedDevicePublicKey;
  if (paymentBinding !== undefined) {
    const bound = paymentBindings.get(paymentBinding);
    requireThat(bound && bound.credential === canonical(credential) && bound.mode === mode && safeContext.paymentOrderId === bound.orderId &&
      safeContext.purpose === 'dbac-payment-v1' && safeContext.scope === 'payments:pay' && typeof safeContext.bodyHash === 'string' && /^[A-Za-z0-9_-]{43}$/.test(safeContext.bodyHash),
    'payment binding does not match the credential, mode, order or request context', 'DBAC_PAYMENT_BINDING_MISMATCH');
    k = bound.k; randomizedDevicePublicKey = bound.randomizedDevicePublicKey;
  } else {
    let randomized;
    do { k = randomScalar(); randomized = dpk.add(mul(H0, k)); } while (randomized.equals(G1.ZERO));
    randomizedDevicePublicKey = pointHex(randomized);
  }
  const Q = deviceMessagePoint(randomizedDevicePublicKey, safeContext);
  const blind = mode === 'bbs-blind-bls' ? randomScalar(true) : 1n;
  const request = mode === 'bbs-blind-bls'
    ? { version: DBAC_VERSION, suite: DBAC_SUITE, mode, blindedPoint: pointHex(mul(Q, blind)) }
    : { version: DBAC_VERSION, suite: DBAC_SUITE, mode, randomizedDevicePublicKey, context: safeContext };
  const state = Object.freeze({});
  states.set(state, { mode, issuerPublicKey: credential.issuerPublicKey, dpk, A, e, C, attributes,
    context: contextCopy(safeContext), disclosed, k, randomizedDevicePublicKey, Q, blind });
  return { state, request };
}

function requestPoint(request) {
  object(request, 'device request');
  header(request);
  modeCheck(request.mode);
  let Q;
  if (request.mode === 'bbs-blind-bls') {
    shape(request, ['version', 'suite', 'mode', 'blindedPoint'], 'blind device request');
    Q = parsePoint(request.blindedPoint, G2, 'blinded message');
  } else {
    shape(request, ['version', 'suite', 'mode', 'randomizedDevicePublicKey', 'context'], 'device request');
    parsePoint(request.randomizedDevicePublicKey, G1, 'randomized device public key');
    Q = deviceMessagePoint(request.randomizedDevicePublicKey, contextCopy(request.context));
  }
  return Q;
}

export function signDeviceRequest({ deviceSecretKey, request }) {
  const secret = scalar(deviceSecretKey, 'device secret key', true);
  const Q = requestPoint(request);
  return { version: DBAC_VERSION, suite: DBAC_SUITE, mode: request.mode, signature: pointHex(mul(Q, secret)) };
}

/**
 * Verify a device contribution under its original public key. An issuer can use
 * a fresh, enrollment-specific normal request to check key possession before
 * issuance. Authentication, authorization, nonce consumption, and hardware
 * attestation remain the caller's responsibilities.
 */
export function verifyDeviceResponse({ devicePublicKey, request, response }) {
  const dpk = parsePoint(devicePublicKey, G1, 'device public key');
  const Q = requestPoint(request);
  shape(response, ['version', 'suite', 'mode', 'signature'], 'device response');
  header(response);
  requireThat(response.mode === request.mode, 'device response mode differs from request');
  const sig = parsePoint(response.signature, G2, 'device signature');
  requireThat(pairingEqual(H0, sig, dpk, Q), 'device response is not signed by the expected device', 'DBAC_DEVICE_SIGNATURE_INVALID');
  return true;
}

function challengeInput(presentation, issuerPublicKey, context, T1, T2) {
  // The suite fixes all generators, hashes, and encodings. The statement includes
  // every public variable from Fig. 5 and footnote 4, plus protocol metadata.
  return {
    version: DBAC_VERSION, suite: DBAC_SUITE, mode: presentation.mode,
    issuerPublicKey, attributeCount: presentation.attributeCount,
    disclosed: presentation.disclosed, context,
    randomizedDevicePublicKey: presentation.randomizedDevicePublicKey,
    deviceSignature: presentation.deviceSignature,
    Abar: presentation.Abar, Bbar: presentation.Bbar, Cbar: presentation.Cbar,
    T1: pointHex(T1), T2: pointHex(T2),
  };
}
function challenge(presentation, issuerPublicKey, context, T1, T2) {
  return hashScalar(`${DBAC_SUITE}:NIZK`, challengeInput(presentation, issuerPublicKey, context, T1, T2));
}

export function finalizePresentation({ state, response }) {
  requireThat(state && typeof state === 'object' && states.has(state), 'presentation state is unknown or already consumed', 'DBAC_INVALID_STATE');
  const data = states.get(state);
  states.delete(state); // A response failure also consumes the one-use session.
  shape(response, ['version', 'suite', 'mode', 'signature'], 'device response');
  header(response);
  requireThat(response.mode === data.mode, 'device response mode differs from request');
  let sig = parsePoint(response.signature, G2, 'device signature');
  if (data.mode === 'bbs-blind-bls') sig = mul(sig, bls.fields.Fr.inv(data.blind));
  // Essential to Unlink-2: reject every non-unique/incorrect device output
  // before it can be adapted and forwarded to the verifier.
  requireThat(pairingEqual(H0, sig, data.dpk, data.Q), 'device response is not signed by the credential-bound device', 'DBAC_DEVICE_SIGNATURE_INVALID');
  const adaptedSignature = sig.add(mul(data.Q, data.k));
  const r1 = randomScalar(true), r2 = randomScalar(true);
  const inverseR1 = bls.fields.Fr.inv(r1);
  const Cbar = mul(data.C, r1);
  const Abar = mul(data.A, mod(r1 * r2));
  const Bbar = mul(Cbar, r2).subtract(mul(Abar, data.e));
  const disclosedSet = new Set(data.disclosed);
  const hidden = data.attributes.map((value, index) => ({ index, value }))
    .filter(({ index }) => !disclosedSet.has(index));
  const tw = randomScalar(), tk = randomScalar(), tr = randomScalar(), te = randomScalar();
  const masks = hidden.map(() => randomScalar());
  let T1 = mul(Cbar, tw).add(mul(H0, tk));
  for (let i = 0; i < hidden.length; i++) T1 = T1.subtract(mul(generator(hidden[i].index + 1), masks[i]));
  const T2 = mul(Cbar, tr).subtract(mul(Abar, te));
  const presentation = {
    version: DBAC_VERSION, suite: DBAC_SUITE, mode: data.mode,
    attributeCount: data.attributes.length,
    disclosed: data.disclosed.map(index => ({ index, value: data.attributes[index] })),
    randomizedDevicePublicKey: data.randomizedDevicePublicKey,
    deviceSignature: pointHex(adaptedSignature),
    Abar: pointHex(Abar), Bbar: pointHex(Bbar), Cbar: pointHex(Cbar),
  };
  const c = challenge(presentation, data.issuerPublicKey, data.context, T1, T2);
  presentation.proof = { challenge: scalarHex(c), responses: {
    inverseR1: scalarHex(tw + c * inverseR1), keyRandomizer: scalarHex(tk + c * data.k),
    hidden: hidden.map(({ index, value }, i) => ({ index, response: scalarHex(masks[i] + c * attributeScalar(value, index)) })),
    r2: scalarHex(tr + c * r2), e: scalarHex(te + c * data.e),
  } };
  return presentation;
}

export function verifyPresentation({ presentation, issuerPublicKey, context, requiredDisclosures = {}, trace, deviceFirst = false }) {
  trace?.start('proof_structure');
  trace?.record?.('proof_structure', { label: 'version / suite / mode', expected: [DBAC_VERSION, DBAC_SUITE, publicTraceValue(context?.mode)], observed: [presentation?.version, presentation?.suite, presentation?.mode].map(publicTraceValue) });
  shape(presentation, ['version', 'suite', 'mode', 'attributeCount', 'disclosed', 'randomizedDevicePublicKey',
    'deviceSignature', 'Abar', 'Bbar', 'Cbar', 'proof'], 'presentation');
  header(presentation);
  modeCheck(presentation.mode);
  const count = presentation.attributeCount;
  requireThat(Number.isSafeInteger(count) && count >= 1 && count <= MAX_ATTRIBUTES, 'invalid attribute count');
  requireThat(Array.isArray(presentation.disclosed), 'disclosed attributes must be an array');
  for (const entry of presentation.disclosed) {
    shape(entry, ['index', 'value'], 'disclosed attribute');
    attributesCopy([entry.value]);
  }
  const disclosedIndices = indicesCopy(presentation.disclosed.map(entry => entry.index), count);
  const disclosedSet = new Set(disclosedIndices);
  const hiddenIndices = Array.from({ length: count }, (_, index) => index).filter(index => !disclosedSet.has(index));
  trace?.pass('proof_structure');
  trace?.start('disclosure');
  object(requiredDisclosures, 'requiredDisclosures');
  const requiredEntries = Object.entries(requiredDisclosures);
  // Only values the verifier requires to be publicly disclosed are recorded.
  // Never record hidden attributes or their proof responses here.
  trace?.record?.('disclosure', { label: 'required disclosures (index=value)', expected: requiredEntries.slice(0, 12).map(([index, value]) => `${index}=${value}`), observed: requiredEntries.slice(0, 12).map(([index]) => `${index}=${presentation.disclosed.find(entry => entry.index === Number(index))?.value ?? '(missing)'}`) });
  for (const [index, expected] of requiredEntries) {
    requireThat(/^(0|[1-9][0-9]*)$/.test(index) && Number(index) < count && typeof expected === 'string', 'invalid required disclosure');
    const entry = presentation.disclosed.find(value => value.index === Number(index));
    requireThat(entry && entry.value === expected, `required attribute ${index} was not disclosed with the expected value`, 'DBAC_POLICY_REJECTED');
  }
  trace?.pass('disclosure');
  trace?.start('proof_encoding');
  trace?.record?.('proof_encoding', { label: 'Abar / Bbar / Cbar (G1)', observed: [presentation.Abar, presentation.Bbar, presentation.Cbar].map(publicTraceValue) });
  trace?.record?.('proof_encoding', { label: 'randomized key (G1) / pi_se (G2)', observed: [presentation.randomizedDevicePublicKey, presentation.deviceSignature].map(publicTraceValue) });
  const safeContext = contextCopy(context);
  const W = parsePoint(issuerPublicKey, G2, 'trusted issuer public key');
  const randomized = parsePoint(presentation.randomizedDevicePublicKey, G1, 'randomized device public key');
  const signature = parsePoint(presentation.deviceSignature, G2, 'adapted device signature');
  const Abar = parsePoint(presentation.Abar, G1, 'Abar');
  const Bbar = parsePoint(presentation.Bbar, G1, 'Bbar');
  const Cbar = parsePoint(presentation.Cbar, G1, 'Cbar');
  shape(presentation.proof, ['challenge', 'responses'], 'NIZK proof');
  const c = scalar(presentation.proof.challenge, 'proof challenge');
  const responses = presentation.proof.responses;
  shape(responses, ['inverseR1', 'keyRandomizer', 'hidden', 'r2', 'e'], 'NIZK responses');
  const zw = scalar(responses.inverseR1, 'inverseR1 response');
  const zk = scalar(responses.keyRandomizer, 'keyRandomizer response');
  const zr = scalar(responses.r2, 'r2 response');
  const ze = scalar(responses.e, 'e response');
  requireThat(Array.isArray(responses.hidden) && responses.hidden.length === hiddenIndices.length,
    'hidden responses must exactly cover undisclosed attributes');
  const hiddenResponses = responses.hidden.map((entry, i) => {
    shape(entry, ['index', 'response'], 'hidden response');
    requireThat(entry.index === hiddenIndices[i], 'hidden response index is missing, duplicated, or out of order');
    return scalar(entry.response, 'hidden attribute response');
  });
  trace?.pass('proof_encoding');
  // The joint-holder application evaluates the same independent pairing first
  // so an encoding-valid device fault is attributed to its actual check. The
  // legacy paper profile preserves its historical evaluation order.
  const verifyDevicePairing = () => {
    trace?.start('device_pairing');
    const Q = deviceMessagePoint(presentation.randomizedDevicePublicKey, safeContext);
    const devicePairingValid = pairingEqual(H0, signature, randomized, Q);
    trace?.record?.('device_pairing', { label: 'hash-to-curve point Q (G2)', observed: pointHex(Q) });
    trace?.record?.('device_pairing', { label: 'e(H0,pi_se) = e(randomizedKey,Q)', expected: true, observed: devicePairingValid, match: devicePairingValid });
    requireThat(devicePairingValid, 'adapted device signature is invalid', 'DBAC_DEVICE_SIGNATURE_INVALID');
    trace?.pass('device_pairing');
  };
  if (deviceFirst) verifyDevicePairing();
  trace?.start('knowledge');
  let Y = G1.BASE.add(randomized);
  for (const { index, value } of presentation.disclosed) Y = Y.add(mul(generator(index + 1), attributeScalar(value, index)));
  // Reconstruct commitments R = M z - c Y (Appendix F.1, page 46).
  let T1 = mul(Cbar, zw).add(mul(H0, zk)).subtract(mul(Y, c));
  for (let i = 0; i < hiddenIndices.length; i++) T1 = T1.subtract(mul(generator(hiddenIndices[i] + 1), hiddenResponses[i]));
  const T2 = mul(Cbar, zr).subtract(mul(Abar, ze)).subtract(mul(Bbar, c));
  const reconstructedChallenge = challenge(presentation, issuerPublicKey, safeContext, T1, T2);
  trace?.record?.('knowledge', { label: 'Fiat-Shamir challenge', expected: scalarHex(reconstructedChallenge), observed: scalarHex(c), match: reconstructedChallenge === c });
  trace?.record?.('knowledge', { label: 'reconstructed T1 / T2 (G1)', observed: [pointHex(T1), pointHex(T2)] });
  requireThat(reconstructedChallenge === c,
    'BBS linear-relation proof or bound context is invalid', 'DBAC_PROOF_INVALID');
  trace?.pass('knowledge');
  trace?.start('credential_pairing');
  trace?.record?.('credential_pairing', { label: 'issuer public key W (G2)', observed: issuerPublicKey });
  const credentialPairingValid = pairingEqual(Abar, W, Bbar, G2.BASE);
  trace?.record?.('credential_pairing', { label: 'e(Abar,W) = e(Bbar,G2)', expected: true, observed: credentialPairingValid, match: credentialPairingValid });
  requireThat(credentialPairingValid, 'randomized BBS signature is invalid', 'DBAC_INVALID_CREDENTIAL');
  trace?.pass('credential_pairing');
  if (!deviceFirst) verifyDevicePairing();
  return { valid: true, mode: presentation.mode, attributeCount: count,
    disclosed: presentation.disclosed.map(({ index, value }) => ({ index, value })) };
}
