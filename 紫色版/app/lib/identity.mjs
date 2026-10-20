import {
  createPublicKey,
  ECDH,
  generateKeyPairSync,
  KeyObject,
  randomUUID,
  sign,
  verify,
} from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';

export const VC_TYP = 'vc+jwt';
export const MAX_CREDENTIAL_LIFETIME_MS = 24 * 60 * 60 * 1000;
const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const NAMESPACE = 'https://example.org/a2a-did-vc#';
const LEGACY_TERMS = {
  '@protected': true,
  AgentCapabilityCredential: `${NAMESPACE}AgentCapabilityCredential`,
  audience: { '@id': `${NAMESPACE}audience`, '@type': '@id' },
  scopes: { '@id': `${NAMESPACE}scopes`, '@container': '@set' },
};
const TERMS = {
  ...LEGACY_TERMS,
  deviceDid: { '@id': `${NAMESPACE}deviceDid`, '@type': '@id' },
};
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_INDEX = new Map([...BASE58].map((char, index) => [char, BigInt(index)]));
const MAX_JWS_LENGTH = 32768;

export class IdentityError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'IdentityError';
    this.code = code;
  }
}

function reject(code, message) { throw new IdentityError(code, message); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exactKeys(value, expected) {
  return object(value) && isDeepStrictEqual(Object.keys(value).sort(), [...expected].sort());
}
function absoluteUri(value) {
  return typeof value === 'string' && value.length <= 2048 && /^[a-z][a-z0-9+.-]*:[^\s]+$/i.test(value);
}
function scopeValue(value) { return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/.test(value); }

function base58Encode(bytes) {
  let number = BigInt(`0x${bytes.toString('hex') || '0'}`);
  let encoded = '';
  while (number > 0n) {
    encoded = BASE58[Number(number % 58n)] + encoded;
    number /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = `1${encoded}`;
  }
  return encoded;
}

function algorithmForJwk(jwk) { return jwk.crv === 'Ed25519' ? 'EdDSA' : 'ES256'; }

function publicJwkFromPoint(point) {
  const raw = ECDH.convertKey(point, 'prime256v1', undefined, undefined, 'uncompressed');
  return { kty: 'EC', crv: 'P-256', x: raw.subarray(1, 33).toString('base64url'), y: raw.subarray(33, 65).toString('base64url') };
}

function canonicalPublicJwk(value) {
  let jwk = value;
  if (value instanceof KeyObject) {
    if (value.type !== 'public') reject('INVALID_IDENTITY', 'Only public keys may be imported as public identities.');
    jwk = value.export({ format: 'jwk' });
  }
  if (!object(jwk)) reject('INVALID_IDENTITY', 'Expected a public KeyObject or public JWK.');
  const fields = jwk.kty === 'OKP' && jwk.crv === 'Ed25519' ? ['kty', 'crv', 'x'] :
    jwk.kty === 'EC' && jwk.crv === 'P-256' ? ['kty', 'crv', 'x', 'y'] : undefined;
  if (!fields || !exactKeys(jwk, Object.hasOwn(jwk, 'alg') ? [...fields, 'alg'] : fields) ||
      (Object.hasOwn(jwk, 'alg') && jwk.alg !== algorithmForJwk(jwk))) {
    reject('INVALID_IDENTITY', 'Expected an Ed25519 or P-256 public JWK without private material.');
  }
  const coordinates = fields.includes('y') ? ['x', 'y'] : ['x'];
  for (const coordinate of coordinates) {
    const encoded = jwk[coordinate];
    if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(encoded) ||
        Buffer.from(encoded, 'base64url').toString('base64url') !== encoded) {
      reject('INVALID_IDENTITY', 'Public key coordinates must be canonical 32-byte base64url values.');
    }
  }
  const normalized = Object.fromEntries(fields.map(field => [field, jwk[field]]));
  if (jwk.crv === 'P-256') {
    try {
      publicJwkFromPoint(Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]));
    } catch { reject('INVALID_IDENTITY', 'Public key is not a valid point on P-256.'); }
  }
  return normalized;
}

function didPublicJwk(did) {
  if (typeof did !== 'string' || !/^did:key:z[1-9A-HJ-NP-Za-km-z]{40,60}$/.test(did)) {
    reject('INVALID_DID', 'Expected an Ed25519 or P-256 did:key using base58btc.');
  }
  const encoded = did.slice('did:key:z'.length);
  let number = 0n;
  for (const char of encoded) number = number * 58n + B58_INDEX.get(char);
  let hex = number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  let bytes = number === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  const leadingZeros = encoded.match(/^1*/)[0].length;
  if (leadingZeros) bytes = Buffer.concat([Buffer.alloc(leadingZeros), bytes]);
  if (base58Encode(bytes) !== encoded) reject('INVALID_DID', 'DID key encoding is not canonical.');
  if (bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) {
    return { kty: 'OKP', crv: 'Ed25519', x: bytes.subarray(2).toString('base64url') };
  }
  // p256-pub multicodec 0x1200 is varint 0x80 0x24, followed by
  // the SEC1 compressed point, as required by the did:key method.
  if (bytes.length === 35 && bytes[0] === 0x80 && bytes[1] === 0x24 && [2, 3].includes(bytes[2])) {
    try { return publicJwkFromPoint(bytes.subarray(2)); }
    catch { reject('INVALID_DID', 'DID contains an invalid P-256 point.'); }
  }
  reject('INVALID_DID', 'Only canonical ed25519-pub and compressed p256-pub did:key identifiers are supported.');
}

export function keyId(did) {
  didPublicJwk(did);
  return `${did}#${did.slice('did:key:'.length)}`;
}

// This resolver selects the JsonWebKey representation for the JOSE profile.
// It resolves only immutable, self-certifying Ed25519 and P-256 did:key keys.
export function resolveDid(did) {
  const publicKeyJwk = didPublicJwk(did);
  const kid = keyId(did);
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/jwk/v1'],
    id: did,
    verificationMethod: [{
      id: kid,
      type: 'JsonWebKey',
      controller: did,
      publicKeyJwk,
    }],
    authentication: [kid],
    assertionMethod: [kid],
  };
}

export function identityFromPublicKey(publicKey, name = 'device') {
  if (typeof name !== 'string' || !name.trim() || name.length > 100) {
    reject('INVALID_IDENTITY', 'Identity name must be a nonempty string of at most 100 characters.');
  }
  const publicJwk = canonicalPublicJwk(publicKey);
  const isEd25519 = publicJwk.crv === 'Ed25519';
  const point = isEd25519 ? Buffer.from(publicJwk.x, 'base64url') : ECDH.convertKey(
    Buffer.concat([Buffer.from([4]), Buffer.from(publicJwk.x, 'base64url'), Buffer.from(publicJwk.y, 'base64url')]),
    'prime256v1', undefined, undefined, 'compressed',
  );
  const did = `did:key:z${base58Encode(Buffer.concat([Buffer.from(isEd25519 ? [0xed, 0x01] : [0x80, 0x24]), point]))}`;
  return {
    name, did, kid: keyId(did), alg: algorithmForJwk(publicJwk), publicJwk,
    publicKey: createPublicKey({ key: publicJwk, format: 'jwk' }), didDocument: resolveDid(did),
  };
}

export function generateIdentity(name = 'agent') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { ...identityFromPublicKey(publicKey, name), privateKey };
}

function decodeSegment(segment) {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) reject('MALFORMED_JWS', 'JWS segments must be unpadded base64url.');
  const decoded = Buffer.from(segment, 'base64url');
  if (decoded.toString('base64url') !== segment) reject('MALFORMED_JWS', 'JWS base64url encoding is not canonical.');
  return decoded;
}

// JSON.parse accepts duplicate names. Reject them before parsing so different
// verifiers cannot interpret a signed header or authorization field differently.
function parseUniqueJson(bytes) {
  try {
    const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    let offset = 0;
    const skip = () => { while (/[\x20\t\r\n]/.test(source[offset] ?? '') && offset < source.length) offset++; };
    function string() {
      const match = /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[\da-fA-F]{4}))*"/.exec(source.slice(offset));
      if (!match) throw new Error('Invalid string');
      offset += match[0].length;
      return JSON.parse(match[0]);
    }
    function value(depth = 0) {
      if (depth > 32) throw new Error('Excessive nesting');
      skip();
      const char = source[offset];
      if (char === '"') { string(); return; }
      if (char === '{' || char === '[') {
        const closing = char === '{' ? '}' : ']';
        const names = new Set();
        offset++;
        skip();
        if (source[offset] === closing) { offset++; return; }
        while (offset < source.length) {
          skip();
          if (char === '{') {
            const name = string();
            if (names.has(name)) throw new Error('Duplicate JSON name');
            names.add(name);
            skip();
            if (source[offset++] !== ':') throw new Error('Missing colon');
          }
          value(depth + 1);
          skip();
          const separator = source[offset++];
          if (separator === closing) return;
          if (separator !== ',') throw new Error('Missing comma');
        }
        throw new Error('Unclosed object or array');
      }
      const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(source.slice(offset));
      if (!match) throw new Error('Invalid JSON value');
      offset += match[0].length;
    }
    value();
    skip();
    if (offset !== source.length) throw new Error('Trailing JSON data');
    const parsed = JSON.parse(source);
    if (!object(parsed)) throw new Error('Expected JSON object');
    return parsed;
  } catch {
    reject('MALFORMED_JWS', 'JWS JSON must be a UTF-8 object without duplicate property names.');
  }
}

function checkType(typ) {
  if (typeof typ !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+/-]{0,99}$/.test(typ)) {
    reject('UNEXPECTED_TOKEN_TYPE', 'An explicit token media type is required.');
  }
}

function signingInput(payload, identity, typ) {
  checkType(typ);
  if (!object(payload) || !object(identity)) {
    reject('INVALID_IDENTITY', 'Expected an object payload and a signing identity.');
  }
  const kid = keyId(identity.did);
  const publicJwk = didPublicJwk(identity.did);
  const alg = algorithmForJwk(publicJwk);
  if ((identity.kid !== undefined && identity.kid !== kid) || (identity.alg !== undefined && identity.alg !== alg) ||
      (identity.publicKey !== undefined && !isDeepStrictEqual(canonicalPublicJwk(identity.publicKey), publicJwk)) ||
      (identity.publicJwk !== undefined && !isDeepStrictEqual(canonicalPublicJwk(identity.publicJwk), publicJwk))) {
    reject('INVALID_IDENTITY', 'Signing algorithm, public key, and DID must refer to the same key.');
  }
  const header = { alg, typ, kid };
  // W3C VC-JOSE-COSE Recommendation §3.1.1: unsecured VC is the JWS
  // payload, typ SHOULD be vc+jwt and optional cty SHOULD be vc.
  if (typ === VC_TYP) header.cty = 'vc';
  let encodedPayload;
  try { encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url'); }
  catch { reject('MALFORMED_JWS', 'Payload is not JSON serializable.'); }
  const input = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${encodedPayload}`;
  if (input.length + 87 > MAX_JWS_LENGTH) reject('MALFORMED_JWS', 'JWS exceeds the profile size limit.');
  return { input: Buffer.from(input, 'ascii'), alg, publicJwk, kid, did: identity.did };
}

function validSignature(input, signature, publicJwk) {
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
  const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' });
  return publicJwk.crv === 'Ed25519' ? verify(null, input, publicKey, signature) :
    verify('sha256', input, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
}

export function signJws(payload, identity, typ) {
  const prepared = signingInput(payload, identity, typ);
  if (!(identity.privateKey instanceof KeyObject) || identity.privateKey.type !== 'private' ||
      !isDeepStrictEqual(canonicalPublicJwk(createPublicKey(identity.privateKey)), prepared.publicJwk)) {
    reject('INVALID_IDENTITY', 'Private signing key and DID must refer to the same key.');
  }
  const signature = prepared.alg === 'EdDSA' ? sign(null, prepared.input, identity.privateKey) :
    sign('sha256', prepared.input, { key: identity.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${prepared.input.toString('ascii')}.${signature.toString('base64url')}`;
}

// The signer receives the original JWS signing input, never a precomputed hash.
// ES256 devices must hash with SHA-256 and return the 64-byte JOSE r || s form.
// No device key generation or private-key fallback takes place in this API.
export async function signJwsWithSigner(payload, identity, typ, signer) {
  const prepared = signingInput(payload, identity, typ);
  if (typeof signer !== 'function') reject('INVALID_IDENTITY', 'An external signing function is required.');
  const signature = await signer(Buffer.from(prepared.input), { alg: prepared.alg, did: prepared.did, kid: prepared.kid });
  if (!validSignature(prepared.input, signature, prepared.publicJwk)) {
    reject('INVALID_SIGNATURE', 'External signer did not return a valid 64-byte signature for this DID.');
  }
  return `${prepared.input.toString('ascii')}.${Buffer.from(signature).toString('base64url')}`;
}

export function verifyJws(token, { typ, purpose = 'authentication', expectedDid } = {}) {
  checkType(typ);
  if (!['authentication', 'assertionMethod'].includes(purpose)) {
    reject('UNSUPPORTED_KEY_PURPOSE', 'Only authentication and assertionMethod are supported.');
  }
  if (typeof token !== 'string' || token.length > MAX_JWS_LENGTH) reject('MALFORMED_JWS', 'Invalid compact JWS size or type.');
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0].length > 2048) reject('MALFORMED_JWS', 'Expected three compact JWS segments.');
  const [headerBytes, payloadBytes, signature] = parts.map(decodeSegment);
  const header = parseUniqueJson(headerBytes);
  if (!['EdDSA', 'ES256'].includes(header.alg)) reject('UNSUPPORTED_ALGORITHM', 'Only Ed25519/EdDSA and P-256/ES256 are supported.');
  if (header.typ !== typ) reject('UNEXPECTED_TOKEN_TYPE', 'Token type does not match the expected protocol step.');
  const allowedHeaders = typ === VC_TYP ? ['alg', 'typ', 'kid', 'cty'] : ['alg', 'typ', 'kid'];
  if (!exactKeys(header, allowedHeaders) || (typ === VC_TYP && header.cty !== 'vc')) {
    reject('MALFORMED_JWS', 'Unsupported protected header or content type.');
  }
  if (typeof header.kid !== 'string' || header.kid.split('#').length !== 2) reject('INVALID_KEY_ID', 'kid must identify the did:key verification method.');
  const signerDid = header.kid.split('#')[0];
  let document;
  try { document = resolveDid(signerDid); }
  catch { reject('INVALID_KEY_ID', 'kid does not contain a supported canonical DID.'); }
  const publicJwk = document.verificationMethod[0].publicKeyJwk;
  if (header.alg !== algorithmForJwk(publicJwk)) reject('UNSUPPORTED_ALGORITHM', 'JWS algorithm does not match the DID key type.');
  if (!document[purpose].includes(header.kid)) reject('INVALID_KEY_ID', 'kid is not authorized for the requested verification relationship.');
  if (expectedDid !== undefined && signerDid !== expectedDid) reject('SIGNER_MISMATCH', 'Signer differs from the expected DID.');
  if (!validSignature(Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), signature, publicJwk)) reject('INVALID_SIGNATURE', 'JWS signature verification failed; this profile requires a 64-byte signature.');
  return { payload: parseUniqueJson(payloadBytes), signerDid, header };
}

function credentialDate(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    reject('INVALID_CREDENTIAL', 'Credential dates must be UTC ISO 8601 timestamps.');
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString().replace('.000Z', 'Z') !== value.replace('.000Z', 'Z')) {
    reject('INVALID_CREDENTIAL', 'Credential contains an invalid calendar date.');
  }
  return timestamp;
}

function normalizeDate(value) {
  if (typeof value === 'string') { credentialDate(value); return new Date(value).toISOString(); }
  const timestamp = value instanceof Date ? value.getTime() : value;
  if (!Number.isSafeInteger(timestamp) || timestamp < 0 || timestamp > 253402300799999) {
    reject('INVALID_CREDENTIAL', 'Credential timestamp must be a valid date or integer milliseconds.');
  }
  return new Date(timestamp).toISOString();
}

function validateCredential(credential) {
  const subject = credential.credentialSubject;
  const hasDevice = object(subject) && Object.hasOwn(subject, 'deviceDid');
  // Older one-signer credentials remain readable by the generic library only.
  // A device claim must use its defined JSON-LD term; network verifiers can
  // require that claim with requireDevice to prevent a profile downgrade.
  const supportedContext = isDeepStrictEqual(credential['@context'], [VC_CONTEXT, TERMS]) ||
    (!hasDevice && isDeepStrictEqual(credential['@context'], [VC_CONTEXT, LEGACY_TERMS]));
  if (!exactKeys(credential, ['@context', 'id', 'type', 'issuer', 'validFrom', 'validUntil', 'credentialSubject']) ||
      !supportedContext ||
      !isDeepStrictEqual(credential.type, ['VerifiableCredential', 'AgentCapabilityCredential']) ||
      !absoluteUri(credential.id)) {
    reject('INVALID_CREDENTIAL', 'Credential does not match the fixed AgentCapabilityCredential profile.');
  }
  try { resolveDid(credential.issuer); }
  catch { reject('INVALID_CREDENTIAL', 'Credential issuer must be a supported did:key.'); }
  const subjectKeys = hasDevice ? ['id', 'audience', 'scopes', 'deviceDid'] : ['id', 'audience', 'scopes'];
  if (!exactKeys(subject, subjectKeys) || !absoluteUri(subject.audience) ||
      !Array.isArray(subject.scopes) || subject.scopes.length === 0 || subject.scopes.length > 32 ||
      subject.scopes.some(scope => !scopeValue(scope)) || new Set(subject.scopes).size !== subject.scopes.length) {
    reject('INVALID_CREDENTIAL', 'Credential subject, audience, or scopes are malformed.');
  }
  try { resolveDid(subject.id); }
  catch { reject('INVALID_CREDENTIAL', 'Credential subject must be a supported did:key.'); }
  if (hasDevice) {
    try { resolveDid(subject.deviceDid); }
    catch { reject('INVALID_CREDENTIAL', 'Credential device must be a supported did:key.'); }
    if (subject.deviceDid === subject.id) {
      reject('INVALID_CREDENTIAL', 'Credential holder and device must use distinct signing identities.');
    }
  }
  const from = credentialDate(credential.validFrom);
  const until = credentialDate(credential.validUntil);
  if (until <= from || until - from > MAX_CREDENTIAL_LIFETIME_MS) {
    reject('INVALID_CREDENTIAL', 'Credential validity must be positive and at most 24 hours in this profile.');
  }
  return { from, until };
}

export function issueCredential(issuer, {
  subjectDid,
  audience,
  scopes,
  deviceDid,
  validFrom = Date.now(),
  validUntil,
  id = `urn:uuid:${randomUUID()}`,
} = {}) {
  const from = normalizeDate(validFrom);
  const credential = {
    '@context': [VC_CONTEXT, structuredClone(TERMS)],
    id,
    type: ['VerifiableCredential', 'AgentCapabilityCredential'],
    issuer: issuer?.did,
    validFrom: from,
    validUntil: normalizeDate(validUntil === undefined ? Date.parse(from) + 60 * 60 * 1000 : validUntil),
    credentialSubject: { id: subjectDid, audience, scopes, ...(deviceDid === undefined ? {} : { deviceDid }) },
  };
  validateCredential(credential);
  return signJws(credential, issuer, VC_TYP);
}

function collection(value) { return value instanceof Set || Array.isArray(value); }
function contains(values, value) { return values instanceof Set ? values.has(value) : values.includes(value); }

export function verifyCredential(token, {
  trustedIssuers,
  subjectDid,
  audience,
  scope,
  revokedIds = new Set(),
  now = Date.now(),
  requireDevice = false,
} = {}) {
  const timestamp = now instanceof Date ? now.getTime() : now;
  if (!collection(trustedIssuers) || !collection(revokedIds) || !absoluteUri(audience) || !scopeValue(scope) || typeof requireDevice !== 'boolean' ||
      !Number.isSafeInteger(timestamp) || timestamp < 0 || timestamp > 253402300799999) {
    reject('INVALID_POLICY', 'Verifier requires trusted issuers, expected subject/audience/scope, and valid current time.');
  }
  try { resolveDid(subjectDid); }
  catch { reject('INVALID_POLICY', 'Verifier requires an expected supported did:key subject.'); }
  const { payload: credential, signerDid } = verifyJws(token, { typ: VC_TYP, purpose: 'assertionMethod' });
  const { from, until } = validateCredential(credential);
  if (credential.issuer !== signerDid) reject('CREDENTIAL_ISSUER_MISMATCH', 'Credential issuer does not control the signing verification method.');
  if (!contains(trustedIssuers, credential.issuer)) reject('CREDENTIAL_UNTRUSTED_ISSUER', 'Credential issuer is not trusted by this service.');
  if (timestamp < from) reject('CREDENTIAL_NOT_YET_VALID', 'Credential validity has not begun.');
  if (timestamp >= until) reject('CREDENTIAL_EXPIRED', 'Credential validity has ended.');
  if (credential.credentialSubject.id !== subjectDid) reject('CREDENTIAL_SUBJECT_MISMATCH', 'Credential does not belong to the requesting DID.');
  if (requireDevice && !Object.hasOwn(credential.credentialSubject, 'deviceDid')) {
    reject('CREDENTIAL_DEVICE_REQUIRED', 'This verifier requires a credential bound to a distinct device DID.');
  }
  if (credential.credentialSubject.audience !== audience) reject('CREDENTIAL_AUDIENCE_MISMATCH', 'Credential is intended for a different service.');
  if (!credential.credentialSubject.scopes.includes(scope)) reject('CREDENTIAL_SCOPE_DENIED', 'Credential does not grant the required scope.');
  if (contains(revokedIds, credential.id)) reject('CREDENTIAL_REVOKED', 'Credential identifier has been revoked by this service.');
  return credential;
}
