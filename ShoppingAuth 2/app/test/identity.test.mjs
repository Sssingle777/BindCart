import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, ECDH, generateKeyPairSync, sign, verify } from 'node:crypto';
import test from 'node:test';
import {
  generateIdentity,
  identityFromPublicKey,
  resolveDid,
  keyId,
  signJws,
  signJwsWithSigner,
  verifyJws,
  issueCredential,
  verifyCredential,
  MAX_CREDENTIAL_LIFETIME_MS,
  VC_TYP,
} from '../lib/identity.mjs';

const issuer = generateIdentity('issuer');
const holder = generateIdentity('holder');
const outsider = generateIdentity('outsider');
const device = generateIdentity('device');
// Software keys are fixtures for JOSE interoperability tests only. The running
// device path imports only the public key and delegates signing to jCardSim.
const p256Keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const p256Device = identityFromPublicKey(p256Keys.publicKey, 'P-256 test device');
const otherP256Keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const NOW = Date.parse('2026-10-02T00:00:00.000Z');
const AUDIENCE = 'https://agent-b.example/a2a';
const POP_TYP = 'a2a-did-pop+jwt';
const issueOptions = {
  subjectDid: holder.did,
  audience: AUDIENCE,
  scopes: ['message:send', 'tasks:get'],
  validFrom: NOW - 1000,
  validUntil: NOW + 60000,
};
const policy = { trustedIssuers: [issuer.did], subjectDid: holder.did, audience: AUDIENCE, scope: 'message:send', now: NOW };
const credentialToken = issueCredential(issuer, issueOptions);
const credential = verifyCredential(credentialToken, policy);

function fails(code, action) { assert.throws(action, error => error.code === code, code); }
function rawToken(header, payload, identity = issuer) {
  const encodedHeader = Buffer.from(typeof header === 'string' ? header : JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload)).toString('base64url');
  const input = `${encodedHeader}.${encodedPayload}`;
  return `${input}.${sign(null, Buffer.from(input), identity.privateKey).toString('base64url')}`;
}
function changedCredential(change) {
  const changed = structuredClone(credential);
  change(changed);
  return signJws(changed, issuer, VC_TYP);
}

test('did:key uses the documented Ed25519 test vector and JOSE verification relationship', () => {
  // did:key specification, Test Vectors / Ed25519:
  // https://w3c-ccg.github.io/did-key-spec/#test-vectors
  const did = 'did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP';
  const document = resolveDid(did);
  assert.equal(document.id, did);
  assert.deepEqual(document.authentication, [`${did}#${did.slice(8)}`]);
  assert.deepEqual(document.assertionMethod, document.authentication);
  assert.equal(document.verificationMethod[0].type, 'JsonWebKey');
  assert.equal(document.verificationMethod[0].publicKeyJwk.crv, 'Ed25519');
  assert.equal(Buffer.from(document.verificationMethod[0].publicKeyJwk.x, 'base64url').length, 32);
  assert.equal(createPublicKey({ key: document.verificationMethod[0].publicKeyJwk, format: 'jwk' }).asymmetricKeyType, 'ed25519');
});

test('random identities preserve standard ed25519-pub encoding and export no private key in DID document', () => {
  assert.notEqual(issuer.did, holder.did);
  assert.match(issuer.did, /^did:key:z6Mk/);
  assert.equal(issuer.kid, keyId(issuer.did));
  const publicJwk = issuer.didDocument.verificationMethod[0].publicKeyJwk;
  assert.equal(publicJwk.x, issuer.publicKey.export({ format: 'jwk' }).x);
  assert.equal(publicJwk.d, undefined);
  assert.equal(JSON.stringify(issuer.didDocument).includes('PRIVATE'), false);
  fails('INVALID_IDENTITY', () => generateIdentity(''));
});

test('DID resolution rejects alternate methods, DID URLs, legacy base64 and wrong multicodec', () => {
  for (const did of [null, '', 'did:web:agent.example', `${issuer.did}#${issuer.did.slice(8)}`, `${issuer.did}?v=1`, issuer.did + '/', issuer.did.replace('z6Mk', 'z6LS'), `did:key:${issuer.publicKey.export({ format: 'jwk' }).x}`, 'did:key:z' + '1'.repeat(47), issuer.did.replace(/.$/, '0')]) {
    fails('INVALID_DID', () => resolveDid(did));
  }
});

test('JWS verifies original signed bytes and is compatible with native RFC 8037 EdDSA verification', () => {
  const payload = { sub: holder.did, nonce: 'nonce-123', audience: AUDIENCE, nested: { a: [true, null, 1.2e3] } };
  const token = signJws(payload, holder, POP_TYP);
  const result = verifyJws(token, { typ: POP_TYP, expectedDid: holder.did });
  assert.deepEqual(result.payload, payload);
  assert.equal(result.signerDid, holder.did);
  assert.equal(result.header.alg, 'EdDSA');
  assert.equal(verifyJws(token, { typ: POP_TYP, purpose: 'assertionMethod' }).signerDid, holder.did);
  fails('SIGNER_MISMATCH', () => verifyJws(token, { typ: POP_TYP, expectedDid: issuer.did }));
  fails('UNEXPECTED_TOKEN_TYPE', () => verifyJws(token, { typ: 'a2a-did-response+jwt' }));
  fails('UNSUPPORTED_KEY_PURPOSE', () => verifyJws(token, { typ: POP_TYP, purpose: 'capabilityInvocation' }));
  fails('INVALID_IDENTITY', () => signJws({}, { ...holder, privateKey: outsider.privateKey }, POP_TYP));
  fails('INVALID_IDENTITY', () => signJws({}, { ...holder, kid: issuer.kid }, POP_TYP));
  fails('UNEXPECTED_TOKEN_TYPE', () => verifyJws(token));
});

test('JWS rejects malformed encodings and empty, oversized, non-object or duplicate JSON', () => {
  const token = signJws({ ok: true }, holder, POP_TYP);
  const [header, payload, signature] = token.split('.');
  for (const bad of [null, '', 'a.b', 'a.b.c.d', `${header}=.${payload}.${signature}`, `${header}.${payload}=.${signature}`, `${header}.${payload}.+${signature}`, 'x'.repeat(32769)]) {
    fails('MALFORMED_JWS', () => verifyJws(bad, { typ: POP_TYP }));
  }
  for (const source of ['[]', 'null', 'true', '{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"nested":{"a":1,"a":2}}', '{"a":1,}', '{"a":01}', '{"a":1} true']) {
    const bad = rawToken({ alg: 'EdDSA', typ: POP_TYP, kid: issuer.kid }, source);
    fails('MALFORMED_JWS', () => verifyJws(bad, { typ: POP_TYP }));
  }
  const duplicateHeader = rawToken(`{"alg":"EdDSA","alg":"EdDSA","typ":"${POP_TYP}","kid":"${issuer.kid}"}`, {});
  fails('MALFORMED_JWS', () => verifyJws(duplicateHeader, { typ: POP_TYP }));
});

test('JWS refuses unsupported algorithms, key identifiers, crit and unencoded payload options', () => {
  const header = { alg: 'EdDSA', typ: POP_TYP, kid: issuer.kid };
  for (const alg of ['none', 'HS256', 'ES256', 'Ed25519']) {
    fails('UNSUPPORTED_ALGORITHM', () => verifyJws(rawToken({ ...header, alg }, {}), { typ: POP_TYP }));
  }
  for (const kid of [issuer.did, `${issuer.did}#other`, `${issuer.kid}#again`, 'did:web:agent.example#key', '', 1]) {
    fails('INVALID_KEY_ID', () => verifyJws(rawToken({ ...header, kid }, {}), { typ: POP_TYP }));
  }
  for (const extra of [{ crit: ['test'], test: true }, { b64: false }, { jwk: outsider.publicKey.export({ format: 'jwk' }) }, { jku: 'https://attacker.example/keys' }]) {
    fails('MALFORMED_JWS', () => verifyJws(rawToken({ ...header, ...extra }, {}), { typ: POP_TYP }));
  }
});

test('a changed payload, forged signature and truncated signature are rejected', () => {
  const [header, payload, signature] = signJws({ ok: true }, holder, POP_TYP).split('.');
  const changedPayload = Buffer.from('{"ok":false}').toString('base64url');
  fails('INVALID_SIGNATURE', () => verifyJws(`${header}.${changedPayload}.${signature}`, { typ: POP_TYP }));
  const badSignature = Buffer.from(signature, 'base64url');
  badSignature[0] ^= 1;
  fails('INVALID_SIGNATURE', () => verifyJws(`${header}.${payload}.${badSignature.toString('base64url')}`, { typ: POP_TYP }));
  fails('INVALID_SIGNATURE', () => verifyJws(`${header}.${payload}.${badSignature.subarray(1).toString('base64url')}`, { typ: POP_TYP }));
});

test('VC is a direct JSON-LD VC 2.0 payload secured as vc+jwt, without a DataIntegrityProof', () => {
  const result = verifyJws(credentialToken, { typ: VC_TYP, purpose: 'assertionMethod', expectedDid: issuer.did });
  assert.equal(result.header.typ, 'vc+jwt');
  assert.equal(result.header.cty, 'vc');
  assert.equal(result.payload['@context'][0], 'https://www.w3.org/ns/credentials/v2');
  assert.equal(result.payload['@context'][1].audience['@type'], '@id');
  assert.equal(result.payload.proof, undefined);
  assert.equal(result.payload.vc, undefined);
  assert.deepEqual(result.payload.type, ['VerifiableCredential', 'AgentCapabilityCredential']);
  assert.match(credential.id, /^urn:uuid:/);
  assert.deepEqual(verifyCredential(credentialToken, { ...policy, trustedIssuers: new Set([issuer.did]), now: new Date(NOW) }), credential);
});

test('VC verification binds issuer, signer, trusted issuer and requesting subject separately', () => {
  fails('CREDENTIAL_ISSUER_MISMATCH', () => verifyCredential(changedCredential(vc => { vc.issuer = outsider.did; }), policy));
  fails('CREDENTIAL_UNTRUSTED_ISSUER', () => verifyCredential(credentialToken, { ...policy, trustedIssuers: [outsider.did] }));
  fails('CREDENTIAL_SUBJECT_MISMATCH', () => verifyCredential(credentialToken, { ...policy, subjectDid: outsider.did }));
  const stolen = signJws(credential, outsider, VC_TYP);
  fails('CREDENTIAL_ISSUER_MISMATCH', () => verifyCredential(stolen, policy));
});

test('VC verification checks validity at both boundaries and rejects future or expired credentials', () => {
  const from = Date.parse(credential.validFrom);
  const until = Date.parse(credential.validUntil);
  assert.equal(verifyCredential(credentialToken, { ...policy, now: from }).id, credential.id);
  assert.equal(verifyCredential(credentialToken, { ...policy, now: until - 1 }).id, credential.id);
  fails('CREDENTIAL_NOT_YET_VALID', () => verifyCredential(credentialToken, { ...policy, now: from - 1 }));
  fails('CREDENTIAL_EXPIRED', () => verifyCredential(credentialToken, { ...policy, now: until }));
});

test('VC verification enforces audience, required scope and local credential revocation', () => {
  fails('CREDENTIAL_AUDIENCE_MISMATCH', () => verifyCredential(credentialToken, { ...policy, audience: 'https://other.example/a2a' }));
  fails('CREDENTIAL_SCOPE_DENIED', () => verifyCredential(credentialToken, { ...policy, scope: 'payments:pay' }));
  fails('CREDENTIAL_REVOKED', () => verifyCredential(credentialToken, { ...policy, revokedIds: new Set([credential.id]) }));
  fails('CREDENTIAL_REVOKED', () => verifyCredential(credentialToken, { ...policy, revokedIds: [credential.id] }));
});

test('VC validation rejects altered context, unexpected claims and structurally invalid subjects', () => {
  const changes = [
    vc => { vc['@context'][0] = 'https://www.w3.org/2018/credentials/v1'; },
    vc => { vc['@context'][1].audience['@type'] = '@vocab'; },
    vc => { vc.type = ['AgentCapabilityCredential']; },
    vc => { vc.issuer = { id: issuer.did }; },
    vc => { vc.credentialSubject = [vc.credentialSubject]; },
    vc => { vc.credentialSubject.id = 'did:web:holder.example'; },
    vc => { vc.credentialSubject.scopes = 'message:send'; },
    vc => { vc.credentialSubject.scopes = []; },
    vc => { vc.credentialSubject.scopes = ['message:send', 'message:send']; },
    vc => { vc.credentialSubject.scopes = ['bad scope']; },
    vc => { vc.credentialSubject.audience = 'relative/a2a'; },
    vc => { vc.id = ''; },
    vc => { vc.id = 'relative-id'; },
    vc => { vc.proof = { type: 'DataIntegrityProof' }; },
    vc => { vc.iss = outsider.did; },
    vc => { delete vc.validUntil; },
  ];
  for (const change of changes) fails('INVALID_CREDENTIAL', () => verifyCredential(changedCredential(change), policy));
});

test('VC refuses ambiguous dates and validity intervals outside the local profile', () => {
  for (const validUntil of [NOW - 1000, NOW - 2000, NOW + MAX_CREDENTIAL_LIFETIME_MS, NaN, Infinity, true, null]) {
    fails('INVALID_CREDENTIAL', () => issueCredential(issuer, { ...issueOptions, validUntil }));
  }
  for (const value of ['2026-02-31T00:00:00Z', '2026-10-02', '2026-10-02T08:00:00+08:00', '2026-10-02T00:00:00.12Z', 'not a date']) {
    fails('INVALID_CREDENTIAL', () => verifyCredential(changedCredential(vc => { vc.validUntil = value; }), policy));
  }
  const defaultToken = issueCredential(issuer, { subjectDid: holder.did, audience: AUDIENCE, scopes: ['message:send'], validFrom: new Date(NOW) });
  const defaultVc = verifyCredential(defaultToken, policy);
  assert.equal(Date.parse(defaultVc.validUntil) - Date.parse(defaultVc.validFrom), 3600000);
});

test('VC verification cannot silently omit authorization policy or accept invalid current time', () => {
  for (const omitted of ['trustedIssuers', 'subjectDid', 'audience', 'scope']) {
    const incomplete = { ...policy };
    delete incomplete[omitted];
    fails('INVALID_POLICY', () => verifyCredential(credentialToken, incomplete));
  }
  for (const now of [NaN, Infinity, -1, '2026-10-02', new Date('invalid'), true, 0.5]) {
    fails('INVALID_POLICY', () => verifyCredential(credentialToken, { ...policy, now }));
  }
});

test('VC media type prevents a generic holder proof from being interpreted as a credential', () => {
  fails('UNEXPECTED_TOKEN_TYPE', () => verifyCredential(signJws(credential, issuer, POP_TYP), policy));
  const header = { alg: 'EdDSA', typ: VC_TYP, kid: issuer.kid };
  fails('MALFORMED_JWS', () => verifyCredential(rawToken(header, credential), policy));
  fails('MALFORMED_JWS', () => verifyCredential(rawToken({ ...header, cty: 'vc+ld+json' }, credential), policy));
});

test('PKCS8 transfer retains DID identity and works with the same verification API', () => {
  const pem = holder.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateKey = createPrivateKey(pem);
  const reconstructed = { did: holder.did, kid: holder.kid, privateKey, publicKey: createPublicKey(privateKey) };
  const token = signJws({ transfer: true }, reconstructed, POP_TYP);
  assert.deepEqual(verifyJws(token, { typ: POP_TYP, expectedDid: holder.did }).payload, { transfer: true });
});

test('device-bound VC signs a separate device DID together with the holder and capability', () => {
  const token = issueCredential(issuer, { ...issueOptions, deviceDid: device.did });
  const verified = verifyCredential(token, { ...policy, requireDevice: true });
  const signed = verifyJws(token, { typ: VC_TYP, purpose: 'assertionMethod', expectedDid: issuer.did });
  assert.equal(signed.signerDid, issuer.did);
  assert.deepEqual(signed.payload.credentialSubject, {
    id: holder.did,
    audience: AUDIENCE,
    scopes: issueOptions.scopes,
    deviceDid: device.did,
  });
  assert.deepEqual(verified, signed.payload);
  assert.deepEqual(verified['@context'][1].deviceDid, {
    '@id': 'https://example.org/a2a-did-vc#deviceDid',
    '@type': '@id',
  });
  assert.deepEqual(verifyCredential(token, policy), verified);
});

test('replacing a signed device DID invalidates the issuer signature', () => {
  const token = issueCredential(issuer, { ...issueOptions, deviceDid: device.did });
  const [header, encoded, signature] = token.split('.');
  const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  payload.credentialSubject.deviceDid = outsider.did;
  const changed = `${header}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${signature}`;
  fails('INVALID_SIGNATURE', () => verifyCredential(changed, { ...policy, requireDevice: true }));
});

test('a device claim must be a canonical supported did:key distinct from the holder', () => {
  const invalidDevices = [null, '', false, 1, {}, [], 'did:web:device.example', `${device.did}#${device.did.slice(8)}`, `${device.did}?version=1`, device.did.replace('z6Mk', 'z6LS'), holder.did];
  for (const deviceDid of invalidDevices) {
    fails('INVALID_CREDENTIAL', () => issueCredential(issuer, { ...issueOptions, deviceDid }));
    const malformed = changedCredential(vc => { vc.credentialSubject.deviceDid = deviceDid; });
    fails('INVALID_CREDENTIAL', () => verifyCredential(malformed, policy));
    fails('INVALID_CREDENTIAL', () => verifyCredential(malformed, { ...policy, requireDevice: true }));
  }
});

test('requireDevice rejects a missing claim while default policy preserves basic VC compatibility', () => {
  assert.equal(Object.hasOwn(credential.credentialSubject, 'deviceDid'), false);
  assert.deepEqual(verifyCredential(credentialToken, policy), credential);
  assert.deepEqual(verifyCredential(credentialToken, { ...policy, requireDevice: false }), credential);
  fails('CREDENTIAL_DEVICE_REQUIRED', () => verifyCredential(credentialToken, { ...policy, requireDevice: true }));
  const explicitlyOmitted = issueCredential(issuer, { ...issueOptions, deviceDid: undefined });
  assert.equal(Object.hasOwn(verifyCredential(explicitlyOmitted, policy).credentialSubject, 'deviceDid'), false);
});

test('legacy VC context remains readable but cannot provide an undefined device term or downgrade device policy', () => {
  const legacy = changedCredential(vc => { delete vc['@context'][1].deviceDid; });
  assert.equal(verifyCredential(legacy, policy).id, credential.id);
  fails('CREDENTIAL_DEVICE_REQUIRED', () => verifyCredential(legacy, { ...policy, requireDevice: true }));
  const undefinedTerm = changedCredential(vc => {
    delete vc['@context'][1].deviceDid;
    vc.credentialSubject.deviceDid = device.did;
  });
  fails('INVALID_CREDENTIAL', () => verifyCredential(undefinedTerm, policy));
  const incorrectTerm = changedCredential(vc => {
    vc['@context'][1].deviceDid['@type'] = '@vocab';
    vc.credentialSubject.deviceDid = device.did;
  });
  fails('INVALID_CREDENTIAL', () => verifyCredential(incorrectTerm, { ...policy, requireDevice: true }));
});

test('requireDevice authorization policy must be a boolean', () => {
  for (const requireDevice of [null, 0, 1, 'true', 'false', {}, [], () => true]) {
    fails('INVALID_POLICY', () => verifyCredential(credentialToken, { ...policy, requireDevice }));
  }
});

test('P-256 did:key encodes the SEC2 generator as p256-pub plus a compressed SEC1 point', () => {
  // SEC 2 secp256r1 generator, not a newly generated or secret device key.
  // The fixed DID was computed separately from 80 24 || 03 || Gx.
  const x = Buffer.from('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 'hex');
  const y = Buffer.from('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 'hex');
  const publicJwk = { kty: 'EC', crv: 'P-256', x: x.toString('base64url'), y: y.toString('base64url') };
  const identity = identityFromPublicKey(publicJwk);
  const did = 'did:key:zDnaepsL7AXenJkVYdkh5KuKsSU7Ykh7kyXaLLU7auN9FWSiZ';
  assert.equal(identity.did, did);
  assert.equal(identity.alg, 'ES256');
  assert.deepEqual(identity.publicJwk, publicJwk);
  assert.deepEqual(resolveDid(did).verificationMethod[0].publicKeyJwk, publicJwk);
  assert.deepEqual(resolveDid(did).authentication, [identity.kid]);
  assert.deepEqual(resolveDid(did).assertionMethod, [identity.kid]);
  const compressed = ECDH.convertKey(Buffer.concat([Buffer.from([4]), x, y]), 'prime256v1', undefined, undefined, 'compressed');
  assert.equal(compressed.toString('hex'), `03${x.toString('hex')}`);
  assert.equal(identity.publicKey.type, 'public');
  assert.equal(Object.hasOwn(identity, 'privateKey'), false);
  assert.equal(JSON.stringify(identity.didDocument).includes('"d":'), false);
});

test('P-256 resolver rejects invalid points, uncompressed representations and wrong varints', () => {
  for (const did of [
    // 80 24 || 02 || ff*32 is outside the base field.
    'did:key:zDnaehfHR8Q5U7ckmLQfuZ3eGEypooJ46zzjRQ1AR9asDvdnv',
    // 80 24 || 04 || Gx || Gy must not replace the compressed form.
    'did:key:z4oJ8bvMUow7fJp7Y6oHK1sHtBWTqaJdwQbcZscsJ3cE7GGscDHFbKSjYsc4EZimeRknigVKHNxisYKeM8dvEAKgSHKqW',
    // 80 12 is not the varint encoding of p256-pub.
    'did:key:zDnB3xspFwdiTwGcWHkLGZKHsyN4FF1rWAYGfjnd8kgQVqEXP',
  ]) fails('INVALID_DID', () => resolveDid(did));
});

test('public identity import supports both curves and rejects private material or malformed public keys', () => {
  assert.equal(identityFromPublicKey(holder.publicKey).did, holder.did);
  assert.equal(identityFromPublicKey(p256Device.publicJwk).did, p256Device.did);
  assert.equal(identityFromPublicKey({ ...p256Device.publicJwk, alg: 'ES256' }).did, p256Device.did);
  const invalid = [
    p256Keys.privateKey,
    p256Keys.privateKey.export({ format: 'jwk' }),
    { ...p256Device.publicJwk, d: undefined },
    { ...p256Device.publicJwk, alg: 'EdDSA' },
    { ...p256Device.publicJwk, crv: 'secp256k1' },
    { ...p256Device.publicJwk, x: `${p256Device.publicJwk.x}=` },
    { ...p256Device.publicJwk, y: Buffer.alloc(32).toString('base64url') },
    { ...holder.publicJwk, x: 'A'.repeat(42) + 'B' },
    {}, null,
  ];
  for (const publicKey of invalid) fails('INVALID_IDENTITY', () => identityFromPublicKey(publicKey));
  fails('INVALID_IDENTITY', () => identityFromPublicKey(p256Keys.publicKey, ''));
  fails('INVALID_IDENTITY', () => signJws({}, p256Device, POP_TYP));
});

test('ES256 JWS uses SHA-256 and IEEE-P1363 signatures interoperable with native crypto', () => {
  const payload = { request: 'pay', nonce: 'p256-123', deviceDid: p256Device.did };
  const token = signJws(payload, { ...p256Device, privateKey: p256Keys.privateKey }, POP_TYP);
  const result = verifyJws(token, { typ: POP_TYP, expectedDid: p256Device.did });
  assert.equal(result.header.alg, 'ES256');
  assert.deepEqual(result.payload, payload);
  const [header, body, signature] = token.split('.');
  const bytes = Buffer.from(signature, 'base64url');
  assert.equal(bytes.length, 64);
  assert.equal(verify('sha256', Buffer.from(`${header}.${body}`), { key: p256Keys.publicKey, dsaEncoding: 'ieee-p1363' }, bytes), true);
  const nativeSignature = sign('sha256', Buffer.from(`${header}.${body}`), { key: p256Keys.privateKey, dsaEncoding: 'ieee-p1363' });
  assert.deepEqual(verifyJws(`${header}.${body}.${nativeSignature.toString('base64url')}`, { typ: POP_TYP }).payload, payload);
});

test('P-256 signatures enforce algorithm/key binding and reject payload changes, DER and truncation', () => {
  const token = signJws({ ok: true }, { ...p256Device, privateKey: p256Keys.privateKey }, POP_TYP);
  const [header, body, signature] = token.split('.');
  const wrongHeader = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: POP_TYP, kid: p256Device.kid })).toString('base64url');
  fails('UNSUPPORTED_ALGORITHM', () => verifyJws(`${wrongHeader}.${body}.${signature}`, { typ: POP_TYP }));
  fails('INVALID_SIGNATURE', () => verifyJws(`${header}.${Buffer.from('{"ok":false}').toString('base64url')}.${signature}`, { typ: POP_TYP }));
  const der = sign('sha256', Buffer.from(`${header}.${body}`), p256Keys.privateKey);
  fails('INVALID_SIGNATURE', () => verifyJws(`${header}.${body}.${der.toString('base64url')}`, { typ: POP_TYP }));
  fails('INVALID_SIGNATURE', () => verifyJws(`${header}.${body}.${Buffer.from(signature, 'base64url').subarray(1).toString('base64url')}`, { typ: POP_TYP }));
});

test('signing rejects mismatched public identity metadata including the opposite point with the same x', () => {
  const valid = { ...p256Device, privateKey: p256Keys.privateKey };
  const prime = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
  const oppositeY = Buffer.from((prime - BigInt(`0x${Buffer.from(p256Device.publicJwk.y, 'base64url').toString('hex')}`)).toString(16).padStart(64, '0'), 'hex').toString('base64url');
  for (const patch of [
    { privateKey: otherP256Keys.privateKey },
    { privateKey: holder.privateKey },
    { publicKey: otherP256Keys.publicKey },
    { publicJwk: { ...p256Device.publicJwk, y: oppositeY } },
    { alg: 'EdDSA' },
    { kid: holder.kid },
  ]) fails('INVALID_IDENTITY', () => signJws({}, { ...valid, ...patch }, POP_TYP));
});

test('external signer receives the original JWS input and emits a verified ES256 JWS from a public identity', async () => {
  let calls = 0;
  const payload = { nonce: 'card-nonce', amount: '1000000' };
  const token = await signJwsWithSigner(payload, p256Device, POP_TYP, async (input, metadata) => {
    calls++;
    assert.equal(Buffer.isBuffer(input), true);
    assert.equal(input.toString('ascii').split('.').length, 2);
    assert.deepEqual(metadata, { alg: 'ES256', did: p256Device.did, kid: p256Device.kid });
    const signature = sign('sha256', input, { key: p256Keys.privateKey, dsaEncoding: 'ieee-p1363' });
    input.fill(0); // The backend cannot mutate the token input after it signs.
    return new Uint8Array(signature);
  });
  assert.equal(calls, 1);
  assert.equal(Object.hasOwn(p256Device, 'privateKey'), false);
  assert.deepEqual(verifyJws(token, { typ: POP_TYP, expectedDid: p256Device.did }).payload, payload);
});

test('external signer failures, wrong keys and signature formats are rejected without software fallback', async () => {
  const identityWithPrivateKey = { ...p256Device, privateKey: p256Keys.privateKey };
  for (const signer of [
    undefined,
    () => null,
    () => Buffer.alloc(64),
    input => sign('sha256', input, { key: otherP256Keys.privateKey, dsaEncoding: 'ieee-p1363' }),
    input => sign('sha256', input, p256Keys.privateKey),
    input => sign('sha256', input, { key: p256Keys.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url'),
  ]) {
    await assert.rejects(signJwsWithSigner({}, identityWithPrivateKey, POP_TYP, signer), error =>
      error.code === (signer === undefined ? 'INVALID_IDENTITY' : 'INVALID_SIGNATURE'));
  }
  const unavailable = new Error('Card is unavailable');
  await assert.rejects(signJwsWithSigner({}, identityWithPrivateKey, POP_TYP, () => { throw unavailable; }), error => error === unavailable);
});

test('external Ed25519 signing preserves existing verification and rejects another identity signature', async () => {
  const publicIdentity = identityFromPublicKey(holder.publicKey);
  const token = await signJwsWithSigner({ ed25519: true }, publicIdentity, POP_TYP, input => sign(null, input, holder.privateKey));
  assert.deepEqual(verifyJws(token, { typ: POP_TYP, expectedDid: holder.did }).payload, { ed25519: true });
  await assert.rejects(signJwsWithSigner({}, publicIdentity, POP_TYP, input => sign(null, input, outsider.privateKey)), error => error.code === 'INVALID_SIGNATURE');
});

test('an Ed25519 issuer VC binds a P-256 device DID while preserving its Ed25519 holder', () => {
  const token = issueCredential(issuer, { ...issueOptions, deviceDid: p256Device.did });
  const result = verifyCredential(token, { ...policy, requireDevice: true });
  assert.equal(result.issuer, issuer.did);
  assert.equal(result.credentialSubject.id, holder.did);
  assert.equal(result.credentialSubject.deviceDid, p256Device.did);
  assert.equal(resolveDid(result.credentialSubject.deviceDid).verificationMethod[0].publicKeyJwk.crv, 'P-256');
  assert.equal(verifyJws(token, { typ: VC_TYP }).header.alg, 'EdDSA');
});
