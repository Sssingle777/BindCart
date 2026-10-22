import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import jsigs from 'jsonld-signatures';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {createVerifyCryptosuite} from '@digitalbazaar/bbs-2023-cryptosuite';
import {
  createW3cBbsIssuer, createW3cBbsVerifier, createW3cBbsDocumentLoader,
  deriveCredential, ESIM_PAYMENT_CONTEXT, W3C_BBS_DISCLOSED_FIELDS,
} from '../lib/w3c-bbs.mjs';

const issuer = await createW3cBbsIssuer({id: 'did:example:w3c-bbs-test-issuer'});
const issuerProfile = issuer.publicInfo();
const verifier = createW3cBbsVerifier(issuerProfile);
const subject = {
  role: 'payment-agent', scope: 'payments:pay', epoch: new Date().toISOString().slice(0, 10),
  mode: 'bbs-bls', bindingId: 'dbac-binding-6be078fb-4931-466f-a2cc-5d8958c4a147',
  organization: 'Private research laboratory', holderLabel: 'Private agent name',
};
const credential = await issuer.issue({credentialSubject: subject});
const presentationHeader = randomBytes(32);
const derived = await deriveCredential({credential, issuerProfile, presentationHeader});
const copy = value => structuredClone(value);
const rejected = code => error => typeof error?.code === 'string' && (!code || error.code === code);

test('VC 2.0 uses a real bbs-2023 DataIntegrityProof and only exports public issuer material', async () => {
  assert.equal(credential['@context'][0], 'https://www.w3.org/ns/credentials/v2');
  assert.equal(credential.proof.type, 'DataIntegrityProof');
  assert.equal(credential.proof.cryptosuite, 'bbs-2023');
  assert.equal(credential.proof.proofPurpose, 'assertionMethod');
  assert.match(credential.proof.proofValue, /^u2V0C/);
  assert.equal(await verifier.verifyBase({credential}), true);
  assert.deepEqual(credential.credentialSubject, subject);
  assert.equal(/secretKey|privateKey/.test(JSON.stringify(issuerProfile)), false);
  const alteredProfile = issuer.publicInfo();
  alteredProfile.verificationMethod.publicKeyMultibase = 'zmodified';
  assert.deepEqual(issuer.publicInfo(), issuerProfile, 'publicInfo must return a copy');
});

test('holder derives from public material, hiding organization and holder label', async () => {
  assert.deepEqual(Object.keys(derived.credentialSubject).sort(), [...W3C_BBS_DISCLOSED_FIELDS].sort());
  assert.equal(JSON.stringify(derived).includes(subject.organization), false);
  assert.equal(JSON.stringify(derived).includes(subject.holderLabel), false);
  assert.equal(await verifier.verifyDerived({credential: derived, presentationHeader}), true);
  const another = await deriveCredential({credential, issuerProfile, presentationHeader});
  assert.notEqual(another.proof.proofValue, derived.proof.proofValue, 'each disclosure proof must use fresh randomness');
  assert.equal(await verifier.verifyDerived({credential: another, presentationHeader}), true);
});

test('derived credential verifies with upstream jsonld-signatures directly', async () => {
  const result = await jsigs.verify(copy(derived), {
    suite: new DataIntegrityProof({cryptosuite: createVerifyCryptosuite({expectedPresentationHeader: presentationHeader})}),
    purpose: new jsigs.purposes.AssertionProofPurpose(),
    documentLoader: createW3cBbsDocumentLoader(issuerProfile),
  });
  assert.equal(result.verified, true, JSON.stringify(result));
});

test('RDF canonicalization accepts JSON property reordering without resigning', async () => {
  const reordered = Object.fromEntries(Object.entries(derived).reverse());
  reordered.credentialSubject = Object.fromEntries(Object.entries(derived.credentialSubject).reverse());
  reordered.proof = Object.fromEntries(Object.entries(derived.proof).reverse());
  assert.equal(await verifier.verifyDerived({credential: reordered, presentationHeader}), true);
});

test('a new challenge header cannot reuse an old disclosure proof', async () => {
  await assert.rejects(verifier.verifyDerived({credential: derived, presentationHeader: randomBytes(32)}), rejected('W3C_BBS_INVALID_PROOF'));
  await assert.rejects(verifier.verifyDerived({credential: derived, presentationHeader: new Uint8Array()}), rejected('W3C_BBS_HEADER_INVALID'));
  await assert.rejects(deriveCredential({credential, issuerProfile, presentationHeader: 'not bytes'}), rejected('W3C_BBS_HEADER_INVALID'));
});

test('tampering any disclosed payment claim breaks verification', async () => {
  for (const field of W3C_BBS_DISCLOSED_FIELDS) {
    const modified = copy(derived);
    modified.credentialSubject[field] += '-forged';
    await assert.rejects(verifier.verifyDerived({credential: modified, presentationHeader}), rejected('W3C_BBS_INVALID_PROOF'), field);
  }
});

test('base credential verification covers hidden claims too', async () => {
  for (const field of ['organization', 'holderLabel']) {
    const modified = copy(credential);
    modified.credentialSubject[field] += '-forged';
    await assert.rejects(verifier.verifyBase({credential: modified}), rejected('W3C_BBS_INVALID_PROOF'), field);
  }
});

test('validity dates are signed and expiry is enforced', async () => {
  const changed = copy(derived);
  changed.validUntil = new Date(Date.now() + 48 * 60 * 60 * 1000).toISOString();
  await assert.rejects(verifier.verifyDerived({credential: changed, presentationHeader}), rejected('W3C_BBS_INVALID_PROOF'));
  const expired = await issuer.issue({credentialSubject: subject, validFrom: '2020-01-01T00:00:00Z', validUntil: '2020-01-02T00:00:00Z'});
  await assert.rejects(verifier.verifyBase({credential: expired}), rejected('W3C_BBS_EXPIRED'));
});

test('unknown and inline contexts are rejected without remote loading', async () => {
  for (const context of [
    ['https://www.w3.org/ns/credentials/v2', 'http://127.0.0.1:1/untrusted.jsonld'],
    ['https://www.w3.org/ns/credentials/v2', {'@vocab': 'https://attacker.example/'}],
    ['https://www.w3.org/ns/credentials/v2', ESIM_PAYMENT_CONTEXT, {'scope': 'https://attacker.example/scope'}],
  ]) {
    const modified = copy(derived); modified['@context'] = context;
    await assert.rejects(verifier.verifyDerived({credential: modified, presentationHeader}), rejected('W3C_BBS_CONTEXT_INVALID'));
  }
  const loader = createW3cBbsDocumentLoader(issuerProfile);
  await assert.rejects(loader('http://127.0.0.1:1/untrusted.jsonld'), rejected('W3C_BBS_DOCUMENT_NOT_ALLOWED'));
  const document = await loader(ESIM_PAYMENT_CONTEXT); document.document['@context'].scope = 'mutated';
  assert.notEqual((await loader(ESIM_PAYMENT_CONTEXT)).document['@context'].scope, 'mutated');
});

test('undefined or unbound JSON fields cannot appear to be authenticated claims', async () => {
  for (const modify of [
    value => {value.credentialSubject.unmappedAuthorization = 'administrator';},
    value => {value.credentialSubject['@context'] = {'@vocab': 'https://attacker.example/'};},
    value => {value.unsignedAuthorization = true;},
    value => {delete value.credentialSubject.bindingId;},
    value => {value.credentialSubject.organization = subject.organization;},
  ]) {
    const modified = copy(derived); modify(modified);
    await assert.rejects(verifier.verifyDerived({credential: modified, presentationHeader}), rejected());
  }
});

test('proof format, assertion purpose, and trusted issuer cannot be substituted', async () => {
  for (const modify of [
    value => {value.proof.cryptosuite = 'DBAC-BBS-BLS12381-SHA512-v1';},
    value => {value.proof.proofPurpose = 'authentication';},
    value => {value.proof.verificationMethod = 'did:example:attacker#key';},
    value => {value.issuer = 'did:example:attacker';},
    value => {value.proof = [value.proof];},
    value => {value.proof.proofValue = `${value.proof.proofValue.slice(0, -5)}AAAAA`;},
  ]) {
    const modified = copy(derived); modify(modified);
    await assert.rejects(verifier.verifyDerived({credential: modified, presentationHeader}), rejected());
  }
  const otherIssuer = await createW3cBbsIssuer({id: issuerProfile.issuer});
  await assert.rejects(createW3cBbsVerifier(otherIssuer.publicInfo()).verifyDerived({credential: derived, presentationHeader}), rejected('W3C_BBS_INVALID_PROOF'));
});

test('issuer refuses undefined subject fields and verifier refuses issuer secrets', async () => {
  await assert.rejects(issuer.issue({credentialSubject: {...subject, unsignedExtra: 'no'}}), rejected('W3C_BBS_CREDENTIAL_INVALID'));
  await assert.rejects(issuer.issue({credentialSubject: subject, validFrom: '2026-02-31T00:00:00Z'}), rejected('W3C_BBS_VALIDITY_INVALID'));
  await assert.rejects(issuer.issue({credentialSubject: subject, validFrom: 'invalid-date'}), rejected('W3C_BBS_VALIDITY_INVALID'));
  const badProfile = copy(issuerProfile); badProfile.verificationMethod.secretKeyMultibase = 'zsecret';
  assert.throws(() => createW3cBbsVerifier(badProfile), rejected('W3C_BBS_ISSUER_INVALID'));
});
