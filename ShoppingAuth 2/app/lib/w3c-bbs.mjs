/**
 * W3C VC 2.0 / Data Integrity bbs-2023 credential layer.
 *
 * The Digital Bazaar cryptosuite performs RDF canonicalization and the BBS
 * signature/proof operations. The project vocabulary below is an application
 * profile; it is not an extension to the bbs-2023 proof format. The additional
 * eSIM possession proof is checked by the payment integration separately.
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {
  createDiscloseCryptosuite, createSignCryptosuite, createVerifyCryptosuite,
} from '@digitalbazaar/bbs-2023-cryptosuite';
import {contexts as credentialContexts} from '@digitalbazaar/credentials-context';
import dataIntegrityContexts from '@digitalbazaar/data-integrity-context';
import multikeyContexts from '@digitalbazaar/multikey-context';
import jsigs from 'jsonld-signatures';

export const VC_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
export const ESIM_PAYMENT_CONTEXT = 'https://example.org/contexts/esim-payment/v1';
export const ESIM_PAYMENT_TYPE = 'EsimBoundPaymentCredential';
export const W3C_BBS_CRYPTOSUITE = 'bbs-2023';
const VOCAB = 'https://example.org/vocab/esim-payment#';
const SUBJECT_FIELDS = ['role', 'scope', 'epoch', 'mode', 'bindingId', 'organization', 'holderLabel'];
const HOLDER_FIELD = 'holderDid';
export const W3C_BBS_DISCLOSED_FIELDS = Object.freeze(SUBJECT_FIELDS.slice(0, 5));
export const W3C_BBS_HIDDEN_FIELDS = Object.freeze(SUBJECT_FIELDS.slice(5));
const TYPES = ['VerifiableCredential', ESIM_PAYMENT_TYPE];
const CONTEXTS = [VC_V2_CONTEXT, ESIM_PAYMENT_CONTEXT];
const MANDATORY_POINTERS = [
  '/type', '/issuer', '/validFrom', '/validUntil',
  ...W3C_BBS_DISCLOSED_FIELDS.map(field => `/credentialSubject/${field}`),
];
const ALL_SUBJECT_POINTERS = SUBJECT_FIELDS.map(field => `/credentialSubject/${field}`);
const BASE_CHECK_HEADER = new TextEncoder().encode('esim-payment:base-credential-validation:v1');
const {AssertionProofPurpose} = jsigs.purposes;

// No @vocab fallback: undefined terms must never silently escape the signature.
export const esimPaymentContextDocument = Object.freeze({
  '@context': Object.freeze({
    '@protected': true,
    [ESIM_PAYMENT_TYPE]: `${VOCAB}${ESIM_PAYMENT_TYPE}`,
    ...Object.fromEntries([...SUBJECT_FIELDS, HOLDER_FIELD].map(field => [field, `${VOCAB}${field}`])),
  }),
});

export class W3cBbsError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'W3cBbsError';
    this.code = code;
  }
}

const clone = value => structuredClone(value);
function requireThat(condition, code, message) {
  if (!condition) throw new W3cBbsError(code, message);
}
function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}
function sameArray(a, b) {
  return Array.isArray(a) && a.length === b.length && a.every((value, i) => value === b[i]);
}
function text(value, limit = 1024) {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && value.isWellFormed();
}
function validDate(value) {
  return typeof value === 'string'
    && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value)
    && Number.isFinite(Date.parse(value))
    && new Date(value).toISOString() === (value.includes('.') ? value : value.replace('Z', '.000Z'));
}
function profileCopy(profile) {
  requireThat(plainObject(profile) && text(profile.issuer), 'W3C_BBS_ISSUER_INVALID', 'Trusted BBS issuer profile is required.');
  const vm = profile.verificationMethod;
  requireThat(plainObject(vm) && vm.type === 'Multikey' && vm.controller === profile.issuer
    && text(vm.id) && vm.id.startsWith(`${profile.issuer}#`) && text(vm.publicKeyMultibase)
    && vm.publicKeyMultibase.startsWith('z') && !('secretKeyMultibase' in vm),
  'W3C_BBS_ISSUER_INVALID', 'Trusted BBS verification method must be a public Multikey controlled by the issuer.');
  return {
    issuer: profile.issuer,
    verificationMethod: {
      '@context': 'https://w3id.org/security/multikey/v1',
      type: 'Multikey', id: vm.id, controller: vm.controller, publicKeyMultibase: vm.publicKeyMultibase,
    },
  };
}

/** Pinned local documents only. No URL fetch, protocol fallback, or remote context. */
export function createW3cBbsDocumentLoader(issuerProfile) {
  const profile = profileCopy(issuerProfile);
  const documents = new Map([
    [VC_V2_CONTEXT, credentialContexts.get(VC_V2_CONTEXT)],
    ...dataIntegrityContexts.contexts,
    ...multikeyContexts.contexts,
    [ESIM_PAYMENT_CONTEXT, esimPaymentContextDocument],
    [profile.verificationMethod.id, profile.verificationMethod],
    [profile.issuer, {
      '@context': 'https://www.w3.org/ns/did/v1', id: profile.issuer,
      assertionMethod: [profile.verificationMethod.id], verificationMethod: [profile.verificationMethod],
    }],
  ]);
  return async url => {
    requireThat(typeof url === 'string' && documents.has(url), 'W3C_BBS_DOCUMENT_NOT_ALLOWED',
      'The JSON-LD document is not in the pinned offline allowlist.');
    return {contextUrl: null, documentUrl: url, document: clone(documents.get(url))};
  };
}

function purpose(profile) {
  // Trusted controller is local. Caller-supplied credentials cannot nominate a
  // different controller document or authorize their own verification method.
  return new AssertionProofPurpose({controller: {
    id: profile.issuer, assertionMethod: [profile.verificationMethod.id],
  }});
}
function headerCopy(presentationHeader) {
  requireThat(presentationHeader instanceof Uint8Array && presentationHeader.length > 0
    && presentationHeader.length <= 4096, 'W3C_BBS_HEADER_INVALID',
  'A nonempty verifier-bound presentation header is required.');
  return Uint8Array.from(presentationHeader);
}
function validateSubject(subject, {base = false} = {}) {
  requireThat(plainObject(subject), 'W3C_BBS_CREDENTIAL_INVALID', 'credentialSubject must be an object.');
  const fields = Object.keys(subject);
  requireThat(fields.every(field => SUBJECT_FIELDS.includes(field) || field === HOLDER_FIELD)
    && (base ? SUBJECT_FIELDS : W3C_BBS_DISCLOSED_FIELDS).every(field => text(subject[field]))
    && fields.every(field => text(subject[field])),
  'W3C_BBS_CREDENTIAL_INVALID', 'The eSIM payment subject has missing, undefined, or invalid claims.');
}
function validateCredential(credential, profile, {base = false, checkTime = true} = {}) {
  requireThat(plainObject(credential), 'W3C_BBS_CREDENTIAL_INVALID', 'A W3C BBS credential object is required.');
  requireThat(Object.keys(credential).every(key => ['@context', 'type', 'issuer', 'validFrom', 'validUntil', 'credentialSubject', 'proof'].includes(key)),
    'W3C_BBS_CREDENTIAL_INVALID', 'The credential contains fields outside the pinned payment profile.');
  requireThat(sameArray(credential['@context'], CONTEXTS), 'W3C_BBS_CONTEXT_INVALID', 'The credential must use the pinned VC 2.0 and eSIM payment contexts.');
  requireThat(sameArray(credential.type, TYPES) && credential.issuer === profile.issuer,
    'W3C_BBS_UNTRUSTED_ISSUER', 'The credential type or issuer does not match the trusted payment issuer.');
  requireThat(validDate(credential.validFrom) && validDate(credential.validUntil)
    && Date.parse(credential.validFrom) < Date.parse(credential.validUntil),
  'W3C_BBS_VALIDITY_INVALID', 'The credential validity interval is invalid.');
  if (checkTime) {
    const now = Date.now();
    requireThat(Date.parse(credential.validFrom) <= now && now < Date.parse(credential.validUntil),
      'W3C_BBS_EXPIRED', 'The credential is not currently valid.');
  }
  validateSubject(credential.credentialSubject, {base});
  const proof = credential.proof;
  requireThat(plainObject(proof) && proof.type === 'DataIntegrityProof'
    && proof.cryptosuite === W3C_BBS_CRYPTOSUITE && proof.proofPurpose === 'assertionMethod'
    && proof.verificationMethod === profile.verificationMethod.id
    && text(proof.proofValue, 65536)
    && Object.keys(proof).every(key => ['type', 'cryptosuite', 'created', 'proofPurpose', 'verificationMethod', 'proofValue'].includes(key)),
  'W3C_BBS_PROOF_INVALID', 'Expected one issuer-authorized DataIntegrityProof using bbs-2023.');
}

async function derive({credential, profile, presentationHeader, selectivePointers = []}) {
  validateCredential(credential, profile, {base: true});
  try {
    return await jsigs.derive(clone(credential), {
      suite: new DataIntegrityProof({cryptosuite: createDiscloseCryptosuite({
        selectivePointers, presentationHeader: headerCopy(presentationHeader),
      })}),
      purpose: purpose(profile), documentLoader: createW3cBbsDocumentLoader(profile),
    });
  } catch (error) {
    if (error instanceof W3cBbsError) throw error;
    throw new W3cBbsError('W3C_BBS_DERIVATION_FAILED', 'BBS selective-disclosure derivation failed.', {cause: error});
  }
}

/** Holder operation: only the signed base credential and issuer PUBLIC key. */
export async function deriveCredential({credential, issuerProfile, presentationHeader, disclosedFields = []}) {
  requireThat(Array.isArray(disclosedFields) && disclosedFields.every(field => W3C_BBS_HIDDEN_FIELDS.includes(field))
    && new Set(disclosedFields).size === disclosedFields.length, 'W3C_BBS_DISCLOSURE_POLICY', 'Only optional organization and holderLabel claims can be selected.');
  return derive({credential, profile: profileCopy(issuerProfile), presentationHeader,
    selectivePointers: disclosedFields.map(field => `/credentialSubject/${field}`)});
}

export function createW3cBbsVerifier(issuerProfile) {
  const profile = profileCopy(issuerProfile);
  const documentLoader = createW3cBbsDocumentLoader(profile);
  async function verifyDerived({credential, presentationHeader}) {
    validateCredential(credential, profile);
    const expectedPresentationHeader = headerCopy(presentationHeader);
    let result;
    try {
      result = await jsigs.verify(clone(credential), {
        suite: new DataIntegrityProof({cryptosuite: createVerifyCryptosuite({expectedPresentationHeader})}),
        purpose: purpose(profile), documentLoader,
      });
    } catch (error) {
      throw new W3cBbsError('W3C_BBS_INVALID_PROOF', 'W3C BBS proof verification failed.', {cause: error});
    }
    requireThat(result.verified, 'W3C_BBS_INVALID_PROOF', 'W3C BBS proof or presentation-header verification failed.');
    return true;
  }
  async function verifyBase({credential}) {
    // bbs-2023 verifiers consume disclosure proofs. Disclose every signed claim
    // locally and verify that fresh proof to validate the received base signature.
    const disclosed = await derive({credential, profile, presentationHeader: BASE_CHECK_HEADER,
      selectivePointers: [...ALL_SUBJECT_POINTERS, ...(credential.credentialSubject?.holderDid ? ['/credentialSubject/holderDid'] : [])]});
    return verifyDerived({credential: disclosed, presentationHeader: BASE_CHECK_HEADER});
  }
  return Object.freeze({verifyDerived, verifyBase});
}

export async function createW3cBbsIssuer({id = 'did:example:payment-bbs-issuer'} = {}) {
  requireThat(text(id) && /^[a-z][a-z0-9+.-]*:/i.test(id) && !id.includes('#'),
    'W3C_BBS_ISSUER_INVALID', 'The BBS issuer must have an absolute controller identifier without a fragment.');
  const key = await Bls12381Multikey.generateBbsKeyPair({
    algorithm: Bls12381Multikey.ALGORITHMS.BBS_BLS12381_SHA256,
    controller: id, id: `${id}#bbs-2023-key`,
  });
  const profile = profileCopy({issuer: id, verificationMethod: await key.export({publicKey: true, includeContext: true})});
  const documentLoader = createW3cBbsDocumentLoader(profile);
  const verifier = createW3cBbsVerifier(profile);
  async function issue({credentialSubject, validFrom = new Date().toISOString(), validUntil} = {}) {
    validateSubject(credentialSubject, {base: true});
    requireThat(validDate(validFrom), 'W3C_BBS_VALIDITY_INVALID', 'The credential start date is invalid.');
    validUntil ??= new Date(Date.parse(validFrom) + 24 * 60 * 60 * 1000).toISOString();
    requireThat(validDate(validFrom) && validDate(validUntil) && Date.parse(validFrom) < Date.parse(validUntil),
      'W3C_BBS_VALIDITY_INVALID', 'The credential validity interval is invalid.');
    const unsigned = {
      '@context': [...CONTEXTS], type: [...TYPES], issuer: profile.issuer,
      validFrom, validUntil, credentialSubject: clone(credentialSubject),
    };
    try {
      return await jsigs.sign(unsigned, {
        suite: new DataIntegrityProof({signer: key.signer(), cryptosuite: createSignCryptosuite({mandatoryPointers:
          [...MANDATORY_POINTERS, ...(credentialSubject.holderDid ? ['/credentialSubject/holderDid'] : [])]})}),
        purpose: purpose(profile), documentLoader,
      });
    } catch (error) {
      throw new W3cBbsError('W3C_BBS_ISSUANCE_FAILED', 'W3C BBS credential issuance failed.', {cause: error});
    }
  }
  // The closure holds the BBS issuer secret; publicInfo never exports it.
  return Object.freeze({publicInfo: () => clone(profile), issue, verifyBase: verifier.verifyBase});
}
