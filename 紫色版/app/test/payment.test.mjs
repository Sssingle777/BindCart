import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import Ajv from 'ajv';
import { generateIdentity, issueCredential, signJws, verifyJws } from '../lib/identity.mjs';
import {
  PAYMENT_SCOPE, PAYMENT_AUTH_TYP, PaymentError,
  issuePaymentAuthorization, verifyPaymentAuthorization, paymentRpc, validatePayment,
} from '../lib/payment.mjs';

const owner = generateIdentity('payment-owner');
const holder = generateIdentity('payment-holder');
const device = generateIdentity('payment-device');
const verifier = generateIdentity('payment-verifier');
const outsider = generateIdentity('payment-outsider');
const NOW = 1790899200;
const credential = issueCredential(owner, {
  subjectDid: holder.did, deviceDid: device.did, audience: verifier.did, scopes: [PAYMENT_SCOPE],
  validFrom: NOW * 1000 - 1000, validUntil: NOW * 1000 + 3600000,
});
const payment = { orderId: 'order-keyboard-1', payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 29900, currency: 'CNY' };
const issueOptions = { holderDid: holder.did, deviceDid: device.did, verifierDid: verifier.did, credential, payment, iat: NOW, exp: NOW + 600 };
const policy = { trustedAuthorizers: [owner.did], holderDid: holder.did, deviceDid: device.did, verifierDid: verifier.did, credential, payment, now: NOW };
const token = issuePaymentAuthorization(owner, issueOptions);
const document = verifyPaymentAuthorization(token, policy);
const digest = value => createHash('sha256').update(value).digest('base64url');

function fails(code, action) {
  assert.throws(action, error => error instanceof PaymentError && error.code === code, code);
}
function changed(change, signer = owner) {
  const value = structuredClone(document); change(value);
  return signJws(value, signer, PAYMENT_AUTH_TYP);
}

test('Owner signs an exact single-payment authorization bound to holder, device, verifier and VC bytes', () => {
  assert.equal(PAYMENT_SCOPE, 'payments:pay');
  assert.equal(PAYMENT_AUTH_TYP, 'a2a-payment-authorization+jwt');
  const signed = verifyJws(token, { typ: PAYMENT_AUTH_TYP, purpose: 'assertionMethod', expectedDid: owner.did });
  assert.equal(signed.signerDid, owner.did);
  assert.deepEqual(document, signed.payload);
  assert.equal(document.type, 'SinglePaymentAuthorization');
  assert.equal(document.version, 1);
  assert.match(document.authorizationId, /^urn:uuid:/);
  assert.equal(document.iss, owner.did);
  assert.equal(document.sub, holder.did);
  assert.equal(document.aud, verifier.did);
  assert.equal(document.deviceDid, device.did);
  assert.equal(document.credentialHash, digest(credential));
  assert.equal(document.maxExecutions, 1);
  assert.equal(document.delegationAllowed, false);
  assert.deepEqual(document.payment, payment);
  assert.deepEqual(verifyPaymentAuthorization(token, { ...policy, trustedAuthorizers: new Set([owner.did]) }), document);
});

test('authorization defaults use independent stable IDs and at most ten minutes validity', () => {
  const { iat, exp, ...options } = issueOptions;
  const first = issuePaymentAuthorization(owner, options);
  const second = issuePaymentAuthorization(owner, options);
  const firstClaims = verifyPaymentAuthorization(first, { ...policy, now: Math.floor(Date.now() / 1000) });
  const secondClaims = verifyPaymentAuthorization(second, { ...policy, now: Math.floor(Date.now() / 1000) });
  assert.equal(firstClaims.exp - firstClaims.iat, 600);
  assert.notEqual(firstClaims.authorizationId, secondClaims.authorizationId);
  const explicit = issuePaymentAuthorization(owner, { ...issueOptions, authorizationId: 'authorization-stable-1' });
  assert.equal(verifyPaymentAuthorization(explicit, policy).authorizationId, 'authorization-stable-1');
});

test('altering the signed amount or signature cannot forge Owner authorization', () => {
  const [header, encoded, signature] = token.split('.');
  const value = JSON.parse(Buffer.from(encoded, 'base64url')); value.payment.amountMinor = 1;
  fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(`${header}.${Buffer.from(JSON.stringify(value)).toString('base64url')}.${signature}`, policy));
  const broken = Buffer.from(signature, 'base64url'); broken[0] ^= 1;
  fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(`${header}.${encoded}.${broken.toString('base64url')}`, policy));
  fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(signJws(document, outsider, PAYMENT_AUTH_TYP), policy));
});

test('a genuine signature by an untrusted authorizer is rejected independently of claims', () => {
  const outsiderToken = issuePaymentAuthorization(outsider, issueOptions);
  fails('PAYMENT_AUTHORIZER_UNTRUSTED', () => verifyPaymentAuthorization(outsiderToken, policy));
  fails('PAYMENT_AUTHORIZER_UNTRUSTED', () => verifyPaymentAuthorization(token, { ...policy, trustedAuthorizers: [] }));
  fails('PAYMENT_AUTHORIZER_UNTRUSTED', () => verifyPaymentAuthorization(token, { ...policy, trustedAuthorizers: new Set([outsider.did]) }));
  assert.equal(verifyPaymentAuthorization(outsiderToken, { ...policy, trustedAuthorizers: [outsider.did] }).iss, outsider.did);
});

test('authorization cannot move to another holder, device, verifier or serialized credential', () => {
  for (const field of ['holderDid', 'deviceDid', 'verifierDid']) {
    fails('PAYMENT_AUTHORIZATION_BINDING_MISMATCH', () => verifyPaymentAuthorization(token, { ...policy, [field]: outsider.did }));
  }
  const reissuedCredential = issueCredential(owner, {
    subjectDid: holder.did, deviceDid: device.did, audience: verifier.did, scopes: [PAYMENT_SCOPE],
    validFrom: NOW * 1000 - 1000, validUntil: NOW * 1000 + 3600000,
  });
  assert.notEqual(reissuedCredential, credential);
  fails('PAYMENT_AUTHORIZATION_BINDING_MISMATCH', () => verifyPaymentAuthorization(token, { ...policy, credential: reissuedCredential }));
});

test('different valid order, merchant or amount terms cannot use the same Owner approval', () => {
  for (const change of [{ orderId: 'order-other' }, { payeeAccount: 'merchant:other' }, { amountMinor: 1 }, { amountMinor: 29901 }]) {
    fails('PAYMENT_TERMS_MISMATCH', () => verifyPaymentAuthorization(token, { ...policy, payment: { ...payment, ...change } }));
  }
  const reordered = { currency: 'CNY', amountMinor: 29900, payeeAccount: 'merchant:keyboard', payerAccount: 'demo:alice', orderId: payment.orderId };
  assert.deepEqual(verifyPaymentAuthorization(token, { ...policy, payment: reordered }), document);
});

test('validity includes issued-at but excludes expiration with no implicit future activation', () => {
  assert.equal(verifyPaymentAuthorization(token, { ...policy, now: NOW }).authorizationId, document.authorizationId);
  assert.equal(verifyPaymentAuthorization(token, { ...policy, now: NOW + 599 }).authorizationId, document.authorizationId);
  fails('PAYMENT_AUTHORIZATION_EXPIRED', () => verifyPaymentAuthorization(token, { ...policy, now: NOW - 1 }));
  fails('PAYMENT_AUTHORIZATION_EXPIRED', () => verifyPaymentAuthorization(token, { ...policy, now: NOW + 600 }));
});

test('authorization intervals must be positive integer seconds and never exceed 600 seconds', () => {
  for (const change of [
    { exp: NOW + 601 }, { exp: NOW }, { exp: NOW - 1 }, { iat: -1, exp: 30 },
    { iat: 'now' }, { exp: 'later' }, { iat: 1.5, exp: 2 },
    { iat: null }, { exp: null }, { exp: Infinity }, { exp: Number.MAX_SAFE_INTEGER + 1 },
  ]) {
    fails('INVALID_PAYMENT_AUTHORIZATION', () => issuePaymentAuthorization(owner, { ...issueOptions, ...change }));
    fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(changed(value => Object.assign(value, change)), policy));
  }
});

test('signed authorization schema rejects missing/extra fields, delegated or repeated execution and changed semantics', () => {
  const mutations = [
    value => { delete value.authorizationId; },
    value => { value.authorizationId = ''; },
    value => { value.extra = true; },
    value => { value.type = 'ReusableAuthorization'; },
    value => { value.version = 2; },
    value => { value.maxExecutions = 2; },
    value => { value.maxExecutions = '1'; },
    value => { value.delegationAllowed = true; },
    value => { value.delegationAllowed = 'false'; },
    value => { value.credentialHash = 'not-sha256'; },
    value => { value.deviceDid = holder.did; },
    value => { value.deviceDid = 'did:web:device.example'; },
    value => { value.iss = { id: owner.did }; },
    value => { value.sub = 'did:web:holder.example'; },
    value => { value.aud = 'did:web:verifier.example'; },
    value => { value.payment = [value.payment]; },
  ];
  for (const mutate of mutations) fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(changed(mutate), policy));
});

test('payment terms reject malformed amounts, unknown or reverse accounts, currencies and arbitrary extra fields', () => {
  const invalid = [
    null, [], {}, { ...payment, extra: true },
    ...[0, -0, -1, 0.1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '1', true, null].map(amountMinor => ({ ...payment, amountMinor })),
    ...[
      { payerAccount: 'merchant:keyboard', payeeAccount: 'demo:alice' },
      { payerAccount: 'demo:alice', payeeAccount: 'demo:alice' },
      { payerAccount: 'unknown' }, { payeeAccount: 'unknown' }, { currency: 'USD' }, { orderId: '' },
    ].map(change => ({ ...payment, ...change })),
  ];
  for (const bad of invalid) {
    fails('INVALID_PAYMENT_AUTHORIZATION', () => validatePayment(bad));
    fails('INVALID_PAYMENT_AUTHORIZATION', () => issuePaymentAuthorization(owner, { ...issueOptions, payment: bad }));
    fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(changed(value => { value.payment = bad; }), policy));
  }
});

test('missing approval is distinguished from malformed tokens and unrelated token media types', () => {
  for (const missing of [undefined, null, '']) fails('PAYMENT_AUTHORIZATION_REQUIRED', () => verifyPaymentAuthorization(missing, policy));
  for (const malformed of ['a.b.c', 'not-a-token', 1, {}, token + '=']) fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(malformed, policy));
  fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(signJws(document, owner, 'a2a-did-pop+jwt'), policy));
  fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(credential, policy));
});

test('issuance and verification cannot silently omit roles, trusted policy, credential or valid current time', () => {
  for (const field of ['holderDid', 'deviceDid', 'verifierDid', 'credential', 'payment']) {
    const incompleteIssue = { ...issueOptions }; delete incompleteIssue[field];
    fails('INVALID_PAYMENT_AUTHORIZATION', () => issuePaymentAuthorization(owner, incompleteIssue));
    const incompletePolicy = { ...policy }; delete incompletePolicy[field];
    fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(token, incompletePolicy));
  }
  for (const trustedAuthorizers of [undefined, null, owner.did, {}, ['did:web:owner.example']]) {
    fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(token, { ...policy, trustedAuthorizers }));
  }
  for (const now of [null, -1, 1.5, Infinity, NaN, 'now']) fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(token, { ...policy, now }));
  fails('INVALID_PAYMENT_AUTHORIZATION', () => issuePaymentAuthorization({ ...owner, privateKey: outsider.privateKey }, issueOptions));
  fails('INVALID_PAYMENT_AUTHORIZATION', () => issuePaymentAuthorization(owner, { ...issueOptions, additional: true }));
  fails('INVALID_PAYMENT_AUTHORIZATION', () => verifyPaymentAuthorization(token, { ...policy, additional: true }));
});

test('paymentRpc creates a standard A2A message/send DataPart with an independent copy of the approved terms', () => {
  const original = { ...payment };
  const rpc = paymentRpc(original, token);
  const schema = JSON.parse(readFileSync(new URL('../vendor/a2a-v0.3.0.schema.json', import.meta.url)));
  const ajv = new Ajv({ strict: false, validateFormats: false });
  ajv.addSchema(schema, 'a2a-payment');
  const valid = ajv.compile({ $ref: 'a2a-payment#/definitions/SendMessageRequest' });
  assert.equal(valid(rpc), true, ajv.errorsText(valid.errors));
  assert.equal(rpc.method, 'message/send');
  assert.equal(rpc.params.message.role, 'user');
  assert.equal(rpc.params.message.parts.length, 1);
  assert.deepEqual(rpc.params.message.parts[0], { kind: 'data', data: { scope: PAYMENT_SCOPE, payment, authorization: token } });
  original.amountMinor = 1;
  assert.equal(rpc.params.message.parts[0].data.payment.amountMinor, 29900);
  const next = paymentRpc(payment, token);
  assert.notEqual(rpc.id, next.id);
  assert.notEqual(rpc.params.message.messageId, next.params.message.messageId);
});
