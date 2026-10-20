import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { generateIdentity, verifyJws } from '../lib/identity.mjs';
import { digest, sendJson } from '../lib/protocol.mjs';
import { createW3cBbsIssuer, createW3cBbsVerifier, deriveCredential } from '../lib/w3c-bbs.mjs';
import { generateDeviceKey, generateIssuerKey, issueCredential, preparePresentation, finalizePresentation, signDeviceRequest } from '../lib/dbac/crypto.mjs';
import { paymentAttributes, DBAC_EXTENSION } from '../lib/dbac/policy.mjs';
import { createDbacPaymentVerifier } from '../lib/dbac/payment-verifier.mjs';
import { DBAC_PAYMENT_CHALLENGE_TYP } from '../lib/dbac/payment-policy.mjs';
import { presentationHeader, bindingContext, W3C_DISCLOSED_INDICES } from '../lib/dbac/w3c-profile.mjs';
import { signHolderProof, verifyHolderProof } from '../lib/dbac/holder-proof.mjs';
import { createDbacDevice, createDbacIssuer } from '../lib/dbac/services.mjs';
import { createCredentialStatusStore, createCredentialStatusReader } from '../lib/dbac/credential-status.mjs';

const token = () => randomBytes(32).toString('base64url');
const rejected = code => error => error.code === code;

test('holder secret is an independent Ed25519 key; proof binds derived VC, DBAC proof and request, never nonce alone', async () => {
  const identity = generateIdentity('A private test key'), b = generateIdentity('B'), device = generateDeviceKey(), issuer = generateIssuerKey();
  const w3c = await createW3cBbsIssuer(), issuerProfile = w3c.publicInfo();
  const mode = 'bbs-bls', bindingId = `urn:uuid:${randomUUID()}`, attributes = [...paymentAttributes(mode), bindingId];
  const [role, scope, epoch, , organization, holderLabel] = attributes;
  const original = await w3c.issue({ credentialSubject: { role, scope, epoch, mode, bindingId, organization, holderLabel, holderDid: identity.did } });
  const context = { mode, purpose: 'test-request-v1', verifier: b.did, phase: 'proposal', bodyHash: token(), challengeId: randomUUID(), nonce: token(), iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 60 };
  const verifiableCredential = await deriveCredential({ credential: original, issuerProfile, presentationHeader: presentationHeader(context) });
  assert.equal(verifiableCredential.credentialSubject.holderDid, identity.did, 'holder key is issuer-protected and mandatory-disclosed');
  const credential = issueCredential({ issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes });
  const prepared = preparePresentation({ credential, mode, context: bindingContext(context, verifiableCredential), disclosedIndices: W3C_DISCLOSED_INDICES });
  const presentation = finalizePresentation({ state: prepared.state, response: signDeviceRequest({ deviceSecretKey: device.secretKey, request: prepared.request }) });
  const input = { identity, context, verifiableCredential, presentation };
  const holderProof = signHolderProof(input);
  assert.equal(verifyHolderProof({ ...input, holderProof }).verified, true);
  assert.doesNotMatch(JSON.stringify({ holderProof, context, verifiableCredential, presentation }), /privateKey|secretKey|BEGIN PRIVATE/);
  assert.throws(() => verifyHolderProof({ ...input }), rejected('HOLDER_PROOF_REQUIRED'));
  const segments = holderProof.split('.'), sig = Buffer.from(segments[2], 'base64url'); sig[7] ^= 1;
  segments[2] = sig.toString('base64url');
  assert.throws(() => verifyHolderProof({ ...input, holderProof: segments.join('.') }), rejected('HOLDER_SIGNATURE_INVALID'));
  for (const changed of [{ ...context, phase: 'settle' }, { ...context, bodyHash: token() }, { ...context, verifier: generateIdentity('other verifier').did }, { ...context, nonce: token() }]) {
    assert.throws(() => verifyHolderProof({ ...input, context: changed, holderProof }), rejected('HOLDER_BINDING_MISMATCH'));
  }
  const another = await deriveCredential({ credential: original, issuerProfile, presentationHeader: presentationHeader(context) });
  assert.throws(() => verifyHolderProof({ ...input, verifiableCredential: another, holderProof }), rejected('HOLDER_BINDING_MISMATCH'));
  assert.throws(() => verifyHolderProof({ ...input, presentation: { ...presentation, Abar: presentation.Cbar }, holderProof }), rejected('HOLDER_BINDING_MISMATCH'));
  assert.throws(() => signHolderProof({ ...input, identity: generateIdentity('not A') }), rejected('HOLDER_BINDING_MISMATCH'));
  const disclosed = await deriveCredential({ credential: original, issuerProfile, presentationHeader: presentationHeader(context), disclosedFields: ['organization'] });
  assert.equal(disclosed.credentialSubject.organization, organization);
  assert.equal(disclosed.credentialSubject.holderLabel, undefined);
  assert.equal(await createW3cBbsVerifier(issuerProfile).verifyDerived({ credential: disclosed, presentationHeader: presentationHeader(context) }), true);
  await assert.rejects(deriveCredential({ credential: original, issuerProfile, presentationHeader: presentationHeader(context), disclosedFields: ['holderDid'] }), rejected('W3C_BBS_DISCLOSURE_POLICY'));
});

test('issuer status table persists revocation and refuses unknown records', async t => {
  const directory = await mkdtemp(join(tmpdir(), 'framework-status-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const statePath = join(directory, 'credential-status.json'), store = createCredentialStatusStore({ statePath });
  const bindingId = `urn:uuid:${randomUUID()}`;
  store.issue({ bindingId, issuer: 'did:example:issuer', deviceId: 'default', holderDid: generateIdentity('A').did });
  assert.equal(store.status(bindingId).status, 'valid');
  store.revoke(bindingId);
  assert.equal(createCredentialStatusStore({ statePath }).status(bindingId).status, 'revoked');
  assert.equal(store.status(`urn:uuid:${randomUUID()}`).status, 'unknown');
  assert.throws(() => store.revoke(`urn:uuid:${randomUUID()}`), rejected('W3C_CREDENTIAL_STATUS_UNKNOWN'));
  assert.doesNotMatch(await readFile(statePath, 'utf8'), /secretKey|privateKey|accessToken/);
});

test('management capabilities control device creation, locking, signing, issuer revocation and read-only status', async t => {
  const accessToken = token(), issuerAccess = token(), statusToken = token();
  const device = createDbacDevice({ accessToken }), deviceUrl = await device.listen(); t.after(() => device.close());
  const issuer = createDbacIssuer({ accessToken: issuerAccess, statusToken, devicePublicKeys: device.publicInfo().publicKeys, w3c: true, requireHolderProof: true });
  const issuerUrl = await issuer.listen(); t.after(() => issuer.close());
  const call = async (url, path, capability, body, deviceId) => {
    const response = await fetch(`${url}${path}`, { method: body === undefined ? 'GET' : 'POST', headers: { 'Content-Type': 'application/json', ...(capability ? { 'X-DBAC-Access': capability } : {}), ...(deviceId ? { 'X-DBAC-Device': deviceId } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const result = await response.json();
    if (!response.ok) throw Object.assign(new Error(result.error.message), result.error);
    return result;
  };
  await assert.rejects(call(deviceUrl, '/devices', null, {}), rejected('DBAC_ACCESS_DENIED'));
  const created = await call(deviceUrl, '/devices', accessToken, {});
  assert.notEqual(created.publicKeys['bbs-bls'], device.publicInfo().publicKeys['bbs-bls']);
  await call(issuerUrl, '/devices/register', issuerAccess, { deviceId: created.deviceId, publicKeys: created.publicKeys });
  await assert.rejects(call(issuerUrl, '/enroll/challenge', issuerAccess, { mode: 'bbs-bls', scope: 'payments:pay' }), rejected('HOLDER_KEY_REQUIRED'));
  const identity = generateIdentity('A'), mode = 'bbs-bls';
  const enrollment = await call(issuerUrl, '/enroll/challenge', issuerAccess, { mode, scope: 'payments:pay', holderDid: identity.did, deviceId: created.deviceId });
  const response = await call(deviceUrl, '/enroll/sign', accessToken, { mode, request: enrollment.request }, created.deviceId);
  const issued = await call(issuerUrl, '/issue', issuerAccess, { registrationId: enrollment.registrationId, response });
  assert.equal(issued.credential.devicePublicKey, created.publicKeys[mode]);
  assert.equal(issued.verifiableCredential.credentialSubject.holderDid, identity.did);
  const read = createCredentialStatusReader({ baseUrl: issuerUrl, accessToken: statusToken });
  const statusInput = { bindingId: enrollment.bindingId, issuer: issuer.publicInfo().w3c.issuer, holderDid: identity.did };
  const observedStatuses = [], observe = { onStatus: value => observedStatuses.push(value) };
  assert.equal((await read(statusInput, observe)).status, 'valid');
  assert.equal(observedStatuses.at(-1).status, 'valid');
  await assert.rejects(read({ ...statusInput, holderDid: generateIdentity('wrong holder').did }, observe), rejected('W3C_CREDENTIAL_STATUS_MISMATCH'));
  assert.equal(observedStatuses.length, 1, 'mismatched identity is not a trusted status observation');
  await assert.rejects(call(issuerUrl, '/credentials/revoke', statusToken, { bindingId: enrollment.bindingId }), rejected('DBAC_ACCESS_DENIED'));
  await assert.rejects(call(issuerUrl, '/issue', null, { registrationId: enrollment.registrationId, response }), rejected('DBAC_ACCESS_DENIED'));
  await call(deviceUrl, '/lock', accessToken, { mode, locked: true }, created.deviceId);
  await assert.rejects(call(deviceUrl, '/sign', accessToken, enrollment.request, created.deviceId), rejected('DBAC_DEVICE_LOCKED'));
  await assert.rejects(call(deviceUrl, '/sign', null, enrollment.request, created.deviceId), rejected('DBAC_ACCESS_DENIED'));
  await call(deviceUrl, '/lock', accessToken, { mode, locked: false }, created.deviceId);
  const inventory = await call(deviceUrl, '/devices', accessToken), selected = inventory.devices.find(entry => entry.deviceId === created.deviceId);
  assert.equal(selected.modes[mode].signatures, 1);
  assert.equal(selected.modes[mode].denied, 1);
  assert.equal(selected.logs.find(log => log.operation === 'sign').outcome, 'DBAC_DEVICE_LOCKED');
  assert.doesNotMatch(JSON.stringify(inventory), /secretKey|privateKey|context|nonce|accessToken/);
  await call(issuerUrl, '/credentials/revoke', issuerAccess, { bindingId: enrollment.bindingId });
  await assert.rejects(read(statusInput, observe), rejected('W3C_CREDENTIAL_REVOKED'));
  assert.equal(observedStatuses.at(-1).status, 'revoked');
  await assert.rejects(read({ ...statusInput, bindingId: `urn:uuid:${randomUUID()}` }, observe), rejected('W3C_CREDENTIAL_STATUS_UNKNOWN'));
  assert.equal(observedStatuses.at(-1).status, 'unknown');
  assert.deepEqual(observedStatuses.map(value => value.status), ['valid', 'revoked', 'unknown']);
  for (const value of observedStatuses) {
    assert.deepEqual(Object.keys(value), ['status', 'bindingId', 'source', 'checkedAt']);
    assert.equal(value.source, 'trusted-local-issuer');
    assert.ok(Number.isFinite(Date.parse(value.checkedAt)));
  }
  await assert.rejects(createCredentialStatusReader({ baseUrl: issuerUrl, accessToken: token() })(statusInput, observe), rejected('W3C_CREDENTIAL_STATUS_UNAVAILABLE'));
  assert.equal(observedStatuses.length, 3, 'denied or unavailable status query cannot fabricate an observation');
});

test('cancellation needs its independent capability and terminates only the unconsumed authentication attempt', async t => {
  const identity = generateIdentity('B'), issuer = generateIssuerKey(), device = generateDeviceKey();
  const mode = 'bbs-bls', credential = issueCredential({ issuerSecretKey: issuer.secretKey, devicePublicKey: device.publicKey, attributes: paymentAttributes(mode) });
  const verifier = createDbacPaymentVerifier({ identity, issuerPublicKey: issuer.publicKey, trustedAuthorizers: [generateIdentity('Owner').did], getBackend: () => null });
  let baseUrl;
  const server = http.createServer({ maxHeaderSize: 24 * 1024 }, async (req, res) => {
    try { await verifier.handle(req, res, baseUrl); }
    catch (error) { sendJson(res, error.status ?? 400, { error: { code: error.code }, verificationTrace: error.verificationTrace }); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); baseUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const post = async (path, value, headers = {}) => {
    const response = await fetch(`${baseUrl}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: typeof value === 'string' ? value : JSON.stringify(value) });
    const result = await response.json();
    if (!response.ok) throw Object.assign(new Error(result.error.code), result.error, { verificationTrace: result.verificationTrace });
    return result;
  };
  const payment = { orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 29900, currency: 'CNY' };
  const raw = JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: { message: { kind: 'message', role: 'user', messageId: randomUUID(), parts: [{ kind: 'data', data: { scope: 'payments:pay', phase: 'proposal', payment } }] } } });
  const prepare = async () => {
    const envelope = await post('/dbac/payment/challenge', { mode, bodyHash: digest(raw), paymentOrderId: payment.orderId });
    const context = verifyJws(envelope.challenge, { typ: DBAC_PAYMENT_CHALLENGE_TYP, expectedDid: identity.did }).payload.context;
    assert.equal(JSON.stringify(context).includes('cancelToken'), false);
    const prepared = preparePresentation({ credential, mode, context, disclosedIndices: [0, 1, 2, 3] });
    const presentation = finalizePresentation({ state: prepared.state, response: signDeviceRequest({ deviceSecretKey: device.secretKey, request: prepared.request }) });
    return { context, presentation, cancelToken: envelope.cancelToken };
  };
  const transmit = prepared => post('/dbac/payment/a2a', raw, { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Challenge': prepared.context.challengeId, 'X-A2A-DBAC-Proof': Buffer.from(JSON.stringify(prepared.presentation)).toString('base64url') });
  const first = await prepare(), second = await prepare();
  await assert.rejects(post('/dbac/payment/cancel', { challengeId: first.context.challengeId, cancelToken: second.cancelToken }), rejected('DBAC_CANCEL_DENIED'));
  await post('/dbac/payment/cancel', { challengeId: first.context.challengeId, cancelToken: first.cancelToken });
  await assert.rejects(transmit(first), error => error.code === 'DBAC_CHALLENGE_CANCELLED' && error.verificationTrace.steps.find(step => step.id === 'consume').status === 'skipped');
  assert.equal((await transmit(second)).result.status.state, 'completed');
  await assert.rejects(post('/dbac/payment/cancel', { challengeId: second.context.challengeId, cancelToken: second.cancelToken }), rejected('DBAC_ALREADY_PROCESSED'));
  await assert.rejects(transmit(second), rejected('DBAC_REPLAY'));
  await assert.rejects(post('/dbac/payment/cancel', { challengeId: randomUUID(), cancelToken: token() }), rejected('DBAC_CHALLENGE_EXPIRED'));
});
