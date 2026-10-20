import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import Ajv from 'ajv';
import { startDbacDemo } from '../lib/dbac/runtime.mjs';
import { createDbacSession, dbacFetch } from '../lib/dbac/session.mjs';
import { preparePresentation, finalizePresentation, verifyDeviceResponse, DBAC_VERSION, DBAC_SUITE } from '../lib/dbac/crypto.mjs';
import { DBAC_EXTENSION, DBAC_MODES, DBAC_SCHEMA } from '../lib/dbac/policy.mjs';
import { bls12_381 as bls } from '@noble/curves/bls12-381';

const ajv = new Ajv({ strict: false, allErrors: true, validateFormats: false });
ajv.addSchema(JSON.parse(readFileSync(new URL('../vendor/a2a-v0.3.0.schema.json', import.meta.url))), 'a2a-0.3.0');
const official = Object.fromEntries(['AgentCard', 'SendMessageRequest', 'SendMessageSuccessResponse'].map(type => [type, ajv.compile({ $ref: `a2a-0.3.0#/definitions/${type}` })]));
function conforms(type, value) {
  assert.equal(official[type](value), true, `${type}: ${ajv.errorsText(official[type].errors)}`);
}

test('paper profile uses four real processes and enforces cryptographic and application boundaries', { timeout: 90000 }, async t => {
  const runtime = await startDbacDemo();
  t.after(() => runtime.close());
  const api = async (path, body, key = runtime.uiToken) => {
    const response = await fetch(`${runtime.a.baseUrl}${path}`, { method: body === undefined ? 'GET' : 'POST', headers: { ...(key ? { 'X-Demo-UI-Key': key } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, data: await response.json() };
  };
  const session = createDbacSession({ ...runtime.profile, baseUrl: runtime.b.baseUrl, verifierDid: runtime.verifierDid });
  await t.test('roles have separate processes and no private keys in public state', async () => {
    assert.equal(new Set(runtime.pids).size, 4);
    assert.ok(!runtime.pids.includes(process.pid));
    assert.notEqual(runtime.device.publicKeys['bbs-bls'], runtime.device.publicKeys['bbs-blind-bls']);
    const state = await api('/api/dbac/state?mode=bbs-bls');
    assert.equal(state.status, 200);
    assert.equal(state.data.device.hardware, false);
    assert.equal(state.data.credential, null);
    assert.doesNotMatch(JSON.stringify(state.data), /secretKey|privateKey|accessToken/);
    assert.equal((await api('/api/dbac/issue', { mode: 'bbs-bls' }, '')).data.error.code, 'UI_ACCESS_DENIED');
    assert.equal((await api('/api/payment/pay', {})).data.error.code, 'DBAC_ONLY');
    const health = (await api('/api/health')).data;
    assert.equal(health.securityProfile, DBAC_EXTENSION);
    assert.equal(health.paymentProtocol, null);
    for (const path of ['/.well-known/agent-card.json', '/dbac/agent-card.json']) {
      const card = await dbacFetch(`${runtime.b.baseUrl}${path}`);
      conforms('AgentCard', card);
      assert.equal(card.url, `${runtime.b.baseUrl}/dbac/a2a`);
      assert.deepEqual(card.skills.map(skill => skill.id), ['demo:echo']);
      assert.equal(card.capabilities.extensions[0].uri, DBAC_EXTENSION);
    }
  });
  await t.test('issuer refuses credential-only issuance, injected attributes and absent access capability', async () => {
    await assert.rejects(dbacFetch(`${runtime.issuer.baseUrl}/issue`, { token: runtime.profile.issuer.accessToken, body: {} }), { code: 'DBAC_ISSUANCE_POLICY' });
    await assert.rejects(dbacFetch(`${runtime.issuer.baseUrl}/enroll/challenge`, { token: runtime.profile.issuer.accessToken, body: { mode: 'bbs-bls', attributes: ['administrator'] } }), { code: 'DBAC_ISSUANCE_POLICY' });
    await assert.rejects(dbacFetch(`${runtime.issuer.baseUrl}/enroll/challenge`, { body: { mode: 'bbs-bls' } }), { code: 'DBAC_ACCESS_DENIED' });
  });
  for (const mode of DBAC_MODES) {
    await t.test(`${mode}: actual A → device → B invocation and 11 negative/privacy checks`, async () => {
      const result = await api('/api/dbac/demo', { mode });
      assert.equal(result.status, 200, JSON.stringify(result.data));
      assert.equal(result.data.passed, 11);
      assert.equal(result.data.total, 11);
      assert.equal(result.data.privacyEvidence.stableDeviceKeyAbsent, true);
      assert.equal(result.data.privacyEvidence.hiddenValuesAbsent, true);
      assert.equal(result.data.privacyEvidence.deviceSeesContext, mode === 'bbs-bls');
      const state = (await api(`/api/dbac/state?mode=${mode}`)).data;
      assert.equal(state.credential.attributes.length, DBAC_SCHEMA.length);
      assert.equal(state.credential.attributes[3].value, mode);
      assert.equal(state.credential.attributes[5].disclosed, false);
      assert.doesNotMatch(JSON.stringify(state.lastResult.wire), /Alice \/ Agent A|Competition team|did:key|secretKey|privateKey/);
      assert.ok(!JSON.stringify(state.lastResult.wire).includes(runtime.device.publicKeys[mode]));
      conforms('SendMessageRequest', state.lastResult.wire.body);
      conforms('SendMessageSuccessResponse', { jsonrpc: '2.0', id: state.lastResult.wire.body.id, result: state.lastResult.task });
    });
  }
  await t.test('mode locks and credentials are isolated', async () => {
    await api('/api/dbac/device/lock', { mode: 'bbs-bls', locked: true });
    assert.equal((await api('/api/dbac/invoke', { mode: 'bbs-bls' })).data.error.code, 'DBAC_DEVICE_LOCKED');
    assert.equal((await api('/api/dbac/invoke', { mode: 'bbs-blind-bls' })).data.accepted, true);
    await api('/api/dbac/device/lock', { mode: 'bbs-bls', locked: false });
  });
  await t.test('B rejects identity headers, mode changes and payment through anonymous profile', async () => {
    await session.issue({ mode: 'bbs-bls' });
    const prepared = await session.prepare({ mode: 'bbs-bls' });
    const headers = { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Challenge': prepared.context.challengeId, 'X-A2A-DBAC-Proof': Buffer.from(JSON.stringify(prepared.presentation)).toString('base64url') };
    await assert.rejects(dbacFetch(`${runtime.b.baseUrl}/dbac/a2a`, { rawBody: prepared.rawBody, headers: { ...headers, Authorization: 'Bearer stable-identity' } }), { code: 'DBAC_IDENTIFIED_HEADERS' });
    const altered = structuredClone(prepared); altered.presentation.mode = 'bbs-blind-bls';
    await assert.rejects(session.transmit(altered), { code: 'DBAC_MODE_MISMATCH' });
    const paymentRpc = JSON.parse(prepared.rawBody); paymentRpc.params.message.parts[0].data.scope = 'payments:pay';
    // Bind a fresh challenge to the payment body: refusal must be scope, not merely the old body hash.
    const { createHash } = await import('node:crypto');
    const rawBody = JSON.stringify(paymentRpc);
    const challenge = await dbacFetch(`${runtime.b.baseUrl}/dbac/challenge`, { body: { mode: 'bbs-bls', bodyHash: createHash('sha256').update(rawBody).digest('base64url') } });
    const { verifyJws } = await import('../lib/identity.mjs');
    const context = verifyJws(challenge.challenge, { typ: 'a2a-dbac-challenge+jwt', expectedDid: runtime.verifierDid }).payload.context;
    await assert.rejects(dbacFetch(`${runtime.b.baseUrl}/dbac/a2a`, { rawBody, headers: { ...headers, 'X-A2A-DBAC-Challenge': context.challengeId } }), { code: 'DBAC_SCOPE_DENIED' });
    assert.equal((await session.transmit(prepared)).accepted, true, 'invalid requests must not consume a valid challenge');
  });
  await t.test('registered device proof is required, one-use, and a valid proof omitting scope is refused', async () => {
    const mode = 'bbs-bls';
    const registration = await dbacFetch(`${runtime.issuer.baseUrl}/enroll/challenge`, { token: runtime.profile.issuer.accessToken, body: { mode } });
    const response = await dbacFetch(`${runtime.device.baseUrl}/enroll/sign`, { token: runtime.profile.device.accessToken, body: { mode, request: registration.request } });
    verifyDeviceResponse({ devicePublicKey: runtime.device.publicKeys[mode], request: registration.request, response });
    const issued = await dbacFetch(`${runtime.issuer.baseUrl}/issue`, { token: runtime.profile.issuer.accessToken, body: { registrationId: registration.registrationId, response } });
    await assert.rejects(dbacFetch(`${runtime.issuer.baseUrl}/issue`, { token: runtime.profile.issuer.accessToken, body: { registrationId: registration.registrationId, response } }), { code: 'DBAC_REGISTRATION_EXPIRED' });
    const prepared = await session.prepare({ mode });
    const proof = preparePresentation({ credential: issued.credential, context: prepared.context, disclosedIndices: [0, 2, 3], mode });
    const signed = await dbacFetch(`${runtime.device.baseUrl}/sign`, { token: runtime.profile.device.accessToken, body: proof.request });
    prepared.presentation = finalizePresentation({ state: proof.state, response: signed });
    await assert.rejects(session.transmit(prepared), { code: 'DBAC_POLICY_REJECTED' });
  });
  await t.test('blind endpoint uses another key, so it cannot supply the ordinary device signature', async () => {
    const prepared = await session.prepare({ mode: 'bbs-bls' });
    const Q = bls.G2.hashToCurve(new TextEncoder().encode('cross-mode test'));
    const request = { version: DBAC_VERSION, suite: DBAC_SUITE, mode: 'bbs-blind-bls', blindedPoint: Q.toHex(true) };
    const response = await dbacFetch(`${runtime.device.baseUrl}/sign`, { token: runtime.profile.device.accessToken, body: request });
    assert.equal(verifyDeviceResponse({ devicePublicKey: runtime.device.publicKeys['bbs-blind-bls'], request, response }), true);
    assert.throws(() => verifyDeviceResponse({ devicePublicKey: runtime.device.publicKeys['bbs-bls'], request, response }));
    await assert.rejects(dbacFetch(`${runtime.device.baseUrl}/enroll/sign`, { token: runtime.profile.device.accessToken, body: { mode: 'bbs-blind-bls', request: prepared.deviceRequest } }), { code: 'DBAC_ISSUANCE_POLICY' });
  });
  await t.test('stopping the device fails closed, with no host signing fallback', async () => {
    process.kill(runtime.device.pid, 'SIGTERM');
    // Runtime supervises all peer processes; either signing fails or A itself exits.
    await assert.rejects(session.prepare({ mode: 'bbs-bls' }));
  });
});
