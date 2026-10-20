import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import Ajv from 'ajv';
import { generateIdentity, issueCredential, signJws, verifyJws } from '../lib/identity.mjs';
import { createVerifier } from '../lib/verifier.mjs';
import { createSession } from '../lib/session.mjs';
import { createEsim } from '../lib/esim.mjs';
import { EXTENSION, SCOPE, POP_TYP, DEVICE_POP_TYP, RESPONSE_TYP, digest, unix, messageRpc, prepareRequest, transmit, getChallenge, makeAuthorization } from '../lib/protocol.mjs';

const official = JSON.parse(readFileSync(new URL('../vendor/a2a-v0.3.0.schema.json', import.meta.url)));
const ajv = new Ajv({ strict: false, allErrors: true, validateFormats: false });
ajv.addSchema(official, 'a2a-0.3.0');
const validators = new Map();
function conforms(type, value) {
  if (!validators.has(type)) validators.set(type, ajv.compile({ $ref: `a2a-0.3.0#/definitions/${type}` }));
  const validate = validators.get(type);
  assert.equal(validate(value), true, `${type}: ${ajv.errorsText(validate.errors)}`);
}

test('official A2A 0.3.0 schema and real HTTP DID/VC security enforcement', { timeout: 30000 }, async t => {
  const issuer = generateIdentity('Issuer'), a = generateIdentity('A'), b = generateIdentity('B'), other = generateIdentity('Other');
  // These private keys are HTTP test fixtures only. The actual simulator owns
  // its device key internally and exposes only a constrained signing API.
  const deviceA = generateIdentity('A test device'), deviceOther = generateIdentity('Other test device');
  const deviceFor = identity => identity.did === other.did ? deviceOther : deviceA;
  const adminToken = randomUUID();
  const verifier = createVerifier({ identity: b, trustedIssuers: new Set([issuer.did]), adminToken });
  const baseUrl = await verifier.listen();
  t.after(() => verifier.close());
  const credential = (holder = a, options = {}, authority = issuer) => issueCredential(authority, { subjectDid: holder.did, audience: b.did, scopes: [SCOPE], deviceDid: deviceFor(holder).did, ...options });
  const token = credential();
  function withDeviceProof(request, signingDevice = deviceFor(request.identity), overrides = {}) {
    const holder = verifyJws(request.token, { typ: POP_TYP }).payload;
    const claims = {
      iss: signingDevice.did, sub: holder.iss, aud: holder.aud,
      iat: unix(), exp: Math.min(unix() + 60, holder.exp), jti: randomUUID(),
      holderProofHash: digest(request.token), credentialHash: digest(holder.credential),
      challengeId: holder.challengeId, nonce: holder.nonce, method: holder.method,
      target: holder.target, bodyHash: holder.bodyHash, ...overrides,
    };
    return { ...request, deviceDid: signingDevice.did, deviceProof: signJws(claims, signingDevice, DEVICE_POP_TYP) };
  }
  const prepare = async (rpc = messageRpc(), identity = a, vc = token, overrides) => withDeviceProof(await prepareRequest({ identity, credential: vc, verifierDid: b.did, baseUrl, rpc, overrides }));
  const invoke = async (...args) => transmit(await prepare(...args));
  async function wire(request, headers = {}) {
    const response = await fetch(`${baseUrl}/a2a`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${request.token}`, 'X-A2A-Extensions': EXTENSION, ...(request.deviceProof ? { 'X-A2A-Device-Proof': request.deviceProof } : {}), ...headers }, body: request.rawBody });
    const raw = await response.text(), body = JSON.parse(raw);
    if (response.status === 200) {
      const { payload } = verifyJws(response.headers.get('X-A2A-DID-Response'), { typ: RESPONSE_TYP, expectedDid: b.did });
      assert.equal(payload.requestHash, digest(request.rawBody)); assert.equal(payload.responseHash, digest(raw));
      assert.equal(payload.aud, request.identity.did); assert.equal(payload.nonce, request.challenge.nonce);
      assert.equal(payload.deviceDid, request.deviceDid); assert.equal(payload.deviceProofHash, digest(request.deviceProof));
    }
    return { response, body };
  }
  let task;
  await t.test('discovery, message/send and task outputs validate against exact official definitions', async () => {
    const card = await (await fetch(`${baseUrl}/.well-known/agent-card.json`)).json();
    conforms('AgentCard', card);
    assert.equal(card.protocolVersion, '0.3.0'); assert.equal(card.capabilities.extensions[0].required, true);
    assert.equal(card.capabilities.extensions[0].uri, EXTENSION);
    assert.equal(card.capabilities.extensions[0].params.requireDevice, true);
    assert.equal(card.capabilities.extensions[0].params.deviceProofHeader, 'X-A2A-Device-Proof');
    const rpc = messageRpc('标准接口验证'); conforms('SendMessageRequest', rpc);
    const { response, body } = await wire(await prepare(rpc));
    assert.equal(response.status, 200); assert.equal(response.headers.get('X-A2A-Extensions'), EXTENSION);
    conforms('SendMessageSuccessResponse', body); conforms('Task', body.result); task = body.result;
    assert.equal(task.status.state, 'completed'); assert.equal(task.artifacts[0].parts[1].data.holderDid, a.did);
  });
  await t.test('authenticated task lookup supports historyLength=0 and does not mutate stored history', async () => {
    const rpc = { jsonrpc: '2.0', id: 'get-1', method: 'tasks/get', params: { id: task.id, historyLength: 0 } };
    conforms('GetTaskRequest', rpc);
    const { body } = await wire(await prepare(rpc)); conforms('GetTaskSuccessResponse', body); assert.deepEqual(body.result.history, []);
    delete rpc.params.historyLength; assert.equal((await invoke(rpc)).task.history.length, 2);
  });
  await t.test('tasks/cancel returns the standard terminal-task error and unknown tasks stay hidden', async () => {
    const rpc = { jsonrpc: '2.0', id: 1, method: 'tasks/cancel', params: { id: task.id } };
    conforms('CancelTaskRequest', rpc);
    const { body } = await wire(await prepare(rpc)); conforms('CancelTaskResponse', body); assert.equal(body.error.code, -32002);
    rpc.params.id = randomUUID(); await assert.rejects(invoke(rpc), { code: -32001 });
  });
  await t.test('other legitimately credentialed holders cannot read, cancel or continue a task/context', async () => {
    const otherToken = credential(other);
    for (const method of ['tasks/get', 'tasks/cancel']) await assert.rejects(invoke({ jsonrpc: '2.0', id: randomUUID(), method, params: { id: task.id } }, other, otherToken), { code: -32001 });
    const rpc = messageRpc(); rpc.params.message.taskId = task.id;
    await assert.rejects(invoke(rpc, other, otherToken), { code: -32001 });
    delete rpc.params.message.taskId; rpc.params.message.contextId = task.contextId;
    await assert.rejects(invoke(rpc, other, otherToken), { code: -32602 });
    assert.equal((await invoke(rpc)).task.contextId, task.contextId);
  });
  await t.test('Bearer authentication and extension negotiation are mandatory', async () => {
    const request = await prepare();
    let result = await wire(request, { Authorization: '' });
    assert.equal(result.response.status, 401); assert.match(result.response.headers.get('www-authenticate'), /^Bearer /);
    result = await wire(request, { 'X-A2A-Extensions': '' }); assert.equal(result.body.error.data.reason, 'EXTENSION_REQUIRED');
    result = await wire(request, { 'X-A2A-Extensions': 'https://example.org/a2a-did-vc/v1' }); assert.equal(result.body.error.data.reason, 'EXTENSION_REQUIRED');
    // Failed validation has not consumed another caller's challenge.
    assert.equal((await transmit(request)).task.status.state, 'completed');
  });
  await t.test('copied VC, modified VC and untrusted/future/expired/wrong-scope/wrong-audience credentials fail closed', async () => {
    await assert.rejects(invoke(messageRpc(), other), { code: 'CREDENTIAL_SUBJECT_MISMATCH' });
    const parts = token.split('.'); const document = JSON.parse(Buffer.from(parts[1], 'base64url')); document.credentialSubject.scopes.push('admin:write'); parts[1] = Buffer.from(JSON.stringify(document)).toString('base64url');
    await assert.rejects(invoke(messageRpc(), a, parts.join('.')), { code: 'INVALID_SIGNATURE' });
    for (const [vc, code] of [
      [credential(a, {}, other), 'CREDENTIAL_UNTRUSTED_ISSUER'],
      [credential(a, { validFrom: Date.now() + 60000 }), 'CREDENTIAL_NOT_YET_VALID'],
      [credential(a, { validFrom: Date.now() - 120000, validUntil: Date.now() - 60000 }), 'CREDENTIAL_EXPIRED'],
      [credential(a, { scopes: ['admin:write'] }), 'CREDENTIAL_SCOPE_DENIED'],
      [credential(a, { audience: other.did }), 'CREDENTIAL_AUDIENCE_MISMATCH'],
    ]) await assert.rejects(invoke(messageRpc(), a, vc), { code });
  });
  await t.test('PoP binds subject, nonce, receiving DID, exact bytes, target, method and short validity', async () => {
    for (const [overrides, code] of [
      [{ iss: other.did }, 'PROOF_IDENTITY_MISMATCH'], [{ aud: other.did }, 'PROOF_IDENTITY_MISMATCH'],
      [{ nonce: 'wrong' }, 'INVALID_CHALLENGE'], [{ challengeId: 'unknown' }, 'INVALID_CHALLENGE'],
      [{ target: `${baseUrl}/other` }, 'INVALID_CHALLENGE'], [{ method: 'GET' }, 'REQUEST_BINDING_MISMATCH'],
      [{ exp: unix() - 1 }, 'PROOF_EXPIRED'], [{ exp: 'invalid' }, 'PROOF_EXPIRED'],
      [{ iat: unix() + 30 }, 'PROOF_EXPIRED'], [{ bodyHash: 'wrong' }, 'REQUEST_BINDING_MISMATCH'],
    ]) await assert.rejects(invoke(messageRpc(), a, token, overrides), { code });
    const request = await prepare(messageRpc('original')); request.rawBody = request.rawBody.replace('original', 'tampered');
    await assert.rejects(transmit(request), { code: 'REQUEST_BINDING_MISMATCH' });
  });
  await t.test('concurrent use of one challenge creates exactly one task', async () => {
    const request = await prepare();
    const attempts = await Promise.allSettled(Array.from({ length: 16 }, () => transmit(request)));
    assert.equal(attempts.filter(x => x.status === 'fulfilled').length, 1);
    assert.equal(attempts.filter(x => x.status === 'rejected' && x.reason.code === 'REPLAYED_CHALLENGE').length, 15);
  });
  await t.test('a signature from another private key cannot authenticate as A', async () => {
    const request = await prepare(); const claims = verifyJws(request.token, { typ: POP_TYP }).payload;
    request.token = signJws(claims, other, POP_TYP);
    await assert.rejects(transmit(request), { code: 'PROOF_IDENTITY_MISMATCH' });
  });
  await t.test('a valid VC and the Agent A private key alone do not satisfy the required device proof', async () => {
    const request = await prepare();
    const holderOnly = { ...request }; delete holderOnly.deviceProof; delete holderOnly.deviceDid;
    await assert.rejects(transmit(holderOnly), { code: 'DEVICE_PROOF_REQUIRED' });
    const result = await transmit(request);
    assert.equal(result.verification.deviceSignature, true);
    assert.equal(result.verification.deviceDid, deviceA.did);
  });
  await t.test('a different device cannot substitute its valid signature for the VC-bound device', async () => {
    const request = await prepare();
    await assert.rejects(transmit(withDeviceProof(request, deviceOther)), { code: 'INVALID_DEVICE_SIGNATURE' });
    assert.equal((await transmit(request)).task.status.state, 'completed');
  });
  await t.test('device proofs require current short-lived numeric timestamps and a valid proof identifier', async () => {
    const request = await prepare();
    for (const change of [
      { iat: unix() - 70, exp: unix() - 10 },
      { iat: unix() + 30, exp: unix() + 40 },
      { iat: unix() - 2, exp: unix() + 60 },
      { exp: 'tomorrow' }, { exp: null }, { iat: null }, { jti: '' }, { jti: 3 },
    ]) await assert.rejects(transmit(withDeviceProof(request, deviceA, change)), { code: 'DEVICE_PROOF_EXPIRED' });
    assert.equal((await transmit(request)).task.status.state, 'completed');
  });
  await t.test('device proofs bind holder, audience, credential, challenge and exact HTTP request fields', async () => {
    const request = await prepare();
    for (const change of [
      { iss: deviceOther.did }, { sub: other.did }, { aud: other.did },
      { holderProofHash: digest('another holder proof') }, { credentialHash: digest(credential()) },
      { challengeId: randomUUID() }, { nonce: 'another nonce' }, { method: 'GET' },
      { target: `${baseUrl}/other` }, { bodyHash: digest('another request') },
    ]) await assert.rejects(transmit(withDeviceProof(request, deviceA, change)), { code: 'DEVICE_PROOF_BINDING_MISMATCH' });
    assert.equal((await transmit(request)).task.status.state, 'completed');
  });
  await t.test('a reissued holder JWT cannot reuse a device signature over the preceding JWT bytes', async () => {
    const request = await prepare();
    const claims = verifyJws(request.token, { typ: POP_TYP }).payload;
    const reissued = { ...request, token: signJws({ ...claims, jti: randomUUID() }, a, POP_TYP) };
    await assert.rejects(transmit(reissued), { code: 'DEVICE_PROOF_BINDING_MISMATCH' });
    assert.equal((await transmit(request)).task.status.state, 'completed');
  });
  await t.test('device proofs cannot cross fresh verifier challenges or newly issued credentials', async () => {
    const rpc = messageRpc();
    const original = await prepare(rpc);
    const nextChallenge = await prepare(rpc);
    await assert.rejects(transmit({ ...nextChallenge, deviceProof: original.deviceProof }), { code: 'DEVICE_PROOF_BINDING_MISMATCH' });
    const claims = verifyJws(original.token, { typ: POP_TYP }).payload;
    const nextCredential = { ...original, token: signJws({ ...claims, credential: credential(), jti: randomUUID() }, a, POP_TYP) };
    await assert.rejects(transmit(nextCredential), { code: 'DEVICE_PROOF_BINDING_MISMATCH' });
    assert.equal((await transmit(nextChallenge)).task.status.state, 'completed');
    assert.equal((await transmit(original)).task.status.state, 'completed');
  });
  await t.test('tampered device proof bytes fail signature verification and do not consume the challenge', async () => {
    const request = await prepare();
    const parts = request.deviceProof.split('.');
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
    claims.bodyHash = digest('tampered bytes');
    parts[1] = Buffer.from(JSON.stringify(claims)).toString('base64url');
    await assert.rejects(transmit({ ...request, deviceProof: parts.join('.') }), { code: 'INVALID_DEVICE_SIGNATURE' });
    assert.equal((await transmit(request)).task.status.state, 'completed');
  });
  await t.test('legacy one-signer credentials cannot downgrade the network device policy', async () => {
    const noDeviceToken = credential(a, { deviceDid: undefined });
    const request = await prepare(messageRpc(), a, noDeviceToken);
    await assert.rejects(transmit(request), { code: 'CREDENTIAL_DEVICE_REQUIRED' });
    const legacy = verifyJws(noDeviceToken, { typ: 'vc+jwt', purpose: 'assertionMethod' }).payload;
    delete legacy['@context'][1].deviceDid;
    await assert.rejects(invoke(messageRpc(), a, signJws(legacy, issuer, 'vc+jwt')), { code: 'CREDENTIAL_DEVICE_REQUIRED' });
  });
  await t.test('nonce consumption happens only after both proofs pass, then rejects further dual-signed use', async () => {
    const request = await prepare();
    const parts = request.token.split('.');
    const signature = Buffer.from(parts[2], 'base64url'); signature[0] ^= 1; parts[2] = signature.toString('base64url');
    await assert.rejects(transmit({ ...request, token: parts.join('.') }), { code: 'INVALID_SIGNATURE' });
    await assert.rejects(transmit(withDeviceProof(request, deviceOther)), { code: 'INVALID_DEVICE_SIGNATURE' });
    assert.equal((await transmit(request)).task.status.state, 'completed');
    await assert.rejects(transmit(request), { code: 'REPLAYED_CHALLENGE' });
  });
  await t.test('completed responses respect negotiated output formats', async () => {
    for (const [mode, kind] of [['text/plain', 'text'], ['application/json', 'data']]) {
      const rpc = messageRpc(); rpc.params.configuration = { acceptedOutputModes: [mode], historyLength: 1 };
      const result = (await invoke(rpc)).task;
      conforms('Task', result); assert.equal(result.history.length, 1);
      assert.deepEqual(result.artifacts[0].parts.map(p => p.kind), [kind]);
      assert.deepEqual(result.status.message.parts.map(p => p.kind), [kind]);
    }
  });
  await t.test('invalid request shapes and unsupported features use standard JSON-RPC errors', async () => {
    const invalid = [
      [r => { r.id = 1.5; }, -32600], [r => { delete r.id; }, -32600],
      [r => { r.method = 'message/stream'; }, -32601],
      [r => { r.params.metadata = 'bad'; }, -32602],
      [r => { r.params.message.referenceTaskIds = 123; }, -32602],
      [r => { r.params.message.metadata = []; }, -32602],
      [r => { r.params.message.parts[0].metadata = 'bad'; }, -32602],
      [r => { r.params.message.role = 'agent'; }, -32602],
      [r => { r.params.configuration = { blocking: 'yes' }; }, -32602],
      [r => { r.params.configuration = { historyLength: -1 }; }, -32602],
      [r => { r.params.configuration = { pushNotificationConfig: { url: 'https://example.org' } }; }, -32003],
      [r => { r.params.configuration = { acceptedOutputModes: ['image/png'] }; }, -32005],
      [r => { r.params.message.parts = [{ kind: 'file', file: { bytes: 'abc' } }]; }, -32005],
    ];
    for (const [mutate, expected] of invalid) {
      const rpc = messageRpc(); mutate(rpc); const { body } = await wire(await prepare(rpc));
      conforms('JSONRPCErrorResponse', body); assert.equal(body.error.code, expected);
    }
  });
  await t.test('authenticated malformed JSON and batches produce parse/invalid-request errors', async () => {
    for (const [rawBody, code] of [['{', -32700], ['[]', -32600]]) {
      const challenge = await getChallenge({ baseUrl, verifierDid: b.did, identity: a });
      const signed = makeAuthorization({ identity: a, verifierDid: b.did, baseUrl, credential: token, rawBody, challenge });
      const { body } = await wire(withDeviceProof({ baseUrl, verifierDid: b.did, identity: a, rawBody, token: signed, challenge }));
      assert.equal(body.error.code, code); conforms('JSONRPCErrorResponse', body);
    }
  });
  await t.test('administration requires the separate local secret and revocation also blocks existing task access', async () => {
    let response = await fetch(`${baseUrl}/admin/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: 'unknown' }) });
    assert.equal(response.status, 403);
    const id = verifyJws(token, { typ: 'vc+jwt', purpose: 'assertionMethod' }).payload.id;
    response = await fetch(`${baseUrl}/admin/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Demo-Admin': adminToken }, body: JSON.stringify({ id }) });
    assert.equal(response.status, 200);
    await assert.rejects(invoke(), { code: 'CREDENTIAL_REVOKED' });
    await assert.rejects(invoke({ jsonrpc: '2.0', id: randomUUID(), method: 'tasks/get', params: { id: task.id } }), { code: 'CREDENTIAL_REVOKED' });
  });
  await t.test('the complete demonstration uses a real simulated-device signing service and passes every declared case', async () => {
    const accessToken = randomBytes(32).toString('base64url');
    const esim = createEsim({ accessToken, holderDid: a.did, verifierDid: b.did, verifierUrl: baseUrl, trustedIssuers: new Set([issuer.did]) });
    const deviceUrl = await esim.listen();
    try {
      const device = { did: esim.publicInfo().did, baseUrl: deviceUrl, accessToken };
      const session = createSession({ issuer, agentA: a, verifierDid: b.did, baseUrl, adminToken, device });
      const result = await session.demo();
      assert.ok(result.total > 0);
      assert.equal(result.total, result.results.length);
      assert.equal(result.passed, result.total, JSON.stringify(result.results));
      assert.ok(result.results.every(item => item.pass && item.expected === item.actual));
      const agentKeyLeak = result.results.find(item => item.name.includes('私钥泄露') && item.name.includes('无设备权限'));
      const fullSigningAccessLeak = result.results.find(item => item.name.includes('全部泄露') && item.name.includes('边界'));
      assert.equal(agentKeyLeak?.actual, 'DEVICE_PROOF_REQUIRED');
      assert.equal(fullSigningAccessLeak?.actual, 'ACCEPTED');
      assert.equal(session.state().credential.revoked, true);
      const log = await (await fetch(`${deviceUrl}/audit`, { headers: { 'X-ESIM-Access': accessToken } })).json();
      assert.ok(log.entries.some(entry => entry.event === 'signed'), 'the complete flow actually invoked the device signing service');
    } finally { await esim.close(); }
  });
});
