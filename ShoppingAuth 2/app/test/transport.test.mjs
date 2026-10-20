import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';
import test from 'node:test';
import { generateIdentity, signJws, verifyJws } from '../lib/identity.mjs';
import {
  CHALLENGE_TYP,
  EXTENSION,
  MAX_BODY,
  RESPONSE_TYP,
  VERSION,
  digest,
  getChallenge,
  parseObject,
  readBody,
  transmit,
  unix,
} from '../lib/protocol.mjs';

const holder = generateIdentity('transport-holder');
const verifier = generateIdentity('transport-verifier');
const impostor = generateIdentity('transport-impostor');
const device = generateIdentity('transport-device');
const baseUrl = 'http://127.0.0.1:49999';
const nonce = Buffer.alloc(32, 7).toString('base64url');
const rawBody = JSON.stringify({ jsonrpc: '2.0', id: 'request-1', method: 'message/send', params: {} });
const request = { baseUrl, rawBody, token: 'test-token', verifierDid: verifier.did, identity: holder, challenge: { nonce } };
const deviceRequest = { ...request, deviceProof: 'test-device-proof', deviceDid: device.did };
const responseBody = { jsonrpc: '2.0', id: 'request-1', result: { kind: 'task', id: 'task-1', contextId: 'context-1', status: { state: 'completed' } } };

function rejectCode(code) { return error => error.code === code; }

function mockFetch(t, factory) {
  const original = globalThis.fetch;
  const replacement = t.mock.method(globalThis, 'fetch', async (url, options) => factory(url, options));
  t.after(() => {
    replacement.mock.restore();
    assert.equal(globalThis.fetch, original, 'global fetch was restored');
  });
  return replacement;
}

function agentResponse({ status = 200, unsigned = false, signer = verifier, changeProof, body = responseBody, sentText, extension = EXTENSION } = {}) {
  const signedText = JSON.stringify(body);
  const proof = {
    iss: verifier.did,
    aud: holder.did,
    requestHash: digest(rawBody),
    responseHash: digest(signedText),
    nonce,
    iat: unix(),
    exp: unix() + 60,
  };
  changeProof?.(proof);
  const headers = { 'Content-Type': 'application/json' };
  if (extension !== undefined) headers['X-A2A-Extensions'] = extension;
  if (!unsigned) headers['X-A2A-DID-Response'] = signJws(proof, signer, RESPONSE_TYP);
  return new Response(sentText ?? signedText, { status, headers });
}

function challengeResponse({ signer = verifier, changeProof } = {}) {
  const proof = {
    iss: verifier.did,
    aud: holder.did,
    target: `${baseUrl}/a2a`,
    nonce,
    jti: randomUUID(),
    iat: unix(),
    exp: unix() + 60,
  };
  changeProof?.(proof);
  return new Response(JSON.stringify({ challenge: signJws(proof, signer, CHALLENGE_TYP) }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

test('transmit accepts a signed HTTP 200 and verifies the exact request/response bytes', async t => {
  const fetch = mockFetch(t, (url, options) => {
    assert.equal(url, `${baseUrl}/a2a`);
    assert.equal(options.method, 'POST');
    assert.equal(options.body, rawBody);
    assert.equal(options.headers.Authorization, 'Bearer test-token');
    assert.equal(options.headers['X-A2A-Extensions'], EXTENSION);
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    return agentResponse();
  });
  const result = await transmit(request);
  assert.deepEqual(result.task, responseBody.result);
  assert.deepEqual(result.verification, {
    verifierDid: verifier.did,
    responseSignature: true,
    requestBound: true,
    deviceSignature: false,
    extension: EXTENSION,
    protocolVersion: VERSION,
  });
  assert.equal(fetch.mock.callCount(), 1);
});

test('transmit forwards the device proof and checks the verifier receipt binds its exact bytes and DID', async t => {
  mockFetch(t, (_url, options) => {
    assert.equal(options.headers['X-A2A-Device-Proof'], deviceRequest.deviceProof);
    return agentResponse({ changeProof: proof => {
      proof.deviceDid = device.did;
      proof.deviceProofHash = digest(deviceRequest.deviceProof);
    } });
  });
  const result = await transmit(deviceRequest);
  assert.equal(result.verification.deviceSignature, true);
  assert.equal(result.verification.deviceDid, device.did);
  assert.equal(result.verification.responseSignature, true);
});

for (const [label, change] of [
  ['missing device DID', proof => { delete proof.deviceDid; }],
  ['wrong device DID', proof => { proof.deviceDid = impostor.did; }],
  ['missing device-proof hash', proof => { delete proof.deviceProofHash; }],
  ['wrong device-proof hash', proof => { proof.deviceProofHash = digest('different proof'); }],
]) {
  test(`transmit rejects an otherwise valid response with ${label}`, async t => {
    mockFetch(t, () => agentResponse({ changeProof: proof => {
      proof.deviceDid = device.did;
      proof.deviceProofHash = digest(deviceRequest.deviceProof);
      change(proof);
    } }));
    await assert.rejects(transmit(deviceRequest), rejectCode('INVALID_RESPONSE_PROOF'));
  });
}

for (const status of [201, 202]) {
  test(`transmit cannot label an unsigned HTTP ${status} response as verified`, async t => {
    mockFetch(t, () => agentResponse({ status, unsigned: true }));
    await assert.rejects(transmit(request), rejectCode('INVALID_AGENT_RESPONSE'));
  });
}

test('transmit rejects an unsigned HTTP 200', async t => {
  mockFetch(t, () => agentResponse({ unsigned: true }));
  await assert.rejects(transmit(request), rejectCode('MALFORMED_JWS'));
});

test('transmit rejects a response body altered after signing', async t => {
  mockFetch(t, () => agentResponse({ sentText: JSON.stringify({ ...responseBody, result: { ...responseBody.result, id: 'attacker-task' } }) }));
  await assert.rejects(transmit(request), rejectCode('INVALID_RESPONSE_PROOF'));
});

const invalidResponseProofs = [
  ['request hash', proof => { proof.requestHash = digest('another request'); }],
  ['nonce', proof => { proof.nonce = 'another-nonce'; }],
  ['issuer claim', proof => { proof.iss = impostor.did; }],
  ['audience', proof => { proof.aud = impostor.did; }],
  ['expired timestamp', proof => { proof.exp = unix() - 1; }],
  ['missing expiration', proof => { delete proof.exp; }],
  ['non-numeric expiration', proof => { proof.exp = 'tomorrow'; }],
  ['missing issued-at', proof => { delete proof.iat; }],
  ['future issued-at', proof => { proof.iat = unix() + 3600; proof.exp = unix() + 3660; }],
];
for (const [label, changeProof] of invalidResponseProofs) {
  test(`transmit rejects a signed response with invalid ${label}`, async t => {
    mockFetch(t, () => agentResponse({ changeProof }));
    await assert.rejects(transmit(request), rejectCode('INVALID_RESPONSE_PROOF'));
  });
}

test('transmit pins the verifier key and refuses an impostor signature', async t => {
  mockFetch(t, () => agentResponse({ signer: impostor }));
  await assert.rejects(transmit(request), rejectCode('SIGNER_MISMATCH'));
});

test('transmit requires the response to confirm the extension', async t => {
  mockFetch(t, () => agentResponse({ extension: 'https://attacker.example/extension' }));
  await assert.rejects(transmit(request), rejectCode('EXTENSION_NOT_ACTIVE'));
});

test('transmit checks JSON-RPC response ID even with a valid response signature', async t => {
  mockFetch(t, () => agentResponse({ body: { ...responseBody, id: 'another-request' } }));
  await assert.rejects(transmit(request), rejectCode('INVALID_AGENT_RESPONSE'));
});

const invalidTaskShapes = [
  ['missing task ID', task => { delete task.id; }],
  ['missing context ID', task => { delete task.contextId; }],
  ['missing kind', task => { delete task.kind; }],
  ['incorrect kind', task => { task.kind = 'message'; }],
  ['missing status', task => { delete task.status; }],
  ['unsupported task state', task => { task.status.state = 'invented-state'; }],
];
for (const [label, changeTask] of invalidTaskShapes) {
  test(`transmit rejects a signed task with ${label}`, async t => {
    const body = structuredClone(responseBody);
    changeTask(body.result);
    mockFetch(t, () => agentResponse({ body }));
    await assert.rejects(transmit(request), rejectCode('INVALID_AGENT_RESPONSE'));
  });
}

test('getChallenge accepts a signed challenge from the pinned verifier', async t => {
  mockFetch(t, (url, options) => {
    assert.equal(url, `${baseUrl}/auth/challenge`);
    assert.equal(options.method, 'POST');
    assert.deepEqual(JSON.parse(options.body), { holderDid: holder.did });
    return challengeResponse();
  });
  const challenge = await getChallenge({ baseUrl, verifierDid: verifier.did, identity: holder });
  assert.equal(challenge.iss, verifier.did);
  assert.equal(challenge.aud, holder.did);
  assert.equal(challenge.nonce, nonce);
  assert.equal(challenge.target, `${baseUrl}/a2a`);
  assert.equal(typeof challenge.token, 'string');
  const { token, ...payload } = challenge;
  assert.deepEqual(verifyJws(token, { typ: CHALLENGE_TYP, expectedDid: verifier.did }).payload, payload);
});

test('getChallenge refuses an impostor despite matching claims', async t => {
  mockFetch(t, () => challengeResponse({ signer: impostor }));
  await assert.rejects(getChallenge({ baseUrl, verifierDid: verifier.did, identity: holder }), rejectCode('SIGNER_MISMATCH'));
});

const invalidChallenges = [
  ['issuer', proof => { proof.iss = impostor.did; }],
  ['audience', proof => { proof.aud = impostor.did; }],
  ['target', proof => { proof.target = 'https://attacker.example/a2a'; }],
  ['expiration', proof => { proof.exp = unix() - 1; }],
  ['future issued-at', proof => { proof.iat = unix() + 3600; proof.exp = unix() + 3660; }],
  ['missing expiration', proof => { delete proof.exp; }],
  ['non-numeric expiration', proof => { proof.exp = 'tomorrow'; }],
  ['missing issued-at', proof => { delete proof.iat; }],
  ['missing nonce', proof => { delete proof.nonce; }],
  ['missing challenge identifier', proof => { delete proof.jti; }],
];
for (const [label, changeProof] of invalidChallenges) {
  test(`getChallenge rejects a signed challenge with invalid ${label}`, async t => {
    mockFetch(t, () => challengeResponse({ changeProof }));
    await assert.rejects(getChallenge({ baseUrl, verifierDid: verifier.did, identity: holder }), rejectCode('INVALID_CHALLENGE'));
  });
}

test('readBody preserves valid UTF-8 across chunk boundaries', async () => {
  const bytes = Buffer.from('{"text":"你好，Agent B"}');
  const input = Readable.from([bytes.subarray(0, 10), bytes.subarray(10, 11), bytes.subarray(11)]);
  const text = await readBody(input);
  assert.equal(text, bytes.toString('utf8'));
  assert.deepEqual(parseObject(text), { text: '你好，Agent B' });
});

test('readBody rejects invalid UTF-8 instead of hashing a replacement character', async () => {
  const input = Readable.from([Buffer.from('{"text":"'), Buffer.from([0xc3, 0x28]), Buffer.from('"}')]);
  await assert.rejects(readBody(input), rejectCode('INVALID_UTF8'));
});

test('readBody preserves UTF-8 BOM so JSON parsing rejects alternate byte encodings', async () => {
  const input = Readable.from([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"ok":true}')]);
  const text = await readBody(input);
  assert.equal(text.charCodeAt(0), 0xfeff);
  assert.throws(() => parseObject(text), rejectCode('INVALID_JSON'));
});

test('readBody accepts exactly 64 KiB and rejects an additional byte across chunks', async () => {
  assert.equal((await readBody(Readable.from([Buffer.alloc(MAX_BODY, 0x61)]))).length, MAX_BODY);
  const overLimit = Readable.from([Buffer.alloc(MAX_BODY, 0x61), Buffer.from('x')]);
  await assert.rejects(readBody(overLimit), error => error.code === 'BODY_TOO_LARGE' && error.status === 413);
});
