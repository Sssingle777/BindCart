import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import test from 'node:test';
import { createEsim, DEVICE_POP_TYP } from '../lib/esim.mjs';
import { generateIdentity, issueCredential, signJws, verifyJws } from '../lib/identity.mjs';
import { CHALLENGE_TYP, POP_TYP, SCOPE, digest, unix } from '../lib/protocol.mjs';

const verifierUrl = 'http://127.0.0.1:49998';
async function fixture(t, options = {}) {
  const issuer = generateIdentity('esim-test-issuer');
  const holder = generateIdentity('esim-test-holder');
  const verifier = generateIdentity('esim-test-verifier');
  const outsider = generateIdentity('esim-test-outsider');
  const accessToken = randomBytes(32).toString('base64url');
  const config = { accessToken, holderDid: holder.did, verifierDid: verifier.did, verifierUrl, trustedIssuers: [issuer.did], ...options };
  const service = createEsim(config);
  const baseUrl = await service.listen();
  t.after(() => service.close());
  const deviceDid = service.publicInfo().deviceDid;
  const credential = issueCredential(issuer, { subjectDid: holder.did, audience: verifier.did, scopes: [SCOPE], deviceDid });
  const request = ({ holderOverrides = {}, challengeOverrides = {}, signer = holder, challengeSigner = verifier, vc = credential } = {}) => {
    const rawBody = JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: { text: 'private request text' } });
    const challengePayload = {
      iss: verifier.did, aud: holder.did, target: `${verifierUrl}/a2a`, nonce: randomBytes(32).toString('base64url'),
      jti: randomUUID(), iat: unix(), exp: unix() + 60, ...challengeOverrides,
    };
    const holderPayload = {
      iss: holder.did, aud: verifier.did, iat: unix(), exp: Math.min(unix() + 60, challengePayload.exp), jti: randomUUID(),
      challengeId: challengePayload.jti, nonce: challengePayload.nonce, method: 'POST', target: `${verifierUrl}/a2a`,
      bodyHash: digest(rawBody), credential: vc, ...holderOverrides,
    };
    return {
      holderProof: signJws(holderPayload, signer, POP_TYP),
      challenge: signJws(challengePayload, challengeSigner, CHALLENGE_TYP), rawBody,
    };
  };
  async function call(path, body, token = accessToken, extraHeaders = {}) {
    const headers = { 'Content-Type': 'application/json', ...extraHeaders };
    if (token !== null) headers['X-ESIM-Access'] = token;
    const response = await fetch(`${baseUrl}${path}`, { method: body === undefined ? 'GET' : 'POST', headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json() };
  }
  return { issuer, holder, verifier, outsider, accessToken, service, config, baseUrl, deviceDid, credential, request, call };
}

test('device generates its own identity and health, DID document and API do not export a private key', async t => {
  const f = await fixture(t);
  assert.deepEqual(Object.keys(f.service).sort(), ['close', 'listen', 'publicInfo', 'server']);
  const info = f.service.publicInfo();
  assert.equal(info.service, 'simulated-esim');
  assert.equal(info.backend, 'jcardsim');
  assert.equal(info.algorithm, 'ES256');
  assert.equal(info.curve, 'P-256');
  assert.equal(info.ready, true);
  assert.notEqual(info.javaPid, process.pid);
  assert.equal(info.didDocument.verificationMethod[0].publicKeyJwk.crv, 'P-256');
  assert.equal(info.hardware, false);
  assert.equal(info.keyExportable, false);
  assert.equal(info.locked, false);
  assert.equal(info.pid, process.pid);
  assert.equal(info.did, f.deviceDid);
  assert.notEqual(info.did, f.holder.did);
  const health = await f.call('/health', undefined, null);
  const doc = await f.call('/did.json', undefined, null);
  assert.equal(health.status, 200);
  assert.equal(doc.status, 200);
  assert.equal(doc.body.id, f.deviceDid);
  for (const output of [info, health.body, doc.body]) {
    const serialized = JSON.stringify(output);
    assert.equal(serialized.includes(f.accessToken), false);
    assert.doesNotMatch(serialized, /privateKey|PRIVATE KEY|"d":/);
  }
  info.didDocument.verificationMethod[0].publicKeyJwk.x = 'changed externally';
  assert.notEqual(f.service.publicInfo().didDocument.verificationMethod[0].publicKeyJwk.x, 'changed externally');
});

for (const [label, token] of [['absent', null], ['wrong', randomBytes(32).toString('base64url')]]) {
  test(`device refuses ${label} access permission even with a valid VC and holder private key`, async t => {
    const f = await fixture(t);
    for (const [path, body] of [['/sign', f.request()], ['/audit', undefined], ['/lock', { locked: true }]]) {
      const result = await f.call(path, body, token);
      assert.equal(result.status, 403);
      assert.equal(result.body.error.code, 'ESIM_ACCESS_DENIED');
    }
  });
}

test('device signs the exact holder proof, VC, challenge and request bytes', async t => {
  const f = await fixture(t);
  const body = f.request();
  const result = await f.call('/sign', body);
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.deepEqual(Object.keys(result.body), ['deviceProof']);
  const { payload, signerDid } = verifyJws(result.body.deviceProof, { typ: DEVICE_POP_TYP, expectedDid: f.deviceDid });
  const { payload: holder } = verifyJws(body.holderProof, { typ: POP_TYP });
  assert.equal(signerDid, f.deviceDid);
  assert.equal(payload.iss, f.deviceDid);
  assert.equal(payload.sub, f.holder.did);
  assert.equal(payload.aud, f.verifier.did);
  assert.equal(payload.holderProofHash, digest(body.holderProof));
  assert.equal(payload.credentialHash, digest(f.credential));
  assert.equal(payload.bodyHash, digest(body.rawBody));
  assert.equal(payload.challengeId, holder.challengeId);
  assert.equal(payload.nonce, holder.nonce);
  assert.equal(payload.method, 'POST');
  assert.equal(payload.target, `${verifierUrl}/a2a`);
  assert.ok(payload.exp > payload.iat && payload.exp <= holder.exp);
  assert.equal(f.service.publicInfo().signatures, 1);
  assert.ok(f.service.publicInfo().apduCommands > 2, 'real JWS signing input crosses multiple APDU chunks');
  const audit = await f.call('/audit');
  assert.equal(audit.body.entries.at(-1).event, 'signed');
  const serialized = JSON.stringify(audit.body);
  for (const sensitive of [f.accessToken, f.credential, body.holderProof, body.rawBody, result.body.deviceProof]) assert.equal(serialized.includes(sensitive), false);
});

const badHolderCases = [
  ['body hash', () => ({ bodyHash: digest('tampered') })],
  ['audience', f => ({ aud: f.outsider.did })],
  ['HTTP method', () => ({ method: 'GET' })],
  ['target', () => ({ target: 'http://127.0.0.1:1/a2a' })],
  ['expiration', () => ({ iat: unix() - 61, exp: unix() - 1 })],
  ['fractional timestamp', () => ({ iat: unix() - 0.5 })],
  ['future timestamp', () => ({ iat: unix() + 30, exp: unix() + 60 })],
  ['excessive validity', () => ({ iat: unix() - 30, exp: unix() + 60 })],
];
for (const [label, overrides] of badHolderCases) {
  test(`device refuses a holder proof with invalid ${label}`, async t => {
    const f = await fixture(t);
    const result = await f.call('/sign', f.request({ holderOverrides: overrides(f) }));
    assert.equal(result.body.error.code, 'ESIM_INVALID_REQUEST');
  });
}

test('device refuses an impostor holder and a different issuer-bound device', async t => {
  const f = await fixture(t);
  const impostor = await f.call('/sign', f.request({ signer: f.outsider, holderOverrides: { iss: f.outsider.did } }));
  assert.equal(impostor.body.error.code, 'ESIM_HOLDER_MISMATCH');
  const swapped = issueCredential(f.issuer, { subjectDid: f.holder.did, audience: f.verifier.did, scopes: [SCOPE], deviceDid: f.outsider.did });
  const result = await f.call('/sign', f.request({ vc: swapped }));
  assert.equal(result.body.error.code, 'ESIM_DEVICE_MISMATCH');
});

test('device rejects invalid, expired and untrusted credentials', async t => {
  const f = await fixture(t);
  const untrusted = issueCredential(f.outsider, { subjectDid: f.holder.did, audience: f.verifier.did, scopes: [SCOPE], deviceDid: f.deviceDid });
  const expired = issueCredential(f.issuer, { subjectDid: f.holder.did, audience: f.verifier.did, scopes: [SCOPE], deviceDid: f.deviceDid, validFrom: Date.now() - 120000, validUntil: Date.now() - 60000 });
  for (const vc of ['invalid.vc.token', untrusted, expired]) {
    const result = await f.call('/sign', f.request({ vc }));
    assert.equal(result.body.error.code, 'ESIM_INVALID_REQUEST');
  }
});

const badChallengeCases = [
  ['signer', f => ({ challengeSigner: f.outsider })],
  ['issuer', f => ({ challengeOverrides: { iss: f.outsider.did } })],
  ['audience', f => ({ challengeOverrides: { aud: f.outsider.did } })],
  ['target', () => ({ challengeOverrides: { target: 'http://127.0.0.1:1/a2a' } })],
  ['expired timestamp', () => ({ challengeOverrides: { iat: unix() - 61, exp: unix() - 1 }, holderOverrides: { exp: unix() + 60 } })],
  ['future timestamp', () => ({ challengeOverrides: { iat: unix() + 30, exp: unix() + 60 } })],
  ['fractional timestamp', () => ({ challengeOverrides: { iat: unix() - 0.5 } })],
  ['too-long validity', () => ({ challengeOverrides: { iat: unix() - 30, exp: unix() + 60 } })],
  ['holder nonce mismatch', () => ({ holderOverrides: { nonce: randomBytes(32).toString('base64url') } })],
  ['holder challenge ID mismatch', () => ({ holderOverrides: { challengeId: randomUUID() } })],
];
for (const [label, options] of badChallengeCases) {
  test(`device rejects a challenge with invalid ${label}`, async t => {
    const f = await fixture(t);
    const result = await f.call('/sign', f.request(options(f)));
    assert.equal(result.body.error.code, 'ESIM_INVALID_CHALLENGE');
  });
}

test('invalid requests do not consume a valid challenge', async t => {
  const f = await fixture(t);
  const body = f.request();
  const rejected = await f.call('/sign', { ...body, rawBody: `${body.rawBody} ` });
  assert.equal(rejected.body.error.code, 'ESIM_INVALID_REQUEST');
  const accepted = await f.call('/sign', body);
  assert.equal(accepted.status, 200);
});

test('locked device refuses signing until an authorized unlock', async t => {
  const f = await fixture(t);
  const body = f.request();
  const locked = await f.call('/lock', { locked: true });
  assert.equal(locked.body.locked, true);
  const rejected = await f.call('/sign', body);
  assert.equal(rejected.body.error.code, 'ESIM_LOCKED');
  await f.call('/lock', { locked: false });
  assert.equal((await f.call('/sign', body)).status, 200);
  const audit = await f.call('/audit');
  assert.ok(audit.body.entries.some(entry => entry.event === 'locked'));
  assert.ok(audit.body.entries.some(entry => entry.event === 'unlocked'));
});

test('concurrent signing requests consume a challenge once', async t => {
  const f = await fixture(t);
  const body = f.request();
  const results = await Promise.all(Array.from({ length: 8 }, () => f.call('/sign', body)));
  assert.equal(results.filter(result => result.status === 200).length, 1);
  assert.equal(results.filter(result => result.body.error?.code === 'ESIM_REPLAYED_CHALLENGE').length, 7);
});

test('capacity exhaustion cannot evict an active replay-prevention entry', async t => {
  const f = await fixture(t, { maxEntries: 1 });
  const first = f.request();
  assert.equal((await f.call('/sign', first)).status, 200);
  assert.equal((await f.call('/sign', f.request())).body.error.code, 'ESIM_CAPACITY_EXCEEDED');
  assert.equal((await f.call('/sign', first)).body.error.code, 'ESIM_REPLAYED_CHALLENGE');
});

test('local transport rejects cross-origin access and malformed administrative input', async t => {
  const f = await fixture(t);
  assert.equal((await f.call('/sign', f.request(), f.accessToken, { Origin: 'https://attacker.example' })).body.error.code, 'CROSS_ORIGIN_DENIED');
  assert.equal((await f.call('/lock', { locked: 'false' })).body.error.code, 'ESIM_INVALID_REQUEST');
  assert.equal((await f.call('/lock', { locked: true, privateKey: 'unexpected' })).body.error.code, 'ESIM_INVALID_REQUEST');
  assert.equal((await f.call('/sign', { ...f.request(), privateKey: 'unexpected' })).body.error.code, 'ESIM_INVALID_REQUEST');
  const raw = await fetch(`${f.baseUrl}/sign`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-ESIM-Access': f.accessToken }, body: '{invalid}' });
  assert.equal((await raw.json()).error.code, 'ESIM_INVALID_REQUEST');
});

test('device configuration refuses key injection and weak access capabilities', async t => {
  const f = await fixture(t);
  for (const extra of [{ privateKey: f.holder.privateKey }, { identity: f.holder }, { accessToken: 'password' }]) {
    assert.throws(() => createEsim({ ...f.config, ...extra }), error => error.code === 'ESIM_INVALID_CONFIG');
  }
});

test('JVM failure returns an error and cannot fall back to a Node-held signing key', async t => {
  const f = await fixture(t);
  const info = f.service.publicInfo();
  process.kill(info.javaPid, 'SIGKILL');
  const deadline = Date.now() + 2000;
  while (f.service.publicInfo().ready && Date.now() < deadline) await delay(10);
  assert.equal(f.service.publicInfo().ready, false);
  const body = f.request();
  const result = await f.call('/sign', body);
  assert.equal(result.status, 503);
  assert.equal(result.body.error.code, 'JCARD_UNAVAILABLE');
  assert.equal(result.body.deviceProof, undefined);
  assert.equal(f.service.publicInfo().signatures, 0);
  // Reserve-before-await is intentionally fail closed, even if no proof returned.
  assert.equal((await f.call('/sign', body)).body.error.code, 'ESIM_REPLAYED_CHALLENGE');
});

test('standalone device process owns a distinct JVM and closes it on IPC disconnect', { timeout: 15000 }, async t => {
  const issuer = generateIdentity('process-issuer');
  const holder = generateIdentity('process-holder');
  const verifier = generateIdentity('process-verifier');
  const child = fork(new URL('../esim.mjs', import.meta.url), [], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  const readyPromise = once(child, 'message');
  child.send({ accessToken: randomBytes(32).toString('base64url'), holderDid: holder.did, verifierDid: verifier.did, verifierUrl, trustedIssuers: [issuer.did] });
  const [ready] = await readyPromise;
  assert.equal(ready.ready, true, JSON.stringify(ready));
  assert.notEqual(ready.pid, process.pid);
  assert.deepEqual(Object.keys(ready).sort(), ['backend', 'baseUrl', 'deviceDid', 'javaPid', 'pid', 'ready']);
  assert.equal(ready.backend, 'jcardsim');
  assert.notEqual(ready.javaPid, ready.pid);
  const health = await (await fetch(`${ready.baseUrl}/health`)).json();
  assert.equal(health.deviceDid, ready.deviceDid);
  assert.equal(health.pid, ready.pid);
  assert.equal(health.keyExportable, false);
  const exited = once(child, 'exit');
  child.disconnect();
  const [code] = await exited;
  assert.equal(code, 0);
  assert.throws(() => process.kill(ready.javaPid, 0), { code: 'ESRCH' });
});
