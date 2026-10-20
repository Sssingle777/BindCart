import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fork } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createExperimentRuns } from '../lib/dbac/experiment-runs.mjs';
import { generateIdentity } from '../lib/identity.mjs';
import { serializeIdentity, sendJson } from '../lib/protocol.mjs';
import { frameworkFixture } from './fixtures/framework.mjs';

const capability = () => randomBytes(32).toString('base64url');
const scenarios = () => [{ id: 'copied-vc' }, { id: 'revoked' }];
const input = (extra = {}) => ({ runId: randomUUID(), mode: 'bbs-bls', scenarioId: 'copied-vc', ...extra });
async function completed(read, signal) {
  for (let i = 0; i < 1000; i++) {
    const record = await read();
    if (record.status !== 'running') return record;
    await delay(20, undefined, { signal });
  }
  assert.fail('Experiment did not finish within the bounded test wait');
}

test('run registry preserves idempotency, parameter binding and failures without inventing security results', async t => {
  let release, calls = 0;
  const waiting = new Promise(resolve => { release = resolve; });
  const runs = createExperimentRuns({ scenarios, maxRecords: 2, run: async () => { calls++; await waiting; throw Object.assign(new Error('transport unavailable'), { code: 'EXPERIMENT_TRANSPORT' }); } });
  const request = input();
  assert.equal(runs.start(request).status, 'running');
  assert.equal(runs.busy(), true);
  assert.equal(runs.start(request, { blocked: true }).runId, request.runId, 'a retry reads its original record even while busy');
  assert.throws(() => runs.start({ ...request, scenarioId: 'revoked' }), { code: 'EXPERIMENT_RUN_CONFLICT' });
  assert.throws(() => runs.start({ ...request, mode: 'bbs-blind-bls' }), { code: 'EXPERIMENT_RUN_CONFLICT' });
  assert.throws(() => runs.start(input()), { code: 'BUSY' });
  assert.throws(() => runs.get(randomUUID()), { code: 'EXPERIMENT_RUN_NOT_FOUND' });
  assert.throws(() => runs.start({ ...input(), extra: true }), { code: 'EXPERIMENT_RUN_INVALID_INPUT' });
  assert.throws(() => runs.start(input({ runId: 'not-a-uuid' })), { code: 'EXPERIMENT_RUN_INVALID_ID' });
  assert.throws(() => runs.start(input({ mode: 'unsupported' })), { code: 'DBAC_INVALID_MODE' });
  assert.throws(() => runs.start(input({ scenarioId: 'unknown' })), { code: 'EXPERIMENT_UNKNOWN_SCENARIO' });
  release();
  const failed = await completed(() => runs.get(request.runId), t.signal);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.error.code, 'EXPERIMENT_TRANSPORT');
  assert.equal(failed.result, undefined);
  assert.equal(calls, 1);
  assert.equal(runs.start(request).status, 'failed', 'failed requests also require a new explicit id to run again');
  assert.equal(calls, 1);
  failed.error.code = 'edited by caller';
  assert.equal(runs.get(request.runId).error.code, 'EXPERIMENT_TRANSPORT');
  const second = input(); runs.start(second);
  await completed(() => runs.get(second.runId), t.signal);
  assert.throws(() => runs.start(input()), { code: 'EXPERIMENT_RUN_CAPACITY' });
  assert.equal(runs.get(request.runId).status, 'failed', 'old ids are retained instead of silently evicted');
  assert.equal(runs.list().runs.length, 2);
  assert.equal(calls, 2);
});

test('session run lock blocks credential/order changes across modes while retaining real B evidence', { timeout: 60000 }, async t => {
  const f = await frameworkFixture(t), mode = 'bbs-bls';
  await f.session.issue({ mode });
  const before = await f.session.state({ mode });
  const request = input();
  assert.equal(f.session.startExperimentRun(request).status, 'running');
  assert.equal(f.session.experimentRunBusy(), true);
  await assert.rejects(f.session.manage({ mode, action: 'lock' }), { code: 'BUSY' });
  await assert.rejects(f.session.manage({ mode, action: 'revoke' }), { code: 'BUSY' });
  await assert.rejects(f.session.newOrder({ mode: 'bbs-blind-bls' }), { code: 'BUSY' });
  await assert.rejects(f.session.issue({ mode }), { code: 'BUSY' });
  await assert.rejects(f.session.manual({ mode, action: 'begin-proposal' }), { code: 'BUSY' });
  await assert.rejects(f.session.pay({ mode }), { code: 'BUSY' });
  await assert.rejects(f.session.experiments({ mode, scenarioId: 'revoked' }), { code: 'BUSY' });
  assert.equal((await f.session.state({ mode })).currentCredentialId, before.currentCredentialId, 'reads remain available');
  const done = await completed(() => f.session.experimentRun(request.runId), t.signal);
  assert.equal(done.status, 'completed');
  assert.equal(done.result.actual, 'W3C_DEVICE_PROOF_REQUIRED');
  assert.equal(done.result.requestRejected, true);
  assert.equal(done.result.rejectionStage, 'vc_device_binding');
  assert.equal(done.result.expectationMet, true);
  assert.equal(f.session.experimentRunBusy(), false);
  const after = await f.session.state({ mode });
  assert.equal(after.currentCredentialId, before.currentCredentialId);
  assert.equal(after.order.orderId, before.order.orderId);
  assert.equal(after.credentialStatus.status, 'valid');
});

async function agentFixture(t) {
  const f = await frameworkFixture(t);
  let verifierUrl, releaseLedger;
  let holdLedger = new Promise(resolve => { releaseLedger = resolve; });
  const server = http.createServer({ maxHeaderSize: 24 * 1024 }, async (req, res) => {
    try {
      if (req.url === '/admin/ledger') { await holdLedger; return sendJson(res, 200, f.ledger); }
      if (!await f.verifier.handle(req, res, verifierUrl)) sendJson(res, 404, { error: { code: 'NOT_FOUND' } });
    } catch (error) { sendJson(res, error.status ?? 400, { error: { code: error.code, message: error.message }, verificationTrace: error.verificationTrace }); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  verifierUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { releaseLedger(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const uiKey = capability(), ownerKey = capability();
  const publicInfo = (await f.session.state()).paymentInfo;
  const child = fork(new URL('../agent-a.mjs', import.meta.url), [], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });
  const exited = new Promise(resolve => child.once('exit', resolve));
  t.after(async () => { child.kill('SIGTERM'); await Promise.race([exited, delay(2000, undefined, { ref: false })]); if (child.exitCode === null) child.kill('SIGKILL'); await exited; });
  const ready = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('message', value => value.error ? reject(new Error('Agent A fixture startup failed')) : resolve(value));
  });
  child.send({ port: 0, uiToken: uiKey, issuer: serializeIdentity(generateIdentity('Fixture issuer')), agentA: serializeIdentity(generateIdentity('Fixture A')), verifierDid: f.identity.did,
    baseUrl: verifierUrl, adminToken: capability(), device: { did: generateIdentity('Fixture baseline device').did, baseUrl: f.device.baseUrl, accessToken: capability() },
    dbac: { issuer: f.issuer, device: f.device }, owner: { did: f.owner.did, baseUrl: 'http://127.0.0.1:1', proposalToken: capability() },
    payerConfig: { url: 'http://127.0.0.1:1', accessToken: capability(), publicInfo } });
  const { baseUrl } = await ready;
  async function api(path, body, authorized = true) {
    const response = await fetch(`${baseUrl}${path}`, { method: body === undefined ? 'GET' : 'POST', headers: { ...(authorized ? { 'X-Demo-UI-Key': uiKey, 'X-Owner-UI-Key': ownerKey } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(10000) });
    return { status: response.status, data: await response.json() };
  }
  return { ...f, api, release: () => { releaseLedger(); holdLedger = Promise.resolve(); } };
}

test('HTTP asynchronous B/C runs are queryable, idempotent, authenticated and preserve global mutation isolation', { timeout: 90000 }, async t => {
  const f = await agentFixture(t), path = '/api/dbac/payment/experiment-runs';
  const request = input();
  assert.equal((await f.api(path, request, false)).data.error.code, 'UI_ACCESS_DENIED');
  assert.equal((await f.api(path, request)).data.status, 'running');
  assert.equal((await f.api(path, request)).data.runId, request.runId);
  assert.equal((await f.api(`${path}?runId=${request.runId}`)).data.status, 'running');
  assert.equal((await f.api(path, { ...request, scenarioId: 'revoked' })).data.error.code, 'EXPERIMENT_RUN_CONFLICT');
  assert.equal((await f.api(path, input())).data.error.code, 'BUSY');
  for (const [endpoint, body] of [
    ['/api/dbac/payment/manage', { mode: 'bbs-bls', action: 'lock' }],
    ['/api/dbac/payment/new', { mode: 'bbs-blind-bls' }],
    ['/api/dbac/payment/experiments', { mode: 'bbs-bls', scenarioId: 'revoked' }],
    ['/api/dbac/device/lock', { mode: 'bbs-bls', locked: true }],
    ['/api/issue', {}],
    ['/owner/api/proposals/test/approve', {}],
  ]) assert.equal((await f.api(endpoint, body)).data.error.code, 'BUSY', `${endpoint} preserves the asynchronous lock`);
  assert.equal((await f.api(path)).data.runs.length, 1);
  assert.equal((await f.api(`${path}?runId=${randomUUID()}`)).data.error.code, 'EXPERIMENT_RUN_NOT_FOUND');
  f.release();
  const copied = await completed(async () => (await f.api(`${path}?runId=${request.runId}`)).data, t.signal);
  assert.equal(copied.status, 'completed');
  assert.equal(copied.result.actual, 'W3C_DEVICE_PROOF_REQUIRED');
  assert.equal(copied.result.expectationMet, true);
  const countAfterCopy = f.deviceService.publicInfo().modes['bbs-bls'].signatures;
  assert.deepEqual((await f.api(path, request)).data.result, copied.result);
  assert.equal(f.deviceService.publicInfo().modes['bbs-bls'].signatures, countAfterCopy, 'completed duplicate does not sign or execute again');
  const revokedRequest = input({ scenarioId: 'revoked', mode: 'bbs-blind-bls' });
  assert.equal((await f.api(path, revokedRequest)).data.status, 'running');
  const revoked = await completed(async () => (await f.api(`${path}?runId=${revokedRequest.runId}`)).data, t.signal);
  assert.equal(revoked.status, 'completed');
  assert.equal(revoked.result.actual, 'W3C_CREDENTIAL_REVOKED');
  assert.equal(revoked.result.rejectionStage, 'credential_status');
  assert.equal(revoked.result.revocation.freshChallenge, true);
  assert.equal(revoked.result.revocation.completeHolderProof, true);
  assert.equal(revoked.result.revocation.completeDeviceProof, true);
  assert.equal(revoked.result.expectationMet, true);
  const countAfterRevoke = f.deviceService.publicInfo().modes['bbs-blind-bls'].signatures;
  assert.deepEqual((await f.api(path, revokedRequest)).data.result, revoked.result);
  assert.equal(f.deviceService.publicInfo().modes['bbs-blind-bls'].signatures, countAfterRevoke);
  for (const record of [copied, revoked]) {
    assert.equal(record.result.sideEffects.paymentExecutionDelta, 0);
    assert.equal(record.result.sideEffects.balancesUnchanged, true);
    assert.doesNotMatch(JSON.stringify(record), /privateKey|secretKey|accessToken|proposalToken/);
  }
  assert.equal((await f.api(path)).data.runs.length, 2);
  assert.equal((await f.api('/api/dbac/payment/state?mode=bbs-bls')).status, 200);
  const legacy = await f.api('/api/dbac/payment/experiments', { mode: 'bbs-bls', scenarioId: 'normal' });
  assert.equal(legacy.status, 200);
  assert.equal(legacy.data.actual, 'ACCEPTED', 'the existing synchronous experiment route still works');
});
