import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import test from 'node:test';
import { generateIdentity, issueCredential, resolveDid } from '../lib/identity.mjs';
import { createOwner } from '../lib/owner.mjs';
import { PAYMENT_SCOPE, verifyPaymentAuthorization } from '../lib/payment.mjs';
import { digest } from '../lib/protocol.mjs';

const issuer = generateIdentity('owner-test-issuer');
const holder = generateIdentity('owner-test-holder');
const verifier = generateIdentity('owner-test-verifier');
const device = generateIdentity('owner-test-device');
const outsider = generateIdentity('owner-test-outsider');
const payment = { orderId: 'owner-order-1', payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 29900, currency: 'CNY' };
const capability = () => randomBytes(32).toString('base64url');
const defaultConfig = () => ({ holderDid: holder.did, verifierDid: verifier.did, trustedIssuers: new Set([issuer.did]), proposalToken: capability(), uiToken: capability() });
function credential(options = {}, authority = issuer) {
  return issueCredential(authority, {
    subjectDid: holder.did, deviceDid: device.did, audience: verifier.did, scopes: [PAYMENT_SCOPE],
    validFrom: Date.now() - 1000, validUntil: Date.now() + 3600000, ...options,
  });
}
async function fixture(t, overrides = {}) {
  const config = { ...defaultConfig(), ...overrides };
  const service = createOwner(config);
  t.after(() => service.close());
  const baseUrl = await service.listen();
  const token = credential();
  const proposalHeaders = { 'X-Owner-Proposal': config.proposalToken };
  const uiHeaders = { 'X-Owner-UI-Key': config.uiToken };
  const request = async (path, { body, headers = {}, method = body === undefined ? 'GET' : 'POST' } = {}) => {
    const response = await fetch(`${baseUrl}${path}`, {
      method, headers: { ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(5000),
    });
    return { status: response.status, body: await response.json() };
  };
  const propose = body => request('/proposals', { body: body ?? { credential: token, payment }, headers: proposalHeaders });
  const confirmation = proposal => ({ confirmed: true, payment: structuredClone(proposal.payment), credentialHash: proposal.credentialHash });
  const approve = (proposal, body = confirmation(proposal), headers = uiHeaders) => request(`/api/proposals/${proposal.id}/approve`, { body, headers });
  return { config, service, baseUrl, token, proposalHeaders, uiHeaders, request, propose, confirmation, approve };
}
function assertError(result, code, status) { assert.equal(result.status, status, JSON.stringify({ error: result.body.error, proposalStatus: result.body.status })); assert.equal(result.body.error?.code, code); }

test('Owner creates a separate public identity and never exposes either capability or private key', async t => {
  const f = await fixture(t);
  for (const path of ['/health', '/api/health', '/did.json']) {
    const result = await f.request(path);
    assert.equal(result.status, 200);
    const text = JSON.stringify(result.body);
    assert.equal(text.includes(f.config.proposalToken), false);
    assert.equal(text.includes(f.config.uiToken), false);
    assert.equal(text.includes('PRIVATE KEY'), false);
    assert.equal(text.includes('privateKey'), false);
  }
  const info = (await f.request('/health')).body;
  assert.notEqual(info.did, issuer.did);
  assert.notEqual(info.did, holder.did);
  assert.notEqual(info.did, device.did);
  assert.equal(info.hardware, false);
  assert.equal(info.keyExportable, false);
  assert.equal(info.pid, process.pid);
  const document = (await f.request('/did.json')).body;
  assert.deepEqual(document, resolveDid(info.did));
  assert.equal(document.verificationMethod[0].publicKeyJwk.d, undefined);
  assert.deepEqual(Object.keys(f.service).sort(), ['close', 'listen', 'publicInfo']);
});

test('the proposing Agent can create and poll immutable pending snapshots but cannot obtain a signature', async t => {
  const f = await fixture(t);
  const created = await f.propose();
  assert.equal(created.status, 200);
  const proposal = created.body;
  assert.equal(proposal.status, 'PENDING');
  assert.equal(proposal.authorization, undefined);
  assert.deepEqual(proposal.payment, payment);
  assert.equal(proposal.credentialHash, digest(f.token));
  assert.equal(proposal.holderDid, holder.did);
  assert.equal(proposal.deviceDid, device.did);
  assert.equal(proposal.verifierDid, verifier.did);
  assert.equal(Date.parse(proposal.expiresAt) - Date.parse(proposal.createdAt), 300000);
  assert.equal(proposal.credential, undefined);
  const polled = await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders });
  assert.deepEqual(polled.body, proposal);
  proposal.payment.amountMinor = 1;
  assert.equal((await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders })).body.payment.amountMinor, 29900);
});

test('proposal capability and Agent console capability cannot approve through the Owner endpoint', async t => {
  const f = await fixture(t);
  const proposal = (await f.propose()).body;
  const agentConsoleKey = capability();
  for (const headers of [{}, f.proposalHeaders, { 'X-Owner-UI-Key': f.config.proposalToken }, { 'X-Owner-UI-Key': agentConsoleKey }]) {
    assertError(await f.approve(proposal, f.confirmation(proposal), headers), 'OWNER_UI_ACCESS_DENIED', 403);
  }
  assertError(await f.request(`/proposals/${proposal.id}/approve`, { body: f.confirmation(proposal), headers: f.proposalHeaders }), 'NOT_FOUND', 404);
  assertError(await f.request('/api/state', { headers: f.proposalHeaders }), 'OWNER_UI_ACCESS_DENIED', 403);
  assert.equal((await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders })).body.status, 'PENDING');
  assert.equal((await f.request('/api/state', { headers: f.uiHeaders })).body.proposals[0].authorization, undefined);
});

test('proposals require their own capability and reject malformed, untrusted, wrong-scope or unbound credentials', async t => {
  const f = await fixture(t);
  assertError(await f.request('/proposals', { body: { credential: f.token, payment } }), 'OWNER_PROPOSAL_ACCESS_DENIED', 403);
  assertError(await f.request('/proposals', { body: { credential: f.token, payment }, headers: f.uiHeaders }), 'OWNER_PROPOSAL_ACCESS_DENIED', 403);
  for (const [token, code] of [
    [credential({}, outsider), 'CREDENTIAL_UNTRUSTED_ISSUER'],
    [credential({ subjectDid: outsider.did }), 'CREDENTIAL_SUBJECT_MISMATCH'],
    [credential({ audience: outsider.did }), 'CREDENTIAL_AUDIENCE_MISMATCH'],
    [credential({ scopes: ['demo:echo'] }), 'CREDENTIAL_SCOPE_DENIED'],
    [credential({ deviceDid: undefined }), 'CREDENTIAL_DEVICE_REQUIRED'],
    [credential({ validFrom: Date.now() - 120000, validUntil: Date.now() - 60000 }), 'CREDENTIAL_EXPIRED'],
  ]) assertError(await f.propose({ credential: token, payment }), code, 403);
  assertError(await f.propose({ credential: f.token, payment, autoApprove: true }), 'OWNER_INVALID_REQUEST', 400);
  assertError(await f.propose({ credential: f.token, payment: { ...payment, amountMinor: -1 } }), 'INVALID_PAYMENT_AUTHORIZATION', 400);
  assert.equal((await f.request('/api/state', { headers: f.uiHeaders })).body.proposals.length, 0);
});

test('Owner approval requires exact current terms, explicit confirmation and the saved credential hash', async t => {
  const f = await fixture(t);
  const proposal = (await f.propose()).body;
  const matching = f.confirmation(proposal);
  for (const body of [{}, { ...matching, confirmed: false }, { payment, credentialHash: proposal.credentialHash }, { confirmed: true, payment }, { ...matching, extra: true }]) {
    assertError(await f.approve(proposal, body), 'OWNER_CONFIRMATION_REQUIRED', 400);
  }
  for (const body of [
    { ...matching, credentialHash: digest('different credential') },
    ...[{ amountMinor: 1 }, { payeeAccount: 'merchant:other' }, { orderId: 'other-order' }, { currency: 'USD' }, { payerAccount: 'merchant:keyboard' }].map(change => ({ ...matching, payment: { ...payment, ...change } })),
    { ...matching, payment: { ...payment, extra: true } },
  ]) assertError(await f.approve(proposal, body), 'OWNER_CONFIRMATION_MISMATCH', 409);
  const state = (await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders })).body;
  assert.equal(state.status, 'PENDING'); assert.equal(state.authorization, undefined);
});

test('only an exact Owner confirmation signs a verifiable authorization and polling returns the same evidence', async t => {
  const f = await fixture(t);
  const proposal = (await f.propose()).body;
  const result = await f.approve(proposal);
  assert.equal(result.status, 200);
  const approved = result.body;
  assert.equal(approved.status, 'APPROVED');
  const document = verifyPaymentAuthorization(approved.authorization.token, {
    trustedAuthorizers: [f.service.publicInfo().did], holderDid: holder.did, deviceDid: device.did,
    verifierDid: verifier.did, credential: f.token, payment,
  });
  assert.deepEqual(document, approved.authorization.document);
  assert.equal(approved.authorization.id, document.authorizationId);
  assert.equal(Date.parse(approved.expiresAt), document.exp * 1000);
  const fetched = await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders });
  assert.deepEqual(fetched.body, approved);
  assertError(await f.approve(proposal), 'OWNER_PROPOSAL_NOT_PENDING', 409);
  const state = (await f.request('/api/state', { headers: f.uiHeaders })).body;
  assert.equal(state.ownerDid, f.service.publicInfo().did);
  assert.deepEqual(state.proposals[0], approved);
});

test('concurrent confirmations cannot mint two independent authorizations for one proposal', async t => {
  const f = await fixture(t);
  const proposal = (await f.propose()).body;
  const attempts = await Promise.all([f.approve(proposal), f.approve(proposal)]);
  assert.deepEqual(attempts.map(item => item.status).sort(), [200, 409]);
  const success = attempts.find(item => item.status === 200).body;
  assert.equal(attempts.find(item => item.status === 409).body.error.code, 'OWNER_PROPOSAL_NOT_PENDING');
  assert.deepEqual((await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders })).body.authorization, success.authorization);
});

test('explicitly rejected proposals never sign and cannot be approved later', async t => {
  const f = await fixture(t); const proposal = (await f.propose()).body;
  assertError(await f.request(`/api/proposals/${proposal.id}/reject`, { body: { rejected: false }, headers: f.uiHeaders }), 'OWNER_CONFIRMATION_REQUIRED', 400);
  const rejected = await f.request(`/api/proposals/${proposal.id}/reject`, { body: { rejected: true }, headers: f.uiHeaders });
  assert.equal(rejected.body.status, 'REJECTED'); assert.equal(rejected.body.authorization, undefined);
  assertError(await f.approve(proposal), 'OWNER_PROPOSAL_NOT_PENDING', 409);
  assert.equal((await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders })).body.authorization, undefined);
});

test('a pending proposal expires at five minutes and cannot be implicitly renewed or approved', async t => {
  const f = await fixture(t); const proposal = (await f.propose()).body;
  t.mock.method(Date, 'now', () => Date.parse(proposal.expiresAt));
  assertError(await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders }), 'OWNER_PROPOSAL_EXPIRED', 410);
  assertError(await f.approve(proposal), 'OWNER_PROPOSAL_EXPIRED', 410);
  const state = (await f.request('/api/state', { headers: f.uiHeaders })).body;
  assert.equal(state.proposals[0].status, 'EXPIRED'); assert.equal(state.proposals[0].authorization, undefined);
});

test('Owner revalidates VC lifetime immediately before approval', async t => {
  const f = await fixture(t);
  const expiration = Date.now() + 60000;
  const proposal = (await f.propose({ credential: credential({ validUntil: expiration }), payment })).body;
  t.mock.method(Date, 'now', () => expiration);
  assertError(await f.approve(proposal), 'CREDENTIAL_EXPIRED', 403);
  const pending = (await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders })).body;
  assert.equal(pending.status, 'PENDING'); assert.equal(pending.authorization, undefined);
});

test('approved proposal lifetime follows its signature expiration and does not expose expired authorizations', async t => {
  const f = await fixture(t); const proposal = (await f.propose()).body;
  const approved = (await f.approve(proposal)).body;
  t.mock.method(Date, 'now', () => approved.authorization.document.exp * 1000);
  assertError(await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders }), 'OWNER_PROPOSAL_EXPIRED', 410);
  const state = (await f.request('/api/state', { headers: f.uiHeaders })).body;
  assert.equal(state.proposals[0].status, 'EXPIRED'); assert.equal(state.proposals[0].authorization, undefined);
});

test('Owner rejects cross-origin, wrong-host and non-JSON requests before proposal or approval changes', async t => {
  const f = await fixture(t); const proposal = (await f.propose()).body;
  assertError(await f.approve(proposal, f.confirmation(proposal), { ...f.uiHeaders, Origin: 'https://untrusted.example' }), 'CROSS_ORIGIN_DENIED', 403);
  // fetch normalizes Host to the URL; use the native HTTP client to put the
  // deliberately wrong Host on the wire rather than testing a dropped header.
  const wrongHost = await new Promise((resolve, reject) => {
    const request = httpRequest(new URL(`/api/proposals/${proposal.id}/approve`, f.baseUrl), {
      method: 'POST', headers: { ...f.uiHeaders, 'Content-Type': 'application/json', Host: 'untrusted.example' },
    }, response => {
      let text = '';
      response.setEncoding('utf8'); response.on('data', chunk => { text += chunk; });
      response.once('end', () => { try { resolve({ status: response.statusCode, body: JSON.parse(text) }); } catch (error) { reject(error); } });
    });
    request.once('error', reject);
    request.setTimeout(5000, () => request.destroy(new Error('Wrong-Host test request timed out.')));
    request.end(JSON.stringify(f.confirmation(proposal)));
  });
  assertError(wrongHost, 'INVALID_HOST', 403);
  assertError(await f.approve(proposal, f.confirmation(proposal), { ...f.uiHeaders, 'Content-Type': 'text/plain' }), 'JSON_REQUIRED', 415);
  assert.equal((await f.request(`/proposals/${proposal.id}`, { headers: f.proposalHeaders })).body.status, 'PENDING');
  assert.equal((await f.approve(proposal, f.confirmation(proposal), { ...f.uiHeaders, Origin: f.baseUrl })).body.status, 'APPROVED');
});

test('missing proposals, bounded capacity and invalid capability configurations fail closed', async t => {
  const f = await fixture(t, { maxEntries: 1 });
  assertError(await f.request('/proposals/missing', { headers: f.proposalHeaders }), 'OWNER_PROPOSAL_NOT_FOUND', 404);
  await f.propose();
  assertError(await f.propose(), 'OWNER_CAPACITY_REACHED', 503);
  const config = defaultConfig();
  for (const bad of [null, [], { ...config, privateKey: 'injected' }, { ...config, uiToken: config.proposalToken }, { ...config, uiToken: Buffer.from(config.proposalToken, 'base64url').toString('hex') }, { ...config, proposalToken: 'short' }, { ...config, uiToken: 'short' }, { ...config, trustedIssuers: [] }, { ...config, maxEntries: 0 }]) {
    assert.throws(() => createOwner(bad), error => error.code === 'OWNER_INVALID_CONFIG');
  }
  const neverStarted = createOwner(defaultConfig()); await neverStarted.close(); await neverStarted.close();
});

test('Owner IPC starts an independent process and publishes only public readiness data', { timeout: 15000 }, async () => {
  const config = defaultConfig();
  const child = fork(new URL('../owner.mjs', import.meta.url), [], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  const exited = new Promise(resolve => child.once('exit', resolve));
  let stderr = '';
  child.stderr.on('data', data => { stderr += data; });
  try {
    const ready = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`Owner startup timed out: ${stderr}`)), 5000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', code => { clearTimeout(timer); reject(new Error(`Owner exited before readiness: ${code} ${stderr}`)); });
      child.once('message', message => { clearTimeout(timer); if (message.error) reject(new Error(message.error)); else resolve(message); });
    });
    child.send({ ...config, trustedIssuers: [...config.trustedIssuers], port: 0 });
    const info = await ready;
    assert.equal(info.ready, true);
    assert.equal(info.pid, child.pid); assert.notEqual(info.pid, process.pid);
    assert.deepEqual(Object.keys(info).sort(), ['baseUrl', 'did', 'pid', 'ready']);
    const health = await (await fetch(`${info.baseUrl}/health`)).json();
    assert.equal(health.did, info.did); assert.equal(health.pid, child.pid);
    assert.equal(JSON.stringify(info).includes(config.proposalToken), false);
    assert.equal(JSON.stringify(info).includes(config.uiToken), false);
    assert.equal(resolveDid(info.did).verificationMethod[0].publicKeyJwk.d, undefined);
  } finally {
    child.kill('SIGTERM');
    let timer;
    try { await Promise.race([exited, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Owner child did not exit.')), 4000); })]); }
    finally { clearTimeout(timer); if (child.exitCode === null) child.kill('SIGKILL'); }
  }
});
