import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import test from 'node:test';
import { generateIdentity, issueCredential, signJws, verifyJws } from '../lib/identity.mjs';
import { issuePaymentAuthorization, paymentRpc, PAYMENT_SCOPE } from '../lib/payment.mjs';
import { AppError, EXTENSION, POP_TYP, DEVICE_POP_TYP, RESPONSE_TYP, digest, unix, prepareRequest } from '../lib/protocol.mjs';
import { createVerifier } from '../lib/verifier.mjs';

const transaction = `0x${'a'.repeat(64)}`;
const deferred = () => {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
};

// The backend is intentionally a fault-injection double. All A2A messages,
// challenges, holder/device signatures and B response signatures are real.
// The separate x402-payment tests exercise the official SDK and test chain.
async function fixture(t, { authorizationSeconds = 600 } = {}) {
  const issuer = generateIdentity('issuer'), owner = generateIdentity('owner');
  const holder = generateIdentity('holder'), device = generateIdentity('device');
  const b = generateIdentity('B'), stranger = generateIdentity('other holder');
  const strangerDevice = generateIdentity('other device'), adminToken = randomUUID();
  const hooks = { snapshot: null, requirements: null, execute: null };
  const calls = { snapshot: 0, requirements: 0, execute: 0 };
  const backend = {
    async snapshot() { calls.snapshot++; await hooks.snapshot?.(); return { receipts: [] }; },
    async requirements(payment, { resourceUrl, taskId }) {
      calls.requirements++; await hooks.requirements?.();
      return { x402Version: 2, resource: { url: resourceUrl, description: taskId, mimeType: 'application/json' }, accepts: [{ scheme: 'exact', network: payment.settlement.network, amount: String(payment.amountMinor), asset: payment.settlement.asset, payTo: payment.settlement.payTo, maxTimeoutSeconds: 60, extra: {} }] };
    },
    async execute(input) {
      calls.execute++;
      if (hooks.execute) return hooks.execute(input);
      return { outcome: 'EXECUTED', receipt: { ...input.payment, receiptId: randomUUID(), transactionHash: transaction, settlementResponse: { success: true, network: input.payment.settlement.network, transaction, payer: input.payment.settlement.payerAddress } } };
    },
  };
  const verifier = createVerifier({ identity: b, trustedIssuers: new Set([issuer.did]), trustedAuthorizers: new Set([owner.did]), adminToken, x402Backend: backend, requireX402: true });
  t.after(() => verifier.close());
  const baseUrl = await verifier.listen();
  const issue = (identity = holder, card = device) => issueCredential(issuer, { subjectDid: identity.did, deviceDid: card.did, audience: b.did, scopes: [PAYMENT_SCOPE] });
  const credential = issue(), credentialId = verifyJws(credential, { typ: 'vc+jwt', purpose: 'assertionMethod' }).payload.id;
  const payment = { orderId: `order-${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 2990000, currency: 'TEST_USDC', settlement: { network: 'eip155:31337', asset: `0x${'1'.repeat(40)}`, payTo: `0x${'2'.repeat(40)}`, payerAddress: `0x${'3'.repeat(40)}` } };
  const authorization = issuePaymentAuthorization(owner, { holderDid: holder.did, deviceDid: device.did, verifierDid: b.did, credential, payment, exp: unix() + authorizationSeconds });
  async function prepare(rpc, { identity = holder, card = device, vc = credential } = {}) {
    const request = await prepareRequest({ identity, credential: vc, verifierDid: b.did, baseUrl, rpc });
    const p = verifyJws(request.token, { typ: POP_TYP }).payload;
    request.deviceDid = card.did;
    request.deviceProof = signJws({ iss: card.did, sub: p.iss, aud: p.aud, iat: unix(), exp: Math.min(unix() + 60, p.exp), jti: randomUUID(), holderProofHash: digest(request.token), credentialHash: digest(p.credential), challengeId: p.challengeId, nonce: p.nonce, method: p.method, target: p.target, bodyHash: p.bodyHash }, card, DEVICE_POP_TYP);
    return request;
  }
  async function send(request) {
    const response = await fetch(`${baseUrl}/a2a`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${request.token}`, 'X-A2A-Extensions': EXTENSION, 'X-A2A-Device-Proof': request.deviceProof }, body: request.rawBody });
    const raw = await response.text(), body = JSON.parse(raw);
    if (response.status === 200) {
      const { payload } = verifyJws(response.headers.get('X-A2A-DID-Response'), { typ: RESPONSE_TYP, expectedDid: b.did, purpose: 'authentication' });
      assert.equal(payload.requestHash, digest(request.rawBody));
      assert.equal(payload.responseHash, digest(raw));
      assert.equal(payload.aud, request.identity.did);
      assert.equal(payload.nonce, request.challenge.nonce);
      assert.equal(payload.deviceDid, request.deviceDid);
      assert.equal(payload.deviceProofHash, digest(request.deviceProof));
    }
    return { status: response.status, body };
  }
  const invoke = async (rpc, options) => send(await prepare(rpc, options));
  const query = id => ({ jsonrpc: '2.0', id: randomUUID(), method: 'tasks/get', params: { id } });
  const continuation = (task, payload = { marker: 'valid' }) => {
    const rpc = paymentRpc(payment, authorization);
    Object.assign(rpc.params.message, { taskId: task.id, contextId: task.contextId, metadata: { 'x402.payment.status': 'payment-submitted', 'x402.payment.payload': payload } });
    return rpc;
  };
  async function negotiate() {
    const response = await invoke(paymentRpc(payment, authorization));
    assert.equal(response.status, 200);
    assert.equal(response.body.result.status.state, 'input-required');
    return response.body.result;
  }
  async function admin(path, body, token = adminToken) {
    const response = await fetch(`${baseUrl}/admin/${path}`, { method: body === undefined ? 'GET' : 'POST', headers: { ...(token === undefined ? {} : { 'X-Demo-Admin': token }), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json() };
  }
  return { holder, device, stranger, strangerDevice, issue, payment, authorization, credentialId, verifier, hooks, calls, prepare, send, invoke, query, continuation, negotiate, admin };
}

test('authenticated x402 rejection becomes a signed failed Task preserving ID, context, history and holder visibility', async t => {
  const f = await fixture(t), before = await f.negotiate();
  f.hooks.execute = () => { throw new AppError('X402_VERIFICATION_FAILED', 'SDK rejected payment', 403); };
  const rpc = f.continuation(before), result = await f.invoke(rpc);
  assert.equal(result.status, 200);
  const failed = result.body.result;
  assert.equal(failed.id, before.id);
  assert.equal(failed.contextId, before.contextId);
  assert.equal(failed.status.state, 'failed');
  assert.deepEqual(failed.history.slice(0, before.history.length), before.history);
  assert.deepEqual(failed.history.at(-2), rpc.params.message);
  assert.deepEqual(failed.status.message.metadata, { 'x402.payment.status': 'payment-failed', 'x402.payment.error': 'X402_VERIFICATION_FAILED', 'x402.payment.receipts': [{ success: false, errorReason: 'X402_VERIFICATION_FAILED', network: 'eip155:31337', transaction: '' }] });
  assert.deepEqual((await f.invoke(f.query(failed.id))).body.result, failed);
  assert.deepEqual((await f.invoke(f.continuation(failed))).body.result, failed, 'failed Task is terminal');
  assert.equal(f.calls.execute, 1);
  const foreign = { identity: f.stranger, card: f.strangerDevice, vc: f.issue(f.stranger, f.strangerDevice) };
  assert.equal((await f.invoke(f.query(failed.id), foreign)).body.error.code, -32001);
  assert.equal((await f.invoke(f.continuation(failed), foreign)).body.error.code, -32001);
  assert.equal((await f.invoke(f.query(randomUUID()))).body.error.code, -32001);
});

test('a known broadcast transaction is preserved without claiming settlement rollback', async t => {
  const f = await fixture(t), before = await f.negotiate();
  f.hooks.execute = () => {
    const error = new AppError('X402_SETTLEMENT_PENDING', 'chain confirmation timed out', 503);
    error.settlementResponse = { success: false, errorReason: 'settlement_pending', transaction };
    throw error;
  };
  const result = await f.invoke(f.continuation(before));
  assert.equal(result.status, 200);
  const message = result.body.result.status.message;
  assert.equal(result.body.result.status.state, 'failed');
  assert.equal(message.metadata['x402.payment.receipts'][0].transaction, transaction);
  assert.equal(message.metadata['x402.payment.receipts'][0].errorReason, 'settlement_pending');
  assert.match(message.parts[0].text, /不表示资金已回滚/);
});

test('an empty SDK transaction does not mask a valid known broadcast hash', async t => {
  const f = await fixture(t), before = await f.negotiate();
  f.hooks.execute = () => {
    const error = new AppError('X402_SETTLEMENT_PENDING', 'confirmation pending', 503);
    error.settlementResponse = { success: false, errorReason: 'settlement_pending', transaction: '' };
    error.transaction = 'unknown';
    error.transactionHash = transaction;
    throw error;
  };
  const result = await f.invoke(f.continuation(before));
  assert.equal(result.status, 200);
  assert.equal(result.body.result.status.message.metadata['x402.payment.receipts'][0].transaction, transaction);
});

test('concurrent continuations serialize and cannot overwrite a completed Task with a late failure', async t => {
  const f = await fixture(t), before = await f.negotiate();
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  f.hooks.execute = async input => {
    if (input.payload.marker === 'bad') throw new AppError('X402_VERIFICATION_FAILED', 'late invalid payload');
    entered.resolve(); await release.promise;
    return { outcome: 'EXECUTED', receipt: { ...input.payment, receiptId: 'receipt-first', transactionHash: transaction, settlementResponse: { success: true, network: 'eip155:31337', transaction } } };
  };
  const goodRequest = await f.prepare(f.continuation(before));
  const badRequest = await f.prepare(f.continuation(before, { marker: 'bad' }));
  const goodPending = f.send(goodRequest);
  await entered.promise;
  const badPending = f.send(badRequest);
  // Wait until B has authenticated both continuations before releasing the
  // good backend operation. The bad continuation must be waiting on its Task.
  for (let attempts = 0; attempts < 100; attempts++) {
    const audit = await f.admin('audit');
    if (audit.body.events.filter(event => event.event === 'authenticated').length >= 3) break;
    assert.notEqual(attempts, 99, 'both continuations reached authentication');
  }
  release.resolve();
  const [good, bad] = await Promise.all([goodPending, badPending]);
  assert.equal(good.status, 200); assert.equal(bad.status, 200);
  assert.equal(good.body.result.status.state, 'completed');
  assert.equal(bad.body.result.status.state, 'completed');
  assert.equal(f.calls.execute, 1, 'late invalid payload never reaches backend after successful completion');
  const outcome = task => task.artifacts.flatMap(a => a.parts).find(p => p.kind === 'data').data.paymentResult;
  assert.equal(outcome(good.body.result).outcome, 'EXECUTED');
  assert.equal(outcome(bad.body.result).outcome, 'ALREADY_PROCESSED');
  assert.deepEqual(outcome(bad.body.result).receipt, outcome(good.body.result).receipt);
  assert.deepEqual((await f.invoke(f.query(before.id))).body.result, good.body.result, 'stored success and original history are unchanged');
});

for (const code of ['PAYMENT_AUTHORIZATION_EXPIRED', 'CREDENTIAL_REVOKED', 'STATUS_UNAVAILABLE']) {
  test(`backend ${code} is a request rejection and leaves the negotiated Task unchanged`, async t => {
    const f = await fixture(t), before = await f.negotiate();
    f.hooks.execute = () => { throw new AppError(code, 'live revalidation rejected', 403); };
    const rejected = await f.invoke(f.continuation(before));
    assert.equal(rejected.status, 403);
    assert.equal(rejected.body.error.data.reason, code);
    assert.deepEqual((await f.invoke(f.query(before.id))).body.result, before);
  });
}

test('invalid Owner and missing device proof cannot mutate an existing Task', async t => {
  const f = await fixture(t), before = await f.negotiate();
  const changed = f.continuation(before);
  delete changed.params.message.parts[0].data.authorization;
  const ownerRejected = await f.invoke(changed);
  assert.ok(ownerRejected.body.error);
  assert.deepEqual((await f.invoke(f.query(before.id))).body.result, before);
  const request = await f.prepare(f.continuation(before));
  request.deviceProof = '';
  const deviceRejected = await f.send(request);
  assert.equal(deviceRejected.status, 401);
  assert.equal(deviceRejected.body.error.data.reason, 'DEVICE_PROOF_REQUIRED');
  assert.deepEqual((await f.invoke(f.query(before.id))).body.result, before);
  assert.equal(f.calls.execute, 0);
});

test('admin credential status is authorized, narrowly scoped and validates its ID', async t => {
  const f = await fixture(t), path = `credential-status?id=${encodeURIComponent(f.credentialId)}`;
  assert.equal((await f.admin(path, undefined, '')).status, 403);
  assert.deepEqual(await f.admin(path), { status: 200, body: { id: f.credentialId, revoked: false } });
  assert.equal((await f.admin('revoke', { id: f.credentialId })).status, 200);
  assert.deepEqual(await f.admin(path), { status: 200, body: { id: f.credentialId, revoked: true } });
  const other = 'urn:uuid:unlisted';
  assert.deepEqual((await f.admin(`credential-status?id=${encodeURIComponent(other)}`)).body, { id: other, revoked: false });
  for (const suffix of ['', '?id=', '?id=a&id=b', `?id=${'a'.repeat(257)}`, '?id=%20', '?id=a%00b']) {
    const response = await f.admin(`credential-status${suffix}`);
    assert.equal(response.status, 400, suffix);
    assert.equal(response.body.error.code, 'INVALID_ID');
  }
});

for (const phase of ['negotiation', 'continuation']) {
  test(`revocation while backend snapshot is awaiting stops ${phase} without Task mutation`, async t => {
    const f = await fixture(t), before = phase === 'continuation' ? await f.negotiate() : null;
    f.hooks.snapshot = async () => { assert.equal((await f.admin('revoke', { id: f.credentialId })).status, 200); };
    const result = await f.invoke(before ? f.continuation(before) : paymentRpc(f.payment, f.authorization));
    assert.equal(result.status, 400);
    assert.equal(result.body.error.data.reason, 'CREDENTIAL_REVOKED');
    assert.equal(f.calls.execute, 0);
    assert.equal(f.calls.requirements, before ? 1 : 0);
    const audit = (await f.admin('audit')).body;
    assert.equal(audit.stats.tasks, before ? 1 : 0);
    assert.equal(audit.events.some(event => event.event === 'x402_payment_failed'), false);
    // A fresh valid credential can inspect the original task after revocation.
    if (before) assert.deepEqual((await f.invoke(f.query(before.id), { vc: f.issue() })).body.result, before);
  });
}

test('Owner expiry during an awaited snapshot stops settlement without changing the Task', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = await fixture(t, { authorizationSeconds: 2 }), before = await f.negotiate();
  f.hooks.snapshot = async () => { t.mock.timers.tick(3000); };
  const result = await f.invoke(f.continuation(before));
  assert.equal(result.status, 403);
  assert.equal(result.body.error.data.reason, 'PAYMENT_AUTHORIZATION_EXPIRED');
  assert.equal(f.calls.execute, 0);
  assert.deepEqual((await f.invoke(f.query(before.id))).body.result, before);
});
