import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { createEsim } from '../lib/esim.mjs';
import { generateIdentity, issueCredential, verifyJws } from '../lib/identity.mjs';
import { issuePaymentAuthorization, paymentRpc, PAYMENT_SCOPE } from '../lib/payment.mjs';
import { SCOPE, prepareRequest, serializeIdentity, transmit } from '../lib/protocol.mjs';
import { createVerifier } from '../lib/verifier.mjs';

const INITIAL_BALANCES = { 'demo:alice': 100000, 'merchant:keyboard': 0, 'merchant:other': 0 };

function balances(snapshot) {
  return Object.fromEntries(snapshot.accounts.map(account => [account.id, account.balanceMinor]));
}

function paymentResult(response) {
  assert.equal(response.verification.responseSignature, true);
  assert.equal(response.verification.deviceSignature, true);
  const parts = response.task.artifacts.flatMap(artifact => artifact.parts);
  const result = parts.find(part => part.kind === 'data' && part.data.paymentResult)?.data.paymentResult;
  assert.ok(result, 'the authenticated task includes a payment result');
  assert.ok(['EXECUTED', 'ALREADY_PROCESSED'].includes(result.outcome));
  return result;
}

function childVerifier(config, testContext) {
  let child, closed;
  return {
    get pid() { return child?.pid; },
    async listen(port = 0) {
      child = fork(new URL('./fixtures/legacy-ledger-b.mjs', import.meta.url), [], {
        execArgv: [], stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
      });
      closed = new Promise(resolve => child.once('close', resolve));
      let stderr = '';
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => finish(new Error(`Agent B readiness timeout: ${stderr}`)), 8000);
        const error = cause => finish(cause);
        const exit = (code, signal) => finish(new Error(`Agent B exited before readiness: ${code ?? signal}; ${stderr}`));
        const abort = () => finish(new Error('Agent B startup aborted by test timeout.'));
        const message = value => {
          if (value?.error) finish(new Error(value.error));
          else if (value?.ready === true && value.pid === child.pid) finish(null, value.baseUrl);
        };
        function finish(cause, baseUrl) {
          clearTimeout(timer);
          child.off('error', error);
          child.off('exit', exit);
          child.off('message', message);
          testContext.signal.removeEventListener('abort', abort);
          if (cause) reject(cause); else resolve(baseUrl);
        }
        child.once('error', error);
        child.once('exit', exit);
        child.on('message', message);
        testContext.signal.addEventListener('abort', abort, { once: true });
        // Signing material is sent only over the fork's private IPC channel.
        child.send({
          identity: serializeIdentity(config.identity),
          trustedIssuers: [...config.trustedIssuers],
          trustedAuthorizers: [...config.trustedAuthorizers],
          adminToken: config.adminToken, ledgerPath: config.ledgerPath, port,
        });
      });
    },
    async close() {
      if (!child || child.exitCode !== null || child.signalCode !== null) return;
      child.kill('SIGTERM');
      const timer = setTimeout(() => child.kill('SIGKILL'), 2000);
      timer.unref();
      try { await closed; } finally { clearTimeout(timer); }
    },
  };
}

// Each scenario has a separate real HTTP verifier, real simulated-device API
// and temporary on-disk ledger. No simulated-device private key is available
// to this test; every dual proof comes through prepareRequest -> /sign.
async function fixture(t, { scopes = [PAYMENT_SCOPE, SCOPE], processVerifier = false } = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'a2a-payment-http-'));
  const issuer = generateIdentity('Payment VC issuer');
  const owner = generateIdentity('Independent payment owner');
  const holder = generateIdentity('Payment Agent A');
  const verifierIdentity = generateIdentity('Payment Agent B');
  const outsider = generateIdentity('Untrusted payment owner');
  const adminToken = randomBytes(32).toString('base64url');
  const accessToken = randomBytes(32).toString('base64url');
  const config = {
    identity: verifierIdentity,
    trustedIssuers: new Set([issuer.did]),
    trustedAuthorizers: new Set([owner.did]),
    adminToken,
    ledgerPath: join(directory, 'ledger.sqlite'),
  };
  let verifier, esim, fetchMock;
  const originalFetch = globalThis.fetch;
  t.after(async () => {
    try {
      if (esim) await esim.close();
      if (verifier) await verifier.close();
    } finally {
      fetchMock?.mock.restore();
      assert.equal(globalThis.fetch, originalFetch, 'fixture restores its transparent fetch wrapper');
      await rm(directory, { recursive: true, force: true });
    }
  });
  const makeVerifier = () => processVerifier ? childVerifier(config, t) : createVerifier(config);
  verifier = makeVerifier();
  const baseUrl = await verifier.listen();
  // All signatures and responses still traverse real HTTP. Only this B's
  // connection reuse is disabled so intentionally rebinding its port cannot
  // race with undici retaining sockets from the previous verifier lifetime.
  fetchMock = t.mock.method(globalThis, 'fetch', (input, options = {}) => {
    const url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url);
    if (url.origin !== baseUrl) return originalFetch(input, options);
    const headers = new Headers(options.headers ?? (input instanceof Request ? input.headers : undefined));
    headers.set('Connection', 'close');
    return originalFetch(input, { ...options, headers });
  });
  esim = createEsim({ accessToken, holderDid: holder.did, verifierDid: verifierIdentity.did, verifierUrl: baseUrl, trustedIssuers: new Set([issuer.did]) });
  const deviceUrl = await esim.listen();
  const device = { did: esim.publicInfo().deviceDid, baseUrl: deviceUrl, accessToken };
  const credential = issueCredential(issuer, { subjectDid: holder.did, deviceDid: device.did, audience: verifierIdentity.did, scopes });
  const payment = { orderId: `order-${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 299, currency: 'CNY' };
  const authorize = ({ terms = payment, vc = credential, signer = owner, ...overrides } = {}) => issuePaymentAuthorization(signer, {
    holderDid: holder.did, deviceDid: device.did, verifierDid: verifierIdentity.did,
    credential: vc, payment: terms, ...overrides,
  });
  const authorization = authorize();
  const prepare = (rpc = paymentRpc(payment, authorization), vc = credential) => prepareRequest({
    identity: holder, verifierDid: verifierIdentity.did, baseUrl, credential: vc, rpc, device,
  });
  const invoke = async (...args) => transmit(await prepare(...args));
  async function admin(path, body) {
    const response = await fetch(`${baseUrl}/admin/${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      // An administrative snapshot may be the last request before B is
      // deliberately torn down and rebound to the same port. Do not let the
      // test's HTTP pool race to reuse that stopped server's keepalive socket.
      headers: { 'X-Demo-Admin': adminToken, Connection: 'close', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    assert.equal(response.status, 200, `admin ${path} status`);
    return response.json();
  }
  async function restart() {
    const port = Number(new URL(baseUrl).port);
    const previous = verifier;
    verifier = undefined;
    await previous.close();
    verifier = makeVerifier();
    assert.equal(await verifier.listen(port), baseUrl, 'same DID, endpoint and database after reopening B');
  }
  const issue = selectedScopes => issueCredential(issuer, {
    subjectDid: holder.did, deviceDid: device.did, audience: verifierIdentity.did, scopes: selectedScopes,
  });
  return { issuer, owner, holder, verifierIdentity, outsider, baseUrl, device, credential, payment, authorization, authorize, prepare, invoke, admin, restart, issue, get verifierPid() { return verifier?.pid; } };
}

async function rejectPaymentWithoutMutation(f, rpc, code) {
  const before = await f.admin('ledger');
  const request = await f.prepare(rpc);
  assert.ok(request.deviceProof, 'the real simulated-device API signed this exact request');
  await assert.rejects(transmit(request), { code });
  assert.deepEqual(await f.admin('ledger'), before, 'rejected payment leaves balances and execution records unchanged');
}

test('valid holder and real device signatures cannot pay without separate Owner authorization', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const rpc = paymentRpc(f.payment, f.authorization);
  delete rpc.params.message.parts[0].data.authorization;
  await rejectPaymentWithoutMutation(f, rpc, 'PAYMENT_AUTHORIZATION_REQUIRED');
});

for (const [field, change] of [
  ['amount', payment => { payment.amountMinor++; }],
  ['payee', payment => { payment.payeeAccount = 'merchant:other'; }],
  ['order', payment => { payment.orderId = `order-${randomUUID()}`; }],
]) {
  test(`fresh valid dual signatures cannot change the Owner-approved payment ${field}`, { timeout: 30000 }, async t => {
    const f = await fixture(t);
    const payment = structuredClone(f.payment);
    change(payment);
    await rejectPaymentWithoutMutation(f, paymentRpc(payment, f.authorization), 'PAYMENT_TERMS_MISMATCH');
  });
}

test('payment authority is pinned separately from valid VC and dual-signer identity', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const authorization = f.authorize({ signer: f.outsider });
  await rejectPaymentWithoutMutation(f, paymentRpc(f.payment, authorization), 'PAYMENT_AUTHORIZER_UNTRUSTED');
  // Even the trusted VC issuer cannot grant this Owner's payment authority.
  await rejectPaymentWithoutMutation(f, paymentRpc(f.payment, f.authorize({ signer: f.issuer })), 'PAYMENT_AUTHORIZER_UNTRUSTED');
});

test('echo-only VC is rejected by the real device before it can authorize a payment request', { timeout: 30000 }, async t => {
  const f = await fixture(t, { scopes: [SCOPE] });
  await assert.rejects(f.prepare(), { code: 'ESIM_INVALID_REQUEST' });
  const snapshot = await f.admin('ledger');
  assert.deepEqual(balances(snapshot), INITIAL_BALANCES);
  assert.equal(snapshot.executionCount, 0);
  assert.deepEqual(snapshot.receipts, []);
});

test('pay-only VC can execute and read its task; a dual-signed echo-only VC cannot read the payment task', { timeout: 30000 }, async t => {
  const f = await fixture(t, { scopes: [PAYMENT_SCOPE] });
  const first = await f.invoke();
  const result = paymentResult(first);
  assert.equal(result.outcome, 'EXECUTED');
  const query = { jsonrpc: '2.0', id: randomUUID(), method: 'tasks/get', params: { id: first.task.id } };
  assert.deepEqual((await f.invoke(query)).task, first.task);
  const echoCredential = f.issue([SCOPE]);
  const echoRequest = await f.prepare(query, echoCredential);
  assert.ok(echoRequest.deviceProof, 'echo task queries are signed by the real device');
  await assert.rejects(transmit(echoRequest), { code: 'CREDENTIAL_SCOPE_DENIED' });
  const snapshot = await f.admin('ledger');
  assert.equal(snapshot.executionCount, 1);
  assert.deepEqual(balances(snapshot), { ...INITIAL_BALANCES, 'demo:alice': 99701, 'merchant:keyboard': 299 });
});

test('new challenges for the same payment authorization return the original receipt without a second debit', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const firstRequest = await f.prepare();
  const first = paymentResult(await transmit(firstRequest));
  assert.equal(first.outcome, 'EXECUTED');
  const before = await f.admin('ledger');
  const retry = await f.prepare();
  assert.notEqual(retry.challenge.nonce, firstRequest.challenge.nonce);
  assert.notEqual(retry.token, firstRequest.token);
  assert.notEqual(retry.deviceProof, firstRequest.deviceProof);
  const duplicate = paymentResult(await transmit(retry));
  assert.equal(duplicate.outcome, 'ALREADY_PROCESSED');
  assert.deepEqual(duplicate.receipt, first.receipt);
  assert.deepEqual(await f.admin('ledger'), before);
});

test('concurrent independently challenged dual-signed attempts execute a payment only once', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const requests = await Promise.all(Array.from({ length: 12 }, () => f.prepare()));
  assert.equal(new Set(requests.map(request => request.challenge.nonce)).size, 12);
  const results = (await Promise.all(requests.map(transmit))).map(paymentResult);
  assert.equal(results.filter(result => result.outcome === 'EXECUTED').length, 1);
  assert.equal(results.filter(result => result.outcome === 'ALREADY_PROCESSED').length, 11);
  const original = results.find(result => result.outcome === 'EXECUTED').receipt;
  for (const result of results) assert.deepEqual(result.receipt, original);
  const snapshot = await f.admin('ledger');
  assert.equal(snapshot.executionCount, 1);
  assert.deepEqual(snapshot.receipts, [original]);
  assert.deepEqual(balances(snapshot), { ...INITIAL_BALANCES, 'demo:alice': 99701, 'merchant:keyboard': 299 });
});

test('same order with a new Owner authorization also reuses its execution record', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const first = paymentResult(await f.invoke());
  const authorization = f.authorize();
  assert.notEqual(authorization, f.authorization);
  const retry = paymentResult(await f.invoke(paymentRpc(f.payment, authorization)));
  assert.equal(retry.outcome, 'ALREADY_PROCESSED');
  assert.deepEqual(retry.receipt, first.receipt);
  assert.equal((await f.admin('ledger')).executionCount, 1);
});

test('closing and reopening Agent B preserves receipt and balances for a newly challenged retry', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const firstRequest = await f.prepare();
  const first = paymentResult(await transmit(firstRequest));
  assert.equal(first.outcome, 'EXECUTED');
  const before = await f.admin('ledger');
  await f.restart();
  assert.deepEqual(await f.admin('ledger'), before, 'committed receipt survives connection and verifier teardown');
  const newRequest = await f.prepare();
  assert.notEqual(newRequest.challenge.nonce, firstRequest.challenge.nonce);
  const retried = paymentResult(await transmit(newRequest));
  assert.equal(retried.outcome, 'ALREADY_PROCESSED');
  assert.deepEqual(retried.receipt, first.receipt);
  assert.deepEqual(await f.admin('ledger'), before, 'restart cannot reset at-most-once execution');
});

test('a new operating-system Agent B process restores the same payment receipt from the durable database', { timeout: 30000 }, async t => {
  const f = await fixture(t, { processVerifier: true });
  const originalPid = f.verifierPid;
  assert.ok(Number.isInteger(originalPid) && originalPid !== process.pid);
  const originalDevice = await (await fetch(`${f.device.baseUrl}/health`)).json();
  const originalRequest = await f.prepare();
  const original = paymentResult(await transmit(originalRequest));
  assert.equal(original.outcome, 'EXECUTED');
  const before = await f.admin('ledger');
  assert.equal(before.executionCount, 1);
  assert.deepEqual(balances(before), { ...INITIAL_BALANCES, 'demo:alice': 99701, 'merchant:keyboard': 299 });
  await f.restart();
  assert.notEqual(f.verifierPid, originalPid, 'the replacement B has a fresh OS process identity');
  assert.notEqual(f.verifierPid, process.pid);
  assert.throws(() => process.kill(originalPid, 0), { code: 'ESRCH' }, 'the original B process has exited');
  const health = await (await fetch(`${f.baseUrl}/health`)).json();
  assert.equal(health.pid, f.verifierPid);
  assert.equal(health.did, f.verifierIdentity.did);
  const currentDevice = await (await fetch(`${f.device.baseUrl}/health`)).json();
  assert.equal(currentDevice.did, originalDevice.did, 'the real simulated device remains running');
  assert.equal(currentDevice.pid, originalDevice.pid);
  assert.deepEqual(await f.admin('ledger'), before);
  const retryRequest = await f.prepare();
  assert.notEqual(retryRequest.challenge.nonce, originalRequest.challenge.nonce);
  const retry = paymentResult(await transmit(retryRequest));
  assert.equal(retry.outcome, 'ALREADY_PROCESSED');
  assert.deepEqual(retry.receipt, original.receipt);
  assert.deepEqual(await f.admin('ledger'), before, 'a new B process cannot debit the same authorization again');
});

test('revoked VC remains unusable after reopening B even when Owner authorization and device signatures are valid', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const credentialId = verifyJws(f.credential, { typ: 'vc+jwt', purpose: 'assertionMethod' }).payload.id;
  assert.equal((await f.admin('revoke', { id: credentialId })).revoked, true);
  // The device has no local revocation list, so its valid dual proof exercises
  // the final executor's authoritative persistent revocation check.
  const requestBeforeRestart = await f.prepare();
  assert.ok(requestBeforeRestart.deviceProof);
  await assert.rejects(transmit(requestBeforeRestart), { code: 'CREDENTIAL_REVOKED' });
  await f.restart();
  const requestAfterRestart = await f.prepare();
  assert.ok(requestAfterRestart.deviceProof);
  await assert.rejects(transmit(requestAfterRestart), { code: 'CREDENTIAL_REVOKED' });
  const snapshot = await f.admin('ledger');
  assert.deepEqual(balances(snapshot), INITIAL_BALANCES);
  assert.equal(snapshot.executionCount, 0);
  assert.deepEqual(snapshot.receipts, []);
});
