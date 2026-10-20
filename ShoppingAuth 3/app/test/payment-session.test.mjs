import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { generateIdentity, issueCredential, verifyJws } from '../lib/identity.mjs';
import { createVerifier } from '../lib/verifier.mjs';
import { createEsim } from '../lib/esim.mjs';
import { createPaymentSession } from '../lib/payment-session.mjs';
import { PAYMENT_SCOPE, PAYMENT_AUTH_TYP, paymentRpc } from '../lib/payment.mjs';
import { SCOPE, AppError, prepareRequest, attachDeviceProof, transmit } from '../lib/protocol.mjs';

async function fixture(t) {
  const issuer = generateIdentity('Owner / Issuer'), agentA = generateIdentity('A'), agentB = generateIdentity('B');
  const adminToken = randomBytes(32).toString('base64url'), accessToken = randomBytes(32).toString('base64url');
  const verifier = createVerifier({ identity: agentB, trustedIssuers: [issuer.did], trustedAuthorizers: [issuer.did], adminToken, ledgerPath: ':memory:' });
  t.after(() => verifier.close());
  const baseUrl = await verifier.listen();
  const esim = createEsim({ accessToken, holderDid: agentA.did, verifierDid: agentB.did, verifierUrl: baseUrl, trustedIssuers: [issuer.did] });
  t.after(() => esim.close());
  const deviceUrl = await esim.listen();
  const device = { did: esim.publicInfo().did, baseUrl: deviceUrl, accessToken };
  let credential;
  const replaceCredential = (options = {}) => {
    const token = issueCredential(issuer, { subjectDid: agentA.did, audience: agentB.did, scopes: [SCOPE, PAYMENT_SCOPE], deviceDid: device.did, ...options });
    const document = verifyJws(token, { typ: 'vc+jwt', purpose: 'assertionMethod' }).payload;
    credential = { token, document, id: document.id, revoked: false };
    return credential;
  };
  replaceCredential();
  let preparedCount = 0;
  const bare = rpc => prepareRequest({ identity: agentA, verifierDid: agentB.did, baseUrl, credential: credential?.token, rpc });
  const prepare = async rpc => { preparedCount++; return attachDeviceProof(await bare(rpc), device); };
  const request = async (url, headers, body) => {
    const response = await fetch(url, { method: body === undefined ? 'GET' : 'POST', headers: { ...headers, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const data = await response.json();
    if (!response.ok) throw new AppError(data.error?.code ?? 'REMOTE_ERROR', data.error?.message ?? 'Request failed', response.status);
    return data;
  };
  const admin = (path, body) => request(`${baseUrl}${path}`, { 'X-Demo-Admin': adminToken }, body);
  const session = createPaymentSession({
    issuer, agentA, verifierDid: agentB.did, device, getCredential: () => credential,
    prepare, invoke: async rpc => transmit(await prepare(rpc)), invokeBare: async rpc => transmit(await bare(rpc)), admin,
  });
  return {
    session, issuer, agentA, agentB, device, admin,
    replaceCredential,
    getCredential: () => credential,
    setCredential: value => { credential = value; },
    preparedCount: () => preparedCount,
    invoke: async rpc => transmit(await prepare(rpc)),
    deviceStatus: () => request(`${device.baseUrl}/health`, {}),
    lockDevice: locked => request(`${device.baseUrl}/lock`, { 'X-ESIM-Access': accessToken }, { locked }),
    confirmation: async () => ({ confirmed: true, payment: (await session.state()).order }),
  };
}

test('payment session requires exact explicit confirmation without implicitly signing or paying', async t => {
  const f = await fixture(t);
  const before = await f.session.state();
  for (const body of [undefined, {}, { confirmed: false, payment: before.order }, { confirmed: 'true', payment: before.order }, { confirmed: true, payment: before.order, extra: true }]) {
    await assert.rejects(f.session.approve(body), { code: 'PAYMENT_CONFIRMATION_REQUIRED' });
  }
  for (const payment of [{ ...before.order, amountMinor: 1 }, { ...before.order, payeeAccount: 'merchant:other' }, { ...before.order, orderId: 'stale-order' }, { ...before.order, extra: true }]) {
    await assert.rejects(f.session.approve({ confirmed: true, payment }), { code: 'PAYMENT_ORDER_CHANGED' });
  }
  await assert.rejects(f.session.pay(), { code: 'PAYMENT_AUTHORIZATION_REQUIRED' });
  await assert.rejects(f.session.retry(), { code: 'PAYMENT_AUTHORIZATION_REQUIRED' });
  const after = await f.session.state();
  assert.deepEqual(after, before);
  assert.equal(f.preparedCount(), 0);
  after.order.amountMinor = 1;
  assert.equal((await f.session.state()).order.amountMinor, 29900, 'state readers cannot mutate the pending order');
});

test('Owner approval checks the signed VC, payment scope, time, revocation and exact bound device', async t => {
  const f = await fixture(t);
  const consent = await f.confirmation();
  f.setCredential(null);
  await assert.rejects(f.session.approve(consent), { code: 'NO_CREDENTIAL' });
  f.replaceCredential({ scopes: [SCOPE] });
  // Mutating the convenience document cannot add a permission absent in its signature.
  f.getCredential().document.credentialSubject.scopes.push(PAYMENT_SCOPE);
  await assert.rejects(f.session.approve(consent), { code: 'CREDENTIAL_SCOPE_DENIED' });
  f.replaceCredential({ validFrom: Date.now() - 120000, validUntil: Date.now() - 60000 });
  await assert.rejects(f.session.approve(consent), { code: 'CREDENTIAL_EXPIRED' });
  f.replaceCredential({ deviceDid: generateIdentity('unbound device').did });
  await assert.rejects(f.session.approve(consent), { code: 'CREDENTIAL_DEVICE_MISMATCH' });
  f.replaceCredential().revoked = true;
  await assert.rejects(f.session.approve(consent), { code: 'CREDENTIAL_REVOKED' });
  assert.equal((await f.session.state()).authorization, null);
  assert.equal((await f.session.state()).ledger.executionCount, 0);
  assert.equal(f.preparedCount(), 0);
});

test('approval signs with Owner and real HTTP pay/retry returns a single ledger receipt', async t => {
  const f = await fixture(t);
  const credentialToken = f.getCredential().token;
  const approved = await f.session.approve(await f.confirmation());
  const verified = verifyJws(approved.authorization.token, { typ: PAYMENT_AUTH_TYP, purpose: 'assertionMethod', expectedDid: f.issuer.did });
  assert.notEqual(verified.signerDid, f.agentA.did);
  assert.deepEqual(verified.payload.payment, approved.order);
  assert.equal(approved.authorization.id, verified.payload.authorizationId);
  assert.equal(approved.ledger.executionCount, 0, 'consent alone does not debit');
  const paid = await f.session.pay();
  assert.equal(paid.paymentResult.outcome, 'EXECUTED');
  assert.equal(paid.verification.deviceSignature, true);
  assert.equal(paid.paymentResult.receipt.payerBalanceMinor, 70100);
  assert.equal(paid.paymentResult.receipt.payeeBalanceMinor, 29900);
  const retry = await f.session.retry();
  assert.equal(retry.paymentResult.outcome, 'ALREADY_PROCESSED');
  assert.deepEqual(retry.paymentResult.receipt, paid.paymentResult.receipt);
  const final = await f.session.state();
  assert.equal(final.ledger.executionCount, 1);
  assert.equal(final.authorization.token, approved.authorization.token, 'pay/retry cannot mint another authorization');
  assert.equal(f.getCredential().token, credentialToken, 'pay/retry cannot issue a VC');
  assert.deepEqual(final.lastResult, retry.paymentResult);
  final.authorization.document.payment.amountMinor = 1;
  assert.equal((await f.session.state()).authorization.document.payment.amountMinor, 29900);
});

test('invalidating an authorization and creating a fresh order never charge or authorize implicitly', async t => {
  const f = await fixture(t);
  const first = await f.session.approve(await f.confirmation());
  await f.session.pay();
  const before = await f.session.state();
  f.session.invalidate();
  let state = await f.session.state();
  assert.equal(state.authorization, null);
  assert.equal(state.lastResult, null);
  assert.deepEqual(state.order, first.order);
  assert.deepEqual(state.ledger, before.ledger);
  await assert.rejects(f.session.pay(), { code: 'PAYMENT_AUTHORIZATION_REQUIRED' });
  state = await f.session.newOrder();
  assert.notEqual(state.order.orderId, first.order.orderId);
  assert.equal(state.authorization, null);
  assert.equal(state.lastResult, null);
  assert.deepEqual(state.ledger, before.ledger);
  await assert.rejects(f.session.approve({ confirmed: true, payment: first.order }), { code: 'PAYMENT_ORDER_CHANGED' });
});

test('payment demonstration verifies attacks, fresh-challenge concurrency and repeat-run idempotency over real HTTP', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const consent = await f.confirmation(), originalVC = f.getCredential().token;
  const demo = await f.session.demo(consent);
  assert.equal(demo.passed, demo.total, JSON.stringify(demo.results));
  assert.ok(demo.results.every(result => result.pass && result.actual === result.expected));
  for (const code of ['PAYMENT_AUTHORIZATION_REQUIRED', 'PAYMENT_TERMS_MISMATCH', 'DEVICE_PROOF_REQUIRED', 'REPLAYED_CHALLENGE', 'ALREADY_PROCESSED']) {
    assert.ok(demo.results.some(result => result.actual === code), `${code} must be exercised`);
  }
  assert.equal(demo.afterLedger.executionCount - demo.beforeLedger.executionCount, 1);
  assert.equal(demo.afterLedger.accounts.find(account => account.id === 'demo:alice').balanceMinor, 70100);
  const once = await f.session.state();
  const repeated = await f.session.demo(consent);
  assert.equal(repeated.passed, repeated.total, JSON.stringify(repeated.results));
  assert.deepEqual(repeated.afterLedger, demo.afterLedger, 'running the same explicitly confirmed order again must not debit it twice');
  const twice = await f.session.state();
  assert.deepEqual(twice.order, once.order);
  assert.notEqual(twice.authorization.id, once.authorization.id, 'the repeat demo exercises a fresh Owner authorization for the same order');
  assert.equal(twice.lastResult.outcome, 'ALREADY_PROCESSED');
  assert.equal(f.getCredential().token, originalVC);
  assert.equal(f.getCredential().revoked, false);
  assert.equal((await f.deviceStatus()).locked, false);
});

test('a payment demo neither unlocks a locked device nor bypasses its refusal', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  const before = await f.session.state();
  await f.lockDevice(true);
  const demo = await f.session.demo({ confirmed: true, payment: before.order });
  assert.ok(demo.passed < demo.total);
  assert.ok(demo.results.some(result => result.actual === 'ESIM_LOCKED'));
  assert.deepEqual((await f.session.state()).ledger, before.ledger);
  assert.equal((await f.deviceStatus()).locked, true);
  assert.equal(f.getCredential().revoked, false);
});

test('final verifier revocation rejects payment even if the local VC flag is stale', async t => {
  const f = await fixture(t);
  await f.session.approve(await f.confirmation());
  await f.admin('/admin/revoke', { id: f.getCredential().id });
  assert.equal(f.getCredential().revoked, false);
  await assert.rejects(f.session.pay(), { code: 'CREDENTIAL_REVOKED' });
  assert.equal((await f.session.state()).ledger.executionCount, 0);
});

test('deep but valid payment JSON is rejected before ledger commit and does not consume the Owner authorization', async t => {
  const f = await fixture(t);
  const approved = await f.session.approve(await f.confirmation());
  const rpc = paymentRpc(approved.order, approved.authorization.token);
  let nested = { value: 'valid JSON at the innermost level' };
  for (let level = 0; level < 2000; level++) nested = { next: nested };
  rpc.params.message.metadata = nested;
  assert.doesNotThrow(() => JSON.stringify(rpc), 'the regression uses valid JSON, not a serialization failure');
  await assert.rejects(f.invoke(rpc), { code: -32602 });
  const rejected = await f.session.state();
  assert.equal(rejected.ledger.executionCount, 0);
  assert.deepEqual(rejected.ledger, approved.ledger, 'deep metadata cannot debit before task construction fails');
  assert.equal(rejected.authorization.token, approved.authorization.token);
  const retry = await f.session.pay();
  assert.equal(retry.paymentResult.outcome, 'EXECUTED');
  assert.equal(retry.paymentResult.receipt.authorizationId, approved.authorization.id);
  assert.equal(retry.paymentResult.receipt.payerBalanceMinor, 70100);
  assert.equal((await f.session.state()).ledger.executionCount, 1);
});

test('present pushNotificationConfig values false/null/0 are rejected before any payment debit', async t => {
  const f = await fixture(t);
  const approved = await f.session.approve(await f.confirmation());
  for (const value of [false, null, 0]) {
    const rpc = paymentRpc(approved.order, approved.authorization.token);
    rpc.params.configuration = { pushNotificationConfig: value };
    await assert.rejects(f.invoke(rpc), { code: -32003 }, `pushNotificationConfig=${String(value)}`);
    const rejected = await f.session.state();
    assert.equal(rejected.ledger.executionCount, 0);
    assert.deepEqual(rejected.ledger, approved.ledger, 'unsupported task configuration cannot partially execute a payment');
    assert.equal(rejected.authorization.token, approved.authorization.token);
  }
  const clean = await f.session.pay();
  assert.equal(clean.paymentResult.outcome, 'EXECUTED');
  assert.equal(clean.paymentResult.receipt.authorizationId, approved.authorization.id);
  assert.equal((await f.session.state()).ledger.executionCount, 1);
});
