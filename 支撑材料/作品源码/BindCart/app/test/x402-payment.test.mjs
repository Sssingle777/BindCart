import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { posixModes } from './helpers/storage-platform.mjs';
import test from 'node:test';
import { createPublicClient, http } from 'viem';
import { x402Facilitator } from '@x402/core/facilitator';
import { generateIdentity, issueCredential, signJws, verifyJws } from '../lib/identity.mjs';
import { issuePaymentAuthorization, PAYMENT_SCOPE } from '../lib/payment.mjs';
import { createLocalX402Environment, createX402Backend, createX402Payer, paymentSettlement } from '../lib/x402-payment.mjs';

const balances = snapshot => Object.fromEntries(snapshot.accounts.map(a => [a.id, a.balanceMinor]));
const rejectsCode = (promise, code) => assert.rejects(promise, error => error.code === code);

test('official x402 SDK verifies and settles an EIP-3009 transfer on a real local EVM', { timeout: 90_000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'a2a-x402-integration-'));
  const issuer = generateIdentity('x402 issuer');
  const owner = generateIdentity('x402 owner');
  const holder = generateIdentity('x402 holder');
  const device = generateIdentity('x402 device');
  const verifier = generateIdentity('x402 verifier');
  const attacker = generateIdentity('x402 attacker');
  // This isolated SDK fixture has no revocations. Production must supply B's
  // authenticated live revocation query, never this fixed fixture answer.
  const config = { stateDir: directory, trustedIssuers: [issuer.did], trustedAuthorizers: [owner.did], holderDid: holder.did, deviceDid: device.did, verifierDid: verifier.did, isCredentialRevoked: async () => false };
  let environment;
  t.after(async () => { try { await environment?.close(); } finally { await rm(directory, { recursive: true, force: true }); } });
  environment = await createLocalX402Environment(config);
  let backend = createX402Backend(environment.backendConfig);
  let payer = createX402Payer(environment.payerConfig);
  const credential = issueCredential(issuer, { subjectDid: holder.did, deviceDid: device.did, audience: verifier.did, scopes: [PAYMENT_SCOPE] });
  const payment = {
    orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard',
    amountMinor: 2_990_000, currency: 'TEST_USDC', settlement: paymentSettlement(environment.publicInfo),
  };
  const issue = (p = payment, extra = {}, signer = owner, vc = credential) => issuePaymentAuthorization(signer, {
    holderDid: holder.did, deviceDid: device.did, verifierDid: verifier.did, credential: vc, payment: p, ...extra,
  });
  const authorization = issue();
  const paymentRequired = backend.requirements(payment, { resourceUrl: 'http://127.0.0.1:4321/a2a' });
  const digest = value => createHash('sha256').update(value).digest('base64url');
  function evidence(p = payment, auth = authorization, required = paymentRequired, signer = verifier) {
    const id = randomUUID();
    const rawRequest = JSON.stringify({ jsonrpc: '2.0', id, method: 'message/send', params: { message: { parts: [{ kind: 'data', data: { scope: PAYMENT_SCOPE, payment: p, authorization: auth } }] } } });
    const rawResponse = JSON.stringify({ jsonrpc: '2.0', id, result: { kind: 'task', id: randomUUID(), status: { state: 'input-required', message: { metadata: { 'x402.payment.status': 'payment-required', 'x402.payment.required': required } } } } });
    const iat = Math.floor(Date.now() / 1000);
    const proof = signJws({ iss: signer.did, aud: holder.did, deviceDid: device.did, deviceProofHash: digest('test-device-proof'), requestHash: digest(rawRequest), responseHash: digest(rawResponse), nonce: digest(id), iat, exp: iat + 60 }, signer, 'a2a-did-response+jwt');
    return { proof, rawRequest, rawResponse };
  }
  const signInput = { payment, paymentRequired, authorization, credential, ...evidence() };
  const start = await backend.snapshot();
  let payload, result;

  await t.test('deploys the real test token and exposes no wallet secrets', async () => {
    assert.equal(environment.publicInfo.localTestOnly, true);
    assert.equal(environment.publicInfo.network, 'eip155:31337');
    assert.equal(environment.publicInfo.decimals, 6);
    assert.deepEqual(balances(start), { 'demo:alice': 1_000_000_000, 'merchant:keyboard': 0, 'merchant:other': 0 });
    assert.notEqual(environment.payerConfig.accessToken, environment.backendConfig.accessToken);
    assert.equal(new URL(environment.publicInfo.rpcUrl).hostname, '127.0.0.1');
    assert.doesNotMatch(JSON.stringify(environment.publicInfo), /privateKey|payerKey|gasKey|accessToken/);
    const reader = createPublicClient({ transport: http(environment.publicInfo.rpcUrl) });
    assert.ok((await reader.getCode({ address: environment.publicInfo.asset })).length > 20);
    const rpcWallets = await reader.request({ method: 'eth_accounts' });
    assert.ok(!rpcWallets.includes(environment.publicInfo.payerAddress), 'payer key is not an unlocked RPC account');
    assert.equal((await stat(join(directory, 'wallets.json'))).isFile(), true);
    assert.equal((await stat(join(directory, 'payments.sqlite'))).isFile(), true);
    const supported = await backend.supported();
    assert.ok(supported.kinds.some(k => k.x402Version === 2 && k.network === environment.publicInfo.network && k.scheme === 'exact'));
  });

  await t.test('wallet and payment database use POSIX private file modes', posixModes, async () => {
    assert.equal((await stat(join(directory, 'wallets.json'))).mode & 0o777, 0o600);
    assert.equal((await stat(join(directory, 'payments.sqlite'))).mode & 0o777, 0o600);
  });

  await t.test('permission tokens do not cross payer and facilitator roles', async () => {
    await rejectsCode(createX402Payer(environment.backendConfig).createPayload(signInput), 'X402_ACCESS_DENIED');
    await rejectsCode(createX402Backend(environment.payerConfig).snapshot(), 'X402_ACCESS_DENIED');
    const r = await fetch(`${environment.backendConfig.url}/snapshot`, { headers: { Authorization: `Bearer ${environment.backendConfig.accessToken}`, Origin: 'https://attacker.invalid' } });
    assert.equal(r.status, 403);
  });

  await t.test('payer requires actual Owner authorization and trusted issuer/device binding', async () => {
    await rejectsCode(payer.createPayload({ ...signInput, authorization: undefined }), 'PAYMENT_AUTHORIZATION_REQUIRED');
    await rejectsCode(payer.createPayload({ ...signInput, authorization: issue(payment, {}, attacker) }), 'PAYMENT_AUTHORIZER_UNTRUSTED');
    const badCredential = issueCredential(attacker, { subjectDid: holder.did, deviceDid: device.did, audience: verifier.did, scopes: [PAYMENT_SCOPE] });
    await assert.rejects(payer.createPayload({ ...signInput, credential: badCredential, authorization: issue(payment, {}, owner, badCredential) }), /签发|issuer|信任/i);
  });

  await t.test('network, token and recipient are bound by signed Owner terms before chain signing', async () => {
    for (const settlement of [
      { ...payment.settlement, network: 'eip155:1' },
      { ...payment.settlement, asset: environment.publicInfo.payees['merchant:other'] },
      { ...payment.settlement, payTo: environment.publicInfo.payees['merchant:other'] },
      { ...payment.settlement, payerAddress: environment.publicInfo.payees['merchant:other'] },
    ]) {
      const changed = { ...payment, settlement };
      await rejectsCode(payer.createPayload({ ...signInput, payment: changed, authorization: issue(changed) }), 'X402_SETTLEMENT_MISMATCH');
    }
  });

  await t.test('official client produces a signed v2 payload, and verify is read-only', async () => {
    payload = await payer.createPayload(signInput);
    assert.equal(payload.x402Version, 2);
    assert.match(payload.payload.signature, /^0x[0-9a-f]+$/i);
    assert.equal(payload.payload.authorization.value, String(payment.amountMinor));
    assert.equal((await backend.verify({ payment, payload })).isValid, true);
    assert.deepEqual(balances(await backend.snapshot()), balances(start));
    const tampered = structuredClone(payload);
    tampered.payload.signature = `0x${'0'.repeat(130)}`;
    assert.equal((await backend.verify({ payment, payload: tampered })).isValid, false);
  });

  await t.test('payer refuses missing, forged or different-order B device attestations', async () => {
    await rejectsCode(payer.createPayload({ ...signInput, proof: undefined }), 'X402_DEVICE_ATTESTATION_REQUIRED');
    await rejectsCode(payer.createPayload({ ...signInput, ...evidence(payment, authorization, paymentRequired, attacker) }), 'X402_DEVICE_ATTESTATION_INVALID');
    const changed = { ...payment, orderId: `urn:uuid:${randomUUID()}` };
    await rejectsCode(payer.createPayload({ ...signInput, payment: changed, authorization: issue(changed), paymentRequired: backend.requirements(changed) }), 'X402_DEVICE_ATTESTATION_MISMATCH');
    await rejectsCode(payer.createPayload({ ...signInput, rawResponse: `${signInput.rawResponse} ` }), 'X402_DEVICE_ATTESTATION_MISMATCH');
  });

  await t.test('facilitator refuses forged approval objects and mismatched signed payloads', async () => {
    await rejectsCode(backend.execute({ payment, payload, approval: { authorizationId: 'forged' }, credential }), 'PAYMENT_AUTHORIZATION_REQUIRED');
    const tampered = structuredClone(payload); tampered.payload.authorization.nonce = `0x${'1'.repeat(64)}`;
    await rejectsCode(backend.execute({ payment, payload: tampered, authorization, credential }), 'X402_UNAPPROVED_PAYLOAD');
  });

  await t.test('pending settlement preserves the original public response and transaction through HTTP', async st => {
    const transaction = `0x${'ab'.repeat(32)}`;
    const settlementResponse = { success: false, errorReason: 'settlement_pending', errorMessage: 'waiting for confirmation', transaction, network: environment.publicInfo.network, payer: environment.publicInfo.payerAddress };
    st.mock.method(x402Facilitator.prototype, 'settle', async () => settlementResponse);
    await assert.rejects(backend.execute({ payment, payload, authorization, credential }), error => {
      assert.equal(error.code, 'X402_SETTLEMENT_PENDING');
      assert.equal(error.transaction, transaction);
      assert.equal(error.transactionHash, transaction);
      assert.deepEqual(error.settlementResponse, settlementResponse);
      assert.match(error.message, /不表示资金已回滚/);
      return true;
    });
    const current = await backend.snapshot();
    assert.equal(current.executionCount, 0);
    assert.deepEqual(balances(current), balances(start));
  });

  await t.test('a thrown settlement error with a broadcast reference retains its evidence', async st => {
    const transaction = `0x${'cd'.repeat(32)}`;
    const settlementResponse = { success: false, errorReason: 'settlement_pending', transaction: '', network: environment.publicInfo.network };
    st.mock.method(x402Facilitator.prototype, 'settle', async () => {
      const error = new Error('provider response timed out');
      error.settlementResponse = settlementResponse;
      error.transaction = '';
      error.transactionHash = transaction;
      throw error;
    });
    await assert.rejects(backend.execute({ payment, payload, authorization, credential }), error => {
      assert.equal(error.code, 'X402_SETTLEMENT_PENDING');
      assert.equal(error.transaction, transaction);
      assert.deepEqual(error.settlementResponse, settlementResponse);
      return true;
    });
  });

  await t.test('receipt lookup failure after reported success keeps the reported transaction visible', async st => {
    const transaction = `0x${'ef'.repeat(32)}`;
    const settlementResponse = { success: true, transaction, network: environment.publicInfo.network, payer: environment.publicInfo.payerAddress };
    st.mock.method(x402Facilitator.prototype, 'settle', async () => settlementResponse);
    await assert.rejects(backend.execute({ payment, payload, authorization, credential }), error => {
      assert.equal(error.code, 'X402_SETTLEMENT_PENDING');
      assert.equal(error.transactionHash, transaction);
      assert.deepEqual(error.settlementResponse, settlementResponse);
      assert.match(error.message, /不表示资金已回滚/);
      return true;
    });
    assert.equal((await backend.snapshot()).executionCount, 0);
  });

  await t.test('lost settlement transport response reports an unconfirmed outcome rather than rollback', async st => {
    st.mock.method(globalThis, 'fetch', async () => { throw new TypeError('fetch failed'); });
    await assert.rejects(backend.execute({ payment, payload, authorization, credential }), error => {
      assert.equal(error.code, 'X402_SETTLEMENT_PENDING');
      assert.equal(error.transaction, undefined);
      assert.match(error.message, /交易可能已广播/);
      return true;
    });
  });

  await t.test('remote errors skip empty or invalid transaction fields before a valid transactionHash', async st => {
    const transactionHash = `0x${'de'.repeat(32)}`;
    const settlementResponse = { success: false, errorReason: 'settlement_pending', transaction: '' };
    for (const transaction of ['', 'unknown']) {
      const fetchMock = st.mock.method(globalThis, 'fetch', async () => ({
        ok: false, status: 503,
        json: async () => ({ error: { code: 'X402_SETTLEMENT_PENDING', message: 'unconfirmed', settlementResponse, transaction, transactionHash } }),
      }));
      try {
        await assert.rejects(backend.execute({ payment, payload, authorization, credential }), error => {
          assert.equal(error.code, 'X402_SETTLEMENT_PENDING');
          assert.equal(error.transaction, transactionHash);
          assert.equal(error.transactionHash, transactionHash);
          assert.deepEqual(error.settlementResponse, settlementResponse);
          return true;
        });
      } finally { fetchMock.mock.restore(); }
    }
  });

  await t.test('concurrent settlement sends one transaction and returns its real receipt/balances', async () => {
    const executions = await Promise.all(Array.from({ length: 4 }, () => backend.execute({ payment, payload, authorization, credential })));
    assert.equal(executions.filter(r => r.outcome === 'EXECUTED').length, 1);
    assert.equal(executions.filter(r => r.outcome === 'ALREADY_PROCESSED').length, 3);
    result = executions.find(r => r.outcome === 'EXECUTED');
    assert.match(result.receipt.transactionHash, /^0x[0-9a-f]{64}$/);
    assert.equal(result.receipt.transactionStatus, 'success');
    assert.equal(result.settlementResponse.success, true);
    assert.equal(result.settlementResponse.transaction, result.receipt.transactionHash);
    assert.ok(result.receipt.blockNumber > 0);
    assert.equal(new Set(executions.map(r => r.receipt.transactionHash)).size, 1);
    const after = await backend.snapshot();
    assert.deepEqual(balances(after), { 'demo:alice': 997_010_000, 'merchant:keyboard': 2_990_000, 'merchant:other': 0 });
    assert.equal(after.executionCount, 1);
    assert.equal(after.receipts.length, 1);
  });

  await t.test('new authorization for same order reuses the original signed nonce and receipt', async () => {
    const anotherAuthorization = issue();
    const anotherPayload = await payer.createPayload({ ...signInput, authorization: anotherAuthorization, ...evidence(payment, anotherAuthorization) });
    assert.deepEqual(anotherPayload, payload);
    const repeated = await backend.execute({ payment, payload: anotherPayload, authorization: anotherAuthorization, credential });
    assert.equal(repeated.outcome, 'ALREADY_PROCESSED');
    assert.equal(repeated.receipt.transactionHash, result.receipt.transactionHash);
    assert.equal((await backend.snapshot()).executionCount, 1);
    const changed = { ...payment, amountMinor: payment.amountMinor + 1 };
    const changedAuth = issue(changed), changedRequired = backend.requirements(changed);
    await rejectsCode(payer.createPayload({ payment: changed, paymentRequired: changedRequired, authorization: changedAuth, credential, ...evidence(changed, changedAuth, changedRequired) }), 'ORDER_TERMS_MISMATCH');
  });

  await t.test('a previously consumed authorization ID cannot be reassigned to another order', async () => {
    const changed = { ...payment, orderId: `urn:uuid:${randomUUID()}` };
    const changedAuth = issue(changed, { authorizationId: verifyJws(authorization, { typ: 'a2a-payment-authorization+jwt', purpose: 'assertionMethod' }).payload.authorizationId });
    const changedRequired = backend.requirements(changed);
    await rejectsCode(payer.createPayload({ payment: changed, authorization: changedAuth, credential, paymentRequired: changedRequired, ...evidence(changed, changedAuth, changedRequired) }), 'AUTHORIZATION_REUSED');
    assert.equal((await backend.snapshot()).executionCount, 1);
  });

  await t.test('after restart, on-chain nonce/event recovery works even after the signed payload expires', async st => {
    const originalAsset = environment.publicInfo.asset;
    await environment.close();
    // Simulate a crash AFTER chain settlement but BEFORE receipt persistence.
    const db = new DatabaseSync(join(directory, 'payments.sqlite'));
    db.prepare("UPDATE x402_orders SET status='SETTLING',transaction_hash=NULL,receipt_json=NULL WHERE order_id=?").run(payment.orderId);
    db.close();
    environment = await createLocalX402Environment(config);
    backend = createX402Backend(environment.backendConfig);
    payer = createX402Payer(environment.payerConfig);
    assert.equal(environment.publicInfo.asset, originalAsset);
    const wallClock = Date.now;
    st.mock.method(Date, 'now', () => wallClock() + 70_000);
    assert.ok(Number(payload.payload.authorization.validBefore) < Math.floor(Date.now() / 1000));
    assert.deepEqual(await payer.createPayload({ ...signInput, ...evidence() }), payload, 'a consumed nonce is recovered even after signature expiry');
    const recovered = await backend.execute({ payment, payload, authorization, credential });
    assert.equal(recovered.outcome, 'ALREADY_PROCESSED');
    assert.equal(recovered.receipt.transactionHash, result.receipt.transactionHash);
    assert.equal((await backend.snapshot()).executionCount, 1);
    assert.deepEqual(balances(await backend.snapshot()), { 'demo:alice': 997_010_000, 'merchant:keyboard': 2_990_000, 'merchant:other': 0 });
  });
});
