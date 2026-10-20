import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateIdentity } from '../lib/identity.mjs';
import { sendJson } from '../lib/protocol.mjs';
import { createOwner } from '../lib/owner.mjs';
import { x402Requirements } from '../lib/x402-payment.mjs';
import { createDbacIssuer, createDbacDevice } from '../lib/dbac/services.mjs';
import { createDbacPaymentVerifier } from '../lib/dbac/payment-verifier.mjs';
import { createDbacPaymentSession } from '../lib/dbac/payment-session.mjs';

const token = () => randomBytes(32).toString('base64url');
const paymentInfo = {
  network: 'eip155:31337', asset: `0x${'1'.repeat(40)}`, payerAddress: `0x${'2'.repeat(40)}`,
  payees: { 'merchant:keyboard': `0x${'3'.repeat(40)}`, 'merchant:other': `0x${'4'.repeat(40)}` },
};

// Real issuance, device proofs, verifier and Owner; only wallet signing and
// settlement are deterministic fixtures. This test is not chain acceptance.
async function fixture(t) {
  const b = generateIdentity('B'), holder = generateIdentity('A'), namedIssuer = generateIdentity('Named issuer');
  const deviceToken = token(), issuerToken = token(), proposalToken = token(), ownerUiToken = token();
  const device = createDbacDevice({ accessToken: deviceToken }), deviceUrl = await device.listen();
  t.after(() => device.close());
  const issuer = createDbacIssuer({ accessToken: issuerToken, devicePublicKeys: device.publicInfo().publicKeys });
  const issuerUrl = await issuer.listen();
  t.after(() => issuer.close());
  const owner = createOwner({ holderDid: holder.did, verifierDid: b.did, trustedIssuers: [namedIssuer.did], proposalToken, uiToken: ownerUiToken, dbacIssuerPublicKey: issuer.publicInfo().publicKey });
  const ownerUrl = await owner.listen();
  t.after(() => owner.close());
  const ledger = { accounts: [{ id: 'demo:alice', balanceMinor: 1000000000 }, { id: 'merchant:keyboard', balanceMinor: 0 }, { id: 'merchant:other', balanceMinor: 0 }], receipts: [], executionCount: 0 };
  let walletUncertain = false;
  const backend = {
    requirements: payment => x402Requirements(paymentInfo, payment),
    async execute({ payment }) {
      const existing = ledger.receipts.find(item => item.orderId === payment.orderId);
      if (existing) return { outcome: 'ALREADY_PROCESSED', receipt: existing };
      const receipt = { ...payment, receiptId: randomUUID(), transactionHash: `0x${'a'.repeat(64)}` };
      ledger.receipts.push(receipt); ledger.executionCount++;
      ledger.accounts.find(item => item.id === payment.payerAccount).balanceMinor -= payment.amountMinor;
      ledger.accounts.find(item => item.id === payment.payeeAccount).balanceMinor += payment.amountMinor;
      return { outcome: 'EXECUTED', receipt };
    },
  };
  const verifier = createDbacPaymentVerifier({ identity: b, issuerPublicKey: issuer.publicInfo().publicKey, trustedAuthorizers: [owner.publicInfo().did], getBackend: () => backend });
  let baseUrl;
  const server = http.createServer({ maxHeaderSize: 24 * 1024 }, async (req, res) => {
    try { if (!await verifier.handle(req, res, baseUrl)) sendJson(res, 404, {}); }
    catch (error) { sendJson(res, error.status ?? 400, { error: { code: error.code, message: error.message }, verificationTrace: error.verificationTrace }); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const session = createDbacPaymentSession({ baseUrl, verifierDid: b.did,
    issuer: { baseUrl: issuerUrl, accessToken: issuerToken, publicKey: issuer.publicInfo().publicKey },
    device: { baseUrl: deviceUrl, accessToken: deviceToken, publicKeys: device.publicInfo().publicKeys },
    owner: { baseUrl: ownerUrl, did: owner.publicInfo().did, proposalToken }, paymentInfo,
    x402Payer: { async createPayload({ paymentRequired }) {
      if (walletUncertain) throw Object.assign(new Error('Fixture wallet response lost after request'), { code: 'DBAC_PAYMENT_TRANSPORT' });
      return { x402Version: 2, accepted: paymentRequired.accepts[0], payload: { signature: 'fixture-only', authorization: { nonce: randomUUID() } } };
    } }, getLedger: async () => structuredClone(ledger),
  });
  async function approve() {
    const { proposal } = await session.state();
    const response = await fetch(`${ownerUrl}/api/proposals/${proposal.id}/approve`, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: ownerUrl, 'X-Owner-UI-Key': ownerUiToken }, body: JSON.stringify({ confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }) });
    assert.equal(response.status, 200, 'fixture Owner explicitly approves the exact proposal');
  }
  async function act(action) {
    const current = await session.state();
    return session.manual({ action, ...(current.manual.attemptId ? { attemptId: current.manual.attemptId } : {}) });
  }
  async function verifyPhase(phase) {
    for (const action of [`begin-${phase}`, 'device-sign', 'prove', 'verify']) await act(action);
  }
  return { session, ledger, act, verifyPhase, approve, setWalletUncertain: value => { walletUncertain = value; } };
}

test('editable example amounts and merchants map only to configured settlement terms and invalid input preserves the order', async t => {
  const f = await fixture(t), initial = await f.session.state();
  assert.equal(initial.order.amountMinor, 2990000);
  assert.equal(initial.order.payeeAccount, 'merchant:keyboard');
  for (const amountMinor of [0, -1, 1.5, 1000000001, Number.MAX_SAFE_INTEGER + 1, '2990000', null, NaN, Infinity]) {
    await assert.rejects(f.session.newOrder({ amountMinor }), { code: 'DBAC_PAYMENT_INVALID_INPUT' });
    assert.deepEqual((await f.session.state()).order, initial.order);
  }
  for (const payeeAccount of ['', 'merchant:unknown', '__proto__', 'toString', paymentInfo.payees['merchant:other'], null, 3]) {
    await assert.rejects(f.session.newOrder({ payeeAccount }), { code: 'DBAC_PAYMENT_INVALID_INPUT' });
    assert.deepEqual((await f.session.state()).order, initial.order);
  }
  const edited = await f.session.newOrder({ amountMinor: 1234567, payeeAccount: 'merchant:other' });
  assert.notEqual(edited.order.orderId, initial.order.orderId);
  assert.equal(edited.order.amountMinor, 1234567);
  assert.deepEqual(edited.order.settlement, { network: paymentInfo.network, asset: paymentInfo.asset, payerAddress: paymentInfo.payerAddress, payTo: paymentInfo.payees['merchant:other'] });
  assert.deepEqual(edited.ledger, initial.ledger);
  assert.equal(edited.manual.stage, 'IDLE');
  assert.equal(edited.paymentPending, false);
  for (const amountMinor of [1, 1000000000]) assert.equal((await f.session.newOrder({ amountMinor })).order.amountMinor, amountMinor);
  assert.equal((await f.session.newOrder()).order.amountMinor, 2990000, 'omitted input retains the old API default');
});

test('unknown automatic wallet response blocks replacing the order or credential until the original order settles', { timeout: 60000 }, async t => {
  const f = await fixture(t);
  await f.session.newOrder({ amountMinor: 1234567, payeeAccount: 'merchant:other' });
  await f.session.issue(); await f.session.propose(); await f.approve(); await f.session.sync();
  const before = await f.session.state();
  assert.deepEqual(before.authorization.document.payment, before.order, 'Owner binds the edited input and mapped destination');
  f.setWalletUncertain(true);
  await assert.rejects(f.session.pay(), { code: 'DBAC_PAYMENT_TRANSPORT' });
  assert.equal((await f.session.state()).paymentPending, true);
  await assert.rejects(f.session.newOrder({ amountMinor: 42 }), { code: 'DBAC_PAYMENT_PENDING' });
  await assert.rejects(f.session.issue(), { code: 'DBAC_PAYMENT_PENDING' });
  assert.deepEqual((await f.session.state()).order, before.order);
  f.setWalletUncertain(false);
  assert.equal((await f.session.pay()).paymentResult.outcome, 'EXECUTED');
  const settled = await f.session.state();
  assert.equal(settled.paymentPending, false);
  const reset = await f.session.newOrder({ amountMinor: 42 });
  assert.deepEqual(reset.ledger, settled.ledger, 'reset preserves balances and receipts');
  assert.equal(reset.lastResult, null); assert.equal(reset.proposal, null); assert.equal(reset.authorization, null);
  assert.equal(reset.manual.stage, 'IDLE'); assert.deepEqual(reset.manual.log, []);
});

test('discard cannot bypass either unconfirmed or received manual wallet signatures; confirmed settlement permits reset', { timeout: 60000 }, async t => {
  const f = await fixture(t);
  await f.session.issue(); await f.verifyPhase('proposal'); await f.act('submit-owner'); await f.approve(); await f.act('sync-owner'); await f.verifyPhase('authorize');
  const original = (await f.session.state()).order;
  f.setWalletUncertain(true);
  await assert.rejects(f.act('wallet-sign'), { code: 'DBAC_PAYMENT_TRANSPORT' });
  assert.equal((await f.session.state()).manual.walletSigningUnconfirmed, true);
  await f.act('discard');
  await assert.rejects(f.session.newOrder({ amountMinor: 42 }), { code: 'DBAC_PAYMENT_PENDING' });
  assert.equal((await f.session.state()).paymentPending, true);
  f.setWalletUncertain(false);
  await f.verifyPhase('authorize'); await f.act('wallet-sign'); await f.act('discard');
  await assert.rejects(f.session.newOrder({ payeeAccount: 'merchant:other' }), { code: 'DBAC_PAYMENT_PENDING' });
  const signed = await f.session.state();
  assert.equal(signed.manual.walletSigned, true); assert.deepEqual(signed.order, original);
  await f.verifyPhase('settle');
  const settled = await f.session.state();
  assert.equal(settled.manual.settled, true); assert.equal(settled.paymentPending, false);
  await f.act('discard');
  const reset = await f.session.newOrder({ amountMinor: 42, payeeAccount: 'merchant:other' });
  assert.notEqual(reset.order.orderId, original.orderId);
  assert.deepEqual(reset.ledger, settled.ledger);
  assert.deepEqual(reset.manual.log, []); assert.equal(reset.manual.walletSigned, false); assert.equal(reset.lastResult, null);
});

test('a verified manual recovery resolves an earlier uncertain automatic request for the same order', { timeout: 60000 }, async t => {
  const f = await fixture(t);
  await f.session.issue(); await f.session.propose(); await f.approve(); await f.session.sync();
  const original = (await f.session.state()).order;
  f.setWalletUncertain(true);
  await assert.rejects(f.session.pay(), { code: 'DBAC_PAYMENT_TRANSPORT' });
  f.setWalletUncertain(false);
  await f.verifyPhase('authorize'); await f.act('wallet-sign'); await f.verifyPhase('settle');
  const recovered = await f.session.state();
  assert.equal(recovered.paymentPending, false);
  assert.equal(recovered.lastResult.paymentResult.receipt.orderId, original.orderId);
  assert.equal(recovered.ledger.executionCount, 1);
  await f.act('discard');
  assert.notEqual((await f.session.newOrder()).order.orderId, original.orderId);
});
