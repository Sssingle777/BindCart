import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { randomUUID } from 'node:crypto';
import { createStorefrontController } from '../lib/storefront/controller.mjs';

// These tests cover adapter/journal behavior. Cryptographic and chain behavior
// is verified separately through the actual original controller in the UI run.
async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'storefront-adapter-'));
  t.after(async () => { if (resolve(directory).startsWith(`${resolve(tmpdir())}${sep}storefront-adapter-`)) await rm(directory, { recursive: true, force: true }); });
  const idle = () => ({ active: false, phase: null, stage: 'IDLE', attemptId: null, availableActions: [] });
  let core = { mode: 'bbs-bls', order: null, credential: null, proposal: null, authorization: null, paymentPending: false, w3c: { enabled: true }, manual: idle(), credentialStatus: { status: 'absent' }, ledger: { accounts: [] } };
  let mode = 'success', payments = 0;
  const session = {
    state: async () => structuredClone(core),
    async newOrder({ amountMinor = 2990000 } = {}) { core = { ...core, order: { orderId: `urn:uuid:${randomUUID()}`, amountMinor, currency: 'TEST_USDC' }, proposal: null, authorization: null, paymentPending: false, manual: { ...idle(), availableActions: core.credential ? ['begin-proposal'] : [] } }; return this.state(); },
    async issue() { core.credential = {}; core.manual.availableActions = ['begin-proposal']; return this.state(); },
    async propose() { assert.fail('manual storefront must not call automatic propose'); },
    async pay() { assert.fail('manual storefront must not call automatic pay'); },
    async manual({ action }) {
      const m = core.manual;
      if (action.startsWith('begin-')) Object.assign(m, { active: true, phase: action.slice(6), stage: 'CHALLENGE_READY', attemptId: randomUUID(), availableActions: ['derive-vc', action, 'discard'] });
      else if (action === 'derive-vc') Object.assign(m, { stage: 'VC_DERIVED', availableActions: ['device-sign', 'discard'] });
      else if (action === 'device-sign') Object.assign(m, { stage: 'DEVICE_SIGNED', availableActions: ['prove', 'discard'] });
      else if (action === 'prove') Object.assign(m, { stage: 'PROOF_READY', availableActions: ['verify', 'discard'] });
      else if (action === 'submit-owner') {
        core.proposal = { status: 'PENDING', id: randomUUID(), payment: core.order, expiresAt: new Date(Date.now() + 300000).toISOString() };
        Object.assign(m, { stage: 'OWNER_SUBMITTED', availableActions: ['sync-owner', 'discard'] });
      } else if (action === 'sync-owner') {
        core.authorization = core.proposal.status === 'APPROVED' ? { id: randomUUID(), document: { exp: Math.floor(Date.now() / 1000) + 600 } } : null;
        if (core.proposal.status === 'EXPIRED') { m.availableActions = ['begin-proposal', 'sync-owner', 'discard']; throw Object.assign(new Error('Owner proposal expired'), { code: 'OWNER_PROPOSAL_EXPIRED' }); }
        m.availableActions = core.authorization ? ['begin-authorize', 'sync-owner', 'discard'] : ['REJECTED', 'EXPIRED'].includes(core.proposal.status) ? ['begin-proposal', 'sync-owner', 'discard'] : ['sync-owner', 'discard'];
      } else if (action === 'wallet-sign') Object.assign(m, { stage: 'WALLET_SIGNED', walletSigned: true, availableActions: ['begin-settle', 'sync-owner', 'discard'] });
      else if (action === 'verify') {
        m.verificationResult = { verificationTrace: { outcome: 'pass', steps: [] } };
        if (m.phase === 'settle') {
          payments++;
          if (mode === 'unknown') { core.paymentPending = true; throw Object.assign(new Error('Response lost'), { code: 'TRANSPORT_UNCERTAIN' }); }
          m.verificationResult.paymentResult = { outcome: 'EXECUTED', receipt: { ...core.order, transactionStatus: 'success', transactionHash: `0x${'ab'.repeat(32)}` } };
          Object.assign(m, { stage: 'SETTLED', settled: true, availableActions: ['discard'] });
        } else Object.assign(m, { stage: 'VERIFIED', availableActions: [m.phase === 'proposal' ? 'submit-owner' : 'wallet-sign', 'sync-owner', 'discard'] });
      } else if (action === 'discard') Object.assign(m, { active: false, stage: 'DISCARDED', availableActions: ['begin-proposal'] });
      return this.state();
    },
    async manage() {},
  };
  const controller = await createStorefrontController({ paymentSession: session, directory });
  return { controller, session, directory, approve() { core.proposal.status = 'APPROVED'; }, reject() { core.proposal.status = 'REJECTED'; }, expireAuthorization() { core.authorization.document.exp = 0; core.proposal.status = 'EXPIRED'; }, uncertain() { mode = 'unknown'; }, paymentCount: () => payments };
}
async function checkout(f) {
  let cart = await f.controller.changeCart({ productId: '02', quantity: 1, revision: 0 });
  cart = await f.controller.changeCart({ productId: '03', quantity: 1, revision: cart.revision });
  cart = await f.controller.checkout({ revision: cart.revision });
  assert.equal(cart.phase, 'verifying'); assert.equal(cart.backend.proposal, null);
  for (const action of ['issue', 'begin-proposal', 'derive-vc', 'device-sign', 'prove', 'verify', 'submit-owner']) cart = await act(f, action);
  return cart;
}
async function act(f, action) {
  const state = await f.controller.state(), control = state.manualControl;
  return f.controller.manual({ action, orderId: state.order.orderId, revision: state.revision, attemptId: control.attemptId, controlToken: control.token });
}
async function settle(f, state) {
  state = await f.controller.pay({ orderId: state.order.orderId, revision: state.revision });
  assert.equal(state.phase, 'paying'); assert.equal(f.paymentCount(), 0);
  for (const action of ['sync-owner', 'begin-authorize', 'derive-vc', 'device-sign', 'prove', 'verify', 'wallet-sign', 'begin-settle', 'derive-vc', 'device-sign', 'prove', 'verify']) state = await act(f, action);
  assert.equal(state.phase, 'confirming');
  return act(f, 'confirm-merchant');
}
test('manual storefront freezes server-priced goods and requires explicit qualification and Owner approval', async t => {
  const f = await fixture(t); const state = await checkout(f);
  assert.equal(state.order.amountMinor, 34_980_000);
  await assert.rejects(() => f.controller.changeCart({ productId: '02', quantity: 1, revision: state.revision }), { code: 'STORE_CART_LOCKED' });
  await assert.rejects(() => f.controller.pay({ orderId: state.order.orderId, revision: state.revision }), { code: 'OWNER_CONFIRMATION_REQUIRED' });
  assert.equal(f.paymentCount(), 0);
});

test('a rejected Owner decision requires explicit synchronization then a fresh manual qualification of the same goods order', async t => {
  const f = await fixture(t); let state = await checkout(f); const orderId = state.order.orderId;
  f.reject();
  state = await f.controller.state(); assert.equal(state.manualControl.nextAction, 'sync-owner');
  state = await act(f, 'sync-owner');
  assert.equal(state.phase, 'verifying'); assert.equal(state.manualControl.nextAction, 'begin-proposal');
  assert.equal(state.order.orderId, orderId); assert.equal(f.paymentCount(), 0);
  state = await act(f, 'begin-proposal');
  assert.equal(state.backend.manual.stage, 'CHALLENGE_READY'); assert.equal(state.order.orderId, orderId);
});

test('expired Owner authorization synchronizes explicitly before any new proof, preserving signed wallet orders', async t => {
  for (const signed of [false, true]) await t.test(signed ? 'wallet already signed' : 'wallet not signed', async t => {
    const f = await fixture(t); let state = await checkout(f); const orderId = state.order.orderId; f.approve();
    state = await f.controller.pay({ orderId, revision: state.revision });
    for (const action of ['sync-owner', 'begin-authorize', 'derive-vc', 'device-sign', 'prove', 'verify']) state = await act(f, action);
    if (signed) state = await act(f, 'wallet-sign');
    f.expireAuthorization(); state = await f.controller.state();
    assert.equal(state.manualControl.nextAction, 'sync-owner');
    await assert.rejects(act(f, 'sync-owner'), { code: 'OWNER_PROPOSAL_EXPIRED' });
    state = await f.controller.state(); assert.equal(state.order.orderId, orderId); assert.equal(f.paymentCount(), 0);
    assert.equal(state.phase, signed ? 'unknown' : 'verifying');
    if (signed) await assert.rejects(f.controller.reset({ revision: state.revision }), { code: 'STORE_PAYMENT_UNRESOLVED' });
    else assert.equal(state.manualControl.nextAction, 'begin-proposal');
  });
});
test('uncertain payment is checkpointed and stays blocked after a process restart', async t => {
  const f = await fixture(t); const state = await checkout(f); f.approve(); f.uncertain();
  await assert.rejects(() => settle(f, state), { code: 'TRANSPORT_UNCERTAIN' });
  const persisted = JSON.parse(await readFile(join(f.directory, 'current.json'), 'utf8'));
  assert.equal(persisted.phase, 'unknown');
  const resumed = await createStorefrontController({ paymentSession: f.session, directory: f.directory });
  assert.equal((await resumed.state()).order.orderId, state.order.orderId);
  await assert.rejects(() => resumed.reset({ revision: state.revision }), { code: 'STORE_PAYMENT_UNRESOLVED' });
  await assert.rejects(() => resumed.pay({ orderId: state.order.orderId, revision: state.revision }), { code: 'STORE_PAYMENT_UNRESOLVED' });
  assert.equal(f.paymentCount(), 1);
});
test('completed order returns its persisted receipt after restart without a new core payment', async t => {
  const f = await fixture(t); const state = await checkout(f); f.approve();
  const payload = { orderId: state.order.orderId, revision: state.revision };
  const paid = await settle(f, state);
  const resumed = await createStorefrontController({ paymentSession: f.session, directory: f.directory });
  assert.deepEqual((await resumed.pay(payload)).receipt, paid.receipt); assert.equal(f.paymentCount(), 1);
});
test('invalid saved cart cannot enter the live order controller', async t => {
  const f = await fixture(t);
  await writeFile(join(f.directory, 'current.json'), JSON.stringify({ version: 1, phase: 'cart', revision: 0, cart: { unknown: -1 } }));
  const resumed = await createStorefrontController({ paymentSession: f.session, directory: f.directory });
  assert.equal((await resumed.state()).phase, 'unknown');
  await assert.rejects(() => resumed.checkout({ revision: 0 }), { code: 'STORE_PAYMENT_UNRESOLVED' });
});

test('active catalog accepts all nine official SKUs once and refuses legacy IDs or extra quantity without mutation', async t => {
  const f = await fixture(t), catalog = f.controller.catalog();
  assert.deepEqual(catalog.map(product => product.id), ['01', '02', '03', '04', '05', '06', '07', '08', '09']);
  for (const body of [{ productId: 'headphones', quantity: 1 }, { productId: '02', quantity: 2 }, { productId: '02', quantity: 1, amountMinor: 1 }]) {
    await assert.rejects(() => f.controller.changeCart({ ...body, revision: 0 }), { code: Object.hasOwn(body, 'amountMinor') ? 'STORE_INPUT_INVALID' : 'STORE_PRODUCT_INVALID' });
    assert.equal((await f.controller.state()).revision, 0);
  }
  let state = await f.controller.state();
  for (const product of catalog) state = await f.controller.changeCart({ productId: product.id, quantity: 1, revision: state.revision });
  assert.equal(state.cart.length, 9);
  assert.equal(state.totalMinor, 676_920_000);
});

test('legacy completed orders retain original product prices and receipts while legacy carts cannot create new payments', async t => {
  const f = await fixture(t), orderId = `urn:uuid:${randomUUID()}`;
  const receipt = { orderId, amountMinor: 100_000_000, currency: 'TEST_USDC', transactionStatus: 'success', transactionHash: `0x${'cd'.repeat(32)}` };
  const record = { version: 1, phase: 'paid', revision: 2, cart: { headphones: 1, sunglasses: 1 }, boundOrder: { orderId, amountMinor: 100_000_000, currency: 'TEST_USDC' }, receipt, verification: null, events: [], message: 'Saved legacy order' };
  await writeFile(join(f.directory, 'current.json'), JSON.stringify(record));
  let resumed = await createStorefrontController({ paymentSession: f.session, directory: f.directory });
  const restored = await resumed.state();
  assert.equal(restored.phase, 'paid'); assert.equal(restored.totalMinor, 100_000_000);
  assert.deepEqual(restored.receipt, receipt); assert.equal(restored.cart[0].unitAmountMinor, 50_000_000);
  assert.equal(f.paymentCount(), 0);
  await writeFile(join(f.directory, 'current.json'), JSON.stringify({ ...record, phase: 'cart', boundOrder: null, receipt: null }));
  resumed = await createStorefrontController({ paymentSession: f.session, directory: f.directory });
  await assert.rejects(() => resumed.checkout({ revision: 2 }), { code: 'STORE_PRODUCT_INVALID' });
  assert.equal(f.paymentCount(), 0);
});
