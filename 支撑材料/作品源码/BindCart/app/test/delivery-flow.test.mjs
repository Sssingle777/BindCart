import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { deliveryFixture } from './fixtures/delivery.mjs';

test('current delivery entry completes real shopping, explicit Owner approval, settlement and merchant confirmation once', { timeout: 180000 }, async t => {
  const { api, live, runtime } = await deliveryFixture(t);
  for (const path of ['/intro/', '/demo/', '/store/', '/mechanism/']) {
    const response = await fetch(runtime.baseUrl + path);
    assert.equal(response.status, 200, path);
    assert.match(response.headers.get('content-type'), /text\/html/);
  }
  let state = await live();
  assert.equal(state.core.ledger.executionCount, 0);
  const initialAccounts = state.core.ledger.accounts;
  const catalog = await api('/api/store/catalog');
  await api('/api/store/cart', { productId: catalog.products[0].id, quantity: 1, revision: state.store.revision });
  await api('/api/store/checkout', { revision: (await live()).store.revision });
  async function step(action) {
    const current = await live();
    return api('/api/store/manual', { action, orderId: current.store.order.orderId,
      revision: current.store.revision, attemptId: current.core.manual.attemptId, controlToken: current.store.manualControl.token });
  }
  for (const action of ['issue','begin-proposal','derive-vc','device-sign','prove','verify','submit-owner']) await step(action);
  state = await live();
  assert.equal(state.core.ledger.executionCount, 0, 'qualification must not pay');
  const denied = await api('/api/store/pay', { orderId: state.store.order.orderId, revision: state.store.revision }, { expected: 403 });
  assert.equal(denied.error.code, 'OWNER_CONFIRMATION_REQUIRED');
  const proposal = state.core.proposal;
  await api(`/owner/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }, { owner: true });
  state = await live();
  assert.equal(state.core.ledger.executionCount, 0, 'Owner approval must not pay');
  await api('/api/store/pay', { orderId: state.store.order.orderId, revision: state.store.revision });
  for (let i = 0; i < 30; i++) {
    state = await live(); if (state.store.phase === 'paid') break;
    assert(state.store.manualControl.nextAction, 'explicit next operation exists');
    await step(state.store.manualControl.nextAction);
  }
  state = await live();
  assert.equal(state.store.phase, 'paid');
  assert.equal(state.core.ledger.executionCount, 1);
  assert.equal(state.store.receipt.transactionStatus, 'success');
  const receipt = state.store.receipt;
  const paidAccounts = state.core.ledger.accounts;
  for (const [id, direction] of [[receipt.payerAccount, -1], [receipt.payeeAccount, 1]]) {
    assert.equal(paidAccounts.find(a => a.id === id).balanceMinor - initialAccounts.find(a => a.id === id).balanceMinor, direction * receipt.amountMinor);
  }
  await api('/api/store/pay', { orderId: state.store.order.orderId, revision: state.store.revision });
  state = await live();
  await api('/api/store/query', { orderId: state.store.order.orderId, revision: state.store.revision });
  state = await live();
  assert.equal(state.store.receipt.transactionHash, receipt.transactionHash);
  assert.equal(state.core.ledger.executionCount, 1);
  assert.deepEqual(state.core.ledger.accounts, paidAccounts);
  await api('/api/store/new', { revision: state.store.revision });
  for (const scenario of ['copied-vc', 'revoked']) {
    await api('/api/store/experiment', { scenario });
    state = await live();
    assert.equal(state.store.experiment.expectationMet, true, scenario);
    assert.equal(state.store.experiment.requestRejected, true, scenario);
    assert.equal(state.core.ledger.executionCount, 1, 'security experiment must not pay');
    assert.deepEqual(state.core.ledger.accounts, paidAccounts);
  }
});

test('both modes execute real three-stage payments and preserve one debit under replay and fresh-proof retries', { timeout: 180000 }, async () => {
  let diagnostics = '';
  const code = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('../scripts/payment-consistency.mjs', import.meta.url))], {
      timeout: 150000, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, UWS_USE_FALLBACK: '1' },
    });
    child.stdout.on('data', () => {});
    child.stderr.on('data', bytes => { diagnostics = (diagnostics + String(bytes).replace(/[A-Za-z0-9_-]{43,}/g, '[redacted]')).slice(-3000); });
    child.once('error', reject); child.once('exit', resolve);
  });
  assert.equal(code, 0, `two-mode payment and ledger assertions must pass: ${diagnostics}`);
});
