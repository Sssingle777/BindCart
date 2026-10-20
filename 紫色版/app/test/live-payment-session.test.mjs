import test from 'node:test';
import assert from 'node:assert/strict';
import { createLivePaymentSession } from '../lib/storefront/live-payment-session.mjs';

// These tests exercise orchestration, binding and failure handling with a mock
// of the original public API. Real credentials and payments are tested by the
// integration run; this fixture never implements or claims cryptographic checks.
function fixture({ w3c = true, observer, stageDelayMs = 0 } = {}) {
  const calls = [], events = [];
  const order = id => ({ orderId: `order-${id}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 50_000_000,
    currency: 'TEST_USDC', settlement: { network: 'eip155:1337', asset: 'token-address', payTo: 'merchant-address', payerAddress: 'payer-address' } });
  const idle = () => ({ active: false, stage: 'IDLE', attemptId: null, phase: null, challenge: null, verificationResult: null,
    walletSigned: false, walletSigningUnconfirmed: false, settled: false, lastError: null, device: { modes: { 'bbs-bls': { locked: false, signatures: 0 } } } });
  let state = { available: true, mode: 'bbs-bls', order: order(1), w3c: { enabled: w3c }, credential: {},
    credentialStatus: { status: 'active' }, currentCredentialId: 'credential-1', currentDeviceId: 'default',
    proposal: null, authorization: null, lastResult: null, manual: idle() };
  let attempts = 0, orders = 1, approved = false, failAction, blockAction, unblock, started;
  const snapshot = () => structuredClone({ ...state, paymentPending: state.manual.walletSigningUnconfirmed || (!state.manual.settled && state.manual.walletSigned) });
  const result = phase => ({ accepted: true, mode: state.mode, phase,
    wire: { context: structuredClone(state.manual.challenge), headers: { 'X-A2A-DBAC-Proof': 'SECRET_OUTBOUND_PROOF' } },
    verificationTrace: { source: 'agent-b', phase, outcome: 'pass', steps: [{ id: `${phase}-verified`, status: 'pass' }] },
    task: { status: { state: phase === 'authorize' ? 'input-required' : 'completed' } },
    ...(phase === 'settle' ? { paymentResult: { outcome: 'EXECUTED', receipt: { ...structuredClone(state.order), transactionStatus: 'success', transactionHash: '0x-receipt' } } } : {}) });
  const core = {
    state: async () => snapshot(),
    inventory: async options => ({ inventory: true, mode: options?.mode }),
    async issue(options) { calls.push({ method: 'issue', options }); state.credential = {}; return snapshot(); },
    async manage(options) { calls.push({ method: 'manage', options }); return { currentCredentialId: 'credential-1', currentDeviceId: 'default', credentials: [], devices: [] }; },
    async newOrder(options) {
      calls.push({ method: 'newOrder', options });
      assert.equal(state.manual.active, false, 'discard must precede original newOrder');
      state = { ...state, order: order(++orders), proposal: null, authorization: null, lastResult: null, manual: idle() };
      return snapshot();
    },
    async manual(options) {
      const { action, attemptId } = options;
      calls.push({ method: 'manual', ...options });
      if (state.manual.active || attemptId !== undefined) assert.equal(attemptId, state.manual.attemptId, 'must bind original attemptId');
      if (action === blockAction) { started(); await new Promise(resolve => { unblock = resolve; }); }
      if (failAction?.action === action) {
        if (failAction.walletUnknown) state.manual.walletSigningUnconfirmed = true;
        throw failAction.error;
      }
      state.manual.lastError = null;
      if (action.startsWith('begin-')) {
        state.manual = { ...state.manual, active: true, phase: action.slice(6), stage: 'CHALLENGE_READY', attemptId: `attempt-${++attempts}`,
          challenge: { challengeId: `challenge-${attempts}`, paymentOrderId: state.order.orderId, mode: state.mode }, verificationResult: null };
      } else if (action === 'derive-vc') { state.manual.stage = 'VC_DERIVED'; }
      else if (action === 'device-sign') { state.manual.stage = 'DEVICE_SIGNED'; state.manual.device.modes[state.mode].signatures++; }
      else if (action === 'prove') { state.manual.stage = 'PROOF_READY'; state.manual.holderProof = 'SECRET_HOLDER_PROOF'; }
      else if (action === 'verify') {
        state.manual.verificationResult = result(state.manual.phase); state.lastResult = state.manual.verificationResult;
        state.manual.stage = state.manual.phase === 'settle' ? 'SETTLED' : 'VERIFIED';
        if (state.manual.phase === 'settle') state.manual.settled = true;
      } else if (action === 'submit-owner') {
        state.proposal = { id: 'proposal-1', mode: state.mode, status: 'PENDING', payment: structuredClone(state.order) };
        state.manual.stage = 'OWNER_SUBMITTED';
      } else if (action === 'sync-owner') {
        if (approved && state.proposal) {
          state.proposal.status = 'APPROVED';
          state.authorization = { id: 'authorization-1', token: 'SECRET_OWNER_TOKEN', document: { payment: structuredClone(state.order) } };
        }
      } else if (action === 'wallet-sign') {
        state.manual.walletSigned = true; state.manual.stage = 'WALLET_SIGNED'; state.manual.walletPayload = { signature: 'SECRET_WALLET_SIGNATURE' };
      } else if (action === 'discard') { state.manual.active = false; state.manual.stage = 'DISCARDED'; }
      else assert.fail(`Unexpected action ${action}`);
      return snapshot();
    },
  };
  const wrapper = createLivePaymentSession({ paymentSession: core, stageDelayMs, emit(event) { events.push(event); observer?.(event); } });
  return { wrapper, core, events, calls, read: snapshot, approve() { approved = true; }, edit(fn) { fn(state); },
    fail(action, error, walletUnknown = false) { failAction = { action, error, walletUnknown }; },
    block(action) { blockAction = action; return new Promise(resolve => { started = resolve; }); },
    release() { unblock(); },
  };
}
const actions = f => f.calls.filter(call => call.method === 'manual').map(call => call.action);
async function prepared(f) { const proposed = await f.wrapper.propose(); f.approve(); return proposed; }

test('checkout and payment execute the original manual phases and expose only actual completed steps', async () => {
  const f = fixture();
  const proposed = await prepared(f);
  assert.equal(proposed.proposal.status, 'PENDING');
  assert.equal(proposed.verificationTrace.phase, 'proposal');
  assert.deepEqual(actions(f), ['begin-proposal', 'derive-vc', 'device-sign', 'prove', 'verify', 'submit-owner']);
  const paid = await f.wrapper.pay();
  assert.equal(paid.paymentResult.receipt.orderId, proposed.order.orderId);
  assert.deepEqual(paid.verificationTraces.map(trace => trace.phase), ['authorize', 'settle']);
  assert.deepEqual(actions(f).slice(6), ['sync-owner', 'begin-authorize', 'derive-vc', 'device-sign', 'prove', 'verify', 'wallet-sign', 'begin-settle', 'derive-vc', 'device-sign', 'prove', 'verify']);
  for (let i = 0; i < f.events.length; i += 2) {
    assert.equal(f.events[i].status, 'start'); assert.equal(f.events[i + 1].status, 'complete');
    assert.equal(f.events[i].action, f.events[i + 1].action);
  }
  const serialized = JSON.stringify(f.events);
  for (const secret of ['SECRET_HOLDER_PROOF', 'SECRET_OWNER_TOKEN', 'SECRET_WALLET_SIGNATURE', 'SECRET_OUTBOUND_PROOF']) assert.equal(serialized.includes(secret), false);
  assert.ok(f.events.some(event => event.from === 'agent-a' && event.to === 'device' && event.action === 'device-sign'));
  assert.ok(f.events.some(event => event.to === 'wallet' && event.action === 'wallet-sign'));
});

test('read-only calls do not advance a protocol or emit mutation events', async () => {
  const f = fixture();
  assert.equal((await f.wrapper.state()).order.orderId, 'order-1');
  assert.deepEqual(await f.wrapper.inventory({ mode: 'bbs-bls' }), { inventory: true, mode: 'bbs-bls' });
  assert.equal(f.calls.length, 0); assert.equal(f.events.length, 0);
});

test('an explicit Owner approval is required before authorization proofs or wallet signatures', async () => {
  const f = fixture(); await f.wrapper.propose();
  await assert.rejects(() => f.wrapper.pay(), { code: 'OWNER_CONFIRMATION_REQUIRED' });
  assert.equal(actions(f).at(-1), 'sync-owner');
  assert.equal(actions(f).includes('begin-authorize'), false);
  assert.equal(actions(f).includes('wallet-sign'), false);
  f.approve();
  await f.wrapper.pay();
});

test('device failure preserves original error and never claims B performed internal verification', async () => {
  const f = fixture(); f.fail('device-sign', Object.assign(new Error('Device is locked'), { code: 'DBAC_DEVICE_LOCKED', status: 403 }));
  const error = await f.wrapper.propose().then(() => assert.fail('must reject'), error => error);
  assert.equal(error.code, 'DBAC_DEVICE_LOCKED'); assert.equal(error.verificationTrace.source, 'agent-a');
  assert.equal(error.verificationTrace.steps[0].status, 'fail');
  assert.ok(error.verificationTrace.steps.slice(1).every(step => step.status === 'skipped'));
  assert.equal(actions(f).includes('verify'), false); assert.equal(actions(f).includes('submit-owner'), false);
  assert.equal(f.events.at(-1).status, 'fail'); assert.equal(f.events.at(-1).action, 'device-sign');
});

test('an actual verifier rejection trace is preserved without borrowing earlier passes', async () => {
  const trace = { source: 'agent-b', outcome: 'fail', steps: [{ id: 'credential_status', status: 'fail', code: 'W3C_CREDENTIAL_REVOKED' }] };
  const f = fixture(); f.fail('verify', Object.assign(new Error('Credential revoked'), { code: 'W3C_CREDENTIAL_REVOKED', verificationTrace: trace }));
  const error = await f.wrapper.propose().then(() => assert.fail('must reject'), error => error);
  assert.deepEqual(error.verificationTrace, trace); assert.equal(actions(f).includes('submit-owner'), false);
});

test('wallet uncertainty blocks a second signature and a new order without discarding the original attempt', async () => {
  const f = fixture(); await prepared(f);
  f.fail('wallet-sign', Object.assign(new Error('Wallet response lost'), { code: 'WALLET_TRANSPORT' }), true);
  await assert.rejects(() => f.wrapper.pay(), { code: 'WALLET_TRANSPORT' });
  const count = f.calls.length;
  await assert.rejects(() => f.wrapper.pay(), { code: 'DBAC_PAYMENT_PENDING' });
  await assert.rejects(() => f.wrapper.newOrder(), { code: 'DBAC_PAYMENT_PENDING' });
  await assert.rejects(() => f.wrapper.issue(), { code: 'DBAC_PAYMENT_PENDING' });
  assert.equal(f.calls.length, count); assert.equal(actions(f).includes('discard'), false);
});

test('settlement transport failure retains the signed wallet state and blocks re-signing', async () => {
  const f = fixture(); await prepared(f);
  f.fail('begin-settle', Object.assign(new Error('No challenge response'), { code: 'DBAC_PAYMENT_TRANSPORT' }));
  await assert.rejects(() => f.wrapper.pay(), { code: 'DBAC_PAYMENT_TRANSPORT' });
  assert.equal(f.read().manual.walletSigned, true);
  await assert.rejects(() => f.wrapper.newOrder(), { code: 'DBAC_PAYMENT_PENDING' });
  await assert.rejects(() => f.wrapper.pay(), { code: 'DBAC_PAYMENT_PENDING' });
  assert.equal(actions(f).filter(action => action === 'wallet-sign').length, 1);
});

test('safe completed orders return the same receipt, then discard the completed attempt before a new order', async () => {
  const f = fixture(); await prepared(f);
  const paid = await f.wrapper.pay(), callCount = f.calls.length;
  const { verificationTraces, paymentFlow, ...originalResult } = paid;
  assert.deepEqual(await f.wrapper.pay(), originalResult);
  assert.equal(f.calls.length, callCount);
  const next = await f.wrapper.newOrder({ amountMinor: 30_000_000 });
  assert.equal(next.order.orderId, 'order-2');
  assert.equal(f.calls.at(-2).action, 'discard'); assert.equal(f.calls.at(-1).method, 'newOrder');
});

test('a mismatched current attempt or stale verification result cannot create an Owner proposal', async () => {
  const f = fixture();
  const original = f.core.manual;
  f.core.manual = async options => {
    const state = await original(options);
    if (options.action === 'verify') {
      state.manual.verificationResult.wire.context.paymentOrderId = 'old-order';
      state.lastResult.wire.context.paymentOrderId = 'old-order';
    }
    return state;
  };
  await assert.rejects(() => f.wrapper.propose(), { code: 'LIVE_RESULT_MISMATCH' });
  assert.equal(actions(f).includes('submit-owner'), false);
  const g = fixture();
  g.edit(state => { state.manual = { ...state.manual, active: true, attemptId: 'stale', challenge: { mode: state.mode, paymentOrderId: 'another-order' } }; });
  await assert.rejects(() => g.wrapper.propose(), { code: 'LIVE_ATTEMPT_MISMATCH' });
  assert.equal(g.calls.length, 0);
});

test('a contradictory settled marker cannot permit a new order', async () => {
  const f = fixture();
  f.edit(state => { state.manual = { ...state.manual, phase: 'settle', settled: true, walletSigned: true, verificationResult: null }; });
  await assert.rejects(() => f.wrapper.newOrder(), { code: 'LIVE_RESULT_MISMATCH' });
  assert.equal(f.calls.length, 0);
});

test('a second mutation cannot interleave an in-flight original action', async () => {
  const f = fixture(), started = f.block('device-sign');
  const proposing = f.wrapper.propose(); await started;
  await assert.rejects(() => f.wrapper.newOrder(), { code: 'DBAC_OPERATION_BUSY' });
  f.release(); await proposing;
  assert.equal(f.calls.some(call => call.method === 'newOrder'), false);
});

test('display observer failures cannot change the result of an actual completed payment', async () => {
  const f = fixture({ observer() { throw new Error('Display disconnected'); } });
  await prepared(f);
  assert.equal((await f.wrapper.pay()).paymentResult.receipt.transactionStatus, 'success');
});

test('non-W3C original sessions retain their original sequence without a fabricated derivation', async () => {
  const f = fixture({ w3c: false }); await f.wrapper.propose();
  assert.deepEqual(actions(f), ['begin-proposal', 'device-sign', 'prove', 'verify', 'submit-owner']);
});

test('explicit Owner synchronization returns original current state without wallet or verification actions', async () => {
  const f = fixture(); await prepared(f);
  const before = f.calls.length, state = await f.wrapper.syncOwner();
  assert.equal(state.proposal.status, 'APPROVED');
  assert.equal(state.authorization.id, 'authorization-1');
  assert.equal(f.calls.length, before + 1); assert.equal(actions(f).at(-1), 'sync-owner');
  assert.equal(f.events.at(-1).from, 'owner'); assert.equal(f.events.at(-1).to, 'agent-a');
});

test('retained verification evidence belongs only to completed verify events with the actual order, phase and challenge', async () => {
  const f = fixture(); await prepared(f); await f.wrapper.pay();
  const retained = f.events.filter(event => event.data.verificationTrace);
  assert.deepEqual(retained.map(event => event.phase), ['proposal', 'authorize', 'settle']);
  for (const event of retained) {
    assert.equal(event.action, 'verify'); assert.equal(event.status, 'complete');
    assert.equal(event.orderId, 'order-1'); assert.equal(event.data.verificationTrace.phase, event.phase);
    assert.equal(event.data.verificationTrace.steps[0].id, `${event.phase}-verified`);
    assert.ok(event.attemptId); assert.ok(event.data.challengeId);
  }
  assert.ok(f.events.filter(event => event.status === 'start').every(event => !event.data.verificationTrace));
  assert.ok(f.events.filter(event => event.action !== 'verify').every(event => !event.data.verificationTrace));
  for (const mismatch of ['order', 'phase', 'challenge']) {
    const g = fixture(), original = g.core.manual;
    g.core.manual = async options => {
      const state = await original(options);
      if (options.action === 'verify') for (const result of [state.manual.verificationResult, state.lastResult]) {
        if (mismatch === 'order') result.wire.context.paymentOrderId = 'stale-order';
        if (mismatch === 'phase') result.phase = 'authorize';
        if (mismatch === 'challenge') result.wire.context.challengeId = 'stale-challenge';
      }
      return state;
    };
    await assert.rejects(() => g.wrapper.propose(), { code: 'LIVE_RESULT_MISMATCH' });
    assert.ok(g.events.every(event => !event.data.verificationTrace), `must not retain ${mismatch}-mismatched trace`);
  }
});

test('presentation holds occur after real checkout results, retain busy exclusion, and keep reads available', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture({ stageDelayMs: 1600 });
  const flush = () => new Promise(resolve => setImmediate(resolve));
  let returned = false;
  const proposing = f.wrapper.propose().then(result => { returned = true; return result; });
  await flush();
  assert.deepEqual(actions(f), ['begin-proposal']);
  assert.equal(f.events.at(-1).status, 'complete', 'only an actual completed core action starts a hold');
  assert.equal((await f.wrapper.state()).manual.stage, 'CHALLENGE_READY');
  await assert.rejects(() => f.wrapper.newOrder(), { code: 'DBAC_OPERATION_BUSY' });
  await assert.rejects(() => f.wrapper.propose(), { code: 'DBAC_OPERATION_BUSY' });
  t.mock.timers.tick(1599); await flush();
  assert.deepEqual(actions(f), ['begin-proposal']);
  assert.equal(returned, false);
  t.mock.timers.tick(1); await flush();
  assert.deepEqual(actions(f), ['begin-proposal', 'derive-vc', 'device-sign'], 'internal derivation has no separate artificial stop');
  for (const next of ['prove', 'verify', 'submit-owner']) {
    assert.equal(f.events.at(-1).status, 'complete');
    t.mock.timers.tick(1600); await flush();
    assert.equal(actions(f).at(-1), next);
    await assert.rejects(() => f.wrapper.issue(), { code: 'DBAC_OPERATION_BUSY' });
  }
  assert.equal((await f.wrapper.state()).proposal.status, 'PENDING');
  assert.equal(returned, false, 'the final real Owner submission remains visible while the request is busy');
  t.mock.timers.tick(1600); await flush();
  assert.equal((await proposing).proposal.status, 'PENDING');
  assert.equal(returned, true);
  assert.deepEqual(actions(f), ['begin-proposal', 'derive-vc', 'device-sign', 'prove', 'verify', 'submit-owner']);
  assert.ok(f.events.every(event => event.phase === 'proposal'));
});

test('paced authorization and settlement use separate original challenges and never release a second payment during holds', async t => {
  const f = fixture(); await prepared(f);
  const before = f.calls.length, events = [];
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const wrapper = createLivePaymentSession({ paymentSession: f.core, stageDelayMs: 1600, emit: event => events.push(event) });
  const flush = () => new Promise(resolve => setImmediate(resolve));
  let returned = false;
  const paying = wrapper.pay().then(result => { returned = true; return result; });
  const holds = ['sync-owner', 'begin-authorize', 'device-sign', 'prove', 'verify', 'wallet-sign', 'begin-settle', 'device-sign', 'prove', 'verify'];
  for (const action of holds) {
    await flush();
    assert.equal(f.calls.at(-1).action, action);
    assert.equal(events.at(-1).status, 'complete');
    assert.equal(returned, false);
    await assert.rejects(() => wrapper.pay(), { code: 'DBAC_OPERATION_BUSY' });
    await assert.rejects(() => wrapper.manage({ action: 'revoke' }), { code: 'DBAC_OPERATION_BUSY' });
    t.mock.timers.tick(1600);
  }
  await flush();
  const paid = await paying;
  assert.equal(paid.paymentResult.receipt.transactionStatus, 'success');
  assert.equal(f.calls.slice(before).filter(call => call.action === 'wallet-sign').length, 1);
  assert.deepEqual(events.filter(event => event.data.verificationTrace).map(event => event.phase), ['authorize', 'settle']);
  assert.equal(new Set(events.filter(event => event.data.verificationTrace).map(event => event.data.challengeId)).size, 2);
  const callCount = f.calls.length;
  assert.equal((await wrapper.pay()).paymentResult.receipt.transactionHash, paid.paymentResult.receipt.transactionHash);
  assert.equal(f.calls.length, callCount, 'a completed duplicate returns the original receipt without another paced protocol');
});

test('presentation pace rejects configurations that could unexpectedly consume challenge lifetime', () => {
  for (const stageDelayMs of [-1, 2001, Infinity, NaN, '1600', 1.5]) {
    assert.throws(() => createLivePaymentSession({ paymentSession: {}, stageDelayMs }), { name: 'TypeError' });
  }
  assert.doesNotThrow(() => createLivePaymentSession({ paymentSession: {}, stageDelayMs: 0 }));
  assert.doesNotThrow(() => createLivePaymentSession({ paymentSession: {}, stageDelayMs: 2000 }));
});

test('console single-step requests return immediately after exactly one original action without preparing the next step', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const f = fixture({ stageDelayMs: 1600 });
  const begun = await f.wrapper.manual({ action: 'begin-proposal', attemptId: null });
  assert.equal(begun.manual.stage, 'CHALLENGE_READY');
  assert.deepEqual(actions(f), ['begin-proposal']);
  assert.equal(begun.manual.device.modes['bbs-bls'].signatures, 0);
  for (let i = 0; i < 3; i++) await f.wrapper.state();
  assert.deepEqual(actions(f), ['begin-proposal']);
  const derived = await f.wrapper.manual({ action: 'derive-vc', attemptId: begun.manual.attemptId });
  assert.equal(derived.manual.stage, 'VC_DERIVED');
  assert.deepEqual(actions(f), ['begin-proposal', 'derive-vc']);
  assert.equal(derived.manual.device.modes['bbs-bls'].signatures, 0);
  assert.deepEqual(f.events.map(event => `${event.action}:${event.status}`), ['begin-proposal:start', 'begin-proposal:complete', 'derive-vc:start', 'derive-vc:complete']);
});

test('console single-step rejects a stale attempt before calling the core and excludes concurrent mutation', async () => {
  const f = fixture();
  const begun = await f.wrapper.manual({ action: 'begin-proposal', attemptId: null });
  await assert.rejects(f.wrapper.manual({ action: 'derive-vc', attemptId: null }), { code: 'DBAC_MANUAL_ATTEMPT_MISMATCH' });
  assert.deepEqual(actions(f), ['begin-proposal']);
  const started = f.block('derive-vc');
  const deriving = f.wrapper.manual({ action: 'derive-vc', attemptId: begun.manual.attemptId });
  await started;
  await assert.rejects(f.wrapper.manual({ action: 'device-sign', attemptId: begun.manual.attemptId }), { code: 'DBAC_OPERATION_BUSY' });
  assert.deepEqual(actions(f), ['begin-proposal', 'derive-vc']);
  f.release();
  assert.equal((await deriving).manual.stage, 'VC_DERIVED');
});
