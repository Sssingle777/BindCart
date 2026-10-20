import test from 'node:test';
import assert from 'node:assert/strict';
import { guideProgress, guidePaymentReceipt } from '../public/guide-progress.js';
import { planPayment } from '../public/guide-model.js';

const now = Date.parse('2026-10-10T12:00:00.000Z');
const order = {
  orderId: 'current-order', amountMinor: 2990000, currency: 'TEST_USDC', payerAccount: 'a', payeeAccount: 'b',
  settlement: { network: 'eip155:31337', asset: 'test-token', payerAddress: '0xa', payTo: '0xb' },
};
function fixture(manual = {}, fields = {}) {
  return {
    available: true, mode: 'bbs-bls', order: structuredClone(order), credential: { suite: 'public-suite' },
    credentialStatus: { status: 'valid', available: true }, owner: { available: true },
    w3c: { enabled: true, originalCredential: { validFrom: '2026-10-10T00:00:00Z', validUntil: '2026-10-11T00:00:00Z' } },
    manual: { active: true, phase: 'proposal', stage: 'CHALLENGE_READY', expiresAtUnix: now / 1000 + 60,
      availableActions: ['derive-vc', 'discard', 'begin-proposal'], ...manual }, ...fields,
  };
}
const approved = () => ({ proposal: { status: 'APPROVED', payment: structuredClone(order) }, authorization: { id: 'auth' } });
function ready() {
  return fixture({ phase: 'settle', stage: 'PROOF_READY', walletSigned: true, presentation: {}, verifiableCredential: {}, deviceResponse: {}, holderProof: {}, availableActions: ['verify', 'discard', 'begin-settle'] }, approved());
}
function completed(outcome = 'EXECUTED') {
  const state = ready();
  state.manual.settled = true;
  state.manual.stage = 'SETTLED';
  state.manual.availableActions = ['discard'];
  state.lastResult = { mode: state.mode, phase: 'settle', accepted: true, task: { status: { state: 'completed' } }, paymentResult: { outcome, receipt: structuredClone(state.order) } };
  return state;
}
const project = (state, options = {}) => guideProgress(state, planPayment(state, { now }), { now, ...options });
const statuses = value => value.steps.map(step => step.status);
const ids = ['w3c_bbs', 'credential_status', 'holder_signature', 'vc_device_binding', 'extension', 'envelope',
  'challenge', 'replay', 'request_binding', 'policy_context', 'scope', 'schema', 'proof_structure', 'disclosure',
  'proof_encoding', 'knowledge', 'credential_pairing', 'device_pairing', 'owner_authorization', 'task_binding',
  'consume', 'settlement_gate', 'execution'];
function trace(phase = 'proposal', failId) {
  const unused = phase === 'proposal' ? ['owner_authorization', 'task_binding', 'settlement_gate'] : phase === 'authorize' ? ['task_binding', 'settlement_gate'] : [];
  return { profile: 'dbac-payment', source: 'agent-b', outcome: failId ? 'fail' : 'pass', steps: ids.map(id => ({
    id, title: id, status: id === failId ? 'fail' : unused.includes(id) ? 'skipped' : 'pass',
    ...(id === 'scope' ? { evidence: [{ label: 'method / scope / phase', observed: ['message/send', 'payments:pay', phase] }] } : {}),
  })) };
}

test('the overview always has four ordered steps and cannot infer issuance from unavailable state', () => {
  for (const state of [undefined, { available: false }, { ...completed(), available: false }, fixture({ active: false, stage: 'IDLE' }, { credential: null })]) {
    const value = project(state);
    assert.deepEqual(value.steps.map(step => [step.id, step.title]), [['credential', '签发凭证'], ['transaction', '资格认证与用户授权'], ['proof', '付款复核与结算证明'], ['result', '结算验证与回执']]);
    assert.deepEqual(statuses(value), ['current', 'pending', 'pending', 'pending']);
    assert.equal(value.total, 4); assert.equal(value.currentIndex, 0); assert.equal(value.currentStep, 1);
  }
});

test('issued credentials are a historical fact, not a claim of current validity or completed qualification', () => {
  const value = project(fixture({}, { credentialStatus: { status: 'revoked' } }));
  assert.deepEqual(statuses(value), ['pass', 'current', 'pending', 'pending']);
  assert.match(value.steps[0].detail, /已签发不等于本次使用有效/);
  assert.match(value.detail, /撤销/);
});

test('proposal proof and successful qualification never stand in for explicit Owner approval', () => {
  for (const stage of ['CHALLENGE_READY', 'VC_DERIVED', 'DEVICE_SIGNED', 'PROOF_READY', 'VERIFIED', 'OWNER_SUBMITTED']) {
    const state = fixture({ stage, verificationResult: { phase: 'proposal', verificationTrace: trace() } });
    assert.deepEqual(statuses(project(state)), ['pass', 'current', 'pending', 'pending'], stage);
  }
  for (const fields of [
    { proposal: { status: 'PENDING', payment: order } },
    { proposal: { status: 'APPROVED', payment: order } },
    { authorization: {} },
    { proposal: { status: 'APPROVED' }, authorization: {} },
    { ...approved(), proposal: { status: 'APPROVED', payment: { ...order, orderId: 'another-order' } } },
  ]) assert.notEqual(project(fixture({}, fields)).steps[1].status, 'pass');
  assert.deepEqual(statuses(project(fixture({}, approved()))), ['pass', 'pass', 'current', 'pending']);
});

test('Owner authorization and every authorize substage still need a fresh settle proof', () => {
  for (const stage of ['CHALLENGE_READY', 'VC_DERIVED', 'DEVICE_SIGNED', 'PROOF_READY', 'VERIFIED', 'WALLET_SIGNED']) {
    const state = ready();
    Object.assign(state.manual, { phase: 'authorize', stage, walletSigned: stage === 'WALLET_SIGNED', verificationResult: { phase: 'authorize', verificationTrace: trace('authorize') } });
    const value = project(state);
    assert.deepEqual(statuses(value), ['pass', 'pass', 'current', 'pending'], stage);
    assert.match(value.steps[2].detail, /结算/);
  }
});

test('only complete, current settle proof material with the backend-enabled verify action finishes proof preparation', () => {
  const value = project(ready());
  assert.deepEqual(statuses(value), ['pass', 'pass', 'pass', 'current']);
  assert.equal(value.currentIndex, 3); assert.equal(value.currentStep, 4);
  assert.match(value.steps[2].detail, /不等于验证通过/);
  const missing = ['presentation', 'verifiableCredential', 'deviceResponse', 'holderProof'];
  for (const key of missing) {
    const state = ready(); delete state.manual[key];
    assert.notEqual(project(state).steps[2].status, 'pass', key);
  }
  for (const change of [
    state => state.manual.walletSigned = false,
    state => state.manual.active = false,
    state => state.manual.availableActions = ['discard'],
    state => state.credential = null,
    state => state.authorization = null,
    state => state.manual.expiresAtUnix = now / 1000,
    state => state.manual.expired = true,
    state => state.manual.stage = 'EXPIRED',
    state => state.credentialStatus = { status: 'revoked' },
  ]) { const state = ready(); change(state); assert.notEqual(project(state).steps[2].status, 'pass'); }
  for (const plan of [{ id: 'verify', enabled: false }, { id: 'refresh', enabled: true }]) {
    assert.notEqual(guideProgress(ready(), plan, { now }).steps[2].status, 'pass');
  }
});

test('both executed and idempotent matching receipts finish the manual flow, including after discard', () => {
  for (const outcome of ['EXECUTED', 'ALREADY_PROCESSED']) {
    const state = completed(outcome);
    assert.deepEqual(statuses(project(state)), ['pass', 'pass', 'pass', 'pass']);
    state.manual.active = false; state.manual.stage = 'DISCARDED';
    delete state.manual.presentation; delete state.manual.verificationResult;
    assert.deepEqual(statuses(project(state)), ['pass', 'pass', 'pass', 'pass']);
    state.manual.verificationResult = state.lastResult; delete state.lastResult;
    assert.equal(project(state).steps[3].status, 'pass');
  }
});

test('the shared receipt helper returns only a confirmed current manual payment and preserves valid fallback', () => {
  for (const outcome of ['EXECUTED', 'ALREADY_PROCESSED']) {
    const state = completed(outcome);
    assert.equal(guidePaymentReceipt(state), state.lastResult.paymentResult);
    state.manual.verificationResult = structuredClone(state.lastResult);
    assert.equal(guidePaymentReceipt(state), state.manual.verificationResult.paymentResult);
    state.manual.verificationResult.paymentResult.receipt.orderId = 'old-order';
    assert.equal(guidePaymentReceipt(state), state.lastResult.paymentResult);
    state.manual.active = false; state.manual.stage = 'DISCARDED'; state.manual.verificationResult = null;
    assert.equal(guidePaymentReceipt(state), state.lastResult.paymentResult);
  }
  const blind = completed(); blind.mode = 'bbs-blind-bls'; blind.lastResult.mode = 'bbs-blind-bls';
  assert.equal(guidePaymentReceipt(blind), blind.lastResult.paymentResult);
});

test('the shared receipt helper rejects unavailable, unsettled or uncertain payment state', () => {
  for (const state of [undefined, null, { available: true }, { ...completed(), available: false }]) assert.equal(guidePaymentReceipt(state), null);
  for (const change of [
    state => state.manual.settled = false,
    state => delete state.manual.settled,
    state => state.manual.walletSigningUnconfirmed = true,
  ]) { const state = completed(); change(state); assert.equal(guidePaymentReceipt(state), null); }
  assert.equal(guidePaymentReceipt(completed(), { uncertain: true }), null);
  const pending = completed(); pending.paymentPending = true; pending.manual.settled = false;
  assert.equal(guidePaymentReceipt(pending), null);
});

test('the shared receipt helper rejects wrong result scope, incomplete completion evidence and incorrect terms', () => {
  for (const mutate of [
    state => state.lastResult.mode = 'bbs-blind-bls',
    state => { delete state.mode; delete state.lastResult.mode; },
    state => state.lastResult.phase = 'authorize',
    state => delete state.lastResult.phase,
    state => state.lastResult.accepted = false,
    state => state.lastResult.task.status.state = 'input-required',
    state => delete state.lastResult.task,
    state => state.lastResult.paymentResult.outcome = 'EXPECTED_PASS',
    state => state.lastResult.paymentResult.receipt.amountMinor++,
    state => state.lastResult.paymentResult.receipt.settlement.payTo = 'other',
    state => delete state.lastResult.paymentResult.receipt,
  ]) { const state = completed(); mutate(state); assert.equal(guidePaymentReceipt(state), null); }
  for (const mutate of [
    result => result.mode = 'bbs-blind-bls', result => result.phase = 'authorize',
    result => result.task.status.state = 'input-required', result => result.paymentResult.receipt.orderId = 'old-order',
  ]) {
    const state = completed(); state.manual.verificationResult = structuredClone(state.lastResult); mutate(state.manual.verificationResult);
    assert.equal(guidePaymentReceipt(state), state.lastResult.paymentResult);
  }
});

test('receipt completion requires every current order term and complete settlement terms', () => {
  for (const key of ['orderId', 'amountMinor', 'currency', 'payerAccount', 'payeeAccount']) {
    const state = completed();
    state.lastResult.paymentResult.receipt[key] = key === 'amountMinor' ? order.amountMinor + 1 : 'other';
    assert.notEqual(project(state).steps[3].status, 'pass', key);
  }
  for (const key of ['network', 'asset', 'payerAddress', 'payTo']) {
    const state = completed(); state.lastResult.paymentResult.receipt.settlement[key] = 'other';
    assert.notEqual(project(state).steps[3].status, 'pass', key);
    delete state.order.settlement[key]; delete state.lastResult.paymentResult.receipt.settlement[key];
    assert.notEqual(project(state).steps[3].status, 'pass', `missing ${key}`);
  }
  const absent = completed(); delete absent.order.settlement; delete absent.lastResult.paymentResult.receipt.settlement;
  assert.notEqual(project(absent).steps[3].status, 'pass');
  for (const invalid of [0, -1, NaN, 2.5, Number.MAX_SAFE_INTEGER + 1]) {
    const state = completed(); state.order.amountMinor = invalid; state.lastResult.paymentResult.receipt.amountMinor = invalid;
    assert.notEqual(project(state).steps[3].status, 'pass');
  }
});

test('a claimed receipt must explicitly come from a completed, accepted settle response of the current mode', () => {
  for (const mutate of [
    result => result.mode = 'bbs-blind-bls', result => delete result.mode,
    result => result.phase = 'authorize', result => delete result.phase,
    result => result.accepted = false, result => delete result.accepted,
    result => result.task.status.state = 'input-required', result => delete result.task,
    result => result.paymentResult.outcome = 'EXPECTED_REJECT', result => delete result.paymentResult.receipt,
  ]) {
    const state = completed(); mutate(state.lastResult);
    const value = project(state); assert.notEqual(value.steps[3].status, 'pass'); assert.match(value.phaseLabel, /回执尚待核对/);
  }
});

test('a settle trace or receipt alone does not complete the new manual guide without its settled state', () => {
  const traceOnly = ready(); traceOnly.manual.verificationResult = { phase: 'settle', verificationTrace: trace('settle') };
  assert.notEqual(project(traceOnly).steps[3].status, 'pass');
  const receiptOnly = completed(); receiptOnly.manual.settled = false;
  assert.notEqual(project(receiptOnly).steps[3].status, 'pass');
  const flagOnly = completed(); delete flagOnly.lastResult;
  assert.notEqual(project(flagOnly).steps[3].status, 'pass'); assert.match(project(flagOnly).phaseLabel, /回执尚待核对/);
});

test('wallet uncertainty and pending payment take priority over receipts and stale failures', () => {
  for (const change of [
    state => state.manual.walletSigningUnconfirmed = true,
    state => { state.paymentPending = true; state.manual.walletSigned = false; state.manual.settled = false; },
  ]) {
    const state = completed(); change(state);
    state.manual.lastError = { verificationTrace: trace('settle', 'credential_status') };
    const value = project(state);
    assert.deepEqual(statuses(value), ['pass', 'pass', 'current', 'pending']);
    assert.equal(value.currentIndex, 2); assert.match(value.phaseLabel, /待确认/);
  }
  const receiptConflict = completed(); receiptConflict.paymentPending = true; receiptConflict.manual.settled = false;
  assert.notEqual(project(receiptConflict).steps[3].status, 'pass');
  assert.match(project(receiptConflict).phaseLabel, /待核对/);
  assert.notEqual(project(ready(), { uncertain: true }).steps[2].status, 'pass');
  const uncertainReceipt = project(completed(), { uncertain: true });
  assert.notEqual(uncertainReceipt.steps[3].status, 'pass'); assert.match(uncertainReceipt.phaseLabel, /待核对/);
});

test('confirmed wallet signing with normal paymentPending continues toward settlement without a false receipt conflict', () => {
  const awaitingChallenge = fixture({ phase: 'authorize', stage: 'WALLET_SIGNED', walletSigned: true,
    availableActions: ['begin-settle', 'discard'] }, { ...approved(), paymentPending: true });
  assert.equal(planPayment(awaitingChallenge, { now }).id, 'begin-settle');
  const preparing = project(awaitingChallenge);
  assert.deepEqual(statuses(preparing), ['pass', 'pass', 'current', 'pending']);
  assert.equal(preparing.phaseLabel, '钱包材料已返回，等待结算证明');
  assert.doesNotMatch(preparing.detail, /原操作结果待核对|通信或后端状态仍有待确认项/);

  const awaitingVerification = ready(); awaitingVerification.paymentPending = true;
  assert.equal(planPayment(awaitingVerification, { now }).id, 'verify');
  const verifying = project(awaitingVerification);
  assert.deepEqual(statuses(verifying), ['pass', 'pass', 'pass', 'current']);
  assert.equal(verifying.phaseLabel, '最终结算验证与回执');
  assert.doesNotMatch(verifying.detail, /原操作结果待核对|通信或后端状态仍有待确认项/);

  const conflictingReceipt = completed(); conflictingReceipt.paymentPending = true; conflictingReceipt.manual.settled = false;
  assert.equal(project(conflictingReceipt).phaseLabel, '原操作结果待核对');
  assert.notEqual(project(conflictingReceipt).steps[3].status, 'pass');
});

test('only actual current-phase verifier rejection fails and focuses its corresponding overview step', () => {
  for (const [phase, index] of [['proposal', 1], ['authorize', 2], ['settle', 3]]) {
    const state = fixture({ phase, lastError: { verificationTrace: trace(phase, 'credential_status') } }, phase === 'proposal' ? {} : approved());
    const value = project(state);
    assert.equal(value.steps[index].status, 'fail', phase); assert.equal(value.currentIndex, index, phase);
    assert.ok(value.steps.every((step, position) => position === index || step.status !== 'fail'));
  }
  const failedSettle = ready(); failedSettle.manual.lastError = { verificationTrace: trace('settle', 'credential_status') };
  assert.deepEqual(statuses(project(failedSettle)), ['pass', 'pass', 'pass', 'fail']);
});

test('expected attack results, communication errors and stale trace scopes never create a verifier failure', () => {
  const states = [
    fixture({ lastAttack: { pass: true, actual: 'REJECTED', expected: 'REJECTED' } }),
    fixture({ lastError: { code: 'NETWORK_ERROR', message: 'rejected' } }),
    fixture({ lastError: { verificationTrace: { ...trace('proposal', 'credential_status'), profile: 'dbac' } } }),
    fixture({ lastError: { verificationTrace: { ...trace('proposal', 'credential_status'), source: 'agent-a' } } }),
    fixture({ lastError: { verificationTrace: trace('authorize', 'credential_status') } }),
    fixture({ verificationResult: { phase: 'settle', verificationTrace: trace('settle', 'credential_status') } }),
    fixture({ verificationResult: { mode: 'bbs-blind-bls', phase: 'proposal', verificationTrace: trace('proposal', 'credential_status') } }),
    fixture({ lastError: { verificationTrace: trace('proposal', 'credential_status') } }),
  ];
  for (const [index, state] of states.entries()) {
    const value = project(state, index === states.length - 1 ? { uncertain: true } : {});
    assert.ok(value.steps.every(step => step.status !== 'fail'), String(index));
  }
});

test('Owner rejection fails only the corresponding order and cannot override unknown wallet state', () => {
  const denied = fixture({}, { proposal: { status: 'REJECTED', payment: structuredClone(order) } });
  assert.equal(project(denied).steps[1].status, 'fail'); assert.equal(project(denied).currentIndex, 1);
  for (const payment of [undefined, { ...order, orderId: 'old-order' }, { ...order, amountMinor: 1 }]) {
    const state = fixture({}, { proposal: { status: 'REJECTED', payment } });
    assert.ok(project(state).steps.every(step => step.status !== 'fail'));
  }
  denied.manual.walletSigningUnconfirmed = true;
  assert.equal(project(denied).currentIndex, 2); assert.ok(project(denied).steps.every(step => step.status !== 'fail'));
});

test('the projection leaves backend state and supplied action plan unchanged', () => {
  const state = ready(), original = structuredClone(state), plan = planPayment(state, { now }), originalPlan = structuredClone(plan);
  const first = guideProgress(state, plan, { now }), second = guideProgress(state, undefined, { now });
  assert.deepEqual(first, second); assert.deepEqual(state, original); assert.deepEqual(plan, originalPlan);
});
