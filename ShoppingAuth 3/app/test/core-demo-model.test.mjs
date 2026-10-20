import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_INPUT, parseInput, formatUnits, inputMatches, pendingPayment, recoveryPhase,
  metrics, difference, noDeviceEvidence, receiptFor, errorState,
} from '../public/core-model.js';

// These are presentation-contract tests, not cryptographic or chain acceptance.
// They prevent the view from presenting missing or unrelated evidence as success.
function evidenceFixture() {
  const before = { payer: 1000000000, payee: 250000, executions: 7, signatures: 11 };
  const state = {
    mode: 'bbs-bls', order: { payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard' },
    ledger: {
      accounts: [{ id: 'demo:alice', balanceMinor: before.payer }, { id: 'merchant:keyboard', balanceMinor: before.payee }],
      executionCount: before.executions,
    },
    manual: {
      device: { modes: { 'bbs-bls': { signatures: before.signatures } } },
      lastAttack: {
        actual: 'W3C_DEVICE_PROOF_REQUIRED', expected: 'W3C_DEVICE_PROOF_REQUIRED', pass: true,
        verificationTrace: { source: 'agent-b', steps: [
          { id: 'w3c_bbs', status: 'pass' }, { id: 'vc_device_binding', status: 'fail' },
        ] },
      },
    },
  };
  return { state, before };
}

function receiptFixture() {
  const order = {
    orderId: 'urn:uuid:current-order', payerAccount: 'demo:alice',
    payeeAccount: 'merchant:keyboard', amountMinor: 2990000, currency: 'TEST_USDC',
    settlement: { network: 'eip155:31337', asset: `0x${'a'.repeat(40)}`,
      payTo: `0x${'b'.repeat(40)}`, payerAddress: `0x${'c'.repeat(40)}` },
  };
  const receipt = { ...structuredClone(order), transactionHash: `0x${'d'.repeat(64)}`,
    transactionStatus: 'success', localTestOnly: true };
  return { order, receipt, state: { ledger: { receipts: [receipt] } } };
}

test('editable decimal inputs retain six-digit precision and accept the documented boundaries', () => {
  assert.equal(parseInput(DEFAULT_INPUT).amountMinor, 2990000);
  for (const [amount, expected] of [['0.000001', 1], ['1.234567', 1234567], ['1000', 1000000000], [' 2.99 ', 2990000]]) {
    const parsed = parseInput({ ...DEFAULT_INPUT, amount });
    assert.equal(parsed.amountMinor, expected, amount);
  }
  assert.deepEqual(parseInput({ amount: '1.234567', payeeAccount: 'merchant:other', mode: 'bbs-blind-bls' }), {
    amountMinor: 1234567, payeeAccount: 'merchant:other', mode: 'bbs-blind-bls',
  });
  assert.equal(formatUnits(1234567), '1.234567');
  assert.equal(formatUnits(-2990000), '-2.99');
});

test('invalid amounts, unconfigured merchants and unconnected modes cannot become a submitted configuration', () => {
  for (const amount of ['1e2', '1E-6', '-1', '-0.000001', '+1', '0.0000001', '1.2345678', '1000.000001', '0', '0.000000', '', 'NaN', 'Infinity']) {
    assert.throws(() => parseInput({ ...DEFAULT_INPUT, amount }), undefined, amount);
  }
  for (const payeeAccount of ['merchant:unknown', '__proto__', '', null]) {
    assert.throws(() => parseInput({ ...DEFAULT_INPUT, payeeAccount }), /商户/);
  }
  assert.throws(() => parseInput(DEFAULT_INPUT, ['merchant:other']), /商户/, 'the backend payee list is authoritative for the view');
  for (const mode of ['bbs', 'unknown', '', null]) assert.throws(() => parseInput({ ...DEFAULT_INPUT, mode }), /模式/);
});

test('editing any visible input invalidates its association with the returned order configuration', () => {
  const config = parseInput(DEFAULT_INPUT);
  const state = { mode: config.mode, order: { amountMinor: config.amountMinor, payeeAccount: config.payeeAccount } };
  assert.equal(inputMatches(config, state), true);
  assert.equal(inputMatches({ ...config, amountMinor: 3000000 }, state), false);
  assert.equal(inputMatches({ ...config, payeeAccount: 'merchant:other' }, state), false);
  assert.equal(inputMatches({ ...config, mode: 'bbs-blind-bls' }, state), false);
  assert.equal(inputMatches(config, undefined), false);
});

test('automatic and manual uncertain payments remain pending until their actual settlement is confirmed', () => {
  assert.equal(pendingPayment({ paymentPending: true }), true);
  assert.equal(pendingPayment({ paymentPending: true, manual: { settled: true } }), true, 'automatic pending evidence is not overridden by a separate manual flag');
  for (const key of ['walletSigned', 'walletSigningUnconfirmed']) {
    assert.equal(pendingPayment({ manual: { [key]: true, settled: false } }), true, key);
    assert.equal(pendingPayment({ manual: { [key]: true, settled: true } }), false, key);
  }
  assert.equal(pendingPayment({ paymentPending: false, manual: { walletSigned: false, walletSigningUnconfirmed: false } }), false);
  assert.equal(pendingPayment(undefined), false);
});

test('recovery distinguishes an unconfirmed signature from an available signed payment payload', () => {
  assert.equal(recoveryPhase({ paymentPending: true, manual: { walletSigningUnconfirmed: true, walletSigned: false, settled: false } }), 'authorize');
  assert.equal(recoveryPhase({ paymentPending: true, manual: { walletSigningUnconfirmed: false, walletSigned: true, settled: false } }), 'settle');
  assert.equal(recoveryPhase({ manual: { walletSigned: true, settled: false } }), 'settle', 'the signed-payload observation is enough even without the aggregate flag');
});

test('missing observations and a generic pending flag do not invent a recovery phase', () => {
  for (const state of [undefined, null, {}, { paymentPending: true }, { paymentPending: true, manual: {} },
    { manual: { walletSigned: false, walletSigningUnconfirmed: false, settled: false } },
    { manual: { walletSigned: 'true', walletSigningUnconfirmed: 'unknown', settled: false } }]) {
    assert.equal(recoveryPhase(state), null);
  }
});

test('a confirmed settlement never offers a new recovery phase even when old pending flags remain', () => {
  for (const previous of [{ walletSigned: true }, { walletSigningUnconfirmed: true }, { walletSigned: true, walletSigningUnconfirmed: true }]) {
    assert.equal(recoveryPhase({ paymentPending: true, manual: { ...previous, settled: true } }), null);
  }
});

test('a no-device comparison succeeds only on the observed BBS pass, binding rejection and unchanged actual counters', () => {
  const { state, before } = evidenceFixture();
  const result = noDeviceEvidence(state, before);
  assert.equal(result.passed, true);
  assert.equal(result.code, 'W3C_DEVICE_PROOF_REQUIRED');
  assert.deepEqual(result.delta, { payer: 0, payee: 0, executions: 0, signatures: 0 });
  assert.equal(result.trace, state.manual.lastAttack.verificationTrace);
});

test('a declared expected pass never substitutes for the actual verifier result', () => {
  for (const mutate of [
    s => { s.manual.lastAttack.actual = 'DBAC_BODY_MISMATCH'; },
    s => { s.manual.lastAttack.verificationTrace.source = 'agent-a'; },
    s => { s.manual.lastAttack.verificationTrace.steps[0].status = 'fail'; },
    s => { s.manual.lastAttack.verificationTrace.steps[1].status = 'pass'; },
    s => { s.manual.lastAttack.verificationTrace.steps[1].status = 'not-run'; },
    s => { delete s.manual.lastAttack.verificationTrace; },
  ]) {
    const { state, before } = evidenceFixture();
    mutate(state);
    assert.equal(noDeviceEvidence(state, before).passed, false);
  }
});

test('any balance, execution-count or device-count movement invalidates the unchanged-state comparison', () => {
  for (const mutate of [
    s => { s.ledger.accounts[0].balanceMinor -= 1; },
    s => { s.ledger.accounts[1].balanceMinor += 1; },
    s => { s.ledger.executionCount += 1; },
    s => { s.manual.device.modes['bbs-bls'].signatures += 1; },
  ]) {
    const { state, before } = evidenceFixture();
    mutate(state);
    assert.equal(noDeviceEvidence(state, before).passed, false);
  }
});

test('missing evidence stays unavailable rather than being rendered as zero or a successful comparison', () => {
  assert.deepEqual(metrics(undefined), { payer: null, payee: null, executions: null, signatures: null });
  assert.deepEqual(difference(undefined, undefined), { payer: null, payee: null, executions: null, signatures: null });
  assert.equal(formatUnits(null), '未取得数据');
  for (const mutate of [
    s => { s.ledger.accounts = []; },
    s => { delete s.ledger.executionCount; },
    s => { delete s.manual.device; },
  ]) {
    const { state, before } = evidenceFixture();
    mutate(state);
    const observed = noDeviceEvidence(state, before);
    assert.equal(observed.passed, false);
    assert.ok(Object.values(observed.delta).includes(null));
  }
  const { state } = evidenceFixture();
  assert.equal(noDeviceEvidence(state, undefined).passed, false, 'a missing pre-operation snapshot cannot establish unchanged state');
});

test('a successful local receipt is associated with exactly the current complete order terms', () => {
  const { state, order, receipt } = receiptFixture();
  assert.equal(receiptFor(state, order), receipt);
  receipt.settlement.asset = receipt.settlement.asset.toUpperCase();
  receipt.settlement.payTo = receipt.settlement.payTo.toUpperCase();
  assert.equal(receiptFor(state, order), receipt, 'address casing does not change an EVM destination');
  assert.equal(receiptFor({ ledger: { receipts: [] } }, order), null);
  assert.equal(receiptFor(undefined, order), null);
});

test('another order, changed payment terms or a failed/nonlocal receipt cannot imply this payment completed', () => {
  const replacements = {
    orderId: 'urn:uuid:previous-order', amountMinor: 2990001, currency: 'OTHER',
    payerAccount: 'demo:bob', payeeAccount: 'merchant:other', transactionStatus: 'reverted', localTestOnly: false,
  };
  for (const [key, value] of Object.entries(replacements)) {
    const { state, order, receipt } = receiptFixture();
    receipt[key] = value;
    assert.equal(receiptFor(state, order), null, key);
  }
  for (const key of ['network', 'asset', 'payTo', 'payerAddress']) {
    const { state, order, receipt } = receiptFixture();
    receipt.settlement[key] = key === 'network' ? 'eip155:31338' : `0x${'e'.repeat(40)}`;
    assert.equal(receiptFor(state, order), null, key);
  }
});

test('an incomplete order and an equally incomplete receipt do not establish full payment-term agreement', () => {
  for (const key of ['orderId', 'amountMinor', 'currency', 'payerAccount', 'payeeAccount']) {
    const { state, order, receipt } = receiptFixture();
    delete order[key]; delete receipt[key];
    assert.equal(receiptFor(state, order), null, `missing ${key}`);
  }
  for (const key of ['network', 'asset', 'payTo', 'payerAddress']) {
    const { state, order, receipt } = receiptFixture();
    delete order.settlement[key]; delete receipt.settlement[key];
    assert.equal(receiptFor(state, order), null, `missing settlement.${key}`);
  }
  const { state, order, receipt } = receiptFixture();
  delete order.settlement; delete receipt.settlement;
  assert.equal(receiptFor(state, order), null, 'missing the entire settlement');
});

test('transport uncertainty and expired challenges remain distinct from definite verifier rejection', () => {
  for (const error of [
    { code: 'DBAC_PAYMENT_TRANSPORT', message: 'The response was lost' },
    { data: { error: { code: 'DBAC_CHALLENGE_EXPIRED' } }, message: 'Challenge expired' },
    { code: 'TIMEOUT', message: 'Request timed out' },
    { name: 'TypeError', message: 'Failed to fetch' },
    { code: 'X402_SETTLEMENT_PENDING', message: '结算结果尚未确认；交易可能已广播，请用同一订单查询，不表示资金已回滚。' },
    { code: 'X402_RECOVERY_REQUIRED', message: '授权已在链上消费，但无法定位唯一交易；停止再次付款。' },
  ]) {
    assert.equal(errorState(error).status, 'timeout');
  }
  const rejection = { data: { error: { code: 'W3C_DEVICE_PROOF_REQUIRED' } }, message: '需要设备证明' };
  assert.deepEqual(errorState(rejection), { status: 'failure', code: 'W3C_DEVICE_PROOF_REQUIRED', message: '需要设备证明' });
  assert.equal(errorState({ code: 'DBAC_BODY_MISMATCH', message: '本次输入已改变' }).status, 'failure');
  assert.equal(errorState({ code: 'X402_SETTLEMENT_FAILED', message: '链上交易未执行成功。' }).status, 'failure');
  assert.equal(errorState(undefined).status, 'failure');
});
