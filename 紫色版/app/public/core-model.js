// Pure presentation helpers. Authentication and payment decisions remain on B.
export const DEFAULT_INPUT = Object.freeze({ amount: '2.99', payeeAccount: 'merchant:keyboard', mode: 'bbs-bls' });
export function parseInput(input, payees = ['merchant:keyboard', 'merchant:other']) {
  const text = String(input.amount ?? '').trim();
  if (!/^\d+(?:\.\d{1,6})?$/.test(text)) throw new Error('金额须为正数，最多 6 位小数；不接受科学计数法。');
  const [whole, fraction = ''] = text.split('.');
  const units = BigInt(whole) * 1000000n + BigInt(fraction.padEnd(6, '0'));
  if (units < 1n || units > 1000000000n) throw new Error('示例金额范围为 0.000001–1000 TEST_USDC。');
  if (!payees.includes(input.payeeAccount)) throw new Error('请选择后端已配置的收款商户。');
  if (!['bbs-bls', 'bbs-blind-bls'].includes(input.mode)) throw new Error('设备模式未接入。');
  return { amountMinor: Number(units), payeeAccount: input.payeeAccount, mode: input.mode };
}
export function formatUnits(value) {
  if (!Number.isSafeInteger(value)) return '未取得数据';
  const n = BigInt(value), absolute = n < 0n ? -n : n;
  const fraction = (absolute % 1000000n).toString().padStart(6, '0').replace(/0+$/, '');
  return `${n < 0n ? '-' : ''}${absolute / 1000000n}${fraction ? `.${fraction}` : ''}`;
}
export function inputMatches(config, state) {
  return Boolean(config && state?.mode === config.mode && state.order?.amountMinor === config.amountMinor && state.order?.payeeAccount === config.payeeAccount);
}
export function pendingPayment(state) {
  return Boolean(state?.paymentPending || (state?.manual?.walletSigned || state?.manual?.walletSigningUnconfirmed) && !state?.manual?.settled);
}
export function recoveryPhase(state) {
  const manual = state?.manual;
  if (!manual || manual.settled === true) return null;
  if (manual.walletSigningUnconfirmed === true) return 'authorize';
  // A generic pending flag does not establish that the wallet payload exists.
  // Only the backend's positive signed-payload observation permits settlement.
  return manual.walletSigned === true ? 'settle' : null;
}
export function metrics(state) {
  const account = id => state?.ledger?.accounts?.find(a => a.id === id)?.balanceMinor;
  return {
    payer: account(state?.order?.payerAccount) ?? null,
    payee: account(state?.order?.payeeAccount) ?? null,
    executions: state?.ledger?.executionCount ?? null,
    signatures: state?.manual?.device?.modes?.[state?.mode]?.signatures ?? null,
  };
}
export function difference(before, after) {
  return Object.fromEntries(['payer', 'payee', 'executions', 'signatures'].map(key => [key,
    Number.isSafeInteger(before?.[key]) && Number.isSafeInteger(after?.[key]) ? after[key] - before[key] : null]));
}
export function noDeviceEvidence(state, before) {
  const attack = state?.manual?.lastAttack;
  const trace = attack?.verificationTrace;
  const delta = difference(before, metrics(state));
  const standard = trace?.steps?.find(step => step.id === 'w3c_bbs')?.status;
  const binding = trace?.steps?.find(step => step.id === 'vc_device_binding')?.status;
  const passed = attack?.actual === 'W3C_DEVICE_PROOF_REQUIRED' && trace?.source === 'agent-b' && standard === 'pass' && binding === 'fail' && delta.payer === 0 && delta.payee === 0 && delta.executions === 0 && delta.signatures === 0;
  return { passed, code: attack?.actual ?? '未返回拒绝原因', standard, binding, delta, trace: trace ?? null };
}
export function receiptFor(state, order) {
  if(!order || !Number.isSafeInteger(order.amountMinor) || order.amountMinor <= 0 ||
    ['orderId','currency','payerAccount','payeeAccount'].some(key=>typeof order[key]!=='string'||!order[key]) ||
    ['network','asset','payTo','payerAddress'].some(key=>typeof order.settlement?.[key]!=='string'||!order.settlement[key])) return null;
  const receipt = state?.ledger?.receipts?.find(r => r.orderId === order?.orderId);
  if (!receipt || receipt.amountMinor !== order.amountMinor || receipt.currency !== order.currency || receipt.payerAccount !== order.payerAccount || receipt.payeeAccount !== order.payeeAccount) return null;
  for (const key of ['network', 'asset', 'payTo', 'payerAddress']) if (String(receipt.settlement?.[key]).toLowerCase() !== String(order.settlement?.[key]).toLowerCase()) return null;
  return receipt.transactionStatus === 'success' && receipt.localTestOnly === true && typeof receipt.transactionHash==='string' && /^0x[0-9a-fA-F]{64}$/.test(receipt.transactionHash) ? receipt : null;
}
export function errorState(error) {
  const code = error?.data?.error?.code || error?.code || error?.name || 'ERROR';
  const timeout = /timeout|expired|TRANSPORT|UNAVAILABLE|SETTLEMENT_PENDING|RECOVERY_REQUIRED|fetch|network/i.test(`${code} ${error?.message}`);
  return { status: timeout ? 'timeout' : 'failure', code, message: error?.message || '操作未完成，未取得结果。' };
}
