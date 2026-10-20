import { AppError } from '../protocol.mjs';
import { preVerificationFailure } from '../verification-trace.mjs';
import { canonicalOrder } from './merchant-protocol.mjs';

// This adapter observes the supplied session's existing manual actions. It does
// not sign, verify, authorize, price an order or submit a wallet payload itself.
const descriptions = {
  issue: ['签发支付资格凭证', 'agent-a', 'issuer'],
  newOrder: ['创建本笔订单', 'agent-a', 'agent-a'],
  'begin-proposal': ['取得资格认证挑战', 'agent-a', 'agent-b'],
  'begin-authorize': ['取得付款前复核挑战', 'agent-a', 'agent-b'],
  'begin-settle': ['取得结算验证挑战', 'agent-a', 'agent-b'],
  'derive-vc': ['派生本轮 BBS 披露材料', 'agent-a', 'agent-a'],
  'device-sign': ['请求软件 eSIM 的设备贡献', 'agent-a', 'device'],
  prove: ['持有者 A 核验并组合本轮证明', 'agent-a', 'agent-a'],
  verify: ['提交验证者 B 实际验证', 'agent-a', 'agent-b'],
  'submit-owner': ['提交本笔用户授权申请', 'agent-a', 'owner'],
  'sync-owner': ['读取用户对本笔订单的决定', 'agent-a', 'owner'],
  'wallet-sign': ['请求钱包核验授权并签名', 'agent-a', 'wallet'],
  discard: ['结束当前认证尝试', 'agent-a', 'agent-a'],
};
const failure = (code, message, status = 409) => new AppError(code, message, status);
const copy = value => structuredClone(value);
const pacedActions = new Set(['issue', 'device-sign', 'prove', 'verify', 'submit-owner', 'sync-owner', 'wallet-sign', 'query-payment']);
const samePayment = (left, right) => Boolean(left && right &&
  ['orderId', 'payerAccount', 'payeeAccount', 'amountMinor', 'currency'].every(key => left[key] === right[key]) &&
  ['network', 'asset', 'payTo', 'payerAddress'].every(key => left.settlement?.[key] === right.settlement?.[key]) && canonicalOrder(left.merchantOrder ?? null) === canonicalOrder(right.merchantOrder ?? null));

function currentResult(state, phase) {
  const manual = state.manual;
  for (const result of [manual?.verificationResult, state.lastResult]) {
    const context = result?.wire?.context;
    if (result?.accepted === true && result.mode === state.mode && result.phase === phase &&
      context?.paymentOrderId === state.order?.orderId && context?.challengeId === manual?.challenge?.challengeId &&
      typeof context?.challengeId === 'string' && result.verificationTrace?.outcome === 'pass') return result;
  }
  throw failure('LIVE_RESULT_MISMATCH', '未取得与当前订单、阶段及挑战一致的实际验证结果。');
}

function completedResult(state) {
  if (!state.manual?.settled || state.manual.phase !== 'settle') return null;
  const result = currentResult(state, 'settle');
  const receipt = result.paymentResult?.receipt;
  if (!['EXECUTED', 'ALREADY_PROCESSED'].includes(result.paymentResult?.outcome) ||
    !samePayment(receipt, state.order) || receipt?.transactionStatus !== 'success') {
    throw failure('DBAC_PAYMENT_RECEIPT_INVALID', '尚未取得匹配当前订单的成功回执，请保留原订单核对。');
  }
  return result;
}

function guardPending(state) {
  const manual = state.manual ?? {};
  if (state.paymentPending || manual.walletSigningUnconfirmed || (!manual.settled && manual.walletSigned)) {
    throw failure('DBAC_PAYMENT_PENDING', '原订单已请求钱包签名或结算结果待确认；请保留原订单核对，不能重新签名或更换订单。');
  }
  if (manual.settled) completedResult(state);
}

// Only allowlisted public metadata enters notifications. In particular, never
// forward a whole core state, manual log, authorization or wallet payload here.
function publicData(state, { verificationPhase } = {}) {
  const m = state?.manual ?? {}, result = m.verificationResult;
  const receipt = result?.paymentResult?.receipt;
  let verificationTrace;
  if (verificationPhase && m.phase === verificationPhase) {
    try { verificationTrace = copy(currentResult(state, verificationPhase).verificationTrace); }
    catch { /* Unassociated results never become retained verification evidence. */ }
  }
  return {
    stage: m.stage ?? null,
    credentialId: state?.currentCredentialId ?? null,
    credentialStatus: state?.credentialStatus?.status ?? null,
    deviceId: state?.currentDeviceId ?? null,
    deviceLocked: m.device?.modes?.[state?.mode]?.locked ?? null,
    deviceSignatures: m.device?.modes?.[state?.mode]?.signatures ?? null,
    challengeId: m.challenge?.challengeId ?? null,
    proposalId: state?.proposal?.id ?? null,
    proposalStatus: state?.proposal?.status ?? null,
    walletSigned: Boolean(m.walletSigned),
    paymentPending: Boolean(state?.paymentPending || m.walletSigningUnconfirmed),
    settled: Boolean(m.settled),
    ...(verificationTrace ? { verificationTrace } : {}),
    ...(samePayment(receipt, state?.order) ? { receipt: { orderId: receipt.orderId, amountMinor: receipt.amountMinor, currency: receipt.currency,
      transactionHash: receipt.transactionHash, transactionStatus: receipt.transactionStatus, outcome: result.paymentResult.outcome } } : {}),
  };
}

export function createLivePaymentSession({ paymentSession: core, emit = () => {}, stageDelayMs = 0 }) {
  if (!Number.isSafeInteger(stageDelayMs) || stageDelayMs < 0 || stageDelayMs > 2000) throw new TypeError('stageDelayMs must be an integer between 0 and 2000 milliseconds');
  let mutationRunning = false;
  async function holdCompletedStage(action) {
    // Pause the real server-side sequence only after the original action has
    // returned and its actual result has been published. No result is invented,
    // no protocol timestamp is changed, and the exclusive lock stays held.
    // Internal derivation and cart changes need no separate presentation stop.
    if (stageDelayMs && (action.startsWith('begin-') || pacedActions.has(action))) {
      await new Promise(resolve => setTimeout(resolve, stageDelayMs));
    }
  }
  function notify(action, status, state, { type = 'protocol', phase, detail, error } = {}) {
    const [title, requestFrom, requestTo] = descriptions[action] ?? [action.startsWith('manage:') ? '更新凭证与设备状态' : action, 'agent-a', action.startsWith('manage:lock') || action.startsWith('manage:unlock') ? 'device' : 'issuer'];
    const [from, to] = status === 'start' ? [requestFrom, requestTo] : [requestTo, requestFrom];
    const event = {
      type, source: 'original-controller', action, status, title,
      detail: detail ?? (status === 'start' ? '原接口正在执行；尚未取得本步结果。' : status === 'fail' ? error?.message ?? '本步接口未完成。' : '原接口已返回本步实际结果。'),
      orderId: state?.order?.orderId ?? null,
      phase: phase ?? state?.manual?.phase ?? null,
      attemptId: state?.manual?.attemptId ?? null,
      from, to,
      data: { ...publicData(state, { verificationPhase: action === 'verify' && status === 'complete' ? phase ?? state?.manual?.phase : undefined }),
        ...(error ? { error: { code: error.code ?? 'ERROR', message: error.message } } : {}) },
    };
    // Display failures cannot turn a successful wallet/settlement operation
    // into a rejected business response that encourages a second submission.
    try { emit(event); } catch { /* The original controller remains authoritative. */ }
  }
  async function exclusive(action) {
    if (mutationRunning) throw failure('DBAC_OPERATION_BUSY', '已有原控制器操作正在处理，请等待结果。');
    mutationRunning = true;
    try { return await action(); } catch (error) {
      error.verificationTrace ??= preVerificationFailure('dbac-payment', error);
      throw error;
    } finally { mutationRunning = false; }
  }
  function bound(state, expected, mode) {
    if (!samePayment(state.order, expected) || state.mode !== mode) throw failure('LIVE_ORDER_CHANGED', '原控制器当前订单或证明模式已变化，请核对原订单。');
    const m = state.manual;
    if (m?.active && (!m.attemptId || !m.challenge || m.challenge.paymentOrderId !== expected.orderId || m.challenge.mode !== mode)) {
      throw failure('LIVE_ATTEMPT_MISMATCH', '当前认证尝试的订单或模式不匹配。');
    }
  }
  async function step(action, state, expected, mode, { hold = true, attemptId = state.manual?.attemptId } = {}) {
    bound(state, expected, mode);
    const phase = action.startsWith('begin-') ? action.slice(6) : state.manual?.phase;
    const previousId = state.manual?.attemptId;
    notify(action, 'start', state, { phase });
    try {
      const next = await core.manual({ mode, action, ...(attemptId ? { attemptId } : {}) });
      bound(next, expected, mode);
      if (!action.startsWith('begin-') && previousId && next.manual?.attemptId !== previousId) throw failure('LIVE_ATTEMPT_MISMATCH', '返回的认证尝试不是本次提交的尝试。');
      if (action.startsWith('begin-') && (next.manual?.phase !== phase || !next.manual?.attemptId)) throw failure('LIVE_ATTEMPT_MISMATCH', '原控制器未返回当前阶段的新认证尝试。');
      if (next.manual?.lastError) {
        const error = failure(next.manual.lastError.code ?? 'LIVE_PROTOCOL_FAILED', next.manual.lastError.message ?? '原协议操作未完成。');
        if (next.manual.lastError.verificationTrace) error.verificationTrace = next.manual.lastError.verificationTrace;
        throw error;
      }
      notify(action, 'complete', next, { phase });
      if (hold) await holdCompletedStage(action);
      return next;
    } catch (error) {
      notify(action, 'fail', state, { phase, error });
      throw error;
    }
  }
  async function phase(name, state, expected, mode) {
    state = await step(`begin-${name}`, state, expected, mode);
    if (state.w3c?.enabled) state = await step('derive-vc', state, expected, mode);
    for (const action of ['device-sign', 'prove', 'verify']) state = await step(action, state, expected, mode);
    currentResult(state, name);
    return state;
  }
  async function operation(name, options = {}) {
    return exclusive(async () => {
      let state = await core.state({ mode: options.mode ?? 'bbs-bls' });
      const action = name === 'manage' ? `manage:${options.action}` : name;
      if (name === 'newOrder' || name === 'issue') guardPending(state);
      if (name === 'newOrder' && state.manual?.active) state = await step('discard', state, copy(state.order), state.mode);
      notify(action, 'start', state, { type: 'operation' });
      try {
        const result = await core[name](options);
        // manage returns inventory, whose device/credential fields differ from
        // payment state. Do not manufacture a payment state from that result.
        const currentDevice = name === 'manage' ? result.devices?.find(device => device.id === result.currentDeviceId || device.deviceId === result.currentDeviceId) : null;
        const currentCredential = name === 'manage' ? result.credentials?.find(credential => credential.id === result.currentCredentialId) : null;
        const notificationState = name === 'manage' ? { order: state.order, mode: state.mode, currentCredentialId: result.currentCredentialId,
          currentDeviceId: result.currentDeviceId, credentialStatus: { status: currentCredential?.status },
          manual: { stage: state.manual?.stage, phase: state.manual?.phase, attemptId: state.manual?.attemptId,
            device: { modes: { [state.mode]: { locked: currentDevice?.locked, signatures: currentDevice?.signCount } } } } } : result;
        notify(action, 'complete', notificationState, { type: 'operation', detail: '原控制器已完成该操作。' });
        await holdCompletedStage(action);
        return result;
      } catch (error) { notify(action, 'fail', state, { type: 'operation', error }); throw error; }
    });
  }
  return {
    state: options => core.state(options),
    inventory: options => core.inventory(options),
    manual: (options = {}) => exclusive(async () => {
      const mode = options.mode ?? 'bbs-bls';
      const state = await core.state({ mode });
      if (options.attemptId !== (state.manual?.attemptId ?? null)) throw failure('DBAC_MANUAL_ATTEMPT_MISMATCH', '此操作来自旧挑战，请重新读取当前控制台。');
      // Exactly one explicit protocol operation. Observing the returned state
      // never invokes the next action, even when it is immediately available.
      return step(options.action, state, copy(state.order), mode, { hold: false, attemptId: options.attemptId });
    }),
    queryPayment: options => exclusive(async () => {
      const result = await core.queryPayment(options);
      await holdCompletedStage('query-payment');
      return result;
    }),
    experiments: options => exclusive(() => core.experiments(options)),
    issue: options => operation('issue', options),
    manage: options => operation('manage', options),
    newOrder: options => operation('newOrder', options),
    syncOwner: (options = {}) => exclusive(async () => {
      const mode = options.mode ?? 'bbs-bls';
      const state = await core.state({ mode });
      return step('sync-owner', state, copy(state.order), mode);
    }),
    propose: (options = {}) => exclusive(async () => {
      const mode = options.mode ?? 'bbs-bls';
      let state = await core.state({ mode });
      guardPending(state);
      if (state.proposal && ['PENDING', 'APPROVED'].includes(state.proposal.status)) throw failure('DBAC_PROPOSAL_EXISTS', '本订单已有用户授权申请，请核对原申请。');
      const order = copy(state.order);
      state = await phase('proposal', state, order, mode);
      const result = currentResult(state, 'proposal');
      state = await step('submit-owner', state, order, mode);
      if (state.proposal?.status !== 'PENDING' || !samePayment(state.proposal.payment, order) || state.proposal.mode !== mode) throw failure('LIVE_PROPOSAL_MISMATCH', '原控制器未返回本笔订单的待确认授权申请。');
      return { ...state, verificationTrace: result.verificationTrace, wire: result.wire };
    }),
    pay: (options = {}) => exclusive(async () => {
      const mode = options.mode ?? 'bbs-bls';
      let state = await core.state({ mode });
      guardPending(state);
      const existing = completedResult(state);
      if (existing) return copy(existing);
      const order = copy(state.order);
      state = await step('sync-owner', state, order, mode);
      if (state.proposal?.status !== 'APPROVED' || !samePayment(state.proposal.payment, order) ||
        state.proposal.mode !== mode || !state.authorization || !samePayment(state.authorization.document?.payment, order)) {
        throw failure('OWNER_CONFIRMATION_REQUIRED', '需要用户明确批准当前订单，才可进行付款前复核。', 403);
      }
      state = await phase('authorize', state, order, mode);
      const authorized = currentResult(state, 'authorize');
      state = await step('wallet-sign', state, order, mode);
      if (!state.manual?.walletSigned || state.manual?.walletSigningUnconfirmed) throw failure('DBAC_PAYMENT_PENDING', '钱包签名结果尚未确认，请保留原订单核对。');
      state = await phase('settle', state, order, mode);
      const settled = completedResult(state);
      if (!settled) throw failure('DBAC_PAYMENT_RECEIPT_INVALID', '原控制器尚未返回本笔订单的最终支付回执。');
      return { ...settled, verificationTraces: [authorized.verificationTrace, settled.verificationTrace], paymentFlow: ['dbac-verified', 'input-required', 'payment-submitted', 'completed'] };
    }),
  };
}
