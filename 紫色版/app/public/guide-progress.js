import { planPayment, verificationVerdict } from './guide-model.js';

// This is a display projection. It never runs, skips or authorizes an action.
const phases = ['proposal', 'authorize', 'settle'];
const nonempty = value => typeof value === 'string' && value.length > 0;
function sameOrder(candidate, order) {
  if (!candidate || !order || !nonempty(order.orderId)) return false;
  if (!Number.isSafeInteger(order.amountMinor) || order.amountMinor <= 0) return false;
  if (!['orderId', 'currency', 'payerAccount', 'payeeAccount'].every(key => nonempty(order[key]) && candidate[key] === order[key])) return false;
  if (candidate.amountMinor !== order.amountMinor) return false;
  if (!order.settlement || !['network', 'asset', 'payerAddress', 'payTo'].every(key => nonempty(order.settlement[key]) && candidate.settlement?.[key] === order.settlement[key])) return false;
  return true;
}
function matchingReceipt(state) {
  if (!['bbs-bls', 'bbs-blind-bls'].includes(state?.mode)) return null;
  for (const result of [state?.manual?.verificationResult, state?.lastResult]) {
    if (result?.mode !== state?.mode || result?.phase !== 'settle' || result?.accepted !== true || result?.task?.status?.state !== 'completed') continue;
    const payment = result?.paymentResult;
    if (['EXECUTED', 'ALREADY_PROCESSED'].includes(payment?.outcome) && sameOrder(payment.receipt, state?.order)) return payment;
  }
  return null;
}
export function guidePaymentReceipt(state, { uncertain = false } = {}) {
  if (state?.available !== true || state?.manual?.settled !== true || state?.manual?.walletSigningUnconfirmed === true || uncertain) return null;
  return matchingReceipt(state);
}
function currentTrace(state) {
  const m = state?.manual || {}, errorTrace = m.lastError?.verificationTrace;
  if (!errorTrace && m.verificationResult?.mode && m.verificationResult.mode !== state?.mode) return null;
  if (!errorTrace && m.verificationResult?.phase && m.verificationResult.phase !== m.phase) return null;
  const trace = errorTrace || m.verificationResult?.verificationTrace;
  if (trace?.profile !== 'dbac-payment') return null;
  // A trace from a previous phase must not label this phase as rejected.
  const recordedPhases = (Array.isArray(trace?.steps) ? trace.steps : []).flatMap(step => (Array.isArray(step?.evidence) ? step.evidence : []).flatMap(row => {
    if (!Array.isArray(row?.observed)) return [];
    if (step.id === 'scope' && row.label === 'method / scope / phase') return [row.observed[2]];
    if (step.id === 'execution' && row.label === 'phase / resulting task') return [row.observed[0]];
    return [];
  })).filter(phase => phases.includes(phase));
  return recordedPhases.some(phase => phase !== m.phase) ? null : trace;
}
function proofDetail(m, plan) {
  if (m.walletSigningUnconfirmed) return '已请求钱包签名，但结果尚未确认。保留原订单核对，不把未知签名当作已完成，也不推进最终结算。';
  if (m.phase === 'settle') return '正在为已签付款材料准备结算阶段的新挑战与双方证明；这是新的请求证明，尚不代表最终验证通过或付款完成。';
  if (m.walletSigned) return '钱包已返回原订单付款材料；接下来仍需新结算挑战及新的双方证明，签名本身不转账。';
  if (m.phase === 'authorize') {
    const detail = { CHALLENGE_READY: '准备本阶段的派生凭证与双方证明。', VC_DERIVED: '派生凭证已返回，等待设备参与。', DEVICE_SIGNED: '设备贡献已返回，等待持有者核验并组合。', PROOF_READY: '本阶段证明已准备，仍需提交付款前核验。', VERIFIED: '付款前核验记录已返回，钱包尚需单独签署材料。' }[m.stage];
    return `付款前复核：${detail || '核对当前请求与用户批准的订单。'}后续结算阶段还会重新取得挑战并生成证明。`;
  }
  return plan?.id === 'wallet-sign' ? '付款前复核已返回，下一步由钱包独立核验并签署本笔材料；之后仍需新的结算证明。' : '用户授权后，依次进行付款前复核、钱包签名和结算证明准备；每个请求阶段使用各自的新挑战。';
}

/** currentIndex is zero-based; currentStep is its display-friendly 1–4 value. */
export function guideProgress(state, suppliedPlan, { now = Date.now(), uncertain = false } = {}) {
  const plan = suppliedPlan || planPayment(state, { now });
  const m = state?.manual || {}, available = state?.available === true;
  const credential = available && Boolean(state.credential);
  const proposalMatches = available && sameOrder(state.proposal?.payment, state.order);
  const approved = proposalMatches && state.proposal?.status === 'APPROVED' && Boolean(state.authorization);
  const deadline = Number.isFinite(m.expiresAtUnix) ? m.expiresAtUnix * 1000 : null;
  const expired = m.active === true && (m.expired === true || m.stage === 'EXPIRED' || deadline !== null && deadline <= now);
  const receipt = available ? matchingReceipt(state) : null;
  const walletUnknown = m.walletSigningUnconfirmed === true;
  const pendingUnknown = state?.paymentPending === true && m.walletSigned !== true && m.settled !== true;
  const receiptConflict = walletUnknown || state?.paymentPending === true && m.settled !== true;
  const settled = Boolean(guidePaymentReceipt(state, { uncertain }));
  const proofReady = available && !uncertain && !walletUnknown && !pendingUnknown && credential && approved
    && !expired && m.active === true && m.phase === 'settle' && m.stage === 'PROOF_READY'
    && m.walletSigned === true && Boolean(m.presentation && m.verifiableCredential && m.deviceResponse && m.holderProof)
    && m.availableActions?.includes('verify') === true && plan.id === 'verify' && plan.enabled === true;
  const steps = [
    { id: 'credential', title: '签发凭证', status: credential ? 'pass' : 'pending', detail: credential ? '后端已返回当前凭证；已签发不等于本次使用有效，后续仍要核验时效与撤销状态。' : '尚未取得当前凭证材料。' },
    { id: 'transaction', title: '资格认证与用户授权', status: approved ? 'pass' : 'pending', detail: approved ? '用户已明确批准并同步本订单授权；批准本身不会付款。' : '先为资格认证生成并验证本次双方证明，再提交订单由用户明确批准；资格认证通过只是业务前置。' },
    { id: 'proof', title: '付款复核与结算证明', status: settled || proofReady ? 'pass' : 'pending', detail: settled ? '本订单已返回结算回执；本段表示流程已完成，不代替各阶段的独立验签记录。' : proofReady ? '结算证明材料已齐备，后端允许提交；材料已生成不等于验证通过，下一步仍须明确执行最终验证。' : proofDetail(m, plan) },
    { id: 'result', title: '结算验证与回执', status: settled ? 'pass' : 'pending', detail: settled ? '已取得金额、币种、收付账户及结算条款均匹配当前订单的真实模拟支付回执。' : '只有最终结算提交返回匹配当前订单的实际回执，才显示本段完成；不使用场景预期作为结论。' },
  ];
  let currentIndex = !available ? 0 : walletUnknown || pendingUnknown ? 2 : settled || m.settled || receipt || proofReady ? 3
    : approved || m.walletSigned || ['authorize', 'settle'].includes(m.phase) ? 2 : credential ? 1 : 0;
  const verdict = verificationVerdict(currentTrace(state), { phase: m.phase });
  let rejection = '';
  if (!settled && available && !uncertain && !walletUnknown && !pendingUnknown) {
    if (proposalMatches && state.proposal?.status === 'REJECTED' && !m.walletSigned) {
      steps[1].status = 'fail'; steps[1].detail = '用户已实际拒绝本笔付款授权，不能继续付款；结束或重开只按原有后端规则执行。'; currentIndex = 1;
    } else if (verdict.status === 'fail' && phases.includes(m.phase)) {
      const failedIndex = { proposal: 1, authorize: 2, settle: 3 }[m.phase];
      steps[failedIndex].status = 'fail'; steps[failedIndex].detail = verdict.detail; rejection = verdict.detail;
      currentIndex = failedIndex;
    }
  }
  if (steps[currentIndex].status === 'pending') steps[currentIndex].status = 'current';
  let phaseLabel = ['凭证准备', '交易资格与用户授权', m.phase === 'settle' ? '结算证明准备' : m.walletSigned ? '钱包材料已返回，等待结算证明' : '付款前复核与证明准备', settled ? '本笔模拟支付已完成' : '最终结算验证与回执'][currentIndex];
  let detail = steps[currentIndex].detail;
  if (!available) detail = '尚未取得可用后端状态；四段总览不表示任何协议步骤已经执行。';
  else if (walletUnknown) { phaseLabel = '钱包签名结果待确认'; detail = proofDetail(m, plan); }
  else if (pendingUnknown) { phaseLabel = '原订单付款状态待确认'; detail = '后端仍标记付款待确认，且没有可继续结算的已确认钱包材料。保留原订单核对，不能从总览跳过签名保护。'; }
  else if (uncertain || receipt && receiptConflict) { phaseLabel = '原操作结果待核对'; detail = '通信或后端状态仍有待确认项。即使保留着旧材料，也不能宣布本次流程已完成；请核对原订单。'; }
  else if (m.settled && !receipt) { phaseLabel = '结算回执尚待核对'; detail = '后端标记已结算，但尚无金额、账户及结算条款匹配的当前订单回执，不能显示付款完成。'; }
  else if (expired && currentIndex >= 1 && currentIndex <= 2) detail = `本阶段挑战或验证证据已过期，需要按当前下一步取得新挑战并重新生成材料。${steps[currentIndex].detail}`;
  else if (rejection) detail = `${rejection} ${plan.reason || '后续操作仍以原有后端允许动作为准。'}`;
  else if (plan.reason && !settled) detail = `${plan.reason} ${detail}`;
  return { steps, currentIndex, currentStep: currentIndex + 1, total: 4, phaseLabel, detail };
}
