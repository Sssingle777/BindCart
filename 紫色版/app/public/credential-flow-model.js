import { protocolSnapshot } from './protocol-model.js';

// Presentation planning only. Every operation is also checked by the backend.
const action = (id, label, enabled = false) => ({ id, label, enabled });
const available = (state, id) => state?.manual?.availableActions?.includes(id) === true;
export function flowBlockReason(state) {
  if (!state || state.available !== true) return '尚未取得可用状态，请刷新状态。';
  const m = state.manual || {};
  if (state.paymentPending || m.walletSigningUnconfirmed || m.walletSigned && !m.settled)
    return '当前模式原订单的钱包或结算结果尚待核对，请在支付应用中处理原订单；也可在演示设置中切换到另一模式独立测试。';
  if (m.phase && m.phase !== 'proposal' || state.proposal || m.ownerSubmitted || m.ownerApproved || m.settled)
    return '当前订单已进入模拟支付流程。请前往支付流程核对当前状态；也可在演示设置中切换到另一模式独立测试。';
  return '';
}
// Modes have separate orders and attempts. Reading another mode must not
// inherit the current order's authentication/payment mutation restrictions.
export function canSwitchMode(state) {
  return state?.available === true;
}
export function canStartRound(state) {
  return !flowBlockReason(state) && available(state, 'begin-proposal');
}
export function flowTiming(state, now = Date.now()) {
  const m = state?.manual || {};
  if (m.active !== true) return { expired: false, seconds: null, kind: '本次挑战' };
  const deadline = Number.isFinite(m.expiresAtUnix) ? m.expiresAtUnix * 1000 : null;
  const expired = Boolean(m.expired || m.stage === 'EXPIRED' || deadline !== null && deadline <= now);
  return { expired, seconds: deadline === null ? null : Math.max(0, Math.ceil((deadline - now) / 1000)),
    kind: m.verificationResult ? '验证证据' : '本次挑战' };
}
export function pendingDisclosureNote(snapshot) {
  if (snapshot?.active !== true) return snapshot?.stage === 'DISCARDED'
    ? '本次认证已结束；请先获取 B 的新挑战，再生成派生凭证。'
    : '准备凭证并取得 B 的挑战后，再生成本次出示内容。';
  if (snapshot.expired) return '原挑战已过期；请获取新挑战，再生成派生凭证。';
  return snapshot.challenge ? '已收到 B 的挑战；可生成本次派生凭证。'
    : '准备凭证并取得 B 的挑战后，再生成本次出示内容。';
}
export function nextFlowAction(state, view, scenario = 'normal', now = Date.now()) {
  if (flowBlockReason(state)) return action('blocked', '请先核对状态');
  const m = state.manual || {};
  if (!state.credential) return action('issue', '准备演示凭证', !m.active);
  const { expired } = flowTiming(state, now);
  if (!m.active || expired) return action('begin-proposal', expired ? '获取新挑战，重新开始' : '获取 B 的本次挑战', canStartRound(state));
  if (m.phase !== 'proposal') return action('blocked', '当前不是资格核验阶段');
  if (view === 'derive') {
    if (m.stage === 'CHALLENGE_READY') return action('derive-vc', '生成派生凭证', available(state, 'derive-vc'));
    if (m.verifiableCredential) return action('view:device', m.deviceResponse ? '查看设备签名材料' : '前往设备签名', true);
  }
  if (view === 'device') {
    if (m.stage === 'CHALLENGE_READY') return action('view:derive', '前往凭证披露', true);
    if (m.stage === 'VC_DERIVED') return action('device-sign', '请求设备签名', available(state, 'device-sign'));
    if (m.stage === 'DEVICE_SIGNED') return action('prove', '核验并组合证明', available(state, 'prove'));
    if (m.presentation) return action('view:verify', m.verificationResult ? '查看验证记录' : '前往验证', true);
  }
  if (view === 'verify') {
    if (scenario === 'missing') {
      if (m.stage === 'VERIFIED') return action('complete', '挑战已使用，需重新认证');
      if (m.verifiableCredential) return action('test-no-device', '提交缺设备证明请求', available(state, 'test-no-device'));
    }
    if (m.stage === 'VERIFIED') return action('complete', '本次验证已结束');
    if (m.stage === 'PROOF_READY') return action('verify', '提交验证', available(state, 'verify'));
    if (m.stage === 'CHALLENGE_READY') return action('view:derive', '前往凭证披露', true);
    if (m.verifiableCredential) return action('view:device', '前往设备签名', true);
  }
  return action('wait', '请刷新状态后继续');
}
export function initialView(state) {
  const m = state?.manual;
  if (['PROOF_READY', 'VERIFIED'].includes(m?.stage)) return 'verify';
  if (['VC_DERIVED', 'DEVICE_SIGNED'].includes(m?.stage)) return 'device';
  return 'derive';
}
export function flowSnapshot(state, scenario = 'normal') {
  const m = state?.manual || {};
  const attack = scenario === 'missing' && m.lastAttack?.action === 'test-no-device' ? m.lastAttack : null;
  const selected = scenario === 'missing'
    ? { ...m, lastAttack: attack, lastError: null, verificationResult: null }
    : { ...m, lastAttack: null };
  const snapshot = protocolSnapshot({ ...state, manual: selected });
  // An omitted proof is not the local proof that A may still possess.
  if (scenario === 'missing') snapshot.presentation = null;
  return { ...snapshot, scenario,
    expiresAtUnix: Number.isFinite(m.expiresAtUnix) ? m.expiresAtUnix : null,
    submitted: scenario === 'missing' ? Boolean(attack) : Boolean(m.verificationResult || m.lastError?.verificationTrace?.source === 'agent-b'),
    attackCode: typeof attack?.actual === 'string' ? attack.actual : null };
}
const groups = [
  ['context', '请求、挑战与调用范围', ['extension', 'envelope', 'challenge', 'replay', 'request_binding', 'policy_context', 'scope']],
  ['w3c', '标准 W3C BBS 派生证明', ['w3c_bbs']],
  ['status', '凭证来源与撤销状态', ['credential_status']],
  ['holder', '持有者秘密依赖证明', ['holder_signature']],
  ['binding', 'VC 与设备材料的绑定', ['vc_device_binding']],
  ['structure', '结构、披露与编码', ['schema', 'proof_structure', 'disclosure', 'proof_encoding']],
  ['knowledge', '知识证明', ['knowledge']],
  ['credential', '配套凭证配对', ['credential_pairing']],
  ['device', '设备贡献配对', ['device_pairing']],
  ['consume', '消费一次性挑战', ['consume']],
];
export function verificationRows(snapshot) {
  const trace = snapshot?.verificationTrace;
  return groups.map(([id, title, ids]) => {
    const steps = (trace?.steps || []).filter(step => ids.includes(step.id));
    let status = 'pending';
    if (trace?.source === 'agent-b') {
      const unique = ids.every(key => steps.filter(step => step.id === key).length === 1);
      if (steps.some(step => step.status === 'fail' || step.evidence?.some(row => row.match === false))) status = 'fail';
      else if (unique && steps.every(step => step.status === 'pass')) status = 'pass';
      else if (unique && steps.every(step => step.status === 'skipped')) status = 'skipped';
    }
    return { id, title, ids, status, steps, evidence: steps.flatMap(step => (step.evidence || []).map(row => ({ stepId: step.id, ...row }))) };
  });
}

/** Human-readable results remain conservative summaries of the B trace. */
export function verificationConclusion(snapshot) {
  const rows = verificationRows(snapshot), trace = snapshot?.verificationTrace;
  if (!trace) return snapshot?.submitted
    ? { kind: 'pending', title: '暂未取得验证结果', detail: '已尝试提交，尚未取得验证者 B 的逐项记录。请刷新状态核对。' }
    : { kind: 'idle', title: '尚未提交验证', detail: '当前显示检查条件，尚无本次判定。请准备完整证明或选择缺设备对照，再提交验证。' };
  if (trace.source !== 'agent-b') return { kind: 'pending', title: '暂未取得验证结果', detail: '请求准备或通信异常不能视为 B 已通过或拒绝。' };
  const failedSteps = (trace.steps || []).filter(step => step.status === 'fail'
    || step.evidence?.some(row => row.match === false));
  if (snapshot.phase === 'proposal' && trace.outcome === 'pass' && !failedSteps.length && rows.every(r => r.status === 'pass'))
    return { kind: 'success', title: '本次凭证使用资格验证通过', detail: '本次必要认证检查全部通过，一次性挑战已消费。可进入付款授权；认证通过不等于用户授权，用户批准不等于支付完成。' };
  const get = id => rows.find(r => r.id === id);
  const binding = get('binding');
  const missingCode = snapshot.attackCode === 'W3C_DEVICE_PROOF_REQUIRED' || snapshot.error?.code === 'W3C_DEVICE_PROOF_REQUIRED'
    || binding.steps.some(step => step.code === 'W3C_DEVICE_PROOF_REQUIRED');
  if (snapshot.phase === 'proposal' && snapshot.scenario === 'missing' && trace.outcome === 'fail'
    && get('context').status === 'pass' && get('w3c').status === 'pass'
    && binding.steps.length === 1 && binding.steps[0].status === 'fail' && missingCode
    && failedSteps.every(step => step.id === 'vc_device_binding')
    && ['structure', 'knowledge', 'credential', 'device', 'consume'].every(id => get(id).status === 'skipped'))
    return { kind: 'failure', title: '使用资格验证未通过：凭证证明通过，但缺少必要的设备证明', detail: '拒绝位置：VC 与设备材料绑定（W3C_DEVICE_PROOF_REQUIRED）。后续知识证明与配对检查未执行。' };
  if (failedSteps.length || rows.some(r => r.status === 'fail')) return { kind: 'failure', title: '本次凭证使用资格验证未通过',
    detail: `实际记录包含失败或不一致：${failedSteps.find(step => step.code)?.code || snapshot.attackCode || snapshot.error?.code || rows.find(r => r.status === 'fail')?.title || failedSteps[0].title || failedSteps[0].id}。请查看对应检查依据。` };
  return { kind: 'pending', title: '核验记录尚不完整', detail: '记录缺失、重复或结论不一致，不能宣布全部通过。' };
}

/** Banner only reads this live attempt, never stored history or an earlier order result. */
export function currentRejectionNotice(state) {
  const snapshot=flowSnapshot(state);
  if (snapshot.active!==true || !snapshot.submitted || snapshot.verificationTrace?.source!=='agent-b'
    || snapshot.verificationTrace.outcome!=='fail' || verificationConclusion(snapshot).kind!=='failure') return null;
  return { title:'本次凭证使用资格验证未通过', detail:'请查看本轮拒绝依据与错误码；需要重新认证时，获取新挑战并重新生成证明。' };
}

export function flowProgress(state) {
  const m = state?.manual || {}, verdict = verificationConclusion(flowSnapshot(state));
  return {
    derive: { done: Boolean(m.verifiableCredential), label: m.verifiableCredential ? '已生成' : '尚未生成' },
    device: { done: Boolean(m.presentation), label: m.presentation ? '已组合' : m.deviceResponse ? '设备贡献已生成，待组合证明' : '尚未取得设备贡献' },
    verify: { done: verdict.kind === 'success', label: verdict.kind === 'success' ? '已核验通过' : verdict.kind === 'failure' ? '未通过' : m.verificationResult ? '结果待核对' : '尚未提交' },
  };
}
