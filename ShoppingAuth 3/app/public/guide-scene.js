import { planPayment, verificationVerdict } from './guide-model.js';
import { guidePaymentReceipt, guideProgress } from './guide-progress.js';
import { currentStepPanel, currentVerificationTrace } from './guide-step-detail.js';

// Read-only projections of returned public records. This module has no API,
// storage, timers, protocol transitions or authority to advance a payment.
const modes = new Set(['bbs-bls', 'bbs-blind-bls']);
const phases = new Set(['proposal', 'authorize', 'settle']);
const text = value => typeof value === 'string' && value.length > 0;
const scalar = value => text(value) || typeof value === 'number' && Number.isFinite(value) ? String(value) : '未返回';
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const statuses = { pending: '尚未开始', running: '处理中', material: '材料已生成', pass: '验证通过', fail: '请求被拒绝', skipped: '未执行', na: '不适用', unknown: '结果待核对' };
const symbols = { pending: '○', running: '◌', material: '◇', pass: '✓', fail: '×', skipped: '—', na: '—', unknown: '?' };
const phaseNames = { proposal: '资格认证', authorize: '付款前复核', settle: '结算验证' };
// Hub layout: A is the centre that requests credentials, device contributions,
// verification and owner decisions; the other roles sit on the outer ring.
const positions = {
  issuer: [122, 83], holder: [380, 230], device: [638, 83],
  verifier: [638, 230], owner: [122, 377], ledger: [638, 377], attacker: [380, 377],
};
const roles = [
  ['issuer', '凭证签发方', 'Issuer · 签发测试凭证', 'credential'],
  ['holder', '持有者智能体 A', '准备材料 · 独立请求签名', 'holder'],
  ['device', '软件模拟 eSIM', '只提供本次设备贡献', 'device'],
  ['verifier', '验证者智能体 B', '分别核验并返回结论', 'verification'],
  ['owner', 'Owner', '逐笔批准或拒绝授权', 'owner'],
  ['ledger', '本地测试账本', 'TEST_USDC · 无真实资金价值', 'receipt'],
];
const nodesFor = scenario => [...roles, ...(scenario === 'copied-vc' ? [['attacker', '复制凭证的攻击者', '无 A 私钥 · 无原设备权限', 'experiment']] : [])]
  .map(([id, title, role, evidence]) => ({ id, title, role, evidence: scenario === 'normal' ? evidence : 'experiment', state: 'pending', label: '尚未参与', detail: '', active: false, position: positions[id] }));
function set(nodes, id, state, label, detail = '') { Object.assign(nodes.find(node => node.id === id), { state, label, detail }); }
const message = (from, to, label, state, evidence, detail = '') => ({ id: `${from}-${to}`, from, to, label, state, evidence, detail });
const fact = (label, value) => ({ label, value: scalar(value) });
function money(order) {
  if (!Number.isSafeInteger(order?.amountMinor) || order.amountMinor <= 0 || !text(order.currency)) return '尚未准备';
  return order.currency === 'TEST_USDC' ? `${(order.amountMinor / 1_000_000).toLocaleString('zh-CN', { maximumFractionDigits: 6 })} TEST_USDC` : `${order.amountMinor} ${order.currency}（最小单位）`;
}
function sameOrder(candidate, order) {
  return text(order?.orderId) && ['orderId', 'currency', 'payerAccount', 'payeeAccount'].every(key => text(order[key]) && candidate?.[key] === order[key])
    && Number.isSafeInteger(order.amountMinor) && candidate.amountMinor === order.amountMinor
    && ['network', 'asset', 'payerAddress', 'payTo'].every(key => text(order.settlement?.[key]) && candidate.settlement?.[key] === order.settlement[key]);
}
function currentAttempt(state, mode, detail, now) {
  const m = state?.manual || {}, c = m.challenge;
  return state?.available === true && state.mode === mode && modes.has(mode) && text(state.order?.orderId)
    && m.active === true && text(m.attemptId) && phases.has(m.phase) && text(c?.challengeId)
    && c.mode === mode && c.paymentOrderId === state.order.orderId
    && (!detail?.phase || detail.phase === m.phase) && !detail?.starting
    && !m.expired && !['EXPIRED', 'DISCARDED'].includes(m.stage)
    && !(Number.isFinite(m.expiresAtUnix) && m.expiresAtUnix * 1000 <= now);
}
function associatedTrace(state, eligible) {
  if (!eligible) return null;
  const m = state.manual, result = m.verificationResult;
  // Successful responses expose their exact sent context. Do not recover a
  // trace from lastResult or from a neighbouring log entry.
  if (!m.lastError?.verificationTrace && (result?.mode !== state.mode || result?.phase !== m.phase
    || result?.wire?.context?.challengeId !== m.challenge.challengeId
    || result?.wire?.context?.paymentOrderId !== state.order.orderId)) return null;
  return currentVerificationTrace(state);
}
function projectNormal(options) {
  const { mode, busy = false, uncertain = false, actionId = '', now } = options;
  const selected = options.state?.mode === mode && modes.has(mode) ? options.state : null;
  const state = selected?.available === true ? selected : null, m = state?.manual || {}, nodes = nodesFor('normal');
  const plan = options.plan || planPayment(state, { now }), progress = guideProgress(state, plan, { now, uncertain });
  // Match the same current-step projection as the command panel. In
  // particular, begin-authorize/begin-settle must not borrow old materials.
  const detail = options.detail || currentStepPanel(state, { plan, action: actionId, uncertain, complete: Boolean(guidePaymentReceipt(state, { uncertain })) });
  const phase = detail?.phase || m.phase, starting = detail?.starting || /^begin-/.test(actionId);
  const eligible = !uncertain && !starting && currentAttempt(state, mode, detail, now);
  const request = eligible ? m.deviceRequest : null, response = eligible ? m.deviceResponse : null;
  const blind = mode === 'bbs-blind-bls';
  const requestReady = request?.mode === mode && (blind ? text(request.blindedPoint)
    : text(request.randomizedDevicePublicKey) && request.context?.challengeId === m.challenge?.challengeId
      && request.context?.bodyHash === m.challenge?.bodyHash && request.context?.w3cPresentationHash === m.cryptography?.w3cPresentationHash);
  const deviceReady = requestReady && response?.mode === mode && text(response.signature);
  const derived = eligible && Boolean(m.verifiableCredential);
  const combined = deviceReady && text(m.holderProof) && text(m.presentation?.deviceSignature)
    && ['PROOF_READY', 'VERIFIED', 'OWNER_SUBMITTED', 'WALLET_SIGNED', 'SETTLED'].includes(m.stage);
  const trace = !actionId ? associatedTrace(state, eligible) : null;
  const verdict = verificationVerdict(trace, { phase: m.phase });
  const payment = state ? guidePaymentReceipt(state, { uncertain }) : null;
  const receipt = payment ? { amount: money(payment.receipt), orderId: payment.receipt.orderId, payer: payment.receipt.payerAccount,
    payee: payment.receipt.payeeAccount, transactionHash: scalar(payment.receipt.transactionHash), network: payment.receipt.settlement.network,
    asset: payment.receipt.settlement.asset, outcome: payment.outcome } : null;
  const proposal = sameOrder(state?.proposal?.payment, state?.order) && state?.proposal?.mode === mode ? state.proposal : null;
  const authorized = proposal?.status === 'APPROVED' && sameOrder(state?.authorization?.document?.payment, state?.order);
  const deviceService = m.device?.available === true ? '软件服务已连接；连接不表示本次证明通过。' : m.device?.available === false ? '软件设备服务不可用。' : '设备服务状态待读取。';
  set(nodes, 'issuer', state?.credential ? 'material' : 'pending', state?.credential ? '凭证与绑定材料已返回' : '尚未取得凭证', '签发材料的存在不代替本次使用验证。');
  set(nodes, 'holder', combined ? 'material' : derived ? 'material' : 'pending', combined ? '本轮组合证明已生成' : derived ? '本轮 BBS 派生材料已生成' : state?.credential ? '持有当前公开凭证' : '等待凭证材料', combined ? `${blind ? '本地去盲、' : ''}核验并适配设备贡献；另附独立请求签名。` : 'A 本地准备材料；尚未提交不表示已通过。');
  set(nodes, 'device', deviceReady ? 'material' : m.device?.available === false ? 'unknown' : 'pending', deviceReady ? '本轮贡献已返回 A' : m.device?.available === false ? '服务不可用' : '等待本轮调用', deviceService);
  set(nodes, 'verifier', trace ? verdict.status === 'pending' ? 'unknown' : verdict.status : 'pending', trace ? verdict.status === 'pass' ? `${phaseNames[m.phase]}通过` : verdict.status === 'fail' ? '本次请求被拒绝' : '本轮结论待核对' : '等待本轮证明', trace ? verdict.detail : '持有者签名与设备贡献分别核验。');
  set(nodes, 'owner', authorized ? 'material' : proposal?.status === 'REJECTED' ? 'fail' : 'pending', authorized ? '本笔授权已批准并同步' : proposal?.status === 'REJECTED' ? '本笔授权已拒绝' : proposal?.status === 'APPROVED' ? '已批准 · 待同步' : proposal?.status === 'PENDING' ? '等待批准或拒绝' : '尚未申请授权', '批准授权尚不执行付款。');
  set(nodes, 'ledger', receipt ? 'pass' : m.walletSigningUnconfirmed || uncertain || m.settled ? 'unknown' : 'pending', receipt ? '本笔测试支付已完成' : !state ? '当前状态待读取' : m.walletSigningUnconfirmed || uncertain || m.settled ? '原订单结果待核对' : m.walletSigned ? '钱包材料已签署 · 尚未结算' : '尚未执行本笔付款', '只有匹配本订单及条款的实际成功回执才表示付款完成。');

  let messages = [], caption = blind ? '盲化模式：设备输入为 blindedPoint 等公开协议字段；明文挑战与正文摘要属于 A 本地材料。' : '普通模式：A 向设备发送绑定本次挑战、正文摘要及派生 VC 摘要的公开输入。';
  if (uncertain) caption = state ? '原操作结果待核对；请读取原订单状态。客户端通信中断不表示服务端操作已取消。' : '当前业务状态待读取；取得服务状态后再显示本轮角色参与与实际结论。';
  else if (m.expired || m.stage === 'EXPIRED' || Number.isFinite(m.expiresAtUnix) && m.expiresAtUnix * 1000 <= now) caption = '本阶段挑战或验证证据已过期；需要用户明确取得新挑战，旧材料不表示本轮验证通过。';
  else if (state && m.attemptId && !eligible && !starting && !receipt) caption = '当前模式、订单、阶段或挑战的材料关联尚未确认；不会沿用其他上下文的结果。';
  const running = busy && text(actionId) && !uncertain;
  if (running) {
    const direction = actionId === 'issue' ? ['holder', 'issuer', '签发请求处理中', 'credential']
      : actionId.startsWith('begin-') ? ['holder', 'verifier', '新挑战请求处理中', 'verification']
        : actionId === 'device-sign' ? ['holder', 'device', blind ? '盲化请求处理中' : '设备请求处理中', 'device']
          : actionId === 'verify' ? ['holder', 'verifier', phase === 'settle' ? '结算请求处理中' : '证明请求处理中', 'verification']
            : ['submit-owner', 'sync-owner'].includes(actionId) ? ['holder', 'owner', '授权请求处理中', 'owner'] : null;
    if (direction) messages = [message(...direction.slice(0, 3), 'running', direction[3], '等待本次接口返回，不表示内部检查已完成。')];
    const id = actionId === 'issue' ? 'issuer' : actionId === 'device-sign' ? 'device' : actionId === 'verify' ? 'verifier' : ['submit-owner', 'sync-owner', 'owner-review'].includes(actionId) ? 'owner' : 'holder';
    set(nodes, id, 'running', actionId === 'prove' ? 'A 本地核验并组合中' : actionId === 'wallet-sign' ? '等待独立钱包签名返回' : '请求处理中', '接口只提供整体请求状态；尚未返回实际结论。');
  } else if (receipt) {
    messages = [message('verifier', 'holder', '返回本笔成功回执', 'pass', 'receipt')];
  } else if (state && !uncertain) {
    if (['submit-owner', 'owner-review', 'sync-owner', 'begin-authorize'].includes(plan.id) && proposal) {
      messages = [message(proposal.status === 'PENDING' ? 'holder' : 'owner', proposal.status === 'PENDING' ? 'owner' : 'holder', proposal.status === 'PENDING' ? '本笔条款待决定' : proposal.status === 'REJECTED' ? '返回拒绝决定' : '返回批准决定', proposal.status === 'REJECTED' ? 'fail' : 'material', 'owner')];
    } else if (trace) {
      messages = [message('holder', 'verifier', `${phaseNames[m.phase]}材料已提交`, 'material', 'verification'), message('verifier', 'holder', verdict.status === 'fail' ? '返回实际拒绝' : verdict.status === 'pass' ? '返回本轮验证结论' : '结论待核对', verdict.status === 'pending' ? 'unknown' : verdict.status, 'verification')];
    } else if (eligible && combined) {
      messages = [message('device', 'holder', '贡献已返回 · A 已组合', 'material', 'holder', 'A 另附持有者请求签名，等待明确提交验证。')];
    } else if (deviceReady) {
      messages = [message('holder', 'device', blind ? '本轮盲化请求' : '本轮上下文输入', 'material', 'device'), message('device', 'holder', '返回设备贡献', 'material', 'device')];
    } else if (requestReady) caption += ' 输入已在 A 准备，尚未调用设备。';
    else if (eligible && m.challenge) messages = [message('verifier', 'holder', '本轮新挑战已返回', 'material', 'verification')];
    else if (state.credential && !m.attemptId) messages = [message('issuer', 'holder', '已返回凭证与绑定材料', 'material', 'credential')];
  }
  let activeIds = new Set(messages.flatMap(item => [item.from, item.to]));
  if (!activeIds.size) activeIds = new Set([plan.id === 'issue' ? 'issuer' : plan.id === 'device-sign' ? 'device' : plan.id === 'verify' ? 'verifier' : plan.id === 'owner-review' ? 'owner' : 'holder']);
  if (receipt || m.walletSigned || actionId === 'wallet-sign') activeIds.add('ledger');
  nodes.forEach(node => { node.active = activeIds.has(node.id); });
  const summaryStatus = !state ? 'unknown' : uncertain || m.walletSigningUnconfirmed || m.settled && !receipt ? 'unknown' : running ? 'running' : receipt ? 'pass' : trace && verdict.status === 'fail' ? 'fail' : 'pending';
  const key = ['normal', mode, state?.order?.orderId || '', m.attemptId || '', phase || '', m.challenge?.challengeId || ''].join(':');
  return { scenario: 'normal', mode, key, eventKey: [key, actionId, m.stage, receipt?.transactionHash, trace?.outcome].join(':'), nodes, messages, receipt, note: caption,
    summary: { title: receipt ? '本笔测试支付已完成' : '智能体发起一笔测试支付', status: summaryStatus,
      label: !state ? '业务状态待读取' : uncertain ? '结果待核对' : progress.phaseLabel, description: !state ? '尚未取得当前模式的可用服务状态。' : progress.detail,
      facts: [fact('本笔金额', state ? money(state.order) : '尚未准备'), fact('订单编号', state?.order?.orderId || '尚未准备'), fact('调用方 → 服务方', state?.order?.payerAccount && state?.order?.payeeAccount ? `${state.order.payerAccount} → ${state.order.payeeAccount}` : '待读取')] } };
}

const experimentChecks = ['w3c_bbs', 'vc_device_binding', 'holder_signature', 'device_pairing', 'knowledge', 'credential_pairing', 'challenge', 'replay', 'credential_status', 'consume'];
function tracePass(trace) {
  return trace?.source === 'agent-b' && trace.profile === 'dbac-payment' && trace.outcome === 'pass'
    && verificationVerdict(trace, { phase: 'proposal' }).status === 'pass'
    && experimentChecks.every(id => trace.steps?.filter(step => step.id === id && step.status === 'pass').length === 1)
    && new Set(trace.steps?.map(step => step.id)).size === trace.steps?.length
    && !trace.steps?.some(step => step.status === 'fail' || step.evidence?.some(row => row.match === false));
}
function projectExperiment({ scenario, mode, experiment, busy, uncertain }) {
  const nodes = nodesFor(scenario), copied = scenario === 'copied-vc';
  const context = experiment?.context, candidate = experiment?.record;
  const matching = text(context?.runId) && context.mode === mode && context.scenarioId === scenario
    && candidate?.mode === mode && candidate.scenarioId === scenario && text(candidate.id)
    && (!candidate.runId || candidate.runId === context.runId);
  const pending = Boolean(experiment?.pending || context?.pending), record = matching && !pending && !uncertain ? candidate : null;
  const trace = record?.verificationTrace, trusted = trace?.source === 'agent-b' && trace.profile === 'dbac-payment' && Array.isArray(trace.steps);
  const failures = trusted ? trace.steps.filter(step => step.status === 'fail' || step.status !== 'skipped' && step.evidence?.some(row => row.match === false)) : [];
  const failed = failures[0], unique = trusted && new Set(trace.steps.map(step => step.id)).size === trace.steps.length;
  const controlPassed = record?.control?.accepted === true && text(record.control.challengeId) && tracePass(record.control.verificationTrace);
  const requestKnown = text(record?.request?.challengeId) && record?.request?.authenticationRoundId === record.request.challengeId;
  const sameRequest = requestKnown && record.request.challengeId !== record.control?.challengeId;
  const rejected = Boolean(record?.completion === 'completed' && sameRequest && unique && record.requestRejected === true
    && record.authenticationIssued === false && record.actual !== 'ACCEPTED' && trace.outcome === 'fail' && failed
    && record.rejectionStage === failed.id && (!failed.code || failed.code === record.actual));
  const accepted = record?.completion === 'completed' && sameRequest && record.requestRejected === false && record.authenticationIssued === true && record.actual === 'ACCEPTED' && tracePass(trace);
  const effects = record?.sideEffects;
  const expectationMet = Boolean(controlPassed && rejected && record.expectationMet === true && record.actual === record.expected
    && effects?.before && effects?.after && effects.paymentExecutionDelta === 0 && effects.balancesUnchanged === true
    && !record.accessChecks?.some(check => check.actual !== 'DBAC_ACCESS_DENIED'));
  const status = pending && !experiment?.permissionBlocked ? 'running' : rejected ? 'fail' : accepted ? 'pass' : record || uncertain || experiment?.permissionBlocked || experiment?.terminalError || experiment?.notFound || candidate && !matching ? 'unknown' : 'pending';
  const label = pending ? experiment?.permissionBlocked ? '原实验结果待核对 · 权限未通过' : '实验执行中' : experiment?.notFound ? '原实验记录不可查询'
    : experiment?.terminalError ? '实验未完成' : rejected ? '本次请求被拒绝' : accepted ? '本次请求获得认证' : record || candidate ? '本轮结果待核对' : '尚未运行';
  const proof = record?.request?.proof;
  set(nodes, 'issuer', record?.revocation?.credential === 'experiment-only' ? 'material' : 'pending', record?.revocation?.credential === 'experiment-only' ? '实验专用凭证已撤销' : '实验专用凭证', '不撤销正常支付使用的凭证。');
  set(nodes, 'holder', controlPassed ? 'material' : 'pending', controlPassed ? '本轮合法控制组成立' : '合法控制组待读取', copied ? '合法控制组由 A 与原设备参与；攻击请求来自独立攻击者。' : '原持有者与原设备继续生成材料；撤销状态由签发方查询确认。');
  set(nodes, 'device', copied ? 'na' : text(proof?.deviceSignature) ? 'material' : 'pending', copied ? '攻击分支无原设备权限' : text(proof?.deviceSignature) ? '本轮材料携带设备贡献' : '原设备参与材料生成', copied ? '缺少调用能力是前提；实际拒绝位置由 B 本轮记录决定。' : '材料生成不等于本轮所有密码学检查通过。');
  set(nodes, 'verifier', rejected ? 'fail' : accepted ? 'pass' : record ? 'unknown' : 'pending', rejected ? `拒绝于 ${failed.title || failed.id}` : accepted ? '本次认证通过' : record ? '本轮结论待核对' : '等待本轮请求', rejected ? `${record.actual}；后续未执行检查不能写成失败或通过。` : '读取同一轮实验的实际 trace。');
  set(nodes, 'owner', 'na', '本场景不请求批准', '实验不进入 Owner 批准或钱包签名。');
  set(nodes, 'ledger', effects ? 'material' : 'pending', effects && Number.isFinite(effects.paymentExecutionDelta) ? `付款执行增量 ${effects.paymentExecutionDelta} 次` : '付款观察待读取', effects?.before && effects?.after ? effects.balancesUnchanged === true ? '本轮观察余额未变化；实验控制组可能增加设备调用记录。' : '本轮观察余额有变化或需核对。' : '是否变化以本轮前后账本观察为准。');
  if (copied) set(nodes, 'attacker', proof?.verifiableCredential ? 'material' : 'pending', proof?.verifiableCredential ? '标准 BBS 派生材料已生成' : '仅有合法公开 VC 副本', '拿到凭证文件，不等于获得使用资格。BBS 材料生成与 B 的独立检查分开。');
  let messages = [];
  if (record && requestKnown && trusted) {
    const actor = copied ? 'attacker' : 'holder';
    messages = [message(actor, 'verifier', copied ? '本轮复制冒用请求' : '撤销后新请求', 'material', 'experiment'), message('verifier', actor, rejected ? '实际返回拒绝' : accepted ? '实际返回认证' : '结果待核对', rejected ? 'fail' : accepted ? 'pass' : 'unknown', 'experiment')];
  }
  // The experiment endpoint exposes one overall operation; do not animate its
  // unseen internal control/derivation/revocation steps while waiting.
  const activeIds = new Set(pending ? ['holder', 'device', 'verifier', ...(copied ? ['attacker'] : ['issuer'])] : messages.flatMap(item => [item.from, item.to]));
  nodes.forEach(node => { node.active = activeIds.has(node.id); });
  const note = pending ? '实验执行中；接口仅返回完整实验结果，没有内部实时进度。'
    : record ? '本轮记录回看 · 只读记录。合法控制组与场景请求使用各自的新挑战；材料生成不代替独立验证。'
      : copied ? '实验前提：获得合法公开 VC；无 A 私钥，无原绑定设备秘密或调用权限。尚未运行不表示已拦截。'
        : '实验前提：撤销实验专用凭证，原持有者与原设备在新挑战下重新生成材料。尚未运行不表示已拦截。';
  const key = [scenario, mode, context?.mode === mode && context?.scenarioId === scenario ? context.runId : '', record?.id || ''].join(':');
  return { scenario, mode, key, eventKey: [key, pending, record?.completion, record?.actual].join(':'), nodes, messages, receipt: null, note,
    comparison: { control: controlPassed ? 'pass' : record?.control ? 'unknown' : 'pending', request: rejected ? 'fail' : accepted ? 'pass' : 'unknown', expectationMet,
      rejectionStage: rejected ? failed.id : null, code: record?.actual || null, skipped: trusted ? trace.steps.filter(step => step.status === 'skipped').map(step => ({ id: step.id, title: step.title || step.id })) : [],
      bbsMaterial: Boolean(proof?.verifiableCredential), holderMaterial: text(proof?.holderProof), deviceMaterial: text(proof?.deviceSignature) },
    summary: { title: copied ? '复制合法凭证后，攻击者能否冒用？' : '凭证已撤销，原持有者和设备还能使用吗？', status, label,
      description: pending ? '正在等待本轮完整记录；不会预先显示拦截成功。' : rejected ? `${failed.title || failed.id} · ${record.actual}` : experiment?.terminalError?.message || (record ? '本轮控制组、材料与检查记录需分别核对。' : copied ? '拿到凭证文件，不等于获得使用资格。' : '保留原持有者与原设备，核对可信凭证状态查询和实际拒绝点。'),
      facts: [fact('本轮实验', context?.mode === mode && context?.scenarioId === scenario ? context.runId : '尚未准备'), fact('场景前提', copied ? '公开 VC 副本 · 无 A 私钥及原设备权限' : '实验凭证已撤销后 · 原 A 与原设备'), fact('记录状态', label)] } };
}

export function deriveScene({ scenario = 'normal', mode = 'bbs-bls', now = Date.now(), ...options } = {}) {
  const selected = ['normal', 'copied-vc', 'revoked'].includes(scenario) ? scenario : 'normal';
  return selected === 'normal' ? projectNormal({ ...options, scenario: selected, mode, now }) : projectExperiment({ ...options, scenario: selected, mode, now });
}
export function buildScenePresentation(options = {}) { return deriveScene({ ...options, actionId: options.actionId || options.busyAction || '' }); }

const icons = {
  issuer: '<path d="M4 20V8l8-5 8 5v12M2 20h20M7 10v7m5-7v7m5-7v7"/>',
  holder: '<circle cx="12" cy="7" r="3"/><path d="M5 21v-4a7 7 0 0 1 14 0v4M8 21v-4m8 4v-4"/>',
  device: '<rect x="6" y="2" width="12" height="20" rx="2"/><path d="M9 6h6v8H9zM10 18h4"/>',
  verifier: '<path d="m12 2 8 4v6c0 5-8 10-8 10S4 17 4 12V6zM8 12l3 3 5-6"/>',
  owner: '<circle cx="9" cy="6" r="3"/><path d="M3 21v-5a6 6 0 0 1 10-4m2 4 2 2 5-5"/>',
  ledger: '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 7h8M8 11h8M8 15h3m3 0h2M8 18h3m3 0h2"/>',
  attacker: '<path d="m5 8 3-5h8l3 5M3 8h18M5 12l5 2m4 0 5-2M7 21v-3a5 5 0 0 1 10 0v3"/><circle cx="8" cy="12" r="2"/><circle cx="16" cy="12" r="2"/>',
};
const shortRoles = { issuer: '签发方', holder: 'A', device: '设备', verifier: 'B', owner: 'Owner', ledger: '账本', attacker: '攻击者' };
function renderWire(item, { path, x, y, width = 196, height = 34, label }) {
  return `<g class="scene-wire" data-state="${escape(item.state)}" data-from="${item.from}" data-to="${item.to}"><path d="${path}" marker-end="url(#scene-arrow)"/><foreignObject x="${x}" y="${y}" width="${width}" height="${height}" pointer-events="all"><button xmlns="http://www.w3.org/1999/xhtml" type="button" class="scene-message" data-scene-evidence="${escape(item.evidence)}">${escape(label)}</button></foreignObject></g>`;
}
const labelSlots = {
  top: { x: 282, y: 53, width: 196, height: 34 },
  topLow: { x: 282, y: 130, width: 196, height: 34 },
  left: { x: 47, y: 213, width: 196, height: 34 },
  midUp: { x: 461, y: 150, width: 96, height: 56 },
  midDown: { x: 461, y: 240, width: 96, height: 56 },
  attackUp: { x: 470, y: 300, width: 80, height: 54 },
  attackDown: { x: 470, y: 364, width: 80, height: 54 },
};
const routes = {
  'issuer->holder': { path: 'M210,83 H250 V230 H292', slot: 'left' },
  'holder->issuer': { path: 'M292,230 H250 V83 H210', slot: 'left' },
  'owner->holder': { path: 'M210,377 H250 V230 H292', slot: 'left' },
  'holder->owner': { path: 'M292,230 H250 V377 H210', slot: 'left' },
  'holder->device': { path: 'M380,162 V100 H520 V83 H550', slot: 'top' },
  'device->holder': { path: 'M550,83 H520 V120 H380 V162', slot: 'topLow' },
  'holder->verifier': { path: 'M468,230 H550', slot: 'midDown' },
  'verifier->holder': { path: 'M550,230 H520 V210 H468', slot: 'midUp' },
  'attacker->verifier': { path: 'M468,377 H500 V230 H550', slot: 'attackUp' },
  'verifier->attacker': { path: 'M550,230 H520 V377 H468', slot: 'attackDown' },
};
function wireLabel(item) {
  if (item.from === 'holder' && item.to === 'device') return `A → 设备：${item.label.includes('盲化') ? item.state === 'running' ? '盲化请求中' : '盲化请求' : item.state === 'running' ? '请求处理中' : '本轮输入'}`;
  if (item.from === 'device' && item.to === 'holder') return '设备 → A：贡献已返回';
  if (item.from === 'attacker' && item.to === 'verifier') return '攻击者 → B：冒用请求';
  if (item.from === 'verifier' && item.to === 'attacker') return `B → 攻击者：${item.state === 'fail' ? '拒绝' : item.state === 'pass' ? '认证' : '待核对'}`;
  if (item.from === 'holder' && item.to === 'verifier') {
    if (item.state === 'running') return 'A → B：提交中';
    if (item.label.includes('结算')) return 'A → B：结算证明';
    if (item.label.includes('付款前')) return 'A → B：付款复核';
    return 'A → B：资格证明';
  }
  if (item.from === 'verifier' && item.to === 'holder') {
    if (item.label.includes('挑战')) return 'B → A：新挑战';
    if (item.label.includes('回执')) return 'B → A：成功回执';
    if (item.state === 'pass') return 'B → A：验证通过';
    if (item.state === 'fail') return 'B → A：拒绝';
    return 'B → A：结论待核对';
  }
  if (item.from === 'issuer' && item.to === 'holder') return '签发方 → A：凭证已返回';
  if (item.from === 'holder' && item.to === 'issuer') return 'A → 签发方：请求签发';
  if (item.from === 'holder' && item.to === 'owner') return 'A → Owner：授权申请';
  if (item.from === 'owner' && item.to === 'holder') return item.label.includes('拒绝') ? 'Owner → A：拒绝' : 'Owner → A：批准';
  return `${shortRoles[item.from]} → ${shortRoles[item.to]} · ${item.label}`;
}
function wire(item) {
  if (!positions[item.from] || !positions[item.to] || item.from === item.to) return '';
  const route = routes[`${item.from}->${item.to}`];
  if (route) return renderWire(item, { path: route.path, ...labelSlots[route.slot], label: wireLabel(item) });
  // Defensive fallback for a future pair: route across the central empty lane.
  const [x1, y1] = positions[item.from], [x2, y2] = positions[item.to];
  const dx = x2 - x1, dy = y2 - y1, length = Math.hypot(dx, dy);
  if (!Number.isFinite(length) || length === 0) return '';
  const ux = dx / length, uy = dy / length;
  const gap = Math.min(96 / Math.abs(ux), 76 / Math.abs(uy));
  if (!Number.isFinite(gap) || gap * 2 >= length) return '';
  const from = [x1 + ux * gap, y1 + uy * gap], to = [x2 - ux * gap, y2 - uy * gap];
  const curve = -54;
  const cx = (x1 + x2) / 2 - dy / length * curve, cy = (y1 + y2) / 2 + dx / length * curve;
  const labelX = (from[0] + 2 * cx + to[0]) / 4, labelY = (from[1] + 2 * cy + to[1]) / 4;
  return renderWire(item, { path: `M${from.join(',')} Q${cx},${cy} ${to.join(',')}`, x: labelX - 98, y: labelY - 16, label: wireLabel(item) });
}
export function renderSceneSummary(model) {
  const value = model.summary;
  return `<section class="scene-summary" data-state="${escape(value.status)}"><div class="scene-summary-heading"><h2>${escape(value.title)}</h2><p><span class="scene-summary-status">${symbols[value.status] || '?'} ${escape(value.label)}</span></p></div><dl class="scene-summary-facts">${value.facts.map(row => `<div><dt>${escape(row.label)}</dt><dd title="${escape(row.value)}">${escape(row.value)}</dd></div>`).join('')}</dl></section>`;
}
export function renderSceneCanvas(model) {
  return `<section class="scene-canvas" data-scenario="${escape(model.scenario)}" data-mode="${escape(model.mode)}" aria-label="当前场景角色交互"><div class="scene-canvas-heading"><h3>本轮角色交互</h3><span>${model.scenario === 'normal' ? model.mode === 'bbs-blind-bls' ? '盲化 BLS' : '普通 BLS' : '实验完整返回后可回看记录'}</span></div><div class="scene-stage"><svg class="scene-wires" viewBox="0 0 760 460" preserveAspectRatio="none" role="group" aria-label="本轮消息方向，点击标签查看公开证据"><defs><marker id="scene-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 0 10 5 0 10Z"/></marker></defs>${model.messages.map(wire).join('')}</svg>${model.nodes.map(node => `<button type="button" class="scene-node" data-node="${node.id}" data-state="${escape(node.state)}" data-active="${node.active}" data-scene-evidence="${escape(node.evidence)}" aria-label="${escape(`${node.title}：${node.label}；查看公开证据`)}"><span class="scene-node-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${icons[node.id]}</svg></span><strong class="scene-node-title">${escape(node.title)}</strong><span class="scene-node-role">${escape(node.role)}</span><span class="scene-node-status">${symbols[node.state] || '?'} ${escape(node.label || statuses[node.state])}</span><span class="scene-node-detail">${escape(node.detail)}</span></button>`).join('')}</div><ol class="scene-messages-list" aria-label="本轮实际消息">${model.messages.map(item => `<li data-state="${escape(item.state)}"><button type="button" data-scene-evidence="${escape(item.evidence)}">${escape(model.nodes.find(node => node.id === item.from)?.title)} → ${escape(model.nodes.find(node => node.id === item.to)?.title)}：${escape(item.label)}</button></li>`).join('')}</ol><p class="scene-caption">${escape(model.note)}</p></section>`;
}
