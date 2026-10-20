import { renderCheckPreview } from './guide-stage-ui.js';
import { renderVerificationChecks, verificationEvidenceModel } from './guide-evidence.js';

const RUNS_ENDPOINT = '/api/dbac/payment/experiment-runs';
const PENDING_KEY = 'a2a-guide-experiment-pending-v1';
const RECENT_KEY = 'a2a-guide-experiment-recent-v1';
const SCENARIOS = new Set(['copied-vc', 'revoked']);
const MODES = new Set(['bbs-bls', 'bbs-blind-bls']);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const escape = value => String(value ?? '—').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
const definitions = [
  ['credential', '凭证来源与真实性', ['w3c_bbs'], '标准 BBS 派生证明由验证者 B 核验。'],
  ['proofs', '持有者与设备的本次证明', ['vc_device_binding', 'holder_signature', 'device_pairing', 'knowledge', 'credential_pairing'], '查看两方材料、绑定关系和配套证明的实际检查。'],
  ['status', '本次挑战与凭证状态', ['challenge', 'replay', 'credential_status', 'consume'], '核对新鲜性、撤销状态与挑战消费，未运行的检查保留为未执行。'],
];

function groupStatus(trace, ids) {
  if (trace?.source !== 'agent-b' || !Array.isArray(trace.steps)) return 'pending';
  const steps = trace.steps.filter(step => ids.includes(step.id));
  if (steps.some(step => step.status === 'fail' || step.evidence?.some(row => row.match === false))) return 'fail';
  if (!ids.every(id => steps.filter(step => step.id === id).length === 1)) return 'pending';
  if (steps.every(step => step.status === 'pass')) return 'pass';
  if (steps.every(step => step.status === 'skipped')) return 'skipped';
  return 'pending';
}

// Summaries describe the returned B trace. A scenario name or expected code
// cannot turn an incomplete, contradictory or missing trace into a verdict.
export function experimentSummary(record) {
  const trace = record?.verificationTrace;
  const groups = definitions.map(([id, title, ids, detail]) => ({ id, title, ids, detail, status: groupStatus(trace, ids) }));
  const steps = Array.isArray(trace?.steps) ? trace.steps : [];
  const failed = steps.find(step => step.status === 'fail');
  const disagreement = steps.some(step => step.evidence?.some(row => row.match === false));
  let state = 'pending', title = record ? '本次结果尚未完整确认' : '尚未运行本场景';
  let detail = record ? '缺少完整、相符的验证记录；这不代表已通过或已拦截。' : '点击运行后，才会显示本次后端判定。';
  if (record?.completion === 'completed' && trace?.source === 'agent-b') {
    if (record.requestRejected === true && record.authenticationIssued === false
      && record.actual !== 'ACCEPTED' && trace.outcome === 'fail' && failed) {
      state = 'fail'; title = '本次请求已被验证者 B 拒绝';
      detail = `${failed.title || failed.id}：${record.error?.message || failed.detail || '请查看本次拒绝依据。'}`;
    } else if (record.authenticationIssued === true && record.requestRejected === false
      && record.actual === 'ACCEPTED' && trace.outcome === 'pass' && !failed && !disagreement
      && groups.every(group => group.status === 'pass')) {
      state = 'pass'; title = '本次请求通过了认证';
      detail = '这是本次实际返回；请继续核对它是否符合所选场景预期。认证通过不等于用户批准或模拟付款完成。';
    }
  }
  const contradictory = trace?.source === 'agent-b' && (
    trace.outcome === 'pass' && (failed || disagreement || record?.requestRejected === true)
    || trace.outcome === 'fail' && (record?.authenticationIssued === true || record?.actual === 'ACCEPTED')
  );
  if (contradictory) {
    state = 'pending'; title = '结果异常：整体结论与逐项记录不一致';
    detail = `后端整体结果：${trace.outcome === 'pass' ? '通过' : '未通过'}；请核对保留的失败项与实际返回码，不能据此宣布通过或拦截成功。`;
  }
  if (record?.completion === 'incomplete') {
    const failure = record.error || record.cleanupError || record.observationError;
    const stopped = record.request ? '场景请求或结果核对' : record.control ? '场景材料准备' : '合法控制组或前置准备';
    title = `实验未完成 · 停在${stopped}`;
    detail = `${failure?.message || '尚不能确认安全验证结论。'}${record.rejectionStage ? `；已记录检查位置：${record.rejectionStage}` : ''}。这不是已确认的冒用拦截。`;
  }
  return { state, title, detail, groups, failed, trace };
}

// This comparison is presentation only. Materials and B's independent checks
// keep different states; a scenario name never supplies a result.
export function experimentDeviceContrast(record, { scenarioId = record?.scenarioId || 'copied-vc', pending = false } = {}) {
  const copied = scenarioId === 'copied-vc';
  const active = pending || record?.scenarioId !== scenarioId ? null : record;
  const trace = active?.request ? active.verificationTrace : null;
  const rawSteps = Array.isArray(trace?.steps) ? trace.steps : [];
  const check = (id, title) => {
    const model = verificationEvidenceModel(trace, { phase: 'proposal', ids: [id] });
    const step = model.steps.find(value => value.id === id);
    const actual = rawSteps.filter(value => value.id === id);
    const reliable = model.trusted && actual.length === 1 && step?.reportedStatus === step?.status
      && ['pass', 'fail', 'skipped'].includes(step?.status);
    const state = reliable ? step.status : active ? 'unknown' : 'pending';
    const status = ({ pass: '通过', fail: '不通过', skipped: '未执行', unknown: '未确认', pending: pending ? '等待本轮记录' : '待运行' })[state];
    const detail = reliable ? `来源：本轮验证者 B · ${id}${step.code ? ` · ${step.code}` : ''}`
      : active ? '没有唯一且一致的本轮独立检查结论。' : '运行后读取本轮验证者 B 的实际检查状态。';
    return { id, title, state, status, detail };
  };
  const rows = copied ? [check('w3c_bbs', '标准 BBS 派生证明'), check('vc_device_binding', 'VC 与模拟 eSIM 绑定')]
    : [check('device_pairing', '模拟 eSIM 本次贡献配对'), check('credential_status', '签发方凭证状态')];
  const proofsVerified = !copied && rows[0].state === 'pass' && check('holder_signature', '').state === 'pass'
    && check('vc_device_binding', '').state === 'pass';
  const summary = experimentSummary(active);
  let conclusion = active ? '本轮对照记录尚未完整确认，请核对下方实际检查与错误原因。'
    : pending ? '正在等待本轮结果，不预判派生证明、设备绑定或凭证状态。' : '运行后在此对照本轮材料与验证者 B 的实际检查，不预先显示通过或拒绝。';
  if (active?.completion === 'incomplete') conclusion = '实验未完整结束；已有记录仅供核对，不能作为冒用或撤销拦截成功的结论。';
  else if (active && summary.state === 'pending') conclusion = '本轮结果缺失或存在矛盾，不能确认拦截成功；以下保留已返回的独立状态。';
  else if (summary.state === 'fail' && copied && rows[0].state === 'pass' && rows[1].state === 'fail')
    conclusion = '本轮标准 BBS 派生证明通过，VC 与模拟 eSIM 绑定检查不通过；公开 VC 副本未满足本次联合验证。';
  else if (summary.state === 'fail' && !copied && rows[1].state === 'fail') {
    conclusion = proofsVerified && active.actual === 'W3C_CREDENTIAL_REVOKED'
      ? '本轮原设备贡献、VC 设备绑定与持有者 A 签名均通过，仍在凭证撤销状态检查处被拒绝；设备参与不能绕过撤销。'
      : active.actual === 'W3C_CREDENTIAL_REVOKED' ? '验证者 B 返回了凭证撤销拒绝；但设备绑定、设备贡献与持有者 A 签名未全部确认通过，不能补写证明对照。'
        : '本轮停在凭证状态检查；具体原因以下方返回码为准，不能把任意状态查询失败说成凭证已撤销。';
  } else if (summary.state === 'pass') conclusion = '本轮实际认证结果为通过；对照采用实际返回状态，不能改写成预期拒绝。';
  return { title: copied ? '本轮对照：公开 VC 与原设备参与' : '本轮对照：设备参与与凭证撤销', rows, conclusion,
    boundary: copied ? '攻击者既无持有者 A 私钥，也无原设备调用权限；本实验不能证明模拟 eSIM 单独抵御持有者 A 私钥失窃。'
      : '设备参与证明与凭证有效状态分别核验；模拟 eSIM 为软件仿真。' };
}

function renderDeviceContrast(record, options) {
  const model = experimentDeviceContrast(record, options);
  return `<section class="guide-device-contrast" aria-label="模拟 eSIM 本轮对照"><h4>${escape(model.title)}</h4><dl class="guide-device-contrast-grid">${model.rows.map(row => `<div data-contrast-id="${escape(row.id)}" data-state="${row.state}"><dt>${escape(row.title)}</dt><dd><strong><span aria-hidden="true">${statusIcons[row.state] || '?'}</span> ${escape(row.status)}</strong><small>${escape(row.detail)}</small></dd></div>`).join('')}</dl><p class="guide-device-contrast-note">${escape(model.conclusion)}</p><p class="guide-device-contrast-boundary">${escape(model.boundary)}</p></section>`;
}

function validContext(value) {
  return value && UUID.test(value.runId || '') && MODES.has(value.mode) && SCENARIOS.has(value.scenarioId);
}
function readSaved(key, fallback) {
  try { return JSON.parse(sessionStorage.getItem(key) || 'null') ?? fallback; } catch { return fallback; }
}
function writeSaved(key, value) {
  try { if (value === null) sessionStorage.removeItem(key); else sessionStorage.setItem(key, JSON.stringify(value)); return true; } catch { return false; }
}
function errorCode(error) { return error?.data?.error?.code || error?.error?.code || error?.code || ''; }
const accessDenied = error => errorCode(error) === 'UI_ACCESS_DENIED' || [401, 403].includes(error?.status);

const publicValue = (value, missing = '未记录') => value === null || value === undefined ? missing
  : ['string', 'boolean', 'number'].includes(typeof value) ? String(value) : missing;
const recordedBoolean = (value, yes, no) => value === true ? yes : value === false ? no : '尚未确认';
const statusIcons = { pass: '✓', fail: '×', ready: '●', running: '◷', pending: '○', skipped: '—' };
function exactValue(value) {
  const text = publicValue(value);
  return text.length > 76
    ? `<details class="guide-public-value"><summary>${escape(text.slice(0, 30))}…${escape(text.slice(-12))} · 查看完整值</summary><pre tabindex="0">${escape(text)}</pre></details>`
    : escape(text);
}
function facts(entries, className = 'guide-facts') {
  return `<dl class="${className}">${entries.map(([label, value]) => `<div><dt>${escape(label)}</dt><dd>${exactValue(value)}</dd></div>`).join('')}</dl>`;
}
function operationRecord({ id, title, description, state = 'pending', status = '待执行', detail = '' }) {
  return `<article class="guide-operation-record" data-operation-id="${id}" data-state="${state}"><div class="guide-operation-heading"><strong>${escape(title)}</strong><span class="guide-operation-status"><span aria-hidden="true">${statusIcons[state] || '○'}</span> ${escape(status)}</span></div><p>${escape(description)}</p>${detail ? `<details class="guide-operation-evidence" data-detail-key="operation-${escape(id)}"><summary>查看操作依据</summary>${detail}</details>` : ''}</article>`;
}

function detailIdentity(item) {
  if (item.dataset.detailKey) return item.dataset.detailKey;
  // The control and scenario requests can contain the same check IDs. Keep
  // their evidence, rows and expected/observed values independently addressable.
  return JSON.stringify([
    item.closest('[data-operation-id]')?.dataset.operationId || 'scenario-request',
    item.closest('[data-check-id]')?.dataset.checkId || '',
    item.closest('.guide-evidence-row')?.querySelector('strong')?.textContent || '',
    item.closest('dd')?.previousElementSibling?.textContent || '',
    item.querySelector('summary')?.textContent || '',
  ]);
}

/** Preserve only the same run's view. This helper never calls the protocol. */
export function replaceExperimentView(root, html, { preserve = false, pendingFocus = null } = {}) {
  const details = [...(root.querySelectorAll?.('details') || [])];
  const opened = new Set(preserve ? details.filter(item => item.open).map(detailIdentity) : []);
  const doc = root.ownerDocument || globalThis.document, active = doc?.activeElement;
  let focus = null;
  if (preserve && active && root.contains(active)) {
    const detail = active.closest?.('details');
    if (detail) focus = { detail: detailIdentity(detail), index: [...detail.querySelectorAll('summary, [tabindex], button, a, input, select')].indexOf(active) };
    else if (active.dataset?.experimentAction) focus = { action: active.dataset.experimentAction };
  } else if (preserve && (!active || active === doc?.body || active === doc?.documentElement)) focus = pendingFocus;
  root.innerHTML = html;
  const nextDetails = [...(root.querySelectorAll?.('details') || [])];
  for (const item of nextDetails) item.open = opened.has(detailIdentity(item));
  let target;
  if (focus?.detail && focus.index >= 0) {
    const detail = nextDetails.find(item => detailIdentity(item) === focus.detail);
    target = detail?.querySelectorAll('summary, [tabindex], button, a, input, select')[focus.index];
  } else if (focus?.action) target = [...(root.querySelectorAll?.('[data-experiment-action]') || [])].find(item => item.dataset.experimentAction === focus.action);
  if (target && !target.disabled) { target.focus({ preventScroll: true }); return null; }
  return target?.disabled ? focus : null;
}

// requestView is created before transmission. Only a matching B trace confirms
// receipt; a saved packet alone must never be labelled as received by B.
function experimentMaterials(record, mode, receivedByB) {
  const request = record?.request, packet = request?.proof, credential = packet?.verifiableCredential;
  if (!request || !packet) return {};
  const subject = credential?.credentialSubject;
  const field = key => subject && Object.hasOwn(subject, key) ? publicValue(subject[key]) : '派生 VC 中未提供';
  const material = value => value ? '本次材料已携带；有效性见服务端检查' : '本次材料未携带';
  const source = receivedByB ? '验证者 B 已收到：本次请求公开材料；接收依据为本次验证者 B 验证记录。' : '持有者 A 本地已准备：后端保存的本次请求材料；尚无验证者 B 接收确认。';
  const rows = entries => `<p class="guide-detail-note">${source}</p>${facts(entries)}`;
  const disclosure = ['role', 'scope', 'epoch', 'mode', 'bindingId', 'holderDid'].map(key => [key, field(key)]);
  // Do not copy hidden local attributes into the verifier view. The absence
  // observation is limited to this derived document, not a crypto verdict.
  const hidden = ['organization', 'holderLabel'].map(key => [key, subject && Object.hasOwn(subject, key) ? '本次派生文档包含该字段；请核对披露策略' : '本次派生文档未包含该字段']);
  return {
    w3c_bbs: rows([['签发方', credential?.issuer], ['证明类型', credential?.proof?.type], ['密码套件', credential?.proof?.cryptosuite], ['标准派生证明', material(credential?.proof)]]),
    disclosure: rows([...disclosure, ...hidden]),
    vc_device_binding: rows([['bindingId', field('bindingId')], ['mode', field('mode')], ['当前实验模式', mode], ['设备贡献', material(packet.deviceSignature)]]),
    holder_signature: rows([['holderDid', field('holderDid')], ['持有者签名', material(packet.holderProof)]]),
    device_pairing: rows([['随机化设备公钥 D', packet.randomizedDevicePublicKey], ['模拟 eSIM 贡献', material(packet.deviceSignature)]]),
    knowledge: rows([['配套知识证明', material(packet.proof)]]),
    request_binding: rows([['挑战编号', request.challengeId], ['方法', request.method], ['端点', request.endpoint]]),
    credential_status: rows([['bindingId', field('bindingId')], ...(record.revocation ? [['撤销操作对象', record.revocation.credential === 'experiment-only' ? '本次实验专用凭证' : '未记录'], ['是否使用新挑战', recordedBoolean(record.revocation.freshChallenge, '是', '否')]] : [])]),
  };
}

function resultEvidence(record) {
  const effects = record.sideEffects;
  const rows = [
    ['后端返回码', record.actual], ['后端记录的拒绝位置', record.rejectionStage],
    ['实际请求是否拒绝', recordedBoolean(record.requestRejected, '是', '否')],
    ['本次认证结果', recordedBoolean(record.authenticationIssued, '已发放', '未发放')],
    ['实验预期核对', record.completion === 'completed' ? recordedBoolean(record.expectationMet, '符合预期', '未满足全部预期') : '实验未完整结束'],
    ['预期返回码', record.expected], ['后端实验编号', record.id], ['完成时间', record.completedAt],
  ];
  const before = Array.isArray(effects?.before?.accounts) ? effects.before.accounts : [];
  const after = Array.isArray(effects?.after?.accounts) ? effects.after.accounts : [];
  const accountIds = [...new Set([...before, ...after].map(account => account.id))];
  const ledgerRows = effects ? [['付款执行次数：实验前', effects.before?.executionCount], ['付款执行次数：实验后', effects.after?.executionCount],
    ...accountIds.flatMap(id => [[`账户 ${id}：实验前 balanceMinor`, before.find(account => account.id === id)?.balanceMinor], [`账户 ${id}：实验后 balanceMinor`, after.find(account => account.id === id)?.balanceMinor]])] : [];
  return `<details class="guide-operation-evidence" data-detail-key="result-evidence"><summary>查看结果与模拟支付副作用依据</summary>${facts(rows)}${ledgerRows.length ? `<p class="guide-muted">余额为测试资产最小单位，取自本轮服务端账本观察。</p>${facts(ledgerRows)}` : ''}</details>`;
}

/** Each action either starts one explicit run or reads that exact run again. */
export function createExperimentGuide({ root, evidenceRoot = null, api, onChange = () => {}, mode, onBusy = () => {}, canStart = () => true }) {
  if (!root || typeof api !== 'function' || typeof mode !== 'function') throw new TypeError('The experiment guide needs a root, API and current mode.');
  let scenarioId = 'copied-vc', context = null, record = null, requestBusy = false;
  let notice = '', noticeState = 'pending', timer = null, polls = 0, generation = 0, lastBusy = null;
  let recovered = false, terminalError = null, notFound = false, notStarted = null, permissionBlocked = false;
  let viewKey = '', pendingFocus = null;
  const initial = readSaved(PENDING_KEY, null);
  if (validContext(initial)) context = { ...initial, pending: true };
  const recentValue = readSaved(RECENT_KEY, []);
  let recent = Array.isArray(recentValue) ? recentValue.filter(validContext).slice(-12) : [];
  // An unresolved run still prohibits another POST. A denied read may release
  // navigation so the user can restore access without discarding that run.
  const busy = () => requestBusy || context?.pending === true && !permissionBlocked;
  const currentMode = () => context?.pending ? context.mode : mode();
  const currentScenario = () => context?.pending ? context.scenarioId : scenarioId;
  const notifyBusy = () => { const value = busy(); if (lastBusy !== value) { lastBusy = value; onBusy(value); } };
  const stopPoll = () => { if (timer !== null) clearTimeout(timer); timer = null; };
  const publicContext = value => ({ runId: value.runId, mode: value.mode, scenarioId: value.scenarioId });
  function remember(value) {
    recent = recent.filter(item => item.runId !== value.runId);
    recent.push(publicContext(value)); recent = recent.slice(-12);
    writeSaved(RECENT_KEY, recent);
  }
  function settleContext() {
    context.pending = false;
    permissionBlocked = false;
    writeSaved(PENDING_KEY, null);
    remember(context);
    notifyBusy();
  }
  function render() {
    const selected = currentScenario(), copied = selected === 'copied-vc';
    const pending = context?.pending === true, recordMode = context?.mode || currentMode();
    const startAllowed = canStart() === true;
    const activeRecord = record && record.mode === recordMode && record.scenarioId === selected ? record : null;
    const startBlocked = !startAllowed && !activeRecord;
    const visible = experimentSummary(activeRecord), actualTrace = activeRecord?.verificationTrace;
    const steps = Array.isArray(actualTrace?.steps) ? actualTrace.steps : [];
    const control = activeRecord?.control, packet = activeRecord?.request?.proof;
    const controlPassed = control?.accepted === true && control.verificationTrace?.source === 'agent-b' && control.verificationTrace.profile === 'dbac-payment'
      && control.verificationTrace.outcome === 'pass'
      && definitions.every(([, , ids]) => groupStatus(control.verificationTrace, ids) === 'pass')
      && !control.verificationTrace.steps?.some(step => step.status === 'fail' || step.evidence?.some(row => row.match === false));
    const receivedByB = Boolean(activeRecord?.request && actualTrace?.source === 'agent-b' && steps.length);
    const finished = Boolean(activeRecord || terminalError || notFound);
    const hasPrepared = Boolean(packet?.verifiableCredential);
    const materialState = receivedByB || hasPrepared ? 'ready' : 'pending';
    const headline = pending ? permissionBlocked ? '原实验结果待核对 · 操作权限失效' : '实验执行中，等待原运行结果'
      : notStarted || startBlocked ? '实验尚未启动 · 操作权限未通过' : terminalError ? '实验未完成，尚无安全判定' : notFound ? '原运行记录已不可查询' : visible.title;
    const headlineDetail = pending ? permissionBlocked ? '已保留原运行编号；请载入本次有效的统一演示链接，再核对原运行。不能重新创建实验或据此判定拦截成功。' : '后端一次执行控制组与场景请求，接口未提供分阶段进度。'
      : notStarted ? notStarted.message : startBlocked ? '尚未载入操作权限，请使用本次启动的统一演示链接。没有提交实验，也没有安全验证结论。'
        : terminalError ? terminalError.message : notFound ? '服务端未找到原运行编号，可能已重启或记录已清理。本页没有自动重跑。' : visible.detail;
    const premise = copied
      ? '让仅持公开 VC 副本的攻击者发起本次请求，核对证明材料与实际阻断位置。'
      : '撤销实验专用凭证后，用新挑战、原持有者和模拟 eSIM 重新提交完整证明。';
    const flow = copied ? ['合法控制组', '复制公开 VC', '提交冒用请求', '验证者 B 联合验证']
      : ['合法控制组', '撤销实验凭证', '生成本次新证明', '验证者 B 检查状态'];
    const effects = activeRecord?.sideEffects;
    const summary = [
      ['证明模式', recordMode === 'bbs-blind-bls' ? '盲化 BLS' : '普通 BLS'],
      ['凭证范围', '本次实验专用凭证与订单'],
      ['持有者 / 模拟 eSIM', copied ? '攻击分支无原私钥、无原设备调用权限' : '原持有者与原设备参与'],
      ['付款授权', effects?.ownerApprovalRequested === false ? '本轮未请求用户授权' : '本场景不请求用户授权'],
    ];
    if (activeRecord?.request?.challengeId) summary.push(['本次挑战', activeRecord.request.challengeId]);
    let operations;
    if (!activeRecord) {
      operations = operationRecord({ id: 'experiment-run', title: '运行完整场景', state: pending && !permissionBlocked ? 'running' : 'pending', status: pending ? permissionBlocked ? '等待恢复查询权限' : '执行中' : '待执行',
        description: '先用正常控制请求确认服务和正常材料可用，再提交本场景的异常请求；两次实际记录分别核对。',
        detail: `<p>运行期间没有逐阶段状态，不能预先判断凭证、签名或撤销检查的结果。</p>${context ? facts([['原运行编号', context.runId], ['查询来源', recovered ? '恢复原运行记录' : '本轮后端运行']]) : '<p>点击下方运行按钮后创建独立实验。</p>'}` });
    } else {
      const controlState = controlPassed ? 'pass' : control?.verificationTrace?.steps?.some(step => step.status === 'fail') || (!control && actualTrace?.steps?.some(step => step.status === 'fail') && !activeRecord.request) ? 'fail' : 'pending';
      const controlTrace = control?.verificationTrace || (!activeRecord.request ? actualTrace : null);
      operations = operationRecord({ id: 'control-reference', title: '合法控制组', state: controlState, status: controlPassed ? '前置请求已通过' : controlState === 'fail' ? '前置请求未通过' : '缺少完整结论',
        description: controlPassed ? '正常控制请求已确认当前服务和正常材料可完成资格认证；下方是该控制请求的独立记录，不能代替异常请求的检查。' : '正常控制请求用于先确认服务和正常材料可用。本轮尚未确认通过，请按下方实际记录核对是否停在前置准备阶段。',
        detail: `${facts([['控制组挑战', control?.challengeId], ['控制组记录来源', controlTrace?.source === 'agent-b' ? '验证者 B' : '未取得验证者 B 的记录']])}${controlTrace ? renderVerificationChecks(controlTrace, { phase: 'proposal' }) : '<p>没有可回看的控制组验证记录。</p>'}` });
      operations += operationRecord({ id: 'request-materials', title: copied ? '派生材料与冒用请求' : '撤销后生成与提交', state: materialState,
        status: receivedByB ? '验证者 B 已收到' : hasPrepared ? '材料已生成' : '未取得材料记录',
        description: receivedByB ? '已有验证者 B 对本次请求的验证记录；材料是否有效由下列事项分别说明。'
          : hasPrepared ? '持有者 A 侧已有请求材料，但没有验证者 B 接收记录，无法确认请求是否到达。' : '本轮尚未取得场景请求材料，后续验证不能记为通过。',
        detail: `${facts([['材料来源', receivedByB ? '本次请求材料与验证者 B 验证记录' : '持有者 A 侧本轮准备记录'], ['标准 BBS 派生 VC', packet?.verifiableCredential ? '已生成' : '未记录'], ['持有者 A 本次签名', packet?.holderProof ? '已携带' : '材料中未提供'], ['模拟 eSIM 贡献', packet?.deviceSignature ? '已携带' : '材料中未提供'], ['本次挑战', activeRecord.request?.challengeId]])}${copied && activeRecord.accessChecks?.length ? `<p>无权限调用探测属于访问控制记录，不是签名验证。</p>${facts(activeRecord.accessChecks.map(check => [check.target === 'device-sign' ? '请求设备签名' : '请求签发方撤销', check.actual]))}` : ''}` });
      if (activeRecord.request) operations += `<div data-experiment-request-checks>${renderVerificationChecks(actualTrace, { phase: 'proposal', materialsById: experimentMaterials(activeRecord, recordMode, receivedByB) })}</div>`;
    }
    const sideEffectText = effects ? `模拟支付执行增量：${Number.isFinite(effects.paymentExecutionDelta) ? `${effects.paymentExecutionDelta} 次` : '未确认'}；余额：${effects.before && effects.after ? recordedBoolean(effects.balancesUnchanged, '未变化', '有变化') : '未确认'}。` : '';
    const nextViewKey = JSON.stringify([context?.runId || '', recordMode, selected]);
    const expectation = activeRecord?.completion === 'completed' && controlPassed && visible.state === 'fail' && activeRecord.expectationMet === true && activeRecord.actual === activeRecord.expected && effects?.before && effects?.after && effects.paymentExecutionDelta === 0 && effects.balancesUnchanged === true
      ? '<span class="stage-expectation">实验符合预期</span>' : activeRecord ? '<span class="stage-expectation" data-state="pending">实验预期待核对</span>' : '';
    const controlFailures = !controlPassed ? (control?.verificationTrace?.steps || (!activeRecord?.request ? steps : [])).filter(step=>step.status==='fail'||step.status!=='skipped'&&step.evidence?.some(row=>row.match===false)) : [];
    const controlFailureHtml=controlFailures.map(step=>`<p class="stage-visible-failure">控制组未成立 · ${escape(step.title||step.id)}：${escape([step.code,step.detail].filter(Boolean).join(' · ')||'请核对控制组失败记录')}。本轮不能宣布防护验证成功。</p>`).join('');
    const comparisons = activeRecord ? `<div class="stage-experiment-compare" aria-label="同一轮合法控制组与场景请求对照"><div data-state="${controlPassed ? 'pass' : 'pending'}"><span>合法控制组</span><strong>${controlPassed ? '验证通过' : '尚未确认成立'}</strong></div><div data-state="${visible.state}"><span>${copied ? '复制攻击' : '撤销后新请求'}</span><strong>${visible.state === 'fail' ? '请求被拒绝' : visible.state === 'pass' ? '请求通过认证' : '结果待核对'}</strong></div></div>` : '';
    const materialNote = activeRecord ? `<p class="stage-material-note">标准 BBS 派生：${packet?.verifiableCredential ? '材料已生成' : '未记录'}；${copied ? '攻击者没有 A 私钥及原设备调用权限。生成派生证明不等于获得完整使用资格。' : `原持有者签名：${packet?.holderProof ? '已携带' : '未记录'}；原设备贡献：${packet?.deviceSignature ? '已携带' : '未记录'}。材料存在不代替独立验证。`}</p>` : '';
    const evidenceHtml = `<p class="guide-control-purpose">本轮先由持有者 A 与原模拟 eSIM 发起正常控制请求，确认当前服务和正常材料可完成资格认证；再提交异常请求。正常控制组通过不能代替异常请求的验证。本轮记录回看 · 控制组与${copied ? '复制攻击' : '撤销后新请求'}使用各自的新挑战。模拟 eSIM 准备控制组会增加调用记录；不请求 Owner 批准、钱包签名或结算。</p>${facts(summary, 'guide-step-summary')}${renderDeviceContrast(activeRecord, { scenarioId: selected, pending })}<section class="guide-step-records" aria-label="本轮操作与验证记录"><h4>本轮记录回看 · 只读记录</h4>${operations}</section>${activeRecord ? resultEvidence(activeRecord) : ''}<details class="guide-tech-details" data-detail-key="run-source"><summary>场景边界与运行来源</summary><p>后端一次运行完整实验，记录回看不表示实时逐阶段执行。实验凭证和订单独立于正常支付，设备服务与测试账本共享。</p>${context ? facts([['运行编号', context.runId], ['记录来源', recovered ? '按原运行编号重新查询后端' : '当前后端运行']]) : ''}</details>`;
    const html = `<section class="guide-step-panel" data-experiment-scenario="${selected}" aria-label="${copied ? '复制冒用实验' : '凭证撤销实验'}主面板">
      <header class="guide-step-heading"><span class="stage-panel-eyebrow">${activeRecord ? '本轮记录回看' : pending ? '实验执行中' : '当前场景与本步检查 · 待执行'}</span><h3>${copied ? '复制冒用' : '撤销后使用'} · ${activeRecord ? '本轮结果' : '运行实验'}</h3><p>${activeRecord ? '对照同一轮的合法控制组与场景请求。' : escape(premise)}</p></header>
      <section class="guide-step-result" data-state="${pending || notStarted || startBlocked || terminalError || notFound ? 'pending' : visible.state}" aria-live="polite" aria-busy="${requestBusy || pending && !permissionBlocked}">
        <h4>${escape(headline)}</h4><p>${escape(headlineDetail)}</p>
        ${activeRecord?.actual ? `<p class="stage-visible-failure"><code>${escape(activeRecord.actual)}</code>${activeRecord.rejectionStage ? ` · 拒绝阶段：${escape(activeRecord.rejectionStage)}` : ''}</p>` : ''}${expectation}
        ${notice && noticeState !== 'complete' ? `<p class="guide-muted" role="status">${escape(notice)}</p>` : ''}
      </section>${comparisons}${controlFailureHtml}
      <div class="guide-panel-actions"><button type="button" class="guide-button primary" data-experiment-action="${pending ? 'refresh' : activeRecord ? 'evidence' : 'run'}" ${requestBusy || !pending && !activeRecord && !startAllowed ? 'disabled' : ''}>${pending ? '核对原运行' : activeRecord ? '查看本轮证据' : finished ? '开始新一轮实验' : '运行本场景'}</button></div>
      ${materialNote}
      ${activeRecord?.request ? `<div class="stage-experiment-checks">${renderCheckPreview(actualTrace, { phase: 'proposal' })}</div>` : ''}
      ${sideEffectText ? `<p class="stage-effects">${escape(sideEffectText)} 新认证：${recordedBoolean(activeRecord.authenticationIssued, '已发放', '未发放')}。</p>` : ''}

      <div class="stage-secondary-actions">${context && !pending ? `<button type="button" class="guide-button text" data-experiment-action="refresh" ${requestBusy ? 'disabled' : ''}>核对原运行</button>` : ''}<details class="stage-more"><summary>更多操作</summary><div>${activeRecord ? `<button type="button" class="guide-button quiet" data-experiment-action="run" ${requestBusy || !startAllowed ? 'disabled' : ''}>开始新一轮实验</button>` : ''}<button type="button" class="guide-button quiet" data-experiment-action="normal" ${busy() ? 'disabled' : ''}>返回正常支付</button></div></details></div>
      ${!evidenceRoot ? `<details class="guide-tech-details"><summary>本轮记录回看 · 只读记录</summary>${evidenceHtml}</details>` : ''}
    </section>`;
    if(evidenceRoot)replaceExperimentView(evidenceRoot,evidenceHtml,{preserve:nextViewKey===viewKey});
    pendingFocus = replaceExperimentView(root, html, { preserve: nextViewKey === viewKey, pendingFocus });
    viewKey = nextViewKey;
    notifyBusy();
    onChange({type:'view',view:{context:context?{...publicContext(context),pending}:null,record:activeRecord,pending,permissionBlocked,terminalError,notFound,requestBusy}});
  }
  function applyResponse(value, expected) {
    if (!value || value.runId !== expected.runId || value.mode !== expected.mode || value.scenarioId !== expected.scenarioId)
      throw new Error('返回的运行编号、模式或场景不匹配，保留原运行编号等待核对。');
    if (value.status === 'running') {
      context.pending = true; writeSaved(PENDING_KEY, publicContext(context));
      notice = '后端仍在运行，已保留原运行编号。'; noticeState = 'pending';
      return;
    }
    if (value.status === 'completed') {
      if (!value.result || value.result.mode !== expected.mode || value.result.scenarioId !== expected.scenarioId)
        throw new Error('后端运行已结束，但结果与本次场景不匹配；请核对原运行。');
      record = value.result; terminalError = null; settleContext();
      notice = '已取得原运行的最终记录；再次演示需要你明确点击新一轮。'; noticeState = 'complete';
      onChange({ type: 'result', record });
      return;
    }
    if (value.status === 'failed') {
      terminalError = value.error || { message: '后端未能完成实验，请核对服务状态。' };
      record = null; settleContext();
      notice = `${terminalError.code || 'EXPERIMENT_FAILED'}：这是实验执行失败，不是安全拦截成功。`; noticeState = 'pending';
      return;
    }
    throw new Error('服务端没有返回明确的运行状态，请核对原运行。');
  }
  function schedulePoll() {
    stopPoll();
    if (!context?.pending) return;
    if (polls >= 25) { notice = '仍未取得最终结果，已暂停自动查询。请点击“核对原运行”；不会自动发起新的实验。'; render(); return; }
    timer = setTimeout(() => { polls += 1; void readRun(); }, 1200);
  }
  async function readRun() {
    if (requestBusy || !context) return;
    stopPoll(); const expected = publicContext(context), ticket = ++generation;
    requestBusy = true; permissionBlocked = false; notice = '正在按原运行编号查询后端…'; render();
    let pollAgain = false;
    try {
      const value = await api(`${RUNS_ENDPOINT}?runId=${encodeURIComponent(expected.runId)}`);
      if (ticket !== generation) return;
      applyResponse(value, expected); pollAgain = value.status === 'running';
    } catch (error) {
      if (ticket !== generation) return;
      if (accessDenied(error)) {
        permissionBlocked = true;
        notice = `查询权限未通过：${error.message || '请重新载入本次操作权限'}。已保留原运行编号，可以离开本页恢复权限；没有创建新实验，也不能判定原实验未启动。`;
      } else if (errorCode(error) === 'EXPERIMENT_RUN_NOT_FOUND' || error?.status === 404) {
        record = null; terminalError = null; notFound = true; context.pending = false;
        writeSaved(PENDING_KEY, null);
        recent = recent.filter(item => item.runId !== expected.runId); writeSaved(RECENT_KEY, recent);
        notice = '原运行记录不可恢复。没有自动重跑；你可明确开始新一轮。';
      } else {
        notice = `查询未完成：${error?.message || '网络响应未知'}。${context.pending ? '原运行可能仍在执行，已禁止创建新一轮。请核对原运行。' : '保留本轮编号；当前显示的既有记录仅供回看。'}`;
      }
      noticeState = 'pending';
    } finally {
      if (ticket === generation) { requestBusy = false; render(); if (pollAgain) schedulePoll(); }
    }
  }
  async function start() {
    if (requestBusy || context?.pending) return;
    stopPoll(); const selectedMode = mode();
    if (!MODES.has(selectedMode)) return;
    if (canStart() !== true) {
      notStarted = { message: '尚未载入操作权限，请使用本次启动的统一演示链接。没有提交实验，也没有安全验证结论。' };
      notice = ''; render(); return;
    }
    const next = { runId: crypto.randomUUID(), mode: selectedMode, scenarioId, pending: true };
    if (!writeSaved(PENDING_KEY, publicContext(next))) {
      notice = '无法保存本次运行编号，本轮尚未启动。请允许浏览器会话存储后再试，以便刷新后查询原运行。'; noticeState = 'pending'; render(); return;
    }
    context = next; record = null; terminalError = null; notFound = false; notStarted = null; permissionBlocked = false; recovered = false; polls = 0;
    requestBusy = true; notice = '已保存本次运行编号，正在提交场景…'; noticeState = 'pending'; render();
    const expected = publicContext(context), ticket = ++generation;
    let pollAgain = false;
    try {
      const value = await api(RUNS_ENDPOINT, expected);
      if (ticket !== generation) return;
      applyResponse(value, expected); pollAgain = value.status === 'running';
    } catch (error) {
      if (ticket !== generation) return;
      if (error?.notSubmitted === true || accessDenied(error)) {
        context = null; writeSaved(PENDING_KEY, null); permissionBlocked = false;
        const denialMessage = String(error?.message || '操作权限未通过').replace(/[。.!！\s]+$/u, '');
        notStarted = { message: `${denialMessage}。实验请求未被受理，本轮尚未启动；这不是安全验证拒绝。请载入本次有效的统一演示链接后再操作。` };
        notice = '';
      } else {
        notice = `启动响应未确认：${error?.message || '通信未完成'}。原运行可能已经开始，请点击“核对原运行”；不会自动重跑。`;
      }
      noticeState = 'pending';
    } finally {
      if (ticket === generation) { requestBusy = false; render(); if (pollAgain) schedulePoll(); }
    }
  }
  async function select(nextScenario) {
    if (!SCENARIOS.has(nextScenario)) return;
    if (requestBusy) return;
    stopPoll();
    if (context?.pending) {
      await resumePending(); return;
    }
    const previous = recent.findLast(item => item.mode === mode() && item.scenarioId === nextScenario);
    const sameRun = previous && context?.runId === previous.runId && record?.mode === previous.mode && record?.scenarioId === nextScenario;
    scenarioId = nextScenario; if (!sameRun) record = null;
    terminalError = null; notFound = false; notStarted = null; permissionBlocked = false; notice = ''; polls = 0;
    context = previous ? { ...previous, pending: false } : null; recovered = Boolean(previous);
    render(); if (context) await readRun();
  }
  async function resumePending() {
    // Startup must reveal this recovery before the root's busy lock hides all
    // routes to it. With no pending run this must not select B by default.
    if (!context?.pending) return false;
    scenarioId = context.scenarioId; recovered = true;
    onChange({ type: 'resume', mode: context.mode, scenarioId });
    render(); polls = 0;
    if (!requestBusy) await readRun();
    return true;
  }
  function refresh() {
    polls = 0;
    // A parent activation can update its mode selector before asking for a
    // refresh. Completed evidence from the previous mode must not survive it.
    if (!context?.pending && context?.mode !== mode()) return select(scenarioId);
    return readRun();
  }
  root.addEventListener('click', event => {
    const button = event.target.closest('[data-experiment-action]');
    if (!button || button.disabled || !root.contains(button)) return;
    if (button.dataset.experimentAction === 'evidence') onChange({type:'evidence',target:'experiment'});
    else if (button.dataset.experimentAction === 'run') void start();
    else if (button.dataset.experimentAction === 'refresh') void refresh();
    else if (button.dataset.experimentAction === 'normal' && !busy()) onChange({ type: 'normal' });
  });
  notifyBusy();
  return { select, resumePending, refresh, busy, getResult: () => record ? structuredClone(record) : null };
}
