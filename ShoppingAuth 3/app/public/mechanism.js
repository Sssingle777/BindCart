import { buildScenePresentation, renderSceneCanvas } from './guide-scene.js';
import { guideProgress } from './guide-progress.js';
import { currentVerificationTrace, currentStepPanel, renderStepMaterial } from './guide-step-detail.js';
import { renderVerificationChecks, verificationEvidenceModel } from './guide-evidence.js';
import { verificationVerdict } from './guide-model.js';
import { layoutSceneLabels } from './scene-labels.js';

// Public projections display real state. Each console click invokes one backend action.
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
const phaseNames = { cart: '等待订单', verifying: '资格验证', checkout: '等待用户确认付款', paying: '付款处理中', confirming: '付款已确认，商户订单待同步', paid: '订单已完成', unknown: '付款结果待核对' };
const proofPhases = { proposal: '资格认证', authorize: '付款前复核', settle: '结算验证' };
const statusNames = { valid: '有效', active: '有效', revoked: '已撤销', absent: '尚未签发', unknown: '待核对', expired: '已过期', PENDING: '等待用户逐笔确认', APPROVED: '用户已批准', REJECTED: '用户已拒绝', EXPIRED: '授权已过期' };
const roleTitles = { credential: '凭证签发方', holder: '持有者智能体 A', device: '软件模拟 eSIM', verification: '验证者智能体 B', owner: 'Owner · 用户逐笔授权', receipt: '本地测试账本' };
const historyCache = new Map(), eventMap = new Map();
let snapshot = null, sequence = 0, instanceId = null, selectedOrder = '', selectedTrace = '', tracePinned = false, historical = null, roleDialogReturn = null;
let streamAbort = null, retryTimer = null, retryCount = 0, stopped = false, securityBusy = false, refreshPromise = null, historyRequest = 0;
let queryBusy = false, experimentBusy = false, faultBusy = false, manualBusy = false;
let manualNotice = '', manualNoticeFailed = false, manualCancelling = false, expiryTimer = null, expiryReadKey = '';
const manualLabels = {
  issue: '准备凭证', 'begin-proposal': '获取认证挑战', 'derive-vc': '生成派生凭证',
  'device-sign': '请求设备签名', prove: '生成联合持有证明',
  'submit-owner': '请求用户授权', 'sync-owner': '同步授权状态',
  'begin-authorize': '获取付款前复核挑战', 'wallet-sign': '签署付款请求',
  'begin-settle': '获取结算挑战', 'confirm-merchant': '核对支付并确认订单',
  discard: '结束本次认证', refresh: '刷新状态',
};
const sourceLabels = { 'original-controller': '认证控制器', 'storefront-controller': '商城', 'owner-service': '用户授权', 'merchant-service': '商户', 'live-service': '状态服务', 'security-experiment': '安全实验' };
const statusLabels = { start: '开始', started: '开始', running: '执行中', pending: '等待中', complete: '完成', completed: '完成', success: '成功', pass: '通过', fail: '失败', error: '错误', rejected: '拒绝' };
const roleLabels = { holder: '持有者 A', issuer: '签发方', device: '软件 eSIM', verifier: '验证者 B', owner: '用户授权', ledger: '本地账本' };
const actorLabels = { ...roleLabels, 'agent-a': '持有者 A', 'agent-b': '验证者 B', wallet: '钱包' };
const operationLabels = { checkout: '资格验证', pay: '付款', manual: '当前步骤', security: '设备与凭证管理', queryPayment: '查询原支付流水' };
function actionLabel(action, phase, fallback = '') {
  if (action === 'verify') return phase === 'settle' ? '验证并执行测试付款' : phase === 'authorize' ? '提交付款前复核' : '提交资格验证';
  return manualLabels[action] || fallback || action || '当前步骤';
}
function resultLabel(status) { return statusLabels[status] || status || '已记录'; }
function displaySource(source) { return sourceLabels[source] || source || '状态服务'; }
function eventAction(event) { return actionLabel(event?.action, event?.phase, event?.title || event?.action || '事件'); }
function eventDirection(event) {
  const from = actorLabels[event?.from] || event?.from, to = actorLabels[event?.to] || event?.to;
  return from && to ? `${from} → ${to} · ` : '';
}
const fragment = new URLSearchParams(location.hash.slice(1));
const key = fragment.get('key') || sessionStorage.getItem('storefront-key') || '';
if (fragment.has('key')) {
  sessionStorage.setItem('storefront-key', key);
  history.replaceState(null, '', `${location.pathname}${location.search}`);
}

function text(value, empty = '未返回') { return value === undefined || value === null || value === '' ? empty : typeof value === 'object' ? JSON.stringify(value) : String(value); }
function compactId(value) { const raw = String(value || ''); return raw.length > 26 ? `${raw.slice(0, 12)}…${raw.slice(-10)}` : raw; }
function time(value, date = false) { const parsed = new Date(value); return Number.isFinite(parsed.getTime()) ? parsed.toLocaleString('zh-CN', date ? { hour12: false } : { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '时间未返回'; }
function money(minor, currency = 'TEST_USDC') { return Number.isSafeInteger(minor) ? `${(minor / 1_000_000).toLocaleString('zh-CN', { maximumFractionDigits: 6 })} ${currency}` : '金额未返回'; }
function badge(value, state = 'pending') { return `<span class="live-badge" data-state="${esc(state)}">${esc(value)}</span>`; }
function fields(rows, className = '') { return `<dl class="${className}">${rows.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(text(value))}</dd></div>`).join('')}</dl>`; }
function compactChecks(trace, phase) {
  const model = verificationEvidenceModel(trace, { phase });
  const labels = { pass: '通过', fail: '不通过', skipped: '未执行', pending: '待验证', running: '验证中', unknown: '待核对' };
  return model.anomalies.map(message => `<p class="guide-evidence-anomaly" role="status">${esc(message)}</p>`).join('')
    + `<table class="live-check-table"><thead><tr><th scope="col">检查</th><th scope="col">结果</th><th scope="col">返回说明</th></tr></thead><tbody>${model.steps.map(step => `<tr data-state="${esc(step.status)}" data-compact-check="${esc(step.id)}"><td>${esc(step.title)}</td><td>${esc(labels[step.status] || step.status)}</td><td>${esc(step.detail || step.description)}${step.code ? ` <code>${esc(step.code)}</code>` : ''}</td></tr>`).join('')}</tbody></table>`
    + `<details class="live-full-checks" data-detail-key="full-checks-${esc(phase)}"><summary>公开输入与核验关系</summary>${renderVerificationChecks(trace, { phase })}</details>`;
}
function publicJson(value) {
  const omitted = /private|secret|password|mnemonic|^(?:(?:ui|api|owner|access)[_-]?key|access[_-]?token|cancelToken|token|cookie|seed)$/i;
  return JSON.stringify(value, (name, entry) => omitted.test(name) ? '[不展示访问凭据]' : entry, 2);
}
function replace(target, html) {
  if (target.dataset.html === html) return;
  const opened = new Set([...target.querySelectorAll('details[open]')].map(item => item.dataset.detailKey || item.querySelector('summary')?.textContent));
  target.innerHTML = html; target.dataset.html = html;
  for (const detail of target.querySelectorAll('details')) if (opened.has(detail.dataset.detailKey || detail.querySelector('summary')?.textContent)) detail.open = true;
}
function connection(label, state) { $('live-connection').textContent = label; $('live-connection').dataset.state = state; }
async function api(path, body, signal) {
  const response = await fetch(path, { method: body === undefined ? 'GET' : 'POST', headers: { 'X-Demo-UI-Key': key, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), cache: 'no-store', signal });
  if (!response.ok) {
    const problem = await response.json().catch(() => ({}));
    const error = new Error(problem.error?.message || problem.message || `服务返回 ${response.status}`); error.status = response.status; throw error;
  }
  return response;
}
function deviceOf(value = snapshot) { const inventory = value?.inventory || {}, id = value?.core?.currentDeviceId || inventory.currentDeviceId; return inventory.devices?.find(device => (device.id || device.deviceId) === id) || null; }
function currentOrder() { return snapshot?.store?.order?.orderId || null; }
function sameCoreOrder() { return Boolean(currentOrder() && snapshot?.core?.order?.orderId === currentOrder()); }
function addEvent(event) {
  if (!event || !Number.isSafeInteger(event.seq)) return;
  if (!eventMap.has(event.seq)) eventMap.set(event.seq, event);
  sequence = Math.max(sequence, event.seq);
  if (eventMap.size > 500) for (const id of [...eventMap.keys()].sort((a, b) => a - b).slice(0, eventMap.size - 500)) eventMap.delete(id);
}
function acceptSnapshot(value) {
  if (!value || typeof value !== 'object' || !value.store || !value.core) return;
  if (instanceId !== value.instanceId) {
    instanceId = value.instanceId; sequence = 0; eventMap.clear(); historyCache.clear(); historical = null;
    if (selectedOrder) { selectedOrder = ''; selectedTrace = ''; tracePinned = false; }
  } else if (Number.isSafeInteger(value.sequence) && value.sequence < (snapshot?.sequence || 0)) return;
  if (!selectedOrder && snapshot?.store?.order?.orderId !== value.store.order?.orderId) { selectedTrace = ''; tracePinned = false; }
  if (snapshot?.store?.order?.orderId !== value.store.order?.orderId) $('live-query-result').textContent = '';
  snapshot = value; scheduleExpiryRead();
  for (const event of Array.isArray(value.events) ? value.events : []) addEvent(event);
  if (Number.isSafeInteger(value.sequence)) sequence = Math.max(sequence, value.sequence);
  render();
}
function eventState(event) { return ['pass', 'ok', 'success', 'complete', 'completed'].includes(event.status || event.result) ? 'pass' : ['fail', 'error', 'rejected'].includes(event.status || event.result) ? 'fail' : ['running', 'start', 'started', 'pending'].includes(event.status) ? 'running' : 'pending'; }
function operationRunning(operation = operationInfo()) { return Boolean(operation && ['running', 'start', 'started', 'pending'].includes(operation.status)); }
function eventsHtml(events) {
  return events.length ? events.map(event => `<li class="live-event" data-state="${eventState(event)}"${Number.isSafeInteger(event.seq) ? ` data-event-seq="${event.seq}"` : ''}><div><time datetime="${esc(event.at || '')}" title="${esc(time(event.at, true))}">${esc(time(event.at))}</time><span class="live-event-seq">${Number.isSafeInteger(event.seq) ? `#${event.seq}` : '留存记录'}</span></div><div class="live-event-body"><div class="live-event-title"><span>${esc(eventDirection(event) + eventAction(event) + ` · ${resultLabel(event.status || event.result)}`)}</span><span class="live-event-source">${esc(displaySource(event.source))}</span></div>${event.detail ? `<p class="live-event-detail">${esc(text(event.detail))}</p>` : ''}${event.orderId ? `<code class="live-event-order">${esc(event.orderId)}</code>` : ''}<details class="live-event-raw"><summary>公开字段</summary><code>${esc(publicJson({ source: event.source, action: event.action, status: event.status || event.result, phase: event.phase, orderId: event.orderId, seq: event.seq }))}</code></details></div></li>`).join('') : '<li class="live-empty">尚无事件记录。</li>';
}
function tracesFor(record, core, { historicalOrder = false } = {}) {
  const values = [];
  const orderId = record?.order?.orderId || record?.boundOrder?.orderId;
  if (!orderId || historicalOrder && orderId !== selectedOrder) return values;
  const add = (trace, phase, source, context = null) => {
    if (!trace || trace.source !== 'agent-b' || !Array.isArray(trace.steps)) return;
    const rows = trace.steps.flatMap(step => Array.isArray(step.evidence) ? step.evidence : []);
    const observedPhases = rows.flatMap(row => row.label === 'method / scope / phase' && Array.isArray(row.observed) ? [row.observed[2]] : row.label === 'phase / resulting task' && Array.isArray(row.observed) ? [row.observed[0]] : []).filter(value => Object.hasOwn(proofPhases, value));
    const observedOrders = rows.filter(row => row.label === 'payment order ID' && typeof row.observed === 'string').map(row => row.observed);
    if (observedOrders.some(value => value !== orderId)) return;
    if (context && (trace.profile !== 'dbac-payment' || observedPhases.some(value => value !== phase))) return;
    const actualPhase = observedPhases[0] || phase;
    if (!Object.hasOwn(proofPhases, actualPhase)) return;
    const key = `${actualPhase}:${trace.outcome}:${JSON.stringify(trace.steps)}`;
    const existing = values.find(item => item.key === key);
    if (!existing) values.push({ key, trace, phase: actualPhase, source, ...(context || {}) });
    else if (context) Object.assign(existing, { source, ...context });
  };
  add(record?.verification, record?.phase === 'paid' ? 'settle' : 'proposal', historicalOrder ? '该订单留存检查' : '商城订单验证记录');
  // These are retained results of real completed verify calls, scoped to this
  // exact order. They remain selectable after the current challenge advances.
  const events = historicalOrder ? record.events : snapshot?.events;
  for (const event of (Array.isArray(events) ? events : []).filter(event => event?.type === 'protocol' && event.source === 'original-controller' && event.action === 'verify' && event.status === 'complete' && event.orderId === orderId && Object.hasOwn(proofPhases, event.phase) && typeof event.attemptId === 'string' && event.attemptId.length > 0 && typeof event.data?.challengeId === 'string' && event.data.challengeId.length > 0).sort((left, right) => (left.seq || 0) - (right.seq || 0))) {
    add(event.data.verificationTrace, event.phase, `${historicalOrder ? '该订单留存' : '当前订单'}认证控制器检查事件${Number.isSafeInteger(event.seq) ? ` #${event.seq}` : ''}`, { orderId, attemptId: event.attemptId, challengeId: event.data.challengeId, eventSeq: event.seq, recordedAt: event.at });
  }
  const matchedCore = core?.order?.orderId === orderId ? core : null;
  const last = matchedCore?.lastResult;
  for (const trace of Array.isArray(last?.verificationTraces) ? last.verificationTraces : []) add(trace, last.phase, '支付返回记录');
  add(last?.verificationTrace, last?.phase, '支付处理返回记录');
  if (matchedCore?.manual?.active) add(currentVerificationTrace(matchedCore), matchedCore.manual.phase, '当前阶段记录');
  return values;
}
function operationInfo() {
  const operation = snapshot?.operation;
  if (!operation) return null;
  if (typeof operation === 'string') return { action: operation, status: 'running' };
  return operation;
}
function renderScene() {
  const core = snapshot.core, store = snapshot.store, device = deviceOf(), operation = operationInfo();
  const realEvents = [...eventMap.values()].sort((a, b) => a.seq - b.seq);
  const latestProtocol = realEvents.filter(event => event.type === 'protocol' && (currentOrder() ? event.orderId === currentOrder() : !event.orderId)).at(-1);
  const runningAction = latestProtocol && ['start', 'started', 'running'].includes(latestProtocol.status) ? latestProtocol.action : '';
  const manualMatches = core.manual?.active && sameCoreOrder();
  const model = buildScenePresentation({ state: manualMatches ? core : null, mode: core.mode || 'bbs-bls', busy: Boolean(runningAction), actionId: runningAction, now: Number.isFinite(Date.parse(snapshot.at)) ? Date.parse(snapshot.at) : Date.now() });
  const set = (id, state, label, detail = '') => Object.assign(model.nodes.find(node => node.id === id), { state, label, detail, active: false });
  const traces = sameCoreOrder() ? tracesFor(store, core) : tracesFor(store, null), latest = traces.at(-1);
  const verdict = latest ? verificationVerdict(latest.trace, { phase: latest.phase }) : null;
  const proposal = sameCoreOrder() ? core.proposal : null;
  if (!manualMatches) {
  set('issuer', core.credentialStatus?.status === 'revoked' ? 'fail' : core.credential ? 'material' : 'pending', core.credentialStatus?.status === 'revoked' ? '当前凭证已撤销' : core.credential ? '当前凭证已返回' : '等待签发凭证', '凭证存在与本次使用验证分别展示。');
  set('holder', core.holder ? 'material' : 'pending', core.holder ? '持有凭证专属签名密钥' : '等待凭证持有者', '私钥保留在原进程中，不在观察页展示。');
  set('device', device?.locked === true ? 'fail' : device ? 'material' : 'unknown', device?.locked === true ? '设备已锁定' : device ? `已连接 · 累计签名 ${text(device.signCount, '未返回')} 次` : '设备状态待读取', '累计计数来自原设备服务，不代表本订单验证已通过。');
  set('verifier', verdict?.status || 'pending', verdict?.title || '等待本单证明', verdict?.detail || '尚未取得本单的验证者 B 结论。');
  set('owner', proposal?.status === 'REJECTED' ? 'fail' : proposal?.status === 'APPROVED' ? 'material' : 'pending', statusNames[proposal?.status] || '尚无本单授权申请', '逐笔批准不等于执行付款。');
  const receipt = store.receipt;
  set('ledger', receipt?.orderId === currentOrder() && receipt.transactionStatus === 'success' ? 'pass' : store.phase === 'unknown' || core.paymentPending ? 'unknown' : 'pending', receipt?.orderId === currentOrder() && receipt.transactionStatus === 'success' ? '本单成功回执已返回' : store.phase === 'unknown' || core.paymentPending ? '本单付款结果待核对' : '本单尚无付款回执', 'TEST_USDC 本地模拟支付。');
  }
  const actorId = value => ({ 'agent-a': 'holder', 'agent-b': 'verifier', wallet: 'ledger' }[value] || value);
  const roleIds = new Set(model.nodes.map(node => node.id));
  const wireEvent = realEvents.map(event => ({ ...event, from: actorId(event.from), to: actorId(event.to) })).filter(event => (currentOrder() ? event.orderId === currentOrder() : !event.orderId) && roleIds.has(event.from) && roleIds.has(event.to)).at(-1);
  model.messages = wireEvent ? [{ id: `event-${wireEvent.seq}`, from: wireEvent.from, to: wireEvent.to, label: `${eventAction(wireEvent)} · ${resultLabel(wireEvent.status || wireEvent.result)}`, state: eventState(wireEvent), evidence: wireEvent.to === 'verifier' ? 'verification' : wireEvent.to === 'device' ? 'device' : wireEvent.to === 'owner' ? 'owner' : wireEvent.to === 'ledger' ? 'receipt' : 'holder', detail: wireEvent.detail || '' }] : [];
  if (wireEvent) for (const node of model.nodes) node.active = [wireEvent.from, wireEvent.to].includes(node.id);
  if (!manualMatches && operationRunning(operation)) {
    const target = /issue|credential/.test(operation.action || '') ? 'issuer' : /device|sign/.test(operation.action || '') ? 'device' : /owner/.test(operation.action || '') ? 'owner' : /pay|settle/.test(operation.action || '') ? 'ledger' : 'verifier';
    const node = model.nodes.find(item => item.id === target); node.active = true;
    if (node.state !== 'fail') { node.state = 'running'; node.label = actionLabel(operation.action, core.manual?.phase, operation.title || '请求处理中'); }
  }
  model.note = (manualMatches ? `${proofPhases[core.manual.phase] || '当前阶段'} · ${model.note} ` : '') + (wireEvent ? `最近事件 #${wireEvent.seq} · ${time(wireEvent.at)}。` : '暂无可展示的有向消息。');
  replace($('live-scene'), renderSceneCanvas(model));
}
function renderSummary() {
  const { core, store } = snapshot, device = deviceOf(), operation = operationInfo();
  $('live-instance').textContent = text(snapshot.instanceId); $('live-sequence').textContent = String(sequence); $('live-updated').textContent = time(snapshot.at); $('live-updated').dateTime = snapshot.at || '';
  const manual = core.manual?.active && sameCoreOrder() ? guideProgress(core) : null;
  const paymentConfirmed = store.phase === 'confirming' && store.receipt?.transactionStatus === 'success';
  const runningLabel = operationRunning(operation) ? operationLabels[operation?.action] || actionLabel(operation?.action, manual?.phase, operation?.title) : '';
  const title = paymentConfirmed ? phaseNames.confirming : store.error ? `操作未完成 · ${store.error.code || '查看原因'}` : manual && operationRunning(operation) ? actionLabel(operation?.action || consoleAction(), manual?.phase, manual.phaseLabel) : runningLabel || phaseNames[store.phase] || text(store.phase);
  $('live-phase').textContent = title; $('live-phase').dataset.phase = store.phase || ''; $('live-phase').dataset.titleLength = [...title].length > 8 ? 'long' : 'short'; $('live-order-stage').textContent = title;
  $('live-phase-code').textContent = `${text(store.phase)}${manual ? ` · ${text(core.manual.phase)} / ${text(core.manual.stage)}` : ''}`; $('live-phase-code').dataset.state = paymentConfirmed ? 'unknown' : store.error ? 'fail' : store.phase === 'paid' ? 'pass' : operationRunning(operation) ? 'running' : ['unknown', 'confirming'].includes(store.phase) ? 'unknown' : 'pending';
  const currentAction = consoleAction();
  const detail = store.phase === 'cart' ? '请在商城选购并前往结算。' : store.phase === 'checkout' ? '请在商城付款窗口确认本单。' : store.phase === 'unknown' ? '付款结果待核对；请查询原支付流水。' : store.phase === 'confirming' ? '付款已确认，商户订单待同步。' : store.phase === 'paid' ? '订单已完成。' : currentAction ? `准备${actionLabel(currentAction, core.manual?.phase)}。` : phaseNames[store.phase] || '等待当前操作。';
  $('live-stage-detail').textContent = store.error?.message || (operationRunning(operation) ? `正在${runningLabel || '处理当前步骤'}。` : detail);
  const orderId = currentOrder();
  $('live-order').textContent = orderId ? compactId(orderId) : '尚未结算 · 当前为购物车'; $('live-order').title = orderId || '';
  $('live-order-full').textContent = orderId || '尚未结算'; $('live-order-copy').disabled = !orderId; $('live-order-copy-status').textContent = '';
  $('live-amount').textContent = money(store.order?.amountMinor ?? store.totalMinor, store.currency);
  const index = ['paid', 'confirming'].includes(store.phase) ? 4 : ['paying', 'unknown'].includes(store.phase) ? 3 : store.phase === 'checkout' ? 2 : store.phase === 'verifying' || store.error ? 1 : 0;
  replace($('live-business-progress'), ['选购', '资格验证', '用户确认', '付款', '商户确认'].map((label, current) => `<li data-state="${store.phase === 'paid' ? 'pass' : current === index ? store.error ? 'fail' : 'current' : current < index ? 'pass' : 'pending'}"${current === index ? ' aria-current="step"' : ''}>${current + 1} ${label}</li>`).join(''));
  replace($('live-credential'), badge(statusNames[core.credentialStatus?.status] || text(core.credentialStatus?.status), core.credentialStatus?.status === 'revoked' ? 'fail' : core.credentialStatus?.status === 'active' ? 'pass' : 'pending') + fields([['当前凭证', core.currentCredentialId], ['持有者公钥标识', core.holder?.did], ['签发状态查询', core.credentialStatus?.checkedAt ? time(core.credentialStatus.checkedAt) : core.credentialStatus?.available === false ? '查询不可用' : '当前快照']]));
  replace($('live-device'), badge(device?.locked === true ? '已锁定' : device?.locked === false ? '已解锁' : '状态未返回', device?.locked === true ? 'fail' : device?.locked === false ? 'pass' : 'unknown') + fields([['当前设备', core.currentDeviceId || snapshot.inventory?.currentDeviceId], ['公开密钥指纹', device?.publicKeyFingerprint]]));
  $('live-device-signs').textContent = Number.isSafeInteger(device?.signCount) ? String(device.signCount) : '未返回';
  const proposal = sameCoreOrder() ? core.proposal : null;
  replace($('live-owner'), badge(statusNames[proposal?.status] || '尚无本单授权', proposal?.status === 'APPROVED' ? 'pass' : proposal?.status === 'REJECTED' ? 'fail' : 'pending') + fields([['申请编号', proposal?.id], ['授权编号', sameCoreOrder() ? core.authorization?.id || core.authorization?.document?.authorizationId : null], ['Owner 服务', core.owner?.available === true ? '已连接' : core.owner?.available === false ? '当前不可用' : '状态未返回']]));
  const allowed = store.phase === 'cart' && !securityBusy && !experimentBusy && !faultBusy && !operationRunning(operation);
  for (const button of document.querySelectorAll('[data-security]')) button.disabled = !allowed || button.dataset.security === 'revoke' && !core.currentCredentialId || button.dataset.security === 'lock' && device?.locked === true || button.dataset.security === 'unlock' && device?.locked === false;
  if (!securityBusy && !$('live-security-result').dataset.result) $('live-security-result').textContent = allowed ? '当前操作直接调用设备与签发方服务。' : '购物车阶段可操作。';
  for (const button of document.querySelectorAll('[data-experiment]')) button.disabled = !allowed;
  for (const button of document.querySelectorAll('[data-fault]')) button.disabled = !allowed;
  if (!experimentBusy && !$('live-experiment-note').dataset.result) $('live-experiment-note').textContent = allowed ? '可运行验证实验；结果单独留存。' : '购物车阶段可运行验证实验。';
  replace($('live-actors'), `<pre>${esc(publicJson(snapshot.actors || {}))}</pre>`);
}
function renderTimeline() {
  const target = $('live-events'), atBottom = target.scrollHeight - target.scrollTop - target.clientHeight < 45;
  const events = [...eventMap.values()].sort((a, b) => a.seq - b.seq);
  replace(target, eventsHtml(events));
  if (atBottom) target.scrollTop = target.scrollHeight;
  $('live-event-count').textContent = `${events.length} 条记录${events.length === 500 ? ' · 显示最近 500 条' : ''}`;
}
function renderHistoryOptions() {
  const summaries = Array.isArray(snapshot.history) ? snapshot.history : [];
  const html = '<option value="">当前订单 · 实时跟随</option>' + summaries.map(order => `<option value="${esc(order.orderId)}">${esc(order.orderId)} · ${esc(phaseNames[order.phase] || order.phase)} · ${esc(money(order.totalMinor))}</option>`).join('');
  if ($('live-history').dataset.options !== html) { $('live-history').innerHTML = html; $('live-history').dataset.options = html; }
  $('live-history').value = selectedOrder;
}
function selectedEvidence() { return selectedOrder ? historical : snapshot.store; }
function selectedCore() { return !selectedOrder && sameCoreOrder() ? snapshot.core : null; }
function renderMerchant(record, old) {
  const merchant = record?.merchant, order = record?.order || record?.boundOrder;
  const names = { none: '尚未创建', created: '订单已创建', 'payment-confirmed': '支付已确认，商户待同步', confirmed: '商户已确认' };
  $('live-merchant-status').textContent = merchant ? names[merchant.status] || text(merchant.status) : old ? '未留存商户记录' : '尚未创建订单';
  const items = merchant?.snapshot?.items;
  const rows = Array.isArray(items) ? `<table class="live-merchant-items"><thead><tr><th scope="col">商品</th><th scope="col">数量</th><th scope="col">单价</th><th scope="col">金额</th></tr></thead><tbody>${items.map(item => `<tr><td>${esc(item.name || item.productId)}</td><td>${esc(text(item.quantity))}</td><td>${esc(money(item.unitAmountMinor, merchant.snapshot.currency))}</td><td>${esc(money(item.amountMinor, merchant.snapshot.currency))}</td></tr>`).join('')}</tbody></table>` : '';
  replace($('live-merchant'), merchant && merchant.status !== 'none' ? rows + fields([
    ['商户', merchant.merchantId], ['商户订单', merchant.orderId], ['订单版本', merchant.orderVersion], ['订单快照摘要', merchant.snapshotHash],
    ['确认时间', merchant.confirmedAt ? time(merchant.confirmedAt, true) : '尚未确认'],
    ...(merchant.lastError ? [['同步结果', text(merchant.lastError.message || merchant.lastError)]] : []),
  ], 'live-evidence-facts') : `<p class="live-empty">${old ? '该订单文件未留存商户快照。' : '结算时创建商户订单快照。'}</p>`);
  const canQuery = !old && order?.orderId && ['confirming', 'unknown'].includes(record?.phase);
  $('live-query-payment').hidden = !canQuery;
  $('live-query-payment').disabled = queryBusy || operationRunning();
}
function renderExperiment() {
  const experiment = snapshot.store.experiment;
  if (!experiment || typeof experiment !== 'object') { replace($('live-experiment-result'), '<p class="live-empty">尚无实验记录。</p>'); return; }
  const title = { 'copied-vc': '复制凭证', revoked: '撤销凭证' }[experiment.scenario] || text(experiment.scenario);
  const boolean = value => value === true ? '是' : value === false ? '否' : '未返回';
  const control = experiment.control;
  const outcome = experiment.completion === 'incomplete' || experiment.completion === 'error' || experiment.completion === 'failed' ? '实验未完成' : experiment.expectationMet === true ? '符合预期' : experiment.expectationMet === false ? '与预期不符' : '等待实验结果';
  const sideEffects = experiment.sideEffects;
  const facts = [
    ['完成状态', experiment.completion], ['预期结果', experiment.expected], ['实际结果', experiment.actual],
    ['合法对照请求通过', boolean(control?.accepted)], ['实验请求被拒绝', boolean(experiment.requestRejected)], ['拒绝位置', experiment.rejectionStage],
    ['支付执行次数变化', sideEffects?.paymentExecutionDelta], ['余额保持不变', boolean(sideEffects?.balancesUnchanged)],
  ];
  const trace = experiment.verificationTrace;
  replace($('live-experiment-result'), `<div class="live-experiment-result-heading"><span>${esc(title)} · ${esc(outcome)}</span><code>${esc(text(experiment.id))}</code></div>`
    + `<table class="live-experiment-table"><tbody>${facts.map(([label, value]) => `<tr><th scope="row">${esc(label)}</th><td>${esc(text(value))}</td></tr>`).join('')}</tbody></table>`
    + (control?.verificationTrace ? `<details class="live-experiment-details" data-detail-key="experiment-control-${esc(experiment.id)}"><summary>合法请求的验证记录</summary><div class="live-checks">${compactChecks(control.verificationTrace, 'proposal')}</div></details>` : '')
    + (trace ? `<details class="live-experiment-details" data-detail-key="experiment-request-${esc(experiment.id)}"><summary>实验请求的验证记录</summary><div class="live-checks">${compactChecks(trace, 'proposal')}</div></details>` : '')
    + (experiment.error ? `<p class="live-security-result-error">${esc(text(experiment.error.message || experiment.error))}</p>` : ''));
}
function renderEvidence() {
  const record = selectedEvidence(), core = selectedCore(), old = Boolean(selectedOrder);
  $('live-evidence-mode').textContent = old ? '历史订单 · 只读留存' : '当前订单 · 实时'; $('live-evidence-mode').dataset.state = old ? 'historical' : 'pending';
  $('live-history-note').textContent = old ? '历史证据只读；上方角色图和系统状态仍显示当前订单。' : '当前订单；随状态更新。';
  renderMerchant(record, old);
  if (!record) {
    $('live-proof-status').textContent = '正在读取该订单'; $('live-proof-status').dataset.state = 'pending';
    $('live-verification-count').textContent = '尚无记录'; $('live-proof-note').textContent = '等待该订单的留存验证结果。';
    $('live-trace-select').innerHTML = '<option value="">正在读取验证记录</option>'; $('live-trace-select').dataset.options = ''; $('live-trace-select').disabled = true;
    replace($('live-evidence-summary'), '<p class="live-empty">正在读取该历史订单的已保存证据。</p>'); replace($('live-receipt'), ''); replace($('live-checks'), '<p class="live-empty">等待留存记录。</p>'); replace($('live-materials'), ''); return;
  }
  const order = record.order || record.boundOrder;
  replace($('live-evidence-summary'), fields([['证据所属订单', order?.orderId || (old ? selectedOrder : '尚未结算')], ['记录状态', phaseNames[record.phase] || record.phase], ['金额', money(order?.amountMinor ?? record.totalMinor, order?.currency || 'TEST_USDC')], ['逐笔授权', core?.proposal ? statusNames[core.proposal.status] || core.proposal.status : old ? '仅展示该订单已保存字段' : '尚无本单申请']], 'live-evidence-facts'));
  const receipt = record.receipt;
  const receiptMatches = receipt && order && ['orderId', 'amountMinor', 'currency', 'payerAccount', 'payeeAccount'].every(name => order[name] !== undefined && receipt[name] === order[name]) && (!order.settlement || ['network', 'asset', 'payerAddress', 'payTo'].every(name => receipt.settlement?.[name] === order.settlement[name]));
  replace($('live-receipt'), receipt ? `<div class="${receiptMatches && receipt.transactionStatus === 'success' ? 'live-receipt-success' : 'live-receipt-unconfirmed'}"><h3>${receiptMatches && receipt.transactionStatus === 'success' ? old ? '留存的本地模拟支付回执' : '本单成功回执已返回' : '回执关联待核对'}</h3><p>交易 <code>${esc(text(receipt.transactionHash))}</code></p><p>${esc(money(receipt.amountMinor, receipt.currency))} · ${esc(text(receipt.transactionStatus))}</p><p>付款 ${esc(text(receipt.payerAccount))} → 收款 ${esc(text(receipt.payeeAccount))}</p></div>` : '<p class="mechanism-caption">本订单尚无留存的成功付款回执。Owner 批准、证明生成和验签通过均不代替付款完成。</p>');
  const traces = tracesFor(record, core, { historicalOrder: old });
  const traceId = item => `${item.phase}:${item.trace.outcome}:${traces.indexOf(item)}`;
  const currentTrace = core?.manual?.active ? currentVerificationTrace(core) : null;
  const desiredPhase = core?.manual?.active ? core.manual.phase : record.phase === 'paid' ? 'settle' : 'proposal';
  const pendingCurrent = core?.manual?.active && !currentTrace;
  const pendingValue = `pending:${desiredPhase}`;
  if (!tracePinned || !traces.some(item => traceId(item) === selectedTrace)) {
    const preferred = traces.filter(item => item.phase === desiredPhase).at(-1) || traces.at(-1);
    selectedTrace = pendingCurrent ? pendingValue : preferred ? traceId(preferred) : '';
  }
  const options = (pendingCurrent ? `<option value="${esc(pendingValue)}">${esc(proofPhases[desiredPhase] || desiredPhase)} · 本轮尚无验证结论</option>` : '') + (traces.length ? traces.map(item => `<option value="${esc(traceId(item))}">${esc(proofPhases[item.phase])} · ${esc(item.trace.outcome || '未提供结论')}</option>`).join('') : pendingCurrent ? '' : '<option value="">尚无验证记录</option>');
  if ($('live-trace-select').dataset.options !== options) { $('live-trace-select').innerHTML = options; $('live-trace-select').dataset.options = options; }
  $('live-trace-select').value = selectedTrace; $('live-trace-select').disabled = !traces.length && !pendingCurrent;
  const chosen = traces.find(item => traceId(item) === selectedTrace);
  const verdict = chosen ? verificationVerdict(chosen.trace, { phase: chosen.phase }) : null;
  $('live-proof-status').textContent = verdict?.title || '尚未取得结论'; $('live-proof-status').dataset.state = verdict?.status || 'pending';
  $('live-proof-note').textContent = chosen ? `${chosen.source} · ${proofPhases[chosen.phase]}。${verdict.detail}${tracePinned ? ' 当前为手动回看所选阶段。' : ''}` : pendingCurrent ? `${proofPhases[desiredPhase] || desiredPhase}正在准备本轮材料，尚无本轮验证结论；不沿用其他阶段或挑战的通过记录。` : '尚无本订单的验证者 B 检查记录。';
  $('live-verification-count').textContent = chosen ? `${chosen.trace.steps.filter(step => step.status === 'pass').length} 项通过 / ${chosen.trace.steps.filter(step => step.status === 'fail').length} 项失败 / ${chosen.trace.steps.filter(step => step.status === 'skipped').length} 项未执行` : '尚无记录';
  replace($('live-checks'), chosen ? renderVerificationChecks(chosen.trace, { phase: chosen.phase }) : '<p class="live-empty">本订单尚无验证检查。</p>');
  let materials = '';
  if (core?.manual?.active) materials = ['challenge', 'disclosure', 'device', 'holder', 'owner'].map(kind => renderStepMaterial(core, kind, core.mode)).join('');
  const last = core?.lastResult;
  const wire = last?.wire;
  const publicMaterial = wire ? { phase: last.phase, orderId: wire.context?.paymentOrderId, challenge: wire.context, derivedCredential: wire.proof?.verifiableCredential, holderProof: wire.proof?.holderProof, deviceProof: wire.proof ? Object.fromEntries(Object.entries(wire.proof).filter(([name]) => !['verifiableCredential', 'holderProof'].includes(name))) : undefined } : null;
  materials += `<p class="mechanism-caption">${old ? '仅显示该订单已保存的公开证据；当前进程材料不补入历史。' : '只读展示认证服务返回的公开材料；页面不执行验签。'}</p>`;
  if (publicMaterial) materials += `<pre>${esc(publicJson(publicMaterial))}</pre>`;
  else if (!core?.manual?.active) materials += '<p class="live-empty">该订单尚无完整公开证明材料；检查结果以验证记录为准。</p>';
  replace($('live-materials'), materials);
  $('live-history-events-details').hidden = !old;
  if (old) replace($('live-history-events'), eventsHtml(Array.isArray(record.events) ? record.events : []));
}
function scheduleExpiryRead() {
  clearTimeout(expiryTimer);
  const control = snapshot?.store?.manualControl;
  if (!Number.isFinite(control?.expiresAtUnix) || control.expired || !['verifying', 'paying'].includes(snapshot.store.phase)) return;
  const readKey = `${control.attemptId}:${control.expiresAtUnix}`;
  if (expiryReadKey === readKey) return;
  // A challenge can expire while the presenter explains a stopped step.
  // Re-read once at that deadline; this timer never submits a protocol action.
  expiryTimer = setTimeout(() => {
    expiryReadKey = readKey;
    if (!stopped) refresh().catch(() => {});
  }, Math.min(Math.max(control.expiresAtUnix * 1000 - Date.now() + 40, 0), 2147483647));
}
function consoleAction() {
  const control = snapshot?.store?.manualControl;
  const next = typeof control?.nextAction === 'string' ? control.nextAction : control?.nextAction?.id;
  return control && typeof next === 'string' && control.availableActions?.includes(next) ? next : '';
}
function completedNotice(action) {
  const core = snapshot?.core, store = snapshot?.store || {}, manual = core?.manual || {}, phase = manual.phase;
  if (action === 'issue') return core?.credential ? '凭证已准备。' : '凭证状态待核对。';
  if (action === 'begin-proposal') return manual.challenge?.challengeId ? '认证挑战已返回。' : '认证挑战状态待核对。';
  if (action === 'begin-authorize') return manual.challenge?.challengeId ? '付款前复核挑战已返回。' : '复核挑战状态待核对。';
  if (action === 'begin-settle') return manual.challenge?.challengeId ? '结算挑战已返回。' : '结算挑战状态待核对。';
  if (action === 'derive-vc') return manual.verifiableCredential ? '派生凭证已生成。' : '派生凭证状态待核对。';
  if (action === 'device-sign') return manual.deviceResponse?.signature ? '设备签名已返回。' : '设备签名结果待核对。';
  if (action === 'prove') return manual.holderProof ? '联合持有证明已生成。' : '联合持有证明状态待核对。';
  if (action === 'submit-owner') return core?.proposal ? '授权申请已提交。' : '授权申请状态待核对。';
  if (action === 'sync-owner') return core?.authorization ? '授权状态已同步。' : '授权状态待核对。';
  if (action === 'wallet-sign') return manual.walletSigned === true ? '付款请求签名已返回。' : manual.walletSigningUnconfirmed ? '付款签名结果待核对。' : '付款签名状态待核对。';
  if (action === 'verify') {
    const trace = core && currentVerificationTrace(core), verdict = trace && verificationVerdict(trace, { phase });
    if (verdict?.status === 'pass') return phase === 'settle' ? '付款结果待核对。' : phase === 'authorize' ? '付款前复核通过。' : '资格验证通过。';
    if (verdict?.status === 'fail') return '验证未通过。';
    return '验证结果待核对。';
  }
  if (action === 'confirm-merchant') return store.phase === 'paid' || store.merchant?.status === 'confirmed' ? '商户订单已确认。' : store.receipt?.transactionStatus === 'success' ? '付款已确认，商户订单待同步。' : '付款结果待核对。';
  return action ? `${actionLabel(action, phase)}已返回。` : '';
}
function renderCurrentStep() {
  const target = $('live-current-check');
  if (!target || !snapshot) return;
  const { core, store } = snapshot, action = consoleAction(), control = store.manualControl || {}, manual = core?.manual || {}, phase = manual.phase || control.phase;
  const uncertain = store.phase === 'unknown' || core?.paymentPending === true || core?.manual?.walletSigningUnconfirmed === true;
  let panel = null;
  try { panel = core ? currentStepPanel(core, { action, uncertain, complete: store.phase === 'paid' }) : null; } catch { panel = null; }
  const trace = !uncertain && core && action === 'verify' ? currentVerificationTrace(core) : null;
  const verdict = trace ? verificationVerdict(trace, { phase }) : null;
  const running = manualBusy || manualCancelling || Boolean(store.busy) || operationRunning();
  const state = store.error ? 'fail' : running ? 'running' : store.phase === 'unknown' ? 'unknown' : verdict?.status || (store.phase === 'paid' ? 'pass' : 'pending');
  const stateText = store.error ? '未完成' : running ? '执行中' : store.phase === 'unknown' ? '付款结果待核对' : verdict?.title || (store.phase === 'paid' ? '已完成' : action ? actionLabel(action, phase) : phaseNames[store.phase] || '等待订单');
  const facts = (panel?.facts || []).slice(0, 3).map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(text(value))}</dd></div>`).join('');
  let check = '';
  if (trace) check = `<div class="current-check-result"><span>本步检查</span><strong data-state="${esc(verdict?.status || 'pending')}">${esc(verdict?.title || '待核对')}</strong><p>${esc(verdict?.detail || '已返回检查记录。')}</p><a href="#live-verification-details">查看本步证据</a></div>`;
  else if (action === 'verify') check = '<div class="current-check-result"><span>本步检查</span><strong data-state="pending">等待验证返回</strong><p>本轮只显示与当前订单、阶段和挑战匹配的记录。</p><a href="#live-verification-details">查看验证记录</a></div>';
  else if (action?.startsWith('begin-')) {
    const deadline = Number.isFinite(manual.expiresAtUnix) ? manual.expiresAtUnix : control.expiresAtUnix;
    const expired = manual.expired || control.expired || manual.stage === 'EXPIRED' || control.stage === 'EXPIRED' || Number.isFinite(deadline) && deadline * 1000 <= Date.now();
    const ready = !panel?.starting && manual.challenge?.challengeId && !expired;
    check = `<div class="current-check-result"><span>挑战状态</span><strong data-state="${expired ? 'fail' : ready ? 'pass' : 'pending'}">${expired ? '挑战已过期' : ready ? '挑战有效' : '待获取'}</strong><p>${esc(Number.isFinite(deadline) ? `有效期至 ${time(deadline * 1000, true)}` : '等待当前阶段的挑战。')}</p><a href="#live-material-details">查看挑战材料</a></div>`;
  } else if (action === 'issue') check = `<div class="current-check-result"><span>凭证状态</span><strong data-state="${core?.credential ? 'pass' : 'pending'}">${core?.credential ? '已返回' : '待准备'}</strong><p>凭证材料准备后进入认证挑战。</p><a href="#live-material-details">查看材料</a></div>`;
  else if (action === 'derive-vc') check = `<div class="current-check-result"><span>材料状态</span><strong data-state="${manual.verifiableCredential ? 'pass' : 'pending'}">${manual.verifiableCredential ? '已生成' : '待生成'}</strong><p>派生材料生成后，再由验证者 B 返回检查结果。</p><a href="#live-material-details">查看材料</a></div>`;
  else if (action === 'device-sign') check = `<div class="current-check-result"><span>设备状态</span><strong data-state="${manual.deviceResponse?.signature ? 'pass' : 'pending'}">${manual.deviceResponse?.signature ? '设备签名已返回' : '等待设备签名'}</strong><p>本步只显示设备返回状态。</p><a href="#live-material-details">查看设备材料</a></div>`;
  else if (action === 'prove') check = `<div class="current-check-result"><span>证明材料</span><strong data-state="${manual.holderProof ? 'pass' : 'pending'}">${manual.holderProof ? '联合持有证明已生成' : '等待组合证明'}</strong><p>设备贡献与持有者请求签名分别保留在证明材料中。</p><a href="#live-material-details">查看材料</a></div>`;
  else if (['submit-owner', 'sync-owner'].includes(action)) {
    const proposalStatus = core?.proposal?.status, approved = proposalStatus === 'APPROVED', rejected = proposalStatus === 'REJECTED';
    check = `<div class="current-check-result"><span>用户授权</span><strong data-state="${approved ? 'pass' : rejected ? 'fail' : 'pending'}">${approved ? '用户已批准' : rejected ? '用户已拒绝' : proposalStatus === 'PENDING' ? '等待用户确认' : '尚未提交申请'}</strong><p>用户确认仍在商城完成。</p><a href="#live-evidence-title">查看订单证据</a></div>`;
  } else if (action === 'wallet-sign') {
    const signed = manual.walletSigned === true, uncertainSign = manual.walletSigningUnconfirmed === true;
    check = `<div class="current-check-result"><span>付款请求</span><strong data-state="${signed ? 'pass' : uncertainSign ? 'unknown' : 'pending'}">${signed ? '签名已返回' : uncertainSign ? '签名结果待核对' : '等待钱包签名'}</strong><p>签名结果与付款执行分开记录。</p><a href="#live-material-details">查看材料</a></div>`;
  } else if (action === 'confirm-merchant') {
    const merchantStatus = store.merchant?.status, receipt = store.receipt?.transactionStatus === 'success';
    check = `<div class="current-check-result"><span>商户同步</span><strong data-state="${merchantStatus === 'confirmed' ? 'pass' : receipt ? 'unknown' : 'pending'}">${merchantStatus === 'confirmed' ? '商户已确认' : receipt ? '付款已确认，商户订单待同步' : '等待付款结果'}</strong><p>${receipt ? '可在订单证据中查询原支付流水。' : '付款回执返回后更新商户状态。'}</p><a href="#live-merchant-details">查看商户记录</a></div>`;
  }
  const rawReason = control.reason || store.error?.message;
  target.innerHTML = `<div class="current-step-label"><span>${esc(proofPhases[phase] || phaseNames[store.phase] || '当前阶段')}</span><strong data-state="${esc(state)}">${esc(stateText)}</strong></div>${facts ? `<dl class="current-step-facts">${facts}</dl>` : ''}${check}${manualNotice ? `<p class="live-just-completed"><span>刚完成</span>${esc(manualNotice)}</p>` : ''}${rawReason ? `<details class="current-step-raw"><summary>服务提示</summary><p>${esc(text(rawReason))}</p></details>` : ''}`;
}
function renderManualConsole() {
  const store = snapshot.store, control = store.manualControl || {}, action = consoleAction(), button = $('live-manual-next');
  const running = manualBusy || manualCancelling || Boolean(store.busy) || operationRunning();
  const label = actionLabel(action, snapshot.core?.manual?.phase || control?.phase, control?.label);
  button.dataset.action = action;
  const m = snapshot.core?.manual || store.backend?.manual || {};
  const cancelAllowed = ['verifying', 'checkout'].includes(store.phase) && !m.walletSigned && !m.walletSigningUnconfirmed && !store.backend?.paymentPending && !snapshot.core?.paymentPending;
  $('live-manual-cancel').hidden = !cancelAllowed;
  $('live-manual-cancel').disabled = !cancelAllowed || running || securityBusy || experimentBusy || faultBusy || queryBusy;
  button.disabled = running || !action || !control?.token || securityBusy || experimentBusy || faultBusy || queryBusy;
  button.textContent = manualCancelling ? '正在结束本次认证…' : running ? '正在执行…' : action ? label : store.phase === 'paid' ? '本单已完成' : store.phase === 'checkout' ? '等待商城确认付款' : store.phase === 'cart' ? '等待订单' : '等待可执行步骤';
  const fallback = store.phase === 'cart' ? '请在商城选购并前往结算。' : store.phase === 'checkout' ? '请在商城付款窗口确认本单。' : store.phase === 'paid' ? '本单已完成，可在商城继续购物。' : action ? `准备${label}。` : '请刷新状态并核对当前订单。';
  $('live-manual-status').textContent = manualCancelling ? '正在结束本次认证并返回购物车。' : manualBusy ? '正在等待服务返回。' : [manualNotice, fallback].filter(Boolean).join(' ');
  $('live-manual-status').classList.toggle('live-security-result-error', manualNoticeFailed);
  $('live-manual-status').dataset.stepRevision = String(control?.stepRevision ?? '');
  renderCurrentStep();
}
function render() { if (!snapshot) return; renderSummary(); renderManualConsole(); renderScene(); layoutSceneLabels($('live-scene')); renderTimeline(); renderHistoryOptions(); renderEvidence(); renderExperiment(); }
async function refresh() {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => { const response = await api('/api/live/state'); acceptSnapshot(await response.json()); })().finally(() => { refreshPromise = null; });
  return refreshPromise;
}
function dispatchEventFrame(frame) {
  let name = 'message'; const lines = [];
  for (const line of frame.split('\n')) { if (line.startsWith('event:')) name = line.slice(6).trim(); else if (line.startsWith('data:')) lines.push(line.slice(5).replace(/^ /, '')); }
  if (!lines.length) return;
  let value; try { value = JSON.parse(lines.join('\n')); } catch { return; }
  if (name === 'snapshot') acceptSnapshot(value);
  else if (name === 'system') { addEvent(value); if (snapshot) { $('live-sequence').textContent = String(sequence); renderTimeline(); } }
}
async function connect() {
  if (stopped || !key) return;
  clearTimeout(retryTimer); streamAbort?.abort(); const controller = new AbortController(); streamAbort = controller;
  try {
    connection(retryCount ? '正在重新连接' : '正在连接', 'pending');
    await refresh();
    if (controller.signal.aborted || stopped) return;
    const response = await api(`/api/live/events?after=${sequence}`, undefined, controller.signal);
    if (!response.body) throw new Error('实时事件流不可用');
    connection('实时连接', 'connected'); retryCount = 0;
    const reader = response.body.getReader(), decoder = new TextDecoder(); let buffer = '';
    while (!stopped) {
      const { value, done } = await reader.read(); if (done) break;
      buffer = (buffer + decoder.decode(value, { stream: true })).replace(/\r\n/g, '\n');
      let boundary;
      while ((boundary = buffer.indexOf('\n\n')) !== -1) { dispatchEventFrame(buffer.slice(0, boundary)); buffer = buffer.slice(boundary + 2); }
    }
    if (!stopped) throw new Error('实时连接已断开');
  } catch (error) {
    if (stopped || error.name === 'AbortError') return;
    connection(error.status === 401 || error.status === 403 ? '访问凭据无效，请从演示入口重新打开' : '连接中断 · 保留最后状态', 'disconnected');
    if (error.status === 401 || error.status === 403) return;
    retryCount++; retryTimer = setTimeout(connect, Math.min(1000 * 2 ** Math.min(retryCount, 4), 10000));
  }
}
async function loadHistory(orderId) {
  const requestId = ++historyRequest;
  selectedOrder = orderId; selectedTrace = ''; tracePinned = false; historical = orderId ? historyCache.get(orderId) || null : null; renderEvidence();
  if (!orderId || historical) return;
  try {
    const response = await api(`/api/live/orders/${encodeURIComponent(orderId)}`); const record = await response.json();
    if (requestId !== historyRequest || selectedOrder !== orderId) return;
    const actualId = record.order?.orderId || record.boundOrder?.orderId;
    if (actualId !== orderId) throw new Error('返回证据与所选历史订单不一致');
    historical = record; historyCache.set(orderId, record); renderEvidence();
  } catch (error) { if (requestId === historyRequest) replace($('live-evidence-summary'), `<p class="live-empty">历史证据读取失败：${esc(error.message)}</p>`); }
}
function openRole(evidence) {
  if (!snapshot) return;
  const core = snapshot.core, device = deviceOf();
  const safe = {
    credential: { credentialId: core.currentCredentialId, status: core.credentialStatus, holderDid: core.holder?.did, originalCredential: core.w3c?.originalCredential },
    holder: { holder: core.holder, orderId: currentOrder() },
    device: device,
    verification: { orderId: currentOrder(), traces: tracesFor(snapshot.store, sameCoreOrder() ? core : null).map(item => ({ phase: item.phase, source: item.source, verificationTrace: item.trace })) },
    owner: { owner: core.owner, proposal: sameCoreOrder() && core.proposal ? { id: core.proposal.id, status: core.proposal.status, payment: core.proposal.payment } : null, authorization: sameCoreOrder() ? core.authorization?.document : null },
    receipt: { receipt: snapshot.store.receipt, ledger: core.ledger },
  };
  $('live-role-title').textContent = roleTitles[evidence] || '当前系统公开状态';
  const value = safe[evidence] || {}, status = value.status || value.proposal?.status || value.receipt?.transactionStatus || value.owner?.available;
  replace($('live-role-content'), `<p class="mechanism-caption">实例 ${esc(instanceId)} · 订单 ${esc(currentOrder() || '尚未结算')}。</p>${fields([['角色', roleTitles[evidence] || evidence], ['状态', status === true ? '可用' : status === false ? '不可用' : status || '未提供']])}<details class="role-public-material"><summary>公开材料</summary><pre>${esc(publicJson(value))}</pre></details>`);
  $('live-role-dialog').showModal();
}
$('live-manual-cancel').addEventListener('click', async () => {
  if (manualCancelling || manualBusy || $('live-manual-cancel').hidden || $('live-manual-cancel').disabled) return;
  const revision = snapshot?.store?.revision;
  manualCancelling = true; manualNotice = ''; manualNoticeFailed = false; renderManualConsole();
  try {
    const response = await api('/api/store/new', { revision });
    await response.json(); await refresh();
    manualNotice = '本次结算已取消。可重新选购；设备与凭证管理现在可操作。';
  } catch (error) {
    manualNotice = `未能取消本次结算：${error.message}`; manualNoticeFailed = true;
    await refresh().catch(() => {});
  } finally { manualCancelling = false; renderManualConsole(); }
});
$('live-manual-next').addEventListener('click', async () => {
  const store = snapshot?.store, control = store?.manualControl, action = consoleAction();
  if (manualBusy || !action || !control?.token || $('live-manual-next').disabled) return;
  const body = { action, orderId: store.order?.orderId, revision: store.revision, attemptId: control.attemptId || null, controlToken: control.token };
  manualBusy = true; manualNotice = ''; manualNoticeFailed = false; renderManualConsole();
  try {
    const response = await api('/api/store/manual', body);
    await response.json();
    await refresh();
    manualNotice = completedNotice(action);
  } catch (error) {
    manualNotice = `本步骤未完成：${error.message}`; manualNoticeFailed = true;
    await refresh().catch(() => {});
  } finally { manualBusy = false; renderManualConsole(); }
});
$('live-history').addEventListener('change', event => { loadHistory(event.target.value); });
$('live-trace-select').addEventListener('change', event => { selectedTrace = event.target.value; tracePinned = !selectedTrace.startsWith('pending:'); renderEvidence(); });
$('live-order-copy').addEventListener('click', async () => {
  const orderId = currentOrder();
  if (!orderId) return;
  try { await navigator.clipboard.writeText(orderId); $('live-order-copy-status').textContent = '已复制'; }
  catch { $('live-order-copy-status').textContent = '复制未完成'; }
});
$('live-refresh').addEventListener('click', () => { clearTimeout(retryTimer); connect(); });
$('live-role-close').addEventListener('click', () => $('live-role-dialog').close());
$('live-role-dialog').addEventListener('close', () => { roleDialogReturn?.focus?.(); roleDialogReturn = null; });
$('live-scene').addEventListener('click', event => { const target = event.target.closest('[data-scene-evidence]'); if (target) { roleDialogReturn = target; openRole(target.dataset.sceneEvidence); } });
$('live-query-payment').addEventListener('click', async () => {
  const store = snapshot?.store, orderId = store?.order?.orderId;
  if (queryBusy || selectedOrder || !orderId || !['confirming', 'unknown'].includes(store.phase)) return;
  queryBusy = true; $('live-query-result').textContent = '正在核对原支付流水…'; renderEvidence();
  try {
    const response = await api('/api/store/query', { orderId, revision: store.revision });
    await response.json(); await refresh();
    $('live-query-result').textContent = snapshot.store.phase === 'paid'
      ? '商户订单已确认。'
      : snapshot.store.phase === 'cart'
        ? '未发现可核对的原付款记录，旧订单已解除锁定；购物车商品已保留。'
        : '已读取原流水；结果以当前订单状态为准。';
  } catch (error) { $('live-query-result').textContent = `核对未完成：${error.message}`; await refresh().catch(() => {}); }
  finally { queryBusy = false; renderEvidence(); }
});
for (const button of document.querySelectorAll('[data-experiment]')) button.addEventListener('click', async () => {
  if (experimentBusy || securityBusy || faultBusy || snapshot?.store?.phase !== 'cart' || operationRunning()) return;
  experimentBusy = true; $('live-experiment-note').dataset.result = ''; $('live-experiment-note').textContent = '正在执行合法对照与实验请求…'; $('live-experiment-note').classList.remove('live-security-result-error'); renderSummary();
  try {
    const response = await api('/api/store/experiment', { scenario: button.dataset.experiment });
    await response.json(); await refresh();
    $('live-experiment-note').textContent = '实验服务已返回；对照结果、拒绝位置与余额变化如下。';
  } catch (error) { $('live-experiment-note').textContent = `实验未完成：${error.message}`; $('live-experiment-note').classList.add('live-security-result-error'); await refresh().catch(() => {}); }
  finally { experimentBusy = false; $('live-experiment-note').dataset.result = 'true'; renderSummary(); }
});
for (const button of document.querySelectorAll('[data-fault]')) button.addEventListener('click', async () => {
  if (faultBusy || experimentBusy || securityBusy || snapshot?.store?.phase !== 'cart' || operationRunning()) return;
  faultBusy = true; $('live-fault-result').textContent = '正在设置商户同步故障…'; $('live-fault-result').classList.remove('live-security-result-error'); renderSummary();
  try {
    const response = await api('/api/store/fault', { action: button.dataset.fault });
    const result = await response.json(); await refresh();
    $('live-fault-result').textContent = result.message || snapshot.store.message || '商户服务已返回设置结果。';
  } catch (error) { $('live-fault-result').textContent = `设置未完成：${error.message}`; $('live-fault-result').classList.add('live-security-result-error'); await refresh().catch(() => {}); }
  finally { faultBusy = false; renderSummary(); }
});
for (const button of document.querySelectorAll('[data-security]')) button.addEventListener('click', async () => {
  if (securityBusy || experimentBusy || faultBusy || snapshot?.store?.phase !== 'cart' || operationRunning()) return;
  securityBusy = true; $('live-security-result').dataset.result = ''; $('live-security-result').textContent = '正在更新设备或凭证状态…'; renderSummary();
  try {
    const response = await api('/api/store/security', { action: button.dataset.security });
    await response.json();
    await refresh(); $('live-security-result').textContent = '操作已返回，凭证与设备状态已更新。'; $('live-security-result').classList.remove('live-security-result-error');
  } catch (error) { $('live-security-result').textContent = error.message; $('live-security-result').classList.add('live-security-result-error'); await refresh().catch(() => {}); }
  finally { securityBusy = false; $('live-security-result').dataset.result = 'true'; renderSummary(); }
});
window.addEventListener('pagehide', () => { stopped = true; clearTimeout(retryTimer); clearTimeout(expiryTimer); streamAbort?.abort(); });
if (key) connect();
else connection('请从本地演示入口打开此页', 'disconnected');
