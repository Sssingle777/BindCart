'use strict';

const $ = (id) => document.getElementById(id);
const actionButtons = ['issue-button', 'invoke-button', 'demo-button', 'revoke-button'];
const deviceButtons = ['device-lock-button', 'device-unlock-button'];
const paymentButtons = ['payment-approve-button', 'payment-sync-button', 'payment-pay-button', 'payment-retry-button', 'payment-new-button', 'payment-demo-button'];
const uiKeyPattern = /^[A-Za-z0-9_-]{43}$/;
let demoUiKey = '';
const entryKey = /^#key=([A-Za-z0-9_-]{43})$/.exec(location.hash);
if (entryKey) {
  demoUiKey = entryKey[1];
  try { sessionStorage.setItem('a2a-did-vc-ui-key', demoUiKey); } catch { /* The key remains available for this page load. */ }
  history.replaceState(history.state, '', `${location.pathname}${location.search}`);
} else {
  try {
    const savedKey = sessionStorage.getItem('a2a-did-vc-ui-key');
    if (savedKey && uiKeyPattern.test(savedKey)) demoUiKey = savedKey;
  } catch { /* Access still works through a fresh console link. */ }
}
let currentState = null;
let currentDeviceInfo = null;
let currentPaymentState = null;
let currentPaymentFlow = [];
let busy = false;
const settlementFields = ['network', 'asset', 'payTo', 'payerAddress'];
const verificationView = window.DemoVerification.create($('verification-trace'));

const requestExample = {
  jsonrpc: '2.0',
  id: 'demo-request-1',
  method: 'message/send',
  params: {
    message: {
      kind: 'message',
      messageId: 'demo-message-1',
      role: 'user',
      parts: [
        { kind: 'data', data: { scope: 'demo:echo', text: '你好，Agent B！' } },
      ],
      extensions: ['https://example.org/a2a-did-vc/v2'],
    },
  },
};

const auditLabels = {
  credential_issued: '签发 VC',
  credential_revoked: '撤销 VC',
  authenticated: '身份与权限验证通过',
  request_verified: '请求校验通过',
  request_rejected: '请求被拒绝',
  task_completed: 'A2A 任务完成',
  task_created: '创建 A2A 任务',
  'credential.issued': '签发 VC',
  'credential.revoked': '撤销 VC',
  'a2a.accepted': 'A2A 请求通过验证',
  'a2a.rejected': 'A2A 请求被拒绝',
  'device.locked': 'jCardSim 设备已锁定',
  'device.unlocked': 'jCardSim 设备已解锁',
  'device.signed': 'jCardSim 设备已签署请求',
  device_locked: 'jCardSim 设备已锁定',
  device_unlocked: 'jCardSim 设备已解锁',
  device_signed: 'jCardSim 设备已签署请求',
  device_rejected: 'jCardSim 设备拒绝请求',
  payment_authorized: '用户已批准单笔授权',
  payment_executed: '本地测试链付款已执行',
  payment_idempotent: '返回已有付款回执',
  payment_rejected: '本地测试链付款被拒绝',
};

function stringify(value) {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

function valueText(value, fallback = '—') {
  if (value === null || value === undefined || value === '') return fallback;
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function setText(id, value, fallback = '—') {
  $(id).textContent = valueText(value, fallback);
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(typeof value === 'number' && value < 1e12 ? value * 1000 : value);
  return Number.isNaN(date.getTime()) ? valueText(value) : date.toLocaleString('zh-CN', { hour12: false });
}

function formatMoney(amountMinor, currency, decimals = currency === 'TEST_USDC' ? 6 : undefined) {
  if (!Number.isSafeInteger(amountMinor) || typeof currency !== 'string' ||
      !Number.isInteger(decimals) || decimals < 0 || decimals > 18) return '—';
  const units = BigInt(amountMinor);
  const absolute = units < 0n ? -units : units;
  const scale = 10n ** BigInt(decimals);
  const fraction = decimals ? `.${(absolute % scale).toString().padStart(decimals, '0')}` : '';
  return `${units < 0n ? '-' : ''}${absolute / scale}${fraction} ${currency}`;
}

function validSettlement(settlement) {
  return settlement && typeof settlement === 'object' && !Array.isArray(settlement) &&
    settlementFields.every(key => typeof settlement[key] === 'string' && settlement[key].length > 0);
}

function renderPaymentFlow(flow) {
  const labels = { 'input-required': '等待支付材料', 'payment-submitted': '已提交支付材料', completed: '支付任务完成' };
  currentPaymentFlow = Array.isArray(flow) ? flow.filter(step => typeof step === 'string') : [];
  const list = $('payment-flow');
  list.replaceChildren();
  if (!currentPaymentFlow.length) {
    const item = document.createElement('li');
    item.textContent = '等待服务端返回支付流程';
    list.append(item);
  }
  currentPaymentFlow.forEach(step => {
    const item = document.createElement('li');
    const label = document.createElement('strong');
    label.textContent = labels[step] || step;
    const code = document.createElement('code');
    code.textContent = step;
    item.className = step === 'completed' ? 'completed' : '';
    item.append(label, code);
    list.append(item);
  });
}

function paymentOutcomeText(outcome) {
  const labels = { EXECUTED: '本笔模拟支付已完成', ALREADY_PROCESSED: '已返回本订单已有结果' };
  return labels[outcome] ? `${labels[outcome]}（${outcome}）` : valueText(outcome, '尚未执行');
}

function proposalStatusText(status) {
  return { PENDING: '等待用户授权', APPROVED: '用户已批准', REJECTED: '用户已拒绝授权', EXPIRED: '提案或授权已过期' }[status] || '尚未提交';
}

function setFeedback(title, message, kind = 'neutral') {
  $('feedback').className = `feedback ${kind}`;
  setText('feedback-title', title);
  setText('feedback-message', message);
}

function setPaymentFeedback(title, message, kind = 'neutral') {
  setFeedback(title, message, kind);
  $('payment-feedback').className = `feedback ${kind}`;
  setText('payment-feedback-title', title);
  setText('payment-feedback-message', message);
}

function updateButtons() {
  window.DemoEmbed?.setBusy('identity', busy);
  const unavailable = busy || !demoUiKey;
  actionButtons.forEach((id) => { $(id).disabled = unavailable; });
  $('revoke-button').disabled = unavailable || !currentState?.credential || currentState.credential.revoked;
  $('device-lock-button').disabled = unavailable || !currentDeviceInfo || currentDeviceInfo.locked;
  $('device-unlock-button').disabled = unavailable || !currentDeviceInfo || !currentDeviceInfo.locked;
  $('refresh-audit').disabled = unavailable;
  paymentButtons.forEach((id) => { $(id).disabled = unavailable || !currentPaymentState?.order; });
  const ownerApproved = Boolean(currentPaymentState?.authorization && currentPaymentState?.proposal?.status === 'APPROVED' && currentPaymentState?.owner?.available !== false);
  $('payment-sync-button').disabled ||= !currentPaymentState?.proposal;
  for (const id of ['payment-pay-button', 'payment-retry-button', 'payment-demo-button']) $(id).disabled ||= !ownerApproved;
  $('actions-title').closest('section').setAttribute('aria-busy', String(busy));
  $('device-card').setAttribute('aria-busy', String(busy));
  $('payment-panel').setAttribute('aria-busy', String(busy));
}

async function api(path, body) {
  if (!demoUiKey) throw new Error('请使用启动终端给出的控制台链接进入演示。');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { Accept: 'application/json', 'X-Demo-UI-Key': demoUiKey, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
      cache: 'no-store',
    });
    let data;
    try { data = await response.json(); } catch {
      throw new Error(`服务端未返回有效 JSON（HTTP ${response.status}）。请确认演示服务正在运行。`);
    }
    if (!response.ok) {
      const error = new Error(data.error?.code === 'UI_ACCESS_DENIED' ? '控制台访问权限已失效，请使用当前启动终端给出的控制台链接重新进入。' : data.error?.message || data.message || `请求失败（HTTP ${response.status}）`);
      error.code = data.error?.code;
      error.data = data;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('请求超过 30 秒未完成，请检查服务端状态后重试。');
    if (error instanceof TypeError) throw new Error('无法连接演示服务，请确认本地服务已启动。');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function publicDidDocument(state, role, did) {
  const documents = state.didDocuments || state.documents || {};
  const document = documents[role] || documents[did] || state[`${role}Document`];
  return document || { id: did, note: '服务端未返回完整公开 DID 文档。' };
}

function renderState(state) {
  currentState = state;
  const identities = [
    ['issuer', 'issuer', state.issuerDid],
    ['agent-a', 'agentA', state.agentADid],
    ['agent-b', 'agentB', state.agentBDid],
    ['device', 'device', state.deviceDid],
  ];
  identities.forEach(([prefix, role, did]) => {
    setText(`${prefix}-did`, did, '身份暂不可用');
    setText(`${prefix}-document`, stringify(publicDidDocument(state, role, did)));
  });
  const credential = state.credential;
  const document = credential?.document || {};
  const subject = Array.isArray(document.credentialSubject) ? document.credentialSubject[0] : document.credentialSubject;
  const rawScope = subject?.scopes || subject?.scope || subject?.permissions || subject?.capability?.scope || credential?.scope;
  setText('credential-id', credential?.id || document.id);
  setText('credential-scope', rawScope);
  setText('credential-device-did', subject?.deviceDid);
  setText('service-url', state.agentBUrl);
  setText('credential-expiry', formatDate(document.validUntil || document.expirationDate || credential?.expiresAt));
  setText('credential-document', credential ? stringify(document) : '尚未准备凭证');
  setText('credential-token', credential?.token, '尚未准备凭证');
  const expiry = document.validUntil || document.expirationDate;
  const expired = Boolean(expiry && !Number.isNaN(Date.parse(expiry)) && Date.parse(expiry) <= Date.now());
  const stateLabel = !credential ? ['尚未准备凭证', 'neutral'] : credential.revoked ? ['已撤销', 'error'] : expired ? ['已过期', 'error'] : ['已签发 · 未撤销', 'success'];
  $('credential-status').textContent = stateLabel[0];
  $('credential-status').className = `status-tag ${stateLabel[1]}`;
  updateButtons();
}

function renderDevice(info) {
  currentDeviceInfo = info;
  const status = !info ? ['设备不可用', 'error'] : info.locked ? ['已锁定 · 拒绝新签名', 'error'] : ['已解锁 · 可签名', 'success'];
  setText('device-status', status[0]);
  $('device-status').className = `status-tag ${status[1]}`;
  setText('device-info', info ? stringify({ ...info, url: currentState?.deviceUrl }) : '设备状态读取失败，请确认 jCardSim Java Card 仿真进程正在运行。');
  if (info?.did) setText('device-did', info.did);
  updateButtons();
}

function renderPayment(state) {
  const previousOrderId = currentPaymentState?.order?.orderId;
  currentPaymentState = state;
  const order = state?.order;
  const authorization = state?.authorization;
  const ledger = state?.ledger;
  const settlement = order?.settlement;
  const money = formatMoney(order?.amountMinor, order?.currency);
  const lastResult = state?.lastResult;
  const proposal = state?.proposal;
  const owner = state?.owner;
  const status = !state ? ['支付服务不可用', 'error'] : owner?.available === false ? ['用户授权服务暂不可用', 'error'] : ['EXECUTED', 'ALREADY_PROCESSED'].includes(lastResult?.outcome) ? [paymentOutcomeText(lastResult.outcome), 'success'] : lastResult ? ['付款结果待核对', 'neutral'] : authorization && proposal?.status === 'APPROVED' ? ['用户已批准', 'success'] : [proposalStatusText(proposal?.status), ['REJECTED', 'EXPIRED'].includes(proposal?.status) ? 'error' : 'neutral'];
  setText('payment-status', status[0]);
  $('payment-status').className = `status-tag ${status[1]}`;
  setText('payment-amount', money);
  setText('payment-order-id', order?.orderId);
  setText('payment-payer', order?.payerAccount);
  setText('payment-payee', order?.payeeAccount);
  setText('payment-network', settlement?.network);
  setText('payment-asset', settlement?.asset);
  setText('payment-pay-to', settlement?.payTo);
  setText('payment-payer-address', settlement?.payerAddress);
  setText('payment-chain-info', state?.paymentInfo ? stringify(state.paymentInfo) : '等待服务端返回本地测试链配置');
  setText('payment-authorization-id', authorization?.id, '尚未确认');
  setText('payment-proposal-id', proposal?.id, '尚未提交');
  setText('payment-proposal-status', proposalStatusText(proposal?.status));
  setText('payment-owner-did', owner?.did);
  const ownerLink = $('payment-owner-link');
  ownerLink.href = '/#view=owner';
  ownerLink.textContent = '前往付款授权 →';
  setText('payment-owner-availability', owner?.available === false ? `用户授权状态读取失败：${valueText(owner.error?.message || owner.error, '请确认独立用户授权服务正在运行。')}` : '前往付款授权后，仍须使用启动终端提供的用户授权专用权限；控制台权限不能代替用户授权。');
  setText('payment-execution-count', ledger?.executionCount);
  setText('payment-outcome', paymentOutcomeText(lastResult?.outcome));
  setText('payment-transaction-hash', lastResult?.receipt?.transactionHash, '尚未取得链上交易回执');
  const settlementResponse = lastResult?.settlementResponse || lastResult?.receipt?.settlementResponse;
  setText('payment-settlement-response', settlementResponse ? stringify(settlementResponse) : '尚无 x402 结算响应');
  renderPaymentFlow(state ? state.paymentFlow || lastResult?.paymentFlow || (previousOrderId === order?.orderId ? currentPaymentFlow : []) : []);
  setText('payment-authorization', authorization ? stringify(authorization) : '尚未确认授权');
  setText('payment-last-result', lastResult ? stringify(lastResult) : '尚无执行结果');
  setText('payment-receipts', ledger ? stringify(ledger.receipts || []) : '链上状态读取失败');
  const balances = $('payment-balances');
  balances.replaceChildren();
  const accounts = Array.isArray(ledger?.accounts) ? ledger.accounts : [];
  if (!accounts.length) {
    const empty = document.createElement('li');
    empty.className = 'subtle';
    empty.textContent = state ? '服务端尚未返回链上代币余额' : '链上状态读取失败';
    balances.append(empty);
  }
  accounts.forEach((account) => {
    const row = document.createElement('li');
    const label = document.createElement('span');
    label.textContent = valueText(account.id);
    const balance = document.createElement('strong');
    balance.textContent = formatMoney(account.balanceMinor, ledger.currency, ledger.decimals);
    row.append(label, balance);
    balances.append(row);
  });
  const credential = currentState?.credential;
  const subject = credential?.document?.credentialSubject;
  const scopes = (Array.isArray(subject) ? subject[0] : subject)?.scopes;
  const prerequisite = !state ? '支付服务暂不可用，请检查服务端状态。' : !credential ? '请先签发 VC，再提交付款授权申请。' : credential.revoked ? '当前 VC 已撤销；请先签发新 VC，再提交付款授权申请。' : !Array.isArray(scopes) || !scopes.includes('payments:pay') ? '当前 VC 没有 payments:pay 权限；请先签发新 VC。' : '先提交订单，在付款授权页面批准后，点击“同步用户授权”再付款。';
  setText('payment-prerequisite', prerequisite);
  updateButtons();
}

function renderAudit(data) {
  const container = $('audit-events');
  container.replaceChildren();
  const events = Array.isArray(data.events) ? data.events : [];
  if (!events.length) {
    const empty = document.createElement('li');
    empty.className = 'subtle';
    empty.textContent = '暂无审计事件。签发或调用后可查看服务端记录。';
    container.append(empty);
    return;
  }
  [...events].sort((a, b) => new Date(b.time || b.timestamp).getTime() - new Date(a.time || a.timestamp).getTime()).forEach((event) => {
    const item = document.createElement('li');
    const heading = document.createElement('div');
    heading.className = 'audit-event-heading';
    const name = document.createElement('strong');
    name.textContent = auditLabels[event.event] || event.event || event.type || '审计事件';
    const time = document.createElement('time');
    time.textContent = formatDate(event.time || event.timestamp);
    heading.append(name, time);
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = event.code ? `结果 ${event.code} · 查看记录` : '查看记录';
    const content = document.createElement('pre');
    content.className = 'json-panel';
    content.textContent = stringify(event);
    details.append(summary, content);
    item.append(heading, details);
    container.append(item);
  });
}

async function refresh() {
  const results = await Promise.allSettled([api('/api/state'), api('/api/audit'), api('/api/card'), api('/api/device'), api('/api/payment')]);
  const errors = [];
  if (results[0].status === 'fulfilled') {
    renderState(results[0].value);
    $('connection').className = 'connection connected';
    setText('connection', '服务已连接');
  } else {
    $('connection').className = 'connection failed';
    setText('connection', '服务连接失败');
    errors.push(results[0].reason.message);
  }
  if (results[1].status === 'fulfilled') renderAudit(results[1].value);
  else errors.push(`审计记录读取失败：${results[1].reason.message}`);
  if (results[2].status === 'fulfilled') setText('agent-card', stringify(results[2].value));
  else {
    setText('agent-card', `AgentCard 读取失败：${results[2].reason.message}`);
    errors.push(`AgentCard 读取失败：${results[2].reason.message}`);
  }
  if (results[3].status === 'fulfilled') renderDevice(results[3].value);
  else {
    renderDevice(null);
    errors.push(`设备状态读取失败：${results[3].reason.message}`);
  }
  if (results[4].status === 'fulfilled') renderPayment(results[4].value);
  else {
    renderPayment(null);
    errors.push(`支付状态读取失败：${results[4].reason.message}`);
  }
  return errors;
}

function showResponse(data, summary) {
  $('result-empty').hidden = true;
  $('demo-results').hidden = true;
  $('response-details').hidden = false;
  $('response-details').open = false;
  $('trace-selection-hint').hidden = true;
  setText('response-json', stringify(data));
  setText('result-summary', summary);
  const deviceVerified = data.verification?.deviceSignature === true;
  $('verification-summary').hidden = !deviceVerified;
  if (deviceVerified) setText('verification-summary', `jCardSim 设备签名验证通过 · 设备 ${valueText(data.verification.deviceDid, '详见响应 JSON')}`);
  verificationView.render(data.verificationTrace, { label: summary, error: data.error?.message });
}

function beginResult(message) {
  $('result-empty').hidden = true;
  $('demo-results').hidden = true;
  $('demo-results-body').replaceChildren();
  $('trace-selection-hint').hidden = true;
  $('verification-summary').hidden = true;
  $('response-details').hidden = true;
  setText('response-json', '本次操作进行中，等待服务端响应。');
  setText('result-summary', '本次操作进行中');
  verificationView.loading(message);
}

function showDemo(data) {
  const results = Array.isArray(data.results) ? data.results : [];
  showResponse(data, `已通过 ${data.passed ?? results.filter((item) => item.pass === true).length} / ${data.total ?? results.length} 项`);
  $('response-details').open = false;
  const body = $('demo-results-body');
  body.replaceChildren();
  results.forEach((result, index) => {
    const row = document.createElement('tr');
    const name = document.createElement('td');
    const select = document.createElement('button');
    select.type = 'button';
    select.className = 'trace-case-button';
    select.textContent = valueText(result.name, '未命名测试');
    select.setAttribute('aria-pressed', String(index === 0));
    const selectCase = () => {
      body.querySelectorAll('tr').forEach(item => item.classList.remove('trace-selected'));
      body.querySelectorAll('.trace-case-button').forEach(item => item.setAttribute('aria-pressed', 'false'));
      row.classList.add('trace-selected');
      select.setAttribute('aria-pressed', 'true');
      $('verification-summary').hidden = true;
      verificationView.render(result.verificationTrace, { label: valueText(result.name, '所选用例'), traces: result.verificationTraces, message: '服务端未返回此用例的验证轨迹。请结合预期、实际结果与完整响应查看。' });
      setText('response-json', stringify(result));
    };
    select.addEventListener('click', () => { selectCase(); window.DemoVerification.focus($('verification-trace')); });
    name.append(select);
    if (result.detail) {
      const detail = document.createElement('span');
      detail.className = 'case-detail';
      detail.textContent = valueText(result.detail);
      name.append(detail);
    }
    row.append(name);
    ['expected', 'actual'].forEach((key) => {
      const cell = document.createElement('td');
      cell.textContent = valueText(result[key]);
      row.append(cell);
    });
    const verdict = document.createElement('td');
    verdict.className = result.pass === true ? 'case-pass' : 'case-fail';
    verdict.textContent = result.pass === true ? '✓ 符合预期' : '✕ 不符合预期';
    row.append(verdict);
    body.append(row);
    if (index === 0) selectCase();
  });
  $('demo-results').hidden = !results.length;
  $('trace-selection-hint').hidden = !results.length;
}

function paymentProposalBody() {
  const order = currentPaymentState?.order;
  if (!order || !Number.isSafeInteger(order.amountMinor) || order.amountMinor <= 0 ||
      !['orderId', 'payerAccount', 'payeeAccount', 'currency'].every((key) => typeof order[key] === 'string' && order[key].length > 0) ||
      order.currency !== 'TEST_USDC' || !validSettlement(order.settlement)) {
    throw new Error('没有可提交的服务端订单，请刷新页面后重试。');
  }
  const { orderId, payerAccount, payeeAccount, amountMinor, currency, settlement } = order;
  return { payment: { orderId, payerAccount, payeeAccount, amountMinor, currency, settlement: structuredClone(settlement) } };
}

async function runPaymentAction(action) {
  if (busy) return;
  busy = true;
  updateButtons();
  const labels = { propose: '正在提交付款授权申请…', sync: '正在同步用户授权…', pay: '正在提交已授权的 x402 付款…', retry: '正在以新挑战重试同一订单…', new: '正在创建待提交订单…', demo: '正在验收已授权订单…' };
  beginResult(labels[action]);
  setPaymentFeedback(labels[action], '余额与执行结果均以服务端返回为准。');
  try {
    const body = action === 'propose' ? paymentProposalBody() : {};
    const result = await api(`/api/payment/${action}`, body);
    if (Array.isArray(result.paymentFlow)) renderPaymentFlow(result.paymentFlow);
    if (result.ok === false) {
      showResponse(result, '支付操作被拒绝');
      setPaymentFeedback('支付操作被拒绝', `${valueText(result.error?.code, '验证失败')}：${valueText(result.error?.message, '服务端拒绝了该请求。')}`, 'error');
    } else if (action === 'demo') {
      showDemo(result);
      const total = result.total ?? result.results?.length ?? 0;
      const passed = result.passed ?? result.results?.filter((item) => item.pass === true).length ?? 0;
      const allPassed = total > 0 && passed === total;
      setPaymentFeedback(allPassed ? '支付验收符合预期' : '支付验收存在未通过项', `${passed} / ${total} 项符合预期。请查看链上余额、累计执行次数与交易回执，核对本次测试代币付款和重复请求结果。`, allPassed ? 'success' : 'error');
    } else if (action === 'propose') {
      showResponse(result, '订单提案接口已返回');
      setPaymentFeedback('付款授权申请已提交', '前往“付款授权”，核对订单并批准；随后回到本页同步授权。提交申请不会签署授权或执行付款。', 'success');
    } else if (action === 'sync') {
      showResponse(result, '用户授权同步结果已返回');
      setPaymentFeedback('用户授权状态已同步', '请查看当前提案状态。只有用户在付款授权页面批准并返回有效授权后，付款与支付验收按钮才会启用。');
    } else if (action === 'new') {
      showResponse(result, '新订单接口已返回');
      renderPaymentFlow([]);
      setPaymentFeedback('已创建待提交订单', '请提交新订单请求用户授权，并在付款授权页面核对条款。此前的链上交易记录仍然保留。', 'success');
    } else {
      const paymentResult = result.paymentResult;
      if (!paymentResult || typeof paymentResult.outcome !== 'string' || !paymentResult.receipt) {
        const error = new Error('服务端未返回完整付款结果，请检查完整响应及账本状态。');
        error.data = result;
        throw error;
      }
      showResponse(result, `本地测试链付款：${paymentOutcomeText(paymentResult.outcome)}`);
      setPaymentFeedback('服务端已返回付款结果', `${paymentOutcomeText(paymentResult.outcome)}。请核对链上余额、交易哈希与 x402 结算响应。`, 'success');
    }
  } catch (error) {
    if (error.data) showResponse(error.data, '支付操作被拒绝或执行失败');
    else showResponse({ source: 'browser', error: { message: error.message } }, '暂未取得本次支付结果');
    setPaymentFeedback(error.data ? '支付操作未完成' : '暂未取得本次支付结果', `${error.code ? `${error.code}：` : ''}${error.message}`, 'error');
  } finally {
    const errors = await refresh();
    if (errors.length) setPaymentFeedback('状态刷新未完成', errors.join('；'), 'error');
    busy = false;
    updateButtons();
  }
}

async function runAction(action) {
  if (busy) return;
  busy = true;
  updateButtons();
  const loading = { issue: '正在签发 VC…', invoke: '正在发起 A2A 调用并验证双签名…', demo: '正在运行安全用例…', revoke: '正在撤销凭证…', 'device-lock': '正在锁定 jCardSim 设备…', 'device-unlock': '正在解锁 jCardSim 设备…' };
  beginResult(loading[action]);
  setFeedback(loading[action], '结果由本地服务返回，请稍候。');
  try {
    const isDeviceAction = action === 'device-lock' || action === 'device-unlock';
    const result = await api(isDeviceAction ? '/api/device/lock' : `/api/${action}`, isDeviceAction ? { locked: action === 'device-lock' } : {});
    if (result.ok === false) {
      showResponse(result, '调用被拒绝');
      setFeedback('调用被拒绝', `${valueText(result.error?.code, '验证失败')}：${valueText(result.error?.message, '服务端拒绝了该请求。')}`, 'error');
    } else if (isDeviceAction) {
      renderDevice(result);
      showResponse(result, action === 'device-lock' ? 'jCardSim 设备已锁定' : 'jCardSim 设备已解锁');
      setFeedback(action === 'device-lock' ? '设备已锁定' : '设备已解锁', action === 'device-lock' ? '设备已停止签发新证明，正常调用将被拒绝。此前已签发且未过期的证明仍可能执行；撤销 VC 可阻止后续执行。' : '设备允许演示服务请求第二份签名；持有有效 VC 时可正常调用 A2A。', 'success');
    } else if (action === 'demo') {
      showDemo(result);
      const total = result.total ?? result.results?.length ?? 0;
      const passed = result.passed ?? result.results?.filter((item) => item.pass === true).length ?? 0;
      const allPassed = total > 0 && passed === total;
      setFeedback(allPassed ? '安全演示符合预期' : '安全演示存在未通过项', `${passed} / ${total} 项符合预期。包含“设备调用权限也泄露时仍可通过”的边界用例。设备已恢复解锁，当前 VC 已撤销。`, allPassed ? 'success' : 'error');
    } else if (action === 'issue') {
      showResponse(result, '签发接口已返回');
      setFeedback('VC 已签发', '凭证已绑定持有者 A 与 jCardSim 设备。设备解锁时可正常调用 A2A，观察双签名校验结果。', 'success');
    } else if (action === 'revoke') {
      showResponse(result, '撤销接口已返回');
      setFeedback('撤销请求已完成', '再次调用可观察撤销后的拒绝结果；重新签发可恢复演示。', 'success');
    } else {
      const task = result.task;
      showResponse(result, task?.id ? `任务 ${task.id}` : 'A2A 调用成功');
      setFeedback('A2A 调用成功', `验证者 B 已返回任务结果${task?.status?.state ? `，状态：${task.status.state}` : ''}。${result.verification?.deviceSignature === true ? 'jCardSim 设备的请求签名验证通过。' : '展开响应可查看任务及验证信息。'}`, 'success');
    }
  } catch (error) {
    if (error.data) showResponse(error.data, '服务端拒绝或执行失败');
    else showResponse({ source: 'browser', error: { message: error.message } }, '浏览器请求未完成');
    setFeedback('操作未完成', `${error.code ? `${error.code}：` : ''}${error.message}`, 'error');
  } finally {
    const errors = await refresh();
    if (errors.length) setFeedback('状态刷新未完成', errors.join('；'), 'error');
    busy = false;
    updateButtons();
  }
}

actionButtons.forEach((id) => {
  const action = id.replace('-button', '');
  $(id).addEventListener('click', () => { void runAction(action); });
});
deviceButtons.forEach((id) => {
  const action = id.replace('-button', '');
  $(id).addEventListener('click', () => { void runAction(action); });
});
paymentButtons.forEach((id) => {
  const action = id === 'payment-approve-button' ? 'propose' : id.replace('payment-', '').replace('-button', '');
  $(id).addEventListener('click', () => { void runPaymentAction(action); });
});

window.addEventListener('demo:activate', () => {
  if (busy || !demoUiKey) return;
  busy = true;
  updateButtons();
  void refresh().then(errors => {
    if (errors.length) setFeedback('状态刷新未完成', errors.join('；'), 'error');
  }).finally(() => { busy = false; updateButtons(); });
});

$('refresh-audit').addEventListener('click', async () => {
  $('refresh-audit').disabled = true;
  try { renderAudit(await api('/api/audit')); }
  catch (error) { setFeedback('审计刷新失败', error.message, 'error'); }
  finally { updateButtons(); }
});

$('copy-request').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(JSON.stringify(requestExample, null, 2));
    setText('copy-request', '已复制');
    setTimeout(() => setText('copy-request', '复制 JSON'), 1800);
  } catch {
    setFeedback('未能自动复制', '浏览器不允许访问剪贴板，请从 A2A 请求示例中选中文字复制。');
  }
});

setText('request-example', stringify(requestExample));
busy = Boolean(demoUiKey);
updateButtons();
if (!demoUiKey) {
  setText('connection', '等待控制台链接');
  setText('credential-status', '未连接');
  setText('device-status', '未连接');
  setText('payment-status', '未连接');
  setFeedback('请从控制台链接进入', '请使用启动终端给出的控制台链接进入演示。此页面没有调用设备的访问权限。');
} else {
  void refresh().then((errors) => {
    if (errors.length) setFeedback('初始化未完成', errors.join('；'), 'error');
    else if (currentState?.credential?.revoked) setFeedback('当前 VC 已撤销', '可以尝试调用观察拒绝结果，或签发新 VC 开始新的流程。');
    else if (currentState?.credential) setFeedback('已加载现有演示凭证', '可以调用 A2A 观察验证结果，或一键运行安全用例。');
  }).finally(() => { busy = false; updateButtons(); });
}
