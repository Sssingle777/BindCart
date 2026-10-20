'use strict';

const $ = id => document.getElementById(id);
const apiPrefix = location.pathname.startsWith('/owner/') ? '/owner' : '';
if (apiPrefix) $('platform-return').hidden = false;
if (apiPrefix && window.parent !== window) {
  const style = document.createElement('link'); style.rel = 'stylesheet'; style.href = '/embed.css'; document.head.insertBefore(style, document.querySelector('link[href="./platform.css"]')); 
  const script = document.createElement('script'); script.src = '/embed.js'; document.head.append(script);
}
const storageKey = 'a2a-owner-ui-key';
const keyPattern = /^[A-Za-z0-9_-]{43}$/;
let ownerUiKey = '';
const entry = /^#key=([A-Za-z0-9_-]{43})$/.exec(location.hash);
if (entry) {
  ownerUiKey = entry[1];
  try { sessionStorage.setItem(storageKey, ownerUiKey); } catch { /* This page load can still use the entry key. */ }
  history.replaceState(history.state, '', `${location.pathname}${location.search}`);
} else {
  try {
    const saved = sessionStorage.getItem(storageKey);
    if (saved && keyPattern.test(saved)) ownerUiKey = saved;
  } catch { /* A fresh Owner console link remains usable. */ }
}

let busy = false;
let stateFresh = false;
let decisionButtons = [];
const statusLabels = { PENDING: '等待用户授权', APPROVED: '已批准 · 付款状态待核对', REJECTED: '已拒绝', EXPIRED: '已过期' };
const paymentFields = ['orderId', 'payerAccount', 'payeeAccount', 'amountMinor', 'currency', 'settlement'];
const settlementFields = ['network', 'asset', 'payTo', 'payerAddress'];
const valueText = (value, fallback = '—') => value === undefined || value === null || value === '' ? fallback : typeof value === 'object' ? JSON.stringify(value) : String(value);
const setText = (id, value, fallback) => { $(id).textContent = valueText(value, fallback); };
function element(tag, text, className) {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = valueText(text);
  if (className) item.className = className;
  return item;
}
function money(payment) {
  if (!Number.isSafeInteger(payment?.amountMinor) || payment.amountMinor <= 0 || payment.currency !== 'TEST_USDC') return '金额不可用';
  const units = BigInt(payment.amountMinor);
  return `${units / 1000000n}.${(units % 1000000n).toString().padStart(6, '0')} ${payment.currency}`;
}
function dateText(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? valueText(value) : date.toLocaleString('zh-CN', { hour12: false });
}
function validProposal(proposal) {
  return typeof proposal?.id === 'string' && proposal.id.length > 0 && typeof proposal.credentialHash === 'string' && proposal.credentialHash.length > 0 &&
    Number.isSafeInteger(proposal.payment?.amountMinor) && proposal.payment.amountMinor > 0 &&
    proposal.payment.currency === 'TEST_USDC' &&
    paymentFields.filter(key => !['amountMinor', 'settlement'].includes(key)).every(key => typeof proposal.payment[key] === 'string' && proposal.payment[key].length > 0) &&
    proposal.payment.settlement && typeof proposal.payment.settlement === 'object' && !Array.isArray(proposal.payment.settlement) &&
    settlementFields.every(key => typeof proposal.payment.settlement[key] === 'string' && proposal.payment.settlement[key].length > 0);
}
function feedback(title, message, kind = 'neutral') {
  $('feedback').className = `feedback ${kind}`;
  setText('feedback-title', title);
  setText('feedback-message', message);
}
function updateButtons() {
  $('refresh-button').disabled = busy || !ownerUiKey;
  decisionButtons.forEach(({ button, pending }) => { button.disabled = busy || !ownerUiKey || !stateFresh || !pending; });
  $('proposals-panel').setAttribute('aria-busy', String(busy));
  setText('owner-permission', !ownerUiKey ? '未载入 Owner 权限' : stateFresh ? 'Owner 权限可用' : busy ? '正在核验 Owner 权限' : 'Owner 权限尚未确认');
  $('owner-permission').className = `status-tag${stateFresh ? ' approved' : ''}`;
  if (window.parent !== window) window.parent.postMessage({ type: 'demo:busy', busy }, location.origin);
}
async function api(path, body) {
  if (!ownerUiKey) throw new Error('请使用启动终端中的用户授权专用链接进入付款授权页。');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(`${apiPrefix}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { Accept: 'application/json', 'X-Owner-UI-Key': ownerUiKey, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      cache: 'no-store', redirect: 'error', signal: controller.signal,
    });
    let data;
    try { data = await response.json(); } catch { throw new Error(`授权服务未返回有效 JSON（HTTP ${response.status}）。`); }
    if (!response.ok || data.ok === false) {
      const error = new Error(response.status === 401 || response.status === 403 && data.error?.code?.includes('UI') ? '用户授权权限不可用，请重新使用启动终端的用户授权专用链接。' : data.error?.message || `授权操作未完成（HTTP ${response.status}）。`);
      error.code = data.error?.code;
      error.data = data;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('暂未取得授权结果，请刷新申请并核对当前状态。');
    if (error instanceof TypeError) throw new Error('暂未连接授权服务，请刷新申请并核对当前状态。');
    throw error;
  } finally { clearTimeout(timeout); }
}
function renderState(state) {
  setText('owner-did', state.ownerDid);
  setText('holder-did', state.holderDid);
  setText('verifier-did', state.verifierDid);
  const proposals = Array.isArray(state.proposals) ? state.proposals : [];
  const pendingCount = proposals.filter(proposal => proposal.status === 'PENDING').length;
  setText('proposal-count', `${proposals.length} 条申请 · ${pendingCount} 条等待用户授权`);
  const list = $('proposal-list');
  list.replaceChildren();
  decisionButtons = [];
  if (!proposals.length) list.append(element('div', '暂无付款授权申请。在模拟支付流程提交授权申请后，点击“刷新申请”。', 'empty-state'));
  [...proposals].sort((a, b) => Number(b.status === 'PENDING') - Number(a.status === 'PENDING') || new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).forEach(proposal => {
    const pending = proposal.status === 'PENDING';
    const anonymous = proposal.profile === 'dbac-payment';
    const w3cBbs = proposal.credentialProfile === 'w3c-bbs-esim-v1';
    const credentialTerms = [['凭证配置', proposal.credentialProfile], ['W3C 签发方', proposal.w3cIssuer], ['VC 设备绑定标识', proposal.vcBindingId]].filter(([, value]) => value !== undefined && value !== null && value !== '');
    const card = element('article', undefined, `proposal${pending ? ' pending' : ''}`);
    const heading = element('div', undefined, 'proposal-heading');
    const headingText = element('div', undefined, 'proposal-heading-copy');
    headingText.append(element('span', '本笔付款授权', 'proposal-kicker'), element('h3', w3cBbs ? 'W3C VC + BBS · 绑定设备付款授权' : anonymous ? '论文设备绑定凭证 · x402 付款授权' : '基础 JWS 具名 VC · x402 付款授权'));
    heading.append(headingText, element('span', statusLabels[proposal.status] || valueText(proposal.status), `status-tag ${valueText(proposal.status, '').toLowerCase()}`));
    const paymentSummary = element('div', undefined, 'proposal-payment');
    paymentSummary.append(element('span', '本笔授权金额', 'amount-caption'), element('p', money(proposal.payment), 'amount'), element('p', `付款账户：${valueText(proposal.payment?.payerAccount)}`, 'payee'), element('p', `收款账户：${valueText(proposal.payment?.payeeAccount)}`, 'payee'), element('p', `提交时间：${dateText(proposal.createdAt)}`, 'hint'), element('p', '请核对金额、资产、支付网络及收款地址。批准后生成本笔付款授权，当前操作不会直接执行付款。', 'payment-summary-note'));
    card.append(heading, paymentSummary);
    const settlement = element('dl', undefined, 'facts settlement-facts');
    for (const [label, value] of [
      ['订单编号', proposal.payment?.orderId], ['资产', proposal.payment?.currency], ['授权有效期', dateText(proposal.expiresAt)], ['支付网络', proposal.payment?.settlement?.network], ['代币合约', proposal.payment?.settlement?.asset],
      ['实际收款地址', proposal.payment?.settlement?.payTo], ['付款地址', proposal.payment?.settlement?.payerAddress],
    ]) {
      const row = element('div');
      if (label === '实际收款地址') row.className = 'settlement-destination';
      else if (['付款地址', '代币合约', '订单编号'].includes(label)) row.className = 'settlement-identifier';
      row.append(element('dt', label), element('dd', value));
      settlement.append(row);
    }
    card.append(settlement);
    const facts = element('dl', undefined, 'facts');
    for (const [label, value] of [
      ['订单编号', proposal.payment?.orderId], ['付款账户', proposal.payment?.payerAccount], ['提案编号', proposal.id],
      ...credentialTerms,
      ...(anonymous ? [['设备签名模式', proposal.mode === 'bbs-blind-bls' ? '盲化 BLS 贡献' : '普通 BLS 贡献'], ['本订单公钥', proposal.orderKey], ['提案证据摘要', proposal.credentialHash]] : [['VC 编号', proposal.credentialId], ['VC 摘要', proposal.credentialHash], ['绑定设备', proposal.deviceDid]]),
      ['提交时间', dateText(proposal.createdAt)], ['失效时间', dateText(proposal.expiresAt)],
    ]) {
      const row = element('div');
      row.append(element('dt', label), element('dd', value));
      facts.append(row);
    }
    const technical=element('details');technical.append(element('summary','签发方、设备模式与授权绑定技术信息'),facts);

    if (pending) {
      const actions = element('div', undefined, 'decision-actions');
      const approve = element('button', '批准本笔付款授权', 'button primary');
      approve.type = 'button';
      approve.addEventListener('click', () => { void decide(proposal, 'approve'); });
      const reject = element('button', '拒绝本笔付款授权', 'button danger');
      reject.type = 'button';
      reject.addEventListener('click', () => { void decide(proposal, 'reject'); });
      decisionButtons.push({ button: approve, pending: validProposal(proposal) }, { button: reject, pending: typeof proposal.id === 'string' && proposal.id.length > 0 });
      actions.append(approve, reject);
      card.append(actions, element('p', validProposal(proposal) ? `确认将签署上方金额、网络、代币合约、收付款地址、订单及${w3cBbs ? 'W3C 签发方、凭证配置、VC 设备绑定标识与本订单公钥' : anonymous ? '本订单公钥' : '绑定的 VC'}。批准后由持有者智能体 A 另行提交付款。` : '金额、链上结算字段或提案摘要不完整，无法批准。请刷新或拒绝此提案。', 'hint'));
    } else card.append(element('p', proposal.status === 'APPROVED' ? '用户已批准本笔付款授权。此页不提供付款结果，请在模拟支付流程同步授权并核对回执。' : '该申请当前不能批准。如需继续，请在模拟支付流程重新提交有效申请。', 'hint'));
    card.append(technical);
    if (anonymous) card.append(element('p', w3cBbs ? '本授权绑定上方 W3C 签发方、凭证配置、VC 设备绑定标识与本订单公钥。同一凭证的 bindingId 可关联；完整 VC、隐藏的姓名和组织、长期设备公钥不写入授权。链上付款地址与交易仍公开可见。' : '本授权绑定本订单的随机化设备公钥。凭证原文、Agent DID 和长期设备公钥不写入授权；同一订单内的各阶段仍可关联，链上付款地址与交易公开可见。', 'hint'));
    const details = element('details');
    details.append(element('summary', '查看原始申请与公开授权'), element('pre', JSON.stringify(proposal, null, 2), 'json-panel'));
    card.append(details);
    list.append(card);
  });
  updateButtons();
}
async function refreshState() {
  try {
    const state = await api('/api/state');
    stateFresh = true;
    renderState(state);
    $('connection').className = 'connection connected';
    setText('connection', '授权服务已连接');
    return state;
  } catch (error) {
    stateFresh = false;
    $('connection').className = 'connection failed';
    setText('connection', '暂未连接授权服务');
    updateButtons();
    throw error;
  }
}
async function refresh() {
  if (busy) return;
  busy = true;
  updateButtons();
  try {
    await refreshState();
    feedback('申请已刷新', '状态已更新；批准与拒绝仅作用于对应申请。');
  } catch (error) { feedback('暂未取得申请状态', error.message, 'error'); }
  finally { busy = false; updateButtons(); }
}
async function decide(proposal, action) {
  if (busy || !stateFresh || !ownerUiKey || proposal.status !== 'PENDING') return;
  if (action === 'approve' && !validProposal(proposal)) { feedback('无法批准本笔申请', '订单字段或 VC 摘要不完整，请刷新后重试。', 'error'); return; }
  busy = true;
  updateButtons();
  feedback(action === 'approve' ? '正在签署本笔付款授权…' : '正在拒绝本笔付款授权…', '以授权服务返回的状态为准。');
  try {
    // Bind consent to exactly the values displayed on this card. Do not refresh
    // and silently substitute changed terms before submitting the decision.
    const body = action === 'approve' ? { confirmed: true, payment: structuredClone(Object.fromEntries(paymentFields.map(key => [key, proposal.payment[key]]))), credentialHash: proposal.credentialHash } : { rejected: true };
    const result = await api(`/api/proposals/${encodeURIComponent(proposal.id)}/${action}`, body);
    $('response-details').hidden = false;
    setText('response-json', JSON.stringify(result, null, 2));
    feedback(action === 'approve' ? '本笔付款授权已批准' : '本笔付款授权已拒绝', action === 'approve' ? '已批准，尚未付款。请返回演示平台或提交申请的页面同步付款授权。' : '用户已拒绝为本笔订单生成付款授权。', 'success');
  } catch (error) {
    if (error.data) { $('response-details').hidden = false; setText('response-json', JSON.stringify(error.data, null, 2)); }
    feedback('操作未完成', `${error.code ? `${error.code}：` : ''}${error.message}`, 'error');
  } finally {
    try { await refreshState(); }
    catch (error) { feedback('暂未取得最终授权状态', `${error.message} 请刷新提案，核对操作是否已完成。`, 'error'); }
    busy = false;
    updateButtons();
  }
}

$('refresh-button').addEventListener('click', () => { void refresh(); });
window.addEventListener('demo:activate', () => { if (!busy && ownerUiKey) void refresh(); });
updateButtons();
if (ownerUiKey) void refresh();
else {
  setText('connection', '等待用户授权权限');
  feedback('尚未载入用户授权权限', '请使用启动终端中的用户授权专用链接进入。持有者智能体 A 的操作权限不能代替用户批准。');
}
