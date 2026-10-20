'use strict';

// Payment shares the selected DBAC scheme and console capability with the mechanism view.
// All verification steps and settlement outcomes below come from backend responses.
window.DBACPayment = (() => {
  const prefix = 'dbac-payment-';
  const el = id => document.getElementById(prefix + id);
  const put = (id, value, fallback = '—') => { el(id).textContent = value == null ? fallback : display(value); };
  const actions = ['issue', 'propose', 'sync', 'pay', 'retry', 'new', 'demo'];
  const verification = window.DemoVerification.create(el('verification-trace'));
  const testVerification = window.DemoVerification.create(el('test-trace'));
  let paymentState = null;
  let currentMode = mode();
  let currentOrder = null;
  let resultShown = false;
  const outcomeLabel = value => ({ EXECUTED: '本笔模拟支付已完成', ALREADY_PROCESSED: '已返回本订单已有结果' }[value] || value || '尚未执行');
  const proposalLabel = value => ({ PENDING: '等待用户授权', APPROVED: '用户已批准', REJECTED: '用户已拒绝授权', EXPIRED: '提案或授权已过期' }[value] || value || '尚未提交');
  const actionLabels = { issue: '正在准备 BBS 支付凭证', propose: '正在提交本笔订单', sync: '正在同步用户授权', pay: '正在生成 DBAC 证明并执行 x402 付款', retry: '正在用新 DBAC 证明重试同一授权订单', new: '正在创建下一笔订单', demo: '正在运行本笔支付攻击验收' };

  function status(value, kind = '') { put('status', value); el('status').className = `status-tag ${kind}`; }
  function feedbackPayment(title, message, kind = '') {
    el('feedback').className = `feedback ${kind}`;
    put('feedback-title', title); put('feedback-message', message);
  }
  function money(amountMinor, currency, decimals = 6) {
    if (!Number.isSafeInteger(amountMinor) || !Number.isInteger(decimals) || decimals < 0 || decimals > 18 || typeof currency !== 'string') return '—';
    const units = BigInt(amountMinor), absolute = units < 0n ? -units : units, scale = 10n ** BigInt(decimals);
    return `${units < 0n ? '-' : ''}${absolute / scale}${decimals ? `.${(absolute % scale).toString().padStart(decimals, '0')}` : ''} ${currency}`;
  }
  function updatePaymentButtons() {
    const unavailable = busy || !uiKey || !paymentState || paymentState.available !== true || currentMode !== mode();
    for (const actionName of actions) el(`${actionName}-button`).disabled = unavailable;
    const hasCredential = Boolean(paymentState?.credential);
    const hasOrder = Boolean(paymentState?.order);
    el('issue-button').disabled ||= Boolean(paymentState?.proposal);
    el('propose-button').disabled ||= !hasCredential || !hasOrder || paymentState?.owner?.available === false || ['PENDING', 'APPROVED'].includes(paymentState?.proposal?.status);
    el('sync-button').disabled ||= !paymentState?.proposal || paymentState?.owner?.available === false;
    const approved = hasCredential && hasOrder && paymentState?.authorization && paymentState?.proposal?.status === 'APPROVED' && paymentState?.owner?.available !== false;
    for (const name of ['pay', 'retry', 'demo']) el(`${name}-button`).disabled ||= !approved;
    el('panel').setAttribute('aria-busy', String(busy));
  }
  function renderFlow(flow) {
    const names = { 'dbac-verified': 'DBAC 支付资格与设备证明通过', 'input-required': 'x402 请求支付材料', 'payment-submitted': '已提交支付材料', completed: '支付任务完成' };
    el('flow').replaceChildren();
    const items = Array.isArray(flow) ? flow.filter(step => typeof step === 'string') : [];
    for (const step of items.length ? items : [null]) {
      const li = document.createElement('li');
      if (step) {
        const title = document.createElement('strong'), code = document.createElement('code');
        title.textContent = names[step] || step; code.textContent = step;
        li.append(title, code); if (step === 'completed') li.className = 'completed';
      } else li.textContent = '本次尚无服务端支付流程';
      el('flow').append(li);
    }
  }
  function renderResult(result, label = '本笔 DBAC 支付请求') {
    resultShown = true;
    verification.render(result?.verificationTrace, { label, traces: result?.verificationTraces, error: result?.error?.message });
    put('wire-json', result?.wire ? json(result.wire) : '本次响应未返回实际出站支付请求。');
    put('result-json', json(result));
    renderFlow(result?.paymentFlow);
    const payment = result?.paymentResult;
    if (payment) {
      put('outcome', outcomeLabel(payment.outcome));
      put('transaction-hash', payment.receipt?.transactionHash, '尚未取得链上回执');
    }
  }
  function resetResult(message) {
    resultShown = false;
    verification.clear(message);
    put('wire-json', message); put('result-json', message); renderFlow([]);
  }
  function clearTests() {
    el('test-results').replaceChildren();
    const row = document.createElement('tr'), cell = document.createElement('td');
    cell.colSpan = 4; cell.textContent = '本方案的本笔订单尚无支付攻击验收结果。'; row.append(cell); el('test-results').append(row);
    put('test-summary', '尚未运行'); el('test-summary').className = 'status-tag';
    testVerification.clear('运行本笔支付攻击验收后，可选择一次实际请求查看后端记录。');
  }
  function renderTests(result) {
    const rows = Array.isArray(result.results) ? result.results : [];
    clearTests();
    if (rows.length) el('test-results').replaceChildren();
    rows.forEach((test, index) => {
      const row = document.createElement('tr'), name = document.createElement('td'), button = document.createElement('button');
      button.type = 'button'; button.className = 'trace-case-button'; button.textContent = display(test.name);
      const select = () => {
        el('test-results').querySelectorAll('tr').forEach(node => node.classList.remove('trace-selected'));
        el('test-results').querySelectorAll('button').forEach(node => node.setAttribute('aria-pressed', 'false'));
        row.classList.add('trace-selected'); button.setAttribute('aria-pressed', 'true');
        testVerification.render(test.verificationTrace, { label: display(test.name), traces: test.verificationTraces, message: '此用例没有返回验证轨迹；请查看服务端的预期与实际结果。' });
      };
      button.addEventListener('click', () => { select(); window.DemoVerification.focus(el('test-trace')); });
      name.append(button);
      if (test.detail != null) { const detail = document.createElement('span'); detail.className = 'case-detail'; detail.textContent = display(test.detail); name.append(detail); }
      row.append(name);
      for (const [value, kind] of [[test.expected, ''], [test.actual, ''], [test.pass === true ? '符合预期' : test.pass === false ? '未符合预期' : '未标注', test.pass === true ? 'case-pass' : test.pass === false ? 'case-fail' : '']]) {
        const cell = document.createElement('td'); cell.textContent = display(value); cell.className = kind; row.append(cell);
      }
      el('test-results').append(row); if (index === 0) select();
    });
    const total = result.total ?? rows.length, passed = result.passed ?? rows.filter(test => test.pass === true).length;
    put('test-summary', `${passed} / ${total} 符合预期`);
    el('test-summary').className = `status-tag ${total > 0 ? passed === total ? 'success' : 'error' : ''}`;
  }
  function renderStatePayment(value) {
    paymentState = value;
    const order = value?.order, proposal = value?.proposal, authorization = value?.authorization;
    const lastPayment = value?.lastResult?.paymentResult || value?.lastResult;
    if (currentOrder !== (order?.orderId || null)) {
      currentOrder = order?.orderId || null;
      resetResult('等待本方案当前订单的 DBAC 支付验证。'); clearTests();
    }
    if (value?.available !== true) status('支付服务不可用', 'error');
    else if (value.owner?.available === false) status('用户授权服务暂不可用', 'error');
    else if (['EXECUTED', 'ALREADY_PROCESSED'].includes(lastPayment?.outcome)) status(outcomeLabel(lastPayment.outcome), 'success');
    else status(proposalLabel(proposal?.status), ['REJECTED', 'EXPIRED'].includes(proposal?.status) ? 'error' : '');
    put('availability', value?.available === true ? '当前方案的支付凭证、订单与用户授权独立保存。使用上方流程完成本笔模拟支付。' : value?.message || value?.reason || '本启动模式未提供支付链和用户授权服务；请使用完整 npm start。辅助机制检查仍可使用。');
    put('amount', money(order?.amountMinor, order?.currency));
    put('order-id', order?.orderId); put('payer', order?.payerAccount); put('payee', order?.payeeAccount);
    put('network', order?.settlement?.network); put('asset', order?.settlement?.asset); put('pay-to', order?.settlement?.payTo); put('payer-address', order?.settlement?.payerAddress);
    put('credential-status', value?.credential ? `已签发 · ${value.credential.suite || currentMode}` : '尚未准备本方案支付凭证');
    put('proposal-id', proposal?.id, '尚未提交'); put('proposal-status', proposalLabel(proposal?.status)); put('authorization-id', authorization?.id, '尚未确认');
    put('owner-did', value?.owner?.did); put('authorization', authorization ? json(authorization.document || authorization) : '尚未确认');
    put('execution-count', value?.ledger?.executionCount);
    put('ledger-json', json({ paymentInfo: value?.paymentInfo, receipts: value?.ledger?.receipts }));
    put('outcome', outcomeLabel(lastPayment?.outcome)); put('transaction-hash', lastPayment?.receipt?.transactionHash, '尚未取得链上回执');
    el('balances').replaceChildren();
    const accounts = Array.isArray(value?.ledger?.accounts) ? value.ledger.accounts : [];
    for (const account of accounts) {
      const row = document.createElement('li'), name = document.createElement('span'), balance = document.createElement('strong');
      name.textContent = display(account.id); balance.textContent = money(account.balanceMinor, value.ledger.currency, value.ledger.decimals ?? 6); row.append(name, balance); el('balances').append(row);
    }
    if (!accounts.length) { const row = document.createElement('li'); row.textContent = '服务端尚未返回链上余额'; el('balances').append(row); }
    el('attributes').replaceChildren();
    const attributes = Array.isArray(value?.credential?.attributes) ? value.credential.attributes : [];
    for (const attribute of attributes) {
      const row = document.createElement('li');
      for (const [textValue, className] of [[attribute.name, 'attribute-name'], [attribute.value, 'attribute-value'], [attribute.disclosed === true ? '将披露' : attribute.disclosed === false ? '不披露' : '未标注', 'status-tag']]) {
        const span = document.createElement('span'); span.className = className; span.textContent = display(textValue); row.append(span);
      }
      el('attributes').append(row);
    }
    if (!attributes.length) { const row = document.createElement('li'); row.textContent = '尚无支付凭证属性'; el('attributes').append(row); }
    if (!resultShown && value?.lastResult) renderResult(value.lastResult, '当前订单最近一次支付验证');
    updatePaymentButtons();
  }
  async function refreshPayment() {
    const selectedMode = mode();
    if (currentMode !== selectedMode) resetMode();
    try {
      const value = await api(`/api/dbac/payment/state?mode=${encodeURIComponent(selectedMode)}`);
      if (selectedMode !== mode()) return;
      renderStatePayment(value);
      if (value.available !== true) feedbackPayment('支付主线暂不可用', '请以完整 npm start 启动本地链与用户授权服务。', 'error');
    } catch (error) {
      if (selectedMode !== mode()) return;
      renderStatePayment({ available: false, message: error.message });
      feedbackPayment('支付状态读取未完成', error.message, 'error');
    }
  }
  function resetMode() {
    currentMode = mode(); currentOrder = null; paymentState = null;
    resetResult('已切换论文方案，等待该方案当前订单的支付验证。'); clearTests();
    renderStatePayment({ available: false, message: '正在读取当前方案的支付状态。' }); status('正在加载本方案');
    feedbackPayment('已切换支付方案', '正在读取该方案的支付凭证、订单与授权。');
  }
  async function run(actionName) {
    if (busy || el(`${actionName}-button`).disabled) return;
    busy = true; updateButtons();
    if (['pay', 'retry', 'demo'].includes(actionName)) status('支付处理中');
    feedbackPayment(actionLabels[actionName], '等待服务端返回。本地测试代币没有真实资金价值。');
    if (['pay', 'retry', 'demo', 'propose'].includes(actionName)) {
      resetResult('正在提交当前订单，等待服务端返回实际请求。');
      verification.loading(actionLabels[actionName]);
    }
    if (['issue', 'new'].includes(actionName)) { resetResult('本次操作准备支付凭证或下一订单，尚无新的付款验证。'); clearTests(); }
    let result = null, failure = null;
    try {
      result = await api(`/api/dbac/payment/${actionName}`, { mode: currentMode });
      if (result.ok === false || result.accepted === false || result.error) {
        failure = new Error(result.error?.message || '服务端拒绝了本次支付操作。'); failure.data = result;
      }
    } catch (error) { failure = error; }
    await refreshPayment();
    if (failure) {
      renderResult(failure.data || { error: { message: failure.message } }, failure.data ? '本次支付操作未完成' : '暂未取得本次支付结果');
      feedbackPayment(failure.data ? '本次支付操作未完成' : '暂未取得本次支付结果', failure.message, 'error');
    } else if (actionName === 'demo') {
      renderTests(result);
      resetResult('本次运行多项支付攻击验收；请在下方选择用例查看各次请求。');
      put('result-json', json(result));
      const total = result.total ?? result.results?.length ?? 0, passed = result.passed ?? result.results?.filter(test => test.pass === true).length ?? 0;
      feedbackPayment('支付攻击验收已返回', `${passed} / ${total} 项符合预期。请核对余额、累计执行次数与回执。`, total > 0 && passed === total ? 'success' : 'error');
    } else if (['pay', 'retry'].includes(actionName)) {
      renderResult(result);
      const payment = result?.paymentResult;
      if (['EXECUTED', 'ALREADY_PROCESSED'].includes(payment?.outcome) && payment?.receipt) feedbackPayment('DBAC 支付结果已返回', `${outcomeLabel(payment.outcome)}。请查看实际证明、验证过程与链上交易哈希。`, 'success');
      else feedbackPayment('付款响应不完整', '服务端未返回完整付款结果；请核对本次响应及链上状态。', 'error');
    } else {
      if (actionName === 'propose') renderResult(result, '提交付款授权申请前的 DBAC 使用资格验证');
      const messages = {
        issue: ['BBS 支付凭证已准备', '这张凭证用于当前方案的 payments:pay 验证。下一步提交本笔付款授权申请。'],
        propose: ['付款授权申请已提交', '前往付款授权，核对当前方案与订单并批准；再回本页同步授权。批准不会直接执行付款。'],
        sync: ['用户授权状态已同步', paymentState?.authorization && paymentState?.proposal?.status === 'APPROVED' ? (['EXECUTED', 'ALREADY_PROCESSED'].includes((paymentState?.lastResult?.paymentResult || paymentState?.lastResult)?.outcome) ? outcomeLabel((paymentState.lastResult.paymentResult || paymentState.lastResult).outcome) : '用户已批准。付款状态请查看本笔执行结果。') : '尚未取得已批准的单笔授权，请查看提案状态并完成用户授权。'],
        new: ['下一笔订单已创建', '本笔订单需要新的用户授权；已有链上回执仍保留。'],
      };
      const message = messages[actionName];
      feedbackPayment(message[0], message[1], actionName === 'sync' ? '' : 'success');
    }
    busy = false; updateButtons();
  }
  for (const name of actions) el(`${name}-button`).addEventListener('click', () => void run(name));
  updatePaymentButtons();
  return { refresh: refreshPayment, updateButtons: updatePaymentButtons, resetMode };
})();

// The mechanism script starts its first refresh before this deferred script loads.
// Refresh once after registering the payment module so the initial page is usable.
void window.DBACPayment.refresh();
