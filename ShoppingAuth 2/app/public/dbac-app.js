'use strict';

const $ = id => document.getElementById(id);
const uiKeyPattern = /^[A-Za-z0-9_-]{43}$/;
const buttons = ['issue-button', 'invoke-button', 'compare-button', 'demo-button', 'lock-button', 'unlock-button', 'refresh-button'];
let uiKey = '';
const entryKey = /^#key=([A-Za-z0-9_-]{43})$/.exec(location.hash);
if (entryKey) {
  uiKey = entryKey[1];
  try { sessionStorage.setItem('a2a-did-vc-ui-key', uiKey); } catch { /* Available for this page load. */ }
  history.replaceState(history.state, '', `${location.pathname}${location.search}`);
} else {
  try {
    const saved = sessionStorage.getItem('a2a-did-vc-ui-key');
    if (saved && uiKeyPattern.test(saved)) uiKey = saved;
  } catch { /* A fresh console link can restore access. */ }
}

let state = null;
let busy = false;
let recentResults = [];
const mode = () => $('scheme').value;
try { const saved = sessionStorage.getItem('a2a-manual-mode'); if (['bbs-bls', 'bbs-blind-bls'].includes(saved)) $('scheme').value = saved; } catch { /* The current mode still works without storage. */ }
$('scheme-note').textContent = mode() === 'bbs-blind-bls' ? '持有者 A 盲化待签消息，模拟 eSIM 接收盲化群元素；调用时间与次数仍可被观察。设备输入盲化不代表整个流程匿名。' : '普通 BLS 模式下，模拟 eSIM 接收公开上下文并返回签名贡献，由持有者 A 适配贡献并生成凭证使用证明。';
const json = value => JSON.stringify(value, null, 2) ?? '—';
const display = value => value === null || value === undefined ? '—' : typeof value === 'object' ? json(value) : String(value);
const setText = (id, value) => { $(id).textContent = display(value); };
const verificationView = window.DemoVerification.create($('verification-trace'));
const testVerificationView = window.DemoVerification.create($('test-verification-trace'));

function feedback(title, message, kind = '') {
  $('feedback').className = `feedback ${kind}`;
  setText('feedback-title', title);
  setText('feedback-message', message);
}

function badge(id, value, kind = '') {
  $(id).className = `status-tag ${kind}`;
  setText(id, value);
}

function updateButtons() {
  window.DemoEmbed?.setBusy('diagnostic', busy);
  const unavailable = busy || !uiKey || !state || state.available === false;
  buttons.forEach(id => { $(id).disabled = unavailable; });
  $('refresh-button').disabled = busy || !uiKey;
  ['invoke-button', 'compare-button'].forEach(id => { $(id).disabled ||= !state?.credential; });
  $('lock-button').disabled ||= !state?.device || state.device.locked === true;
  $('unlock-button').disabled ||= !state?.device || state.device.locked !== true;
  $('scheme').disabled = busy;
  $('request-text').disabled = busy;
  $('actions-panel').setAttribute('aria-busy', String(busy));
  window.DBACPayment?.updateButtons();
}

async function api(path, body) {
  if (!uiKey) throw new Error('请先使用启动终端中的控制台链接打开原演示页，再进入本页；也可使用带有当前访问密钥的本页链接。');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 90000);
  try {
    const response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { Accept: 'application/json', 'X-Demo-UI-Key': uiKey, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: 'no-store',
      signal: controller.signal,
    });
    let data;
    try { data = await response.json(); } catch { throw new Error(`服务端未返回有效 JSON（HTTP ${response.status}）。请确认已启动支持论文复现的服务。`); }
    if (!response.ok) {
      const error = new Error(data.error?.code === 'UI_ACCESS_DENIED' ? '控制台访问权限已失效，请使用当前启动终端给出的链接重新进入。' : data.error?.message || data.message || `请求失败（HTTP ${response.status}）`);
      error.data = data;
      throw error;
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('请求超过 90 秒未完成；服务端可能仍在处理，请刷新状态后再决定是否重试。');
    if (error instanceof TypeError) throw new Error('无法连接演示服务，请确认本地服务已启动。');
    throw error;
  } finally { clearTimeout(timeout); }
}

function renderState(value) {
  state = value;
  $('connection').className = `connection ${state.available === false ? 'failed' : 'connected'}`;
  setText('connection', state.available === false ? '模块不可用' : '服务已连接');
  const credential = state.credential;
  badge('credential-status', credential ? '凭证已准备' : '尚未准备凭证', credential ? 'success' : '');
  setText('credential-suite', credential?.suite);
  setText('issuer-public-key', state.issuer?.publicKey);
  setText('device-public-key', state.device?.publicKey);
  setText('device-backend', state.device?.backend || '独立 Node BLS12-381 软件模块');
  setText('device-signatures', state.device?.signatures);
  const locked = state.device?.locked;
  badge('device-status', locked === true ? '已锁定' : locked === false ? '可签名' : '状态未知', locked === true ? 'error' : locked === false ? 'success' : '');
  const attributes = Array.isArray(credential?.attributes) ? credential.attributes : [];
  $('credential-attributes').replaceChildren();
  $('attribute-empty').hidden = attributes.length > 0;
  attributes.forEach(attribute => {
    const row = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'attribute-name';
    name.textContent = display(attribute.name ?? `属性 ${attribute.index ?? ''}`);
    const valueNode = document.createElement('span');
    valueNode.className = 'attribute-value';
    valueNode.textContent = display(attribute.value);
    const visibility = document.createElement('span');
    visibility.className = `status-tag ${attribute.disclosed === true ? 'success' : ''}`;
    visibility.textContent = attribute.disclosed === true ? '将披露' : attribute.disclosed === false ? '不披露' : '未标注';
    row.append(name, valueNode, visibility);
    $('credential-attributes').append(row);
  });
  updateButtons();
}

async function refresh() {
  const [mechanism] = await Promise.allSettled([
    api(`/api/dbac/state?mode=${encodeURIComponent(mode())}`),
    window.DBACPayment?.refresh(),
  ]);
  if (mechanism.status === 'rejected') throw mechanism.reason;
  renderState(mechanism.value);
}

function fieldsList(id, value, emptyText) {
  const list = $(id);
  list.replaceChildren();
  let items = Array.isArray(value) ? value : value && typeof value === 'object' ? Object.entries(value).map(([name, item]) => ({ name, value: item })) : value === undefined || value === null ? [] : [value];
  if (!items.length) items = [emptyText];
  items.forEach(item => {
    const li = document.createElement('li');
    li.textContent = typeof item === 'object' && item !== null && item.name !== undefined ? `${display(item.name)}${item.value !== undefined ? `：${display(item.value)}` : ''}` : display(item);
    list.append(li);
  });
}

function allEntries(value, output = []) {
  if (value && typeof value === 'object') {
    Object.entries(value).forEach(([key, child]) => {
      output.push({ key, value: child });
      allEntries(child, output);
    });
  }
  return output;
}

function renderStructure(wire) {
  const list = $('structure-checks');
  list.replaceChildren();
  const append = (text, kind = '') => {
    const li = document.createElement('li');
    li.textContent = text;
    li.className = kind;
    list.append(li);
  };
  if (!wire || typeof wire !== 'object') { append('服务端未返回实际出站数据，无法检查。'); return; }
  const entries = allEntries(wire);
  const deviceKey = state?.device?.publicKey;
  const keyMatches = deviceKey !== undefined && deviceKey !== null && entries.some(entry => json(entry.value) === json(deviceKey));
  const keyNamed = entries.some(entry => /^(longTermDevicePublicKey|longTermPublicKey|deviceDid|subjectDid)$/i.test(entry.key));
  append(keyMatches || keyNamed ? '发现长期设备标识候选：请检查出站 JSON。' : deviceKey ? '未发现设备长期公钥的相同值或显式长期标识字段。' : '长期设备公钥未返回，无法完成值检查。', keyMatches || keyNamed ? 'warn' : deviceKey ? 'pass' : '');
  const rawCredential = entries.some(entry => /^(credential|rawCredential|originalCredential|verifiableCredential|credentialSubject)$/i.test(entry.key));
  append(rawCredential ? '发现原始凭证字段候选：请检查出站 JSON。' : '未发现 credential 等原始凭证字段（仅字段检查）。', rawCredential ? 'warn' : 'pass');
  const hidden = (Array.isArray(state?.credential?.attributes) ? state.credential.attributes : []).filter(attribute => attribute.disclosed === false);
  const matches = hidden.filter(attribute => entries.some(entry => entry.key === attribute.name || (attribute.value !== undefined && attribute.value !== null && attribute.value !== '' && json(entry.value) === json(attribute.value))));
  append(matches.length ? `发现隐藏属性同名字段或相同值：${matches.map(attribute => attribute.name ?? attribute.index).join('、')}。请人工核对。` : hidden.length ? '未发现本地隐藏属性的同名字段或相同值。' : '未返回隐藏属性清单，无法完成属性检查。', matches.length ? 'warn' : hidden.length ? 'pass' : '');
}

function publicKey(result) {
  const roots = [result?.presentation, result?.wire?.proof, result?.wire?.body, result?.presentation?.deviceProof];
  for (const root of roots) {
    if (!root || typeof root !== 'object') continue;
    const direct = root.randomizedDevicePublicKey ?? root.randomizedPublicKey ?? root.pkTilde ?? root.pkRandomized;
    if (direct !== undefined) return direct;
    const match = allEntries(root).find(entry => /^(randomizedDevicePublicKey|randomizedPublicKey|pkTilde|pkRandomized)$/.test(entry.key));
    if (match) return match.value;
  }
  return undefined;
}

function renderComparison() {
  const pair = recentResults.filter(result => result.mode === mode()).slice(-2);
  const firstKey = publicKey(pair[0]);
  const secondKey = publicKey(pair[1]);
  setText('comparison-first', firstKey);
  setText('comparison-second', secondKey);
  if (pair.length < 2) {
    badge('comparison-status', `已有 ${pair.length} 次展示`);
    setText('comparison-summary', '还需要同一方案的两次展示，才能比较随机化输出。');
    return;
  }
  if (firstKey === undefined || secondKey === undefined) {
    badge('comparison-status', '缺少公钥字段');
    setText('comparison-summary', '已收到两次结果，但服务端未返回可识别的随机化设备公钥字段。请展开实际请求 JSON 检查。');
    return;
  }
  const different = json(firstKey) !== json(secondKey);
  const firstProof = pair[0].wire?.proof ?? pair[0].presentation;
  const secondProof = pair[1].wire?.proof ?? pair[1].presentation;
  const proofText = firstProof !== undefined && secondProof !== undefined ? (json(firstProof) !== json(secondProof) ? '两次证明输出不同。' : '两次证明输出相同。') : '服务端未返回可比较的证明字段。';
  badge('comparison-status', different ? '观察到公钥变化' : '公钥相同，需检查', different ? 'success' : 'error');
  setText('comparison-summary', `${different ? '同一凭证的两次随机化设备公钥不同。' : '两次返回的随机化设备公钥相同。'}${proofText}这仅是本次运行观察。`);
}

function renderResult(result, record = true) {
  badge('presentation-status', result.accepted === true ? '本次凭证使用资格验证通过' : result.accepted === false ? '本次凭证使用资格验证未通过' : '已返回结果', result.accepted === true ? 'success' : result.accepted === false ? 'error' : '');
  fieldsList('disclosed-fields', result.disclosed, '服务端未返回披露清单');
  fieldsList('hidden-fields', result.hiddenFields, '服务端未返回未披露字段清单');
  setText('wire-json', result.wire ? json(result.wire) : '服务端未返回实际出站数据，无法展示。');
  setText('verification-json', json({ accepted: result.accepted, mode: result.mode, verification: result.verification, verificationTrace: result.verificationTrace, task: result.task, timings: result.timings }));
  verificationView.render(result.verificationTrace, { label: record ? '本次匿名展示验证' : '最近一次服务端展示记录', error: result.error?.message });
  renderStructure(result.wire);
  if (record) {
    recentResults.push({ ...result, mode: result.mode || mode() });
    recentResults = recentResults.slice(-2);
    renderComparison();
  }
}

function renderDemo(result) {
  const rows = Array.isArray(result.results) ? result.results : [];
  $('test-results').replaceChildren();
  rows.forEach((test, index) => {
    const tr = document.createElement('tr');
    const name = document.createElement('td');
    const select = document.createElement('button');
    select.type = 'button';
    select.className = 'trace-case-button';
    select.textContent = display(test.name);
    select.setAttribute('aria-pressed', String(index === 0));
    const selectCase = () => {
      $('test-results').querySelectorAll('tr').forEach(item => item.classList.remove('trace-selected'));
      $('test-results').querySelectorAll('.trace-case-button').forEach(item => item.setAttribute('aria-pressed', 'false'));
      tr.classList.add('trace-selected');
      select.setAttribute('aria-pressed', 'true');
      testVerificationView.render(test.verificationTrace, { label: display(test.name), traces: test.verificationTraces, message: '服务端没有返回此用例的验证轨迹。预期、实际结果仍显示在该用例中。' });
    };
    select.addEventListener('click', () => { selectCase(); window.DemoVerification.focus($('test-verification-trace')); });
    name.append(select);
    if (test.detail !== undefined) {
      const detail = document.createElement('span');
      detail.className = 'case-detail';
      detail.textContent = display(test.detail);
      name.append(detail);
    }
    tr.append(name);
    [test.expected, test.actual, test.pass === true ? '符合预期' : test.pass === false ? '未符合预期' : '未标注'].forEach((value, index) => {
      const td = document.createElement('td');
      td.textContent = display(value);
      if (index === 2) td.className = test.pass === true ? 'case-pass' : test.pass === false ? 'case-fail' : '';
      tr.append(td);
    });
    $('test-results').append(tr);
    if (index === 0) selectCase();
  });
  if (!rows.length) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 4;
    td.textContent = '本次尚无攻击验收结果。运行攻击验收后可选择用例。';
    tr.append(td);
    $('test-results').append(tr);
  }
  const total = result.total ?? rows.length;
  const passed = result.passed ?? rows.filter(test => test.pass === true).length;
  badge('test-summary', total > 0 ? `${passed} / ${total} 符合预期` : '本次尚未运行', total > 0 ? passed === total ? 'success' : 'error' : '');
  if (!rows.length) testVerificationView.clear('运行攻击验收后，点击用例名称查看对应的验证记录。');
  $('privacy-details').hidden = result.privacyEvidence === undefined;
  setText('privacy-json', json(result.privacyEvidence));
}

async function action(title, execute) {
  if (busy) return;
  busy = true;
  updateButtons();
  feedback(title, '正在处理；密码学运算可能需要一些时间。');
  resetPresentation('本次操作进行中，等待服务端返回。');
  renderDemo({ results: [] });
  verificationView.loading(title);
  try {
    await execute();
  } catch (error) {
    feedback('操作未完成', error.message, 'error');
    resetPresentation('本次操作未完成，没有新的展示输入可供检查。');
    badge('presentation-status', '本次操作未完成', 'error');
    verificationView.render(error.data?.verificationTrace, { label: '本次操作未完成', error: error.message });
    if (error.data) setText('verification-json', json(error.data));
  } finally {
    if (verificationView.pending) verificationView.clear('本次操作未产生新的匿名展示验证。生成展示后，可查看验证方实际执行的步骤。');
    busy = false;
    updateButtons();
  }
}

function resetPresentation(message) {
  badge('presentation-status', '等待本次展示');
  setText('wire-json', message);
  setText('verification-json', message);
  fieldsList('disclosed-fields', null, '等待本次展示');
  fieldsList('hidden-fields', null, '等待本次展示');
  renderStructure(null);
}

async function invoke() {
  const text = $('request-text').value.trim();
  if (!text) throw new Error('请填写本次服务请求。');
  resetPresentation('正在生成本次展示，等待服务端响应。');
  verificationView.loading('正在生成凭证使用证明并提交给验证者 B。');
  const result = await api('/api/dbac/invoke', { mode: mode(), text });
  renderResult(result);
  return result;
}

$('issue-button').addEventListener('click', () => action('正在准备 BBS 凭证', async () => {
  await api('/api/dbac/issue', { mode: mode() });
  recentResults = [];
  renderComparison();
  await refresh();
  feedback('凭证已准备', '可生成证明并提交验证，或运行攻击验收。', 'success');
}));
$('invoke-button').addEventListener('click', () => action('正在生成匿名展示', async () => {
  const result = await invoke();
  await refresh();
  feedback(result.accepted === true ? '本次凭证使用资格验证通过' : result.accepted === false ? '本次凭证使用资格验证未通过' : '验证结果已返回', '下方显示验证端实际收到的请求与证明。', result.accepted === true ? 'success' : result.accepted === false ? 'error' : '');
}));
$('compare-button').addEventListener('click', () => action('正在生成两次展示', async () => {
  recentResults = [];
  renderComparison();
  await invoke();
  feedback('第一次展示已完成', '正在使用同一凭证生成第二次展示。');
  await invoke();
  await refresh();
  feedback('两次展示已完成', '已显示两次公钥与证明的结构比较；比较结果不能替代不可关联性证明。', 'success');
}));
$('demo-button').addEventListener('click', () => action('正在运行攻击验收', async () => {
  const result = await api('/api/dbac/demo', { mode: mode() });
  renderDemo(result);
  verificationView.clear('本次运行了多项攻击验收。请在下方攻击验收列表中选择一次请求，查看对应验证轨迹。');
  await refresh();
  const allPassed = result.total > 0 && result.passed === result.total;
  feedback('攻击验收已完成', '请查看各用例预期、实际结果与服务端证据。', allPassed ? 'success' : '');
}));

window.addEventListener('demo:activate', () => {
  if (busy || !uiKey) return;
  try {
    const saved = sessionStorage.getItem('a2a-manual-mode');
    if (['bbs-bls', 'bbs-blind-bls'].includes(saved) && saved !== mode()) {
      $('scheme').value = saved;
      $('scheme').dispatchEvent(new Event('change'));
      return;
    }
  } catch { /* Refresh the currently selected mode when storage is unavailable. */ }
  busy = true;
  updateButtons();
  void refresh().catch(error => {
    $('connection').className = 'connection failed';
    setText('connection', '状态刷新失败');
    feedback('状态刷新未完成', error.message, 'error');
  }).finally(() => { busy = false; updateButtons(); });
});
for (const [id, locked] of [['lock-button', true], ['unlock-button', false]]) {
  $(id).addEventListener('click', () => action(locked ? '正在锁定软件设备' : '正在解锁软件设备', async () => {
    await api('/api/dbac/device/lock', { mode: mode(), locked });
    await refresh();
    feedback(locked ? '软件设备已锁定' : '软件设备已解锁', locked ? '设备当前不接受新的签名请求；已有证明仍需以验证结果为准。' : '设备现在可以为新展示贡献签名。', 'success');
  }));
}
$('refresh-button').addEventListener('click', () => action('正在刷新状态', async () => { await refresh(); feedback('状态已刷新', '已读取当前凭证与软件设备状态。', 'success'); }));
$('scheme').addEventListener('change', () => action('正在切换论文方案', async () => {
  try { sessionStorage.setItem('a2a-manual-mode', mode()); } catch { /* The current selection still applies. */ }
  setText('scheme-note', mode() === 'bbs-blind-bls' ? '持有者 A 盲化待签消息，模拟 eSIM 接收盲化群元素；调用时间与次数仍可被观察。设备输入盲化不代表整个流程匿名。' : '普通 BLS 模式下，模拟 eSIM 接收公开上下文并返回签名贡献，由持有者 A 适配贡献并生成凭证使用证明。');
  state = null;
  window.DBACPayment?.resetMode();
  recentResults = [];
  renderComparison();
  badge('credential-status', '正在加载本方案');
  badge('device-status', '正在加载本方案');
  $('credential-attributes').replaceChildren();
  $('attribute-empty').hidden = false;
  for (const id of ['credential-suite', 'issuer-public-key', 'device-public-key', 'device-signatures']) setText(id, null);
  badge('presentation-status', '等待本方案展示');
  setText('wire-json', '已切换方案，等待本方案的新展示。');
  setText('verification-json', '尚无本方案的验证结果。');
  fieldsList('disclosed-fields', null, '等待本方案展示');
  fieldsList('hidden-fields', null, '等待本方案展示');
  renderStructure(null);
  renderDemo({ results: [], total: 0, passed: 0 });
  badge('test-summary', '本方案尚未运行');
  await refresh();
  feedback('论文方案已切换', state.credential ? '已加载本方案的凭证与设备状态，可生成展示。' : '本方案尚无凭证，请先签发。', 'success');
}));

updateButtons();
action('正在连接论文复现模块', async () => {
  await refresh();
  if (state.lastResult) renderResult(state.lastResult, false);
  if (state.available === false) feedback('论文复现模块不可用', state.message || state.reason || '请检查服务端启动输出。', 'error');
  else feedback('服务已连接', state.credential ? '已有 BBS 凭证，可直接生成展示。' : '先准备 BBS 凭证，再生成证明并提交验证。', 'success');
});
