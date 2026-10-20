const $ = id => document.getElementById(id);
const fragment = new URLSearchParams(location.hash.slice(1));
for (const name of ['key', 'ownerKey']) if (fragment.get(name)) sessionStorage.setItem(`adyen-shop-${name}`, fragment.get(name));
if (location.hash) history.replaceState(null, '', location.pathname);
const key = sessionStorage.getItem('adyen-shop-key') ?? '';
const ownerKey = sessionStorage.getItem('adyen-shop-ownerKey') ?? '';
let current, localBusy = false, previewUrl;
const money = amount => `€${(amount / 100).toFixed(2)}`;
$('product-image').addEventListener('load', () => { $('product-image').hidden = false; $('placeholder').hidden = true; });
$('product-image').addEventListener('error', () => { $('product-image').hidden = true; $('placeholder').hidden = false; $('placeholder').querySelector('small').textContent = '商品图片暂未加载，可继续查看价格与结算'; });
async function request(path, method = 'GET') {
  const response = await fetch(path, { method, headers: { 'X-Demo-UI-Key': key, ...(method === 'POST' ? { 'Content-Type': 'application/json', 'X-Owner-UI-Key': ownerKey } : {}) }, ...(method === 'POST' ? { body: '{}' } : {}) });
  const data = await response.json();
  if (!response.ok) { if (data.state) render(data.state); throw new Error(data.error?.message ?? '请求未完成。'); }
  return data;
}
function render(state) {
  current = state;
  const busy = localBusy || state.busy;
  document.body.classList.toggle('is-busy', busy);
  $('status').textContent = state.message;
  $('assistant-title').textContent = busy ? '购物助手正在处理' : state.phase === 'paid' ? '本次购物已完成' : '你的 Agent 购物助手';
  if (state.product?.image && $('product-image').src !== state.product.image) { $('product-image').src = state.product.image; }
  if (state.order) { $('price').textContent = money(state.order.amountMinor); $('payment-total').textContent = money(state.order.amountMinor); }
  const texts = { idle: '查看商品与价格 →', error: '重新连接商城 →', loading: '正在连接官方商城…', cart: '确认商品，去结算 →', verifying: '正在验证本次操作资格…', checkout: '打开测试付款窗口 →', paying: '正在提交官方测试付款…', paid: '开始下一笔购物 →', unknown: '付款结果待核对', 'not-authorised': '开始下一笔购物 →' };
  $('main-action').textContent = texts[state.phase] ?? '继续';
  $('main-action').disabled = busy || ['unknown', 'paying'].includes(state.phase);
  $('pay').disabled = busy || state.phase !== 'checkout';
  $('pay').textContent = busy ? '正在验证并提交测试付款…' : `确认并模拟支付 ${state.order ? money(state.order.amountMinor) : ''}`;
  $('dialog-close').disabled = busy;
  $('attack').disabled = busy || state.phase !== 'cart';
  $('reissue').disabled = busy || state.phase !== 'cart';
  $('revoke').disabled = busy || !state.credential || !['cart', 'checkout'].includes(state.phase);
  $('receipt').hidden = state.phase !== 'paid';
  if (state.result) {
    $('receipt-amount').textContent = money(state.result.amountMinor);
    $('receipt-reference').textContent = state.result.providerReference;
    $('receipt-result').textContent = `${state.result.resultCode} · 官方测试环境`;
  }
  for (const step of document.querySelectorAll('.step')) step.classList.toggle('active', Number(step.dataset.step) === (state.phase === 'paid' ? 2 : ['checkout', 'paying'].includes(state.phase) ? 1 : 0));
  $('verification-steps').replaceChildren(...(state.verification?.steps ?? []).map(step => {
    const item = document.createElement('div'); item.className = `verification-item ${step.status === 'fail' ? 'fail' : ''}`; item.textContent = step.label; return item;
  }));
  $('evidence').textContent = JSON.stringify({ order: state.order, credential: state.credential, verification: state.verification, providerResult: state.result, actors: state.actors }, null, 2);
}
async function action(path, progress) {
  if (localBusy) return;
  localBusy = true;
  render({ ...current, message: progress });
  try { const data = await request(path, 'POST'); localBusy = false; render(data); return data; }
  catch (error) { localBusy = false; render({ ...current, message: error.message }); $('payment-note').textContent = error.message; throw error; }
}
async function showPayment() {
  $('payment-note').textContent = '点击确认后，助手会重新验证本笔订单，并使用官方测试卡提交一次付款。';
  if (!$('payment-dialog').open) $('payment-dialog').showModal();
  $('checkout-preview').hidden = true; $('preview-loading').hidden = false;
  try {
    const response = await fetch('/api/adyen/preview', { headers: { 'X-Demo-UI-Key': key } });
    if (!response.ok) throw new Error('当前收银台预览未能加载。');
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    previewUrl = URL.createObjectURL(await response.blob());
    $('checkout-preview').src = previewUrl; $('checkout-preview').hidden = false;
    $('preview-loading').hidden = true;
  } catch (error) { $('preview-loading').textContent = error.message; }
}
$('main-action').addEventListener('click', async () => {
  try {
    if (current.phase === 'checkout') return await showPayment();
    if (current.phase === 'cart') {
      const state = await action('/api/adyen/checkout', '正在核验本笔订单的凭证、持有者与软件 eSIM 证明，再打开官方收银台…');
      if (state?.phase === 'checkout') await showPayment();
    } else await action('/api/adyen/connect', '正在连接官方商城，读取耳机商品与实时价格…');
  } catch {}
});
$('pay').addEventListener('click', async () => {
  try {
    const state = await action('/api/adyen/pay', '正在复核本笔订单并提交一次官方测试付款…');
    if (state?.phase === 'paid' || state?.phase === 'not-authorised') $('payment-dialog').close();
    if (state?.phase === 'paid') $('receipt').scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch {}
});
$('dialog-close').addEventListener('click', () => $('payment-dialog').close());
$('payment-dialog').addEventListener('cancel', event => { if (localBusy) event.preventDefault(); });
function details(show) { $('details').hidden = !show; if (show) $('details').scrollIntoView({ behavior: 'smooth', block: 'start' }); }
$('details-toggle').addEventListener('click', () => details($('details').hidden));
$('details-close').addEventListener('click', () => details(false));
for (const [id, progress] of [['attack', '正在实际验证缺少设备证明的请求…'], ['revoke', '正在由签发方撤销这张凭证…'], ['reissue', '正在签发绑定持有者与设备的新凭证…']]) $(id).addEventListener('click', () => action(`/api/adyen/${id}`, progress).catch(() => {}));
request('/api/adyen/state').then(render).catch(error => {
  current = { phase: 'error', message: error.message };
  render(current);
  if (!key) { $('main-action').disabled = true; $('status').textContent = '请双击“启动 Adyen 购物演示.cmd”，打开带有本次会话权限的入口。'; }
});
