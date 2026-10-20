/* Independent controller bridge for the complete, preserved MyStore build. */
(() => {
  'use strict';
  const credentials = new URLSearchParams(location.hash.slice(1));
  for (const name of ['key', 'ownerKey']) if (/^[A-Za-z0-9_-]{43}$/.test(credentials.get(name) ?? '')) sessionStorage.setItem(`storefront-${name}`, credentials.get(name));
  if (credentials.has('key') || credentials.has('ownerKey')) history.replaceState(null, '', location.pathname + location.search + '#/');
  const key = sessionStorage.getItem('storefront-key') ?? '', ownerKey = sessionStorage.getItem('storefront-ownerKey') ?? '';
  const initialRoute = location.hash.startsWith('#/') ? location.hash.slice(1) : '/';
  let state, official, initialized = false, busy = false, sequence = 0, queued = Promise.resolve(), refreshTimer, firstRoute = true;
  const initial = api('/api/store/state').then(value => { state = value; initialized = true; return value; });
  let ready = initial;
  initial.catch(error => console.error('MyStore controller:', error.code ?? 'INITIALIZATION_FAILED'));

  async function api(url, body, owner = false) {
    const response = await fetch(url, { method: body === undefined ? 'GET' : 'POST',
      headers: { [owner ? 'X-Owner-UI-Key' : 'X-Demo-UI-Key']: owner ? ownerKey : key, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(120000) });
    const result = await response.json();
    if (!response.ok) {
      if (result.state) state = result.state;
      const error = new Error(result.error?.message ?? '请求失败'); error.code = result.error?.code; throw error;
    }
    return result;
  }
  const manualWaiting = value => ['verifying', 'paying'].includes(value?.phase);
  const pending = value => ['unknown', 'merchant_pending', 'confirming'].includes(value?.phase) || value?.phase !== 'paying' && Boolean(value?.backend?.paymentPending);
  const orderLocked = value => Boolean(value?.order) && !['cart', 'paid'].includes(value?.phase);
  const amount = cents => `${(Number(cents) / 100).toFixed(2)} 测试币`;
  const route = () => official?.store.getState().activeSection ?? '/';
  function go(path) {
    if (!official) return;
    official.store.setState({ activeSection: path });
    if (location.hash !== '#' + path) history.replaceState(null, '', location.pathname + location.search + '#' + path);
    window.scroll(0, 0);
  }
  function products() {
    return (state?.cart ?? []).flatMap(item => { const product = official?.catalog.find(candidate => candidate.id === item.id);
      return product ? [{ ...product, price: item.amountMinor / 10000 }] : []; });
  }
  function update() {
    if (!official || !state) return;
    document.body.dataset.phase = state.phase; document.body.dataset.revision = String(state.revision);
    document.body.dataset.orderId = state.order?.orderId ?? ''; document.body.dataset.busy = String(busy || Boolean(state.busy));
    const next = state.phase === 'paid' ? [] : products();
    if (JSON.stringify(official.store.getState().products) !== JSON.stringify(next)) official.store.setState({ products: next });
    for (const button of document.querySelectorAll('.product-detail__button,.order-summary__list__list-item__remove-product,.local-express-button')) button.disabled = busy || Boolean(state.busy) || orderLocked(state);
    for (const link of document.querySelectorAll('a.button')) link.setAttribute('aria-disabled', String(busy || Boolean(state.busy) || orderLocked(state)));
    for (const button of document.querySelectorAll('.cart_checkout-button')) {
      if (!button.dataset.checkoutText) button.dataset.checkoutText = button.textContent;
      const text = state.phase === 'verifying' ? '等待右侧资格验证' : button.dataset.checkoutText;
      if (button.textContent !== text) button.textContent = text;
    }
    for (const button of document.querySelectorAll('.local-payment-button')) {
      button.disabled = busy || Boolean(state.busy) || manualWaiting(state) || state.phase === 'paid';
      const text = busy || state.busy ? '处理中…' : state.phase === 'paying' ? '等待右侧控制台操作' : state.phase === 'verifying' ? '等待右侧资格验证' : pending(state) ? '查询支付结果' : `支付 ${amount(state.totalMinor / 10000)}`;
      if (button.textContent !== text) button.textContent = text;
    }
  }
  function apply(value, navigate = true) {
    state = value;
    if (navigate && !busy && !state.busy) {
      if (state.phase === 'paid') go('/confirmation');
      else if (state.phase === 'verifying') go('/cart');
      else if (state.phase === 'paying' || pending(state)) go('/checkout');
      else if (state.error) go('/error');
      else if (state.phase === 'checkout') go('/checkout');
      else if (['/confirmation', '/checkout', '/error', '/collaborate'].includes(route())) go(state.cart.length ? '/cart' : '/');
    }
    update();
  }
  function run(action) {
    if (busy || state?.busy) return Promise.resolve(); busy = true; update();
    return (async () => {
      try { await ready; await action(); }
      catch (error) {
        console.error('MyStore controller:', error.code ?? 'REQUEST_FAILED');
        try { state = await api('/api/store/state'); } catch { /* retain last known result */ }
        go(state?.phase === 'verifying' ? '/cart' : state?.phase === 'paying' || pending(state) ? '/checkout' : '/error');
      } finally { busy = false; update(); }
    })();
  }
  function enqueue(action) { queued = queued.then(() => run(action)); return queued; }
  async function resetKeepingCart(keep) {
    const cart = keep ? products().map(item => item.id) : [];
    state = await api('/api/store/new', { revision: state.revision });
    for (const id of cart) state = await api('/api/store/cart', { productId: id, quantity: 1, revision: state.revision });
    update();
  }
  async function navigate(path) {
    if (path === '/confirmation' || path === '/collaborate') { go(state.phase === 'paid' ? '/confirmation' : state.cart.length ? '/cart' : '/'); return; }
    if (state.phase === 'verifying') { go('/cart'); return; }
    if (state.phase === 'paying' || pending(state)) { go('/checkout'); return; }
    if (path === '/checkout') {
      if (state.phase !== 'checkout') state = await api('/api/store/checkout', { revision: state.revision });
      go(state.phase === 'checkout' ? path : '/cart');
    } else {
      if (state.phase === 'paid' || state.error && !orderLocked(state)) await resetKeepingCart(false);
      if (state.phase === 'checkout') { go('/checkout'); return; }
      go(path);
    }
  }
  async function change(product, quantity) {
    if (orderLocked(state)) { go(state.phase === 'verifying' ? '/cart' : '/checkout'); return; }
    if (state.phase !== 'cart') await resetKeepingCart(false);
    state = await api('/api/store/cart', { productId: product.id, quantity, revision: state.revision }); update();
  }
  async function pay() {
    if (manualWaiting(state)) { go(state.phase === 'verifying' ? '/cart' : '/checkout'); return; }
    if (pending(state)) {
      state = await api('/api/store/query', { orderId: state.order.orderId, revision: state.revision });
      if (state.phase === 'paid') go('/confirmation');
      else if (state.phase === 'cart') go(state.cart.length ? '/cart' : '/');
      else go('/checkout');
      return;
    }
    if (state.phase === 'paid') { go('/confirmation'); return; }
    if (state.phase !== 'checkout') throw new Error('订单尚未通过资格验证');
    const proposal = state.backend?.proposal;
    if (!proposal || proposal.payment.orderId !== state.order?.orderId || proposal.payment.amountMinor !== state.totalMinor ||
      JSON.stringify(proposal.payment.merchantOrder) !== JSON.stringify(state.order.merchantOrder)) throw new Error('授权申请与当前商品订单不一致');
    if (proposal.status !== 'APPROVED') await api(`/owner/api/proposals/${encodeURIComponent(proposal.id)}/approve`, {
      confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }, true);
    state = await api('/api/store/pay', { orderId: state.order.orderId, revision: state.revision });
    go(state.phase === 'paid' ? '/confirmation' : '/checkout');
  }
  function mountPayment(container) {
    if (!container) return; container.replaceChildren();
    const button = document.createElement('button'); button.type = 'button'; button.className = 'button local-payment-button'; button.id = 'local-payment-confirm';
    button.addEventListener('click', () => void run(pay)); container.append(button); update();
  }
  window.MyStoreLocal = {
    mount(integration) {
      official = integration; official.localisation.amount = amount; official.localisation.locale = 'zh-CN';
      official.payment.prototype.initPaymentForm = function () { mountPayment(this.ref); };
      const action = official.store.action.bind(official.store);
      official.store.action = function (fn) { const original = action(fn); return function (...args) {
        if (fn.name === 'addProduct') return enqueue(() => change(args[0], 1));
        if (fn.name === 'removeProduct') return enqueue(() => change(args[0], 0));
        if (fn.name === 'removeAllProducts' || fn.name === 'setProducts') return;
        if (fn.name === 'setActiveSection') {
          if (firstRoute) { firstRoute = false; return original('/'); }
          return enqueue(() => navigate(args[0]));
        }
        return original(...args);
      }; };
      official.store.setState({ products: [], activeSection: '/', shopperData: { email: null }, feature: { clickToPay: false }, settings: { ...official.store.getState().settings, locale: 'zh-CN' } });
      ready = initial.then(async value => {
        if (value.phase === 'cart' && value.cart.some(item => !official.catalog.some(product => product.id === item.id))) {
          value = await api('/api/store/new', { revision: value.revision });
        }
        apply(value);
        if (value.phase === 'cart' && !value.error) {
          if (initialRoute === '/checkout' && value.cart.length) go('/cart');
          else if (initialRoute === '/cart' || /^\/product\/0[1-9]$/.test(initialRoute)) go(initialRoute);
        }
      }).catch(error => { go('/error'); throw error; });
      ready.catch(() => {});
      window.addEventListener('hashchange', () => { const path = location.hash.slice(1) || '/'; if (path !== route()) void enqueue(() => navigate(path)); });
      const observer = new MutationObserver(() => { if (initialized) update(); });
      observer.observe(document.body, { childList: true, subtree: true });
      import('/live-feed.js').then(({ observeSystem }) => observeSystem({ key, onSnapshot(snapshot) {
        if (!snapshot.store || snapshot.sequence < sequence) return; sequence = snapshot.sequence;
        if (busy || snapshot.store.revision < (state?.revision ?? 0)) return;
        apply(snapshot.store);
        if (snapshot.store.busy) { clearTimeout(refreshTimer); refreshTimer = setTimeout(() => {
          if (!busy) api('/api/store/state').then(value => apply(value)).catch(() => {});
        }, 1000); }
      } })).catch(() => {});
      window.addEventListener('pagehide', () => { observer.disconnect(); clearTimeout(refreshTimer); }, { once: true });
    },
    express(product) { return enqueue(async () => { await change(product, 1); await navigate('/checkout'); }); },
  };
})();
