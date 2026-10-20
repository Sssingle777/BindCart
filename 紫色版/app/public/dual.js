const fragment = new URLSearchParams(location.hash.slice(1));
for (const name of ['key', 'ownerKey']) if (/^[A-Za-z0-9_-]{43}$/.test(fragment.get(name) ?? '')) sessionStorage.setItem(`storefront-${name}`, fragment.get(name));
history.replaceState(null, '', location.pathname);
const key = sessionStorage.getItem('storefront-key') ?? '', ownerKey = sessionStorage.getItem('storefront-ownerKey') ?? '';
const store = new URL('/store/', location.origin), mechanism = new URL('/mechanism/', location.origin);
store.hash = new URLSearchParams({ key, ownerKey }).toString(); mechanism.hash = new URLSearchParams({ key }).toString();
document.getElementById('open-store').href = store.href; document.getElementById('open-mechanism').href = mechanism.href;
const storeFrame = document.getElementById('store-frame'), mechanismFrame = document.getElementById('mechanism-frame');
let loaded = 0;
for (const frame of [storeFrame, mechanismFrame]) frame.addEventListener('load', () => { if (++loaded >= 2) document.getElementById('dual-status').textContent = '在商城操作，机制页会同步显示同一系统的变化'; });
storeFrame.src = store.href; mechanismFrame.src = mechanism.href;
for (const button of document.querySelectorAll('button[data-layout]')) button.addEventListener('click', () => {
  document.body.dataset.layout = button.dataset.layout;
  for (const item of document.querySelectorAll('button[data-layout]')) item.setAttribute('aria-pressed', String(item === button));
});
document.getElementById('dual-fullscreen').addEventListener('click', async () => {
  try { if (document.fullscreenElement) await document.exitFullscreen(); else await document.documentElement.requestFullscreen(); }
  catch { document.getElementById('dual-status').textContent = '浏览器也可使用 F11 进入全屏。'; }
});
window.addEventListener('message', event => {
  if (event.origin === location.origin && event.source === storeFrame.contentWindow && event.data?.type === 'focus-mechanism') mechanismFrame.focus();
});
