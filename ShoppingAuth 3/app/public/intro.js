// Presentation only: no API calls, protocol mutations, or connection claims.
(() => {
  const valid = value => /^[A-Za-z0-9_-]{43}$/.test(value ?? '');
  let ready = false;
  let storageBlocked = false;
  const note = document.getElementById('access-note');
  function receiveAccess() {
    const fragment = new URLSearchParams(location.hash.slice(1));
    const supplied = ['key', 'ownerKey'].some(name => fragment.has(name));
    // Remove capability fragments even if storage is blocked. Ordinary anchors stay.
    if (supplied) history.replaceState(null, '', location.pathname);
    ready = false;
    storageBlocked = false;
    try {
      if (supplied) {
        // A fresh launch must not mix a new UI key with a stale Owner key.
        for (const name of ['key', 'ownerKey']) {
          sessionStorage.removeItem(`storefront-${name}`);
          if (valid(fragment.get(name))) sessionStorage.setItem(`storefront-${name}`, fragment.get(name));
        }
      }
      ready = ['key', 'ownerKey'].every(name => valid(sessionStorage.getItem(`storefront-${name}`)));
    } catch { storageBlocked = true; }
    note.dataset.warning = String(storageBlocked);
    note.textContent = ready
      ? '启动访问凭据已接收。进入演示后，由原系统确认连接状态。'
      : '完整演示请通过 Start-Windows.cmd 或 Start-Mac.command 启动。';
    if (storageBlocked) {
      note.textContent = '浏览器未允许会话存储。请允许本站会话存储后，重新运行启动器。';
    }
  }
  receiveAccess();
  window.addEventListener('hashchange', receiveAccess);
  for (const link of document.querySelectorAll('[data-demo]')) {
    link.addEventListener('click', event => {
      if (ready) return; // Same-tab /demo/ uses the existing sessionStorage contract.
      event.preventDefault();
      note.textContent = storageBlocked
        ? '请允许本站会话存储后，重新运行启动器。'
        : '请先运行 Start-Windows.cmd 或 Start-Mac.command，再从启动器打开的介绍页进入演示。';
      note.dataset.warning = 'true';
      note.scrollIntoView({ block: 'center', behavior: 'auto' });
    });
  }
})();
