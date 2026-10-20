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
    note.hidden = !storageBlocked;
    note.textContent = storageBlocked
      ? '浏览器未允许会话存储。请允许本站会话存储后，重新运行启动器。'
      : '';
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
      note.hidden = false;
      note.scrollIntoView({ block: 'center', behavior: 'auto' });
    });
  }
  // Native modal details retain the full principles without resizing the cards.
  // showModal provides focus containment, Escape dismissal and focus restoration.
  for (const trigger of document.querySelectorAll('[data-tech-detail]')) {
    const dialog = document.getElementById(trigger.dataset.techDetail);
    trigger.addEventListener('click', () => dialog.showModal());
  }
})();

// All motion is decorative; it never starts a protocol step or changes access state.
(() => {
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
  const finePointer = matchMedia('(hover: hover) and (pointer: fine)');
  let dispose = () => {};

  function configureMotion() {
    dispose();
    const root = document.documentElement;
    const controller = new AbortController();
    const { signal } = controller;
    const animations = new Map();
    const observers = [];
    const pointerCleanup = [];
    const updatePause = () => {
      const paused = reducedMotion.matches || document.hidden;
      root.classList.toggle('motion-paused', paused);
      for (const animation of animations.values()) {
        if (paused) animation.pause(); else animation.play();
      }
    };
    document.addEventListener('visibilitychange', updatePause, { signal });
    updatePause();
    dispose = () => {
      controller.abort();
      observers.forEach(observer => observer.disconnect());
      for (const animation of animations.values()) animation.cancel();
      animations.clear();
      pointerCleanup.forEach(cleanup => cleanup());
    };
    if (reducedMotion.matches) return;

    if ('IntersectionObserver' in window) {
      // Text reveals once on entry; decorative CSS loops keep running independently.
      // Without JS/observer support, the content stays visible.
      if (typeof Element.prototype.animate === 'function') {
        const reveal = new IntersectionObserver(entries => {
          let delay = 0;
          for (const entry of entries) {
            if (!entry.isIntersecting) continue;
            reveal.unobserve(entry.target);
            const animation = entry.target.animate([
              { opacity: 0, translate: '0 12px' },
              { opacity: 1, translate: '0 0' },
            ], { duration: 520, delay, easing: 'cubic-bezier(.22, 1, .36, 1)', fill: 'backwards' });
            delay = Math.min(delay + 65, 195);
            animations.set(entry.target, animation);
            animation.addEventListener('finish', () => animations.delete(entry.target), { once: true });
            if (document.hidden) animation.pause();
          }
        }, { threshold: .1, rootMargin: '0px 0px -20px 0px' });
        document.querySelectorAll('.hero-copy > :not(.access-note), .trust-figure, .technology-strip, .approach .section-heading, .evolution-row, .technology-heading, .tech-card, .technology-summary, .demo-inner').forEach(element => reveal.observe(element));
        observers.push(reveal);
        document.addEventListener('focusin', event => {
          for (const [element, animation] of animations) {
            if (element.contains(event.target)) animation.finish();
          }
        }, { signal });
      }
    }

    if (finePointer.matches) {
      for (const card of document.querySelectorAll('.tech-card')) {
        let frame = 0;
        let pointerX = 0;
        let pointerY = 0;
        const clearGlow = () => {
          cancelAnimationFrame(frame);
          frame = 0;
          card.style.removeProperty('--glow-x');
          card.style.removeProperty('--glow-y');
        };
        card.addEventListener('pointermove', event => {
          if (event.pointerType !== 'mouse' && event.pointerType !== 'pen') return;
          pointerX = event.clientX;
          pointerY = event.clientY;
          if (frame) return;
          frame = requestAnimationFrame(() => {
            frame = 0;
            const rect = card.getBoundingClientRect();
            card.style.setProperty('--glow-x', `${Math.max(0, Math.min(rect.width, pointerX - rect.left))}px`);
            card.style.setProperty('--glow-y', `${Math.max(0, Math.min(rect.height, pointerY - rect.top))}px`);
          });
        }, { signal });
        card.addEventListener('pointerleave', clearGlow, { signal });
        pointerCleanup.push(clearGlow);
      }
      for (const section of document.querySelectorAll('.demo-section')) {
        let frame = 0;
        let pointerX = 0;
        let pointerY = 0;
        const clearDrift = () => {
          cancelAnimationFrame(frame);
          frame = 0;
          section.style.removeProperty('--demo-drift-x');
          section.style.removeProperty('--demo-drift-y');
        };
        section.addEventListener('pointermove', event => {
          if (event.pointerType !== 'mouse' && event.pointerType !== 'pen') return;
          pointerX = event.clientX;
          pointerY = event.clientY;
          if (frame) return;
          frame = requestAnimationFrame(() => {
            frame = 0;
            const rect = section.getBoundingClientRect();
            const x = Math.max(-1, Math.min(1, (pointerX - rect.left) / rect.width * 2 - 1));
            const y = Math.max(-1, Math.min(1, (pointerY - rect.top) / rect.height * 2 - 1));
            section.style.setProperty('--demo-drift-x', `${(x * 6).toFixed(2)}px`);
            section.style.setProperty('--demo-drift-y', `${(y * 4).toFixed(2)}px`);
          });
        }, { signal });
        section.addEventListener('pointerleave', clearDrift, { signal });
        pointerCleanup.push(clearDrift);
      }
    }
  }

  reducedMotion.addEventListener('change', configureMotion);
  finePointer.addEventListener('change', configureMotion);
  configureMotion();
})();
