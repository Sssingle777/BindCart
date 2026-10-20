'use strict';
const activeOperations = new Set();
window.DemoEmbed = Object.freeze({setBusy(source, value) {
  if (value) activeOperations.add(source); else activeOperations.delete(source);
  if (window.parent !== window) window.parent.postMessage({type:'demo:busy',busy:activeOperations.size > 0},location.origin);
}});
if (window.parent !== window) {
  document.documentElement.classList.add('demo-embedded');
  let scheduled = false;
  function report() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      const shell = document.querySelector('.page-shell, .shell') || document.body;
      window.parent.postMessage({ type:'demo:height', height:Math.ceil(shell.getBoundingClientRect().height + 16) }, location.origin);
    });
  }
  new ResizeObserver(report).observe(document.body);
  window.addEventListener('load', report);
  window.addEventListener('message', event => {
    if (event.origin !== location.origin || event.source !== window.parent || event.data?.type !== 'demo:activate') return;
    window.dispatchEvent(new CustomEvent('demo:activate'));
    report();
  });
  report();
}

document.addEventListener('click',event=>{const link=event.target.closest('a[data-demo-view]');if(!link)return;if(window.parent!==window){event.preventDefault();window.parent.postMessage({type:'demo:navigate',view:link.dataset.demoView},location.origin);}});
