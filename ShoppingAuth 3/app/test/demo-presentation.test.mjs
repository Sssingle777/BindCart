import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { views, scenarios, normalizeRoute, routeHash, availableViews } from '../public/navigation-model.js';

const source = (await readFile(new URL('../public/demo.js', import.meta.url), 'utf8')).replace(/^import[^\n]+\n/, '');
const flush = () => new Promise(resolve => setImmediate(resolve));

function shell({ preference, hash = '#view=guide&scenario=normal', deniedStorage = false } = {}) {
  const nodes = new Map(), listeners = new Map(), requests = [], messages = [], frameLoads = [], preferences = new Map();
  if (preference) preferences.set('a2a-demo-display', preference);
  const location = { origin: 'http://127.0.0.1:4340', hash };
  let activeElement;
  const node = id => {
    if (!nodes.has(id)) {
      const attrs = new Map(), handlers = new Map();
      let src;
      const value = { id, hidden: true, disabled: false, dataset: {}, value: '', textContent: '', handlers,
        classList: { toggle() {} },
        setAttribute(name, content) { attrs.set(name, content); }, getAttribute(name) { return attrs.get(name); }, removeAttribute(name) { attrs.delete(name); },
        addEventListener(name, callback) { handlers.set(name, callback); },
        focus() { activeElement = this; },
        contains(target) { return target === this || (id === 'platform-navigation' && target?.id?.startsWith('tab-')); },
        click() { if (!this.disabled) handlers.get('click')?.(); },
        get src() { return src; }, set src(value) { src = value; frameLoads.push({ id, value }); },
      };
      if (id.startsWith('frame-')) value.contentWindow = { postMessage(message, origin) { messages.push({ message: JSON.parse(JSON.stringify(message)), origin }); }, scrollTo() {} };
      nodes.set(id, value);
    }
    return nodes.get(id);
  };
  const buttons = Object.keys(views).map(view => { const item = node(`tab-${view}`); item.dataset.view = view; if (['guide', 'manage', 'attacks', 'owner'].includes(view)) item.setAttribute('role', 'tab'); return item; });
  const document = { getElementById: node, body: node('body'), get activeElement() { return activeElement; },
    querySelectorAll: selector => selector === '[data-view]' ? buttons : buttons.filter(item => item.getAttribute('role') === 'tab'),
    querySelector: selector => selector === '.demo-tabs [aria-selected=true]' ? buttons.find(item => item.getAttribute('aria-selected') === 'true') : node(selector),
  };
  runInNewContext(source, {
    views, scenarios, normalizeRoute, routeHash, availableViews, URL, URLSearchParams, AbortSignal, location, document,
    history: { replaceState(state, title, url) { location.hash = new URL(url, location.origin).hash; }, pushState(state, title, url) { location.hash = new URL(url, location.origin).hash; } },
    window: { addEventListener(name, fn) { listeners.set(name, fn); } }, matchMedia: () => ({ matches: false }),
    sessionStorage: { getItem: () => '', setItem() {}, removeItem() {} },
    localStorage: { getItem(key) { if (deniedStorage) throw Error('unavailable'); return preferences.get(key); }, setItem(key, value) { if (deniedStorage) throw Error('unavailable'); preferences.set(key, value); } },
    fetch(path, init) { return new Promise(resolve => requests.push({ path, init, resolve })); },
  }, { filename: 'public/demo.js' });
  return { node, requests, messages, frameLoads, preferences, listeners, location, document,
    async ready(health = { namedAvailable: true, dbacAvailable: true, ownerAvailable: true }) { requests[0].resolve({ ok: true, json: async () => health }); await flush(); },
    message(data, { view = 'guide', origin = location.origin, source = node(`frame-${view}`).contentWindow } = {}) { listeners.get('message')({ data, origin, source }); },
  };
}

test('the first guide visit is compact and display controls never reload a frame or send business or activation requests', async () => {
  const p = shell(); await p.ready();
  assert.equal(p.node('body').dataset.presentation, 'compact');
  assert.equal(p.node('platform-navigation').hidden, true);
  assert.equal(p.node('platform-tools-toggle').hidden, false);
  p.node('platform-tools-toggle').click();
  assert.equal(p.node('platform-navigation').hidden, false);
  assert.equal(p.node('platform-tools-toggle').getAttribute('aria-expanded'), 'true');
  p.listeners.get('keydown')({ key: 'Escape', preventDefault() {} });
  assert.equal(p.node('platform-navigation').hidden, true);
  assert.equal(p.document.activeElement.id, 'platform-tools-toggle');
  p.node('presentation-toggle').click();
  assert.equal(p.node('body').dataset.presentation, 'platform');
  assert.equal(p.node('platform-navigation').hidden, false);
  assert.equal(p.node('presentation-toggle').textContent, '收起平台导航');
  p.node('presentation-toggle').click();
  assert.equal(p.node('body').dataset.presentation, 'compact');
  assert.deepEqual(p.frameLoads, [{ id: 'frame-guide', value: '/guide/normal.html' }]);
  assert.deepEqual(p.messages, []);
  assert.deepEqual(p.requests.map(item => item.path), ['/api/health']);
  assert.deepEqual([...p.preferences], [['a2a-demo-display', 'compact']]);
});

test('the display preference persists across every module and refresh without reloading retained frames', async () => {
  const p = shell({ preference: 'platform' }); await p.ready();
  assert.equal(p.node('body').dataset.presentation, 'platform');
  p.node('presentation-toggle').click();
  for (const view of Object.keys(views)) {
    p.node('platform-tools-toggle').click();
    p.node(`tab-${view}`).click();
    assert.equal(p.node('body').dataset.presentation, 'compact', `${view} keeps compact preference`);
    assert.equal(p.node('platform-navigation').hidden, true, 'choosing a module only closes the popover');
    assert.equal(p.node('platform-tools-toggle').hidden, false);
    assert.equal(p.node('presentation-toggle').hidden, false);
    assert.equal(p.node('shell-scenarios').hidden, view !== 'guide');
    assert.equal(p.node('shell-module-context').hidden, view === 'guide');
  }
  p.node('tab-guide').click();
  assert.equal(p.frameLoads.filter(item => item.id === 'frame-guide').length, 1);
  const refreshed = shell({ preference: p.preferences.get('a2a-demo-display') }); await refreshed.ready();
  assert.equal(refreshed.node('body').dataset.presentation, 'compact');
});

test('the single scenario navigation uses the original loaded frame and route restoration only', async () => {
  const p = shell(); await p.ready();
  p.node('scenario-copied-vc').click();
  assert.equal(p.location.hash, '#view=guide&scenario=copied-vc');
  assert.equal(p.node('scenario-copied-vc').getAttribute('aria-pressed'), 'true');
  assert.deepEqual(p.messages.map(item => item.message), [{ type: 'demo:guide-route', scenario: 'copied-vc', activate: true }]);
  p.node('scenario-copied-vc').click();
  assert.equal(p.messages.length, 1, 'reselecting a scenario does not cause another read');
  p.message({ type: 'demo:scenario-selected', scenario: 'revoked' });
  assert.equal(p.node('scenario-revoked').getAttribute('aria-pressed'), 'true');
  assert.equal(p.frameLoads.length, 1);
  assert.deepEqual(p.requests.map(item => item.path), ['/api/health']);
});

test('compact tools and scenarios preserve the busy lock and reject messages from foreign origins or unknown frames', async () => {
  const p = shell(); await p.ready();
  p.message({ type: 'demo:busy', busy: true });
  p.node('platform-tools-toggle').click();
  assert.equal(p.node('tab-attacks').disabled, true);
  assert.equal(p.node('scenario-revoked').disabled, true);
  p.node('tab-attacks').click(); p.node('scenario-revoked').click();
  p.node('presentation-toggle').click();
  assert.equal(p.node('body').dataset.presentation, 'platform', 'display-only changes remain possible during a request');
  p.message({ type: 'demo:busy', busy: false }, { origin: 'https://untrusted.example' });
  p.message({ type: 'demo:busy', busy: false }, { source: {} });
  assert.equal(p.node('tab-attacks').disabled, true);
  assert.equal(p.location.hash, '#view=guide&scenario=normal');
  assert.equal(p.frameLoads.length, 1); assert.deepEqual(p.messages, []);
  p.message({ type: 'demo:busy', busy: false });
  assert.equal(p.node('scenario-revoked').disabled, false);
});

test('storage denial does not break a display change and auxiliary startup never enables scenarios', async () => {
  const p = shell({ deniedStorage: true }); await p.ready();
  p.node('presentation-toggle').click();
  assert.equal(p.node('body').dataset.presentation, 'platform');
  const auxiliary = shell(); await auxiliary.ready({ namedAvailable: false, dbacAvailable: true, ownerAvailable: false });
  assert.equal(auxiliary.node('body').dataset.module, 'diagnostic');
  assert.equal(auxiliary.node('body').dataset.presentation, 'compact');
  assert.equal(auxiliary.node('shell-scenarios').hidden, true);
  for (const scenario of scenarios) assert.equal(auxiliary.node(`scenario-${scenario}`).disabled, true);
});

test('closing a compact tools menu by returning to the guide restores focus to its visible trigger', async () => {
  const p = shell(); await p.ready();
  p.node('platform-tools-toggle').click();
  p.node('tab-guide').focus(); p.node('tab-guide').click();
  assert.equal(p.node('platform-navigation').hidden, true);
  assert.equal(p.document.activeElement.id, 'platform-tools-toggle');
});


test('expanded preference is global for direct entry and invalid saved values fall back to compact', async () => {
  for (const view of Object.keys(views)) {
    for (const preference of ['platform', 'compact', 'invalid', '']) {
      const p = shell({ preference, hash: `#view=${view}` }); await p.ready();
      const expanded = preference === 'platform';
      assert.equal(p.node('body').dataset.presentation, expanded ? 'platform' : 'compact');
      assert.equal(p.node('presentation-toggle').hidden, false);
      assert.equal(p.node('platform-navigation').hidden, !expanded);
      p.node('presentation-toggle').click();
      p.node('tab-attacks').click();
      assert.equal(p.node('body').dataset.presentation, expanded ? 'compact' : 'platform');
      assert.equal(p.requests.length, 1, 'display controls and routes only perform initial health GET');
      for (const frame of new Set(p.frameLoads.map(item => item.id))) assert.equal(p.frameLoads.filter(item => item.id === frame).length, 1);
    }
  }
});
