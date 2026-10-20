import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { views, scenarios, normalizeRoute, routeHash, availableViews } from '../public/navigation-model.js';

const controller = (await readFile(new URL('../public/demo.js', import.meta.url), 'utf8')).replace(/^import[^\n]+\n/, '');
const flush = () => new Promise(resolve => setImmediate(resolve));

// Run the actual shell with controllable history, frame messages and health GET.
// Navigating a frame can only send routing/activation messages, never protocol actions.
function page({ hash = '#view=guide&scenario=normal' } = {}) {
  const nodes = new Map(), listeners = new Map(), requests = [], messages = [], writes = [];
  const location = { hash, origin: 'http://127.0.0.1:4340' };
  const entries = [location.hash]; let position = 0;
  const node = id => {
    if (!nodes.has(id)) {
      const attrs = new Map(), handlers = new Map();
      const current = { id, dataset: {}, hidden: true, disabled: false, textContent: '', value: '', handlers,
        classList: { toggle() {} },
        setAttribute(name, value) { attrs.set(name, value); }, getAttribute: name => attrs.get(name), removeAttribute: name => attrs.delete(name),
        addEventListener(name, callback) { handlers.set(name, callback); },
        focus() {}, click() { if (!this.disabled) handlers.get('click')?.(); },
      };
      if (id.startsWith('frame-')) current.contentWindow = {
        postMessage(message, origin) { messages.push({ view: id.slice(6), message: JSON.parse(JSON.stringify(message)), origin }); }, scrollTo() {},
      };
      nodes.set(id, current);
    }
    return nodes.get(id);
  };
  const buttons = Object.keys(views).map(view => {
    const current = node(`tab-${view}`); current.dataset.view = view;
    if (['guide', 'manage', 'attacks', 'owner'].includes(view)) current.setAttribute('role', 'tab');
    return current;
  });
  const history = {
    replaceState(state, title, url) { location.hash = new URL(url, location.origin).hash; entries[position] = location.hash; writes.push({ method: 'replace', hash: location.hash }); },
    pushState(state, title, url) { location.hash = new URL(url, location.origin).hash; entries.splice(position + 1); entries.push(location.hash); position++; writes.push({ method: 'push', hash: location.hash }); },
  };
  const window = { addEventListener(name, callback) { listeners.set(name, callback); } };
  runInNewContext(controller, {
    views, scenarios, normalizeRoute, routeHash, availableViews, URL, URLSearchParams, AbortSignal,
    location, history, window, matchMedia: () => ({ matches: false }),
    sessionStorage: { getItem: () => '', setItem() {}, removeItem() {} },
    document: {
      getElementById: node, body: node('body'),
      querySelectorAll(selector) { return selector === '[data-view]' ? buttons : buttons.filter(button => button.getAttribute('role') === 'tab'); },
      querySelector(selector) { return selector === '.demo-tabs [aria-selected=true]' ? buttons.find(button => button.getAttribute('aria-selected') === 'true') : node(selector); },
    },
    fetch(path, init) { return new Promise(resolve => requests.push({ path, init, resolve })); },
  }, { filename: 'public/demo.js' });
  return { node, buttons, requests, messages, writes, location, entries, listeners,
    async ready() { requests[0].resolve({ ok: true, json: async () => ({ namedAvailable: true, dbacAvailable: true, ownerAvailable: true }) }); await flush(); },
    navigate(view) { node(`tab-${view}`).click(); },
    loaded(view) { node(`frame-${view}`).handlers.get('load')?.(); },
    message(view, data) { listeners.get('message')({ origin: location.origin, source: node(`frame-${view}`).contentWindow, data }); },
    traverse(delta, bothEvents = true) {
      position += delta; assert.ok(position >= 0 && position < entries.length);
      location.hash = entries[position]; listeners.get('popstate')(); if (bothEvents) listeners.get('hashchange')();
    },
    get position() { return position; },
    get requestedFrames() { return [...nodes.keys()].filter(id => id.startsWith('frame-')); },
  };
}

async function loadedHistory() {
  const p = page(); await p.ready(); p.loaded('guide');
  p.navigate('attacks'); p.loaded('attacks'); p.navigate('guide');
  p.messages.length = 0; p.writes.length = 0;
  return p;
}

test('Back during a busy frame preserves the browser entry and applies the destination exactly once after completion', async () => {
  const p = await loadedHistory();
  p.message('guide', { type: 'demo:busy', busy: true });
  const before = [...p.entries]; p.traverse(-1);
  assert.equal(p.location.hash, '#view=attacks');
  assert.equal(p.node('body').dataset.module, 'guide');
  assert.deepEqual(p.entries, before);
  assert.deepEqual(p.writes, []); assert.deepEqual(p.messages, []);
  p.message('guide', { type: 'demo:busy', busy: false });
  assert.equal(p.node('body').dataset.module, 'attacks');
  assert.deepEqual(p.messages.map(entry => entry.message), [{ type: 'demo:activate' }]);
  assert.deepEqual(p.writes, []); assert.deepEqual(p.entries, before);
  p.listeners.get('hashchange')(); p.message('guide', { type: 'demo:busy', busy: false });
  assert.equal(p.messages.length, 1, 'duplicate history events and busy releases do not reactivate');
  assert.equal(p.requests.length, 1); assert.equal(p.requests[0].path, '/api/health');
});

test('rapid Back then Forward while busy cancels the queued scene change without another activation', async () => {
  const p = await loadedHistory();
  p.message('guide', { type: 'demo:busy', busy: true });
  const before = [...p.entries]; p.traverse(-1); p.traverse(1);
  p.message('guide', { type: 'demo:busy', busy: false });
  assert.equal(p.location.hash, '#view=guide&scenario=normal');
  assert.equal(p.node('body').dataset.module, 'guide');
  assert.deepEqual(p.entries, before); assert.deepEqual(p.writes, []); assert.deepEqual(p.messages, []);
});

test('the latest of several history destinations wins and waits until every busy frame has finished', async () => {
  const p = await loadedHistory();
  p.message('guide', { type: 'demo:busy', busy: true });
  p.message('attacks', { type: 'demo:busy', busy: true });
  p.traverse(-1); p.traverse(-1); p.traverse(1);
  assert.equal(p.location.hash, '#view=attacks');
  p.message('guide', { type: 'demo:busy', busy: false });
  assert.equal(p.node('body').dataset.module, 'guide'); assert.deepEqual(p.messages, []);
  p.message('attacks', { type: 'demo:busy', busy: false });
  assert.equal(p.node('body').dataset.module, 'attacks');
  assert.deepEqual(p.messages.map(entry => entry.message), [{ type: 'demo:activate' }]);
  assert.deepEqual(p.writes, []);
});

test('a history scenario is forwarded atomically to the guide and popstate/hashchange do not duplicate it', async () => {
  const p = await loadedHistory();
  p.message('guide', { type: 'demo:scenario-selected', scenario: 'revoked' });
  p.messages.length = 0; p.writes.length = 0;
  p.message('guide', { type: 'demo:busy', busy: true }); p.traverse(-1);
  assert.equal(p.location.hash, '#view=guide&scenario=normal');
  p.message('guide', { type: 'demo:busy', busy: false });
  assert.deepEqual(p.messages.map(entry => entry.message), [{ type: 'demo:guide-route', scenario: 'normal', activate: true }]);
  assert.deepEqual(p.writes, []);
  p.traverse(1);
  assert.deepEqual(p.messages.at(-1).message, { type: 'demo:guide-route', scenario: 'revoked', activate: true });
  assert.equal(p.messages.length, 2); assert.deepEqual(p.writes, []);
});

test('a late scenario announcement cannot rewrite a pending history destination', async () => {
  const p = await loadedHistory();
  p.message('guide', { type: 'demo:busy', busy: true }); p.traverse(-1);
  p.message('guide', { type: 'demo:scenario-selected', scenario: 'revoked' });
  assert.equal(p.location.hash, '#view=attacks'); assert.deepEqual(p.writes, []);
  p.message('guide', { type: 'demo:busy', busy: false });
  assert.equal(p.node('body').dataset.module, 'attacks');
  assert.deepEqual(p.messages.map(entry => entry.message), [{ type: 'demo:activate' }]);
});

test('Back and Forward while idle do not push or replace the traversed entries', async () => {
  const p = await loadedHistory(), before = [...p.entries];
  p.traverse(-1); p.traverse(1);
  assert.deepEqual(p.messages.map(entry => entry.message), [{ type: 'demo:activate' }, { type: 'demo:guide-route', scenario: 'normal', activate: true }]);
  assert.deepEqual(p.entries, before); assert.deepEqual(p.writes, []);
});

test('a route requested during the startup health read is applied without replacing its history entry', async () => {
  const p = page();
  p.entries.push('#view=attacks'); p.traverse(1);
  p.writes.length = 0;
  await p.ready();
  assert.equal(p.node('body').dataset.module, 'attacks');
  assert.equal(p.location.hash, '#view=attacks');
  assert.deepEqual(p.writes, []);
  assert.equal(p.node('frame-attacks').src, '/workspace.html?module=attacks');
});

test('busy module buttons and navigation messages cannot dispatch a new route or business operation', async () => {
  const p = await loadedHistory();
  p.message('guide', { type: 'demo:busy', busy: true });
  p.navigate('attacks'); p.message('guide', { type: 'demo:navigate', view: 'attacks' });
  assert.equal(p.node('body').dataset.module, 'guide'); assert.deepEqual(p.writes, []); assert.deepEqual(p.messages, []);
  p.message('guide', { type: 'demo:busy', busy: false });
  assert.deepEqual(p.messages, []);
  assert.equal(p.requests.length, 1, 'navigation invokes no business endpoint');
});

for (const retired of ['payment-detail', 'payment-advanced']) test(`the retired ${retired} bookmark loads the guide and retains its selected scenario`, async () => {
  const p = page({ hash: `#view=${retired}&scenario=revoked` }); await p.ready(); p.loaded('guide');
  assert.equal(p.location.hash, '#view=guide&scenario=revoked');
  assert.equal(p.node('body').dataset.module, 'guide');
  assert.equal(p.node('frame-guide').src, '/guide/revoked.html');
  assert.deepEqual(p.requestedFrames, ['frame-guide']);
  assert.deepEqual(p.messages.map(entry => entry.message), [{ type: 'demo:guide-route', scenario: 'revoked', activate: false }]);
  assert.equal(p.requests.length, 1, 'retired navigation never calls a business endpoint');
});

test('a retired route reached through busy history restores the guide without creating an obsolete frame or rewriting history', async () => {
  const p = await loadedHistory();
  p.entries.push('#view=payment-advanced&scenario=copied-vc');
  p.message('guide', { type: 'demo:busy', busy: true }); p.traverse(1);
  assert.equal(p.location.hash, '#view=payment-advanced&scenario=copied-vc');
  assert.deepEqual(p.writes, []); assert.deepEqual(p.messages, []);
  p.message('guide', { type: 'demo:busy', busy: false });
  assert.equal(p.node('body').dataset.module, 'guide');
  assert.deepEqual(p.messages.map(entry => entry.message), [{ type: 'demo:guide-route', scenario: 'copied-vc', activate: true }]);
  assert.deepEqual(p.writes, []);
  assert.ok(p.requestedFrames.every(id => id !== 'frame-payment-detail'));
});
