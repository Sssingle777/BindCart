import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const guide = await readFile(new URL('../public/guide.js', import.meta.url), 'utf8');
const shell = await readFile(new URL('../public/demo.js', import.meta.url), 'utf8');
const activation = guide.slice(guide.indexOf('function activateGuideRoute('), guide.indexOf("window.addEventListener('demo:activate'"));
const notification = shell.slice(shell.indexOf('function notifyFrame('), shell.indexOf('function loadFrame('));
const flush = () => new Promise(resolve => setImmediate(resolve));

// Exercise the actual routing coordinator with controllable state-read boundaries.
// Rendering, cryptography and server state are outside this regression's scope.
function page({ scenario = 'normal', mode = 'bbs-bls', savedMode = mode, refreshing = false } = {}) {
  const calls = [], selector = { value: mode }, dialog = { open: true, close() { this.open = false; } };
  const context = {
    scenario, busy: false, experimentBusy: false, refreshing, pendingGuideRoute: null,
    scenarios: { normal: {}, 'copied-vc': {}, revoked: {} },
    mode: () => selector.value, store: { get: () => savedMode },
    renderModeDescription(){},
    state: { mode }, ownerProposal: { id: 'old-proposal' }, generation: 0,
    $: id => id === 'guide-mode' ? selector : dialog,
    queueMicrotask,
    refresh() { calls.push({ kind: 'normal-read', mode: selector.value }); context.refreshing = true; },
    experiment: { refresh() { calls.push({ kind: 'experiment-read', mode: selector.value }); context.experimentBusy = true; } },
    selectScenario(next, options) {
      calls.push({ kind: 'select', scenario: next, mode: selector.value, fromHistory: options.fromHistory });
      context.scenario = next;
      if (next === 'normal') context.refresh(); else context.experiment.refresh();
    },
  };
  runInNewContext(activation, context, { filename: 'public/guide.js#activation' });
  return { context, calls, selector, dialog };
}

test('returning to another scene synchronizes the shared mode before exactly one state read', () => {
  const p = page({ scenario: 'copied-vc', savedMode: 'bbs-blind-bls' });
  p.context.activateGuideRoute({ scenario: 'normal', activate: true });
  assert.deepEqual(p.calls, [
    { kind: 'select', scenario: 'normal', mode: 'bbs-blind-bls', fromHistory: true },
    { kind: 'normal-read', mode: 'bbs-blind-bls' },
  ]);
  assert.equal(p.context.state, null);
  assert.equal(p.context.ownerProposal, null);
  assert.equal(p.dialog.open, false);
});

test('unchanged initial load notification does not duplicate the startup read', async () => {
  const p = page({ refreshing: true });
  p.context.activateGuideRoute({ scenario: 'normal', activate: false });
  p.context.refreshing = false;
  p.context.drainGuideRoute();
  await flush();
  assert.deepEqual(p.calls, []);
});

test('a route arriving during startup is applied once after the read finishes', async () => {
  const p = page({ refreshing: true, savedMode: 'bbs-blind-bls' });
  p.context.activateGuideRoute({ scenario: 'revoked', activate: false });
  assert.deepEqual(p.calls, []);
  p.context.refreshing = false;
  p.context.drainGuideRoute();
  p.context.drainGuideRoute();
  await flush();
  assert.deepEqual(p.calls, [
    { kind: 'select', scenario: 'revoked', mode: 'bbs-blind-bls', fromHistory: true },
    { kind: 'experiment-read', mode: 'bbs-blind-bls' },
  ]);
});

test('the newest route can cancel a queued scene change without another read', async () => {
  const p = page({ refreshing: true });
  p.context.activateGuideRoute({ scenario: 'revoked', activate: true });
  p.context.activateGuideRoute({ scenario: 'normal', activate: true });
  p.context.refreshing = false;
  p.context.drainGuideRoute();
  await flush();
  assert.deepEqual(p.calls, []);
});

test('same-scene activation with a new mode reads the new mode once', () => {
  const p = page({ scenario: 'revoked', savedMode: 'bbs-blind-bls' });
  p.context.activateGuideRoute({ scenario: 'revoked', activate: true });
  assert.deepEqual(p.calls, [{ kind: 'experiment-read', mode: 'bbs-blind-bls' }]);
});

test('the shell sends one atomic guide message and preserves ordinary frame activation', () => {
  const messages = [];
  const context = { route: { scenario: 'revoked' }, location: { origin: 'http://127.0.0.1:4340' },
    $: id => ({ contentWindow: { postMessage: (message, origin) => messages.push({ id, message: JSON.parse(JSON.stringify(message)), origin }) } }) };
  runInNewContext(notification, context, { filename: 'public/demo.js#notifyFrame' });
  context.notifyFrame('guide', true);
  assert.deepEqual(messages.map(value => value.message), [{ type: 'demo:guide-route', scenario: 'revoked', activate: true }]);
  messages.length = 0;
  context.notifyFrame('manage', true);
  assert.deepEqual(messages.map(value => value.message), [{ type: 'demo:activate' }]);
});


function historyPage(options={}) {
  const p=page(options);
  p.context.pathScenario=()=>p.destination;
  p.context.window={addEventListener(){}};
  const start=guide.indexOf('function restoreScenarioFromHistory(){'),end=guide.indexOf("$('guide-main').onclick",start);
  runInNewContext(guide.slice(start,end),p.context);
  return p;
}

test('standalone Back queues its target while busy and applies it without another history write',async()=>{
  const p=historyPage({scenario:'copied-vc'});p.context.busy=true;p.destination='normal';
  p.context.restoreScenarioFromHistory();assert.deepEqual(p.calls,[]);
  assert.equal(p.context.pendingGuideRoute.scenario,'normal');
  p.context.busy=false;p.context.drainGuideRoute();p.context.drainGuideRoute();await flush();
  assert.deepEqual(p.calls,[{kind:'select',scenario:'normal',mode:'bbs-bls',fromHistory:true},{kind:'normal-read',mode:'bbs-bls'}]);
});

test('standalone Forward back to the current scene cancels an earlier busy Back',async()=>{
  const p=historyPage({scenario:'copied-vc'});p.context.experimentBusy=true;
  p.destination='normal';p.context.restoreScenarioFromHistory();
  p.destination='copied-vc';p.context.restoreScenarioFromHistory();
  p.context.experimentBusy=false;p.context.drainGuideRoute();await flush();assert.deepEqual(p.calls,[]);
});
