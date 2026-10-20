import test from 'node:test';
import assert from 'node:assert/strict';
import { createExperimentGuide, experimentSummary, experimentDeviceContrast, replaceExperimentView } from '../public/guide-experiments.js';

const ids = ['w3c_bbs', 'vc_device_binding', 'holder_signature', 'device_pairing', 'knowledge', 'credential_pairing', 'challenge', 'replay', 'credential_status', 'consume'];
function result(scenarioId = 'copied-vc') {
  const rejectedAt = scenarioId === 'copied-vc' ? 'vc_device_binding' : 'credential_status';
  const skipped = scenarioId === 'copied-vc' ? ['holder_signature', 'device_pairing', 'knowledge', 'credential_pairing', 'credential_status', 'consume'] : ['consume'];
  return { mode: 'bbs-bls', scenarioId, completion: 'completed', requestRejected: true, authenticationIssued: false,
    actual: scenarioId === 'copied-vc' ? 'W3C_DEVICE_PROOF_REQUIRED' : 'W3C_CREDENTIAL_REVOKED', expectationMet: true,
    verificationTrace: { source: 'agent-b', profile: 'dbac-payment', outcome: 'fail', steps: ids.map(id => ({ id, title: id, status: id === rejectedAt ? 'fail' : skipped.includes(id) ? 'skipped' : 'pass' })) } };
}

test('copied VC shows actual rejection while later checks remain unconfirmed', () => {
  const summary = experimentSummary(result());
  assert.equal(summary.state, 'fail');
  assert.match(summary.title, /被验证者 B 拒绝/);
  assert.equal(summary.groups.find(item => item.id === 'credential').status, 'pass');
  assert.equal(summary.groups.find(item => item.id === 'proofs').status, 'fail');
  assert.equal(summary.groups.find(item => item.id === 'status').status, 'pending');
});

test('revoked original-holder record separates valid proofs from rejected status', () => {
  const summary = experimentSummary(result('revoked'));
  assert.equal(summary.groups.find(item => item.id === 'proofs').status, 'pass');
  assert.equal(summary.groups.find(item => item.id === 'status').status, 'fail');
});

test('expected match, pre-verifier errors, missing traces and contradictory acceptance cannot create success', () => {
  for (const change of [
    { completion: 'incomplete' }, { verificationTrace: null },
    { verificationTrace: { source: 'agent-a', outcome: 'fail', steps: [{ id: 'preparation', status: 'fail' }] } },
    { actual: 'ACCEPTED', authenticationIssued: true, requestRejected: false },
  ]) assert.equal(experimentSummary({ ...result(), ...change }).state, 'pending');
  const accepted = { ...result(), actual: 'ACCEPTED', authenticationIssued: true, requestRejected: false,
    verificationTrace: { source: 'agent-b', outcome: 'pass', steps: ids.map(id => ({ id, status: 'pass' })) } };
  assert.equal(experimentSummary(accepted).state, 'pass', 'an unexpected real acceptance is visible');
  accepted.verificationTrace.steps[0].evidence = [{ match: false }];
  assert.equal(experimentSummary(accepted).state, 'pending');
  accepted.verificationTrace.steps[0].evidence = [];
  accepted.verificationTrace.steps.push({ id: 'w3c_bbs', status: 'pass' });
  assert.equal(experimentSummary(accepted).state, 'pending', 'duplicate evidence cannot satisfy the group');
});

function environment(t) {
  const originalStorage = globalThis.sessionStorage, originalWindow = globalThis.window;
  const storage = new Map();
  globalThis.sessionStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  globalThis.window = {};
  t.after(() => { if (originalStorage === undefined) delete globalThis.sessionStorage; else globalThis.sessionStorage = originalStorage;
    if (originalWindow === undefined) delete globalThis.window; else globalThis.window = originalWindow; });
  const root = () => {
    let click;
    return { innerHTML: '', querySelector: () => null, contains: () => true,
      addEventListener: (event, listener) => { if (event === 'click') click = listener; },
      click: action => click({ target: { closest: () => ({ disabled: false, dataset: { experimentAction: action } }) } }),
    };
  };
  return { storage, root };
}
const drain = () => new Promise(resolve => setImmediate(resolve));

// A DOM boundary double replaces nodes on innerHTML assignment and exposes
// browser focus behavior. The actual controller chooses the context to retain.
function experimentView(versions, initial = '') {
  const doc = { body: {}, documentElement: {}, activeElement: null };
  doc.activeElement = doc.body;
  let details = [], actions = [], markup = '', click;
  const root = {
    ownerDocument: doc,
    contains: node => details.some(item => node === item || item.focusables.includes(node)) || actions.includes(node),
    querySelectorAll: selector => selector === 'details' ? details : selector === '[data-experiment-action]' ? actions : [],
    querySelector: () => null,
    addEventListener: (event, listener) => { if (event === 'click') click = listener; },
    click(action) { const button = actions.find(item => item.dataset.experimentAction === action); assert.ok(button); click({ target: button }); },
    details: () => details,
    actions: () => actions,
    doc,
    get innerHTML() { return markup; },
    set innerHTML(value) {
      if (root.contains(doc.activeElement)) doc.activeElement = doc.body;
      markup = value;
      const version = typeof versions === 'function' ? versions(value) : versions[value];
      assert.ok(version);
      details = (version.details || []).map(({ key, check = '', operation = '', row = '', column = '', summary = '查看验证依据', open = false }) => {
        const detail = {
          dataset: key ? { detailKey: key } : {}, open,
          closest(selector) {
            if (selector === '[data-operation-id]') return operation ? { dataset: { operationId: operation } } : null;
            if (selector === '[data-check-id]') return check ? { dataset: { checkId: check } } : null;
            if (selector === '.guide-evidence-row') return row ? { querySelector: () => ({ textContent: row }) } : null;
            if (selector === 'dd') return column ? { previousElementSibling: { textContent: column } } : null;
            throw new Error(`Unexpected detail selector: ${selector}`);
          },
          querySelector: selector => { assert.equal(selector, 'summary'); return detail.focusables[0]; },
          querySelectorAll: selector => { assert.equal(selector, 'summary, [tabindex], button, a, input, select'); return detail.focusables; },
        };
        detail.focusables = ['SUMMARY', 'PRE'].map((tagName, index) => ({ tagName, textContent: index ? '完整公开值' : summary, dataset: {},
          closest: selector => { assert.equal(selector, 'details'); return detail; },
          focus: options => { assert.deepEqual(options, { preventScroll: true }); doc.activeElement = detail.focusables[index]; },
        }));
        return detail;
      });
      actions = (version.actions || []).map(({ action, disabled = false }) => {
        const button = { dataset: { experimentAction: action }, disabled,
          closest: selector => selector === '[data-experiment-action]' ? button : null,
          focus: options => { assert.deepEqual(options, { preventScroll: true }); if (!button.disabled) doc.activeElement = button; },
        };
        return button;
      });
    },
  };
  root.innerHTML = initial;
  return root;
}

function markupView() {
  return experimentView(html => ({
    details: [...html.matchAll(/<details\b[^>]*data-detail-key="([^"]+)"[^>]*><summary>([\s\S]*?)<\/summary>/g)].map(match => ({ key: match[1], summary: match[2] })),
    actions: [...html.matchAll(/data-experiment-action="([^"]+)"([^>]*)>/g)].map(match => ({ action: match[1], disabled: /\bdisabled\b/.test(match[2]) })),
  }));
}

test('same-run evidence retains distinct control/scenario expansions and the focused public value after replacement', () => {
  const control = { operation: 'control-reference', check: 'w3c_bbs', row: '证明公开值', column: '验证约束 / 预期值', summary: 'identical…value' };
  const scenario = { ...control, operation: '' };
  const observed = { ...scenario, column: 'B 返回的本次记录' };
  const root = experimentView({ before: { details: [control, scenario, observed] }, after: { details: [observed, scenario, control] } }, 'before');
  root.details()[0].open = true; root.details()[1].open = true;
  root.doc.activeElement = root.details()[1].focusables[1];
  replaceExperimentView(root, 'after', { preserve: true });
  assert.deepEqual(root.details().map(item => item.open), [false, true, true]);
  assert.equal(root.doc.activeElement, root.details()[1].focusables[1]);
});

test('changed context clears expansion and focus, while same-context refresh does not steal outside focus', () => {
  const root = experimentView({ before: { details: [{ key: 'source', open: true }] }, after: { details: [{ key: 'source', open: true }] } }, 'before');
  root.doc.activeElement = root.details()[0].focusables[0];
  replaceExperimentView(root, 'after', { preserve: false });
  assert.equal(root.details()[0].open, false); assert.equal(root.doc.activeElement, root.doc.body);
  const outside = {}; root.doc.activeElement = outside;
  replaceExperimentView(root, 'before', { preserve: true, pendingFocus: { detail: 'source', index: 0 } });
  assert.equal(root.doc.activeElement, outside);
});

test('a refresh button regains focus after its same-run read temporarily disables it', () => {
  const root = experimentView({ idle: { actions: [{ action: 'refresh' }] }, reading: { actions: [{ action: 'refresh', disabled: true }] } }, 'idle');
  root.doc.activeElement = root.actions()[0];
  const pendingFocus = replaceExperimentView(root, 'reading', { preserve: true });
  assert.deepEqual(pendingFocus, { action: 'refresh' }); assert.equal(root.doc.activeElement, root.doc.body);
  replaceExperimentView(root, 'idle', { preserve: true, pendingFocus });
  assert.equal(root.doc.activeElement, root.actions()[0]);
});

test('controller keeps a completed run view on refresh and return, then resets it for a new UUID or mode', async t => {
  environment(t);
  const root = markupView(), evidenceRoot = markupView(), calls = []; let selectedMode = 'bbs-bls', latest;
  const guide = createExperimentGuide({ root, evidenceRoot, mode: () => selectedMode, api: async (path, body) => {
    calls.push({ path, body }); if (body) latest = { ...body, status: 'completed', result: result(body.scenarioId) };
    return latest;
  } });
  await guide.select('copied-vc'); root.click('run'); await drain();
  const runId = calls[0].body.runId;
  evidenceRoot.details().find(item => item.dataset.detailKey === 'result-evidence').open = true;
  evidenceRoot.doc.activeElement = evidenceRoot.details().find(item => item.dataset.detailKey === 'result-evidence').focusables[0];
  await guide.refresh();
  assert.equal(evidenceRoot.details().find(item => item.dataset.detailKey === 'result-evidence').open, true);
  assert.equal(evidenceRoot.doc.activeElement, evidenceRoot.details().find(item => item.dataset.detailKey === 'result-evidence').focusables[0]);
  await guide.select('copied-vc');
  assert.equal(evidenceRoot.details().find(item => item.dataset.detailKey === 'result-evidence').open, true);
  assert.equal(calls.filter(call => call.body).length, 1); assert.ok(calls.slice(1).every(call => call.path.endsWith(runId)));
  root.click('run'); await drain();
  assert.notEqual(calls.at(-1).body.runId, runId);
  assert.ok(evidenceRoot.details().every(item => item.open === false)); assert.equal(evidenceRoot.doc.activeElement, evidenceRoot.doc.body);
  evidenceRoot.details().find(item => item.dataset.detailKey === 'run-source').open = true;
  selectedMode = 'bbs-blind-bls'; await guide.refresh();
  assert.ok(evidenceRoot.details().every(item => item.open === false));
  assert.equal(calls.filter(call => call.body).length, 2, 'view preservation never reruns an experiment');
});

test('missing local access disables starting without persisting a run or locking navigation', async t => {
  const env = environment(t), root = env.root(), busyStates = [], calls = [];
  let allowed = false;
  const guide = createExperimentGuide({ root, mode: () => 'bbs-bls', canStart: () => allowed,
    onBusy: value => busyStates.push(value), api: async (path, body) => {
      calls.push({ path, body }); return { ...body, status: 'completed', result: result('revoked') };
    } });
  await guide.select('copied-vc'); root.click('run'); await drain();
  assert.equal(guide.busy(), false);
  assert.deepEqual(busyStates, [false]); assert.equal(calls.length, 0);
  assert.equal(env.storage.has('a2a-guide-experiment-pending-v1'), false);
  assert.match(root.innerHTML, /实验尚未启动/);
  assert.match(root.innerHTML, /data-experiment-action="run" disabled/);
  assert.doesNotMatch(root.innerHTML, /实验正在执行|本次请求已被验证者 B 拒绝/);
  await guide.select('revoked');
  assert.match(root.innerHTML, /data-experiment-scenario="revoked"/);
  allowed = true; await guide.refresh(); root.click('run'); await drain();
  assert.equal(calls.length, 1); assert.equal(calls[0].body.scenarioId, 'revoked');
  assert.equal(guide.getResult().actual, 'W3C_CREDENTIAL_REVOKED');
});

test('definite local, 401 and 403 start denial clears recovery and never claims a safety rejection', async t => {
  const env = environment(t);
  for (const error of [
    Object.assign(new Error('missing key'), { code: 'UI_ACCESS_DENIED', notSubmitted: true }),
    Object.assign(new Error('expired key'), { status: 401, data: { error: { code: 'UI_ACCESS_DENIED' } } }),
    Object.assign(new Error('forbidden key'), { status: 403, notSubmitted: true }),
  ]) {
    const root = env.root(), calls = [], busyStates = [];
    const guide = createExperimentGuide({ root, mode: () => 'bbs-bls', onBusy: value => busyStates.push(value),
      api: async (path, body) => { calls.push({ path, body }); throw error; } });
    await guide.select('copied-vc'); root.click('run'); await drain();
    assert.equal(calls.length, 1); assert.ok(calls[0].body.runId);
    assert.equal(guide.busy(), false); assert.equal(busyStates.at(-1), false);
    assert.equal(env.storage.has('a2a-guide-experiment-pending-v1'), false);
    assert.match(root.innerHTML, /本轮尚未启动/);
    assert.match(root.innerHTML, /不是安全验证拒绝/);
    assert.doesNotMatch(root.innerHTML, /实验正在执行|核对原运行|本次请求已被验证者 B 拒绝/);
    await guide.refresh(); assert.equal(calls.length, 1, 'no nonexistent run is queried after a rejected start');
    await guide.select('revoked'); assert.match(root.innerHTML, /data-experiment-scenario="revoked"/);
    const reloaded = createExperimentGuide({ root: env.root(), mode: () => 'bbs-bls', api: async () => { throw new Error('unexpected recovery request'); } });
    assert.equal(await reloaded.resumePending(), false, 'a page reload does not revive the rejected start');
  }
});

test('denied reads release navigation but preserve the admitted run and recover only its original ID', async t => {
  const env = environment(t), root = env.root(), runId = '2f975630-8b07-4b4c-bca8-9f1614c5eac0', calls = [], events = [];
  env.storage.set('a2a-guide-experiment-pending-v1', JSON.stringify({ runId, mode: 'bbs-bls', scenarioId: 'copied-vc' }));
  let denied = true;
  const guide = createExperimentGuide({ root, mode: () => 'bbs-bls', onChange: event => events.push(event), api: async (path, body) => {
    calls.push({ path, body });
    if (denied) throw Object.assign(new Error('access expired'), { status: 401, code: 'UI_ACCESS_DENIED', notSubmitted: true });
    return { runId, mode: 'bbs-bls', scenarioId: 'copied-vc', status: 'completed', result: result() };
  } });
  assert.equal(await guide.resumePending(), true);
  assert.equal(guide.busy(), false, 'the platform can be left to restore access');
  assert.ok(env.storage.get('a2a-guide-experiment-pending-v1').includes(runId));
  assert.match(root.innerHTML, /原实验结果待核对 · 操作权限失效/);
  assert.doesNotMatch(root.innerHTML, /本轮尚未启动|data-experiment-action="run"/);
  root.click('run'); await drain(); assert.equal(calls.length, 1, 'unlocked navigation cannot create another run');
  root.click('normal'); assert.equal(events.at(-1).type, 'normal');
  await guide.refresh(); assert.equal(calls.length, 2);
  assert.ok(calls.every(call => call.body === undefined && call.path.endsWith(runId)));
  denied = false;
  const reloadCalls = [], reloaded = createExperimentGuide({ root: env.root(), mode: () => 'bbs-blind-bls', api: async (path, body) => {
    reloadCalls.push({ path, body }); return { runId, mode: 'bbs-bls', scenarioId: 'copied-vc', status: 'completed', result: result() };
  } });
  await reloaded.resumePending();
  assert.equal(reloadCalls.length, 1); assert.ok(reloadCalls[0].path.endsWith(runId)); assert.equal(reloadCalls[0].body, undefined);
  assert.equal(reloaded.busy(), false); assert.equal(reloaded.getResult().actual, 'W3C_DEVICE_PROOF_REQUIRED');
  assert.equal(env.storage.has('a2a-guide-experiment-pending-v1'), false);
});

test('a server error during start stays unresolved and refresh cannot create another experiment', async t => {
  const env = environment(t), root = env.root(), calls = [];
  const guide = createExperimentGuide({ root, mode: () => 'bbs-bls', api: async (path, body) => {
    calls.push({ path, body }); throw Object.assign(new Error('upstream unavailable'), { status: 503 });
  } });
  await guide.select('copied-vc'); root.click('run'); await drain();
  const runId = calls[0].body.runId;
  assert.equal(guide.busy(), true); assert.ok(env.storage.get('a2a-guide-experiment-pending-v1').includes(runId));
  root.click('run'); await drain(); await guide.refresh();
  assert.equal(calls.filter(call => call.body).length, 1);
  assert.ok(calls[1].path.endsWith(runId)); assert.equal(guide.busy(), true);
  assert.match(root.innerHTML, /启动响应未确认|查询未完成/);
  assert.doesNotMatch(root.innerHTML, /本轮尚未启动/);
});

test('loss of access after a completed run preserves its recorded outcome without calling it unstarted', async t => {
  const env = environment(t), root = env.root();
  let allowed = true, posts = 0;
  const guide = createExperimentGuide({ root, mode: () => 'bbs-bls', canStart: () => allowed, api: async (path, body) => {
    if (body) { posts++; return { ...body, status: 'completed', result: result() }; }
    throw Object.assign(new Error('access expired'), { status: 403 });
  } });
  await guide.select('copied-vc'); root.click('run'); await drain();
  allowed = false; await guide.refresh();
  assert.equal(guide.busy(), false); assert.equal(posts, 1);
  assert.equal(guide.getResult().actual, 'W3C_DEVICE_PROOF_REQUIRED');
  assert.match(root.innerHTML, /本次请求已被验证者 B 拒绝/);
  assert.match(root.innerHTML, /查询权限未通过/);
  assert.doesNotMatch(root.innerHTML, /实验尚未启动|本轮尚未启动/);
  root.click('run'); await drain(); assert.equal(posts, 1, 'missing access cannot start another run');
});

test('unknown start is saved before POST, blocks another run and recovers the same ID after reload', async t => {
  const env = environment(t), root = env.root(), calls = [];
  const api = async (path, body) => { calls.push({ path, body }); if (body) {
    assert.ok([...env.storage.values()].some(value => value.includes(body.runId)), 'persist before mutation');
    throw new Error('response lost');
  } throw new Error('connection still offline'); };
  const first = createExperimentGuide({ root, api, mode: () => 'bbs-bls' });
  await first.select('copied-vc'); root.click('run'); await drain();
  assert.equal(first.busy(), true);
  root.click('run'); await drain();
  assert.equal(calls.filter(call => call.body).length, 1, 'uncertain result never starts another run');
  await first.refresh(); assert.equal(first.busy(), true, 'read error preserves the unresolved lock');
  const runId = calls[0].body.runId, events = [], secondCalls = [];
  const second = createExperimentGuide({ root: env.root(), mode: () => 'bbs-blind-bls', onChange: event => events.push(event),
    api: async (path, body) => { secondCalls.push({ path, body }); return { runId, mode: 'bbs-bls', scenarioId: 'copied-vc', status: 'completed', result: result() }; } });
  await second.select('revoked');
  assert.equal(secondCalls.length, 1); assert.equal(secondCalls[0].body, undefined);
  assert.ok(secondCalls[0].path.endsWith(runId));
  assert.deepEqual(events[0], { type: 'resume', mode: 'bbs-bls', scenarioId: 'copied-vc' });
  assert.equal(second.busy(), false); assert.equal(second.getResult().actual, 'W3C_DEVICE_PROOF_REQUIRED');
});

test('a confirmed missing run releases recovery without automatically posting a new run', async t => {
  const env = environment(t), root = env.root();
  env.storage.set('a2a-guide-experiment-pending-v1', JSON.stringify({ runId: '2b5dfc6b-b43a-4b8a-9a3c-3d8d7581d99f', mode: 'bbs-bls', scenarioId: 'revoked' }));
  let posts = 0;
  const guide = createExperimentGuide({ root, mode: () => 'bbs-bls', api: async (path, body) => { if (body) posts++;
    throw Object.assign(new Error('not found'), { data: { error: { code: 'EXPERIMENT_RUN_NOT_FOUND' } } }); } });
  await guide.select('revoked');
  assert.equal(guide.busy(), false); assert.equal(posts, 0); assert.equal(guide.getResult(), null);
  assert.match(root.innerHTML, /没有自动重跑/);
  assert.equal(env.storage.has('a2a-guide-experiment-pending-v1'), false);
});

test('switching scenario does not carry the previous scene result into the new scene', async t => {
  const env = environment(t), root = env.root(), runId = '6e0e706e-4a01-4c7a-8e90-457779e303a5';
  env.storage.set('a2a-guide-experiment-recent-v1', JSON.stringify([{ runId, mode: 'bbs-bls', scenarioId: 'copied-vc' }]));
  let calls = 0;
  const guide = createExperimentGuide({ root, mode: () => 'bbs-bls', api: async () => { calls++; return { runId, mode: 'bbs-bls', scenarioId: 'copied-vc', status: 'completed', result: result() }; } });
  await guide.select('copied-vc'); assert.equal(guide.getResult().scenarioId, 'copied-vc');
  await guide.select('revoked'); assert.equal(guide.getResult(), null); assert.equal(calls, 1);
  assert.doesNotMatch(root.innerHTML, /W3C_DEVICE_PROOF_REQUIRED/);
});

test('startup recovery is inert without a pending run and reveals an existing pending context before reading', async t => {
  const env = environment(t), idleRoot = env.root(), idleEvents = [];
  let idleCalls = 0;
  const idle = createExperimentGuide({ root: idleRoot, mode: () => 'bbs-bls', onChange: event => idleEvents.push(event), api: async () => { idleCalls++; } });
  assert.equal(await idle.resumePending(), false);
  assert.equal(idleRoot.innerHTML, ''); assert.equal(idleEvents.length, 0); assert.equal(idleCalls, 0);
  const runId = '47b0d163-b5a0-40c2-890d-4c2032716872', events = [], activeRoot = env.root();
  env.storage.set('a2a-guide-experiment-pending-v1', JSON.stringify({ runId, mode: 'bbs-bls', scenarioId: 'revoked' }));
  const active = createExperimentGuide({ root: activeRoot, mode: () => 'bbs-blind-bls', onChange: event => events.push(event), api: async () => {
    assert.deepEqual(events[0], { type: 'resume', mode: 'bbs-bls', scenarioId: 'revoked' });
    assert.match(activeRoot.innerHTML, /核对原运行/);
    throw new Error('offline');
  } });
  assert.equal(await active.resumePending(), true);
  assert.equal(active.busy(), true, 'the old run remains locked but its recovery controls are revealed');
});

test('refresh after parent mode change clears previous mode evidence and queries only matching history', async t => {
  const env = environment(t), root = env.root(), runId = 'b149ed50-eaa7-430c-a173-f1f17582e34b';
  env.storage.set('a2a-guide-experiment-recent-v1', JSON.stringify([{ runId, mode: 'bbs-bls', scenarioId: 'copied-vc' }]));
  let selectedMode = 'bbs-bls', calls = 0;
  const guide = createExperimentGuide({ root, mode: () => selectedMode, api: async () => { calls++; return { runId, mode: 'bbs-bls', scenarioId: 'copied-vc', status: 'completed', result: result() }; } });
  await guide.select('copied-vc'); assert.equal(guide.getResult().mode, 'bbs-bls');
  selectedMode = 'bbs-blind-bls'; await guide.refresh();
  assert.equal(guide.getResult(), null); assert.equal(calls, 1);
  assert.match(root.innerHTML, /盲化 BLS/); assert.doesNotMatch(root.innerHTML, /W3C_DEVICE_PROOF_REQUIRED/);
});

function requestRecord(scenarioId = 'copied-vc') {
  const record = result(scenarioId);
  record.error = { code: record.actual, message: scenarioId === 'copied-vc' ? '本次请求未携带原设备贡献' : '签发方记录本凭证已撤销' };
  record.rejectionStage = scenarioId === 'copied-vc' ? 'vc_device_binding' : 'credential_status';
  record.request = { method: 'POST', endpoint: '/dbac/payment/a2a', challengeId: `challenge-${scenarioId}`, role: '验证者智能体 B 实际收到的公开材料', proof: {
    verifiableCredential: { issuer: 'did:key:issuer-one', proof: { type: 'DataIntegrityProof', cryptosuite: 'bbs-2023' }, credentialSubject: {
      role: 'authorized-agent', scope: 'payments:pay', epoch: '2026-10-11', mode: 'bbs-bls', bindingId: 'binding-one', holderDid: 'did:key:holder-one',
      secretKey: 'SHOULD_NEVER_RENDER',
    } },
  } };
  if (scenarioId === 'revoked') {
    record.request.proof.holderProof = 'public-signature'; record.request.proof.deviceSignature = 'public-device-contribution';
    record.revocation = { credential: 'experiment-only', freshChallenge: true, completeHolderProof: true, completeDeviceProof: true };
  }
  record.sideEffects = { paymentExecutionDelta: 0, ownerApprovalRequested: false, walletSignatureRequested: false,
    before: { executionCount: 0, accounts: [] }, after: { executionCount: 0, accounts: [] }, balancesUnchanged: true };
  return record;
}
async function showRecord(t, record) {
  const env = environment(t), root = env.root(), evidenceRoot = env.root(), runId = 'af3909e7-4c3c-42a6-a856-d30a80233e99';
  env.storage.set('a2a-guide-experiment-recent-v1', JSON.stringify([{ runId, mode: 'bbs-bls', scenarioId: record.scenarioId }]));
  let calls = 0;
  const guide = createExperimentGuide({ root, evidenceRoot, mode: () => 'bbs-bls', api: async () => { calls++; return { runId, mode: 'bbs-bls', scenarioId: record.scenarioId, status: 'completed', result: record }; } });
  await guide.select(record.scenarioId);
  return { root, evidenceRoot, guide, calls: () => calls };
}
function visibleText(html) {
  // Remove all closed details, including nested ones, to test default visibility.
  let depth = 0;
  return html.split(/(<\/?details\b[^>]*>)/).filter(chunk => {
    if (/^<details\b/.test(chunk)) { depth++; return false; }
    if (/^<\/details/.test(chunk)) { depth--; return false; }
    return depth === 0;
  }).join('');
}

test('idle experiments use one main panel and never pre-render a rejected result or later check details', async t => {
  const env = environment(t), root = env.root(), evidenceRoot = env.root();
  const guide = createExperimentGuide({ root, evidenceRoot, mode: () => 'bbs-bls', api: async () => { throw new Error('no calls expected'); } });
  await guide.select('revoked');
  assert.equal((root.innerHTML.match(/class="guide-step-panel"/g) || []).length, 1);
  assert.doesNotMatch(root.innerHTML, /guide-lower-grid|guide-current|guide-validation|<h3>当前步骤|<h3>验证检查项|data-check-id/);
  assert.doesNotMatch(visibleText(root.innerHTML), /本次请求已被验证者 B 拒绝|凭证状态.*未通过|W3C_CREDENTIAL_REVOKED/);
  assert.match(root.innerHTML, /data-experiment-action="run"/);
  assert.match(visibleText(root.innerHTML), /尚未运行本场景/);
  assert.match(evidenceRoot.innerHTML, /待执行/);
  assert.ok(root.innerHTML.indexOf('guide-panel-actions') > root.innerHTML.indexOf('guide-step-result'));
  assert.doesNotMatch(root.innerHTML, /guide-step-summary|guide-device-contrast/);
  assert.match(evidenceRoot.innerHTML, /guide-step-summary|guide-device-contrast/);
  assert.equal((root.innerHTML.match(/data-experiment-action="run"/g) || []).length, 1);
});

test('control purpose is visible before running, and completed control and abnormal traces remain separate', async t => {
  const env = environment(t), idleRoot = env.root(), idleEvidence = env.root(); let calls = 0;
  const idle = createExperimentGuide({ root: idleRoot, evidenceRoot: idleEvidence, mode: () => 'bbs-bls', api: async () => { calls++; } });
  await idle.select('revoked');
  const explanation = visibleText(idleRoot.innerHTML) + visibleText(idleEvidence.innerHTML);
  assert.match(explanation, /先由持有者 A 与原模拟 eSIM 发起正常控制请求/);
  assert.match(explanation, /确认当前服务和正常材料可完成资格认证/);
  assert.match(explanation, /再提交异常请求/);
  assert.match(explanation, /撤销实验专用凭证后，用新挑战、原持有者和模拟 eSIM 重新提交完整证明/);
  assert.match(explanation, /运行后读取本轮验证者 B 的实际检查状态/);
  assert.match(explanation, /控制组与撤销后新请求使用各自的新挑战/);
  assert.match(explanation, /正常控制组通过不能代替异常请求的验证/);
  assert.match(explanation, /不请求 Owner 批准、钱包签名或结算/);
  assert.equal(calls, 0); assert.doesNotMatch(explanation, /前置请求已通过|本次请求已被验证者 B 拒绝/);
  const record = requestRecord();
  record.control = { accepted: true, challengeId: 'control-challenge-independent', verificationTrace: {
    source: 'agent-b', profile: 'dbac-payment', outcome: 'pass', steps: ids.map(id => ({ id, title: id, status: 'pass' })),
  } };
  const { root, evidenceRoot } = await showRecord(t, record);
  assert.match(visibleText(root.innerHTML), /同一轮合法控制组与场景请求对照/);
  assert.match(visibleText(evidenceRoot.innerHTML), /正常控制请求已确认当前服务和正常材料可完成资格认证/);
  assert.match(visibleText(evidenceRoot.innerHTML), /该控制请求的独立记录，不能代替异常请求的检查/);
  const controlStart = evidenceRoot.innerHTML.indexOf('data-operation-id="control-reference"');
  const requestStart = evidenceRoot.innerHTML.indexOf('data-operation-id="request-materials"');
  assert.ok(controlStart >= 0 && requestStart > controlStart);
  const controlMarkup = evidenceRoot.innerHTML.slice(controlStart, requestStart), requestMarkup = evidenceRoot.innerHTML.slice(requestStart);
  assert.match(controlMarkup, /control-challenge-independent/);
  assert.match(controlMarkup, /data-check-id="vc_device_binding"/);
  assert.doesNotMatch(controlMarkup, /W3C_DEVICE_PROOF_REQUIRED/);
  assert.match(requestMarkup, /challenge-copied-vc|W3C_DEVICE_PROOF_REQUIRED/);
  assert.match(requestMarkup, /data-check-id="vc_device_binding"/);
});

test('actual copied-VC failure stays visible while allowed public materials appear once in the evidence drawer', async t => {
  const { root, evidenceRoot } = await showRecord(t, requestRecord());
  const visible = visibleText(root.innerHTML);
  assert.match(visible, /本次请求未携带原设备贡献/);
  assert.match(visible, /vc_device_binding/);
  assert.match(visibleText(evidenceRoot.innerHTML), /验证者 B 已收到/);
  assert.match(evidenceRoot.innerHTML, /data-check-id="vc_device_binding"/);
  assert.match(root.innerHTML, /未执行/);
  for (const publicIdentifier of ['did:key:holder-one', 'did:key:issuer-one', 'binding-one']) {
    assert.ok(evidenceRoot.innerHTML.includes(publicIdentifier));
    assert.ok(!visible.includes(publicIdentifier), 'long public identifiers stay in the single drawer');
  }
  assert.doesNotMatch(root.innerHTML + evidenceRoot.innerHTML, /SHOULD_NEVER_RENDER|右侧验证|本次材料逐项对照|guide-compare-table/);
  assert.match(root.innerHTML, /开始新一轮实验/);
});

test('revocation result uses the actual status check and does not treat generated proofs as accepted', async t => {
  const { root, evidenceRoot } = await showRecord(t, requestRecord('revoked'));
  const visible = visibleText(root.innerHTML);
  assert.match(visible, /签发方记录本凭证已撤销/);
  assert.match(visible, /credential_status/);
  assert.match(evidenceRoot.innerHTML, /data-check-id="credential_status"/);
  assert.doesNotMatch(visible, /本次请求通过了认证|模拟支付完成/);
});

test('prepared packet and misleading request role do not assert B receipt after transport failure', async t => {
  const record = requestRecord();
  Object.assign(record, { completion: 'incomplete', requestRejected: false, verificationTrace: null, rejectionStage: null, actual: 'EXPERIMENT_TRANSPORT',
    error: { message: '独立攻击工作区未收到有效 HTTP 响应' } });
  const { root, evidenceRoot } = await showRecord(t, record);
  const visible = visibleText(root.innerHTML);
  assert.match(visible, /材料已生成/);
  assert.match(visible, /独立攻击工作区未收到有效 HTTP 响应/);
  assert.doesNotMatch(root.innerHTML + evidenceRoot.innerHTML, /验证者 B 已收到/);
  assert.doesNotMatch(visible, /本次请求已被验证者 B 拒绝|全部通过/);
});

test('starting another run immediately clears old evidence and pending requests cannot switch their scene', async t => {
  const env = environment(t), root = env.root(), evidenceRoot = env.root();
  let resolveRun, count = 0, request;
  const guide = createExperimentGuide({ root, evidenceRoot, mode: () => 'bbs-bls', api: async (path, body) => {
    count++; request = body;
    if (count === 1) return { ...body, status: 'completed', result: requestRecord() };
    return new Promise(resolve => { resolveRun = resolve; });
  } });
  await guide.select('copied-vc'); root.click('run'); await drain();
  assert.match(root.innerHTML, /W3C_DEVICE_PROOF_REQUIRED/);
  root.click('run'); await drain();
  assert.doesNotMatch(root.innerHTML + evidenceRoot.innerHTML, /W3C_DEVICE_PROOF_REQUIRED|data-check-id/);
  assert.match(visibleText(root.innerHTML), /实验执行中/);
  await guide.select('revoked');
  assert.match(root.innerHTML, /data-experiment-scenario="copied-vc"/);
  resolveRun({ ...request, status: 'completed', result: requestRecord() }); await drain();
  assert.equal(guide.getResult().scenarioId, 'copied-vc');
  assert.equal(count, 2);
});

test('contradictory overall acceptance is reported explicitly with the failed item retained', async t => {
  const record = requestRecord();
  Object.assign(record, { actual: 'ACCEPTED', requestRejected: false, authenticationIssued: true });
  record.verificationTrace.outcome = 'pass';
  const { root } = await showRecord(t, record);
  assert.match(visibleText(root.innerHTML), /结果异常：整体结论与逐项记录不一致/);
  assert.match(visibleText(root.innerHTML), /vc_device_binding/);
  assert.doesNotMatch(visibleText(root.innerHTML), /本次请求通过了认证/);
});


test('device contrast uses only current trace and has no rejection prediction before execution', () => {
  for (const scenarioId of ['copied-vc', 'revoked']) {
    const idle = experimentDeviceContrast(null, { scenarioId });
    assert.ok(idle.rows.every(row => row.state === 'pending' && row.status === '待运行'));
    assert.doesNotMatch(idle.conclusion, /本轮.*通过.*不通过|设备参与不能绕过撤销/);
    const pending = experimentDeviceContrast(requestRecord(scenarioId), { scenarioId, pending: true });
    assert.ok(pending.rows.every(row => row.state === 'pending'));
    assert.match(pending.conclusion, /等待本轮结果/);
    const otherScenario = experimentDeviceContrast(requestRecord(scenarioId), { scenarioId: scenarioId === 'copied-vc' ? 'revoked' : 'copied-vc' });
    assert.ok(otherScenario.rows.every(row => row.state === 'pending'));
  }
});

test('copied contrast distinguishes actual BBS success from binding failure and states its key-theft boundary', () => {
  const value = experimentDeviceContrast(requestRecord());
  assert.deepEqual(value.rows.map(row => [row.id, row.state]), [['w3c_bbs', 'pass'], ['vc_device_binding', 'fail']]);
  assert.match(value.conclusion, /标准 BBS 派生证明通过，VC 与模拟 eSIM 绑定检查不通过/);
  assert.match(value.boundary, /既无持有者 A 私钥，也无原设备调用权限/);
  assert.match(value.boundary, /不能证明模拟 eSIM 单独抵御持有者 A 私钥失窃/);
  const contradictory = requestRecord(); contradictory.verificationTrace.outcome = 'pass';
  assert.doesNotMatch(experimentDeviceContrast(contradictory).conclusion, /公开 VC 副本未满足/);
  assert.match(experimentDeviceContrast(contradictory).conclusion, /存在矛盾/);
});

test('revocation contrast distinguishes actual device verification from the independent status rejection', () => {
  const record = requestRecord('revoked'), value = experimentDeviceContrast(record);
  assert.deepEqual(value.rows.map(row => [row.id, row.state]), [['device_pairing', 'pass'], ['credential_status', 'fail']]);
  assert.match(value.conclusion, /原设备贡献、VC 设备绑定与持有者 A 签名均通过/);
  assert.match(value.conclusion, /设备参与不能绕过撤销/);
  record.verificationTrace.steps.find(step => step.id === 'holder_signature').status = 'skipped';
  assert.match(experimentDeviceContrast(record).conclusion, /未全部确认通过/);
  assert.doesNotMatch(experimentDeviceContrast(record).conclusion, /均通过，仍在/);
});

test('missing, duplicate, wrong-phase and incomplete records cannot complete the focused security comparison', () => {
  for (const mutate of [
    value => { value.verificationTrace = null; },
    value => { value.verificationTrace.steps = []; },
    value => { value.verificationTrace.source = 'agent-a'; },
    value => { value.request = null; },
    value => { value.verificationTrace.steps = value.verificationTrace.steps.filter(step => step.id !== 'w3c_bbs'); },
    value => { value.verificationTrace.steps.push({ id: 'vc_device_binding', status: 'pass' }); },
    value => { value.verificationTrace.steps.push({ id: 'scope', status: 'pass', evidence: [{ label: 'method / scope / phase', observed: ['message/send', 'payments:pay', 'settle'] }] }); },
  ]) {
    const value = requestRecord(); mutate(value);
    const contrast = experimentDeviceContrast(value);
    assert.ok(contrast.rows.some(row => row.state === 'unknown'));
    assert.doesNotMatch(contrast.conclusion, /公开 VC 副本未满足本次联合验证/);
  }
  const incomplete = requestRecord(); incomplete.completion = 'incomplete';
  assert.match(experimentDeviceContrast(incomplete).conclusion, /实验未完整结束/);
  assert.doesNotMatch(experimentDeviceContrast(incomplete).conclusion, /公开 VC 副本未满足/);
  const network = requestRecord('revoked');
  network.completion = 'incomplete'; network.actual = 'W3C_CREDENTIAL_STATUS_UNAVAILABLE'; network.error.message = '状态服务不可用';
  assert.match(experimentDeviceContrast(network).conclusion, /不能作为冒用或撤销拦截成功/);
  assert.doesNotMatch(experimentDeviceContrast(network).conclusion, /设备参与不能绕过撤销/);
});

test('focused device comparison is retained once in the evidence drawer while the main panel exposes its actual statuses', async t => {
  const { root, evidenceRoot } = await showRecord(t, requestRecord());
  const visible = visibleText(evidenceRoot.innerHTML);
  assert.match(visible, /guide-device-contrast/);
  assert.match(visible, /标准 BBS 派生证明通过，VC 与模拟 eSIM 绑定检查不通过/);
  assert.match(visible, /攻击者既无持有者 A 私钥，也无原设备调用权限/);
  const contrast = evidenceRoot.innerHTML.slice(evidenceRoot.innerHTML.indexOf('<section class="guide-device-contrast"')).split('</section>')[0];
  assert.doesNotMatch(contrast, /did:key:holder-one|binding-one/);
  assert.doesNotMatch(root.innerHTML + evidenceRoot.innerHTML, /SHOULD_NEVER_RENDER/);
  assert.equal(((root.innerHTML + evidenceRoot.innerHTML).match(/class="guide-device-contrast"/g) || []).length, 1);
  assert.match(visibleText(root.innerHTML), /data-scene-evidence="check:w3c_bbs" data-state="pass"/);
  assert.match(visibleText(root.innerHTML), /data-scene-evidence="check:vc_device_binding" data-state="fail"/);
});

test('holder-signature rejection stays visible and later device checks remain unexecuted', async t => {
  const record = requestRecord();
  record.actual = 'HOLDER_SIGNATURE_INVALID'; record.rejectionStage = 'holder_signature';
  record.error = { code: record.actual, message: '本次持有者签名无效' };
  record.verificationTrace.steps = ids.map(id => ({ id, status: id === 'holder_signature' ? 'fail' : ['w3c_bbs', 'vc_device_binding'].includes(id) ? 'pass' : 'skipped',
    ...(id === 'holder_signature' ? { code: record.actual, detail: record.error.message } : {}) }));
  const { root, evidenceRoot } = await showRecord(t, record);
  const visible = visibleText(root.innerHTML);
  assert.match(visible, /拒绝阶段：holder_signature/);
  assert.match(visible, /HOLDER_SIGNATURE_INVALID/);
  assert.match(visible, /本次持有者签名无效/);
  assert.match(visible, /data-scene-evidence="check:device_pairing" data-state="skipped"[^>]*>[\s\S]*?未执行/);
  assert.doesNotMatch(visible, /设备验证失败|设备贡献[^<]*请求被拒绝/);
  assert.match(evidenceRoot.innerHTML, /data-check-id="holder_signature"/);
});

test('failed control checks are visible without opening the drawer and cannot award expected-protection success', async t => {
  const record = requestRecord();
  record.control = { accepted: false, challengeId: 'failed-control-challenge', verificationTrace: {
    source: 'agent-b', profile: 'dbac-payment', outcome: 'fail', steps: [
      { id: 'challenge', status: 'fail', code: 'CONTROL_CHALLENGE_EXPIRED', detail: '控制请求的新挑战已过期' },
      { id: 'w3c_bbs', status: 'skipped' },
    ],
  } };
  const { root } = await showRecord(t, record), visible = visibleText(root.innerHTML);
  assert.match(visible, /控制组未成立/);
  assert.match(visible, /CONTROL_CHALLENGE_EXPIRED/);
  assert.match(visible, /控制请求的新挑战已过期/);
  assert.match(visible, /本轮不能宣布防护验证成功/);
  assert.doesNotMatch(visible, />实验符合预期</);
});

test('all returned failures including uncommon checks are directly visible and retain their own error codes', async t => {
  const record = requestRecord();
  record.verificationTrace.steps.push({ id: 'custom_status_dependency', title: '本轮状态来源', status: 'fail', code: 'STATUS_DEPENDENCY_OFFLINE', detail: '可信状态来源暂时不可用' });
  const { root } = await showRecord(t, record), visible = visibleText(root.innerHTML);
  assert.match(visible, /W3C_DEVICE_PROOF_REQUIRED/);
  assert.match(visible, /STATUS_DEPENDENCY_OFFLINE/);
  assert.match(visible, /可信状态来源暂时不可用/);
  assert.match(visible, /data-scene-evidence="check:custom_status_dependency" data-state="fail"/);
});

test('opening evidence and repeatedly viewing the same run never posts or allocates a replacement run', async t => {
  environment(t);
  const root = markupView(), evidenceRoot = markupView(), requests = [], events = []; let returned;
  const guide = createExperimentGuide({ root, evidenceRoot, mode: () => 'bbs-bls', onChange: event => events.push(event), api: async (path, body) => {
    requests.push({ path, body });
    if (body) returned = { ...body, status: 'completed', result: requestRecord() };
    return returned;
  } });
  await guide.select('copied-vc'); root.click('run'); await drain();
  const runId = requests[0].body.runId;
  for (let index = 0; index < 3; index++) root.click('evidence');
  evidenceRoot.details().find(detail => detail.dataset.detailKey === 'result-evidence').open = true;
  assert.equal(requests.length, 1, 'opening evidence is local and read-only');
  assert.equal(events.filter(event => event.type === 'evidence').length, 3);
  for (let index = 0; index < 3; index++) { await guide.refresh(); await guide.select('copied-vc'); }
  assert.equal(requests.filter(request => request.body).length, 1, 'same-run view recovery never repeats the experiment POST');
  assert.ok(requests.slice(1).every(request => request.path.endsWith(runId) && request.body === undefined));
  assert.ok(events.filter(event => event.type === 'view' && event.view.context).every(event => event.view.context.runId === runId));
  assert.equal(evidenceRoot.details().find(detail => detail.dataset.detailKey === 'result-evidence').open, true);
  assert.doesNotMatch(root.innerHTML, /did:key:holder-one|binding-one/);
  assert.match(evidenceRoot.innerHTML, /本轮记录回看 · 只读记录/);
});
