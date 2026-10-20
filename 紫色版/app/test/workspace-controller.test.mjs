import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

const controller = await readFile(new URL('../public/workspace.js', import.meta.url), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));
const scenes = [
  { id: 'valid', title: '合法控制实验', kind: 'control', premise: '合法请求', expected: 'ACCEPTED' },
  { id: 'copied-vc', title: '复制凭证实验', kind: 'black-box', premise: '复制凭证但缺少设备', expected: 'DEVICE_REJECTED' },
];
const completed = {
  scenarioId: 'copied-vc', runId: 'run-second-scene', completion: 'completed',
  expectationMet: true, requestRejected: true, authenticationIssued: false,
  expected: 'DEVICE_REJECTED', actual: 'DEVICE_REJECTED', rejectionStage: 'device_access',
  sideEffects: { paymentExecutionDelta: 0 }, control: { accepted: true },
  verificationTrace: { steps: [{ id: 'device_access', status: 'fail' }] },
};

// Execute the shipped controller, including its event handlers. The DOM boundary
// models native select behavior: replacing options selects the first option.
function page(moduleName = 'attacks') {
  const nodes = new Map(), requests = [], listeners = new Map(), documentListeners = new Map(), traceCalls = [], copied = [];
  const focusState = { activeElement: null };
  let disclosures = [];
  const storage = new Map([['a2a-did-vc-ui-key', 'a'.repeat(43)], ['a2a-manual-mode', 'bbs-bls']]);
  const node = id => {
    if (!nodes.has(id)) {
      let html = '', value = id === 'workspace-mode' ? 'bbs-bls' : '';
      let options = id === 'workspace-mode' ? ['bbs-bls', 'bbs-blind-bls'] : [];
      nodes.set(id, {
        id, textContent: '', dataset: {}, disabled: false, hidden: true,
        setAttribute(name, next) { this[name] = next; },
        focus() { this.focused = true; },
        scrollIntoView() { this.scrolled = true; },
        querySelectorAll(selector) { return id === 'manage-content' && selector === 'details' ? disclosures : []; },
        get value() { return value; },
        set value(next) { value = options.includes(next) ? next : ''; },
        get innerHTML() { return html; },
        set innerHTML(next) {
          html = next;
          if (id === 'manage-content') {
            if (disclosures.some(detail => detail.summary === focusState.activeElement)) focusState.activeElement = null;
            disclosures = [...next.matchAll(/<details\b[^>]*data-disclosure-key="([^"]*)"[^>]*>/g)].map(match => {
              const summary = { focus() { focusState.activeElement = summary; } };
              return { dataset: { disclosureKey: match[1] }, open: /\sopen(?:\s|>)/.test(match[0]), summary,
                parentElement: { closest() { return null; } }, querySelector: () => summary, querySelectorAll: () => [] };
            });
          }
          if (id === 'attack-scenario') {
            options = [...next.matchAll(/<option value="([^"]*)">/g)].map(match => match[1]);
            value = options[0] || '';
          }
        },
      });
    }
    return nodes.get(id);
  };
  for (const id of ['workspace-mode', 'workspace-refresh', 'attack-run', 'attack-scenario']) node(id);
  const window = {
    DemoEmbed: { setBusy() {} },
    DemoVerification: { create: element => ({ render(value) { traceCalls.push(value); element.innerHTML = value ? JSON.stringify(value) : ''; } }) },
    addEventListener(name, callback) { listeners.set(name, callback); },
  };
  const parent = { postMessage() {} };
  runInNewContext(controller, {
    URLSearchParams, AbortSignal, Intl, window,
    location: { search: `?module=${moduleName}`, hash: '', pathname: '/workspace.html', origin: 'http://127.0.0.1:4340' },
    history: { replaceState() {} },
    sessionStorage: { getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value) },
    document: { get activeElement() { return focusState.activeElement; }, getElementById: node, querySelector: () => node('page'), querySelectorAll: () => [...nodes.values()], addEventListener: (name, handler) => documentListeners.set(name, handler) },
    parent, navigator: { clipboard: { writeText: async value => { copied.push(value); } } },
    fetch(path, init) {
      return new Promise((resolve, reject) => requests.push({ path, init, reject,
        resolve(data, status = 200) { resolve({ ok: status < 400, json: async () => data }); },
      }));
    },
  }, { filename: 'public/workspace.js' });
  return { node, requests, listeners, documentListeners, storage, traceCalls, copied, parent, focusState,
    disclosure(key) { return disclosures.find(detail => detail.dataset.disclosureKey === key); },
    async respond(data, status = 200) { requests.at(-1).resolve(data, status); await flush(); },
    activate() { listeners.get('demo:activate')(); },
  };
}

async function runSecondScene(p) {
  await p.respond({ scenarios: scenes });
  p.node('attack-scenario').value = 'copied-vc';
  p.node('attack-scenario').onchange();
  p.node('attack-run').onclick();
  assert.equal(p.requests.at(-1).init.method, 'POST');
  assert.deepEqual(JSON.parse(p.requests.at(-1).init.body), { mode: 'bbs-bls', scenarioId: 'copied-vc' });
  await p.respond(completed);
  assert.match(p.node('attack-result').innerHTML, /run-second-scene/);
  assert.equal(p.node('attack-raw').textContent, JSON.stringify(completed, null, 2));
}

function assertCleared(p) {
  assert.doesNotMatch(p.node('attack-result').innerHTML, /run-second-scene/);
  assert.equal(p.traceCalls.at(-1), null);
  assert.equal(p.node('attack-trace').innerHTML, '');
  assert.equal(p.node('attack-raw').textContent, '尚无本次结果');
}

for (const trigger of ['refresh', 'activate', 'invalidate']) test(`${trigger} preserves a completed non-first experiment and only queries state`, async () => {
  const p = page();
  await runSecondScene(p);
  const result = p.node('attack-result').innerHTML, raw = p.node('attack-raw').textContent, trace = p.node('attack-trace').innerHTML;
  if (trigger === 'refresh') p.node('workspace-refresh').onclick();
  else if (trigger === 'activate') p.activate();
  else p.listeners.get('message')({ origin: 'http://127.0.0.1:4340', source: p.parent, data: { type: 'demo:invalidate' } });
  const latest = p.requests.at(-1);
  assert.equal(latest.path, '/api/dbac/payment/experiments?mode=bbs-bls');
  assert.equal(latest.init.method, 'GET');
  assert.equal(latest.init.body, undefined);
  await p.respond({ scenarios: scenes });
  assert.equal(p.node('attack-scenario').value, 'copied-vc');
  assert.match(p.node('attack-premise').innerHTML, /复制凭证实验/);
  assert.equal(p.node('attack-result').innerHTML, result);
  assert.equal(p.node('attack-raw').textContent, raw);
  assert.equal(p.node('attack-trace').innerHTML, trace);
  assert.equal(p.requests.filter(request => request.init.method === 'POST').length, 1);
});

test('a removed scene clears its evidence and explicitly explains the new selection', async () => {
  const p = page();
  await runSecondScene(p);
  p.node('workspace-refresh').onclick();
  await p.respond({ scenarios: [scenes[0]] });
  assert.equal(p.node('attack-scenario').value, 'valid');
  assert.match(p.node('attack-premise').innerHTML, /合法控制实验/);
  assertCleared(p);
  assert.match(p.node('attack-result').innerHTML, /原场景已不在当前可运行列表/);
  assert.match(p.node('workspace-feedback').textContent, /已切换场景并清除旧实验记录/);
  assert.equal(p.node('attack-run').disabled, false);
});

test('an empty refreshed scene list clears evidence and disables execution', async () => {
  const p = page();
  await runSecondScene(p);
  p.node('workspace-refresh').onclick();
  await p.respond({ scenarios: [] });
  assert.equal(p.node('attack-scenario').value, '');
  assert.match(p.node('attack-premise').innerHTML, /后端尚未提供可运行场景/);
  assertCleared(p);
  assert.equal(p.node('attack-run').disabled, true);
});

for (const trigger of ['mode-selector', 'activate']) test(`${trigger} switching modes clears old evidence before the new state read`, async () => {
  const p = page();
  await runSecondScene(p);
  if (trigger === 'mode-selector') {
    p.node('workspace-mode').value = 'bbs-blind-bls';
    p.node('workspace-mode').onchange();
  } else {
    p.storage.set('a2a-manual-mode', 'bbs-blind-bls');
    p.activate();
  }
  assert.equal(p.node('workspace-mode').value, 'bbs-blind-bls');
  assert.equal(p.node('attack-scenario').value, '');
  assertCleared(p);
  assert.equal(p.requests.at(-1).path, '/api/dbac/payment/experiments?mode=bbs-blind-bls');
  assert.equal(p.requests.at(-1).init.method, 'GET');
  await p.respond({ scenarios: scenes });
  assert.equal(p.node('attack-scenario').value, 'valid');
  assertCleared(p);
  assert.equal(p.requests.filter(request => request.init.method === 'POST').length, 1);
});

for (const failure of ['network', 'server']) test(`a ${failure} refresh failure clears the obsolete scene and its evidence together`, async () => {
  const p = page();
  await runSecondScene(p);
  p.node('workspace-refresh').onclick();
  if (failure === 'network') { p.requests.at(-1).reject(new Error('offline')); await flush(); }
  else await p.respond({ ok: false, error: { code: 'DEMO_UNAUTHORIZED', message: '会话权限无效' } }, 403);
  assert.equal(p.node('attack-scenario').value, '');
  assert.match(p.node('attack-premise').innerHTML, /后端尚未提供可运行场景/);
  assertCleared(p);
  assert.match(p.node('attack-result').innerHTML, /旧场景与实验记录已清除/);
  assert.equal(p.node('attack-run').disabled, true);
  assert.equal(p.node('workspace-feedback').dataset.kind, 'error');
  p.node('workspace-refresh').onclick();
  await p.respond({ scenarios: scenes });
  assert.equal(p.node('attack-scenario').value, 'valid');
  assertCleared(p);
  assert.equal(p.node('attack-run').disabled, false);
});

for (const [completion, expectationMet, expectedLabel] of [
  ['completed', true, '实验结果符合预期'],
  ['completed', false, '实验结果不符合预期'],
  ['incomplete', true, '实验尚未完成'],
]) test(`request rejection remains separate from ${expectedLabel}`, async () => {
  const p = page();
  await p.respond({ scenarios: scenes });
  p.node('attack-run').onclick();
  await p.respond({ ...completed, completion, expectationMet });
  const html = p.node('attack-result').innerHTML;
  assert.match(html, /请求结果/);
  assert.match(html, /本次请求已被拒绝/);
  assert.match(html, new RegExp(expectedLabel));
  if (expectedLabel !== '实验结果符合预期') assert.doesNotMatch(html, /实验结果符合预期/);
  assert.match(html, /设备调用权限/);
  assert.match(html, /data-open-evidence/);
  assert.equal(p.requests.filter(request => request.init.method === 'POST').length, 1);
});

test('opening verification evidence restores its focus without running another request', async () => {
  const p = page();
  await runSecondScene(p);
  const count = p.requests.length, result = p.node('attack-result').innerHTML;
  p.documentListeners.get('click')({ target: { closest: selector => selector === '[data-open-evidence]' ? {} : null } });
  assert.equal(p.node('attack-evidence-details').open, true);
  assert.equal(p.node('attack-evidence-summary').focused, true);
  assert.equal(p.node('attack-evidence-details').scrolled, true);
  assert.equal(p.requests.length, count);
  assert.equal(p.node('attack-result').innerHTML, result);
});

test('management leads with selected objects, preserves other actions and only reads state', async () => {
  const p = page('manage');
  const publicDid = `did:example:${'complete-public-identity-'.repeat(5)}`;
  await p.respond({
    currentCredentialId: 'selected-credential', currentDeviceId: 'selected-device', statusService: { available: false },
    credentials: [
      { id: 'older-credential', mode: 'bbs-bls', status: 'revoked', deviceId: 'other-device' },
      { id: 'selected-credential', mode: 'bbs-bls', status: 'expired', deviceId: 'selected-device', holderDid: publicDid },
    ],
    devices: [
      { id: 'other-device', label: '其他模拟设备', locked: true, mode: 'bbs-bls' },
      { id: 'selected-device', label: '当前模拟设备', locked: false, mode: 'bbs-bls' },
    ],
  });
  const html = p.node('manage-content').innerHTML;
  assert.ok(html.indexOf('data-id="selected-credential"') < html.indexOf('data-id="older-credential"'));
  assert.ok(html.indexOf('data-id="selected-device"') < html.indexOf('data-id="other-device"'));
  assert.match(html, /其他与历史凭证/);
  assert.match(html, /其他设备/);
  assert.match(html, /凭证绑定设备/);
  assert.match(html, /凭证状态服务：不可用/);
  assert.match(html, /已过期/);
  for (const action of ['select-credential', 'revoke', 'select-device', 'lock', 'unlock', 'create-device', 'issue']) {
    assert.match(html, new RegExp(`data-manage-action="${action}"`));
  }
  assert.ok(html.includes(`data-copy-value="${publicDid}"`));
  p.documentListeners.get('click')({ target: { closest: selector => selector === '[data-copy-value]' ? { dataset: { copyValue: publicDid } } : null } });
  await flush();
  assert.deepEqual(p.copied, [publicDid]);
  assert.equal(p.requests.length, 1);
  assert.equal(p.requests[0].init.method, 'GET');
});

test('an empty management inventory does not invent assets or issue them automatically', async () => {
  const p = page('manage');
  await p.respond({ credentials: [], devices: [] });
  const html = p.node('manage-content').innerHTML;
  assert.match(html, /尚未选择凭证/);
  assert.match(html, /尚未准备凭证/);
  assert.match(html, /尚未选择演示设备/);
  assert.match(html, /data-manage-action="issue"/);
  assert.match(html, /data-manage-action="create-device"/);
  assert.doesNotMatch(html, /data-manage-action="select-credential"/);
  assert.doesNotMatch(html, /data-manage-action="select-device"/);
  assert.equal(p.requests.length, 1);
  assert.equal(p.requests[0].init.method, 'GET');
});

test('management refresh keeps disclosure reading state and restores focus only for existing objects', async () => {
  const p = page('manage');
  assert.match(p.node('manage-content').innerHTML, /正在读取准备材料/);
  const state = { currentCredentialId: 'selected', credentials: [
    { id: 'selected', mode: 'bbs-bls', status: 'valid' },
    { id: 'older', mode: 'bbs-bls', status: 'revoked' },
  ], devices: [] };
  await p.respond(state);
  const details = p.disclosure('credential-history');
  details.open = true;
  details.summary.focus();
  p.node('workspace-refresh').onclick();
  await p.respond(state);
  const refreshed = p.disclosure('credential-history');
  assert.notEqual(refreshed, details);
  assert.equal(refreshed.open, true);
  assert.equal(p.focusState.activeElement, refreshed.summary);
  p.node('workspace-refresh').onclick();
  await p.respond({ ...state, credentials: [state.credentials[0]] });
  assert.equal(p.disclosure('credential-history'), undefined);
  assert.equal(p.focusState.activeElement, null);
  assert.equal(p.requests.length, 3);
  assert.ok(p.requests.every(request => request.init.method === 'GET'));
});
