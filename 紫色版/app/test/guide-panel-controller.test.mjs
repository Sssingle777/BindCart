import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { planPayment } from '../public/guide-model.js';

const guide = await readFile(new URL('../public/guide.js', import.meta.url), 'utf8');
function sourceBetween(start, end) {
  const first = guide.indexOf(start), last = guide.indexOf(end, first + start.length);
  assert.ok(first >= 0 && last > first, `actual controller function boundary: ${start}`);
  return guide.slice(first, last);
}
const controller = [
  sourceBetween('async function read(){', 'async function refresh(){'),
  sourceBetween('async function invoke(id){', 'async function run(){'),
  sourceBetween('function replaceDetails(', 'function render(){'),
].join('\n');

// Exercise the shipped functions directly. Only their HTTP and DOM boundaries
// are controlled; the stale-response guards and detail restoration are not copied.
function page() {
  const requests = [], effects = [], selector = { value: 'bbs-bls' };
  const environment = { textContent: 'current environment', dataset: { state: 'pending' } };
  const context = {
    state: { marker: 'original', manual: { attemptId: 'attempt-original' } },
    scenario: 'normal', generation: 0, uncertain: true, pause: false, actionId: 'verify',
    mode: () => selector.value,
    $: id => { assert.equal(id, 'guide-environment'); return environment; },
    api(path, body) {
      let resolve, reject;
      const promise = new Promise((done, failed) => { resolve = done; reject = failed; });
      requests.push({ path, body: body === undefined ? undefined : JSON.parse(JSON.stringify(body)), resolve, reject });
      return promise;
    },
    render() { effects.push('render'); },
    changed() { effects.push('changed'); },
  };
  runInNewContext(controller, context, { filename: 'public/guide.js#panel-controller' });
  return { context, requests, effects, selector, environment };
}

test('a current read commits its actual response once without issuing business requests', async () => {
  const p = page(), value = { available: true, mode: 'bbs-bls', marker: 'current response' };
  const promise = p.context.read();
  assert.equal(p.requests.length, 1);
  assert.equal(p.requests[0].path, '/api/dbac/payment/state?mode=bbs-bls');
  assert.equal(p.requests[0].body, undefined);
  p.requests[0].resolve(value);
  assert.equal(await promise, value);
  assert.equal(p.context.state, value);
  assert.equal(p.context.uncertain, false);
  assert.deepEqual(p.effects, ['render']);
  assert.equal(p.environment.dataset.state, 'pass');
});

test('an older read resolving last cannot overwrite the latest read or its uncertainty state', async () => {
  const p = page(), older = p.context.read(), newer = p.context.read();
  const latest = { available: true, marker: 'newer response' };
  p.requests[1].resolve(latest);
  await newer;
  p.context.uncertain = true;
  const banner = p.environment.textContent;
  p.requests[0].resolve({ available: false, marker: 'stale response' });
  assert.equal(await older, undefined);
  assert.equal(p.context.state, latest);
  assert.equal(p.context.uncertain, true);
  assert.equal(p.environment.textContent, banner);
  assert.deepEqual(p.effects, ['render']);
});

for (const dimension of ['scenario', 'mode', 'generation']) test(`read discards a response after the ${dimension} alone changes`, async () => {
  const p = page(), original = p.context.state, pending = p.context.read();
  if (dimension === 'scenario') p.context.scenario = 'revoked';
  if (dimension === 'mode') p.selector.value = 'bbs-blind-bls';
  if (dimension === 'generation') p.context.generation++;
  p.requests[0].resolve({ available: true, marker: 'stale successful read' });
  assert.equal(await pending, undefined);
  assert.equal(p.context.state, original);
  assert.equal(p.context.uncertain, true);
  assert.equal(p.environment.textContent, 'current environment');
  assert.deepEqual(p.effects, []);
});

test('manual invoke captures the current mode and attempt and commits its response only once', async () => {
  const p = page(), pending = p.context.invoke('verify');
  assert.deepEqual(p.requests.map(({ path, body }) => ({ path, body })), [{
    path: '/api/dbac/payment/manual', body: { mode: 'bbs-bls', action: 'verify', attemptId: 'attempt-original' },
  }]);
  const response = { available: true, manual: { attemptId: 'attempt-original', stage: 'VERIFIED' } };
  p.requests[0].resolve(response);
  await pending;
  assert.equal(p.context.state, response);
  assert.equal(p.context.uncertain, false);
  assert.equal(p.context.actionId, '');
  assert.deepEqual(p.effects, ['changed', 'render']);
  assert.equal(p.requests.length, 1);
});

test('new-order invoke uses its existing endpoint and accepts the newly returned order', async () => {
  const p = page(), pending = p.context.invoke('new');
  assert.equal(p.requests[0].path, '/api/dbac/payment/new');
  assert.deepEqual(p.requests[0].body, { mode: 'bbs-bls' });
  const response = { available: true, order: { orderId: 'new-order' }, manual: { active: false } };
  p.requests[0].resolve(response);
  await pending;
  assert.equal(p.context.state, response);
  assert.deepEqual(p.effects, ['changed', 'render']);
});

for (const dimension of ['scenario', 'mode', 'generation']) test(`invoke cannot overwrite a new context after the ${dimension} alone changes`, async () => {
  const p = page(), pending = p.context.invoke('verify');
  if (dimension === 'scenario') p.context.scenario = 'copied-vc';
  if (dimension === 'mode') p.selector.value = 'bbs-blind-bls';
  if (dimension === 'generation') p.context.generation++;
  const current = { marker: 'new current order', manual: { attemptId: 'new-attempt' } };
  p.context.state = current;
  p.context.actionId = 'device-sign';
  p.requests[0].resolve({ marker: 'stale response', manual: { lastError: { code: 'OLD_FAILURE', message: 'error from old request' } } });
  await pending;
  assert.equal(p.context.state, current);
  assert.equal(p.context.actionId, 'device-sign');
  assert.equal(p.context.uncertain, true);
  assert.equal(p.context.pause, true, 'a discarded response must stop the original guided action chain');
  assert.deepEqual(p.effects, []);
  assert.equal(p.requests.length, 1, 'no automatic retry or replacement business request');
});

test('a state read invalidates a still-pending mutation response without erasing the new snapshot', async () => {
  const p = page(), mutation = p.context.invoke('verify'), read = p.context.read();
  const current = { available: true, marker: 'new current snapshot', manual: { attemptId: 'current-attempt' } };
  p.requests[1].resolve(current); await read;
  p.requests[0].resolve({ available: true, marker: 'older mutation response' }); await mutation;
  assert.equal(p.context.state, current);
  assert.equal(p.context.pause, true);
  assert.deepEqual(p.effects, ['render']);
});

test('a current failed operation keeps the actual server error and does not turn it into success', async () => {
  const p = page(), pending = p.context.invoke('verify');
  const response = { manual: { attemptId: 'attempt-original', lastError: { code: 'W3C_CREDENTIAL_REVOKED', message: '签发方已撤销此凭证' } } };
  p.requests[0].resolve(response);
  await assert.rejects(pending, error => error.code === 'W3C_CREDENTIAL_REVOKED' && error.message === response.manual.lastError.message);
  assert.equal(p.context.state, response);
  assert.deepEqual(p.effects, ['changed', 'render']);
});

test('transport rejections leave the old snapshot intact for the caller to mark as unconfirmed', async () => {
  for (const operation of ['read', 'invoke']) {
    const p = page(), original = p.context.state, pending = operation === 'read' ? p.context.read() : p.context.invoke('verify');
    const error = Object.assign(new Error('request timed out'), { uncertain: true });
    p.requests[0].reject(error);
    await assert.rejects(pending, caught => caught === error);
    assert.equal(p.context.state, original);
    assert.equal(p.context.uncertain, true);
    assert.deepEqual(p.effects, []);
  }
});

// A narrow DOM boundary double: markup assignments choose new detail nodes.
// The actual controller still decides which keys to save and restore.
function detailElement(versions, initial) {
  let nodes = [];
  const element = {
    querySelectorAll(selector) {
      assert.ok(['details', 'details[open]'].includes(selector));
      return selector === 'details[open]' ? nodes.filter(node => node.open) : nodes;
    },
    set innerHTML(value) {
      assert.ok(Object.hasOwn(versions, value));
      nodes = versions[value].map(({ key, check, row, summary, open = false }) => ({
        dataset: key ? { detailKey: key } : {}, open,
        closest(selector) {
          if (selector === '[data-check-id]') return check ? { dataset: { checkId: check } } : null;
          assert.equal(selector, '.guide-evidence-row');
          return row ? { querySelector(name) { assert.equal(name, 'strong'); return { textContent: row }; } } : null;
        },
        querySelector(selector) { assert.equal(selector, 'summary'); return { textContent: summary }; },
      }));
    },
    nodes: () => nodes,
  };
  element.innerHTML = initial;
  return element;
}

test('same-context details retain their own expansion after records reorder or labels change', () => {
  const p = page(), element = detailElement({
    before: [{ key: 'challenge', summary: '挑战依据', open: true }, { key: 'device', summary: '设备依据' }],
    after: [{ key: 'device', summary: '设备依据更新' }, { key: 'challenge', summary: '挑战依据更新' }, { key: 'new', summary: '新记录' }],
  }, 'before');
  p.context.replaceDetails(element, 'after', true);
  assert.deepEqual(element.nodes().map(node => [node.dataset.detailKey, node.open]), [['device', false], ['challenge', true], ['new', false]]);
  assert.deepEqual(p.requests, []);
});

test('a changed panel context uses the new operation defaults without borrowing old expansion', () => {
  const p = page(), element = detailElement({
    before: [{ key: 'credential', summary: '凭证依据', open: true }, { key: 'device', summary: '设备依据', open: true }],
    after: [{ key: 'credential', summary: '凭证依据', open: true }, { key: 'device', summary: '设备依据' }],
  }, 'before');
  p.context.replaceDetails(element, 'after', false);
  assert.deepEqual(element.nodes().map(node=>node.open),[true,false]);
  assert.deepEqual(p.requests, []);
});

test('opening one check evidence must not automatically open nested long public values on rerender', () => {
  const p = page(), element = detailElement({
    before: [{ check: 'w3c_bbs', summary: '查看验证依据', open: true }, { check: 'w3c_bbs', summary: 'abcdef…7890 查看完整值' }],
    after: [{ check: 'w3c_bbs', summary: '查看验证依据' }, { check: 'w3c_bbs', summary: 'abcdef…7890 查看完整值' }],
  }, 'before');
  p.context.replaceDetails(element, 'after', true);
  assert.deepEqual(element.nodes().map(node => node.open), [true, false]);
  assert.deepEqual(p.requests, []);
});

test('identical shortened values in different evidence rows retain separate expansion state', () => {
  const p = page(), element = detailElement({
    before: [{ check: 'w3c_bbs', row: '证明公开值', summary: 'abcdef…7890 查看完整值', open: true }, { check: 'w3c_bbs', row: '验证方输入', summary: 'abcdef…7890 查看完整值' }],
    after: [{ check: 'w3c_bbs', row: '验证方输入', summary: 'abcdef…7890 查看完整值' }, { check: 'w3c_bbs', row: '证明公开值', summary: 'abcdef…7890 查看完整值' }],
  }, 'before');
  p.context.replaceDetails(element, 'after', true);
  assert.deepEqual(element.nodes().map(node => node.open), [false, true]);
  assert.deepEqual(p.requests, []);
});

// Run the actual click controller with the real planner. Only the HTTP boundary
// returns staged snapshots, so these assertions cover which actions a click sends.
function guidedPage(phase = 'proposal', pace = 'guided', initialStage = null) {
  const actions = [], reads = [];
  const state = {
    available: true, mode: 'bbs-bls', credential: { id: 'test-vc' }, order: { orderId: 'order-current' },
    ...(phase !== 'proposal' ? { authorization: {}, proposal: { status: 'APPROVED' } } : {}),
    manual: { phase, active: Boolean(initialStage), stage: initialStage, attemptId: 'old-attempt',
      walletSigned: phase === 'settle', availableActions: initialStage ? [{CHALLENGE_READY:'derive-vc',VC_DERIVED:'device-sign',DEVICE_SIGNED:'prove',PROOF_READY:'verify'}[initialStage]] : [`begin-${phase}`] },
  };
  const context = {
    state, scenario: 'normal', busy: false, experimentBusy: false, refreshing: false, uncertain: false,
    pause: false, feedbackState: '', feedback: '', actionId: '', actionRunning: '',
    $: id => { assert.equal(id, 'guide-pace'); return { value: pace }; },
    currentPlan: () => planPayment(context.state, { ownerAvailable: true }),
    render() {}, done: () => false,
    read: async () => reads.push('state'),
    async invoke(id) {
      actions.push(id);
      if (context.failure) throw Error(context.failure);
      const m = context.state.manual;
      if (id.startsWith('begin-')) Object.assign(m, { active: true, attemptId: 'current-attempt', stage: 'CHALLENGE_READY', availableActions: ['derive-vc'] });
      else {
        const stages = {'derive-vc':['VC_DERIVED','device-sign'], 'device-sign':['DEVICE_SIGNED','prove'], prove:['PROOF_READY','verify'], verify:['VERIFIED','submit-owner']};
        const next = stages[id];
        if (next) Object.assign(m, { stage: next[0], availableActions: [next[1]] });
      }
      if (context.pauseAfter === id) context.pause = true;
    },
  };
  runInNewContext(sourceBetween('async function run(){', 'async function openOwner(){'), context);
  return { context, actions, reads };
}

for (const phase of ['proposal', 'authorize', 'settle']) test(`guided ${phase} preparation stops before the device and each subsequent click performs one action`, async () => {
  const p = guidedPage(phase);
  await p.context.run();
  assert.deepEqual(p.actions, [`begin-${phase}`, 'derive-vc']);
  assert.equal(p.context.state.manual.stage, 'VC_DERIVED');
  for (const action of ['device-sign', 'prove', 'verify']) {
    const before = p.actions.length;
    await p.context.run();
    assert.deepEqual(p.actions.slice(before), [action]);
  }
  assert.ok(!p.actions.includes('submit-owner'));
  assert.ok(!p.actions.includes('wallet-sign'));
  assert.deepEqual(p.reads, []);
});

test('message-by-message mode keeps challenge acquisition separate from derivation', async () => {
  const p = guidedPage('proposal', 'step');
  await p.context.run();
  assert.deepEqual(p.actions, ['begin-proposal']);
  await p.context.run();
  assert.deepEqual(p.actions, ['begin-proposal', 'derive-vc']);
});

for (const [stage, action] of [['CHALLENGE_READY','derive-vc'],['DEVICE_SIGNED','prove']]) test(`resuming ${stage} only sends ${action}`, async () => {
  const p = guidedPage('proposal', 'guided', stage);
  await p.context.run();
  assert.deepEqual(p.actions, [action]);
});

test('a failed preparation or an explicit pause cannot automatically invoke the next action', async () => {
  for (const mode of ['failure', 'pause']) {
    const p = guidedPage();
    if (mode === 'failure') p.context.failure = 'transport error';
    else p.context.pauseAfter = 'begin-proposal';
    await p.context.run();
    assert.deepEqual(p.actions, ['begin-proposal']);
    assert.equal(p.context.busy, false);
    assert.equal(p.context.actionId, '');
    if (mode === 'failure') assert.deepEqual(p.reads, ['state']);
  }
});

test('disabled or uncertain state sends no cryptographic or payment action', async () => {
  for (const uncertain of [true, false]) {
    const p = guidedPage('settle', 'guided', 'PROOF_READY');
    p.context.uncertain = uncertain;
    if (!uncertain) p.context.state.manual.availableActions = [];
    await p.context.run();
    assert.deepEqual(p.actions, []);
  }
});


test('a user-collapsed default-open core view stays collapsed during same-step refresh', () => {
  const p=page(),element=detailElement({before:[{key:'core',summary:'本步核心证据',open:false}],after:[{key:'core',summary:'本步核心证据',open:true}]},'before');
  p.context.replaceDetails(element,'after',true);
  assert.equal(element.nodes()[0].open,false);
});

test('normal feedback is visible while waiting for pause and after the request returns', async () => {
  const element={textContent:'',hidden:true,dataset:{}},p=guidedPage();
  p.context.$=id=>id==='guide-feedback'?element:{value:'guided'};
  runInNewContext(sourceBetween('function renderOperationFeedback(){','function render(){'),p.context);
  p.context.render=()=>p.context.renderOperationFeedback();
  p.context.busy=true;p.context.feedback='将在当前请求返回后暂停，不撤回已发送请求。';p.context.render();
  assert.equal(element.hidden,false);assert.match(element.textContent,/当前请求返回后暂停/);assert.equal(element.dataset.state,'running');
  p.context.busy=false;p.context.pauseAfter='begin-proposal';await p.context.run();
  assert.equal(element.hidden,false);assert.match(element.textContent,/已暂停后续自动准备/);assert.match(element.textContent,/需再次点击/);assert.equal(element.dataset.state,'info');
  assert.deepEqual(p.actions,['begin-proposal']);
  for(const text of ['已核对原订单状态；没有重新签名、重新认证或付款。','新订单已创建。旧回执保留。','已结束本次认证尝试。']){
    p.context.feedback=text;p.context.render();assert.equal(element.textContent,text);assert.equal(element.hidden,false);
  }
  p.context.feedback='';p.context.render();assert.equal(element.hidden,true);
});

// Preserve the read-only mode-switch contract on the remaining guide page.
// Execute its real selector handler, API, read and refresh functions; only the
// server snapshots and DOM rendering are boundary doubles.
function modeSwitchPage(kind) {
  const ordinary = 'bbs-bls', blind = 'bbs-blind-bls';
  const clone = value => JSON.parse(JSON.stringify(value));
  const snapshot = (selectedMode, walletState) => {
    const settled = walletState === 'settled';
    const walletSigned = walletState === 'walletSigned' || settled;
    const walletSigningUnconfirmed = walletState === 'walletSigningUnconfirmed';
    return {
      available: true, mode: selectedMode,
      paymentPending: !settled && (walletSigned || walletSigningUnconfirmed),
      order: { orderId: `order-${selectedMode}`, amountMinor: 2990000, currency: 'TEST_USDC' },
      credential: { id: `credential-${selectedMode}` },
      authorization: { id: `authorization-${selectedMode}` },
      manual: {
        active: true, attemptId: `attempt-${selectedMode}`, phase: settled ? 'settle' : 'authorize',
        stage: settled ? 'SETTLED' : walletSigned ? 'WALLET_SIGNED' : walletSigningUnconfirmed ? 'VERIFIED' : 'CHALLENGE_READY',
        walletSigned, walletSigningUnconfirmed, settled,
        walletPayload: walletSigned ? { signature: `public-wallet-signature-${selectedMode}`, orderId: `order-${selectedMode}` } : null,
        verifiableCredential: { id: `derived-vc-${selectedMode}` },
        log: [{ id: `history-${selectedMode}` }],
      },
    };
  };
  const states = new Map([[ordinary, snapshot(ordinary, kind)], [blind, snapshot(blind, 'active')]]);
  const originals = [...states].map(([selectedMode, value]) => [selectedMode, clone(value)]);
  const elements = new Map(['guide-mode', 'guide-pace', 'guide-refresh', 'guide-normal', 'guide-environment'].map(id => [id, {
    value: id === 'guide-mode' ? ordinary : '', disabled: false, dataset: {}, setAttribute() {},
  }]));
  const storage = new Map([['a2a-did-vc-ui-key', 'x'.repeat(43)]]), requests = [], messages = [], renders = [];
  const context = {
    state: null, scenario: 'normal', busy: false, experimentBusy: false, refreshing: false,
    uncertain: false, generation: 0, detailPlanKey: '', ownerProposal: { id: 'old-owner-proposal' },
    feedback: '', feedbackState: '',
    mode: () => elements.get('guide-mode').value,
    $: id => { assert.ok(elements.has(id), `mode switch requested a known element: ${id}`); return elements.get(id); },
    store: { get: key => storage.get(key) || '', set: (key, value) => storage.set(key, value) },
    keyPattern: /^[A-Za-z0-9_-]{43}$/, ownerKey: () => '',
    renderModeDescription() {}, drainGuideRoute() {},
    render() { renders.push(context.state && clone(context.state)); context.lock(); },
    document: { querySelectorAll: () => [] },
    parent: { postMessage: message => messages.push(clone(message)) },
    location: { origin: 'http://127.0.0.1:4340' },
    AbortSignal,
    async fetch(path, options) {
      const url = new URL(path, 'http://127.0.0.1:4340');
      const requestedMode = url.searchParams.get('mode');
      requests.push({ path: url.pathname, mode: requestedMode, method: options.method, body: options.body });
      assert.equal(options.method, 'GET', 'switching modes cannot discard, approve, sign or settle');
      assert.equal(options.body, undefined);
      assert.equal(url.pathname, '/api/dbac/payment/state');
      assert.ok(states.has(requestedMode));
      return { ok: true, status: 200, json: async () => clone(states.get(requestedMode)) };
    },
  };
  runInNewContext([
    sourceBetween('function lock(){', 'async function api('),
    sourceBetween('async function api(', 'const experiment='),
    sourceBetween('async function read(){', 'function sameOrder('),
    sourceBetween("$('guide-mode').onchange=", "$('guide-pace').onchange="),
  ].join('\n'), context, { filename: 'public/guide.js#mode-change' });
  return { context, states, originals, elements, storage, requests, messages, renders, ordinary, blind, clone };
}

for (const kind of ['walletSigned', 'walletSigningUnconfirmed', 'settled']) {
  test(`guide selector preserves ${kind} materials through a read-only mode round trip`, async () => {
    const p = modeSwitchPage(kind);
    await p.context.refresh();
    const original = p.clone(p.context.state);
    assert.equal(p.elements.get('guide-mode').disabled, false);
    for (const selectedMode of [p.blind, p.ordinary]) {
      p.elements.get('guide-mode').value = selectedMode;
      const switching = p.elements.get('guide-mode').onchange();
      assert.equal(p.context.state, null, 'the previous mode cannot remain visible during the new read');
      assert.equal(p.context.ownerProposal, null);
      assert.equal(p.elements.get('guide-mode').disabled, true, 'the state read locks reentrant selection');
      await switching;
      assert.deepEqual(p.clone(p.context.state), p.clone(p.states.get(selectedMode)));
      assert.equal(p.storage.get('a2a-manual-mode'), selectedMode);
      assert.equal(p.context.uncertain, false);
      assert.equal(p.elements.get('guide-mode').disabled, false);
    }
    assert.deepEqual(p.clone(p.context.state), original, 'order, attempt, credential, approval and wallet materials survive');
    assert.deepEqual([...p.states].map(([selectedMode, value]) => [selectedMode, p.clone(value)]), p.originals);
    assert.deepEqual(p.requests, [p.ordinary, p.blind, p.ordinary].map(selectedMode => ({
      path: '/api/dbac/payment/state', mode: selectedMode, method: 'GET', body: undefined,
    })));
    assert.ok(p.messages.every(message => message.type === 'demo:busy'));
    assert.ok(p.messages.some(message => message.busy === true));
    assert.equal(p.messages.at(-1).busy, false);
    assert.match(p.context.feedback, /没有重新签名、重新认证或付款/);
  });
}
