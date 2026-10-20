import test from 'node:test';
import assert from 'node:assert/strict';
import { deriveScene, renderSceneCanvas, renderSceneSummary } from '../public/guide-scene.js';

const now = Date.parse('2026-10-12T00:00:00Z');
const mode = 'bbs-bls';
const order = { orderId: 'order-current', amountMinor: 2990000, currency: 'TEST_USDC', payerAccount: 'agent-a', payeeAccount: 'agent-b',
  settlement: { network: 'eip155:31337', asset: 'test-token', payerAddress: '0x-a', payTo: '0x-b' } };
const ids = ['extension', 'envelope', 'challenge', 'replay', 'request_binding', 'policy_context', 'scope', 'w3c_bbs', 'holder_signature',
  'credential_status', 'vc_device_binding', 'schema', 'proof_structure', 'disclosure', 'proof_encoding', 'knowledge', 'credential_pairing',
  'device_pairing', 'owner_authorization', 'task_binding', 'consume', 'settlement_gate', 'execution'];
function trace(phase = 'proposal', { failed, code, challengeId = 'challenge-current' } = {}) {
  const unused = phase === 'proposal' ? ['owner_authorization', 'task_binding', 'settlement_gate'] : phase === 'authorize' ? ['task_binding', 'settlement_gate'] : [];
  const failIndex = ids.indexOf(failed);
  return { source: 'agent-b', profile: 'dbac-payment', outcome: failed ? 'fail' : 'pass', steps: ids.map((id, index) => ({ id, title: id, status: id === failed ? 'fail' : unused.includes(id) || failIndex >= 0 && index > failIndex ? 'skipped' : 'pass', ...(id === failed ? { code } : {}),
    ...(id === 'scope' ? { evidence: [{ label: 'payment order ID', expected: order.orderId, observed: order.orderId }, { label: 'method / scope / phase', expected: ['message/send', 'payments:pay', phase], observed: ['message/send', 'payments:pay', phase] }] }
      : id === 'challenge' ? { evidence: [{ label: 'challenge found / now / expiry (s)', observed: [true, now / 1000, now / 1000 + 60] }], challengeId } : {}),
  })) };
}
function fixture(phase = 'proposal', stage = 'VC_DERIVED', selectedMode = mode) {
  const context = { mode: selectedMode, paymentOrderId: order.orderId, challengeId: `challenge-${phase}`, bodyHash: `body-${phase}` };
  const vc = { credentialSubject: { bindingId: 'bound-vc', holderDid: 'did:test:a', mode: selectedMode } };
  return { available: true, mode: selectedMode, credential: { suite: 'public-suite' }, currentCredentialId: 'vc-current',
    order: structuredClone(order), credentialStatus: { available: true, status: 'valid' }, owner: { available: true },
    w3c: { enabled: true, originalCredential: { ...vc, validUntil: '2026-10-13T00:00:00Z' }, disclosedPaths: ['/credentialSubject/bindingId', '/credentialSubject/holderDid', '/credentialSubject/mode'] },
    manual: { active: true, attemptId: `attempt-${phase}`, phase, stage, expiresAtUnix: now / 1000 + 60, challenge: context,
      cryptography: { w3cPresentationHash: `vc-hash-${phase}` }, verifiableCredential: vc,
      device: { available: true, publicKey: 'public-device-key' }, availableActions: ['device-sign', 'discard'],
      deviceRequest: selectedMode === 'bbs-blind-bls' ? { version: 'v1', suite: 'public-suite', mode: selectedMode, blindedPoint: 'public-blinded-point' }
        : { mode: selectedMode, randomizedDevicePublicKey: 'public-pseudonym', context: { challengeId: context.challengeId, bodyHash: context.bodyHash, w3cPresentationHash: `vc-hash-${phase}` } } } };
}
function deviceReturned(state) {
  state.manual.deviceResponse = { mode: state.mode, signature: 'public-device-contribution' };
  state.manual.stage = 'DEVICE_SIGNED'; state.manual.availableActions = ['prove', 'discard']; return state;
}
function combined(state) {
  deviceReturned(state); state.manual.presentation = { deviceSignature: 'public-adapted-contribution' };
  state.manual.holderProof = 'public.holder.proof'; state.manual.stage = 'PROOF_READY'; state.manual.availableActions = ['verify', 'discard']; return state;
}
function verified(state, options = {}) {
  combined(state); state.manual.sentCredential = structuredClone(state.manual.verifiableCredential);
  state.manual.stage = 'VERIFIED'; state.manual.availableActions = [state.manual.phase === 'proposal' ? 'submit-owner' : 'wallet-sign', 'discard'];
  state.manual.verificationResult = { accepted: true, mode: state.mode, phase: state.manual.phase,
    wire: { context: structuredClone(state.manual.challenge) }, verificationTrace: trace(state.manual.phase, options) }; return state;
}
const scene = (state, options = {}) => deriveScene({ state, mode: state?.mode || mode, now, ...options });
const node = (model, id) => model.nodes.find(value => value.id === id);
const messagePairs = model => model.messages.map(value => `${value.from}->${value.to}`);

test('empty, disconnected and wrong-mode snapshots never create success or sample amounts', () => {
  for (const value of [undefined, { available: false, mode }, { ...verified(fixture()), available: false }]) {
    const model = scene(value);
    assert.equal(model.summary.status, 'unknown'); assert.equal(model.receipt, null);
    assert.equal(model.messages.length, 0); assert.ok(model.nodes.every(value => value.state !== 'pass'));
    assert.equal(model.summary.facts.find(value => value.label === '本笔金额').value, '尚未准备');
  }
  const model = scene(verified(fixture()), { mode: 'bbs-blind-bls' });
  assert.equal(model.summary.facts.find(value => value.label === '订单编号').value, '尚未准备');
  assert.equal(node(model, 'verifier').state, 'pending');
  const noPermission = scene(null, { uncertain: true });
  assert.equal(node(noPermission, 'ledger').label, '当前状态待读取');
  assert.doesNotMatch(noPermission.note, /原操作结果|通信中断/);
});

test('device online, prepared public input, contribution and B verification remain distinct', () => {
  const prepared = scene(fixture());
  assert.equal(node(prepared, 'device').state, 'pending'); assert.match(node(prepared, 'device').detail, /连接不表示/);
  assert.equal(prepared.messages.length, 0, 'prepared input is not a transmitted request');
  const returned = scene(deviceReturned(fixture()));
  assert.equal(node(returned, 'device').state, 'material'); assert.equal(node(returned, 'verifier').state, 'pending');
  assert.deepEqual(messagePairs(returned), ['holder->device', 'device->holder']);
  assert.ok(returned.messages.every(value => value.state !== 'pass'));
  const ready = scene(combined(fixture()));
  assert.equal(node(ready, 'holder').label, '本轮组合证明已生成'); assert.match(node(ready, 'holder').detail, /独立请求签名/);
  assert.equal(node(ready, 'verifier').state, 'pending');
  assert.deepEqual(messagePairs(scene(verified(fixture()))), ['holder->verifier', 'verifier->holder']);
  assert.equal(node(scene(verified(fixture())), 'verifier').state, 'pass');
});

test('only the actual in-flight request animates, with no invented internal progress', () => {
  const base = combined(fixture());
  for (const [actionId, pair] of [['device-sign', 'holder->device'], ['verify', 'holder->verifier'], ['begin-proposal', 'holder->verifier']]) {
    const value = scene(base, { busy: true, actionId });
    assert.deepEqual(messagePairs(value), [pair]); assert.equal(value.messages[0].state, 'running');
    assert.equal(value.receipt, null);
  }
  const proving = scene(deviceReturned(fixture()), { busy: true, actionId: 'prove' });
  assert.equal(proving.messages.length, 0); assert.match(node(proving, 'holder').label, /本地核验并组合/);
  assert.equal(node(proving, 'verifier').state, 'pending');
});

test('phase, order, attempt, selected phase and challenge mismatches cannot reuse current material or success', () => {
  const mutations = [
    state => { state.manual.attemptId = null; },
    state => { state.order.orderId = 'new-order'; },
    state => { state.manual.challenge.mode = 'bbs-blind-bls'; },
    state => { state.manual.verificationResult.phase = 'authorize'; },
    state => { state.manual.verificationResult.mode = 'bbs-blind-bls'; },
    state => { state.manual.verificationResult.wire.context.challengeId = 'old-challenge'; },
    state => { state.manual.verificationResult.wire.context.paymentOrderId = 'old-order'; },
    state => { state.manual.verificationResult.verificationTrace = trace('authorize'); },
    state => { state.manual.verificationResult.verificationTrace.steps.find(item => item.id === 'scope').evidence[0].observed = 'old-order'; },
  ];
  for (const mutate of mutations) {
    const state = verified(fixture()); mutate(state);
    assert.notEqual(node(scene(state), 'verifier').state, 'pass');
  }
  assert.equal(node(scene(verified(fixture()), { detail: { phase: 'authorize' } }), 'device').state, 'pending');
  assert.equal(node(scene(verified(fixture()), { detail: { phase: 'authorize', starting: true } }), 'verifier').state, 'pending');
  const nextPhase = fixture('authorize'); nextPhase.lastResult = verified(fixture()).manual.verificationResult;
  assert.equal(node(scene(nextPhase), 'verifier').state, 'pending');
});

test('old ordinary device input is not rendered as this challenge contribution', () => {
  for (const mutate of [state => { state.manual.deviceRequest.context.challengeId = 'old'; }, state => { state.manual.deviceRequest.context.bodyHash = 'old'; },
    state => { state.manual.deviceRequest.context.w3cPresentationHash = 'old'; }, state => { state.manual.deviceResponse.mode = 'bbs-blind-bls'; }]) {
    const state = combined(fixture()); mutate(state);
    assert.equal(node(scene(state), 'device').state, 'pending'); assert.notEqual(node(scene(state), 'holder').label, '本轮组合证明已生成');
  }
});

test('default current-step projection suppresses prior-stage materials before a new phase starts', () => {
  const state = verified(fixture('authorize'));
  state.manual.walletSigned = true;
  state.manual.stage = 'WALLET_SIGNED';
  state.manual.availableActions = ['begin-settle', 'discard'];
  const model = scene(state);
  assert.equal(node(model, 'device').state, 'pending');
  assert.equal(node(model, 'verifier').state, 'pending');
  assert.equal(model.messages.length, 0);
  assert.match(node(model, 'ledger').label, /钱包材料已签署/);
  const explicit = scene(verified(fixture()), { plan: { id: 'begin-authorize', enabled: true } });
  assert.equal(node(explicit, 'device').state, 'pending');
  assert.equal(node(explicit, 'verifier').state, 'pending');
});

test('blind public fields and A-local context are described without emitting raw payloads or secrets', () => {
  const state = deviceReturned(fixture('proposal', 'VC_DERIVED', 'bbs-blind-bls'));
  state.manual.deviceRequest.ownerKey = 'DO-NOT-EXPOSE-owner';
  state.manual.deviceRequest.blindingSecret = 'DO-NOT-EXPOSE-blinding';
  state.manual.challenge.bodyHash = 'A-LOCAL-CONTEXT';
  const model = scene(state), rendered = renderSceneCanvas(model) + renderSceneSummary(model);
  assert.match(model.note, /blindedPoint.*A 本地材料/); assert.match(model.messages[0].label, /盲化请求/);
  assert.doesNotMatch(rendered, /DO-NOT-EXPOSE|A-LOCAL-CONTEXT/);
  assert.equal(node(model, 'device').state, 'material');
  assert.ok(model.messages.every(value => !(value.from === 'device' && value.to === 'verifier')));
});

test('expiry and uncertain responses are visible and cannot produce fresh verifier success', () => {
  const state = verified(fixture()); state.manual.expiresAtUnix = now / 1000;
  const expired = scene(state); assert.match(expired.note, /已过期/); assert.notEqual(node(expired, 'verifier').state, 'pass');
  const unknown = scene(verified(fixture()), { uncertain: true });
  assert.equal(unknown.summary.status, 'unknown'); assert.match(unknown.note, /不表示服务端操作已取消/);
  assert.equal(unknown.messages.length, 0); assert.equal(unknown.receipt, null);
});

test('Owner approval, wallet signature and receipt require their own actual records', () => {
  const state = verified(fixture());
  state.proposal = { mode, status: 'APPROVED', payment: structuredClone(order) };
  assert.match(node(scene(state), 'owner').label, /待同步/);
  state.authorization = { document: { payment: structuredClone(order) } };
  assert.equal(node(scene(state), 'owner').state, 'material'); assert.equal(scene(state).receipt, null);
  state.manual.walletSigned = true;
  assert.match(node(scene(state), 'ledger').label, /尚未结算/); assert.equal(scene(state).receipt, null);
  state.authorization.document.payment.amountMinor++;
  assert.notEqual(node(scene(state), 'owner').label, '本笔授权已批准并同步');
});

function completed() {
  const state = verified(fixture('settle')); state.manual.stage = 'SETTLED'; state.manual.settled = true; state.manual.walletSigned = true;
  state.manual.verificationResult.task = { status: { state: 'completed' } };
  state.manual.verificationResult.paymentResult = { outcome: 'EXECUTED', receipt: { ...structuredClone(order), transactionHash: 'actual-transaction-hash' } };
  return state;
}
test('only a successful current-order receipt renders payment completion', () => {
  const model = scene(completed());
  assert.equal(model.receipt.amount, '2.99 TEST_USDC'); assert.equal(model.summary.status, 'pass');
  assert.equal(node(model, 'ledger').state, 'pass'); assert.deepEqual(messagePairs(model), ['verifier->holder']);
  for (const mutate of [state => { state.manual.settled = false; }, state => { state.manual.walletSigningUnconfirmed = true; },
    state => { state.manual.verificationResult.phase = 'authorize'; }, state => { state.manual.verificationResult.mode = 'bbs-blind-bls'; },
    state => { state.manual.verificationResult.task.status.state = 'working'; }, state => { state.manual.verificationResult.accepted = false; },
    state => { state.manual.verificationResult.paymentResult.outcome = 'PENDING'; }, state => { state.manual.verificationResult.paymentResult.receipt.amountMinor++; },
    state => { state.manual.verificationResult.paymentResult.receipt.settlement.asset = 'other-token'; }, state => { delete state.manual.verificationResult.paymentResult; }]) {
    const state = completed(); mutate(state); const rejected = scene(state);
    assert.equal(rejected.receipt, null); assert.notEqual(node(rejected, 'ledger').state, 'pass');
  }
  assert.equal(scene(completed(), { uncertain: true }).receipt, null);
});

function experiment(scenarioId = 'copied-vc', failed = scenarioId === 'copied-vc' ? 'holder_signature' : 'credential_status') {
  const code = scenarioId === 'copied-vc' ? 'HOLDER_PROOF_REQUIRED' : 'W3C_CREDENTIAL_REVOKED';
  const record = { id: 'record-id', mode, scenarioId, completion: 'completed', requestRejected: true, authenticationIssued: false,
    actual: code, expected: code, expectationMet: true, rejectionStage: failed,
    control: { accepted: true, challengeId: 'control-challenge', verificationTrace: trace() },
    request: { challengeId: 'attack-challenge', authenticationRoundId: 'attack-challenge', proof: { verifiableCredential: { proof: { type: 'DataIntegrityProof' } },
      ...(scenarioId === 'revoked' ? { holderProof: 'holder.public.signature', deviceSignature: 'public-device-signature' } : {}) } },
    ...(scenarioId === 'revoked' ? { revocation: { credential: 'experiment-only', freshChallenge: true, completeHolderProof: true, completeDeviceProof: true } } : {}),
    verificationTrace: trace('proposal', { failed, code }),
    sideEffects: { before: { executionCount: 0, accounts: [] }, after: { executionCount: 0, accounts: [] }, paymentExecutionDelta: 0, balancesUnchanged: true, ownerApprovalRequested: false, walletSignatureRequested: false } };
  return { context: { runId: 'run-id', mode, scenarioId, pending: false }, record };
}
const experimentScene = (value, options = {}) => deriveScene({ scenario: value?.context?.scenarioId || 'copied-vc', mode, experiment: value, now, ...options });

test('unrun and pending experiments never forecast rejection or animate internal phases', () => {
  const empty = experimentScene(null);
  assert.equal(empty.summary.status, 'pending'); assert.equal(empty.comparison.expectationMet, false); assert.equal(empty.messages.length, 0);
  const value = experiment(); value.context.pending = true;
  const pending = experimentScene(value);
  assert.equal(pending.summary.status, 'running'); assert.equal(pending.messages.length, 0);
  assert.equal(pending.comparison.expectationMet, false); assert.equal(pending.comparison.bbsMaterial, false);
  assert.match(pending.note, /没有内部实时进度/);
});

test('copied VC uses a separate attacker and preserves actual early holder rejection with skipped device checks', () => {
  const model = experimentScene(experiment());
  assert.equal(model.summary.status, 'fail'); assert.equal(model.comparison.expectationMet, true);
  assert.equal(model.comparison.control, 'pass'); assert.equal(model.comparison.request, 'fail');
  assert.equal(model.comparison.rejectionStage, 'holder_signature');
  assert.ok(model.comparison.skipped.some(value => value.id === 'device_pairing'));
  assert.equal(node(model, 'attacker').state, 'material'); assert.equal(node(model, 'device').state, 'na');
  assert.deepEqual(messagePairs(model), ['attacker->verifier', 'verifier->attacker']);
  assert.equal(model.comparison.bbsMaterial, true); assert.match(node(model, 'attacker').label, /派生材料已生成/);
  assert.match(model.note, /本轮记录回看.*只读/);
});

test('revocation preserves original A and device, with material presence distinct from independent verification', () => {
  const model = experimentScene(experiment('revoked'));
  assert.equal(model.summary.status, 'fail'); assert.equal(model.comparison.rejectionStage, 'credential_status');
  assert.equal(model.nodes.some(value => value.id === 'attacker'), false);
  assert.equal(node(model, 'device').state, 'material'); assert.match(node(model, 'issuer').label, /实验专用凭证已撤销/);
  assert.deepEqual(messagePairs(model), ['holder->verifier', 'verifier->holder']);
  assert.doesNotMatch(renderSceneCanvas(model), /设备失效|设备丢失|设备离线|设备锁定|所有密码学检查均已通过/);
});

test('experiment context mismatch, missing control, contradictions and incomplete runs cannot become successful defense', () => {
  for (const mutate of [value => { value.record.mode = 'bbs-blind-bls'; }, value => { value.record.scenarioId = 'revoked'; },
    value => { value.record.runId = 'other-run'; }, value => { delete value.record.id; }, value => { value.record.control = null; },
    value => { value.record.control.accepted = false; }, value => { value.record.control.verificationTrace.steps[0].status = 'fail'; },
    value => { value.record.completion = 'incomplete'; }, value => { value.record.request.challengeId = 'control-challenge'; },
    value => { value.record.verificationTrace.outcome = 'pass'; }, value => { value.record.rejectionStage = 'device_pairing'; },
    value => { value.record.sideEffects.paymentExecutionDelta = 1; }, value => { value.record.sideEffects.balancesUnchanged = false; },
    value => { value.record.verificationTrace.steps.push({ id: 'holder_signature', status: 'pass' }); }]) {
    const value = experiment(); mutate(value); assert.equal(experimentScene(value).comparison.expectationMet, false);
  }
  const old = experiment(); old.context.mode = 'bbs-blind-bls';
  assert.equal(experimentScene(old).summary.facts[0].value, '尚未准备');
  assert.equal(experimentScene(experiment(), { uncertain: true }).comparison.expectationMet, false);
});

test('scene identity stays stable for repeated polling and changes only with actual context/results', () => {
  const state = deviceReturned(fixture());
  assert.equal(scene(state).eventKey, scene(structuredClone(state)).eventKey);
  const other = structuredClone(state); other.manual.challenge.challengeId = 'new-challenge';
  assert.notEqual(scene(state).eventKey, scene(other).eventKey);
  assert.equal(experimentScene(experiment()).eventKey, experimentScene(experiment()).eventKey);
});

test('renderer escapes public labels, keeps read-only evidence hooks and has at most two correctly directed arrows', () => {
  const state = deviceReturned(fixture()); state.order.orderId = '<img src=x onerror=alert(1)>';
  const summary = renderSceneSummary(scene(state));
  assert.doesNotMatch(summary, /<img/); assert.match(summary, /&lt;img/);
  const html = renderSceneCanvas(scene(deviceReturned(fixture())));
  assert.equal((html.match(/class="scene-wire"/g) || []).length, 2);
  assert.match(html, /data-from="holder" data-to="device"/); assert.match(html, /data-from="device" data-to="holder"/);
  assert.doesNotMatch(html, /data-from="device" data-to="verifier"|onclick=|fetch\(/);
  assert.match(html, /data-scene-evidence="device"/); assert.match(html, /aria-label="当前场景角色交互"/);
  assert.match(html, /class="scene-wires"[^>]*role="group"/);
  assert.doesNotMatch(html, /class="scene-wires"[^>]*aria-hidden="true"/);
  assert.match(html, /<foreignObject[^>]*pointer-events="all"/);
  assert.doesNotMatch(html, /\bstyle=/, 'runtime CSP disallows inline style');
  assert.match(html, /A → 设备：本轮输入/);
  assert.match(html, /设备 → A：贡献已返回/);
  const routes = [...html.matchAll(/<path d="(M[^\"]+)" marker-end/g)].map(match => match[1]);
  assert.equal(routes.length, 2); assert.notEqual(routes[0], routes[1], 'opposite arrows use separate routes and label positions');
});

test('SVG endpoints clear the node rectangles and invalid or self messages cannot emit NaN geometry', () => {
  for (const model of [scene(deviceReturned(fixture())), scene(verified(fixture())), scene(completed()), experimentScene(experiment())]) {
    const html = renderSceneCanvas(model);
    const paths = [...html.matchAll(/data-from="([^"]+)" data-to="([^"]+)"><path d="([^"]+)"/g)];
    assert.equal(paths.length, model.messages.length);
    for (const [, fromId, toId, path] of paths) {
      const points = [...path.matchAll(/(-?[\d.]+),(-?[\d.]+)/g)].map(([, x, y]) => [Number(x), Number(y)]);
      assert.ok(points.flat().every(Number.isFinite));
      for (const [id, point] of [[fromId, points[0]], [toId, points.at(-1)]]) {
        const center = node(model, id).position;
        const distanceToBorder = Math.max(Math.abs(point[0] - center[0]) - 80, Math.abs(point[1] - center[1]) - 60);
        assert.ok(distanceToBorder >= 7.999, 'arrow endpoint remains outside the card by the configured padding');
      }
    }
  }
  const invalid = scene(fixture());
  invalid.messages = [{ from: 'holder', to: 'holder', label: 'self', state: 'pending', evidence: 'holder' },
    { from: 'unrecognized', to: 'holder', label: 'unknown', state: 'pending', evidence: 'holder' }];
  const html = renderSceneCanvas(invalid);
  assert.doesNotMatch(html, /class="scene-wire"|NaN|Infinity/);
});

test('copied-scene labels use the central corridor and never intersect any role rectangle', () => {
  const model = experimentScene(experiment()), html = renderSceneCanvas(model);
  const rectangles = [...html.matchAll(/<foreignObject x="([^"]+)" y="([^"]+)" width="([^"]+)" height="([^"]+)"/g)]
    .map(([, x, y, width, height]) => ({ x: Number(x), y: Number(y), width: Number(width), height: Number(height) }));
  assert.equal(rectangles.length, 2);
  const intersects = (a, b) => a.x < b.x + b.width && a.x + a.width > b.x && a.y < b.y + b.height && a.y + a.height > b.y;
  for (const label of rectangles) for (const role of model.nodes) {
    // The mechanism scene cards are 138 x 88; the padded 160 x 120 bounds also
    // cover wrapped status text and the role-detail label affordance.
    const card = { x: role.position[0] - 80, y: role.position[1] - 60, width: 160, height: 120 };
    assert.equal(intersects(label, card), false, `label must clear ${role.id}`);
  }
  assert.equal(intersects(rectangles[0], rectangles[1]), false, 'request and response labels are separate');
  assert.match(html, /攻击者 → B：冒用请求/);
  assert.match(html, /B → 攻击者：拒绝/);
  assert.doesNotMatch(html, /攻击者 → B · 本轮复制冒用请求/);
  const accepted = structuredClone(model); accepted.messages[1].state = 'pass';
  assert.match(renderSceneCanvas(accepted), /B → 攻击者：认证/);
  accepted.messages[1].state = 'unknown';
  assert.match(renderSceneCanvas(accepted), /B → 攻击者：待核对/);
});

test('ordinary and blind device labels clear all cards, including the single returned contribution after combination', () => {
  const intersects = (a, b) => a.x < b.x + b.width && a.x + a.width > b.x && a.y < b.y + b.height && a.y + a.height > b.y;
  for (const selectedMode of ['bbs-bls', 'bbs-blind-bls']) for (const prepare of [deviceReturned, combined]) {
    const model = scene(prepare(fixture('proposal', 'VC_DERIVED', selectedMode))), html = renderSceneCanvas(model);
    const rectangles = [...html.matchAll(/<foreignObject x="([^"]+)" y="([^"]+)" width="([^"]+)" height="([^"]+)"/g)]
      .map(([, x, y, width, height]) => ({ x: Number(x), y: Number(y), width: Number(width), height: Number(height) }));
    assert.equal(rectangles.length, prepare === combined ? 1 : 2);
    for (const label of rectangles) for (const role of model.nodes) {
      const card = { x: role.position[0] - 80, y: role.position[1] - 60, width: 160, height: 120 };
      assert.equal(intersects(label, card), false, `${selectedMode} label must clear ${role.id}`);
    }
    if (rectangles.length === 2) assert.equal(intersects(rectangles[0], rectangles[1]), false);
    assert.match(html, /设备 → A：贡献已返回/);
    if (prepare === deviceReturned) assert.match(html, selectedMode === 'bbs-blind-bls' ? /A → 设备：盲化请求/ : /A → 设备：本轮输入/);
  }
});
