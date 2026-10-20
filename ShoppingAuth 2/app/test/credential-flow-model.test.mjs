import test from 'node:test';
import assert from 'node:assert/strict';
import {
  nextFlowAction, flowSnapshot, verificationRows, verificationConclusion, flowTiming, flowProgress,
  initialView, flowBlockReason, canSwitchMode, canStartRound, pendingDisclosureNote, currentRejectionNotice,
} from '../public/credential-flow-model.js';

// Presentation-contract tests. The real verifier remains responsible for
// cryptographic decisions; this model must not invent or mix its observations.
const step = (id, status = 'pass', evidence = []) => ({ id, title: id, actor: 'agent-b', status, evidence });
const verifierIds = ['extension', 'envelope', 'challenge', 'replay', 'request_binding', 'policy_context',
  'scope', 'schema', 'w3c_bbs', 'credential_status', 'holder_signature', 'vc_device_binding', 'proof_structure', 'disclosure', 'proof_encoding',
  'knowledge', 'credential_pairing', 'device_pairing', 'consume'];
const trace = (steps = verifierIds.map(id => step(id))) => ({
  profile: 'dbac-payment', source: 'agent-b', outcome: 'pass', steps,
});
function fixture(overrides = {}) {
  return {
    available: true, mode: 'bbs-bls', paymentPending: false,
    credential: { suite: 'public-suite', attributes: [{ index: 0, name: 'role', value: 'payer', disclosed: true }] },
    order: { orderId: 'order-current', amountMinor: 2990000, currency: 'TEST_USDC',
      payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard' },
    w3c: { enabled: true, originalCredential: {
      '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential'],
      issuer: 'did:example:issuer', credentialSubject: { role: 'payer', bindingId: 'binding-current' },
      proof: { type: 'DataIntegrityProof', cryptosuite: 'bbs-2023', proofValue: 'public-proof' },
    } },
    manual: { active: true, phase: 'proposal', stage: 'CHALLENGE_READY', attemptId: 'attempt-current',
      expired: false, ownerApproved: false, walletSigned: false, walletSigningUnconfirmed: false, settled: false,
      availableActions: ['derive-vc', 'discard'], ...overrides },
  };
}
function expectAction(state, view, id, scenario = 'normal') {
  const action = nextFlowAction(state, view, scenario, 1000);
  assert.equal(action.id, id);
  assert.equal(typeof action.label, 'string');
  assert.ok(action.label.length > 0, 'an offered action has a visible label');
  assert.equal(action.enabled, !['complete', 'blocked', 'wait'].includes(id));
  return action;
}

test('the three visible steps expose only the current explicit credential action', () => {
  expectAction(fixture(), 'derive', 'derive-vc');
  const derived = fixture({ stage: 'VC_DERIVED', verifiableCredential: { proof: { proofValue: 'derived' } },
    deviceRequest: { mode: 'bbs-bls' }, availableActions: ['device-sign', 'test-no-device', 'discard'] });
  expectAction(derived, 'derive', 'view:device');
  expectAction(derived, 'device', 'device-sign');
  expectAction(derived, 'verify', 'view:device');
  const signed = fixture({ stage: 'DEVICE_SIGNED', deviceResponse: { signature: 'public-contribution' },
    availableActions: ['prove', 'discard'] });
  expectAction(signed, 'device', 'prove');
  const proved = fixture({ stage: 'PROOF_READY', presentation: { proof: { challenge: 'public-challenge' } },
    availableActions: ['verify', 'discard'] });
  expectAction(proved, 'device', 'view:verify');
  expectAction(proved, 'verify', 'verify');
});

test('missing credentials and inactive or expired attempts never skip preparation', () => {
  const unissued = fixture({ active: false, stage: 'IDLE', availableActions: ['begin-proposal'] });
  unissued.credential = null;
  unissued.w3c.originalCredential = null;
  expectAction(unissued, 'derive', 'issue');
  expectAction(fixture({ active: false, stage: 'IDLE', availableActions: ['begin-proposal'] }), 'derive', 'begin-proposal');
  expectAction(fixture({ expired: true, stage: 'PROOF_READY', presentation: { proof: {} },
    availableActions: ['begin-proposal', 'discard'] }), 'verify', 'begin-proposal');
});

test('backend availableActions are authoritative for every operation offered by the three-step UI', () => {
  for (const [view, stage, available, omitted] of [
    ['derive', 'CHALLENGE_READY', ['derive-vc'], 'derive-vc'],
    ['device', 'VC_DERIVED', ['device-sign'], 'device-sign'],
    ['device', 'DEVICE_SIGNED', ['prove'], 'prove'],
    ['verify', 'PROOF_READY', ['verify'], 'verify'],
  ]) {
    const state = fixture({ stage, presentation: stage === 'PROOF_READY' ? { proof: {} } : null,
      availableActions: available.filter(id => id !== omitted) });
    const action = nextFlowAction(state, view);
    assert.equal(action.enabled, false, `${omitted} cannot be enabled without server availability`);
  }
  const missing = nextFlowAction(fixture({ stage: 'VC_DERIVED', availableActions: [] }), 'verify', 'missing');
  assert.equal(missing.enabled, false);
});

test('a completed proposal verification ends the main flow before Owner approval or payment', () => {
  const state = fixture({ stage: 'VERIFIED', presentation: { proof: {} },
    verificationResult: { verificationTrace: trace() }, availableActions: ['submit-owner', 'discard'] });
  expectAction(state, 'verify', 'complete');
  assert.equal(state.manual.ownerApproved, false);
  assert.equal(state.manual.walletSigned, false);
  assert.equal(state.manual.settled, false);
});

test('pending signatures, uncertain settlement and payment phases block new credential rounds', () => {
  const states = [
    { ...fixture(), paymentPending: true },
    fixture({ walletSigned: true, settled: false }),
    fixture({ walletSigningUnconfirmed: true, settled: false }),
    fixture({ phase: 'authorize', availableActions: ['derive-vc', 'verify', 'wallet-sign'] }),
    fixture({ phase: 'settle', availableActions: ['derive-vc', 'verify'] }),
  ];
  for (const state of states) {
    assert.ok(flowBlockReason(state), 'the page explains why this saved payment state is blocked');
    assert.equal(canStartRound(state), false);
    for (const view of ['derive', 'device', 'verify']) expectAction(state, view, 'blocked');
  }
  assert.equal(flowBlockReason(fixture()), '');
  assert.equal(canStartRound(fixture({ availableActions: ['begin-proposal'] })), true);
  assert.equal(canStartRound(fixture({ availableActions: [] })), false, 'even a safe new round needs server availability');
});

test('read-only mode switching remains available while the current order blocks authentication mutations', () => {
  const states = [
    { ...fixture(), paymentPending: true },
    fixture({ walletSigned: true, settled: false }),
    fixture({ walletSigningUnconfirmed: true, settled: false }),
    fixture({ phase: 'authorize', ownerApproved: true }),
    fixture({ phase: 'settle', settled: true }),
    { ...fixture(), proposal: { status: 'PENDING' } },
  ];
  for (const state of states) {
    assert.equal(canSwitchMode(state), true, 'another mode can be read without clearing this order');
    assert.equal(canStartRound(state), false, 'switching does not unlock a new round for this order');
    assert.equal(nextFlowAction(state, 'derive').enabled, false);
  }
  assert.equal(canSwitchMode(null), false);
  assert.equal(canSwitchMode({ available: false }), false);
});

test('the missing-device comparison is explicit and does not prevent a later legitimate device action', () => {
  const state = fixture({ stage: 'VC_DERIVED', verifiableCredential: { proof: { proofValue: 'derived' } },
    availableActions: ['test-no-device', 'device-sign', 'discard'] });
  expectAction(state, 'verify', 'test-no-device', 'missing');
  state.manual.lastAttack = { action: 'test-no-device', actual: 'W3C_DEVICE_PROOF_REQUIRED',
    verificationTrace: { source: 'agent-b', outcome: 'fail', steps: [step('w3c_bbs'), step('vc_device_binding', 'fail')] } };
  expectAction(state, 'device', 'device-sign');
});

test('normal and missing-device views never borrow one another\'s verification result', () => {
  const state = fixture({ verificationResult: { verificationTrace: trace() }, lastAttack: {
    action: 'test-no-device', verificationTrace: { source: 'agent-b', outcome: 'fail',
      steps: [step('w3c_bbs'), step('vc_device_binding', 'fail')] },
  } });
  const normal = flowSnapshot(state);
  const missing = flowSnapshot(state, 'missing');
  assert.equal(normal.scenario, 'normal'); assert.equal(normal.verificationTrace.outcome, 'pass');
  assert.equal(missing.scenario, 'missing'); assert.equal(missing.verificationTrace.outcome, 'fail');
  delete state.manual.lastAttack.verificationTrace;
  assert.equal(flowSnapshot(state, 'missing').verificationTrace, null, 'missing negative evidence cannot borrow the prior normal pass');
  state.manual.lastAttack = { action: 'test-wrong-device', verificationTrace: trace() };
  assert.equal(flowSnapshot(state, 'missing').verificationTrace, null, 'a different attack cannot stand in for the selected comparison');
  delete state.manual.lastAttack;
  assert.equal(flowSnapshot(state, 'missing').verificationTrace, null);
  state.manual.lastError = { code: 'DBAC_DEVICE_LOCKED', message: 'Device is locked' };
  assert.equal(flowSnapshot(state).verificationTrace, null, 'a preparation failure cannot display an earlier normal success');
});

test('flow snapshots retain only public protocol data and remain independent of later backend state', () => {
  const secret = 'PRIVATE_VALUE_MUST_NOT_BE_SAVED';
  const state = fixture({ verificationResult: { verificationTrace: trace() },
    walletPayload: { signature: secret }, device: { publicKey: 'public-device-key', secretKey: secret },
    presentation: { Abar: 'public-Abar', privateState: { randomizer: secret } } });
  state.authorization = { token: secret };
  state.w3c.originalCredential.proof.secretKey = secret;
  const snapshot = flowSnapshot(state);
  assert.equal(JSON.stringify(snapshot).includes(secret), false);
  assert.equal(snapshot.device.publicKey, 'public-device-key');
  assert.equal(snapshot.presentation.Abar, 'public-Abar');
  state.manual.presentation.Abar = 'later-Abar';
  state.manual.verificationResult.verificationTrace.steps[0].status = 'fail';
  assert.equal(snapshot.presentation.Abar, 'public-Abar');
  assert.equal(snapshot.verificationTrace.steps[0].status, 'pass');
});

test('verification rows present all ten groups without inventing completed checks', () => {
  const groups = ['context', 'w3c', 'status', 'holder', 'binding', 'structure', 'knowledge', 'credential', 'device', 'consume'];
  const empty = verificationRows(flowSnapshot(fixture()));
  assert.deepEqual(empty.map(row => row.id), groups);
  assert.ok(empty.every(row => row.status === 'pending'));
  const complete = verificationRows(flowSnapshot(fixture({ verificationResult: { verificationTrace: trace() } })));
  assert.ok(complete.every(row => row.status === 'pass'));
  for (const row of complete) {
    assert.ok(row.ids.length > 0);
    assert.ok(row.steps.length > 0);
  }
  const fromA = trace(); fromA.source = 'agent-a';
  assert.ok(verificationRows(flowSnapshot(fixture({ verificationResult: { verificationTrace: fromA } })))
    .every(row => row.status !== 'pass'), 'local preparation cannot claim that Agent B ran its checks');
});

test('duplicates, contradictory evidence and skipped equations remain distinct from a passing check', () => {
  const observed = fixture({ verificationResult: { verificationTrace: trace([
    step('w3c_bbs'), step('w3c_bbs'),
    step('device_pairing', 'pass', [{ label: 'pairing comparison', expected: true, observed: false, match: false }]),
    step('knowledge', 'skipped'), step('credential_pairing', 'skipped'),
  ]) } });
  const rows = Object.fromEntries(verificationRows(flowSnapshot(observed)).map(row => [row.id, row]));
  assert.equal(rows.w3c.status, 'pending');
  assert.equal(rows.device.status, 'fail');
  assert.equal(rows.knowledge.status, 'skipped');
  assert.equal(rows.credential.status, 'skipped');
  assert.equal(rows.device.evidence[0].observed, false);
  assert.equal(rows.device.evidence[0].expected, true);
  assert.equal(rows.device.evidence[0].match, false);
});

test('initial navigation follows the observed credential stage without advancing the backend', () => {
  for (const [stage, expected] of [['IDLE', 'derive'], ['CHALLENGE_READY', 'derive'],
    ['VC_DERIVED', 'device'], ['DEVICE_SIGNED', 'device'], ['PROOF_READY', 'verify'], ['VERIFIED', 'verify']]) {
    const state = fixture({ stage });
    const before = structuredClone(state);
    assert.equal(initialView(state), expected, stage);
    assert.deepEqual(state, before, 'choosing an initial tab is read-only');
  }
});

test('timing expires at the exact deadline and distinguishes a saved verification from a challenge', () => {
  const state = fixture({ expiresAtUnix: 60 });
  assert.deepEqual(flowTiming(state, 59001), { expired: false, seconds: 1, kind: '本次挑战' });
  assert.deepEqual(flowTiming(state, 60000), { expired: true, seconds: 0, kind: '本次挑战' });
  state.manual.verificationResult = { verificationTrace: trace() };
  assert.deepEqual(flowTiming(state, 70000), { expired: true, seconds: 0, kind: '验证证据' });
  assert.equal(flowTiming(fixture({ expired: true, expiresAtUnix: 60 }), 0).expired, true);
  assert.equal(flowTiming(fixture({ stage: 'EXPIRED' }), 0).expired, true);
  assert.deepEqual(flowTiming(fixture(), 0), { expired: false, seconds: null, kind: '本次挑战' });
});

test('a locally expired view offers a new challenge without erasing completed observations', () => {
  const state = fixture({ stage: 'VERIFIED', expiresAtUnix: 60,
    verifiableCredential: { proof: {} }, deviceResponse: { signature: 'public' }, presentation: { proof: {} },
    verificationResult: { verificationTrace: trace() }, availableActions: ['begin-proposal', 'submit-owner', 'discard'] });
  const before = structuredClone(state);
  const action = nextFlowAction(state, 'verify', 'normal', 60000);
  assert.equal(action.id, 'begin-proposal');
  assert.match(action.label, /新挑战/);
  assert.equal(action.enabled, true);
  assert.deepEqual(flowProgress(state), {
    derive: { done: true, label: '已生成' }, device: { done: true, label: '已组合' },
    verify: { done: true, label: '已核验通过' },
  });
  assert.deepEqual(state, before, 'timing and progress never clear or replay the saved evidence');
});

test('progress separates a returned device contribution from a composed and verified proof', () => {
  const state = fixture({ stage: 'DEVICE_SIGNED', verifiableCredential: { proof: {} }, deviceResponse: { signature: 'public' } });
  assert.deepEqual(flowProgress(state), {
    derive: { done: true, label: '已生成' }, device: { done: false, label: '设备贡献已生成，待组合证明' },
    verify: { done: false, label: '尚未提交' },
  });
  state.manual.presentation = { proof: {} };
  state.manual.verificationResult = { verificationTrace: trace([step('w3c_bbs')]) };
  assert.equal(flowProgress(state).device.done, true);
  assert.deepEqual(flowProgress(state).verify, { done: false, label: '结果待核对' });
});

test('completed-stage navigation says view instead of asking to execute the step again', () => {
  const state = fixture({ stage: 'VERIFIED', verifiableCredential: { proof: {} }, deviceResponse: { signature: 'public' },
    presentation: { proof: {} }, verificationResult: { verificationTrace: trace() }, availableActions: ['submit-owner'] });
  assert.equal(nextFlowAction(state, 'derive').label, '查看设备签名材料');
  assert.equal(nextFlowAction(state, 'device').label, '查看验证记录');
  assert.equal(nextFlowAction(state, 'verify').enabled, false);
});

test('a passing proposal requires complete unique checks from Agent B and a consistent global outcome', () => {
  const state = fixture({ verificationResult: { verificationTrace: trace() } });
  assert.equal(verificationConclusion(flowSnapshot(state)).kind, 'success');
  for (const mutate of [
    s => { s.manual.phase = 'settle'; },
    s => { s.manual.verificationResult.verificationTrace.source = 'agent-a'; },
    s => { s.manual.verificationResult.verificationTrace.outcome = 'fail'; },
    s => { s.manual.verificationResult.verificationTrace.steps.pop(); },
    s => { s.manual.verificationResult.verificationTrace.steps.push(step('w3c_bbs')); },
  ]) {
    const changed = structuredClone(state); mutate(changed);
    assert.notEqual(verificationConclusion(flowSnapshot(changed)).kind, 'success');
  }
});

test('a failure outside the eight display groups cannot be hidden behind a passing summary', () => {
  for (const extra of [
    { ...step('execution', 'fail'), code: 'EXECUTION_FAILED' },
    step('owner_authorization', 'pass', [{ label: 'authorization comparison', match: false }]),
  ]) {
    const snapshot = flowSnapshot(fixture({ verificationResult: { verificationTrace: trace([...verifierIds.map(id => step(id)), extra]) } }));
    assert.ok(verificationRows(snapshot).every(row => row.status === 'pass'), 'the conflicting step is outside the grouped summary');
    assert.equal(verificationConclusion(snapshot).kind, 'failure');
  }
});

function missingSnapshot() {
  const later = new Set(['schema', 'proof_structure', 'disclosure', 'proof_encoding', 'knowledge', 'credential_pairing', 'device_pairing', 'consume']);
  const steps = verifierIds.map(id => id === 'vc_device_binding'
    ? { ...step(id, 'fail'), code: 'W3C_DEVICE_PROOF_REQUIRED' }
    : step(id, later.has(id) ? 'skipped' : 'pass'));
  return flowSnapshot(fixture({ lastAttack: { action: 'test-no-device', actual: 'W3C_DEVICE_PROOF_REQUIRED',
    verificationTrace: { ...trace(steps), outcome: 'fail' } } }), 'missing');
}

test('a specific missing-device explanation requires passed request checks and no unrelated failure', () => {
  const expected = missingSnapshot();
  assert.equal(verificationConclusion(expected).title, '使用资格验证未通过：凭证证明通过，但缺少必要的设备证明');
  for (const mutate of [
    s => { s.verificationTrace.steps.find(item => item.id === 'challenge').status = 'fail'; },
    s => { s.verificationTrace.steps.find(item => item.id === 'request_binding').evidence = [{ label: 'body hash', match: false }]; },
    s => { s.verificationTrace.steps = s.verificationTrace.steps.filter(item => item.id !== 'scope'); },
    s => { s.verificationTrace.steps.push(step('scope')); },
    s => { s.verificationTrace.steps.push(step('execution', 'fail')); },
    s => { s.verificationTrace.steps.find(item => item.id === 'device_pairing').status = 'pass'; },
  ]) {
    const changed = structuredClone(expected); mutate(changed);
    const result = verificationConclusion(changed);
    assert.notEqual(result.title, '使用资格验证未通过：凭证证明通过，但缺少必要的设备证明');
    assert.notEqual(result.kind, 'success');
  }
});

test('an unsubmitted view and an attempted request without evidence have different conclusions', () => {
  const blank = flowSnapshot(fixture());
  assert.deepEqual(verificationConclusion(blank), {
    kind: 'idle', title: '尚未提交验证', detail: '当前显示检查条件，尚无本次判定。请准备完整证明或选择缺设备对照，再提交验证。',
  });
  const lost = flowSnapshot(fixture({ lastAttack: { action: 'test-no-device', actual: 'DBAC_PAYMENT_TRANSPORT', pass: false } }), 'missing');
  assert.equal(verificationConclusion(lost).kind, 'pending');
  assert.equal(verificationConclusion(lost).title, '暂未取得验证结果');
});


test('holder proof and credential status are required before UI announces authentication pass', () => {
  for (const missing of ['holder_signature','credential_status']) {
    const incomplete=trace(verifierIds.filter(id=>id!==missing).map(id=>step(id)));
    assert.notEqual(verificationConclusion(flowSnapshot(fixture({verificationResult:{verificationTrace:incomplete}}))).kind,'success');
  }
  const revoked=trace(verifierIds.map(id=>step(id,id==='credential_status'?'fail':'pass')));revoked.outcome='fail';
  assert.equal(verificationConclusion(flowSnapshot(fixture({verificationResult:{verificationTrace:revoked}}))).kind,'failure');
});

test('holder public projection keeps compact JWS and metadata without serializing private fields',()=>{
  const state=fixture({holderProof:'public.header.signature'});state.holder={did:'did:key:holder',keyFingerprint:'public-fingerprint',storage:'holder-only',privateKey:'DO_NOT_SERIALIZE'};
  const result=flowSnapshot(state);assert.equal(result.holderProof,'public.header.signature');assert.equal(result.holder.did,'did:key:holder');assert.equal(JSON.stringify(result).includes('DO_NOT_SERIALIZE'),false);
});


test('cancelled authentication does not reuse a retained challenge for the empty card or countdown', () => {
  const state=fixture({active:false,stage:'DISCARDED',challenge:{challengeId:'retained-old-challenge'},expiresAtUnix:60,expired:true,availableActions:['begin-proposal']});
  assert.match(pendingDisclosureNote(flowSnapshot(state)),/已结束.*新挑战/);
  for(const now of [59000,70000]) {
    assert.deepEqual(flowTiming(state,now),{expired:false,seconds:null,kind:'本次挑战'});
    assert.equal(nextFlowAction(state,'derive','normal',now).label,'获取 B 的本次挑战');
  }
  const active=fixture({challenge:{challengeId:'new-challenge'}});
  assert.match(pendingDisclosureNote(flowSnapshot(active)),/已收到 B 的挑战/);
});


test('live rejection overrides a retryable proof-ready banner but never leaks into a new attempt', () => {
  const denied={source:'agent-b',outcome:'fail',steps:[{...step('credential_status','fail'),code:'W3C_CREDENTIAL_REVOKED'}]};
  const state=fixture({stage:'PROOF_READY',presentation:{proof:{}},lastError:{code:'W3C_CREDENTIAL_REVOKED',verificationTrace:denied},availableActions:['verify','begin-proposal','discard']});
  const before=structuredClone(state);
  assert.equal(currentRejectionNotice(state).title,'本次凭证使用资格验证未通过');
  assert.match(currentRejectionNotice(state).detail,/拒绝依据.*新挑战/);
  assert.equal(nextFlowAction(state,'verify').id,'verify','display does not change backend retry semantics');
  assert.deepEqual(state,before);
  const next=fixture({attemptId:'new-attempt',stage:'CHALLENGE_READY'});next.lastResult={verificationTrace:denied};
  assert.equal(currentRejectionNotice(next),null,'historical order result cannot label a new challenge rejected');
  assert.equal(currentRejectionNotice({...state,manual:{...state.manual,active:false,stage:'DISCARDED'}}),null);
  assert.equal(currentRejectionNotice(fixture({lastError:{code:'NETWORK_ERROR'}})),null,'transport failure is not a B rejection');
});
