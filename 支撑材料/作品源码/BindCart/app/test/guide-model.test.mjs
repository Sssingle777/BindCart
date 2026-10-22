import test from 'node:test';
import assert from 'node:assert/strict';
import { planPayment, verificationSummary, verificationVerdict, paymentMilestones, currentVerificationCompletion } from '../public/guide-model.js';

const now = Date.parse('2026-10-10T12:00:00.000Z');
const ids = ['w3c_bbs', 'credential_status', 'holder_signature', 'vc_device_binding', 'extension', 'envelope',
  'challenge', 'replay', 'request_binding', 'policy_context', 'scope', 'schema', 'proof_structure', 'disclosure',
  'proof_encoding', 'knowledge', 'credential_pairing', 'device_pairing', 'owner_authorization', 'task_binding',
  'consume', 'settlement_gate', 'execution'];
function trace(phase = 'proposal', { orderId = 'current-order', bindingId = 'binding-current', mode = 'bbs-bls' } = {}) {
  const unused = phase === 'proposal' ? ['owner_authorization', 'task_binding', 'settlement_gate'] : phase === 'authorize' ? ['task_binding', 'settlement_gate'] : [];
  return { profile: 'dbac-payment', source: 'agent-b', outcome: 'pass', steps: ids.map(id => ({
    id, title: id, status: unused.includes(id) ? 'skipped' : 'pass',
    ...(id === 'scope' ? { evidence: [{ label: 'method / scope / phase', observed: ['message/send', 'payments:pay', phase] },
      { label: 'payment order ID', expected: orderId, observed: orderId }] } : {}),
    ...(id === 'vc_device_binding' ? { evidence: [{ label: 'bindingId / mode / device contribution', expected: [bindingId, mode, true], observed: [bindingId, mode, true] }] } : {}),
  })) };
}
function fixture(manual = {}, fields = {}) {
  return {
    available: true, mode: 'bbs-bls', credential: { suite: 'public-suite' }, credentialStatus: { status: 'valid', available: true },
    order: { orderId: 'current-order', amountMinor: 2990000, currency: 'TEST_USDC', payerAccount: 'a', payeeAccount: 'b',
      settlement: { network: 'eip155:1337', asset: 'test-token', payerAddress: '0xa', payTo: '0xb' } },
    w3c: { enabled: true, originalCredential: { validFrom: '2026-10-10T00:00:00Z', validUntil: '2026-10-11T00:00:00Z', credentialSubject: subject() },
      disclosedPaths: Object.keys(subject()).map(key => `/credentialSubject/${key}`), hiddenPaths: ['/credentialSubject/organization', '/credentialSubject/holderLabel'] },
    owner: { available: true },
    manual: { active: true, phase: 'proposal', stage: 'CHALLENGE_READY', expiresAtUnix: now / 1000 + 60,
      availableActions: ['derive-vc', 'discard', 'begin-proposal'], ...manual }, ...fields,
  };
}
const plan = (state, options = {}) => planPayment(state, { now, ...options });
const subject = () => ({ role: 'authorized-agent', scope: 'payments:pay', epoch: '2026-10-10', mode: 'bbs-bls', bindingId: 'binding-current', holderDid: 'did:key:holder-current' });
const phaseResult = phase => ({ phase, accepted: true, verificationTrace: trace(phase), wire: { proof: { verifiableCredential: { credentialSubject: subject() } } } });
const phaseLog = (phase, credentialSubject = subject(), verificationTrace = trace(phase)) => [
  { from: 'agent-a', action: 'verify', status: 'sent', data: { body: { params: { message: { parts: [{ data: { phase, payment: { orderId: 'current-order' } } }] } } }, verifiableCredential: { credentialSubject } } },
  { from: 'agent-b', action: 'verify', status: 'received', data: { verificationTrace } },
];
const withReceipt = state => ({ ...state, lastResult: { phase: 'settle', paymentResult: { outcome: 'EXECUTED', receipt: structuredClone(state.order) } } });

test('the normal payment guide follows real stages without requesting two steps at once', () => {
  for (const phase of ['proposal', 'authorize', 'settle']) {
    const extras = phase === 'proposal' ? {} : { proposal: { status: 'APPROVED' }, authorization: { id: 'auth' } };
    for (const [stage, id] of [['CHALLENGE_READY', 'derive-vc'], ['VC_DERIVED', 'device-sign'], ['DEVICE_SIGNED', 'prove'], ['PROOF_READY', 'verify']]) {
      const value = plan(fixture({ phase, stage, walletSigned: phase === 'settle', availableActions: [id, `begin-${phase}`, 'discard'] }, extras));
      assert.equal(value.id, id, `${phase}/${stage}`); assert.equal(value.enabled, true);
      assert.ok(value.label && value.description); assert.ok(['prepare', 'request', 'proof', 'result'].includes(value.step));
    }
  }
  assert.equal(plan(fixture({ stage: 'VERIFIED', verificationResult: phaseResult('proposal'), availableActions: ['submit-owner'] })).id, 'submit-owner');
  assert.equal(plan(fixture({ phase: 'authorize', stage: 'VERIFIED', verificationResult: phaseResult('authorize'), availableActions: ['wallet-sign'] }, { proposal: { status: 'APPROVED' }, authorization: {} })).id, 'wallet-sign');
});
test('manual mutations are never enabled when the backend did not offer them', () => {
  for (const [stage, id] of [['CHALLENGE_READY', 'derive-vc'], ['VC_DERIVED', 'device-sign'], ['DEVICE_SIGNED', 'prove'], ['PROOF_READY', 'verify']]) {
    const value = plan(fixture({ stage, availableActions: [] })); assert.equal(value.id, id); assert.equal(value.enabled, false);
  }
  assert.equal(plan(fixture({ active: false, stage: 'IDLE', availableActions: [] })).enabled, false);
  assert.equal(plan(fixture({ stage: 'VERIFIED', verificationResult: phaseResult('proposal'), availableActions: [] })).enabled, false);
});
test('expiration restarts only the current phase and never reuses the expired proof', () => {
  for (const phase of ['proposal', 'authorize', 'settle']) for (const timing of [{ expiresAtUnix: now / 1000 }, { expired: true }, { stage: 'EXPIRED' }]) {
    const value = plan(fixture({ phase, stage: 'PROOF_READY', walletSigned: phase === 'settle', availableActions: [`begin-${phase}`, 'verify'], ...timing }));
    assert.equal(value.id, `begin-${phase}`); assert.equal(value.enabled, true);
  }
  const value = plan(fixture({ expired: true, phase: 'authorize', availableActions: ['begin-proposal'] }));
  assert.equal(value.id, 'begin-authorize'); assert.equal(value.enabled, false);
});
test('wallet uncertainty and absent credentials cannot cause a new order or repeated signing', () => {
  for (const state of [
    fixture({ walletSigningUnconfirmed: true, availableActions: ['wallet-sign', 'begin-authorize'] }),
    fixture({ active: false }, { paymentPending: true, credential: null }),
    fixture({ walletSigned: true, active: false }, { credential: null }),
    fixture({ active: false }, { credential: null, proposal: { status: 'PENDING' } }),
  ]) { const value = plan(state); assert.equal(value.id, 'refresh'); assert.equal(value.enabled, true); }
  assert.equal(plan(fixture({ active: false, stage: 'IDLE' }, { credential: null })).id, 'issue');
});
test('signed original orders resume settlement even after discard or while other actions are offered', () => {
  const value = plan(fixture({ active: false, phase: 'authorize', stage: 'DISCARDED', walletSigned: true,
    availableActions: ['begin-authorize', 'begin-proposal', 'begin-settle'] }, { paymentPending: true }));
  assert.equal(value.id, 'begin-settle'); assert.equal(value.enabled, true);
  assert.equal(plan(fixture({ walletSigned: true, availableActions: ['begin-authorize'] })).enabled, false);
});
test('Owner decisions require separate capability, synchronization and explicit restart', () => {
  const pending = fixture({ stage: 'OWNER_SUBMITTED', expiresAtUnix: null, availableActions: ['sync-owner', 'discard'] }, { proposal: { status: 'PENDING' } });
  assert.equal(plan(pending).id, 'owner-review'); assert.equal(plan(pending).enabled, false);
  assert.equal(plan(pending, { ownerAvailable: true }).enabled, true);
  assert.equal(plan({ ...pending, owner: { available: false } }, { ownerAvailable: true }).enabled, false);
  assert.equal(plan({ ...pending, proposal: { status: 'APPROVED' } }).id, 'sync-owner');
  assert.equal(plan(fixture({ stage: 'OWNER_SUBMITTED', expiresAtUnix: null, availableActions: ['begin-authorize'] }, { proposal: { status: 'APPROVED' }, authorization: {} })).id, 'begin-authorize');
  for (const status of ['REJECTED', 'EXPIRED']) {
    assert.equal(plan({ ...pending, proposal: { status } }).id, 'discard');
    assert.equal(plan({ ...pending, manual: { ...pending.manual, active: false }, proposal: { status } }).id, 'new');
  }
});
test('revoked, unknown, not-yet-valid and expired VC block normal payment progress', () => {
  const cases = [
    { credentialStatus: { status: 'revoked' } }, { credentialStatus: { status: 'unknown', available: false } },
    { w3c: { originalCredential: { validUntil: new Date(now).toISOString() } } },
    { w3c: { originalCredential: { validFrom: new Date(now + 1).toISOString() } } },
  ];
  for (const values of cases) { const value = plan(fixture({ walletSigned: true, availableActions: ['begin-settle'] }, values)); assert.equal(value.id, 'refresh'); assert.ok(value.reason.includes('原订单')); }
});
test('completion requires matching order terms and never accepts an old or mismatched receipt', () => {
  const state = withReceipt(fixture({ settled: true, availableActions: ['discard'] }));
  assert.equal(plan(state).id, 'discard');
  assert.equal(plan({ ...state, manual: { ...state.manual, active: false } }).id, 'new');
  for (const mutate of [r => r.orderId = 'old-order', r => r.amountMinor++, r => r.settlement.payTo = '0xwrong']) {
    const wrong = structuredClone(state); mutate(wrong.lastResult.paymentResult.receipt);
    assert.equal(plan(wrong).id, 'refresh'); assert.equal(paymentMilestones(wrong).find(r => r.id === 'settle').status, 'pending');
  }
  const uncertain = withReceipt(fixture({ walletSigningUnconfirmed: true, availableActions: ['discard'] }));
  assert.equal(plan(uncertain).id, 'refresh');
});
test('grouped evidence never turns missing, duplicate or mixed skipped steps into pass', () => {
  const full = trace(); assert.deepEqual(verificationSummary(full).map(row => row.status), ['pass', 'pass', 'pass', 'pass']);
  for (const change of [
    t => t.steps = t.steps.filter(step => step.id !== 'device_pairing'),
    t => t.steps.push(structuredClone(t.steps.find(step => step.id === 'device_pairing'))),
    t => t.steps.find(step => step.id === 'device_pairing').status = 'skipped',
  ]) { const t = trace(); change(t); assert.equal(verificationSummary(t).find(row => row.id === 'participation').status, 'pending'); assert.equal(verificationVerdict(t, { phase: 'proposal' }).status, 'pending'); }
  const unrun = trace(); unrun.steps.forEach(step => step.status = 'skipped');
  assert.ok(verificationSummary(unrun).every(row => row.status === 'skipped'));
  assert.equal(verificationVerdict(unrun, { phase: 'proposal' }).status, 'pending');
});
test('false evidence and backend failures take priority over a pass outcome', () => {
  const t = trace(); t.steps.find(step => step.id === 'holder_signature').evidence = [{ match: false }];
  assert.equal(verificationSummary(t).find(row => row.id === 'participation').status, 'fail');
  assert.equal(verificationVerdict(t, { phase: 'proposal' }).status, 'fail');
  const state = fixture({ stage: 'VERIFIED', verificationResult: { verificationTrace: t }, availableActions: ['submit-owner'] });
  assert.equal(plan(state).id, 'refresh');
});
test('a verdict requires verifier source, correct profile and explicit matching phase', () => {
  assert.equal(verificationVerdict(trace()).status, 'pending');
  assert.equal(verificationVerdict(trace('authorize'), { phase: 'proposal' }).status, 'pending');
  assert.equal(verificationVerdict({ ...trace(), source: 'agent-a' }, { phase: 'proposal' }).status, 'pending');
  assert.equal(verificationVerdict({ ...trace(), profile: 'dbac' }, { phase: 'proposal' }).status, 'pending');
  assert.equal(verificationVerdict({ ...trace(), outcome: 'fail' }, { phase: 'proposal' }).status, 'pending');
  for (const phase of ['proposal', 'authorize', 'settle']) assert.equal(verificationVerdict(trace(phase), { phase }).status, 'pass');
  const earlyGate = trace('settle'); earlyGate.steps.find(step => step.id === 'execution').status = 'skipped';
  assert.equal(verificationVerdict(earlyGate, { phase: 'settle' }).status, 'pending');
  const malformed = trace(); malformed.steps.push({ id: 'unconfirmed', status: 'pending', evidence: {} });
  assert.equal(verificationVerdict(malformed, { phase: 'proposal' }).status, 'pending');
});
test('milestones use real phase records and never infer payment from authorization or wallet signing', () => {
  const state = fixture({ phase: 'authorize', stage: 'WALLET_SIGNED', walletSigned: true, expiresAtUnix: null,
    log: phaseLog('proposal'),
    verificationResult: phaseResult('authorize') }, { proposal: { status: 'APPROVED' }, authorization: {} });
  const rows = paymentMilestones(state); assert.deepEqual(rows.map(row => row.id), ['prepare', 'qualification', 'owner', 'authorize', 'wallet', 'settle']);
  assert.deepEqual(rows.map(row => row.status), ['pass', 'pass', 'pass', 'pass', 'pass', 'pending']);
  const noTrace = paymentMilestones(fixture({ phase: 'authorize', walletSigned: true }, { proposal: { status: 'APPROVED' }, authorization: {} }));
  assert.equal(noTrace.find(row => row.id === 'qualification').status, 'pending');
  assert.equal(noTrace.find(row => row.id === 'authorize').status, 'pending');
  assert.equal(paymentMilestones(withReceipt(state)).find(row => row.id === 'settle').status, 'pass');
  const denied = trace('authorize'); denied.outcome = 'fail'; denied.steps.find(step => step.id === 'credential_status').status = 'fail';
  const currentFailure = paymentMilestones({ ...state, manual: { ...state.manual, lastError: { verificationTrace: denied } } });
  assert.equal(currentFailure.find(row => row.id === 'authorize').status, 'fail');
});

test('milestones keep valid prior-stage records without borrowing a previous credential or order', () => {
  const current = fixture({ phase: 'authorize', stage: 'CHALLENGE_READY', log: phaseLog('proposal') });
  assert.equal(paymentMilestones(current).find(row => row.id === 'qualification').status, 'pass', 'new authorize challenge preserves this order and credential qualification');
  for (const change of [
    state => state.w3c.originalCredential.credentialSubject.bindingId = 'binding-newly-issued',
    state => state.w3c.originalCredential.credentialSubject.holderDid = 'did:key:new-holder',
    state => state.order.orderId = 'next-order',
    state => state.mode = 'bbs-blind-bls',
  ]) {
    const changed = structuredClone(current); change(changed);
    assert.equal(paymentMilestones(changed).find(row => row.id === 'qualification').status, 'pending');
  }
  assert.deepEqual(current.manual.log, phaseLog('proposal'), 'historical records stay intact');
});

test('changing optional disclosure cannot inherit qualification from the previous disclosure policy', () => {
  const current = fixture({ active: false, stage: 'DISCARDED', log: phaseLog('proposal') });
  current.w3c.originalCredential.credentialSubject.organization = 'local-organization';
  current.w3c.disclosedPaths.push('/credentialSubject/organization');
  current.w3c.hiddenPaths = ['/credentialSubject/holderLabel'];
  assert.equal(paymentMilestones(current).find(row => row.id === 'qualification').status, 'pending');
  current.manual.log.push(...phaseLog('proposal', { ...subject(), organization: 'local-organization' }));
  assert.equal(paymentMilestones(current).find(row => row.id === 'qualification').status, 'pass');
  current.w3c.disclosedPaths = current.w3c.disclosedPaths.filter(path => !path.endsWith('/organization'));
  current.w3c.hiddenPaths.push('/credentialSubject/organization');
  assert.equal(paymentMilestones(current).find(row => row.id === 'qualification').status, 'pending', 'reverting policy cannot resurrect an older pass over the latest different-policy request');
});

test('incomplete history cannot announce a current credential qualification pass', () => {
  for (const log of [phaseLog('proposal').slice(1), phaseLog('proposal', undefined, trace('proposal', { bindingId: 'other-binding' }))]) {
    assert.equal(paymentMilestones(fixture({ log })).find(row => row.id === 'qualification').status, 'pending');
  }
});


for(const phase of ['proposal','authorize'])test(`${phase} completion remains visible only with current matching verifier evidence`,()=>{
  const valid=()=>fixture({phase,stage:'VERIFIED',verificationResult:{...phaseResult(phase),mode:'bbs-bls'}});
  const value=currentVerificationCompletion(valid(),{now});
  assert.ok(value);assert.match(value.title,/验证者 B/);assert.match(value.detail,/尚未付款/);
  const changes=[
    state=>state.order.orderId='other-order',
    state=>state.w3c.originalCredential.credentialSubject.bindingId='other-binding',
    state=>state.mode='bbs-blind-bls',
    state=>state.manual.verificationResult.phase=phase==='proposal'?'authorize':'proposal',
    state=>state.manual.expiresAtUnix=now/1000,
    state=>state.credentialStatus.status='revoked',
    state=>state.w3c.disclosedPaths.push('/credentialSubject/organization'),
    state=>state.manual.verificationResult.verificationTrace.steps.find(step=>step.id==='device_pairing').status='skipped',
    state=>state.manual.verificationResult.accepted=false,
    state=>{state.manual.challenge={challengeId:'new-challenge'};state.manual.verificationResult.wire.context={challengeId:'old-challenge'};},
    state=>state.manual.sentCredential={credentialSubject:{...subject(),bindingId:'old-binding'}},
  ];
  for(const change of changes){const state=valid();change(state);assert.equal(currentVerificationCompletion(state,{now}),null);}
  assert.equal(currentVerificationCompletion(valid(),{now,uncertain:true}),null);
});
