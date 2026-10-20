import test from 'node:test';
import assert from 'node:assert/strict';
import { createHistory } from '../public/credential-flow-history.js';

const START = Date.parse('2026-10-09T01:00:00.000Z');
const step = (id, status = 'pass') => ({ id, actor: 'agent-b', title: id, status, evidence: [] });
const goodTrace = () => ({ profile: 'dbac-payment', source: 'agent-b', outcome: 'pass',
  steps: [step('w3c_bbs'), step('vc_device_binding'), step('knowledge'), step('credential_pairing'), step('device_pairing')] });
const badTrace = () => ({ profile: 'dbac-payment', source: 'agent-b', outcome: 'fail',
  steps: [step('w3c_bbs'), step('vc_device_binding', 'fail'), step('knowledge', 'skipped')] });
function fixture({ mode = 'bbs-bls', orderId = 'order-1', bindingId = 'binding-1', attemptId = 'attempt-1',
  challengeId = 'challenge-1', digest = 'H'.repeat(43) } = {}) {
  const derived = { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential'],
    issuer: 'did:example:issuer', credentialSubject: { role: 'payer', scope: 'payments:pay', epoch: '2026-10-09', mode, bindingId },
    proof: { type: 'DataIntegrityProof', cryptosuite: 'bbs-2023', proofValue: 'u' + 'P'.repeat(512) } };
  const challenge = { mode, paymentOrderId: orderId, challengeId, bodyHash: 'B'.repeat(43), nonce: 'nonce', iat: 1, exp: 2 };
  const state = { available: true, mode, order: { orderId },
    w3c: { originalCredential: { ...structuredClone(derived), credentialSubject: { ...derived.credentialSubject,
      organization: 'Hidden organization', holderLabel: 'Hidden holder' } } },
    credential: { attributes: [{ name: 'organization', value: 'Hidden organization' }] },
    manual: { phase: 'proposal', active: true, stage: 'VERIFIED', expired: false, attemptId,
      verifiableCredential: derived, sentCredential: structuredClone(derived), challenge,
      cryptography: { presentationHeader: 'ab'.repeat(128), w3cPresentationHash: digest },
      deviceRequest: { mode, randomizedDevicePublicKey: 'public-randomized', context: { ...challenge, w3cPresentationHash: digest } },
      deviceResponse: { mode, signature: 'public-device-contribution' },
      device: { publicKey: 'long-term-device-key', secretKey: 'secret-device-key' },
      presentation: { mode, Abar: 'public-Abar', deviceSignature: 'public-adapted-signature', proof: { challenge: 'public-fiat-shamir' } },
      verificationResult: { verificationTrace: goodTrace() }, log: [] } };
  state.manual.log = [
    { action: 'begin-proposal', status: 'received', time: new Date(START).toISOString(), data: structuredClone(challenge) },
    { action: 'verify', status: 'received', time: new Date(START + 1000).toISOString(),
      data: { verificationTrace: structuredClone(state.manual.verificationResult.verificationTrace) } },
  ];
  return state;
}
function missing(state) {
  state.manual.verificationResult = null;
  state.manual.lastAttack = { action: 'test-no-device', actual: 'W3C_DEVICE_PROOF_REQUIRED',
    verificationTrace: badTrace(), error: { code: 'W3C_DEVICE_PROOF_REQUIRED', message: 'Device proof is required' } };
  state.manual.log.push({ action: 'test-no-device', status: 'rejected-as-expected', time: new Date(START + 2000).toISOString(),
    data: structuredClone(state.manual.lastAttack) });
  return state;
}

test('one round retains independent negative and normal results after the backend clears lastAttack', () => {
  const history = createHistory(), state = missing(fixture());
  history.capture(state, START + 10000);
  assert.equal(history.current(state).records.missing.snapshot.presentation, null);
  delete state.manual.lastAttack;
  state.manual.stage = 'DEVICE_SIGNED'; history.capture(state, START + 20000);
  state.manual.stage = 'PROOF_READY'; history.capture(state, START + 30000);
  assert.equal(history.current(state).records.missing.snapshot.verificationTrace.outcome, 'fail');
  assert.equal(history.current(state).records.normal, undefined);
  state.manual.stage = 'VERIFIED'; state.manual.verificationResult = { verificationTrace: goodTrace() };
  history.capture(state, START + 40000);
  const round = history.current(state);
  assert.equal(round.records.normal.snapshot.verificationTrace.outcome, 'pass');
  assert.equal(round.records.missing.snapshot.verificationTrace.outcome, 'fail');
  assert.equal(createHistory(history.serialize()).current(state).records.missing.snapshot.presentation, null);
});

test('identity separates attempts, modes, orders, bindings, challenges and derived hashes', () => {
  const history = createHistory(), first = fixture(); history.capture(first, START);
  const firstKey = history.current(first).key;
  for (const changes of [{ attemptId: 'attempt-2' }, { mode: 'bbs-blind-bls' }, { orderId: 'order-2' },
    { bindingId: 'binding-2' }, { challengeId: 'challenge-2' }, { digest: 'X'.repeat(43) }]) {
    const state = fixture(changes);
    assert.equal(history.current(state), null, 'a different identity has no current historical result');
    history.capture(state, START + 100);
    assert.notEqual(history.current(state).key, firstKey);
  }
  assert.equal(history.rounds(first).length, 4, 'only the same mode, order and binding are listed across attempts');
  assert.equal(history.rounds(fixture({ mode: 'bbs-blind-bls' })).length, 1);
  assert.equal(history.rounds(fixture({ orderId: 'order-2' })).length, 1);
  assert.equal(history.current(first).challengeId, 'challenge-1');
  assert.equal(history.current(first).w3cPresentationHash, 'H'.repeat(43));
});

test('current challenge-anchored backend result time remains unchanged by refresh and expiry', () => {
  const history = createHistory(), state = fixture();
  state.manual.expiresAtUnix = START / 1000 + 300;
  history.capture(state, START + 20000);
  const before = history.current(state).records.normal;
  assert.equal(before.timestampSource, 'backend');
  assert.equal(before.recordedAt, new Date(START + 1000).toISOString());
  state.manual.expired = true; state.manual.stage = 'EXPIRED';
  history.capture(state, START + 80000);
  assert.deepEqual(history.current(state).records.normal, before);
  const restored = createHistory(history.serialize());
  restored.capture(state, START + 90000);
  assert.deepEqual(restored.current(state).records.normal, before);
  assert.equal(restored.current(state).records.normal.snapshot.expiresAtUnix, START / 1000 + 300);
});

test('later device and proof observations cannot rewrite the missing-device snapshot or its first time', () => {
  const history = createHistory(), state = missing(fixture());
  state.manual.deviceResponse = null; state.manual.presentation = null;
  history.capture(state, START + 10000);
  const before = history.current(state).records.missing;
  state.manual.stage = 'DEVICE_SIGNED'; state.manual.deviceResponse = { mode: state.mode, signature: 'new-device-response' };
  history.capture(state, START + 20000);
  state.manual.stage = 'PROOF_READY'; state.manual.presentation = { mode: state.mode, Abar: 'new-proof' };
  history.capture(state, START + 30000);
  state.manual.verificationResult = { verificationTrace: goodTrace() };
  history.capture(state, START + 40000);
  assert.deepEqual(history.current(state).records.missing, before);
  assert.equal(history.current(state).records.missing.snapshot.deviceResponse, null);
  assert.equal(history.current(state).records.missing.snapshot.presentation, null);
});

test('missing or unrelated log times use the first observation and never import an old log result', () => {
  const history = createHistory(), state = fixture({ attemptId: 'attempt-new', challengeId: 'challenge-new' });
  state.manual.log = fixture().manual.log;
  const result = state.manual.verificationResult;
  state.manual.verificationResult = null;
  history.capture(state, START + 3000);
  assert.equal(history.current(state), null, 'old successful logs cannot become a new attempt result');
  state.manual.verificationResult = result;
  history.capture(state, START + 4000);
  assert.equal(history.current(state).records.normal.timestampSource, 'observed');
  assert.equal(history.current(state).records.normal.recordedAt, new Date(START + 4000).toISOString());
  history.capture(state, START + 9999);
  assert.equal(history.current(state).records.normal.recordedAt, new Date(START + 4000).toISOString());
});

test('a new B rejection replaces normal success while a transport failure creates no successful observation', () => {
  const history = createHistory(), state = fixture(); history.capture(state, START);
  state.manual.lastError = { code: 'DBAC_PROOF_INVALID', message: 'Proof was rejected', verificationTrace: badTrace() };
  history.capture(state, START + 3000);
  assert.equal(history.current(state).records.normal.snapshot.verificationTrace.outcome, 'fail');
  assert.equal(history.current(state).records.normal.snapshot.error.code, 'DBAC_PROOF_INVALID');
  state.manual.lastError = { code: 'DBAC_PAYMENT_TRANSPORT', message: 'Response unavailable' };
  const before = history.serialize(); history.capture(state, START + 4000);
  assert.equal(history.serialize(), before, 'communication uncertainty must not select verificationResult containing an older success');
  assert.equal(createHistory().capture(state, START + 4000), null);
});

test('non-B traces, other attacks, non-proposal phases and incomplete or contradictory identities are not saved', () => {
  const mutations = [
    s => { s.manual.verificationResult.verificationTrace.source = 'agent-a'; },
    s => { s.manual.phase = 'settle'; },
    s => { s.manual.attemptId = null; },
    s => { delete s.manual.challenge.challengeId; },
    s => { s.manual.challenge.paymentOrderId = 'other'; },
    s => { s.manual.cryptography.w3cPresentationHash = null; },
    s => { s.manual.deviceRequest.context.w3cPresentationHash = 'Z'.repeat(43); },
    s => { s.manual.verifiableCredential.credentialSubject.bindingId = 'other'; },
    s => { s.manual.sentCredential.proof.proofValue = 'different-derived-proof'; },
    s => { s.manual.deviceResponse.mode = 'bbs-blind-bls'; },
    s => { s.manual.verificationResult = null; s.manual.lastAttack = { action: 'test-wrong-device', verificationTrace: badTrace() }; },
  ];
  for (const mutate of mutations) {
    const state = fixture(), history = createHistory(); mutate(state); history.capture(state, START);
    assert.deepEqual(history.rounds(state), []);
  }
});

test('saved and restored snapshots strip original VC, hidden declarations, long-term keys, tokens and unknown nested data', () => {
  const secret = 'PRIVATE_MATERIAL_MUST_NOT_BE_PERSISTED', state = fixture();
  state.authorization = { token: secret }; state.manual.walletPayload = { signature: secret };
  state.manual.presentation.privateWitness = secret;
  state.manual.verifiableCredential.credentialSubject.organization = secret;
  state.manual.sentCredential.credentialSubject.holderLabel = secret;
  const history = createHistory(); history.capture(state, START);
  assert.equal(history.serialize().includes(secret), false);
  assert.equal(history.serialize().includes('Hidden organization'), false);
  assert.equal(history.serialize().includes('long-term-device-key'), false);
  const input = JSON.parse(history.serialize()), snapshot = input.rounds[0].records.normal.snapshot;
  snapshot.originalCredential = { credentialSubject: { organization: secret } };
  snapshot.credential = { attributes: [{ value: secret }] }; snapshot.device = { publicKey: secret };
  snapshot.authorization = { token: secret }; snapshot.deviceResponse.secretKey = secret;
  snapshot.derivedCredential.credentialSubject.organization = secret;
  snapshot.derivedCredential.proof.privateWitness = secret;
  snapshot.presentation.proof.privateRandomizer = secret;
  snapshot.verificationTrace.steps[0].private = secret;
  input.rounds[0].records.normal.fingerprint = secret;
  const restored = createHistory(JSON.stringify(input));
  assert.ok(restored.current(state));
  assert.equal(restored.serialize().includes(secret), false);
  const clean = restored.current(state).records.normal.snapshot;
  for (const key of ['originalCredential', 'credential', 'device', 'authorization', 'walletPayload']) assert.equal(Object.hasOwn(clean, key), false);
  assert.equal(clean.derivedCredential.proof.proofValue, state.manual.verifiableCredential.proof.proofValue);
  assert.equal(clean.presentation.Abar, 'public-Abar');
  assert.equal(clean.challenge.challengeId, 'challenge-1');
});

test('restore rejects invalid group identities, times, trace sources and malformed structures', () => {
  const state = fixture(), history = createHistory(); history.capture(state, START);
  for (const mutate of [
    input => { input.rounds[0].attemptId = 'other-attempt'; },
    input => { input.rounds[0].key = 'fake-key'; },
    input => { input.rounds[0].records.normal.recordedAt = 'not-a-date'; },
    input => { input.rounds[0].records.normal.timestampSource = 'invented'; },
    input => { input.rounds[0].records.normal.snapshot.expiresAtUnix = 'not-a-number'; },
    input => { input.rounds[0].records.normal.snapshot.verificationTrace.source = 'agent-a'; },
    input => { input.rounds[0].records.normal.snapshot.derivedCredential = null; },
    input => { input.rounds[0].records.normal.snapshot.cryptography.w3cPresentationHash = 'bad-hash'; },
  ]) {
    const input = JSON.parse(history.serialize()); mutate(input);
    assert.equal(createHistory(JSON.stringify(input)).current(state), null);
  }
});

test('empty, bad and oversized JSON are safely ignored, and history is limited to eight newest rounds', () => {
  for (const value of [null, '', '{', 'null', '[]', '{}', JSON.stringify({ version: 99, rounds: [] }), ' '.repeat(1024 * 1024 + 1)]) {
    const history = createHistory(value);
    assert.deepEqual(history.rounds(fixture()), []);
    assert.equal(history.find('unknown', 'normal'), null);
  }
  const history = createHistory();
  for (let index = 0; index < 10; index++) {
    const state = fixture({ attemptId: `attempt-${index}`, challengeId: `challenge-${index}` });
    state.manual.log = []; history.capture(state, START + index * 1000);
  }
  const rounds = history.rounds(fixture());
  assert.equal(rounds.length, 8); assert.equal(rounds[0].attemptId, 'attempt-9');
  assert.equal(rounds.at(-1).attemptId, 'attempt-2');
  assert.equal(createHistory(history.serialize()).rounds(fixture()).length, 8);
});

test('returned snapshots and records cannot mutate the stored historical observation', () => {
  const state = fixture(), history = createHistory(); history.capture(state, START);
  const key = history.current(state).key;
  state.manual.presentation.Abar = 'later-live-value';
  history.find(key, 'normal').snapshot.presentation.Abar = 'caller-mutation';
  history.current(state).records.normal.snapshot.verificationTrace.outcome = 'caller-mutation';
  history.rounds(state)[0].records.normal.recordedAt = 'caller-mutation';
  assert.equal(history.find(key, 'normal').snapshot.presentation.Abar, 'public-Abar');
  assert.equal(history.find(key, 'normal').snapshot.verificationTrace.outcome, 'pass');
  assert.equal(history.find(key, 'unknown'), null);
});

test('large but individually bounded results cannot produce storage that its own restore rejects', () => {
  const history = createHistory();
  let state;
  for (let index = 0; index < 8; index++) {
    state = fixture({ attemptId: `large-${index}`, challengeId: `large-${index}` });
    state.manual.log = [];
    state.manual.cryptography.presentationHeader = 'a'.repeat(32768);
    state.manual.verifiableCredential.proof.proofValue = 'p'.repeat(8192);
    state.manual.sentCredential = structuredClone(state.manual.verifiableCredential);
    history.capture(state, START + index * 1000);
    missing(state); state.manual.log = [];
    history.capture(state, START + index * 1000 + 1);
  }
  const serialized = history.serialize();
  assert.ok(serialized.length <= 1024 * 1024);
  assert.ok(history.rounds(state).length > 0);
  assert.deepEqual(createHistory(serialized).current(state), history.current(state));
});

test('restore reapplies the total size limit after rebuilding untrusted fingerprints', () => {
  const rounds = [];
  let state;
  for (let index = 0; index < 8; index++) {
    const partial = createHistory();
    state = fixture({ attemptId: `restored-${index}`, challengeId: `restored-${index}` });
    state.manual.cryptography.presentationHeader = 'a'.repeat(32768);
    state.manual.verifiableCredential.proof.proofValue = 'p'.repeat(8192);
    state.manual.sentCredential = structuredClone(state.manual.verifiableCredential);
    state.manual.log = []; partial.capture(state, START + index * 1000);
    missing(state); state.manual.log = []; partial.capture(state, START + index * 1000 + 1);
    const round = JSON.parse(partial.serialize()).rounds[0];
    for (const record of Object.values(round.records)) record.fingerprint = '';
    rounds.push(round);
  }
  const input = JSON.stringify({ version: 1, rounds });
  assert.ok(input.length <= 1024 * 1024, 'the untrusted input itself fits within the read limit');
  const restored = createHistory(input), serialized = restored.serialize();
  assert.ok(serialized.length <= 1024 * 1024, 'recomputed fingerprints cannot expand storage beyond its limit');
  assert.ok(restored.rounds(state).length > 0 && restored.rounds(state).length < 8);
  assert.ok(restored.current(state), 'the newest round remains available after oldest-round eviction');
  assert.deepEqual(createHistory(serialized).current(state), restored.current(state));
});
