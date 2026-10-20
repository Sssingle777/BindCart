import { flowSnapshot } from './credential-flow-model.js';

// A bounded, public display history, not an authorization or verification cache.
const VERSION = 1, MAX_ROUNDS = 8, MAX_SERIALIZED = 1024 * 1024, MAX_RECORD = 64 * 1024;
const MODES = ['bbs-bls', 'bbs-blind-bls'], SCENARIOS = ['normal', 'missing'];
const SUBJECT_KEYS = ['role', 'scope', 'epoch', 'mode', 'bindingId'];
const SNAPSHOT_KEYS = ['mode', 'orderId', 'bindingId', 'phase', 'stage', 'attemptId', 'active', 'expired', 'expiresAtUnix',
  'derivedCredential', 'sentCredential', 'cryptography', 'challenge', 'deviceRequest', 'deviceResponse',
  'presentation', 'verificationTrace', 'error', 'scenario', 'submitted', 'attackCode'];
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const identifier = value => typeof value === 'string' && value.length > 0 && value.length <= 256;
const hash = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
const clone = value => value == null ? value : structuredClone(value);
function iso(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) return null;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value ? value : null;
}
function bounded(value, depth = 0, budget = { left: 6000 }) {
  if (--budget.left < 0 || depth > 20) return false;
  if (typeof value === 'string') return value.length <= 32768;
  if (value === null || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.length <= 200 && value.every(item => bounded(item, depth + 1, budget));
  return object(value) && Object.keys(value).length <= 100
    && Object.values(value).every(item => bounded(item, depth + 1, budget));
}
function publicSnapshot(snapshot) {
  const result = Object.fromEntries(SNAPSHOT_KEYS.filter(key => Object.hasOwn(snapshot, key)).map(key => [key, snapshot[key]]));
  // History needs the document actually shown to B, never A's original VC or
  // the source credential's undisclosed attributes and long-term device key.
  for (const key of ['derivedCredential', 'sentCredential']) {
    const subject = result[key]?.credentialSubject;
    if (object(subject)) result[key].credentialSubject = Object.fromEntries(SUBJECT_KEYS
      .filter(field => Object.hasOwn(subject, field)).map(field => [field, subject[field]]));
  }
  return result;
}
function identity(snapshot) {
  const { mode, orderId, bindingId, attemptId } = snapshot || {};
  const challengeId = snapshot?.challenge?.challengeId, w3cPresentationHash = snapshot?.cryptography?.w3cPresentationHash;
  if (snapshot?.phase !== 'proposal' || !MODES.includes(mode)
    || ![orderId, bindingId, attemptId, challengeId].every(identifier) || !hash(w3cPresentationHash)) return null;
  const challenge = snapshot.challenge, subject = snapshot.derivedCredential?.credentialSubject;
  if (!object(subject) || subject.bindingId !== bindingId || subject.mode !== mode
    || snapshot.derivedCredential?.proof?.cryptosuite !== 'bbs-2023'
    || typeof snapshot.derivedCredential?.proof?.proofValue !== 'string'
    || !snapshot.derivedCredential.proof.proofValue.length || snapshot.derivedCredential.proof.proofValue.length > 16384) return null;
  if (challenge.paymentOrderId != null && challenge.paymentOrderId !== orderId
    || challenge.mode != null && challenge.mode !== mode
    || challenge.w3cPresentationHash != null && challenge.w3cPresentationHash !== w3cPresentationHash) return null;
  for (const field of ['deviceRequest', 'deviceResponse', 'presentation']) {
    if (snapshot[field]?.mode != null && snapshot[field].mode !== mode) return null;
  }
  const context = snapshot.deviceRequest?.context;
  if (context && (context.w3cPresentationHash != null && context.w3cPresentationHash !== w3cPresentationHash
    || context.challengeId != null && context.challengeId !== challengeId
    || context.paymentOrderId != null && context.paymentOrderId !== orderId)) return null;
  const sent = snapshot.sentCredential?.credentialSubject;
  if (sent && (sent.bindingId !== bindingId || sent.mode !== mode)) return null;
  if (snapshot.sentCredential && JSON.stringify(snapshot.sentCredential) !== JSON.stringify(snapshot.derivedCredential)) return null;
  const fields = { mode, orderId, bindingId, attemptId, challengeId, w3cPresentationHash };
  return { key: JSON.stringify(Object.values(fields)), ...fields };
}
function currentIdentity(state) { return identity(publicSnapshot(flowSnapshot(state))); }
function validTrace(snapshot) {
  const trace = snapshot?.verificationTrace;
  return trace?.source === 'agent-b' && ['pass', 'fail'].includes(trace.outcome)
    && Array.isArray(trace.steps) && trace.steps.length > 0
    && trace.steps.every(step => ['pass', 'fail', 'pending', 'skipped'].includes(step.status));
}
function fingerprint(snapshot) {
  // Stage/expiry and later local preparation are observations, not a new B
  // response. A refresh must not move the recorded time of the same result.
  return JSON.stringify(['scenario', 'mode', 'orderId', 'bindingId', 'attemptId',
    'derivedCredential', 'cryptography', 'challenge', 'presentation', 'verificationTrace', 'error', 'attackCode']
    .map(key => [key, snapshot[key] ?? null]));
}
function eventTime(state, snapshot) {
  const log = state?.manual?.log;
  if (!Array.isArray(log)) return null;
  const challenge = snapshot.challenge;
  // Backend log entries lack an attemptId. Anchor to this exact received
  // challenge before consulting any result event; never import a log result.
  const start = log.findLastIndex(event => event?.action === 'begin-proposal' && event.status === 'received'
    && event.data?.challengeId === challenge.challengeId && event.data?.bodyHash === challenge.bodyHash
    && event.data?.paymentOrderId === challenge.paymentOrderId && event.data?.mode === snapshot.mode);
  if (start < 0) return null;
  for (let index = log.length - 1; index > start; index--) {
    const event = log[index];
    if (event?.action?.startsWith('begin-')) return null;
    if (event?.action !== (snapshot.scenario === 'missing' ? 'test-no-device' : 'verify')) continue;
    const rawTrace = event.data?.verificationTrace ?? event.data?.error?.verificationTrace;
    if (!rawTrace) continue;
    const projected = flowSnapshot({ ...state, manual: { ...state.manual,
      lastAttack: null, lastError: null, verificationResult: { verificationTrace: rawTrace } } });
    if (JSON.stringify(projected.verificationTrace) === JSON.stringify(snapshot.verificationTrace)) return iso(event.time);
  }
  return null;
}
function restoreSnapshot(value, scenario) {
  if (!object(value) || value.scenario !== scenario || !bounded(value)) return null;
  if (value.expiresAtUnix !== null && !Number.isFinite(value.expiresAtUnix)) return null;
  // Re-enter the original projection with explicitly mapped fields. Unknown
  // data, arbitrary raw state and prototype-shaped properties are not spread.
  const manual = { phase: value.phase, stage: value.stage, attemptId: value.attemptId,
    active: value.active, expired: value.expired, expiresAtUnix: value.expiresAtUnix,
    challenge: value.challenge, cryptography: value.cryptography,
    verifiableCredential: value.derivedCredential, sentCredential: value.sentCredential,
    deviceRequest: value.deviceRequest, deviceResponse: value.deviceResponse, presentation: value.presentation };
  if (scenario === 'missing') manual.lastAttack = { action: 'test-no-device', actual: value.attackCode,
    verificationTrace: value.verificationTrace, error: value.error };
  else if (value.error) manual.lastError = { code: value.error.code, message: value.error.message, verificationTrace: value.verificationTrace };
  else manual.verificationResult = { verificationTrace: value.verificationTrace };
  const projected = publicSnapshot(flowSnapshot({ mode: value.mode, order: { orderId: value.orderId },
    w3c: { originalCredential: { credentialSubject: { bindingId: value.bindingId } } }, manual }, scenario));
  return identity(projected) && validTrace(projected) ? projected : null;
}
function roundTime(round) { return Math.max(...Object.values(round.records).map(record => Date.parse(record.recordedAt))); }

export function createHistory(serialized = null) {
  const saved = new Map();
  function trim() {
    const rounds = [...saved.values()].sort((a, b) => roundTime(b) - roundTime(a));
    for (const round of rounds.slice(MAX_ROUNDS)) saved.delete(round.key);
    while (saved.size && JSON.stringify({ version: VERSION, rounds: [...saved.values()] }).length > MAX_SERIALIZED) {
      const oldest = [...saved.values()].sort((a, b) => roundTime(a) - roundTime(b))[0];
      saved.delete(oldest.key);
    }
  }
  if (typeof serialized === 'string' && serialized.length <= MAX_SERIALIZED) {
    try {
      const input = JSON.parse(serialized);
      if (object(input) && input.version === VERSION && Array.isArray(input.rounds) && input.rounds.length <= MAX_ROUNDS) {
        for (const round of input.rounds) {
          if (!object(round) || !object(round.records)) continue;
          for (const scenario of SCENARIOS) {
            const record = round.records[scenario];
            if (!object(record) || record.scenario !== scenario || !iso(record.recordedAt)
              || !['backend', 'observed'].includes(record.timestampSource)) continue;
            const snapshot = restoreSnapshot(record.snapshot, scenario);
            if (!snapshot || JSON.stringify(snapshot).length > MAX_RECORD) continue;
            const group = identity(snapshot);
            if (group.key !== round.key || Object.entries(group).some(([key, value]) => round[key] !== value)) continue;
            const target = saved.get(group.key) || { ...group, records: {} };
            target.records[scenario] = { scenario, recordedAt: record.recordedAt,
              timestampSource: record.timestampSource, snapshot, fingerprint: fingerprint(snapshot) };
            saved.set(group.key, target);
          }
        }
      }
    } catch { /* Malformed storage is disposable display history. */ }
  }
  trim();
  const current = state => {
    const group = currentIdentity(state);
    return group ? clone(saved.get(group.key) || null) : null;
  };
  return {
    capture(state, now = Date.now()) {
      if (!Number.isFinite(now) || !Number.isFinite(new Date(now).getTime())) return current(state);
      const observedTime = iso(new Date(now).toISOString());
      if (!observedTime) return current(state);
      for (const scenario of SCENARIOS) {
        const snapshot = publicSnapshot(flowSnapshot(state, scenario));
        const group = identity(snapshot);
        if (!group || !validTrace(snapshot) || !bounded(snapshot) || JSON.stringify(snapshot).length > MAX_RECORD) continue;
        const resultFingerprint = fingerprint(snapshot), target = saved.get(group.key) || { ...group, records: {} };
        if (target.records[scenario]?.fingerprint === resultFingerprint) continue;
        const backendTime = eventTime(state, snapshot);
        target.records[scenario] = { scenario, recordedAt: backendTime || observedTime,
          timestampSource: backendTime ? 'backend' : 'observed', snapshot, fingerprint: resultFingerprint };
        saved.set(group.key, target);
      }
      trim();
      return current(state);
    },
    rounds(state) {
      const mode = state?.mode, orderId = state?.order?.orderId,
        bindingId = state?.w3c?.originalCredential?.credentialSubject?.bindingId;
      return clone([...saved.values()].filter(round => round.mode === mode && round.orderId === orderId && round.bindingId === bindingId)
        .sort((a, b) => roundTime(b) - roundTime(a)));
    },
    current,
    serialize() { return JSON.stringify({ version: VERSION, rounds: [...saved.values()] }); },
    find(key, scenario) { return SCENARIOS.includes(scenario) ? clone(saved.get(key)?.records[scenario] || null) : null; },
  };
}
