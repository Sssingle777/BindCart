// Read-only presentation projection. It never verifies a proof or authorizes a
// payment; those decisions and their evidence remain on the backend.
const MODES = ['bbs-bls', 'bbs-blind-bls'];
const SUBJECT_FIELDS = ['role', 'scope', 'epoch', 'mode', 'bindingId', 'holderDid', 'organization', 'holderLabel'];
const TRACE_IDS = new Set(['extension', 'envelope', 'challenge', 'replay', 'request_binding',
  'policy_context', 'scope', 'schema', 'w3c_bbs', 'vc_device_binding', 'proof_structure',
  'disclosure', 'proof_encoding', 'knowledge', 'credential_pairing', 'device_pairing',
  'owner_authorization', 'task_binding', 'consume', 'settlement_gate', 'execution',
  'preparation', 'device_contribution_binding', 'holder_signature', 'credential_status']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const scalar = value => value === null || typeof value === 'string' || typeof value === 'boolean'
  || typeof value === 'number' && Number.isFinite(value);
function pick(value, keys) {
  if (!object(value)) return null;
  const result = {};
  for (const key of keys) if (Object.hasOwn(value, key) && scalar(value[key])) result[key] = value[key];
  return result;
}
function texts(value) { return Array.isArray(value) ? value.filter(item => typeof item === 'string').slice() : []; }
function bool(value) { return typeof value === 'boolean' ? value : null; }
function string(value) { return typeof value === 'string' ? value : null; }
function list(value, projector) { return Array.isArray(value) ? value.map(projector).filter(Boolean) : []; }

function credential(value) {
  const result = pick(value, ['id', 'issuer', 'validFrom', 'validUntil']);
  if (!result) return null;
  result['@context'] = texts(value['@context']); result.type = texts(value.type);
  result.credentialSubject = pick(value.credentialSubject, SUBJECT_FIELDS);
  result.proof = pick(value.proof, ['type', 'cryptosuite', 'created', 'proofPurpose', 'verificationMethod', 'proofValue']);
  return result;
}
function issuer(value) {
  const result = pick(value, ['issuer']);
  if (!result) return null;
  result.verificationMethod = pick(value.verificationMethod, ['@context', 'type', 'id', 'controller', 'publicKeyMultibase']);
  return result;
}
function context(value) {
  const result = pick(value, ['profile', 'purpose', 'scope', 'mode', 'verifier', 'target', 'method',
    'bodyHash', 'paymentOrderId', 'challengeId', 'nonce', 'iat', 'exp', 'credentialProfile', 'w3cPresentationHash']);
  if (!result) return null;
  if (Array.isArray(value.schema)) result.schema = texts(value.schema);
  if (object(value.requiredDisclosures)) result.requiredDisclosures = pick(value.requiredDisclosures, ['0', '1', '2', '3', '6']);
  return result;
}
function request(value) {
  const result = pick(value, ['version', 'suite', 'mode', 'randomizedDevicePublicKey', 'blindedPoint']);
  if (!result) return null;
  // A blind request contains only Q-prime and protocol metadata. Never invent
  // a context from the agent's local state and label it a device input.
  if (value.mode !== 'bbs-blind-bls' && object(value.context)) result.context = context(value.context);
  return result;
}
function presentation(value) {
  const result = pick(value, ['version', 'suite', 'mode', 'attributeCount', 'randomizedDevicePublicKey',
    'deviceSignature', 'Abar', 'Bbar', 'Cbar']);
  if (!result) return null;
  result.disclosed = list(value.disclosed, item => pick(item, ['index', 'value']));
  result.proof = pick(value.proof, ['challenge']);
  if (result.proof) {
    const responses = value.proof.responses;
    result.proof.responses = pick(responses, ['inverseR1', 'keyRandomizer', 'r2', 'e']);
    if (result.proof.responses) result.proof.responses.hidden = list(responses.hidden, item => pick(item, ['index', 'response']));
  }
  return result;
}
function evidenceValue(value) {
  if (scalar(value)) return value;
  if (Array.isArray(value) && value.length <= 12 && value.every(scalar)) return value.slice();
  return undefined;
}
function evidenceRow(value) {
  const result = pick(value, ['label', 'note']);
  if (!result || typeof result.label !== 'string') return null;
  for (const key of ['expected', 'observed']) {
    if (!Object.hasOwn(value, key)) continue;
    const projected = evidenceValue(value[key]);
    if (projected !== undefined) result[key] = projected;
  }
  if (typeof value.match === 'boolean') result.match = value.match;
  return result;
}
function trace(value) {
  const result = pick(value, ['profile', 'source', 'outcome']);
  if (!result) return null;
  result.steps = list(value.steps, step => {
    if (!object(step) || !TRACE_IDS.has(step.id)) return null;
    const projected = pick(step, ['id', 'title', 'actor', 'status', 'detail', 'code']);
    projected.evidence = list(step.evidence, evidenceRow);
    if (typeof step.evidenceTruncated === 'boolean') projected.evidenceTruncated = step.evidenceTruncated;
    return projected;
  });
  return result;
}
function device(value) {
  const result = pick(value, ['backend', 'hardware', 'keyExportable', 'available', 'publicKey', 'publicKeyFingerprint']);
  if (!result) return null;
  result.modes = {};
  for (const mode of MODES) {
    const observed = value.modes?.[mode];
    if (!object(observed)) continue;
    const modeState = {};
    if (typeof observed.locked === 'boolean') modeState.locked = observed.locked;
    if (Number.isSafeInteger(observed.signatures) && observed.signatures >= 0) modeState.signatures = observed.signatures;
    result.modes[mode] = modeState;
  }
  return result;
}
function payment(value) {
  const result = pick(value, ['orderId', 'payerAccount', 'payeeAccount', 'amountMinor', 'currency']);
  if (result) result.settlement = pick(value.settlement, ['network', 'asset', 'payTo', 'payerAddress']);
  return result;
}
function paymentResult(value) {
  const result = pick(value, ['outcome']);
  if (result) result.receipt = pick(value.receipt, ['orderId', 'amountMinor', 'currency', 'transactionHash', 'transactionStatus', 'localTestOnly']);
  return result;
}

/** Safe public protocol observation, suitable for retaining as a stage snapshot. */
export function protocolSnapshot(state) {
  const m = object(state?.manual) ? state.manual : {};
  // A later failure or negative case must not borrow an earlier success trace.
  const currentTrace = m.lastAttack ? m.lastAttack.verificationTrace ?? m.lastAttack.error?.verificationTrace
    : m.lastError ? m.lastError.verificationTrace : m.verificationResult?.verificationTrace;
  const projectedCredential = pick(state?.credential, ['suite']);
  if (projectedCredential) projectedCredential.attributes = list(state.credential.attributes,
    item => pick(item, ['index', 'name', 'value', 'disclosed']));
  return {
    available: bool(state?.available), mode: MODES.includes(state?.mode) ? state.mode : null,
    orderId: string(state?.order?.orderId), bindingId: string(state?.w3c?.originalCredential?.credentialSubject?.bindingId),
    phase: string(m.phase), stage: string(m.stage), attemptId: string(m.attemptId), active: bool(m.active), expired: bool(m.expired),
    issuerProfile: issuer(state?.w3c?.issuerProfile), originalCredential: credential(state?.w3c?.originalCredential),
    derivedCredential: credential(m.verifiableCredential), sentCredential: credential(m.sentCredential),
    credential: projectedCredential, device: device(m.device),
    holder: pick(state?.holder,['did','keyFingerprint','storage']), holderProof:string(m.holderProof),
    disclosedPaths: texts(state?.w3c?.disclosedPaths), hiddenPaths: texts(state?.w3c?.hiddenPaths),
    cryptography: pick(m.cryptography, ['presentationHeader', 'w3cPresentationHash']),
    challenge: context(m.challenge), deviceRequest: request(m.deviceRequest),
    deviceResponse: pick(m.deviceResponse, ['version', 'suite', 'mode', 'signature']),
    presentation: presentation(m.presentation), verificationTrace: trace(currentTrace),
    error: pick(m.lastError || m.lastAttack?.error, ['code', 'message']),
    payment: payment(state?.order), proposal: pick(state?.proposal, ['id', 'status']),
    ownerApproved: bool(m.ownerApproved), walletSigned: bool(m.walletSigned),
    walletSigningUnconfirmed: bool(m.walletSigningUnconfirmed), settled: bool(m.settled),
    paymentResult: paymentResult(m.verificationResult?.paymentResult),
  };
}

/** Summarize recorded backend steps; absence and group failure never mean pass. */
export function protocolChecks(snapshot) {
  const safeTrace = trace(snapshot?.verificationTrace);
  const groups = { standard: ['w3c_bbs'], binding: ['request_binding', 'vc_device_binding'],
    knowledge: ['knowledge', 'credential_pairing'], device: ['device_pairing'] };
  return Object.fromEntries(Object.entries(groups).map(([name, ids]) => {
    const steps = safeTrace?.steps.filter(step => ids.includes(step.id)) || [];
    let status = 'skipped';
    if (safeTrace?.source === 'agent-b') {
      if (steps.some(step => step.status === 'fail' || step.evidence.some(row => row.match === false))) status = 'fail';
      else if (ids.every(id => steps.filter(step => step.id === id).length === 1)
        && steps.every(step => step.status === 'pass')) status = 'pass';
      else if (steps.some(step => step.status === 'pending') || new Set(steps.map(step => step.id)).size !== steps.length) status = 'pending';
    }
    return [name, { status, steps, evidence: steps.flatMap(step => step.evidence.map(row => ({ stepId: step.id, ...row }))) }];
  }));
}
