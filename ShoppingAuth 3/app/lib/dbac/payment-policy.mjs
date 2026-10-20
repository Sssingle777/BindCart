import { randomUUID } from 'node:crypto';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { resolveDid, signJws, verifyJws } from '../identity.mjs';
import { AppError, digest, unix } from '../protocol.mjs';
import { PAYMENT_SCOPE, validatePayment } from '../payment.mjs';
import { DBAC_EXTENSION, DBAC_MODES, DBAC_SCHEMA, paymentDisclosures, exact } from './policy.mjs';
import { W3C_PAYMENT_PROFILE, W3C_PAYMENT_SCHEMA } from './w3c-profile.mjs';

export const DBAC_PAYMENT_PROFILE = 'dbac-payment';
export const DBAC_PAYMENT_CHALLENGE_TYP = 'a2a-dbac-payment-challenge+jwt';
export const DBAC_PAYMENT_RESPONSE_TYP = 'a2a-dbac-payment-response+jwt';
export const DBAC_PAYMENT_AUTH_TYP = 'a2a-dbac-payment-authorization+jwt';
const PHASES = ['proposal', 'authorize', 'settle'];
const AUTH_KEYS = ['type', 'version', 'profile', 'authorizationId', 'iss', 'aud', 'mode', 'issuerPublicKey', 'orderKey', 'iat', 'exp', 'maxExecutions', 'delegationAllowed', 'payment'];
const CONTEXT_KEYS = ['profile', 'purpose', 'scope', 'mode', 'verifier', 'target', 'method', 'bodyHash', 'paymentOrderId', 'challengeId', 'nonce', 'iat', 'exp', 'schema', 'requiredDisclosures'];
const VC_BINDING_KEYS = ['credentialProfile', 'w3cIssuer', 'vcBindingId'];
const fail = (code, message, status = 403) => { throw new AppError(code, message, status); };
const identifier = value => typeof value === 'string' && value.length > 0 && value.length <= 256 && value.trim() === value && !/[\u0000-\u001f\u007f]/.test(value);
const isDigest = value => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value;
const isDid = value => { try { resolveDid(value); return true; } catch { return false; } };
const hasKeys = (value, required, optional = []) => value !== null && typeof value === 'object' && !Array.isArray(value) && required.every(key => Object.hasOwn(value, key)) && Object.keys(value).every(key => [...required, ...optional].includes(key));

// Stable application hashing, independent of JSON property insertion order.
// This hashes public payment terms and evidence; it is not a new proof scheme.
function canonical(value, depth = 0) {
  if (depth > 24) fail('DBAC_PAYMENT_INVALID_INPUT', '支付证据嵌套过深。');
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') { if (!value.isWellFormed()) fail('DBAC_PAYMENT_INVALID_INPUT', '支付证据字符串编码无效。'); return JSON.stringify(value); }
  if (typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(item => canonical(item, depth + 1)).join(',')}]`;
  if (value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key], depth + 1)}`).join(',')}}`;
  fail('DBAC_PAYMENT_INVALID_INPUT', '支付证据包含不可序列化值。');
}
export const dbacPaymentHash = value => digest(canonical(value));
const same = (a, b) => canonical(a) === canonical(b);
function point(value, group, bytes) {
  try {
    if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value)) return false;
    const parsed = group.ProjectivePoint.fromHex(value);
    parsed.assertValidity();
    return !parsed.equals(group.ProjectivePoint.ZERO) && parsed.toHex(true) === value;
  } catch { return false; }
}
function binding(mode, issuerPublicKey, orderKey) {
  return DBAC_MODES.includes(mode) && point(issuerPublicKey, bls.G2, 96) && point(orderKey, bls.G1, 48);
}
export function credentialBindingOf(value) {
  if (value?.credentialProfile === undefined) return undefined;
  const result = Object.fromEntries(VC_BINDING_KEYS.map(key => [key, value[key]]));
  if (result.credentialProfile !== W3C_PAYMENT_PROFILE || !identifier(result.w3cIssuer) || !/^[a-z][a-z0-9+.-]*:/i.test(result.w3cIssuer) || !identifier(result.vcBindingId)) fail('W3C_CREDENTIAL_BINDING_INVALID', 'W3C VC 的签发方或设备绑定标识无效。');
  return result;
}
function enforceCredentialBinding(actual, expected, expectedIssuer) {
  if (expected !== undefined && (!exact(expected, VC_BINDING_KEYS) || !credentialBindingOf(expected))) fail('W3C_CREDENTIAL_BINDING_INVALID', 'VC 绑定验证策略必须包含全部绑定字段。');
  if (expectedIssuer !== undefined && (typeof expectedIssuer !== 'string' || expectedIssuer.length > 256 || !/^[a-z][a-z0-9+.-]*:\S+$/i.test(expectedIssuer))) fail('W3C_CREDENTIAL_BINDING_INVALID', 'W3C 签发方验证策略必须是非空绝对标识。');
  const got = credentialBindingOf(actual);
  if (expected && (!got || !same(got, expected)) || expectedIssuer && (!got || got.w3cIssuer !== expectedIssuer)) fail('PAYMENT_AUTHORIZATION_BINDING_MISMATCH', '凭证类型、W3C 签发方或设备绑定标识不匹配。');
}
function authorizationDocument(document) {
  const vcBinding = credentialBindingOf(document);
  if (!exact(document, [...AUTH_KEYS, ...(vcBinding ? VC_BINDING_KEYS : [])]) || document.type !== 'DbacSinglePaymentAuthorization' || document.version !== 1 || document.profile !== DBAC_PAYMENT_PROFILE ||
      !identifier(document.authorizationId) || !isDid(document.iss) || !isDid(document.aud) || !binding(document.mode, document.issuerPublicKey, document.orderKey) ||
      document.maxExecutions !== 1 || document.delegationAllowed !== false || !Number.isSafeInteger(document.iat) || document.iat < 0 ||
      !Number.isSafeInteger(document.exp) || document.exp <= document.iat || document.exp - document.iat > 600) fail('INVALID_DBAC_PAYMENT_AUTHORIZATION', 'DBAC 单笔授权结构、订单公钥或有效期无效。');
  validatePayment(document.payment);
}

export function issueDbacPaymentAuthorization(identity, options = {}) {
  if (!hasKeys(options, ['verifierDid', 'mode', 'issuerPublicKey', 'orderKey', 'payment'], ['authorizationId', 'iat', 'exp', 'credentialBinding'])) fail('INVALID_DBAC_PAYMENT_AUTHORIZATION', 'DBAC 单笔授权必须明确指定验证方、方案、公钥和支付条款。');
  if (options.credentialBinding !== undefined && (!exact(options.credentialBinding, VC_BINDING_KEYS) || !credentialBindingOf(options.credentialBinding))) fail('W3C_CREDENTIAL_BINDING_INVALID', 'VC 绑定字段不完整。');
  const iat = options.iat ?? unix();
  const document = { type: 'DbacSinglePaymentAuthorization', version: 1, profile: DBAC_PAYMENT_PROFILE, authorizationId: options.authorizationId ?? `urn:uuid:${randomUUID()}`,
    iss: identity?.did, aud: options.verifierDid, mode: options.mode, issuerPublicKey: options.issuerPublicKey, orderKey: options.orderKey,
    iat, exp: options.exp ?? iat + 600, maxExecutions: 1, delegationAllowed: false, payment: validatePayment(options.payment), ...credentialBindingOf(options.credentialBinding) };
  authorizationDocument(document);
  return signJws(document, identity, DBAC_PAYMENT_AUTH_TYP);
}

export function verifyDbacPaymentAuthorization(token, options = {}) {
  if (!token) fail('PAYMENT_AUTHORIZATION_REQUIRED', '需要 Owner 明确批准的 DBAC 单笔支付授权。', 401);
  if (!hasKeys(options, ['trustedAuthorizers', 'verifierDid', 'issuerPublicKey', 'payment'], ['mode', 'orderKey', 'now', 'credentialBinding', 'w3cIssuer']) ||
      !(options.trustedAuthorizers instanceof Set || Array.isArray(options.trustedAuthorizers)) || ![...options.trustedAuthorizers].length ||
      ![...options.trustedAuthorizers].every(isDid) || !isDid(options.verifierDid) || !point(options.issuerPublicKey, bls.G2, 96)) fail('INVALID_DBAC_PAYMENT_AUTHORIZATION', 'DBAC 授权验证缺少可信 Owner 或签发者。');
  let document, signerDid;
  try { ({ payload: document, signerDid } = verifyJws(token, { typ: DBAC_PAYMENT_AUTH_TYP, purpose: 'assertionMethod' })); }
  catch { fail('INVALID_DBAC_PAYMENT_AUTHORIZATION', 'DBAC 单笔授权签名或类型无效。', 401); }
  authorizationDocument(document);
  enforceCredentialBinding(document, options.credentialBinding, options.w3cIssuer);
  if (document.iss !== signerDid || ![...options.trustedAuthorizers].includes(signerDid)) fail('PAYMENT_AUTHORIZER_UNTRUSTED', 'DBAC 支付授权不是由可信 Owner 签署。');
  const now = options.now ?? unix();
  if (!Number.isSafeInteger(now) || now < 0) fail('INVALID_DBAC_PAYMENT_AUTHORIZATION', '授权校验时间无效。');
  if (document.iat > now || document.exp <= now) fail('PAYMENT_AUTHORIZATION_EXPIRED', 'DBAC 单笔授权尚未生效或已经过期。');
  if (document.aud !== options.verifierDid || document.issuerPublicKey !== options.issuerPublicKey ||
      (options.mode !== undefined && document.mode !== options.mode) || (options.orderKey !== undefined && document.orderKey !== options.orderKey)) fail('PAYMENT_AUTHORIZATION_BINDING_MISMATCH', 'Owner 授权未绑定当前 DBAC 方案、订单公钥或验证方。');
  if (!same(validatePayment(document.payment), validatePayment(options.payment))) fail('PAYMENT_TERMS_MISMATCH', '订单、金额、链、资产或收付款方与 Owner 批准内容不一致。');
  return document;
}

export function parseDbacPaymentRequest(rawRequest) {
  let request;
  try { request = JSON.parse(rawRequest); } catch { fail('DBAC_PAYMENT_INVALID_REQUEST', 'DBAC 支付请求不是有效 JSON。'); }
  const message = request?.params?.message, data = message?.parts?.[0]?.data;
  if (['authorize', 'settle'].includes(data?.phase) && !data.authorization) fail('PAYMENT_AUTHORIZATION_REQUIRED', '支付阶段缺少 Owner 单笔授权。');
  if (!exact(request, ['jsonrpc', 'id', 'method', 'params']) || request.jsonrpc !== '2.0' || !identifier(request.id) || request.method !== 'message/send' ||
      !exact(request.params, ['message']) || !hasKeys(message, ['kind', 'role', 'messageId', 'parts'], ['taskId', 'contextId']) || message.kind !== 'message' || message.role !== 'user' || !identifier(message.messageId) ||
      (message.taskId !== undefined && !identifier(message.taskId)) || (message.contextId !== undefined && !identifier(message.contextId)) || !Array.isArray(message.parts) || message.parts.length !== 1 ||
      !exact(message.parts[0], ['kind', 'data']) || message.parts[0].kind !== 'data' || !PHASES.includes(data?.phase) || data.scope !== PAYMENT_SCOPE ||
      !exact(data, ['scope', 'phase', 'payment', ...(data.phase === 'proposal' ? [] : ['authorization']), ...(data.phase === 'settle' ? ['payload'] : [])])) fail('DBAC_PAYMENT_INVALID_REQUEST', '支付请求必须是包含明确阶段和精确支付数据的 A2A message/send。');
  validatePayment(data.payment);
  if (data.phase !== 'proposal' && (typeof data.authorization !== 'string' || data.authorization.length > 32768 || !data.authorization)) fail('PAYMENT_AUTHORIZATION_REQUIRED', '支付阶段缺少 Owner 单笔授权。');
  if (data.phase === 'settle' && (!data.payload || typeof data.payload !== 'object' || Array.isArray(data.payload))) fail('DBAC_PAYMENT_INVALID_REQUEST', '结算阶段缺少 x402 payload。');
  return request;
}

export function verifyDbacPaymentEvidence(evidence, options = {}) {
  if (!hasKeys(options, ['verifierDid', 'issuerPublicKey', 'phase', 'payment'], ['authorization', 'paymentRequired', 'payload', 'credentialBinding', 'w3cIssuer']) || !isDid(options.verifierDid) || !PHASES.includes(options.phase) || !point(options.issuerPublicKey, bls.G2, 96)) fail('DBAC_PAYMENT_EVIDENCE_INVALID', '支付证据验证策略无效。');
  if (!exact(evidence, ['proof', 'rawRequest', 'rawResponse', 'context']) || ![evidence.proof, evidence.rawRequest, evidence.rawResponse].every(value => typeof value === 'string' && value.length > 0 && value.length <= 131072)) fail('DBAC_PAYMENT_EVIDENCE_REQUIRED', '缺少 B 签署的完整 DBAC 支付验证证据。');
  let signed, response;
  try { signed = verifyJws(evidence.proof, { typ: DBAC_PAYMENT_RESPONSE_TYP, purpose: 'authentication', expectedDid: options.verifierDid }).payload; response = JSON.parse(evidence.rawResponse); }
  catch { fail('DBAC_PAYMENT_EVIDENCE_INVALID', 'B 的 DBAC 支付响应签名或 JSON 无效。'); }
  const request = parseDbacPaymentRequest(evidence.rawRequest), data = request.params.message.parts[0].data, context = evidence.context, gate = signed.paymentGate;
  const phase = options.phase, time = unix(), maxAge = phase === 'proposal' ? 300 : 60;
  const w3c = context?.credentialProfile === W3C_PAYMENT_PROFILE;
  const payment = validatePayment(options.payment);
  if (!exact(signed, ['iss', 'requestHash', 'responseHash', 'contextHash', 'iat', 'exp', 'paymentGate', 'verificationTrace']) || signed.iss !== options.verifierDid ||
      !Number.isSafeInteger(signed.iat) || !Number.isSafeInteger(signed.exp) || signed.iat > time + 5 || signed.exp <= time || signed.exp <= signed.iat || signed.exp - signed.iat > maxAge ||
      signed.requestHash !== digest(evidence.rawRequest) || signed.responseHash !== digest(evidence.rawResponse) || signed.contextHash !== digest(JSON.stringify(context))) fail('DBAC_PAYMENT_EVIDENCE_INVALID', 'B 的支付证据已过期或未绑定原始请求、响应及挑战。');
  if (!exact(context, [...CONTEXT_KEYS, ...(w3c ? ['credentialProfile'] : [])]) || context.profile !== DBAC_EXTENSION || context.purpose !== 'dbac-payment-v1' || context.scope !== PAYMENT_SCOPE ||
      context.verifier !== options.verifierDid || context.method !== 'POST' || typeof context.target !== 'string' || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]*\/dbac\/payment\/a2a$/.test(context.target) ||
      context.bodyHash !== digest(evidence.rawRequest) || context.paymentOrderId !== payment.orderId || !identifier(context.challengeId) || !isDigest(context.nonce) ||
      !Number.isSafeInteger(context.iat) || !Number.isSafeInteger(context.exp) || context.exp <= context.iat || context.exp - context.iat > 60 ||
      context.iat > signed.iat || context.exp < signed.iat || (phase !== 'proposal' && context.exp <= time) ||
      !same(context.schema, w3c ? W3C_PAYMENT_SCHEMA : DBAC_SCHEMA) || !same(context.requiredDisclosures, paymentDisclosures(context.mode))) fail('DBAC_PAYMENT_EVIDENCE_CONTEXT', '支付证据的挑战、日期、订单或作用域不匹配。');
  if (!exact(gate, ['profile', 'phase', 'mode', 'issuerPublicKey', 'orderKey', 'paymentHash', ...(w3c ? [...VC_BINDING_KEYS, 'w3cPresentationHash'] : []), ...(phase === 'proposal' ? [] : ['authorizationHash']), ...(phase === 'settle' ? ['payloadHash'] : [])]) ||
      gate.profile !== DBAC_PAYMENT_PROFILE || gate.phase !== phase || !binding(gate.mode, gate.issuerPublicKey, gate.orderKey) || gate.mode !== context.mode || gate.issuerPublicKey !== options.issuerPublicKey ||
      gate.paymentHash !== dbacPaymentHash(payment) || data.phase !== phase || !same(validatePayment(data.payment), payment)) fail('DBAC_PAYMENT_EVIDENCE_MISMATCH', 'B 的 DBAC 门槛未绑定当前阶段、方案、公钥或精确订单。');
  enforceCredentialBinding(gate, options.credentialBinding, options.w3cIssuer);
  if (w3c && (gate.credentialProfile !== W3C_PAYMENT_PROFILE || !isDigest(gate.w3cPresentationHash) || !['w3c_bbs', 'vc_device_binding'].every(id => signed.verificationTrace?.steps?.some(step => step.id === id && step.status === 'pass')))) fail('DBAC_PAYMENT_EVIDENCE_MISMATCH', '缺少标准 BBS 与 eSIM 凭证绑定的实际验证证据。');
  if (phase !== 'proposal' && (typeof options.authorization !== 'string' || data.authorization !== options.authorization || gate.authorizationHash !== digest(options.authorization))) fail('DBAC_PAYMENT_EVIDENCE_MISMATCH', 'B 的 DBAC 门槛未绑定当前 Owner 授权。');
  if (phase === 'settle' && (!options.payload || !same(data.payload, options.payload) || gate.payloadHash !== dbacPaymentHash(options.payload))) fail('DBAC_PAYMENT_EVIDENCE_MISMATCH', '结算证据未绑定完整 x402 payload。');
  const task = response?.result, metadata = task?.status?.message?.metadata;
  if (response.jsonrpc !== '2.0' || response.id !== request.id || response.error || task?.kind !== 'task' || !identifier(task.id) || !identifier(task.contextId) || signed.verificationTrace?.profile !== DBAC_PAYMENT_PROFILE || signed.verificationTrace?.outcome !== 'pass') fail('DBAC_PAYMENT_EVIDENCE_MISMATCH', 'B 的支付响应或实际验证结果无效。');
  if (phase === 'proposal' && task.status?.state !== 'completed') fail('DBAC_PAYMENT_EVIDENCE_MISMATCH', 'Owner 需要已经完成的 DBAC 支付资格验证。');
  if (phase === 'authorize' && (task.status?.state !== 'input-required' || metadata?.['x402.payment.status'] !== 'payment-required' || !options.paymentRequired || !same(metadata['x402.payment.required'], options.paymentRequired))) fail('DBAC_PAYMENT_EVIDENCE_MISMATCH', '钱包需要绑定精确付款要求的 DBAC authorize 证据。');
  if (phase === 'settle') {
    if (!identifier(request.params.message.taskId) || !identifier(request.params.message.contextId) || task.id !== request.params.message.taskId || task.contextId !== request.params.message.contextId) fail('DBAC_PAYMENT_EVIDENCE_MISMATCH', '结算回执没有继续原始付款任务。');
    const pending = task.status?.state === 'working' && metadata?.['dbac.payment.status'] === 'settlement-authorized';
    const results = (task.artifacts ?? []).flatMap(artifact => (artifact.parts ?? []).filter(part => part.kind === 'data' && part.data?.paymentResult).map(part => part.data.paymentResult));
    let settled = false;
    try { settled = task.status?.state === 'completed' && metadata?.['x402.payment.status'] === 'payment-completed' && results.length === 1 && ['EXECUTED', 'ALREADY_PROCESSED'].includes(results[0].outcome) && same(validatePayment(Object.fromEntries(Object.keys(payment).map(key => [key, results[0].receipt?.[key]]))), payment); } catch { /* Invalid final receipts never authorize another settlement. */ }
    if (!pending && !settled) fail('DBAC_PAYMENT_EVIDENCE_MISMATCH', '结算入口需要 B 签署的 DBAC settle 门槛或经核对的同订单结算回执。');
  }
  return { gate: structuredClone(gate), request, response, context: structuredClone(context) };
}
