import { createHash, randomUUID } from 'node:crypto';
import { validateMerchantOrder } from './storefront/merchant-protocol.mjs';
import { resolveDid, signJws, verifyJws } from './identity.mjs';

export const PAYMENT_SCOPE = 'payments:pay';
export const PAYMENT_AUTH_TYP = 'a2a-payment-authorization+jwt';
const MAX_AUTHORIZATION_SECONDS = 600;
const PAYMENT_KEYS = ['orderId', 'payerAccount', 'payeeAccount', 'amountMinor', 'currency'];
const AUTHORIZATION_KEYS = ['type', 'version', 'authorizationId', 'iss', 'sub', 'aud', 'deviceDid', 'credentialHash', 'iat', 'exp', 'maxExecutions', 'delegationAllowed', 'payment'];
const ISSUE_KEYS = ['holderDid', 'deviceDid', 'verifierDid', 'credential', 'payment', 'authorizationId', 'iat', 'exp'];
const VERIFY_KEYS = ['trustedAuthorizers', 'holderDid', 'deviceDid', 'verifierDid', 'credential', 'payment', 'now'];
const digest = value => createHash('sha256').update(value).digest('base64url');
const unix = () => Math.floor(Date.now() / 1000);

export class PaymentError extends Error {
  constructor(code, message, status = 400, options) {
    super(message, options);
    this.name = 'PaymentError';
    this.code = code;
    this.status = status;
  }
}

function fail(code, message, status = 400) { throw new PaymentError(code, message, status); }
function objectWithKeys(value, allowed, exact = true) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const keys = Reflect.ownKeys(value);
  return (!exact || keys.length === allowed.length) && keys.every(key => typeof key === 'string' && allowed.includes(key) && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
}
function identifier(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && value.trim() === value && !/[\u0000-\u001f\u007f]/.test(value);
}
function canonicalDigest(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value;
}
function identity(did) {
  try { resolveDid(did); return true; } catch { return false; }
}
function credentialToken(value) {
  // Credential verification is a separate mandatory step at the caller. This
  // authorization binds its exact serialized token, without importing SQLite
  // or duplicating the verifier's VC issuer/revocation policy here.
  return typeof value === 'string' && value.length > 0 && value.length <= 32768 && !/\s/.test(value);
}
function roles(holderDid, deviceDid, verifierDid) {
  return identity(holderDid) && identity(deviceDid) && identity(verifierDid) && holderDid !== deviceDid;
}

export function validatePayment(payment) {
  const chainPayment = payment?.currency === 'TEST_USDC';
  const allowed = [...(chainPayment ? [...PAYMENT_KEYS, 'settlement'] : PAYMENT_KEYS), ...(payment?.merchantOrder !== undefined ? ['merchantOrder'] : [])];
  if (!objectWithKeys(payment, allowed) || !identifier(payment.orderId) ||
      payment.payerAccount !== 'demo:alice' || !['merchant:keyboard', 'merchant:other'].includes(payment.payeeAccount) ||
      !['CNY', 'TEST_USDC'].includes(payment.currency) || !Number.isSafeInteger(payment.amountMinor) || payment.amountMinor <= 0) {
    fail('INVALID_PAYMENT_AUTHORIZATION', '支付条款必须包含合法订单、账户、币种和正整数最小单位金额。');
  }
  const s = payment.settlement;
  if (chainPayment && (!objectWithKeys(s, ['network', 'asset', 'payTo', 'payerAddress']) ||
      !/^eip155:[1-9][0-9]*$/.test(s.network) || ['asset', 'payTo', 'payerAddress'].some(k => !/^0x[0-9a-fA-F]{40}$/.test(s[k])))) {
    fail('INVALID_PAYMENT_AUTHORIZATION', '测试代币付款必须明确绑定链、合约、付款和收款地址。');
  }
  if (payment.merchantOrder !== undefined) validateMerchantOrder(payment.merchantOrder, payment, { allowExpired: true });
  return {
    orderId: payment.orderId,
    payerAccount: payment.payerAccount,
    payeeAccount: payment.payeeAccount,
    amountMinor: payment.amountMinor,
    currency: payment.currency,
    ...(chainPayment ? { settlement: { network: s.network, asset: s.asset.toLowerCase(), payTo: s.payTo.toLowerCase(), payerAddress: s.payerAddress.toLowerCase() } } : {}),
    ...(payment.merchantOrder !== undefined ? { merchantOrder: structuredClone(payment.merchantOrder) } : {}),
  };
}

function validateDocument(document) {
  if (!objectWithKeys(document, AUTHORIZATION_KEYS) || document.type !== 'SinglePaymentAuthorization' || document.version !== 1 ||
      !identifier(document.authorizationId) || !identity(document.iss) || !roles(document.sub, document.deviceDid, document.aud) ||
      !canonicalDigest(document.credentialHash) || document.maxExecutions !== 1 || document.delegationAllowed !== false ||
      !Number.isSafeInteger(document.iat) || !Number.isSafeInteger(document.exp) || document.iat < 0 ||
      document.exp <= document.iat || document.exp - document.iat > MAX_AUTHORIZATION_SECONDS) {
    fail('INVALID_PAYMENT_AUTHORIZATION', '单次支付授权结构、身份、次数、委托策略或有效期不符合要求。');
  }
  validatePayment(document.payment);
}

export function issuePaymentAuthorization(owner, options = {}) {
  if (!objectWithKeys(options, ISSUE_KEYS, false) || !roles(options.holderDid, options.deviceDid, options.verifierDid) || !credentialToken(options.credential)) {
    fail('INVALID_PAYMENT_AUTHORIZATION', '签发支付授权需要持有者、独立设备、接收方 DID 与明确的 VC。');
  }
  const iat = options.iat === undefined ? unix() : options.iat;
  const document = {
    type: 'SinglePaymentAuthorization', version: 1,
    authorizationId: options.authorizationId === undefined ? `urn:uuid:${randomUUID()}` : options.authorizationId,
    iss: owner?.did,
    sub: options.holderDid,
    aud: options.verifierDid,
    deviceDid: options.deviceDid,
    credentialHash: digest(options.credential),
    iat,
    exp: options.exp === undefined ? iat + MAX_AUTHORIZATION_SECONDS : options.exp,
    maxExecutions: 1,
    delegationAllowed: false,
    payment: validatePayment(options.payment),
  };
  validateDocument(document);
  try { return signJws(document, owner, PAYMENT_AUTH_TYP); }
  catch (error) { throw new PaymentError('INVALID_PAYMENT_AUTHORIZATION', '支付授权签名身份或密钥无效。', 400, { cause: error }); }
}

export function verifyPaymentAuthorization(token, options = {}) {
  if (token === undefined || token === null || token === '') fail('PAYMENT_AUTHORIZATION_REQUIRED', '模拟支付需要 Owner 签署的单次支付授权。', 401);
  if (!objectWithKeys(options, VERIFY_KEYS, false) || !(options.trustedAuthorizers instanceof Set || Array.isArray(options.trustedAuthorizers)) ||
      ![...options.trustedAuthorizers].every(identity) || !roles(options.holderDid, options.deviceDid, options.verifierDid) || !credentialToken(options.credential)) {
    fail('INVALID_PAYMENT_AUTHORIZATION', '验证支付授权需要明确的可信 Owner 与完整的身份、VC 和支付条款。');
  }
  const now = options.now === undefined ? unix() : options.now;
  if (!Number.isSafeInteger(now) || now < 0) fail('INVALID_PAYMENT_AUTHORIZATION', '支付授权验证时间必须为非负整数 Unix 秒。');
  const payment = validatePayment(options.payment);
  let document, signerDid;
  try {
    const verified = verifyJws(token, { typ: PAYMENT_AUTH_TYP, purpose: 'assertionMethod' });
    document = verified.payload; signerDid = verified.signerDid;
  } catch (error) {
    throw new PaymentError('INVALID_PAYMENT_AUTHORIZATION', '支付授权签名、媒体类型或编码无效。', 401, { cause: error });
  }
  validateDocument(document);
  if (document.iss !== signerDid) fail('INVALID_PAYMENT_AUTHORIZATION', '支付授权声明的 Owner 与签名者不一致。', 401);
  const trusted = options.trustedAuthorizers instanceof Set ? options.trustedAuthorizers.has(signerDid) : options.trustedAuthorizers.includes(signerDid);
  if (!trusted) fail('PAYMENT_AUTHORIZER_UNTRUSTED', '支付授权签发者不在受信任 Owner 列表中。', 403);
  if (now < document.iat || now >= document.exp) fail('PAYMENT_AUTHORIZATION_EXPIRED', '支付授权尚未生效或已经过期。', 403);
  if (document.sub !== options.holderDid || document.deviceDid !== options.deviceDid || document.aud !== options.verifierDid || document.credentialHash !== digest(options.credential)) {
    fail('PAYMENT_AUTHORIZATION_BINDING_MISMATCH', '支付授权未绑定当前持有者、设备、接收方或 VC。', 403);
  }
  if (JSON.stringify(validatePayment(document.payment)) !== JSON.stringify(payment)) {
    fail('PAYMENT_TERMS_MISMATCH', '本次订单、付款方、收款方、金额或币种与 Owner 授权不一致。', 403);
  }
  return document;
}

export function paymentRpc(payment, authorization) {
  return {
    jsonrpc: '2.0', id: randomUUID(), method: 'message/send',
    params: { message: {
      kind: 'message', messageId: randomUUID(), role: 'user',
      parts: [{ kind: 'data', data: { scope: PAYMENT_SCOPE, payment: validatePayment(payment), authorization } }],
    } },
  };
}
