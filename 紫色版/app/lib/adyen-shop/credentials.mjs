import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { generateIdentity, signJws, verifyJws } from '../identity.mjs';
import { AppError, digest, unix } from '../protocol.mjs';
import { createW3cBbsVerifier, deriveCredential } from '../w3c-bbs.mjs';
import { createPaymentBinding, preparePresentation, finalizePresentation, verifyCredential, verifyPresentation } from '../dbac/crypto.mjs';
import { paymentAttributes, paymentDisclosures, DBAC_MODES } from '../dbac/policy.mjs';
import { W3C_PAYMENT_PROFILE, W3C_PAYMENT_SCHEMA, W3C_DISCLOSED_INDICES, presentationHeader, bindingContext, transcriptHash } from '../dbac/w3c-profile.mjs';
import { signHolderProof, verifyHolderProof } from '../dbac/holder-proof.mjs';
import { createCredentialStatusReader } from '../dbac/credential-status.mjs';

export const SHOP_ORIGIN = 'https://www.mystoredemo.io';
export const RECEIPT_TYPE = 'adyen-mystore-qualification+jwt';
export const PERMIT_TYPE = 'adyen-mystore-owner-permit+jwt';
const fail = (code, message, status = 403) => { throw new AppError(code, message, status); };
export const sameSecret = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && timingSafeEqual(Buffer.from(a), Buffer.from(b));
export function validateShopOrder(order) {
  const keys = ['id', 'provider', 'origin', 'productId', 'productName', 'quantity', 'amountMinor', 'currency', 'providerReference'];
  if (!order || Object.keys(order).sort().join() !== [...keys].sort().join() || !/^urn:uuid:[0-9a-f-]{36}$/.test(order.id) ||
    order.provider !== 'adyen-mystore' || order.origin !== SHOP_ORIGIN || order.productId !== '02' || order.productName !== 'Headphones' ||
    order.quantity !== 1 || order.currency !== 'EUR' || !Number.isSafeInteger(order.amountMinor) || order.amountMinor < 1 || order.amountMinor > 100000 ||
    !(order.providerReference === null || (typeof order.providerReference === 'string' && /^[A-Za-z0-9_:. -]{1,160}$/.test(order.providerReference)))) {
    fail('SHOP_ORDER_INVALID', '订单必须是 MyStore 演示商城的一副耳机，且金额、币种和商品字段完整。', 400);
  }
  return structuredClone(order);
}
export const orderHash = order => transcriptHash('adyen-mystore:order:v1', validateShopOrder(order));
export async function postJson(url, body, headers = {}) {
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(30000), redirect: 'error' });
  const result = await response.json();
  if (!response.ok) {
    const error = new AppError(result.error?.code ?? 'SHOP_UPSTREAM_ERROR', result.error?.message ?? '服务未完成请求。', response.status);
    error.steps = result.steps;
    throw error;
  }
  return result;
}

// Agent A reuses the supplied package's issuer, device, VC derivation and holder
// signature. Neither the private holder key nor the base credential reaches B.
export function createShopHolder({ issuer, device, verifierDid }) {
  const verifier = createW3cBbsVerifier(issuer.w3c);
  let issued;
  const issuerCall = (path, body) => postJson(`${issuer.baseUrl}${path}`, body, { 'X-DBAC-Access': issuer.accessToken });
  const deviceCall = (path, body) => postJson(`${device.baseUrl}${path}`, body, { 'X-DBAC-Access': device.accessToken });
  return {
    info() { return issued ? { issuer: issuer.w3c.issuer, holderDid: issued.identity.did, bindingId: issued.bindingId, mode: issued.mode, credentialType: 'W3C VC / bbs-2023', device: '独立 Node BLS12-381 软件 eSIM 进程' } : null; },
    async issue(mode = 'bbs-bls') {
      if (!DBAC_MODES.includes(mode)) fail('SHOP_MODE_INVALID', '凭证方案不受支持。', 400);
      const identity = generateIdentity('MyStore shopper / Agent A');
      const enrollment = await issuerCall('/enroll/challenge', { mode, scope: 'payments:pay', holderDid: identity.did });
      const expected = [...paymentAttributes(mode), enrollment.bindingId];
      if (enrollment.request?.context?.purpose !== 'dbac-enrollment-v1' || enrollment.request.context.issuerPublicKey !== issuer.publicKey || enrollment.request.randomizedDevicePublicKey !== device.publicKeys[mode] || enrollment.request.context.attributeHash !== digest(JSON.stringify(expected))) fail('SHOP_ENROLLMENT_MISMATCH', '签发请求没有绑定当前设备及支付资格。');
      const response = await deviceCall('/enroll/sign', { mode, request: enrollment.request });
      const result = await issuerCall('/issue', { registrationId: enrollment.registrationId, response });
      verifyCredential(result.credential, { issuerPublicKey: issuer.publicKey });
      await verifier.verifyBase({ credential: result.verifiableCredential });
      if (result.credential.devicePublicKey !== device.publicKeys[mode] || JSON.stringify(result.credential.attributes) !== JSON.stringify(expected) || result.verifiableCredential.credentialSubject.holderDid !== identity.did) fail('SHOP_ISSUANCE_MISMATCH', '签发凭证与本地持有者或设备不符。');
      for (const [index, name] of W3C_PAYMENT_SCHEMA.entries()) if (result.verifiableCredential.credentialSubject[name] !== expected[index]) fail('SHOP_BINDING_MISMATCH', '标准凭证和设备材料不属于同次签发。');
      issued = { ...result, identity, bindingId: enrollment.bindingId, mode, orders: new Map() };
      return this.info();
    },
    async prove(context, order, { omitDevice = false, omitHolder = false } = {}) {
      if (!issued) fail('SHOP_CREDENTIAL_REQUIRED', '请先取得支付资格凭证。');
      if (context.verifier !== verifierDid || context.purpose !== 'dbac-payment-v1' || context.application !== 'adyen-mystore-checkout-v1' || context.paymentOrderId !== order.id || context.orderHash !== orderHash(order) || context.bodyHash !== context.orderHash || context.mode !== issued.mode || context.exp <= unix()) fail('SHOP_CHALLENGE_MISMATCH', '挑战没有绑定当前验证方、订单或凭证。');
      const vc = await deriveCredential({ credential: issued.verifiableCredential, issuerProfile: issuer.w3c, presentationHeader: presentationHeader(context) });
      if (!issued.orders.has(order.id)) issued.orders.set(order.id, createPaymentBinding({ credential: issued.credential, mode: issued.mode, orderId: order.id }));
      const prepared = preparePresentation({ credential: issued.credential, context: bindingContext(context, vc), disclosedIndices: W3C_DISCLOSED_INDICES, mode: issued.mode, paymentBinding: issued.orders.get(order.id) });
      const response = await deviceCall('/sign', prepared.request);
      const presentation = finalizePresentation({ state: prepared.state, response });
      const holderProof = signHolderProof({ identity: issued.identity, context, verifiableCredential: vc, presentation });
      return { challengeId: context.challengeId, order, verifiableCredential: vc, presentation: omitDevice ? {} : presentation, ...(!omitHolder ? { holderProof } : {}) };
    },
    async revoke() {
      if (!issued) fail('SHOP_CREDENTIAL_REQUIRED', '尚未签发凭证。');
      return issuerCall('/credentials/revoke', { bindingId: issued.bindingId });
    },
    async lock(locked) { return deviceCall('/lock', { locked, mode: issued?.mode ?? 'bbs-bls' }); },
  };
}

// This is a local Agent B gate. The public Adyen demo does not receive or verify
// these credentials; the local connector enforces this gate before its actions.
export function createShopVerifier({ identity, issuer, statusSource, ownerKey }) {
  const verifier = createW3cBbsVerifier(issuer.w3c);
  const readStatus = createCredentialStatusReader(statusSource);
  const challenges = new Map(), receipts = new Map();
  return {
    did: identity.did,
    challenge(order, mode = 'bbs-bls') {
      validateShopOrder(order);
      if (!DBAC_MODES.includes(mode)) fail('SHOP_MODE_INVALID', '凭证方案不受支持。', 400);
      for (const [id, entry] of challenges) if (entry.context.exp <= unix()) challenges.delete(id);
      for (const [id, entry] of receipts) if (entry.exp <= unix()) receipts.delete(id);
      if (challenges.size > 128) fail('SHOP_BUSY', '有效挑战过多。', 429);
      const context = { profile: W3C_PAYMENT_PROFILE, purpose: 'dbac-payment-v1', application: 'adyen-mystore-checkout-v1', scope: 'payments:pay', verifier: identity.did, mode, challengeId: randomUUID(), nonce: randomBytes(32).toString('base64url'), iat: unix(), exp: unix() + 60, paymentOrderId: order.id, bodyHash: orderHash(order), orderHash: orderHash(order), schema: [...W3C_PAYMENT_SCHEMA] };
      challenges.set(context.challengeId, { context, used: false });
      return { context: structuredClone(context), signature: signJws({ iss: identity.did, context }, identity, 'adyen-mystore-challenge+jwt') };
    },
    async verify({ challengeId, order, verifiableCredential, presentation, holderProof }) {
      const steps = [];
      const pass = (id, label) => steps.push({ id, label, status: 'pass' });
      try {
        const entry = challenges.get(challengeId);
        if (!entry || entry.context.exp <= unix()) fail('SHOP_CHALLENGE_EXPIRED', '订单挑战已过期，请重新验证。');
        if (entry.used) fail('SHOP_REPLAY', '本次挑战已经使用，旧证明不能再次放行。');
        const { context } = entry;
        if (context.orderHash !== orderHash(order)) fail('SHOP_ORDER_CHANGED', '商品、金额或订单编号变化，需要重新验证。');
        pass('order', '商品、金额和本次挑战匹配');
        await verifier.verifyDerived({ credential: verifiableCredential, presentationHeader: presentationHeader(context) });
        const subject = verifiableCredential.credentialSubject;
        const expected = paymentDisclosures(context.mode);
        if (subject.role !== expected[0] || subject.scope !== expected[1] || subject.epoch !== expected[2] || subject.mode !== context.mode || typeof subject.holderDid !== 'string' || !/^urn:uuid:[0-9a-f-]{36}$/.test(subject.bindingId)) fail('SHOP_SCOPE_DENIED', '凭证没有当前有效的支付资格。');
        pass('vc', '签发方的 bbs-2023 凭证有效');
        if (!presentation?.deviceSignature) fail('W3C_DEVICE_PROOF_REQUIRED', '缺少绑定 eSIM 的本次持有性证明。');
        if (presentation.attributeCount !== W3C_PAYMENT_SCHEMA.length || presentation.mode !== context.mode || presentation.disclosed?.find(x => x.index === 6)?.value !== subject.bindingId) fail('SHOP_DEVICE_BINDING', '凭证与设备证明没有绑定同一次签发。');
        verifyPresentation({ presentation, issuerPublicKey: issuer.publicKey, context: bindingContext(context, verifiableCredential), deviceFirst: true, requiredDisclosures: { ...expected, 6: subject.bindingId } });
        pass('device', '软件 eSIM 的设备贡献验证通过');
        verifyHolderProof({ holderProof, context, verifiableCredential, presentation });
        pass('holder', 'Agent 持有者签名验证通过');
        await readStatus({ bindingId: subject.bindingId, issuer: issuer.w3c.issuer, holderDid: subject.holderDid });
        pass('status', '签发方确认凭证未撤销');
        // Async proof/status checks must be followed by an atomic replay check.
        if (entry.used) fail('SHOP_REPLAY', '本次挑战已被另一请求使用。');
        if (context.exp <= unix()) fail('SHOP_CHALLENGE_EXPIRED', '验证期间挑战已过期。');
        entry.used = true;
        pass('nonce', '一次性挑战已消费');
        const claims = { iss: identity.did, id: randomUUID(), orderHash: context.orderHash, bindingId: subject.bindingId, iat: unix(), exp: unix() + 120 };
        receipts.set(claims.id, claims);
        return { accepted: true, steps, receipt: signJws(claims, identity, RECEIPT_TYPE), orderHash: context.orderHash, bindingId: subject.bindingId };
      } catch (error) {
        error.steps = [...steps, { id: error.code ?? 'verification', label: error.message, status: 'fail' }];
        throw error;
      }
    },
    approve({ receipt, order, suppliedOwnerKey }) {
      if (!sameSecret(ownerKey, suppliedOwnerKey)) fail('OWNER_CONFIRMATION_REQUIRED', '需要用户明确确认本次测试支付。');
      const { payload } = verifyJws(receipt, { typ: RECEIPT_TYPE, expectedDid: identity.did, purpose: 'authentication' });
      if (!receipts.has(payload.id) || payload.exp <= unix() || payload.orderHash !== orderHash(order) || !order.providerReference) fail('SHOP_APPROVAL_MISMATCH', '付款确认没有绑定有效验证结果与官方测试订单。');
      const permit = { iss: identity.did, id: randomUUID(), orderId: order.id, orderHash: payload.orderHash, providerReference: order.providerReference, iat: unix(), exp: unix() + 120, testOnly: true };
      return { permit: signJws(permit, identity, PERMIT_TYPE) };
    },
  };
}

export function verifyShopPermit(permit, order, verifierDid) {
  const { payload } = verifyJws(permit, { typ: PERMIT_TYPE, expectedDid: verifierDid, purpose: 'authentication' });
  if (payload.exp <= unix() || payload.iat > unix() + 5 || payload.orderHash !== orderHash(order) || payload.orderId !== order.id || payload.providerReference !== order.providerReference || payload.testOnly !== true) fail('SHOP_PERMIT_INVALID', '本次付款许可已失效或订单不符。');
  return payload;
}
