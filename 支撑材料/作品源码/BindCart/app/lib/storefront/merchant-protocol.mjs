import { createHash } from 'node:crypto';
import { verifyJws } from '../identity.mjs';
import { CATALOG, LEGACY_CATALOG, catalogProduct } from './catalog.mjs';

export const MERCHANT_ORDER_TYP = 'mystore-order-snapshot+jwt';
const fail = (code, message) => { throw Object.assign(new Error(message), { code, status: 403 }); };
const exact = (v, keys) => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).sort().join() === [...keys].sort().join();
export function canonicalOrder(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalOrder).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map(k => `${JSON.stringify(k)}:${canonicalOrder(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}
export const merchantOrderHash = v => createHash('sha256').update(canonicalOrder(v)).digest('base64url');

// Optional application binding. The existing BBS/device/Owner signatures bind
// this complete value through the unchanged payment body and payment digest.
export function validateMerchantOrder(value, payment, { trusted, paymentInfo, allowExpired = false, allowLegacy = true } = {}) {
  const s = value?.snapshot;
  const legacy = Array.isArray(s?.items) && s.items.length > 0 && s.items.every(item => LEGACY_CATALOG.some(product => product.id === item?.productId));
  const validItem = item => {
    const product = catalogProduct(item?.productId);
    return exact(item, ['productId', 'name', 'quantity', 'unitAmountMinor', 'amountMinor']) && product &&
      (!product.legacy || allowLegacy) && Boolean(product.legacy) === legacy &&
      item.name === product.name && Number.isInteger(item.quantity) && item.quantity >= 1 && item.quantity <= product.maxQuantity &&
      item.unitAmountMinor === product.unitAmountMinor && item.amountMinor === item.unitAmountMinor * item.quantity;
  };
  if (!exact(value, ['snapshot', 'snapshotHash', 'signature']) || !exact(s, ['type', 'version', 'merchantDid', 'merchantId', 'orderId', 'orderVersion', 'createdAt', 'validUntil', 'payerAccount', 'payeeAccount', 'currency', 'amountMinor', 'settlement', 'items']) ||
      s.type !== 'MyStoreOrderSnapshot' || s.version !== 1 || s.merchantId !== 'mystore' || !/^urn:uuid:[0-9a-f-]{36}$/.test(s.orderId) ||
      !Number.isSafeInteger(s.orderVersion) || s.orderVersion < 1 || !Number.isFinite(Date.parse(s.createdAt)) || !Number.isFinite(Date.parse(s.validUntil)) || Date.parse(s.validUntil) <= Date.parse(s.createdAt) ||
      s.payerAccount !== 'demo:alice' || s.payeeAccount !== 'merchant:keyboard' || s.currency !== 'TEST_USDC' || !Number.isSafeInteger(s.amountMinor) || s.amountMinor < 1 || s.amountMinor > 1_000_000_000 ||
      !Array.isArray(s.items) || s.items.length < 1 || s.items.length > (legacy ? LEGACY_CATALOG.length : CATALOG.length) || new Set(s.items.map(i => i?.productId)).size !== s.items.length ||
      s.items.some(i => !validItem(i)) ||
      s.items.reduce((n, i) => n + i.amountMinor, 0) !== s.amountMinor || !exact(s.settlement, ['network', 'asset', 'payTo', 'payerAddress']) || !/^eip155:[1-9][0-9]*$/.test(s.settlement.network) || ['asset', 'payTo', 'payerAddress'].some(k => !/^0x[0-9a-f]{40}$/.test(s.settlement[k])) ||
      typeof value.signature !== 'string' || value.signature.length > 16384 || value.snapshotHash !== merchantOrderHash(s)) fail('MERCHANT_ORDER_INVALID', '商家订单快照、商品价格、版本或摘要无效。');
  let signed;
  try { signed = verifyJws(value.signature, { typ: MERCHANT_ORDER_TYP, purpose: 'assertionMethod', expectedDid: s.merchantDid }).payload; }
  catch { fail('MERCHANT_SIGNATURE_INVALID', '商家订单签名无效。'); }
  if (!exact(signed, ['type', 'version', 'iss', 'snapshotHash', 'snapshot']) || signed.type !== 'SignedMyStoreOrder' || signed.version !== 1 || signed.iss !== s.merchantDid || signed.snapshotHash !== value.snapshotHash || canonicalOrder(signed.snapshot) !== canonicalOrder(s)) fail('MERCHANT_SIGNATURE_INVALID', '订单快照与商家签署的原文不一致。');
  if (trusted && (s.merchantDid !== trusted.did || s.merchantId !== trusted.merchantId || s.payeeAccount !== trusted.payeeAccount)) fail('MERCHANT_UNTRUSTED', '订单签发商家不在验证方的可信配置中。');
  if (!allowExpired && (Date.parse(s.createdAt) > Date.now() + 5000 || Date.parse(s.validUntil) <= Date.now())) fail('MERCHANT_ORDER_EXPIRED', '商家报价已过期，请重新结算。');
  if (payment && (['orderId', 'payerAccount', 'payeeAccount', 'currency', 'amountMinor'].some(k => s[k] !== payment[k]) || canonicalOrder(s.settlement) !== canonicalOrder(payment.settlement))) fail('MERCHANT_PAYMENT_MISMATCH', '商品订单与付款条款、金额或收款目标不一致。');
  if (paymentInfo && (s.settlement.network !== paymentInfo.network || s.settlement.asset.toLowerCase() !== paymentInfo.asset.toLowerCase() || s.settlement.payTo.toLowerCase() !== paymentInfo.payees[s.payeeAccount]?.toLowerCase() || s.settlement.payerAddress.toLowerCase() !== paymentInfo.payerAddress.toLowerCase())) fail('MERCHANT_PAYEE_UNTRUSTED', '商家订单的链、资产或收款地址不在可信配置中。');
  return structuredClone(value);
}
