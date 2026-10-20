import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { generateIdentity, signJws } from '../identity.mjs';
import { serializeIdentity, deserializeIdentity, AppError } from '../protocol.mjs';
import { MERCHANT_ORDER_TYP, merchantOrderHash, validateMerchantOrder, canonicalOrder } from './merchant-protocol.mjs';

async function atomic(path, value, mode = 0o600) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  await writeFile(temporary, JSON.stringify(value, null, 2), { mode });
  await rename(temporary, path);
}
export async function loadMerchantIdentity(directory) {
  await mkdir(directory, { recursive: true });
  const path = resolve(directory, 'identity.json');
  try { return deserializeIdentity(JSON.parse(await readFile(path, 'utf8'))); }
  catch (error) { if (error.code !== 'ENOENT') throw new Error('商家身份文件损坏，不能替换已有商家身份。'); }
  const identity = generateIdentity('MyStore local merchant');
  await atomic(path, serializeIdentity(identity));
  return identity;
}

export async function createLocalMerchant({ directory, trusted, paymentInfo, queryPayment, emit = () => {} }) {
  const identity = await loadMerchantIdentity(directory);
  if (identity.did !== trusted.did) throw new Error('商家身份与可信配置不一致');
  let failConfirmationOnce = false;
  const pathFor = orderId => {
    if (!/^urn:uuid:[0-9a-f-]{36}$/.test(orderId)) throw new AppError('MERCHANT_ORDER_INVALID', '商家订单编号无效。');
    return resolve(directory, `${orderId.slice(9)}.json`);
  };
  const read = async orderId => {
    try {
      const record = JSON.parse(await readFile(pathFor(orderId), 'utf8'));
      validateMerchantOrder(record.payment.merchantOrder, record.payment, { trusted, paymentInfo, allowExpired: true });
      if (record.orderId !== orderId) throw new Error('Order mismatch');
      return record;
    } catch (error) { if (error.code === 'ENOENT') throw new AppError('MERCHANT_ORDER_NOT_FOUND', '商家未找到该订单。', 404); throw error; }
  };
  function notify(action, status, order, detail) {
    try { emit({ type: 'business', source: 'merchant-service', action, status, title: action === 'merchant-order' ? '商家签发商品订单' : '商家核对付款结果', orderId: order.orderId, phase: 'merchant', detail, data: { snapshotHash: order.payment.merchantOrder.snapshotHash, merchantStatus: order.status, receiptHash: order.receiptHash ?? null } }); } catch { /* Observer failure never changes payment. */ }
  }
  function view(order) {
    return { status: order.status, merchantId: 'mystore', orderId: order.orderId, snapshotHash: order.payment.merchantOrder.snapshotHash, orderVersion: order.payment.merchantOrder.snapshot.orderVersion, snapshot: order.payment.merchantOrder.snapshot, receiptHash: order.receiptHash ?? null, confirmedAt: order.confirmedAt ?? null, lastError: order.lastError ?? null };
  }
  return {
    async create(items, orderVersion) {
      const orderId = `urn:uuid:${randomUUID()}`, createdAt = new Date().toISOString();
      const settlement = { network: paymentInfo.network, asset: paymentInfo.asset.toLowerCase(), payTo: paymentInfo.payees['merchant:keyboard'].toLowerCase(), payerAddress: paymentInfo.payerAddress.toLowerCase() };
      const snapshot = { type: 'MyStoreOrderSnapshot', version: 1, merchantDid: identity.did, merchantId: 'mystore', orderId, orderVersion, createdAt, validUntil: new Date(Date.now() + 15 * 60_000).toISOString(), payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', currency: 'TEST_USDC', amountMinor: items.reduce((n, i) => n + i.amountMinor, 0), settlement,
        items: items.map(({ id: productId, name, quantity, unitAmountMinor, amountMinor }) => ({ productId, name, quantity, unitAmountMinor, amountMinor })).sort((a, b) => a.productId.localeCompare(b.productId)) };
      const snapshotHash = merchantOrderHash(snapshot);
      const merchantOrder = { snapshot, snapshotHash, signature: signJws({ type: 'SignedMyStoreOrder', version: 1, iss: identity.did, snapshotHash, snapshot }, identity, MERCHANT_ORDER_TYP) };
      const payment = { orderId, payerAccount: snapshot.payerAccount, payeeAccount: snapshot.payeeAccount, amountMinor: snapshot.amountMinor, currency: snapshot.currency, settlement, merchantOrder };
      validateMerchantOrder(merchantOrder, payment, { trusted, paymentInfo, allowLegacy: false });
      const record = { orderId, payment, status: 'created', createdAt };
      await atomic(pathFor(orderId), record); notify('merchant-order', 'complete', record, '商家已签署商品、数量、价格、收款目标及订单版本。');
      return { payment, merchant: view(record) };
    },
    async state(orderId) { return orderId ? view(await read(orderId)) : { status: 'none', merchantId: 'mystore' }; },
    async confirm(orderId, suppliedReceipt) {
      const record = await read(orderId);
      notify('merchant-confirm', 'start', record, '商家独立查询原 x402 账本，不以购物页面显示的成功为依据。');
      try {
        const result = await queryPayment({ payment: record.payment });
        const receipt = result?.receipt;
        if (result?.status !== 'confirmed' || receipt?.transactionStatus !== 'success' || !/^0x[0-9a-f]{64}$/i.test(receipt.transactionHash ?? '') || canonicalOrder(Object.fromEntries(Object.keys(record.payment).map(k => [k, receipt?.[k]]))) !== canonicalOrder(record.payment)) throw new AppError('MERCHANT_PAYMENT_UNCONFIRMED', '商家尚未查到匹配本订单的已确认付款。', 409);
        if (suppliedReceipt && suppliedReceipt.transactionHash !== receipt.transactionHash) throw new AppError('MERCHANT_RECEIPT_MISMATCH', '页面回执与商家独立查询的原交易不一致。', 409);
        if (record.receiptHash && record.receiptHash !== receipt.transactionHash) throw new AppError('MERCHANT_RECEIPT_MISMATCH', '已确认商家订单不能替换付款交易。', 409);
        record.status = 'payment-confirmed'; record.receiptHash = receipt.transactionHash; await atomic(pathFor(orderId), record);
        if (failConfirmationOnce) { failConfirmationOnce = false; throw new AppError('MERCHANT_CONFIRMATION_DELAYED', '付款已确认，商家订单确认暂未完成；请查询原订单。', 503); }
        record.status = 'confirmed'; record.confirmedAt ??= new Date().toISOString(); delete record.lastError; await atomic(pathFor(orderId), record);
        notify('merchant-confirm', 'complete', record, '商家已独立核对原交易、收款目标、金额和完整商品快照，订单确认完成。');
        return { merchant: view(record), receipt };
      } catch (error) { record.lastError = { code: error.code ?? 'MERCHANT_ERROR', message: error.message }; await atomic(pathFor(orderId), record); notify('merchant-confirm', 'fail', record, error.message); throw error; }
    },
    fault(enabled) { failConfirmationOnce = enabled; return { confirmationDelayOnce: failConfirmationOnce }; },
  };
}
