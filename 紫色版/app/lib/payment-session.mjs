import { randomUUID } from 'node:crypto';
import { verifyCredential, verifyJws } from './identity.mjs';
import { AppError, transmit } from './protocol.mjs';
import { PAYMENT_SCOPE, PAYMENT_AUTH_TYP, issuePaymentAuthorization, paymentRpc } from './payment.mjs';

const PAYMENT_KEYS = ['orderId', 'payerAccount', 'payeeAccount', 'amountMinor', 'currency'];
const createOrder = () => ({ orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 29900, currency: 'CNY' });
const fail = (code, message, status = 400) => { throw new AppError(code, message, status); };
function exactObject(value, keys) {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && actual.every(key => typeof key === 'string' && keys.includes(key) && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
}

// Owner is the existing VC issuer, with a key distinct from Agent A. The
// console's explicit confirmation is checked here; this module does not mint
// VCs, unlock the device, or authorize a payment as a side effect of pay/retry.
export function createPaymentSession({ issuer, agentA, verifierDid, device, getCredential, invoke, prepare, invokeBare, admin }) {
  let order = createOrder(), authorization = null, lastResult = null;

  function confirm(input) {
    if (!exactObject(input, ['confirmed', 'payment']) || input.confirmed !== true) {
      fail('PAYMENT_CONFIRMATION_REQUIRED', '请核对当前收款方与金额，并明确确认这笔模拟支付。');
    }
    if (!exactObject(input.payment, PAYMENT_KEYS) || PAYMENT_KEYS.some(key => input.payment[key] !== order[key])) {
      fail('PAYMENT_ORDER_CHANGED', '确认内容与当前订单不一致，请重新读取并核对订单。', 409);
    }
  }

  function currentCredential() {
    const current = getCredential();
    if (!current?.token) fail('NO_CREDENTIAL', '请先签发包含支付权限的 VC。');
    if (current.revoked) fail('CREDENTIAL_REVOKED', '当前 VC 已撤销，请先重新签发。', 403);
    const document = verifyCredential(current.token, {
      trustedIssuers: [issuer.did], subjectDid: agentA.did, audience: verifierDid,
      scope: PAYMENT_SCOPE, requireDevice: true,
    });
    if (document.credentialSubject.deviceDid !== device.did) fail('CREDENTIAL_DEVICE_MISMATCH', '当前 VC 绑定的设备不是本次模拟设备。', 403);
    return current;
  }

  function signAuthorization() {
    const credential = currentCredential();
    const token = issuePaymentAuthorization(issuer, {
      holderDid: agentA.did, deviceDid: device.did, verifierDid,
      credential: credential.token, payment: structuredClone(order),
    });
    const { payload: document } = verifyJws(token, { typ: PAYMENT_AUTH_TYP, purpose: 'assertionMethod', expectedDid: issuer.did });
    authorization = { id: document.authorizationId, token, document };
  }

  function requireAuthorization() {
    if (!authorization) fail('PAYMENT_AUTHORIZATION_REQUIRED', '请先确认当前订单的单笔支付授权。', 403);
    currentCredential();
    return authorization.token;
  }

  function paymentResult(result) {
    const candidates = (result?.task?.artifacts || []).flatMap(artifact => (artifact.parts || []).filter(part => part.kind === 'data' && part.data?.paymentResult).map(part => part.data.paymentResult));
    if (candidates.length !== 1 || !['EXECUTED', 'ALREADY_PROCESSED'].includes(candidates[0].outcome) ||
        !candidates[0].receipt || PAYMENT_KEYS.some(key => candidates[0].receipt[key] !== order[key])) {
      fail('INVALID_PAYMENT_RESPONSE', 'A2A 任务未返回唯一且与当前订单一致的支付回执。', 502);
    }
    lastResult = structuredClone(candidates[0]);
    return { ...result, paymentResult: structuredClone(lastResult) };
  }

  async function pay() {
    const token = requireAuthorization();
    return paymentResult(await invoke(paymentRpc(structuredClone(order), token)));
  }

  const session = {
    async state() {
      const ledger = await admin('/admin/ledger');
      return { order: structuredClone(order), authorization: structuredClone(authorization), ledger: structuredClone(ledger), lastResult: structuredClone(lastResult) };
    },
    async newOrder() {
      order = createOrder();
      session.invalidate();
      return session.state();
    },
    async approve(input) {
      confirm(input);
      signAuthorization();
      return session.state();
    },
    pay,
    retry: pay,
    invalidate() { authorization = null; lastResult = null; },
    async demo(input) {
      confirm(input);
      signAuthorization();
      const before = await admin('/admin/ledger');
      const previouslyExecuted = before.receipts.some(receipt => receipt.payerAccount === order.payerAccount && receipt.orderId === order.orderId);
      const expectedOutcome = previouslyExecuted ? 'ALREADY_PROCESSED' : 'EXECUTED';
      const expectedDelta = previouslyExecuted ? 0 : order.amountMinor;
      const results = [];
      const check = async (name, expected, action, detail) => {
        let actual;
        try { actual = await action(); }
        catch (error) { actual = String(error.code ?? 'ERROR'); }
        results.push({ name, expected, actual, pass: actual === expected, detail });
      };
      const rejected = async (rpc, call = invoke) => { await call(rpc); return 'ACCEPTED'; };
      await check('有效双签名但缺少 Owner 单笔授权', 'PAYMENT_AUTHORIZATION_REQUIRED', () => rejected(paymentRpc(order)), 'VC 和双签名只证明调用资格，不能代替本次付款确认。');
      for (const [name, changed] of [
        ['篡改已授权金额', { amountMinor: order.amountMinor + 1 }],
        ['篡改已授权收款方', { payeeAccount: 'merchant:other' }],
        ['替换已授权订单编号', { orderId: `urn:uuid:${randomUUID()}` }],
      ]) {
        await check(name, 'PAYMENT_TERMS_MISMATCH', () => rejected(paymentRpc({ ...order, ...changed }, authorization.token)), '重新获取有效双签名也不能改变 Owner 已签署的支付条款。');
      }
      await check('有效单笔授权但缺少设备证明', 'DEVICE_PROOF_REQUIRED', () => rejected(paymentRpc(order, authorization.token), invokeBare), 'Owner 授权不取消绑定设备的共同签名要求。');
      let originalRequest;
      await check('正常提交已确认订单', expectedOutcome, async () => {
        originalRequest = await prepare(paymentRpc(order, authorization.token));
        return paymentResult(await transmit(originalRequest)).paymentResult.outcome;
      }, previouslyExecuted ? '当前订单已有回执，本次验收只返回原回执。' : '当前订单首次执行，模拟余额应只扣除一次。');
      await check('原样重放已提交的支付请求', 'REPLAYED_CHALLENGE', async () => {
        if (!originalRequest) fail('PAYMENT_DEMO_NOT_PREPARED', '正常支付请求未能生成。');
        await transmit(originalRequest); return 'ACCEPTED';
      }, '复用已消费挑战会在认证层被拒绝。');
      await check('新挑战重试同一授权与订单', 'ALREADY_PROCESSED', async () => (await session.retry()).paymentResult.outcome, '新 nonce 不能绕过账本的授权与订单幂等检查。');
      await check('8 个并发新挑战提交同一授权', '0 executed / 8 already processed / 0 rejected', async () => {
        const settled = await Promise.allSettled(Array.from({ length: 8 }, () => session.retry()));
        const first = settled.filter(item => item.status === 'fulfilled' && item.value.paymentResult.outcome === 'EXECUTED').length;
        const duplicates = settled.filter(item => item.status === 'fulfilled' && item.value.paymentResult.outcome === 'ALREADY_PROCESSED').length;
        const rejectedCount = settled.filter(item => item.status === 'rejected').length;
        return `${first} executed / ${duplicates} already processed / ${rejectedCount} rejected`;
      }, '每个请求都有自己的挑战和双签名，账本仍不能再次扣款。');
      await check('重新签署同一订单的 Owner 授权', 'ALREADY_PROCESSED', async () => {
        // The user explicitly approved these exact terms for this demonstration.
        signAuthorization();
        return (await session.pay()).paymentResult.outcome;
      }, '更换 authorizationId 仍受稳定订单编号约束，返回原付款回执。');
      const after = await admin('/admin/ledger');
      const balance = (snapshot, id) => snapshot.accounts.find(account => account.id === id)?.balanceMinor;
      await check('付款方模拟余额核对', balance(before, order.payerAccount) - expectedDelta, async () => balance(after, order.payerAccount), '首次只扣本笔金额，重复验收当前订单不再扣款。');
      await check('收款方模拟余额核对', balance(before, order.payeeAccount) + expectedDelta, async () => balance(after, order.payeeAccount), '收款方只在本笔首次执行时入账。');
      await check('累计扣款次数核对', before.executionCount + (previouslyExecuted ? 0 : 1), async () => after.executionCount, '攻击请求、并发重试与重新签授权不能增加执行次数。');
      return { results, passed: results.filter(result => result.pass).length, total: results.length, beforeLedger: before, afterLedger: after, paymentResult: structuredClone(lastResult) };
    },
  };
  return session;
}
