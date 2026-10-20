import { randomUUID } from 'node:crypto';
import { resolveDid, verifyCredential } from './identity.mjs';
import { AppError, digest, fetchWithTimeout, transmit } from './protocol.mjs';
import { PAYMENT_SCOPE, issuePaymentAuthorization, verifyPaymentAuthorization, paymentRpc, validatePayment } from './payment.mjs';

const KEYS = ['orderId', 'payerAccount', 'payeeAccount', 'amountMinor', 'currency'];
const newPayment = () => ({ orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 29900, currency: 'CNY' });
const equalPayment = (a, b) => { try { return JSON.stringify(validatePayment(a)) === JSON.stringify(validatePayment(b)); } catch { return false; } };
const fail = (code, message, status = 403) => { throw new AppError(code, message, status); };

// This client only submits proposals and retrieves signed results. It never
// receives Owner's signing key or Owner UI capability. The A key is used below
// solely by an explicit negative test that B must reject as an untrusted Owner.
export function createRemotePaymentSession({ issuer, agentA, verifierDid, device, owner, getCredential, invoke, prepare, invokeBare, admin, x402Payer, paymentInfo }) {
  try {
    resolveDid(owner.did);
    const endpoint = new URL(owner.baseUrl);
    if (owner.did === agentA.did || owner.did === issuer.did || endpoint.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(endpoint.hostname) || endpoint.origin !== owner.baseUrl || !/^[A-Za-z0-9_-]{43}$/.test(owner.proposalToken)) throw new Error();
  } catch { fail('OWNER_CONFIG_REQUIRED', '需要独立 Owner DID、回环地址及仅提案权限。', 500); }
  const makeOrder = () => paymentInfo ? validatePayment({ ...newPayment(), amountMinor: 2990000, currency: 'TEST_USDC', settlement: { network: paymentInfo.network, asset: paymentInfo.asset, payTo: paymentInfo.payees['merchant:keyboard'], payerAddress: paymentInfo.payerAddress } }) : newPayment();
  let order = makeOrder(), proposal = null, authorization = null, lastResult = null, revision = 0, syncSequence = 0;
  let ownerAvailable = true, ownerError = null;
  const ownerInfo = () => ({ did: owner.did, baseUrl: owner.baseUrl, available: ownerAvailable, ...(ownerError ? { error: ownerError } : {}) });
  function credential() {
    const current = getCredential();
    if (!current?.token) fail('NO_CREDENTIAL', '请先签发包含支付权限的 VC。', 400);
    if (current.revoked) fail('CREDENTIAL_REVOKED', '当前 VC 已撤销，请先重新签发。');
    const doc = verifyCredential(current.token, { trustedIssuers: [issuer.did], subjectDid: agentA.did, audience: verifierDid, scope: PAYMENT_SCOPE, requireDevice: true });
    if (doc.credentialSubject.deviceDid !== device.did) fail('CREDENTIAL_DEVICE_MISMATCH', '当前 VC 未绑定本次模拟设备。');
    return current;
  }
  const policy = token => ({ trustedAuthorizers: [owner.did], holderDid: agentA.did, deviceDid: device.did, verifierDid, credential: token, payment: order });
  async function request(path, body) {
    const response = await fetchWithTimeout(`${owner.baseUrl}${path}`, {
      method: body === undefined ? 'GET' : 'POST', headers: { 'X-Owner-Proposal': owner.proposalToken, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const data = await response.json();
    if (!response.ok) throw new AppError(data.error?.code ?? 'OWNER_UNAVAILABLE', data.error?.message ?? 'Owner 服务未返回有效结果。', response.status);
    return data;
  }
  function acceptProposal(value, expectedCredential) {
    if (!value || typeof value.id !== 'string' || !value.id || value.id.length > 256 ||
        !['PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'].includes(value.status) || !equalPayment(value.payment, order) ||
        value.credentialHash !== digest(expectedCredential) || value.holderDid !== agentA.did || value.deviceDid !== device.did || value.verifierDid !== verifierDid) {
      fail('INVALID_OWNER_RESPONSE', 'Owner 返回的提案与当前订单或凭证不一致。', 502);
    }
    let verified = null;
    if (value.status === 'APPROVED') {
      const document = verifyPaymentAuthorization(value.authorization?.token, policy(expectedCredential));
      verified = { id: document.authorizationId, token: value.authorization.token, document };
    }
    // Keep only known public proposal fields. Never proxy arbitrary Owner data.
    proposal = Object.fromEntries(['id', 'status', 'payment', 'credentialId', 'credentialHash', 'holderDid', 'deviceDid', 'verifierDid', 'createdAt', 'expiresAt'].map(key => [key, structuredClone(value[key])]));
    authorization = verified;
    ownerAvailable = true; ownerError = null;
  }
  async function syncProposal(strict = false) {
    if (!proposal) return;
    const expected = { revision, id: proposal.id, token: getCredential()?.token, sequence: ++syncSequence };
    const current = () => revision === expected.revision && proposal?.id === expected.id && getCredential()?.token === expected.token && syncSequence === expected.sequence;
    try {
      const value = await request(`/proposals/${encodeURIComponent(expected.id)}`);
      if (!current()) return;
      acceptProposal(value, expected.token);
    } catch (error) {
      if (!current()) return;
      if (['OWNER_PROPOSAL_EXPIRED', 'PAYMENT_AUTHORIZATION_EXPIRED'].includes(error.code)) {
        proposal.status = 'EXPIRED'; authorization = null;
      } else {
        ownerAvailable = false; ownerError = { code: error.code ?? 'OWNER_UNAVAILABLE', message: error.message };
        if (strict) throw error;
      }
    }
  }
  async function requireAuthorization() {
    if (!authorization && proposal) await syncProposal(true);
    if (!authorization) {
      if (proposal?.status === 'PENDING') fail('OWNER_APPROVAL_PENDING', '请到独立 Owner 页面核对并确认，再同步授权。');
      if (proposal?.status === 'REJECTED') fail('OWNER_APPROVAL_REJECTED', 'Owner 已拒绝这笔提案；A 不能代替用户批准。');
      if (proposal?.status === 'EXPIRED') fail('PAYMENT_AUTHORIZATION_EXPIRED', '提案或授权已过期，请重新提交并由 Owner 确认。');
      fail('OWNER_CONFIRMATION_REQUIRED', '请先提交订单，并由独立 Owner 页面确认。');
    }
    verifyPaymentAuthorization(authorization.token, policy(credential().token));
    return authorization.token;
  }
  function result(response) {
    const matches = (response?.task?.artifacts ?? []).flatMap(artifact => (artifact.parts ?? []).filter(part => part.kind === 'data' && part.data?.paymentResult).map(part => part.data.paymentResult));
    const keys = order.currency === 'TEST_USDC' ? [...KEYS, 'settlement'] : KEYS;
    if (matches.length !== 1 || !['EXECUTED', 'ALREADY_PROCESSED'].includes(matches[0].outcome) || !equalPayment(Object.fromEntries(keys.map(key => [key, matches[0].receipt?.[key]])), order)) fail('INVALID_PAYMENT_RESPONSE', 'B 未返回与当前订单一致的唯一支付回执。', 502);
    lastResult = structuredClone(matches[0]);
    return { ...response, paymentResult: structuredClone(lastResult) };
  }
  async function completePayment(response, token) {
    if (response.task.status.state !== 'input-required') return result(response);
    const metadata = response.task.status.message?.metadata;
    if (!x402Payer || metadata?.['x402.payment.status'] !== 'payment-required' || !metadata['x402.payment.required']) fail('X402_REQUIREMENTS_MISSING', '缺少可验证的 x402 付款要求。', 502);
    const payload = await x402Payer.createPayload({ paymentRequired: metadata['x402.payment.required'], authorization: token, credential: credential().token, payment: order, ...response.responseEvidence });
    const rpc = paymentRpc(order, token);
    rpc.params.message.taskId = response.task.id;
    rpc.params.message.contextId = response.task.contextId;
    rpc.params.message.metadata = { 'x402.payment.status': 'payment-submitted', 'x402.payment.payload': payload };
    const completed = await invoke(rpc);
    if (completed.task.status.state === 'failed') {
      const failure = completed.task.status.message?.metadata;
      const error = new AppError(failure?.['x402.payment.error'] ?? 'X402_PAYMENT_FAILED', completed.task.status.message?.parts?.find(p => p.kind === 'text')?.text ?? 'x402 支付未确认成功，请按原订单查询状态。', 502);
      if (completed.verificationTrace) error.verificationTrace = completed.verificationTrace;
      throw error;
    }
    const settled = result(completed);
    lastResult.paymentFlow = ['input-required', 'payment-submitted', completed.task.status.state];
    return { ...settled, paymentResult: structuredClone(lastResult), paymentFlow: lastResult.paymentFlow, paymentRequired: metadata['x402.payment.required'] };
  }
  async function pay() { const token = await requireAuthorization(); return completePayment(await invoke(paymentRpc(order, token)), token); }
  const session = {
    async state() {
      const [ledger] = await Promise.all([admin('/admin/ledger'), syncProposal()]);
      return { order: structuredClone(order), owner: ownerInfo(), proposal: structuredClone(proposal), authorization: structuredClone(authorization), lastResult: structuredClone(lastResult), ledger, paymentInfo };
    },
    async newOrder() { order = makeOrder(); session.invalidate(); return session.state(); },
    invalidate() { revision++; proposal = null; authorization = null; lastResult = null; },
    approve() { fail('OWNER_CONFIRMATION_REQUIRED', 'A 无权批准付款，请在独立 Owner 页面确认。'); },
    async propose(input) {
      if (!input || Object.keys(input).length !== 1 || !equalPayment(input.payment, order)) fail('PAYMENT_ORDER_CHANGED', '提交内容与当前订单不一致，请刷新并重新核对。', 409);
      const current = credential(), expectedRevision = revision;
      const value = await request('/proposals', { credential: current.token, payment: order });
      if (revision !== expectedRevision || getCredential()?.token !== current.token) fail('PAYMENT_ORDER_CHANGED', '提交期间凭证或订单已改变，请重新提交。', 409);
      acceptProposal(value, current.token);
      return session.state();
    },
    async sync() { await syncProposal(true); return session.state(); },
    pay, retry: pay,
    async demo() {
      const token = await requireAuthorization();
      const before = await admin('/admin/ledger');
      const existing = before.receipts.some(receipt => receipt.payerAccount === order.payerAccount && receipt.orderId === order.orderId);
      const expectedDelta = existing ? 0 : order.amountMinor;
      const results = [];
      const check = async (name, expected, action, detail) => {
        let actual, verificationTrace, verificationTraces;
        try {
          const value = await action();
          if (value && typeof value === 'object' && Object.hasOwn(value, 'actual')) ({ actual, verificationTrace, verificationTraces } = value);
          else actual = value;
        } catch (error) { actual = String(error.code ?? 'ERROR'); verificationTrace = error.verificationTrace; }
        results.push({ name, expected, actual, pass: actual === expected, detail,
          ...(verificationTrace ? { verificationTrace } : {}), ...(verificationTraces ? { verificationTraces } : {}) });
      };
      const denied = async (rpc, call = invoke) => { const response = await call(rpc); return { actual: 'ACCEPTED', verificationTrace: response.verificationTrace }; };
      await check('有效双签名但缺少 Owner 单笔授权', 'PAYMENT_AUTHORIZATION_REQUIRED', () => denied(paymentRpc(order)), 'A 与设备签名不能替代独立 Owner 的确认。');
      for (const [name, changed] of [['篡改已授权金额', { amountMinor: order.amountMinor + 1 }], ['篡改已授权收款方', { payeeAccount: 'merchant:other' }], ['替换已授权订单编号', { orderId: `urn:uuid:${randomUUID()}` }]]) {
        await check(name, 'PAYMENT_TERMS_MISMATCH', () => denied(paymentRpc({ ...order, ...changed }, token)), '即使重新获得双签名，也不能改变 Owner 已批准的条款。');
      }
      await check('有效单笔授权但缺少设备证明', 'DEVICE_PROOF_REQUIRED', () => denied(paymentRpc(order, token), invokeBare), '独立确认仍须配合绑定设备证明。');
      let sent, verificationTrace;
      await check('正常提交已由 Owner 确认的订单', existing ? 'ALREADY_PROCESSED' : 'EXECUTED', async () => {
        sent = await prepare(paymentRpc(order, token));
        const response = await completePayment(await transmit(sent), token);
        verificationTrace = response.verificationTrace;
        return { actual: response.paymentResult.outcome, verificationTrace };
      }, '本按钮使用既有 Owner 授权，不会代用户批准。');
      await check('原样重放已提交的支付请求', 'REPLAYED_CHALLENGE', async () => { const response = await transmit(sent); return { actual: 'ACCEPTED', verificationTrace: response.verificationTrace }; }, '旧挑战由 B 拒绝。');
      await check('新挑战重试同一授权与订单', 'ALREADY_PROCESSED', async () => { const response = await pay(); return { actual: response.paymentResult.outcome, verificationTrace: response.verificationTrace }; }, '新挑战不能重复扣款。');
      await check('8 个并发新挑战提交同一授权', '0 executed / 8 already processed / 0 rejected', async () => {
        const settled = await Promise.allSettled(Array.from({ length: 8 }, () => pay()));
        const count = outcome => settled.filter(item => item.status === 'fulfilled' && item.value.paymentResult.outcome === outcome).length;
        const verificationTraces = settled.map(item => item.status === 'fulfilled' ? item.value.verificationTrace : item.reason.verificationTrace).filter(Boolean);
        return { actual: `${count('EXECUTED')} executed / ${count('ALREADY_PROCESSED')} already processed / ${settled.filter(item => item.status === 'rejected').length} rejected`,
          verificationTrace: settled.find(item => item.status === 'rejected')?.reason.verificationTrace ?? verificationTraces[0], verificationTraces };
      }, '所有请求均获取新挑战与两份签名。');
      await check('A 自行签发 Owner 付款授权', 'PAYMENT_AUTHORIZER_UNTRUSTED', () => {
        const forged = issuePaymentAuthorization(agentA, { holderDid: agentA.did, deviceDid: device.did, verifierDid, credential: credential().token, payment: order });
        return denied(paymentRpc(order, forged));
      }, 'A 只能用自己的私钥造出声明；B 只信任独立 Owner DID。');
      const after = await admin('/admin/ledger');
      const balance = (snapshot, id) => snapshot.accounts.find(account => account.id === id)?.balanceMinor;
      await check('付款方模拟余额核对', balance(before, order.payerAccount) - expectedDelta, async () => balance(after, order.payerAccount), '仅首次执行扣款。');
      await check('收款方模拟余额核对', balance(before, order.payeeAccount) + expectedDelta, async () => balance(after, order.payeeAccount), '重复调用不增加入账。');
      await check('累计扣款次数核对', before.executionCount + (existing ? 0 : 1), async () => after.executionCount, '攻击请求不得增加执行次数。');
      return { ...(verificationTrace ? { verificationTrace } : {}), results, passed: results.filter(item => item.pass).length, total: results.length, beforeLedger: before, afterLedger: after, paymentResult: structuredClone(lastResult) };
    },
  };
  return session;
}
