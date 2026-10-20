import { randomUUID } from 'node:crypto';
import { AppError, digest, unix } from '../protocol.mjs';
import { verifyJws } from '../identity.mjs';
import { PAYMENT_SCOPE, validatePayment } from '../payment.mjs';
import { preparePresentation, finalizePresentation, generateDeviceKey, signDeviceRequest, verifyDeviceResponse } from './crypto.mjs';
import { DBAC_PAYMENT_PROFILE, DBAC_PAYMENT_RESPONSE_TYP, verifyDbacPaymentAuthorization } from './payment-policy.mjs';

const fail = (code, message, status = 409) => { throw new AppError(code, message, status); };
const liveStages = new Set(['CHALLENGE_READY', 'VC_DERIVED', 'DEVICE_SIGNED', 'PROOF_READY']);
const verifiedStages = new Set(['VERIFIED', 'OWNER_SUBMITTED', 'WALLET_SIGNED', 'SETTLED']);
const phases = ['proposal', 'authorize', 'settle'];
const publicError = error => ({ code: error.code ?? 'ERROR', message: error.message, ...Object.fromEntries(['transaction', 'transactionHash', 'settlementResponse', 'verificationTrace'].filter(key => error[key] !== undefined).map(key => [key, structuredClone(error[key])])) });

// In-memory presentation states and order randomizers remain private to A.
// Every action has one visible protocol effect. Reads only fetch device health.
export function createDbacPaymentManual({ entry, requireCredential, challengeFor, deviceRequest, deviceHealth, transmit, ownerRequest, acceptProposal, syncOwner, issuer, verifierDid, owner, x402Payer, state, w3cEnabled = false, prepareCredential, credentialBinding, signHolder, cancelChallenge }) {
  const flows = new WeakMap();
  function flow(e) {
    if (!flows.has(e)) flows.set(e, { active: false, busy: false, attempt: null, log: [], payload: null, walletRequested: false, authorizeResult: null, settled: false, lastError: null, lastAttack: null });
    return flows.get(e);
  }
  function event(f, from, to, action, status, summary, data) {
    f.log.push({ id: randomUUID(), time: new Date().toISOString(), from, to, action, status, summary, ...(data === undefined ? {} : { data: structuredClone(data) }) });
    if (f.log.length > 100) f.log.splice(0, f.log.length - 100);
  }
  function checkedAuthorization(e) {
    requireCredential(e);
    if (!e.authorization) fail('OWNER_CONFIRMATION_REQUIRED', '请逐笔批准并显式同步 Owner 授权，再开始付款验证。', 403);
    verifyDbacPaymentAuthorization(e.authorization.token, { trustedAuthorizers: [owner.did], verifierDid, issuerPublicKey: issuer.publicKey, payment: e.order, mode: e.mode, orderKey: e.orderKey, ...(w3cEnabled ? { credentialBinding: credentialBinding(e) } : {}) });
    return e.authorization.token;
  }
  function expiry(a) {
    if (!a) return null;
    if (liveStages.has(a.stage)) return a.context.exp;
    if (a.stage === 'VERIFIED' && ['proposal', 'authorize'].includes(a.phase)) return a.evidenceExpiry;
    return null;
  }
  function expired(a) { const end = expiry(a); return end !== null && end <= unix(); }
  function fresh(a) { if (expired(a)) fail('DBAC_CHALLENGE_EXPIRED', '当前挑战或验证证据已过期，请显式重新开始本阶段；不会自动调用设备。', 401); }
  function actions(e, f) {
    if (f.busy) return [];
    const a = f.attempt, result = [];
    if (!f.active) {
      if (e.credential && (!e.proposal || ['REJECTED', 'EXPIRED'].includes(e.proposal.status))) result.push('begin-proposal');
      if (e.proposal) result.push('sync-owner');
      if (e.authorization) result.push('begin-authorize');
      if (f.payload && f.authorizeResult) result.push('begin-settle');
      return result;
    }
    if (a.phase !== 'proposal' || !e.proposal || ['REJECTED', 'EXPIRED'].includes(e.proposal.status)) result.push(`begin-${a.phase}`);
    result.push('discard');
    if (!expired(a)) {
      if (a.stage === 'CHALLENGE_READY' && w3cEnabled) result.push('derive-vc');
      if (a.stage === (w3cEnabled ? 'VC_DERIVED' : 'CHALLENGE_READY')) result.push('device-sign', 'test-wrong-device');
      if (a.stage === 'DEVICE_SIGNED') result.push('prove');
      if (a.stage === 'PROOF_READY') result.push('verify', 'test-tamper');
      if (liveStages.has(a.stage) && (!w3cEnabled || a.verifiableCredential)) result.push('test-no-device');
      if (a.stage === 'VERIFIED' && a.phase === 'proposal') result.push('submit-owner');
      if (a.stage === 'VERIFIED' && a.phase === 'authorize') result.push('wallet-sign');
    }
    if (verifiedStages.has(a.stage)) result.push('replay');
    if (e.proposal) result.push('sync-owner');
    if (e.credential && e.proposal && ['REJECTED', 'EXPIRED'].includes(e.proposal.status)) result.push('begin-proposal');
    if (e.authorization && (a.stage === 'OWNER_SUBMITTED' || f.payload || a.stage === 'SETTLED')) result.push('begin-authorize');
    if (f.payload && f.authorizeResult) result.push('begin-settle');
    return [...new Set(result)];
  }
  const preparedForTransport = a => ({ rawBody: a.rawBody, context: a.context, presentation: a.presentation, verifiableCredential: a.verifiableCredential, holderProof: a.holderProof, mode: a.mode, phase: a.phase, payment: a.payment, authorization: a.authorization, payload: a.payload, timings: {} });
  async function snapshot(e) {
    let device;
    try {
      const health = await deviceHealth(e);
      device = { backend: health.backend, hardware: health.hardware, keyExportable: health.keyExportable, modes: health.modes, publicKeyFingerprint: digest(health.publicKeys[e.mode]), publicKey: health.publicKeys[e.mode], available: true };
    } catch (error) { device = { backend: 'node-bls12-381', hardware: false, keyExportable: false, available: false, error: publicError(error) }; }
    const f = flow(e), a = f.attempt;
    const end = expiry(a);
    return { active: f.active, attemptId: a?.id ?? null, phase: a?.phase ?? null, stage: a ? (expired(a) ? 'EXPIRED' : a.stage) : 'IDLE',
      expiresAt: end === null ? null : new Date(end * 1000).toISOString(), expiresAtUnix: end, expired: expired(a), challengeExpiresAt: a ? new Date(a.context.exp * 1000).toISOString() : null,
      challenge: structuredClone(a?.context ?? null), deviceRequest: structuredClone(a?.prepared?.request ?? null), deviceResponse: structuredClone(a?.deviceResponse ?? null),
      holderProof: a?.holderProof ?? null, presentation: structuredClone(a?.presentation ?? null), verificationResult: structuredClone(a?.verified ?? null),
      verifiableCredential: structuredClone(a?.verifiableCredential ?? null), sentCredential: structuredClone(a?.sentCredential ?? null),
      cryptography: structuredClone(a?.cryptography ?? null),
      ownerSubmitted: Boolean(e.proposal), ownerApproved: Boolean(e.authorization), walletSigned: Boolean(f.payload), walletSigningUnconfirmed: f.walletRequested && !f.payload, walletPayload: structuredClone(f.payload), settled: f.settled,
      credentialPresent: Boolean(e.credential), device, lastError: structuredClone(f.lastError), lastAttack: structuredClone(f.lastAttack), log: structuredClone(f.log), availableActions: actions(e, f) };
  }
  const api = {
    active: e => flow(e).active,
    guard(e) { const f = flow(e); if (f.active || f.busy) fail('DBAC_MANUAL_ACTIVE', '手动消息演示正在进行，请先明确丢弃当前挑战再使用自动接口或更换订单。'); if (f.walletRequested && !f.settled) fail('DBAC_PAYMENT_PENDING', '本订单已请求钱包签名或待确认结算，必须保留原订单并用手动流程核对；不能更换订单或凭证。'); },
    reset(e) { flows.delete(e); },
    snapshot,
    async act({ mode = 'bbs-bls', action, attemptId } = {}) {
      const e = entry(mode), f = flow(e), previous = f.attempt;
      if (f.busy) fail('DBAC_MANUAL_BUSY', '已有手动消息正在处理。');
      if ((f.active || attemptId !== undefined) && attemptId !== previous?.id) fail('DBAC_MANUAL_ATTEMPT_MISMATCH', '此操作来自旧页面或旧挑战，请刷新当前手动状态。');
      if (previous && ['derive-vc', 'device-sign', 'prove', 'verify', 'submit-owner', 'wallet-sign'].includes(action)) fresh(previous);
      if (!actions(e, f).includes(action)) fail('DBAC_MANUAL_STAGE', '当前阶段不允许此消息操作，请按可用操作手动推进。');
      f.busy = true; f.lastError = null; f.lastAttack = null;
      try {
        if (action.startsWith('begin-')) {
          const phase = action.slice(6);
          if (previous) await cancelChallenge?.(previous.context);
          if (!phases.includes(phase)) fail('DBAC_MANUAL_STAGE', '无效支付阶段。');
          const credential = requireCredential(e), authorization = phase === 'proposal' ? undefined : checkedAuthorization(e);
          const payment = structuredClone(e.order), payload = phase === 'settle' ? f.payload : undefined;
          if (phase === 'settle' && (!payload || !f.authorizeResult)) fail('DBAC_MANUAL_STAGE', '请先手动完成钱包签名，才能发送结算证明。');
          const body = { jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: { message: { kind: 'message', role: 'user', messageId: randomUUID(), parts: [{ kind: 'data', data: { scope: PAYMENT_SCOPE, phase, payment, ...(authorization ? { authorization } : {}), ...(payload ? { payload } : {}) } }], ...(phase === 'settle' ? { taskId: f.authorizeResult.task.id, contextId: f.authorizeResult.task.contextId } : {}) } } };
          const rawBody = JSON.stringify(body);
          event(f, 'agent-a', 'agent-b', action, 'sent', '请求本阶段的新支付挑战；尚未调用模拟 eSIM。', { phase, bodyHash: digest(rawBody), paymentOrderId: payment.orderId });
          const context = await challengeFor(rawBody, mode, payment.orderId);
          const prepared = w3cEnabled ? null : preparePresentation({ credential, context, disclosedIndices: [0, 1, 2, 3], mode, paymentBinding: e.binding });
          f.attempt = { id: randomUUID(), mode, phase, stage: 'CHALLENGE_READY', rawBody, payment, authorization, payload: structuredClone(payload), context, prepared, presentation: null, deviceResponse: null, verified: null };
          f.active = true;
          event(f, 'agent-b', 'agent-a', action, 'received', w3cEnabled ? '收到真实挑战；下一步手动派生 W3C BBS 凭证，尚未调用设备。' : '收到真实挑战，已准备设备待签输入；需要下一次手动操作才发送给设备。', context);
        } else if (action === 'derive-vc') {
          fresh(previous);
          const derived = await prepareCredential(e, previous.context);
          fresh(previous);
          previous.prepared = derived.prepared;
          previous.verifiableCredential = derived.verifiableCredential;
          previous.cryptography = derived.cryptography;
          previous.stage = 'VC_DERIVED';
          event(f, 'agent-a', 'agent-a', action, 'completed', '已从 W3C VC 派生 bbs-2023 选择性披露证明；按所选披露策略生成。已准备绑定此派生 VC 的设备输入，尚未签名或提交 B。', { verifiableCredential: previous.verifiableCredential, cryptography: previous.cryptography });
        } else if (action === 'discard') {
          if (previous) await cancelChallenge?.(previous.context);
          f.active = false;
          if (previous) { previous.prepared = null; previous.presentation = null; previous.deviceResponse = null; previous.verified = null; previous.verifiableCredential = null; previous.sentCredential = null; previous.cryptography = null; previous.holderProof = null; previous.stage = 'DISCARDED'; }
          event(f, 'agent-a', 'agent-a', action, 'completed', '已丢弃当前挑战材料，原订单、Owner 授权及已产生的钱包签名继续保留。');
        } else if (action === 'sync-owner') {
          event(f, 'agent-a', 'owner', action, 'sent', '显式查询此订单的 Owner 决定。', { proposalId: e.proposal?.id });
          await syncOwner(e, true);
          event(f, 'owner', 'agent-a', action, 'received', '收到 Owner 当前状态；查询不会代替人工批准。', { status: e.proposal?.status, authorization: e.authorization?.document ?? null });
        } else if (action === 'device-sign') {
          fresh(previous);
          event(f, 'agent-a', 'device', action, 'sent', '向 Node BLS 模拟 eSIM 接口发送真实签名请求。', previous.prepared.request);
          previous.deviceResponse = await deviceRequest('/sign', previous.prepared.request, e.deviceId);
          previous.stage = 'DEVICE_SIGNED';
          event(f, 'device', 'agent-a', action, 'received', '模拟 eSIM 已返回设备签名贡献；尚未生成匿名证明或发送给 B。', previous.deviceResponse);
        } else if (action === 'prove') {
          fresh(previous);
          previous.presentation = finalizePresentation({ state: previous.prepared.state, response: previous.deviceResponse });
          if (e.orderKey && e.orderKey !== previous.presentation.randomizedDevicePublicKey) fail('DBAC_ORDER_KEY_CHANGED', '同一订单设备伪名发生变化，已停止。');
          e.orderKey = previous.presentation.randomizedDevicePublicKey;
          previous.holderProof = signHolder?.(preparedForTransport(previous));
          previous.stage = 'PROOF_READY';
          event(f, 'agent-a', 'agent-a', action, 'completed', '持有者 A 核验设备贡献，组合随机化凭证与知识证明，并用凭证专属私钥签署本次上下文与完整证明摘要；尚未发送给 B。', previous.presentation);
        } else if (action === 'verify') {
          fresh(previous);
          event(f, 'agent-a', 'agent-b', action, 'sent', previous.phase === 'settle' ? '发送绑定已签付款 payload 的新证明；本次明确操作将允许 B 验证后结算。' : '发送当前证明与精确支付正文，等待 B 实际验证。', { body: JSON.parse(previous.rawBody), presentation: previous.presentation, ...(previous.verifiableCredential ? { verifiableCredential: previous.verifiableCredential } : {}) });
          previous.sentCredential = previous.verifiableCredential ?? null;
          previous.verified = await transmit(preparedForTransport(previous));
          if (previous.phase === 'settle') {
            const result = previous.verified.paymentResult;
            let sameTerms = false;
            try { sameTerms = JSON.stringify(validatePayment(Object.fromEntries(Object.keys(previous.payment).map(key => [key, result?.receipt?.[key]])))) === JSON.stringify(validatePayment(previous.payment)); } catch { /* Preserve the original signed order until a verified final receipt is available. */ }
            if (previous.verified.task?.status?.state !== 'completed' || !['EXECUTED', 'ALREADY_PROCESSED'].includes(result?.outcome) || !sameTerms) fail('DBAC_PAYMENT_RECEIPT_INVALID', 'B 尚未返回匹配本订单的最终结算回执；请保留原订单查询，不能将结算门槛当作付款成功。', 502);
          }
          previous.evidenceExpiry = verifyJws(previous.verified.responseEvidence.proof, { typ: DBAC_PAYMENT_RESPONSE_TYP, purpose: 'authentication', expectedDid: verifierDid }).payload.exp;
          previous.stage = previous.phase === 'settle' ? 'SETTLED' : 'VERIFIED';
          e.lastResult = previous.verified;
          if (previous.phase === 'settle') f.settled = true;
          event(f, 'agent-b', 'agent-a', action, 'received', previous.phase === 'proposal' ? 'B 已核验支付资格；还没有提交 Owner 或授权付款。' : previous.phase === 'authorize' ? 'B 已核验论文证明及 Owner 授权并返回付款要求；钱包尚未签名。' : 'B 返回实际支付回执。', { task: previous.verified.task, verificationTrace: previous.verified.verificationTrace });
        } else if (action === 'submit-owner') {
          fresh(previous);
          if (e.proposal && ['PENDING', 'APPROVED'].includes(e.proposal.status)) fail('DBAC_PROPOSAL_EXISTS', '此订单已经提交 Owner，请显式同步原提案。');
          event(f, 'agent-a', 'owner', action, 'sent', '向 Owner 提交已由 B 验证的订单与资格证据；等待人工批准。', { payment: e.order, orderKey: e.orderKey, mode });
          const proposal = await ownerRequest('/proposals', { profile: DBAC_PAYMENT_PROFILE, payment: e.order, dbacEvidence: previous.verified.responseEvidence });
          acceptProposal(e, proposal); previous.stage = 'OWNER_SUBMITTED';
          event(f, 'owner', 'agent-a', action, 'received', 'Owner 已接收提案，尚需用户逐笔确认。', { proposalId: proposal.id, status: proposal.status, payment: proposal.payment });
        } else if (action === 'wallet-sign') {
          fresh(previous);
          const authorization = checkedAuthorization(e);
          if (authorization !== previous.authorization) fail('PAYMENT_AUTHORIZATION_BINDING_MISMATCH', 'Owner 授权已变化，请重新手动核验 authorize 阶段。');
          const paymentRequired = previous.verified.task.status.message.metadata['x402.payment.required'];
          event(f, 'agent-a', 'wallet', action, 'sent', '请求钱包独立核验 B 的 authorize 证据及 Owner 精确授权，再签署测试代币付款。', { payment: e.order, paymentRequired });
          f.walletRequested = true;
          f.payload = await x402Payer.createPayload({ profile: DBAC_PAYMENT_PROFILE, payment: e.order, authorization, paymentRequired, responseEvidence: previous.verified.responseEvidence });
          f.authorizeResult = previous.verified; previous.stage = 'WALLET_SIGNED';
          event(f, 'wallet', 'agent-a', action, 'received', '钱包返回绑定原订单的付款签名；尚未提交结算，下一阶段仍需新的设备证明。', f.payload);
        } else {
          let expected, actual, error, source, data;
          try {
            if (action === 'test-wrong-device') {
              fresh(previous); expected = 'DBAC_DEVICE_SIGNATURE_INVALID'; source = 'agent-a';
              const attacker = generateDeviceKey();
              const response = signDeviceRequest({ deviceSecretKey: attacker.secretKey, request: previous.prepared.request });
              data = { credentialPresent: true, originalDeviceFingerprint: digest(e.credential.devicePublicKey), attackerDeviceFingerprint: digest(attacker.publicKey), attackerPublicKey: attacker.publicKey, request: previous.prepared.request, response };
              // A copied credential does not change its bound public key. This
              // real signature is rejected before any presentation reaches B.
              verifyDeviceResponse({ devicePublicKey: e.credential.devicePublicKey, request: previous.prepared.request, response });
            } else {
              source = 'agent-b';
              let prepared = preparedForTransport(previous), options;
              if (action === 'test-no-device') { fresh(previous); expected = w3cEnabled ? 'W3C_DEVICE_PROOF_REQUIRED' : 'DBAC_INVALID_ENVELOPE'; options = w3cEnabled ? { omitDeviceProof: true } : { omitProof: true }; data = { credentialPresent: true, w3cCredentialSent: w3cEnabled, deviceProofPresent: false, deviceCalled: false }; }
              else if (action === 'test-tamper') { fresh(previous); expected = 'DBAC_BODY_MISMATCH'; const body = JSON.parse(previous.rawBody); body.params.message.parts[0].data.payment.amountMinor++; prepared = { ...prepared, rawBody: JSON.stringify(body) }; data = { originalPayment: previous.payment, changedPayment: body.params.message.parts[0].data.payment }; }
              else if (action === 'replay') { expected = previous.context.exp <= unix() ? 'DBAC_CHALLENGE_EXPIRED' : 'DBAC_REPLAY'; data = { challengeId: previous.context.challengeId }; }
              else fail('DBAC_MANUAL_STAGE', '未知手动攻击操作。');
              if (previous.verifiableCredential) previous.sentCredential = previous.verifiableCredential;
              await transmit(prepared, options);
            }
            actual = 'ACCEPTED';
          } catch (caught) { actual = caught.code ?? 'ERROR'; error = publicError(caught); }
          if (action === 'test-wrong-device' && error) error.verificationTrace = { profile: DBAC_PAYMENT_PROFILE, source: 'agent-a', outcome: 'fail', steps: [{ id: 'device_contribution_binding', title: '核对设备贡献与绑定公钥', actor: 'agent-a', status: 'fail', code: actual, detail: '另一设备真实签署当前设备请求后，Agent A 使用凭证绑定的原设备公钥执行配对检查并拒绝；请求未发送给 B。' }] };
          f.lastAttack = { action, expected, actual, pass: actual === expected, source, ...(error ? { error } : {}), ...(error?.verificationTrace ? { verificationTrace: error.verificationTrace } : {}) };
          event(f, action === 'test-wrong-device' ? 'attacker-device' : 'agent-a', source, action, actual === expected ? 'rejected-as-expected' : 'unexpected', action === 'test-wrong-device' ? '复制凭证并由另一设备产生有效签名，在 Agent A 绑定原设备公钥的配对检查被拒绝；未发送给 B。' : '已单独执行本次攻击请求；原正确阶段不变。', { ...data, ...f.lastAttack });
        }
      } catch (error) {
        f.lastError = publicError(error);
        event(f, 'protocol', 'agent-a', action, 'failed', error.message, f.lastError);
        throw error;
      } finally { f.busy = false; }
      return state({ mode });
    },
  };
  return api;
}
