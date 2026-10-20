import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { generateIdentity, verifyJws } from '../identity.mjs';
import { AppError, digest, unix } from '../protocol.mjs';
import { PAYMENT_SCOPE, validatePayment } from '../payment.mjs';
import { preVerificationFailure } from '../verification-trace.mjs';
import { createPaymentBinding, preparePresentation, finalizePresentation, verifyCredential } from './crypto.mjs';
import { DBAC_EXTENSION, DBAC_MODES, DBAC_SCHEMA, paymentAttributes, paymentDisclosures } from './policy.mjs';
import { DBAC_PAYMENT_PROFILE, DBAC_PAYMENT_CHALLENGE_TYP, DBAC_PAYMENT_RESPONSE_TYP, verifyDbacPaymentEvidence, verifyDbacPaymentAuthorization } from './payment-policy.mjs';
import { createDbacPaymentManual } from './payment-manual.mjs';
import { createW3cBbsVerifier, deriveCredential } from '../w3c-bbs.mjs';
import { W3C_PAYMENT_PROFILE, W3C_PAYMENT_SCHEMA, W3C_DISCLOSED_INDICES, presentationHeader, bindingContext } from './w3c-profile.mjs';

import { signHolderProof } from './holder-proof.mjs';
import { createFrameworkAttackExperiments } from './attack-experiments.mjs';
import { createExperimentRuns } from './experiment-runs.mjs';

const samePayment = (a, b) => JSON.stringify(validatePayment(Object.fromEntries(Object.keys(validatePayment(b)).map(key => [key, a?.[key]])))) === JSON.stringify(validatePayment(b));
const modeValue = mode => { if (!DBAC_MODES.includes(mode)) throw new AppError('DBAC_INVALID_MODE', '不支持的论文方案。'); return mode; };
const fail = (code, message, status = 400) => { throw new AppError(code, message, status); };

async function request(url, { body, rawBody, headers = {}, includeHeaders = false } = {}) {
  const post = body !== undefined || rawBody !== undefined;
  let response;
  try {
    response = await fetch(url, { method: post ? 'POST' : 'GET', headers: { Accept: 'application/json', ...(post ? { 'Content-Type': 'application/json' } : {}), ...headers }, ...(post ? { body: rawBody ?? JSON.stringify(body) } : {}), signal: AbortSignal.timeout(30000), redirect: 'error' });
  } catch (error) { throw new AppError('DBAC_PAYMENT_TRANSPORT', '支付通信未完成；若已提交结算，请用同一订单核对回执。', 503); }
  const data = await response.json();
  if (!response.ok) {
    const error = new AppError(data.error?.code ?? 'DBAC_PAYMENT_HTTP_ERROR', data.error?.message ?? '支付请求未完成。', response.status);
    if (data.verificationTrace) error.verificationTrace = data.verificationTrace;
    for (const key of ['settlementResponse', 'transaction', 'transactionHash']) if (data.error?.[key] !== undefined) error[key] = data.error[key];
    throw error;
  }
  return includeHeaders ? { data, headers: Object.fromEntries(response.headers) } : data;
}

// Only public order state and signed evidence leave this session. The BBS
// credential and the opaque order randomizer remain inside Agent A.
export function createDbacPaymentSession({ baseUrl, verifierDid, issuer, device, owner, x402Payer, paymentInfo, getLedger }) {
  const entries = new Map(), credentials = new Map(), cancelHandles = new Map();
  const deviceRegistry = new Map([['default', { deviceId: 'default', publicKeys: device.publicKeys }]]);
  let experimentalSession;
  const holderView = e => e.holderIdentity ? { did: e.holderIdentity.did, keyFingerprint: digest(e.holderIdentity.did), storage: 'Agent A 进程内 KeyObject；每张凭证独立生成；不导出私钥' } : null;
  const signHolder = prepared => { const e = entry(prepared.mode); return e.holderIdentity && prepared.verifiableCredential ? signHolderProof({ identity: e.holderIdentity, context: prepared.context, verifiableCredential: prepared.verifiableCredential, presentation: prepared.presentation }) : undefined; };
  const w3cVerifier = issuer.w3c !== undefined ? createW3cBbsVerifier(issuer.w3c) : null;
  const credentialBinding = e => w3cVerifier ? { credentialProfile: W3C_PAYMENT_PROFILE, w3cIssuer: issuer.w3c.issuer, vcBindingId: e.credential.attributes[6] } : undefined;
  const attributesFor = (mode, bindingId) => [...paymentAttributes(mode), ...(w3cVerifier ? [bindingId] : [])];
  function makeOrder({ amountMinor = 2990000, payeeAccount = 'merchant:keyboard', orderId = `urn:uuid:${randomUUID()}`, merchantOrder } = {}) {
    if (!Number.isSafeInteger(amountMinor) || amountMinor < 1 || amountMinor > 1000000000) fail('DBAC_PAYMENT_INVALID_INPUT', '示例金额必须是 1 到 1000000000 之间的整数最小单位（最多 1000 TEST_USDC）。');
    if (typeof payeeAccount !== 'string' || !Object.hasOwn(paymentInfo.payees, payeeAccount)) fail('DBAC_PAYMENT_INVALID_INPUT', '请选择本地测试环境中已配置的收款商户。');
    // Editable demonstration terms never supply chain, asset or destination
    // addresses. Those values are resolved solely from the trusted runtime.
    return validatePayment({ orderId, ...(merchantOrder ? { merchantOrder } : {}), payerAccount: 'demo:alice', payeeAccount, amountMinor, currency: 'TEST_USDC', settlement: { network: paymentInfo.network, asset: paymentInfo.asset, payTo: paymentInfo.payees[payeeAccount], payerAddress: paymentInfo.payerAddress } });
  }
  function guardAutomaticSettlement(e) {
    if (e.paymentPending) fail('DBAC_PAYMENT_PENDING', '本订单已请求钱包签名且结算尚未确认，请保留原订单并重试核对回执；不能更换订单或凭证。', 409);
  }
  function entry(mode = 'bbs-bls') {
    modeValue(mode);
    if (!entries.has(mode)) entries.set(mode, { mode, deviceId: 'default', optionalFields: [], order: makeOrder(), credential: null, binding: null, orderKey: null, proposal: null, authorization: null, lastResult: null, ownerAvailable: true });
    return entries.get(mode);
  }
  const deviceRequest = (path, body, deviceId = entry(body?.mode ?? 'bbs-bls').deviceId) => request(`${device.baseUrl}${path}`, { body, headers: { 'X-DBAC-Access': device.accessToken, 'X-DBAC-Device': deviceId } });
  const issuerRequest = (path, body) => request(`${issuer.baseUrl}${path}`, { body, headers: { 'X-DBAC-Access': issuer.accessToken } });
  const ownerRequest = (path, body) => request(`${owner.baseUrl}${path}`, { body, headers: { 'X-Owner-Proposal': owner.proposalToken } });
  function requireCredential(e) {
    if (!e.credential || !e.binding) fail('DBAC_PAYMENT_CREDENTIAL_REQUIRED', '请先签发本方案的支付资格凭证。');
    if (w3cVerifier && !e.verifiableCredential) fail('W3C_CREDENTIAL_REQUIRED', '需要已签发的 W3C BBS VC 及对应设备绑定材料。');
    if (JSON.stringify(e.credential.attributes) !== JSON.stringify(attributesFor(e.mode, e.verifiableCredential?.credentialSubject.bindingId))) fail('DBAC_EPOCH_EXPIRED', '支付凭证日期已到期，请保留原订单记录并为下一订单重新签发。', 403);
    return e.credential;
  }
  async function challengeFor(rawBody, mode, orderId) {
    const result = await request(`${baseUrl}/dbac/payment/challenge`, { body: { mode, bodyHash: digest(rawBody), paymentOrderId: orderId } });
    const { payload } = verifyJws(result.challenge, { typ: DBAC_PAYMENT_CHALLENGE_TYP, purpose: 'authentication', expectedDid: verifierDid });
    const ctx = payload.context;
    if (payload.iss !== verifierDid || !ctx || ctx.profile !== DBAC_EXTENSION || ctx.purpose !== 'dbac-payment-v1' || ctx.scope !== PAYMENT_SCOPE || ctx.mode !== mode || ctx.verifier !== verifierDid || ctx.target !== `${baseUrl}/dbac/payment/a2a` || ctx.method !== 'POST' || ctx.bodyHash !== digest(rawBody) || ctx.paymentOrderId !== orderId || typeof ctx.challengeId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(ctx.nonce) || !Number.isSafeInteger(ctx.iat) || !Number.isSafeInteger(ctx.exp) || ctx.iat > unix() + 5 || ctx.exp <= unix() || ctx.exp <= ctx.iat || ctx.exp - ctx.iat > 60 || JSON.stringify(ctx.schema) !== JSON.stringify(w3cVerifier ? W3C_PAYMENT_SCHEMA : DBAC_SCHEMA) || ctx.credentialProfile !== (w3cVerifier ? W3C_PAYMENT_PROFILE : undefined) || JSON.stringify(ctx.requiredDisclosures) !== JSON.stringify(paymentDisclosures(mode))) fail('DBAC_BAD_CHALLENGE', '支付挑战签名、订单、目标或披露策略不匹配。', 403);
    if (typeof result.cancelToken === 'string') cancelHandles.set(ctx.challengeId, { token: result.cancelToken, exp: ctx.exp });
    for (const [id, handle] of cancelHandles) if (handle.exp <= unix()) cancelHandles.delete(id);
    return ctx;
  }
  async function cancelChallenge(context) {
    const cancelToken = cancelHandles.get(context?.challengeId)?.token;
    if (!cancelToken) return;
    try { await request(`${baseUrl}/dbac/payment/cancel`, { body: { challengeId: context.challengeId, cancelToken } }); }
    catch (error) { if (error.code !== 'DBAC_ALREADY_PROCESSED' && error.code !== 'DBAC_CHALLENGE_EXPIRED') throw error; }
    cancelHandles.delete(context.challengeId);
  }
  async function prepareCredential(e, context, paymentBinding = e.binding) {
    const credential = requireCredential(e);
    const header = w3cVerifier ? presentationHeader(context) : null;
    const verifiableCredential = w3cVerifier ? await deriveCredential({ credential: e.verifiableCredential, issuerProfile: issuer.w3c, presentationHeader: header, disclosedFields: e.optionalFields ?? [] }) : null;
    const deviceContext = verifiableCredential ? bindingContext(context, verifiableCredential) : context;
    const prepared = preparePresentation({ credential, context: deviceContext,
      disclosedIndices: w3cVerifier ? W3C_DISCLOSED_INDICES : [0, 1, 2, 3], mode: e.mode, paymentBinding });
    return { prepared, verifiableCredential, cryptography: header ? { presentationHeader: Buffer.from(header).toString('hex'), w3cPresentationHash: deviceContext.w3cPresentationHash } : null };
  }
  async function prepare({ mode = 'bbs-bls', phase, payment, authorization, payload, continuation, paymentBinding } = {}) {
    const e = entry(mode), credential = requireCredential(e);
    const terms = validatePayment(payment ?? e.order);
    const data = { scope: PAYMENT_SCOPE, phase, payment: terms, ...(authorization !== undefined ? { authorization } : {}), ...(payload !== undefined ? { payload } : {}) };
    const rpc = { jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: { message: { kind: 'message', role: 'user', messageId: randomUUID(), parts: [{ kind: 'data', data }], ...(continuation ? { taskId: continuation.id, contextId: continuation.contextId } : {}) } } };
    const rawBody = JSON.stringify(rpc), started = performance.now();
    const context = await challengeFor(rawBody, mode, terms.orderId);
    const { prepared, verifiableCredential } = await prepareCredential(e, context, paymentBinding ?? e.binding);
    const response = await deviceRequest('/sign', prepared.request, e.deviceId);
    const presentation = finalizePresentation({ state: prepared.state, response });
    if (!paymentBinding) {
      if (e.orderKey && e.orderKey !== presentation.randomizedDevicePublicKey) fail('DBAC_ORDER_KEY_CHANGED', '同一订单的设备伪名发生变化，已停止付款。', 409);
      e.orderKey = presentation.randomizedDevicePublicKey;
    }
    return { rawBody, context, presentation, verifiableCredential, holderProof: signHolder({ mode, context, presentation, verifiableCredential }), mode, phase, payment: terms, authorization, payload, timings: { prepareMs: +(performance.now() - started).toFixed(2) } };
  }
  async function transmit(prepared, { omitProof = false, omitDeviceProof = false, omitHolderProof = false } = {}) {
    const proof = prepared.verifiableCredential ? { ...(!omitDeviceProof ? prepared.presentation : {}), verifiableCredential: prepared.verifiableCredential, ...(!omitHolderProof && prepared.holderProof ? { holderProof: prepared.holderProof } : {}) } : prepared.presentation;
    const headers = { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Challenge': prepared.context.challengeId, ...(!omitProof ? { 'X-A2A-DBAC-Proof': Buffer.from(JSON.stringify(proof)).toString('base64url') } : {}) };
    const received = await request(`${baseUrl}/dbac/payment/a2a`, { rawBody: prepared.rawBody, headers, includeHeaders: true });
    cancelHandles.delete(prepared.context.challengeId);
    const responseEvidence = { proof: received.headers['x-a2a-dbac-payment-response'], rawRequest: prepared.rawBody, rawResponse: JSON.stringify(received.data), context: prepared.context };
    const verified = verifyDbacPaymentEvidence(responseEvidence, { verifierDid, issuerPublicKey: issuer.publicKey, ...(w3cVerifier ? { w3cIssuer: issuer.w3c.issuer, credentialBinding: credentialBinding(entry(prepared.mode)) } : {}), phase: prepared.phase, payment: prepared.payment, authorization: prepared.authorization, ...(prepared.phase === 'authorize' ? { paymentRequired: received.data.result?.status?.message?.metadata?.['x402.payment.required'] } : {}), ...(prepared.phase === 'settle' ? { payload: prepared.payload } : {}) });
    if (verified.gate.orderKey !== prepared.presentation.randomizedDevicePublicKey || verified.gate.mode !== prepared.mode) fail('DBAC_PAYMENT_GATE_MISMATCH', '支付回执的模式或订单设备伪名不匹配。', 403);
    const proofPayload = verifyJws(responseEvidence.proof, { typ: DBAC_PAYMENT_RESPONSE_TYP, purpose: 'authentication', expectedDid: verifierDid }).payload;
    const task = received.data.result;
    const paymentResult = task?.artifacts?.flatMap(artifact => artifact.parts ?? []).find(part => part.kind === 'data' && part.data?.paymentResult)?.data.paymentResult;
    return { accepted: true, mode: prepared.mode, phase: prepared.phase, task, paymentResult, gate: verified.gate, verificationTrace: proofPayload.verificationTrace, responseEvidence,
      wire: { endpoint: `${baseUrl}/dbac/payment/a2a`, headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.parse(prepared.rawBody), context: prepared.context, proof }, timings: prepared.timings };
  }
  function acceptProposal(e, proposal) {
    if (!proposal || proposal.profile !== DBAC_PAYMENT_PROFILE || proposal.mode !== e.mode || proposal.orderKey !== e.orderKey || !samePayment(proposal.payment, e.order) || !['PENDING', 'APPROVED', 'REJECTED', 'EXPIRED'].includes(proposal.status)) fail('DBAC_OWNER_RESPONSE_MISMATCH', 'Owner 返回的提案与本方案、订单或设备伪名不匹配。', 502);
    let authorization = null;
    if (proposal.status === 'APPROVED') {
      const document = verifyDbacPaymentAuthorization(proposal.authorization?.token, { trustedAuthorizers: [owner.did], verifierDid, issuerPublicKey: issuer.publicKey, payment: e.order, mode: e.mode, orderKey: e.orderKey, ...(w3cVerifier ? { credentialBinding: credentialBinding(e) } : {}) });
      authorization = { id: document.authorizationId, token: proposal.authorization.token, document };
    }
    e.proposal = structuredClone(proposal); e.authorization = authorization; e.ownerAvailable = true; delete e.ownerError;
  }
  async function sync(e, strict = false) {
    if (!e.proposal) return;
    const proposalId = e.proposal.id, orderId = e.order.orderId, binding = e.binding;
    const current = () => e.proposal?.id === proposalId && e.order.orderId === orderId && e.binding === binding;
    try {
      const proposal = await ownerRequest(`/proposals/${encodeURIComponent(proposalId)}`);
      if (!current()) return;
      acceptProposal(e, proposal);
    }
    catch (error) {
      if (!current()) return;
      if (/EXPIRED/.test(error.code)) { e.proposal.status = 'EXPIRED'; e.authorization = null; }
      e.ownerAvailable = false; e.ownerError = { code: error.code, message: error.message };
      if (strict) throw error;
    }
  }
  async function requireAuthorization(e) {
    requireCredential(e);
    await sync(e, true);
    if (!e.authorization) fail('OWNER_CONFIRMATION_REQUIRED', '请先提交论文支付提案，并在 Owner 页面明确批准这笔订单。', 403);
    verifyDbacPaymentAuthorization(e.authorization.token, { trustedAuthorizers: [owner.did], verifierDid, issuerPublicKey: issuer.publicKey, payment: e.order, mode: e.mode, orderKey: e.orderKey, ...(w3cVerifier ? { credentialBinding: credentialBinding(e) } : {}) });
    return e.authorization.token;
  }
  async function pay({ mode = 'bbs-bls' } = {}) {
    if (session.experimentRunBusy?.()) fail('BUSY', '实验正在执行，请等待原运行完成后再操作。', 409);
    const e = entry(mode);
    manual.guard(e);
    if (e.mutating) fail('DBAC_OPERATION_BUSY', '管理操作尚未完成，请刷新后重试。', 409);
    e.payRunning = (e.payRunning ?? 0) + 1;
    try {
      const authorization = await requireAuthorization(e);
      const authorized = await transmit(await prepare({ mode, phase: 'authorize', authorization }));
      const paymentRequired = authorized.task?.status?.message?.metadata?.['x402.payment.required'];
      if (authorized.task?.status?.state !== 'input-required' || !paymentRequired) fail('X402_REQUIREMENTS_MISSING', 'B 未返回论文证明验证后的付款要求。', 502);
      // A lost wallet/settlement response is not proof that no signature or
      // transfer exists. Keep the original order until a matching receipt.
      e.paymentPending = true;
      const payload = await x402Payer.createPayload({ profile: DBAC_PAYMENT_PROFILE, payment: e.order, authorization, paymentRequired, responseEvidence: authorized.responseEvidence });
      const settled = await transmit(await prepare({ mode, phase: 'settle', authorization, payload, continuation: authorized.task }));
      if (settled.task?.status?.state !== 'completed' || !['EXECUTED', 'ALREADY_PROCESSED'].includes(settled.paymentResult?.outcome) || !samePayment(settled.paymentResult.receipt, e.order)) fail('DBAC_PAYMENT_RECEIPT_INVALID', '未取得匹配本订单的链上成功回执，请查询原订单。', 502);
      e.paymentPending = false;
      e.lastResult = { ...settled, verificationTraces: [authorized.verificationTrace, settled.verificationTrace], paymentFlow: ['dbac-verified', 'input-required', 'payment-submitted', 'completed'] };
      return structuredClone(e.lastResult);
    } catch (error) {
      error.verificationTrace ??= preVerificationFailure('dbac-payment', error);
      // An uncertain request never causes an automatic new order or new nonce.
      throw error;
    } finally { e.payRunning--; }
  }
  async function credentialStatus(e) {
    if (!e.credentialId || !w3cVerifier) return { status: e.credential ? 'legacy-session' : 'absent', available: true };
    try { return { ...await issuerRequest('/credential/status', { bindingId: e.credentialId }), available: true }; }
    catch (error) { return { status: 'unknown', available: false, error: { code: error.code, message: error.message } }; }
  }
  async function inventory({ mode = 'bbs-bls' } = {}) {
    const e = entry(mode), health = await deviceRequest('/devices', undefined, e.deviceId);
    const records = [];
    for (const c of credentials.values()) {
      const status = await credentialStatus({ credentialId: c.id, credential: c.credential });
      records.push({ id: c.id, bindingId: c.id, issuer: issuer.w3c?.issuer ?? 'local DBAC issuer', holderDid: c.holderIdentity?.did, scope: PAYMENT_SCOPE, mode: c.mode, deviceId: c.deviceId,
        validFrom: c.verifiableCredential?.validFrom, validUntil: c.verifiableCredential?.validUntil, status: status.available ? (status.status ?? (status.revoked ? 'revoked' : 'active')) : 'unknown', statusAvailable: status.available });
    }
    const devices = (health.devices ?? []).map(d => { const m = d.modes?.[mode] ?? {}; return { ...d, id: d.deviceId ?? d.id, mode, publicKeyFingerprint: digest(d.publicKeys?.[mode] ?? ''), locked: m.locked, signCount: m.signatures ?? m.signCount ?? m.calls ?? m.signed ?? 0, logs: d.logs ?? m.logs ?? [] }; });
    return { mode, currentCredentialId: e.credentialId ?? null, currentDeviceId: e.deviceId, credentials: records, devices, holder: holderView(e), statusService: { available: records.every(c => c.statusAvailable) }, scope: '本地管理视图；重启需要重新签发，会话私钥不持久化；撤销状态表持久化。' };
  }
  async function invalidate(e) {
    const current = await manual.snapshot(e);
    if (current.walletSigned || current.walletSigningUnconfirmed || e.paymentPending) guardAutomaticSettlement({ paymentPending: !current.settled });
    if (current.active) await manual.act({ mode: e.mode, action: 'discard', attemptId: current.attemptId });
    e.lastResult = null;
  }
  const session = {
    async state({ mode = 'bbs-bls' } = {}) {
      const e = entry(mode);
      if (!manual.active(e)) await sync(e);
      const ledger = await getLedger();
      const manualState = await manual.snapshot(e);
      return { available: true, profile: DBAC_PAYMENT_PROFILE, mode, order: structuredClone(e.order), orderKey: e.orderKey,
        holder: holderView(e), credentialStatus: await credentialStatus(e), currentCredentialId: e.credentialId ?? null, currentDeviceId: e.deviceId,
        credential: e.credential ? { suite: e.credential.suite, attributes: e.credential.attributes.map((value, index) => ({ index, name: (w3cVerifier ? W3C_PAYMENT_SCHEMA : DBAC_SCHEMA)[index], value, disclosed: index < 4 || index === 6 })) } : null,
        w3c: { enabled: Boolean(w3cVerifier), profile: w3cVerifier ? W3C_PAYMENT_PROFILE : null, issuerProfile: structuredClone(issuer.w3c ?? null), originalCredential: structuredClone(e.verifiableCredential ?? null),
          disclosedPaths: ['role', 'scope', 'epoch', 'mode', 'bindingId', ...(e.holderIdentity ? ['holderDid'] : []), ...(e.optionalFields ?? [])].map(name => `/credentialSubject/${name}`), hiddenPaths: ['organization', 'holderLabel'].filter(name => !(e.optionalFields ?? []).includes(name)).map(name => `/credentialSubject/${name}`), linkability: '同一凭证的 bindingId 可关联；长期设备公钥不披露。' },
        proposal: structuredClone(e.proposal), authorization: structuredClone(e.authorization), owner: { did: owner.did, available: e.ownerAvailable, ...(e.ownerError ? { error: e.ownerError } : {}) },
        ledger, paymentInfo, paymentPending: Boolean(e.paymentPending || (!manualState.settled && (manualState.walletSigned || manualState.walletSigningUnconfirmed))), lastResult: structuredClone(e.lastResult), manual: manualState };
    },
    inventory,
    async manage({ mode = 'bbs-bls', action, deviceId, credentialId, optionalFields } = {}) {
      const e = entry(mode);
      if (action === 'revoke') {
        const id = credentialId ?? e.credentialId;
        if (!credentials.has(id)) fail('CREDENTIAL_NOT_FOUND', '只能管理当前 A 会话签发的测试凭证。', 404);
        await issuerRequest('/credentials/revoke', { bindingId: id });
        // Status changes do not masquerade as cancelling authentication or refunding payment.
      } else if (action === 'lock' || action === 'unlock') {
        const id = deviceId ?? e.deviceId;
        if (!deviceRegistry.has(id)) fail('DEVICE_NOT_FOUND', '设备不属于本地演示会话。', 404);
        await deviceRequest('/lock', { mode, locked: action === 'lock' }, id);
      } else if (action === 'create-device') {
        const created = await deviceRequest('/devices', {});
        await issuerRequest('/devices/register', { deviceId: created.deviceId, publicKeys: created.publicKeys });
        deviceRegistry.set(created.deviceId, created);
      } else if (action === 'issue') {
        await invalidate(e); await rawMutations.issue({ mode });
      } else if (action === 'disclosure') {
        if (!Array.isArray(optionalFields) || optionalFields.some(f => !['organization', 'holderLabel'].includes(f)) || new Set(optionalFields).size !== optionalFields.length) fail('DISCLOSURE_POLICY_INVALID', '仅允许选择组织与持有者标签，协议必需字段不可移除。');
        await invalidate(e); e.optionalFields = [...optionalFields];
        // Existing approval stays valid only because exact order/credential binding is unchanged.
      } else if (action === 'select-device' || action === 'select-credential') {
        const record = action === 'select-credential' ? credentials.get(credentialId) : null;
        if (action === 'select-credential' && (!record || record.mode !== mode)) fail('CREDENTIAL_NOT_FOUND', '请选择当前模式已签发的凭证。', 404);
        const target = record?.deviceId ?? deviceId;
        if (!deviceRegistry.has(target)) fail('DEVICE_NOT_FOUND', '请选择本地注册设备。', 404);
        await invalidate(e);
        e.deviceId = target; e.credential = record?.credential ?? null; e.verifiableCredential = record?.verifiableCredential ?? null; e.holderIdentity = record?.holderIdentity ?? null; e.credentialId = record?.id ?? null;
        e.binding = e.credential ? createPaymentBinding({ credential: e.credential, mode, orderId: e.order.orderId }) : null;
        e.orderKey = null; e.proposal = null; e.authorization = null; manual.reset(e);
      } else fail('MANAGEMENT_ACTION_INVALID', '未知管理操作。');
      return inventory({ mode });
    },
    async issue({ mode = 'bbs-bls' } = {}) {
      const e = entry(mode);
      manual.guard(e);
      guardAutomaticSettlement(e);
      if (e.proposal) fail('DBAC_ORDER_IN_PROGRESS', '本订单已提交给 Owner。请保留并核对原订单；需要新凭证时先明确创建下一笔订单。', 409);
      const holderIdentity = w3cVerifier ? generateIdentity('持有者 A：凭证专属密钥') : null;
      const selectedDevice = deviceRegistry.get(e.deviceId);
      const enrollment = await issuerRequest('/enroll/challenge', { mode, scope: PAYMENT_SCOPE, ...(holderIdentity ? { holderDid: holderIdentity.did } : {}), ...(e.deviceId !== 'default' ? { deviceId: e.deviceId } : {}) });
      const expectedAttributes = attributesFor(mode, enrollment.bindingId);
      if (w3cVerifier && (typeof enrollment.bindingId !== 'string' || !enrollment.bindingId)) fail('W3C_CREDENTIAL_BINDING_INVALID', '签发方没有生成凭证设备绑定标识。');
      if (enrollment.request?.context?.purpose !== 'dbac-enrollment-v1' || enrollment.request.context.mode !== mode || enrollment.request.context.issuerPublicKey !== issuer.publicKey || enrollment.request.randomizedDevicePublicKey !== selectedDevice.publicKeys[mode] || enrollment.request.context.attributeHash !== digest(JSON.stringify(expectedAttributes))) fail('DBAC_ISSUANCE_MISMATCH', '支付凭证注册挑战未绑定当前设备和支付资格。', 403);
      const response = await deviceRequest('/enroll/sign', { mode, request: enrollment.request }, e.deviceId);
      const result = await issuerRequest('/issue', { registrationId: enrollment.registrationId, response });
      verifyCredential(result.credential, { issuerPublicKey: issuer.publicKey });
      if (result.credential.devicePublicKey !== selectedDevice.publicKeys[mode] || JSON.stringify(result.credential.attributes) !== JSON.stringify(expectedAttributes)) fail('DBAC_ISSUANCE_MISMATCH', '签发凭证不是当前模式设备的支付资格。', 403);
      if (w3cVerifier) {
        await w3cVerifier.verifyBase({ credential: result.verifiableCredential });
        for (const [index, name] of W3C_PAYMENT_SCHEMA.entries()) if (result.verifiableCredential.credentialSubject[name] !== expectedAttributes[index]) fail('W3C_CREDENTIAL_BINDING_INVALID', '标准 VC 与设备绑定材料不属于同一次签发。');
        if (result.verifiableCredential.credentialSubject.holderDid !== holderIdentity.did) fail('HOLDER_BINDING_MISMATCH', '签发的持有者公钥不是 A 本地生成的公钥。');
        e.verifiableCredential = structuredClone(result.verifiableCredential);
        e.holderIdentity = holderIdentity;
      }
      e.credential = result.credential; e.binding = createPaymentBinding({ credential: e.credential, mode, orderId: e.order.orderId }); e.orderKey = null; e.lastResult = null;
      e.credentialId = enrollment.bindingId ?? `urn:uuid:${randomUUID()}`;
      credentials.set(e.credentialId, { id: e.credentialId, mode, deviceId: e.deviceId, credential: e.credential, verifiableCredential: e.verifiableCredential, holderIdentity });
      return session.state({ mode });
    },
    async newOrder({ mode = 'bbs-bls', amountMinor, payeeAccount, orderId, merchantOrder } = {}) {
      const e = entry(mode);
      manual.guard(e);
      guardAutomaticSettlement(e);
      const order = makeOrder({ amountMinor, payeeAccount, orderId, merchantOrder });
      e.order = order; e.proposal = null; e.authorization = null; e.orderKey = null; e.lastResult = null;
      e.paymentPending = false; e.ownerAvailable = true; delete e.ownerError;
      e.binding = e.credential ? createPaymentBinding({ credential: e.credential, mode, orderId: e.order.orderId }) : null;
      manual.reset(e);
      return session.state({ mode });
    },
    async propose({ mode = 'bbs-bls' } = {}) {
      const e = entry(mode);
      manual.guard(e);
      if (e.proposal && ['PENDING', 'APPROVED'].includes(e.proposal.status)) fail('DBAC_PROPOSAL_EXISTS', '本订单已有提案，请同步或到 Owner 页面处理，无需重复提交。', 409);
      try {
        const result = await transmit(await prepare({ mode, phase: 'proposal' }));
        const proposal = await ownerRequest('/proposals', { profile: DBAC_PAYMENT_PROFILE, payment: e.order, dbacEvidence: result.responseEvidence });
        acceptProposal(e, proposal); e.lastResult = result;
        return { ...await session.state({ mode }), verificationTrace: result.verificationTrace, wire: result.wire };
      } catch (error) { error.verificationTrace ??= preVerificationFailure('dbac-payment', error); throw error; }
    },
    async sync({ mode = 'bbs-bls' } = {}) { if (session.experimentRunBusy?.()) fail('BUSY', '实验正在执行，请等待原运行完成后再操作。', 409); const e = entry(mode); await sync(e, true); return session.state({ mode }); },
    async queryPayment({ mode = 'bbs-bls', payment } = {}) {
      const terms = validatePayment(payment ?? entry(mode).order);
      const result = x402Payer.queryPayment ? await x402Payer.queryPayment({ payment: terms }) : { status: 'unknown', receipt: null };
      if (result.status === 'confirmed') {
        if (!result.receipt || result.receipt.transactionStatus !== 'success' || !samePayment(result.receipt, terms)) fail('DBAC_PAYMENT_RECEIPT_INVALID', '原订单查询返回不匹配的回执。', 502);
        const e = entry(mode);
        if (e.order.orderId === terms.orderId && samePayment(e.order, terms)) {
          e.paymentPending = false;
          // A confirmed chain query can release an uncertain in-memory flow.
          // It neither invents a verifier trace nor re-signs/submits a payment.
          const current = await manual.snapshot(e);
          if (!current.settled) manual.reset(e);
        }
      }
      return structuredClone(result);
    },
    pay, retry: pay,
    async demo({ mode = 'bbs-bls' } = {}) {
      if (session.experimentRunBusy?.()) fail('BUSY', '实验正在执行，请等待原运行完成后再操作。', 409);
      const e = entry(mode);
      manual.guard(e);
      const authorization = await requireAuthorization(e);
      const before = await getLedger(), existing = before.receipts.some(receipt => receipt.orderId === e.order.orderId && receipt.payerAccount === e.order.payerAccount);
      const results = [];
      const check = async (name, expected, action, detail) => {
        let actual, verificationTrace, verificationTraces;
        try { const value = await action(); if (value && typeof value === 'object' && Object.hasOwn(value, 'actual')) ({ actual, verificationTrace, verificationTraces } = value); else actual = value; }
        catch (error) { actual = error.code ?? 'ERROR'; verificationTrace = error.verificationTrace ?? preVerificationFailure(DBAC_PAYMENT_PROFILE, error); }
        results.push({ name, expected, actual, pass: actual === expected, detail, ...(verificationTrace ? { verificationTrace } : {}), ...(verificationTraces ? { verificationTraces } : {}) });
      };
      const denied = async prepared => { const result = await transmit(await prepared); return { actual: 'ACCEPTED', verificationTrace: result.verificationTrace }; };
      await check('匿名设备证明不能替代 Owner 批准', 'PAYMENT_AUTHORIZATION_REQUIRED', () => denied(prepare({ mode, phase: 'authorize' })), '实际向 B 提交缺少单笔授权的支付请求。');
      for (const [name, changes] of [
        ['篡改已批准金额', { amountMinor: e.order.amountMinor + 1 }],
        ['篡改已批准收款账户', { payeeAccount: 'merchant:other' }],
        ['篡改已批准收款地址', { settlement: { ...e.order.settlement, payTo: e.order.settlement.payerAddress } }],
        ['替换已批准支付链', { settlement: { ...e.order.settlement, network: 'eip155:31338' } }],
      ]) await check(name, 'PAYMENT_TERMS_MISMATCH', () => denied(prepare({ mode, phase: 'authorize', authorization, payment: { ...e.order, ...changes } })), '重新生成有效论文证明仍不能修改 Owner 已批准的订单。');
      await check('移除匿名证明', 'DBAC_INVALID_ENVELOPE', async () => { const value = await transmit(await prepare({ mode, phase: 'authorize', authorization }), { omitProof: true }); return { actual: 'ACCEPTED', verificationTrace: value.verificationTrace }; }, '钱包签名之前必须先通过 B 的证明检查。');
      await check('生成证明后改动付款正文', 'DBAC_BODY_MISMATCH', async () => {
        const prepared = await prepare({ mode, phase: 'authorize', authorization }), body = JSON.parse(prepared.rawBody);
        body.params.message.parts[0].data.payment.amountMinor += 1;
        return denied({ ...prepared, rawBody: JSON.stringify(body) });
      }, '挑战和论文证明共同绑定本次实际支付正文。');
      await check('把旧证明套到新的支付挑战', w3cVerifier ? 'W3C_BBS_INVALID_PROOF' : 'DBAC_PROOF_INVALID', async () => {
        const prepared = await prepare({ mode, phase: 'authorize', authorization });
        return denied({ ...prepared, context: await challengeFor(prepared.rawBody, mode, e.order.orderId) });
      }, '新 nonce 要求新的设备参与和匿名证明。');
      await check('更换订单设备伪名沿用原授权', 'PAYMENT_AUTHORIZATION_BINDING_MISMATCH', () => denied(prepare({ mode, phase: 'authorize', authorization, paymentBinding: createPaymentBinding({ credential: e.credential, mode, orderId: e.order.orderId }) })), 'Owner 的批准绑定同一订单设备伪名。');
      const deviceInfo = await deviceRequest('/health', undefined, e.deviceId), wasLocked = deviceInfo.modes[mode].locked;
      try {
        await deviceRequest('/lock', { mode, locked: true });
        await check('批准后锁定论文设备仍不能付款', 'DBAC_DEVICE_LOCKED', () => pay({ mode }), '复制凭证和 Owner 授权不足以获得设备贡献。');
      } finally { await deviceRequest('/lock', { mode, locked: wasLocked }); }
      let sent;
      await check('提交已批准订单完成实际测试链付款', existing ? 'ALREADY_PROCESSED' : 'EXECUTED', async () => {
        const value = await pay({ mode });
        sent = { rawBody: JSON.stringify(value.wire.body), context: value.wire.context, presentation: value.wire.proof, mode, phase: 'settle', payment: e.order, authorization, payload: value.wire.body.params.message.parts[0].data.payload };
        return { actual: value.paymentResult.outcome, verificationTrace: value.verificationTrace, verificationTraces: value.verificationTraces };
      }, '只使用已有的 Owner 批准，不会自动批准新订单。');
      if (sent) await check('原样重放结算证明', 'DBAC_REPLAY', () => denied(sent), '已消费的支付挑战拒绝第二次使用。');
      await check('使用新证明重试原订单', 'ALREADY_PROCESSED', async () => { const value = await pay({ mode }); return { actual: value.paymentResult.outcome, verificationTrace: value.verificationTrace, verificationTraces: value.verificationTraces }; }, '沿用原付款 nonce 和交易回执。');
      await check('3 个并发新证明提交同一订单', '0 executed / 3 already processed / 0 rejected', async () => {
        const settled = await Promise.allSettled(Array.from({ length: 3 }, () => pay({ mode })));
        const count = outcome => settled.filter(value => value.status === 'fulfilled' && value.value.paymentResult.outcome === outcome).length;
        const verificationTraces = settled.flatMap(value => value.status === 'fulfilled' ? value.value.verificationTraces : [value.reason.verificationTrace]).filter(Boolean);
        return { actual: `${count('EXECUTED')} executed / ${count('ALREADY_PROCESSED')} already processed / ${settled.filter(value => value.status === 'rejected').length} rejected`, verificationTrace: verificationTraces[0], verificationTraces };
      }, '每次请求使用新挑战、新随机化证明和设备签名。');
      const after = await getLedger(), delta = existing ? 0 : e.order.amountMinor;
      const balance = (snapshot, account) => snapshot.accounts.find(value => value.id === account)?.balanceMinor;
      await check('付款方链上余额核对', balance(before, e.order.payerAccount) - delta, async () => balance(after, e.order.payerAccount), '链上 TEST_USDC 只允许本订单首次付款扣减。');
      await check('收款方链上余额核对', balance(before, e.order.payeeAccount) + delta, async () => balance(after, e.order.payeeAccount), '攻击与重试均不得额外入账。');
      await check('实际结算次数核对', before.executionCount + (existing ? 0 : 1), async () => after.executionCount, '只统计持久化的实际成功结算。');
      return { mode, results, total: results.length, passed: results.filter(value => value.pass).length, beforeLedger: before, afterLedger: after, paymentResult: e.lastResult?.paymentResult };
    },
    // Internal test helpers only; HTTP dispatch exposes the fixed actions above.
    prepare, transmit,
  };
  const manual = createDbacPaymentManual({ entry, requireCredential, challengeFor, deviceRequest,
    deviceHealth: e => deviceRequest('/health', undefined, e.deviceId), transmit, ownerRequest, acceptProposal, syncOwner: sync,
    issuer, verifierDid, owner, x402Payer, w3cEnabled: Boolean(w3cVerifier), prepareCredential, credentialBinding, signHolder, cancelChallenge, state: options => session.state(options) });
  session.manual = async options => {
    const result = await manual.act(options);
    if (result.manual.settled) {
      // Manual recovery of the same order also resolves an earlier automatic
      // request once its exact final receipt has passed the existing checks.
      entry(options?.mode).paymentPending = false;
      result.paymentPending = false;
    }
    return result;
  };
  const rawMutations = {};
  for (const name of ['issue', 'newOrder', 'manage', 'manual', 'propose']) {
    rawMutations[name] = session[name];
    session[name] = async (options = {}) => {
      if (session.experimentRunBusy?.()) fail('BUSY', '实验正在执行，请等待原运行完成后再操作。', 409);
      const e = entry(options.mode);
      if (e.mutating || e.payRunning) fail('DBAC_OPERATION_BUSY', '此模式已有状态变更或付款请求正在处理，请等待结果再操作。', 409);
      e.mutating = true;
      try { return await rawMutations[name](options); } finally { e.mutating = false; }
    };
  }
  const experiments = createFrameworkAttackExperiments({ entry, prepare, prepareCredential, challengeFor, transmit, deviceRequest,
    deviceHealth: () => deviceRequest('/health', undefined, 'default'), issuerRequest, getLedger, issuer, device, baseUrl, verifierDid, signHolder,
    initialize: async ({ mode, paymentOrder }) => { await session.newOrder({ mode, ...paymentOrder }); await session.issue({ mode }); },
  });
  session.experimentScenarios = () => experiments.catalog();
  const runExperiment = async options => {
    experimentalSession ??= createDbacPaymentSession({ baseUrl, verifierDid, issuer, device, owner, x402Payer, paymentInfo, getLedger });
    return experimentalSession._runExperiment(options);
  };
  let legacyExperimentBusy = false;
  const mutationBusy = () => [...entries.values()].some(e => e.mutating || e.payRunning);
  const experimentRuns = createExperimentRuns({ run: runExperiment, scenarios: session.experimentScenarios, canStart: () => !legacyExperimentBusy && !mutationBusy() });
  session.experimentRunBusy = () => legacyExperimentBusy || experimentRuns.busy();
  session.startExperimentRun = (options, blocked = false) => experimentRuns.start(options, { blocked });
  session.experimentRun = runId => experimentRuns.get(runId);
  session.experimentRuns = () => experimentRuns.list();
  session.experiments = async options => {
    if (session.experimentRunBusy() || mutationBusy()) fail('BUSY', '已有演示操作或实验正在执行，请等待完成后再操作。', 409);
    legacyExperimentBusy = true;
    try { return await runExperiment(options); } finally { legacyExperimentBusy = false; }
  };
  // Private closure methods are never dynamically dispatchable over HTTP.
  session._runExperiment = options => experiments.run(options);
  return session;
}
