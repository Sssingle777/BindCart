import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { signJws } from '../identity.mjs';
import { AppError, digest, parseObject, readBody, sendJson, unix } from '../protocol.mjs';
import { validatePayment, PAYMENT_SCOPE } from '../payment.mjs';
import { createVerificationTrace } from '../verification-trace.mjs';
import { verifyPresentation } from './crypto.mjs';
import { DBAC_EXTENSION, DBAC_MODES, DBAC_SCHEMA, paymentDisclosures, exact } from './policy.mjs';
import { DBAC_PAYMENT_PROFILE, DBAC_PAYMENT_CHALLENGE_TYP, DBAC_PAYMENT_RESPONSE_TYP, dbacPaymentHash, parseDbacPaymentRequest, verifyDbacPaymentAuthorization, credentialBindingOf } from './payment-policy.mjs';
import { createW3cBbsVerifier } from '../w3c-bbs.mjs';
import { W3C_PAYMENT_PROFILE, W3C_PAYMENT_SCHEMA, presentationHeader, bindingContext, w3cPresentationHash } from './w3c-profile.mjs';
import { verifyHolderProof } from './holder-proof.mjs';
import { createCredentialStatusReader } from './credential-status.mjs';
import { validateMerchantOrder } from '../storefront/merchant-protocol.mjs';

const fail = (code, message, status = 403) => { throw new AppError(code, message, status); };
const identifier = value => typeof value === 'string' && value.length > 0 && value.length <= 256 && value.trim() === value && !/[\u0000-\u001f\u007f]/.test(value);
const same = (a, b) => dbacPaymentHash(a) === dbacPaymentHash(b);
const timestamp = () => new Date().toISOString();
const publicValue = value => value === null || ['string', 'number', 'boolean', 'undefined'].includes(typeof value) ? value : `[invalid ${Array.isArray(value) ? 'array' : typeof value}]`;
function selectedAuthorizationClaims(token) {
  try {
    const claims = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    return [claims.iss, claims.vcBindingId, claims.iat, claims.exp].map(publicValue);
  } catch { return [null, null, null, null]; }
}

export function createDbacPaymentVerifier({ identity, issuerPublicKey, trustedAuthorizers, getBackend, maxEntries = 256, w3cIssuer, requireHolderProof = false, statusSource, trustedMerchant }) {
  if (!identity?.did || typeof issuerPublicKey !== 'string' || !(trustedAuthorizers instanceof Set || Array.isArray(trustedAuthorizers)) || typeof getBackend !== 'function') throw new Error('DBAC payment verifier requires trusted Owner, issuer and payment backend configuration');
  const trustedW3cIssuer = w3cIssuer === undefined ? null : structuredClone(w3cIssuer);
  const w3cVerifier = trustedW3cIssuer ? createW3cBbsVerifier(trustedW3cIssuer) : null;
  if (w3cIssuer !== undefined && !w3cVerifier) throw new Error('Configured W3C payment issuer cannot be empty');
  if (requireHolderProof && (!w3cVerifier || !statusSource)) throw new Error('The joint holder profile requires a W3C issuer and fail-closed status source');
  const readCredentialStatus = statusSource ? createCredentialStatusReader(statusSource) : null;
  const schema = w3cVerifier ? W3C_PAYMENT_SCHEMA : DBAC_SCHEMA;
  const challenges = new Map(), tasks = new Map();
  const metadata = () => ({ profile: DBAC_PAYMENT_PROFILE, scope: PAYMENT_SCOPE, modes: DBAC_MODES, issuerPublicKey, endpoint: '/dbac/payment/a2a', challengeUrl: '/dbac/payment/challenge', paymentSupported: true, devicePseudonymScope: 'one-order', anonymousSettlement: false,
    ...(w3cVerifier ? { credentialProfile: W3C_PAYMENT_PROFILE, w3cIssuer: structuredClone(trustedW3cIssuer), schema: [...schema], credentialBindingLinkability: 'same-credential', holderProofRequired: requireHolderProof, credentialStatusSource: readCredentialStatus ? 'trusted-local-issuer' : 'legacy-no-status' } : {}) });
  const card = baseUrl => ({
    protocolVersion: '0.3.0', name: w3cVerifier ? 'Agent B · W3C BBS VC 与 eSIM 绑定支付' : 'Agent B · DBAC 设备绑定支付',
    description: w3cVerifier ? '同一支付入口核验标准 bbs-2023 派生 VC 和对应 eSIM 的论文设备绑定证明，再取得 Owner 明确批准并执行测试支付。' : '将论文 BBS-BLS / BBS-BlindBLS 用于单笔支付：核验资格，取得 Owner 明确批准，再分别核验钱包签名及结算前的新设备证明。',
    url: `${baseUrl}/dbac/payment/a2a`, preferredTransport: 'JSONRPC', version: '1.0.0',
    capabilities: { streaming: false, pushNotifications: false, extensions: [
      { uri: DBAC_EXTENSION, required: true, description: '论文设备绑定凭证支付配置；订单内复用随机化设备公钥，每阶段使用新挑战和证明。', params: {
        ...metadata(), endpoint: `${baseUrl}/dbac/payment/a2a`, challengeUrl: `${baseUrl}/dbac/payment/challenge`,
        agentCardUrl: `${baseUrl}/dbac/payment/agent-card.json`, phases: ['proposal', 'authorize', 'settle'],
        challengeType: DBAC_PAYMENT_CHALLENGE_TYP, responseType: DBAC_PAYMENT_RESPONSE_TYP,
        responseHeader: 'X-A2A-DBAC-Payment-Response', ownerApprovalRequired: true,
      } },
      { uri: 'https://github.com/google-a2a/a2a-x402/v0.1', required: true, description: 'x402 v2 本地 TEST_USDC 测试链付款；链上地址仍可关联。' },
    ] },
    defaultInputModes: ['application/json'], defaultOutputModes: ['application/json'],
    skills: [{ id: PAYMENT_SCOPE, name: '论文设备绑定单笔支付', description: 'proposal 核验支付资格；authorize 核验 Owner 授权并返回 x402 要求；settle 核验新证明及原付款任务，再执行幂等结算。', tags: ['dbac', 'bbs', 'payment', 'x402'] }],
  });
  function prune() {
    for (const [id, entry] of challenges) if (entry.context.exp <= unix()) challenges.delete(id);
    for (const [id, entry] of tasks) if (entry.exp <= unix()) tasks.delete(id);
  }
  function responseTrace(trace, phase) {
    const snapshot = trace.snapshot();
    // The settlement response is carried in an HTTP header. Keep the actual
    // settlement-gate evidence and status, but omit its descriptive copy to
    // leave room for the signed payment gate and the transport envelope.
    if (phase === 'settle') {
      const settlement = snapshot.steps.find(step => step.id === 'settlement_gate');
      if (settlement) delete settlement.detail;
    }
    return snapshot;
  }
  function responseEvidence({ result, rawRequest, context, gate, trace }) {
    const rawResponse = JSON.stringify(result), iat = unix();
    const proof = signJws({ iss: identity.did, requestHash: digest(rawRequest), responseHash: digest(rawResponse), contextHash: digest(JSON.stringify(context)), iat, exp: iat + (gate.phase === 'proposal' ? 300 : 60), paymentGate: gate, verificationTrace: responseTrace(trace, gate.phase) }, identity, DBAC_PAYMENT_RESPONSE_TYP);
    return { proof, rawRequest, rawResponse, context: structuredClone(context) };
  }
  const baseTask = (state, id = randomUUID(), contextId = randomUUID()) => ({ kind: 'task', id, contextId, status: { state, timestamp: timestamp() } });
  const taskMessage = (task, text, metadata) => ({ kind: 'message', role: 'agent', messageId: randomUUID(), taskId: task.id, contextId: task.contextId, parts: [{ kind: 'text', text }], metadata });
  return {
    metadata, card,
    async handle(req, res, baseUrl) {
      if (!req.url.startsWith('/dbac/payment/')) return false;
      if (req.method === 'GET' && req.url === '/dbac/payment/metadata') { sendJson(res, 200, metadata()); return true; }
      if (req.method === 'GET' && req.url === '/dbac/payment/agent-card.json') { sendJson(res, 200, card(baseUrl)); return true; }
      if (req.method === 'POST' && req.url === '/dbac/payment/cancel') {
        const body = parseObject(await readBody(req));
        if (!exact(body, ['challengeId', 'cancelToken']) || typeof body.challengeId !== 'string' || typeof body.cancelToken !== 'string') fail('DBAC_CANCEL_DENIED', '取消认证需要该轮独立的取消权限。');
        const entry = challenges.get(body.challengeId), token = Buffer.from(body.cancelToken);
        if (!entry || entry.context.exp <= unix()) fail('DBAC_CHALLENGE_EXPIRED', '此轮不存在或已过期，不能再取得认证放行。', 401);
        if (token.length !== entry.cancelToken.length || !timingSafeEqual(token, entry.cancelToken)) fail('DBAC_CANCEL_DENIED', '不能取消不属于当前持有者的认证轮次。');
        if (entry.used) fail('DBAC_ALREADY_PROCESSED', '本轮已处理，取消不会撤销认证结果或已完成付款。', 409);
        entry.cancelled = true;
        sendJson(res, 200, { challengeId: body.challengeId, status: 'cancelled' }); return true;
      }
      if (req.method === 'POST' && req.url === '/dbac/payment/challenge') {
        const body = parseObject(await readBody(req));
        if (!exact(body, ['mode', 'bodyHash', 'paymentOrderId']) || !DBAC_MODES.includes(body.mode) || typeof body.bodyHash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.bodyHash) || !identifier(body.paymentOrderId)) fail('DBAC_INVALID_CHALLENGE_REQUEST', '支付挑战只接受方案、完整正文摘要及订单编号。', 400);
        prune();
        if (challenges.size >= maxEntries) fail('DBAC_CAPACITY', '有效支付挑战过多。', 429);
        const context = { profile: DBAC_EXTENSION, purpose: 'dbac-payment-v1', scope: PAYMENT_SCOPE, mode: body.mode, verifier: identity.did, target: `${baseUrl}/dbac/payment/a2a`, method: 'POST', bodyHash: body.bodyHash, paymentOrderId: body.paymentOrderId, challengeId: randomUUID(), nonce: randomBytes(32).toString('base64url'), iat: unix(), exp: unix() + 60, schema: [...schema], requiredDisclosures: paymentDisclosures(body.mode), ...(w3cVerifier ? { credentialProfile: W3C_PAYMENT_PROFILE } : {}) };
        const cancelToken = randomBytes(32).toString('base64url');
        challenges.set(context.challengeId, { context, used: false, cancelled: false, cancelToken: Buffer.from(cancelToken) });
        sendJson(res, 200, { challenge: signJws({ iss: identity.did, context }, identity, DBAC_PAYMENT_CHALLENGE_TYP), cancelToken }); return true;
      }
      if (req.method !== 'POST' || req.url !== '/dbac/payment/a2a') fail('NOT_FOUND', 'DBAC 支付接口不存在。', 404);
      const trace = createVerificationTrace(DBAC_PAYMENT_PROFILE);
      try {
        trace.start('extension');
        trace.record('extension', { label: 'extension / identified headers', expected: [DBAC_EXTENSION, false], observed: [publicValue(req.headers['x-a2a-extensions']), Boolean(req.headers.authorization || req.headers['x-a2a-device-proof'])] });
        if (req.headers['x-a2a-extensions'] !== DBAC_EXTENSION) fail('DBAC_EXTENSION_REQUIRED', '支付请求需要 DBAC 扩展。', 400);
        if (req.headers.authorization || req.headers['x-a2a-device-proof']) fail('DBAC_IDENTIFIED_HEADERS', 'DBAC 支付请求不得包含具名 VC 或设备 DID 证明。', 400);
        trace.pass('extension');
        trace.start('envelope');
        const rawRequest = await readBody(req), encoded = req.headers['x-a2a-dbac-proof'];
        trace.record('envelope', { label: 'body / proof encoded length', expected: ['<=49152', '<=16384'], observed: [rawRequest.length, typeof encoded === 'string' ? encoded.length : null] });
        if (rawRequest.length > 49152 || typeof encoded !== 'string' || encoded.length > 16384 || !/^[A-Za-z0-9_-]+$/.test(encoded) || Buffer.from(encoded, 'base64url').toString('base64url') !== encoded) fail('DBAC_INVALID_ENVELOPE', '匿名证明编码或支付正文无效。', 400);
        const envelope = parseObject(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(encoded, 'base64url')));
        let presentation = envelope;
        const verifiableCredential = w3cVerifier ? envelope.verifiableCredential : null;
        if (w3cVerifier) { const { verifiableCredential: omitted, holderProof: omittedHolder, ...dbacPresentation } = envelope; presentation = dbacPresentation; }
        trace.pass('envelope');
        trace.start('challenge');
        const entry = challenges.get(req.headers['x-a2a-dbac-challenge']);
        const challengeNow = unix();
        trace.record('challenge', { label: 'challenge found / now / expiry (s)', expected: [true, 'now < expiry'], observed: [Boolean(entry), challengeNow, entry?.context.exp], match: Boolean(entry && entry.context.exp > challengeNow) });
        if (!entry || entry.context.exp <= challengeNow) fail('DBAC_CHALLENGE_EXPIRED', '支付挑战不存在或已过期。', 401);
        if (entry.cancelled) fail('DBAC_CHALLENGE_CANCELLED', '本轮认证已取消，需要获取新的挑战。', 401);
        const context = entry.context;
        trace.pass('challenge');
        trace.start('replay');
        trace.record('replay', { label: 'challenge already used', expected: false, observed: entry.used, match: !entry.used });
        if (entry.used) fail('DBAC_REPLAY', '该支付挑战已经消费。', 401);
        trace.pass('replay');
        trace.start('request_binding');
        const bodyHash = digest(rawRequest);
        trace.record('request_binding', { label: 'raw body SHA-256', expected: context.bodyHash, observed: bodyHash, match: context.bodyHash === bodyHash });
        if (context.bodyHash !== bodyHash) fail('DBAC_BODY_MISMATCH', '支付正文与挑战绑定的摘要不同。', 400);
        trace.pass('request_binding');
        trace.start('policy_context');
        const currentDisclosures = paymentDisclosures(context.mode);
        trace.record('policy_context', { label: 'role / scope / epoch / mode', expected: Object.values(currentDisclosures), observed: Object.values(context.requiredDisclosures), match: same(context.requiredDisclosures, currentDisclosures) });
        if (!same(context.requiredDisclosures, currentDisclosures)) fail('DBAC_EPOCH_EXPIRED', '支付资格凭证日期已过期，请重新签发。');
        if (!w3cVerifier && presentation.mode !== context.mode) fail('DBAC_MODE_MISMATCH', '展示与支付挑战的方案不同。');
        trace.pass('policy_context');
        trace.start('scope');
        let incoming;
        try { incoming = JSON.parse(rawRequest); } catch { /* The actual parser below supplies the protocol failure. */ }
        trace.record('scope', { label: 'method / scope / phase', expected: ['message/send', PAYMENT_SCOPE, 'proposal | authorize | settle'], observed: [incoming?.method, incoming?.params?.message?.parts?.[0]?.data?.scope, incoming?.params?.message?.parts?.[0]?.data?.phase].map(publicValue) });
        const request = parseDbacPaymentRequest(rawRequest), message = request.params.message, data = message.parts[0].data, payment = validatePayment(data.payment);
        trace.record('scope', { label: 'payment order ID', expected: context.paymentOrderId, observed: payment.orderId, match: context.paymentOrderId === payment.orderId });
        if (context.paymentOrderId !== payment.orderId) fail('DBAC_PAYMENT_ORDER_MISMATCH', '支付挑战绑定的是另一个订单。');
        if (data.phase !== 'settle' && (message.taskId !== undefined || message.contextId !== undefined)) fail('DBAC_PAYMENT_TASK_MISMATCH', '只有 settle 阶段可以继续已有付款任务。');
        trace.pass('scope');
        if (trustedMerchant || payment.merchantOrder) {
          trace.start('merchant_order');
          trace.record('merchant_order', { label: 'trusted merchant / snapshot SHA-256', expected: trustedMerchant?.did ?? 'explicit trusted merchant required', observed: [payment.merchantOrder?.snapshot?.merchantDid, payment.merchantOrder?.snapshotHash] });
          if (!trustedMerchant) fail('MERCHANT_UNTRUSTED', '验证方未配置可信商家，不能接受自报签名的订单。');
          validateMerchantOrder(payment.merchantOrder, payment, { trusted: trustedMerchant, paymentInfo: getBackend()?.publicInfo });
          trace.pass('merchant_order');
        }
        if (!w3cVerifier) {
          trace.start('schema');
          trace.record('schema', { label: 'signed attribute count', expected: schema.length, observed: publicValue(presentation.attributeCount), match: presentation.attributeCount === schema.length });
          if (presentation.attributeCount !== schema.length) fail('DBAC_SCHEMA_MISMATCH', '支付展示不符合固定属性 schema。');
          trace.pass('schema');
        }
        let vcBinding;
        if (w3cVerifier) {
          trace.start('w3c_bbs');
          const expectedHeader = presentationHeader(context);
          trace.record('w3c_bbs', { label: 'proof type / suite / issuer', expected: ['DataIntegrityProof', 'bbs-2023', trustedW3cIssuer.issuer], observed: [verifiableCredential?.proof?.type, verifiableCredential?.proof?.cryptosuite, verifiableCredential?.issuer].map(publicValue) });
          trace.record('w3c_bbs', { label: 'expected presentationHeader (hex)', observed: Buffer.from(expectedHeader).toString('hex'), note: 'Verifier input; checked by bbs-2023.' });
          await w3cVerifier.verifyDerived({ credential: verifiableCredential, presentationHeader: expectedHeader });
          const subject = verifiableCredential.credentialSubject;
          const mandatorySubject = ['role', 'scope', 'epoch', 'mode', 'bindingId'];
          if (!mandatorySubject.every(key => Object.hasOwn(subject, key)) || Object.keys(subject).some(key => ![...mandatorySubject, 'holderDid', 'organization', 'holderLabel'].includes(key)) || subject.role !== context.requiredDisclosures[0] ||
              subject.scope !== PAYMENT_SCOPE || subject.epoch !== context.requiredDisclosures[2] || subject.mode !== context.mode ||
              typeof subject.bindingId !== 'string' || !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(subject.bindingId)) fail('W3C_BBS_PAYMENT_POLICY', '标准 VC 未披露匹配本次支付的角色、权限、日期、设备模式及随机绑定标识。');
          trace.pass('w3c_bbs');
          if (requireHolderProof && !subject.holderDid) { trace.start('holder_signature'); fail('HOLDER_KEY_REQUIRED', '此主线只接受签发方已保护持有者公钥的新凭证。'); }
          const bindingEvidence = { label: 'bindingId / mode / device contribution', expected: [subject.bindingId, context.mode, true], observed: [Array.isArray(presentation.disclosed) ? publicValue(presentation.disclosed.find(item => item?.index === 6)?.value) : null, publicValue(presentation.mode), typeof presentation.deviceSignature === 'string' && presentation.deviceSignature.length > 0] };
          if (!bindingEvidence.observed[2] || presentation.mode !== context.mode) {
            trace.start('vc_device_binding'); trace.record('vc_device_binding', bindingEvidence);
            if (!bindingEvidence.observed[2]) fail('W3C_DEVICE_PROOF_REQUIRED', '标准 BBS VC 有效，但缺少绑定 eSIM 的本次设备贡献与证明，不能继续支付。');
            fail('DBAC_MODE_MISMATCH', '设备展示与标准 VC 的方案模式不同。');
          }
          trace.start('schema');
          trace.record('schema', { label: 'signed attribute count', expected: schema.length, observed: publicValue(presentation.attributeCount), match: presentation.attributeCount === schema.length });
          if (presentation.attributeCount !== schema.length) fail('DBAC_SCHEMA_MISMATCH', '支付设备展示不符合固定属性 schema。');
          trace.pass('schema');
          trace.start('vc_device_binding');
          trace.record('vc_device_binding', bindingEvidence);
          if (!Array.isArray(presentation.disclosed) || presentation.disclosed.find(item => item?.index === 6)?.value !== subject.bindingId) fail('W3C_DEVICE_BINDING_MISMATCH', '标准 VC 与设备绑定凭证不是同一签发记录，不能混搭使用。');
          const derivedCredentialHash = w3cPresentationHash(verifiableCredential);
          trace.record('vc_device_binding', { label: 'hVC: derived credential hash', observed: derivedCredentialHash });
          trace.pass('vc_device_binding');
          vcBinding = { credentialProfile: W3C_PAYMENT_PROFILE, w3cIssuer: trustedW3cIssuer.issuer, vcBindingId: subject.bindingId, w3cPresentationHash: derivedCredentialHash };
        }
        verifyPresentation({ presentation, issuerPublicKey, context: w3cVerifier ? bindingContext(context, verifiableCredential) : context, deviceFirst: Boolean(verifiableCredential?.credentialSubject?.holderDid),
          requiredDisclosures: w3cVerifier ? { ...context.requiredDisclosures, 6: vcBinding.vcBindingId } : context.requiredDisclosures, trace });
        const holderBound = Boolean(verifiableCredential?.credentialSubject?.holderDid);
        if (holderBound) {
          trace.start('holder_signature');
          const holder = verifyHolderProof({ holderProof: envelope.holderProof, context, verifiableCredential, presentation });
          trace.record('holder_signature', { label: 'issuer-protected holder key / signed input digest', observed: [holder.keyFingerprint, holder.inputHash], match: holder.verified });
          trace.pass('holder_signature');
        }
        const checkCredentialStatus = async () => {
          if (!holderBound && !requireHolderProof && !readCredentialStatus) return;
          trace.start('credential_status');
          if (!readCredentialStatus) fail('W3C_CREDENTIAL_STATUS_UNAVAILABLE', '没有配置可信签发方状态查询，不能放行主线凭证。', 503);
          await readCredentialStatus({ bindingId: vcBinding.vcBindingId, issuer: vcBinding.w3cIssuer, holderDid: verifiableCredential.credentialSubject.holderDid }, {
            onStatus: status => trace.record('credential_status', { label: 'issuer status / source / checked at', expected: 'valid', observed: [status.status, status.source, status.checkedAt], match: status.status === 'valid' }),
          });
          trace.pass('credential_status');
        };
        const orderKey = presentation.randomizedDevicePublicKey;
        const gate = { profile: DBAC_PAYMENT_PROFILE, phase: data.phase, mode: context.mode, issuerPublicKey, orderKey, paymentHash: dbacPaymentHash(payment), ...vcBinding, ...(data.phase !== 'proposal' ? { authorizationHash: digest(data.authorization) } : {}), ...(data.phase === 'settle' ? { payloadHash: dbacPaymentHash(data.payload) } : {}) };
        let approval;
        const authorize = () => verifyDbacPaymentAuthorization(data.authorization, { trustedAuthorizers, verifierDid: identity.did, issuerPublicKey, payment, mode: context.mode, orderKey, ...(vcBinding ? { credentialBinding: credentialBindingOf(gate) } : {}) });
        if (data.phase !== 'proposal') {
          trace.start('owner_authorization');
          trace.record('owner_authorization', { label: 'Owner / VC binding / issued / expires', expected: [[...trustedAuthorizers].join(', '), vcBinding?.vcBindingId ?? null, 'iat <= now', `exp > ${unix()}`], observed: selectedAuthorizationClaims(data.authorization), note: 'Claims untrusted until signature and binding checks pass.' });
          approval = authorize(); trace.pass('owner_authorization');
        }
        let previous;
        if (data.phase === 'settle') {
          trace.start('task_binding');
          previous = tasks.get(message.taskId);
          const taskTuple = (contextId, values) => [contextId ?? null, values.mode, values.orderKey, values.paymentHash, values.authorizationHash, values.vcBindingId ?? null];
          trace.record('task_binding', { label: 'task continuity tuple hash', expected: previous ? dbacPaymentHash(taskTuple(previous.contextId, previous)) : null, observed: dbacPaymentHash(taskTuple(message.contextId, gate)) });
          if (!previous || previous.exp <= unix() || previous.contextId !== message.contextId || previous.mode !== context.mode || previous.orderKey !== orderKey || previous.paymentHash !== gate.paymentHash || previous.authorizationHash !== gate.authorizationHash || previous.vcBindingId !== gate.vcBindingId) fail('DBAC_PAYMENT_TASK_MISMATCH', '结算未继续同一 Owner 授权、订单、VC 及随机化设备公钥的付款任务。');
          trace.pass('task_binding');
        }
        // Query only after proof verification; failed crypto requests never
        // consume a challenge. This network await is followed by atomic recheck.
        await checkCredentialStatus();
        trace.start('consume');
        // W3C proof validation yields to the event loop. Recheck after every
        // await, then consume synchronously so concurrent requests cannot both
        // use this challenge. Order idempotency remains a separate backend gate.
        const consumeNow = unix();
        trace.record('consume', { label: 'before consume: used / now / expires', expected: [false, 'now < expiry'], observed: [entry.used, consumeNow, context.exp] });
        if (entry.used) fail('DBAC_REPLAY', '该支付挑战已经消费。', 401);
        if (entry.cancelled) fail('DBAC_CHALLENGE_CANCELLED', '验证期间本轮认证已取消。', 401);
        if (context.exp <= consumeNow || !same(context.requiredDisclosures, paymentDisclosures(context.mode))) fail('DBAC_CHALLENGE_EXPIRED', '验证期间支付挑战或资格日期已经过期。', 401);
        entry.used = true;
        trace.record('consume', { label: 'after synchronous consume: used', expected: true, observed: entry.used, match: entry.used });
        trace.pass('consume');
        let task;
        if (data.phase === 'proposal') {
          trace.start('execution');
          task = baseTask('completed');
          task.artifacts = [{ artifactId: randomUUID(), name: w3cVerifier ? 'W3C BBS VC 与 eSIM 支付资格核验' : 'DBAC 支付资格核验', parts: [{ kind: 'data', data: { profile: DBAC_PAYMENT_PROFILE, phase: 'proposal', payment, orderKey, mode: context.mode, issuerPublicKey, anonymousCredentialVerified: true, deviceContributionVerified: true, ownerApprovalRequired: true, ...(vcBinding ? { ...vcBinding, w3cBbsVerified: true } : {}) } }] }];
          trace.record('execution', { label: 'phase / resulting task', observed: [data.phase, task.status.state] });
          trace.pass('execution');
        } else {
          const backend = getBackend();
          if (!backend) { trace.start('execution'); fail('X402_NOT_READY', 'x402 支付后端尚未就绪。', 503); }
          if (data.phase === 'authorize') {
            trace.start('execution');
            prune();
            if (tasks.size >= maxEntries) fail('DBAC_CAPACITY', '有效支付任务过多。', 429);
            task = baseTask('input-required');
            const required = await backend.requirements(payment, { resourceUrl: `${baseUrl}/dbac/payment/a2a`, taskId: task.id });
            approval = authorize();
            await checkCredentialStatus();
            trace.start('execution');
            if (context.exp <= unix() || !same(context.requiredDisclosures, paymentDisclosures(context.mode))) fail('DBAC_CHALLENGE_EXPIRED', '生成付款要求期间支付挑战或资格已过期。');
            task.status.message = taskMessage(task, 'DBAC 设备绑定凭证及 Owner 单笔授权已通过；钱包核验此回执后才可签署付款。', { 'x402.payment.status': 'payment-required', 'x402.payment.required': required });
            tasks.set(task.id, { contextId: task.contextId, mode: context.mode, orderKey, paymentHash: gate.paymentHash, authorizationHash: gate.authorizationHash, ...(vcBinding ? { vcBindingId: vcBinding.vcBindingId } : {}), exp: approval.exp });
            trace.record('execution', { label: 'phase / resulting task', observed: [data.phase, task.status.state] });
            trace.pass('execution');
          } else {
            trace.start('settlement_gate');
            const working = baseTask('working', message.taskId, message.contextId);
            working.status.message = taskMessage(working, '新的 DBAC 证明已绑定本次付款 payload，允许后端核验结算。', { 'dbac.payment.status': 'settlement-authorized' });
            trace.record('settlement_gate', { label: 'order / authorization / payload digest', observed: [gate.paymentHash, gate.authorizationHash, gate.payloadHash] });
            trace.pass('settlement_gate');
            const settlementEvidence = responseEvidence({ result: { jsonrpc: '2.0', id: request.id, result: working }, rawRequest, context, gate, trace });
            trace.start('execution');
            const paymentResult = await backend.execute({ profile: DBAC_PAYMENT_PROFILE, payment, authorization: data.authorization, payload: data.payload, responseEvidence: settlementEvidence });
            if (!['EXECUTED', 'ALREADY_PROCESSED'].includes(paymentResult?.outcome) || !paymentResult.receipt || !same(validatePayment(Object.fromEntries(Object.keys(payment).map(key => [key, paymentResult.receipt[key]]))), payment)) fail('INVALID_PAYMENT_RESPONSE', '结算后端没有返回与本订单完全一致的支付回执。', 502);
            task = baseTask('completed', message.taskId, message.contextId);
            task.status.message = taskMessage(task, `DBAC 支付 ${paymentResult.outcome}。`, { 'x402.payment.status': 'payment-completed', 'x402.payment.receipts': [paymentResult.receipt.settlementResponse ?? paymentResult.settlementResponse ?? { success: true, transaction: paymentResult.receipt.transactionHash, network: payment.settlement?.network, payer: payment.settlement?.payerAddress }] });
            task.artifacts = [{ artifactId: randomUUID(), name: 'DBAC 设备绑定支付回执', parts: [{ kind: 'data', data: { profile: DBAC_PAYMENT_PROFILE, mode: context.mode, orderKey, scope: PAYMENT_SCOPE, anonymousCredentialVerified: true, deviceContributionVerified: true, paymentResult } }] }];
            trace.record('execution', { label: 'settlement outcome / transaction', observed: [paymentResult.outcome, publicValue(paymentResult.receipt.transactionHash)] });
            trace.pass('execution');
          }
        }
        const result = { jsonrpc: '2.0', id: request.id, result: task };
        const evidence = responseEvidence({ result, rawRequest, context, gate, trace });
        sendJson(res, 200, result, { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Payment-Response': evidence.proof });
        return true;
      } catch (error) {
        trace.fail(error);
        error.verificationTrace = trace.snapshot();
        // The caller's HTTP error renderer must preserve the backend's public
        // transaction/settlement evidence. Never infer a rollback from failure.
        throw error;
      }
    },
  };
}
