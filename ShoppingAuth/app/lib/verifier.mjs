import http from 'node:http';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { resolveDid, signJws, verifyJws, verifyCredential } from './identity.mjs';
import { AppError, EXTENSION, VERSION, SCOPE, POP_TYP, CHALLENGE_TYP, RESPONSE_TYP, DEVICE_POP_TYP, verifyDeviceProof, digest, unix, readBody, parseObject, sendJson, checkLocalRequest, requestScope } from './protocol.mjs';
import { PAYMENT_SCOPE, verifyPaymentAuthorization, validatePayment } from './payment.mjs';
import { createLedger } from './ledger.mjs';
import { createDbacVerifier } from './dbac/services.mjs';
import { createDbacPaymentVerifier } from './dbac/payment-verifier.mjs';
import { createVerificationTrace } from './verification-trace.mjs';

const rpcError = (id, code, message, reason) => ({ jsonrpc: '2.0', id, error: { code, message, ...(reason ? { data: { reason } } : {}) } });
const isObject = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
const stringId = (x) => typeof x === 'string' && x.length > 0 && x.length <= 256;
function boundedJsonDepth(value) {
  const stack = [[value, 0]];
  while (stack.length) {
    const [item, depth] = stack.pop();
    if (depth > 32) return false;
    if (item && typeof item === 'object') for (const child of Object.values(item)) stack.push([child, depth + 1]);
  }
  return true;
}

export function createVerifier({ identity, trustedIssuers, trustedAuthorizers = trustedIssuers, adminToken, maxEntries = 1000, ledgerPath = ':memory:', x402Backend = null, requireX402 = false, dbac = null, dbacOnly = false }) {
  let baseUrl;
  let payments = x402Backend;
  const challenges = new Map(), tasks = new Map(), contexts = new Map(), events = [];
  const paymentTaskLocks = new Map();
  const ledger = createLedger({ path: ledgerPath });
  const anonymous = dbac ? createDbacVerifier({ identity, issuerPublicKey: dbac.issuerPublicKey }) : null;
  const anonymousPayment = dbac && !dbacOnly ? createDbacPaymentVerifier({ identity, issuerPublicKey: dbac.issuerPublicKey, w3cIssuer: dbac.w3cIssuer, requireHolderProof: dbac.requireHolderProof, statusSource: dbac.statusSource, trustedMerchant: dbac.trustedMerchant, trustedAuthorizers, getBackend: () => payments, maxEntries }) : null;
  const audit = (event, data = {}) => {
    events.push({ time: new Date().toISOString(), event, ...data });
    if (events.length > 200) events.shift();
  };
  const card = () => dbacOnly ? anonymous.card(baseUrl) : ({
    protocolVersion: VERSION, name: 'Agent B · DID/VC 双签名验证服务', description: '核验 VC、jCardSim 设备证明与 Owner 授权，通过 x402 v2 在本地测试链结算，并提供 echo 任务。',
    url: `${baseUrl}/a2a`, preferredTransport: 'JSONRPC', version: '0.5.0',
    capabilities: { streaming: false, pushNotifications: false, extensions: [{
      uri: EXTENSION, description: '设备绑定 VC + 持有者与设备双签名，绑定同一挑战、凭证与请求。', required: true,
      params: { did: identity.did, challengeUrl: `${baseUrl}/auth/challenge`, credentialFormat: 'vc+jwt', proofType: POP_TYP, deviceProofType: DEVICE_POP_TYP, deviceProofHeader: 'X-A2A-Device-Proof', requireDevice: true, documentationUrl: EXTENSION },
    }, ...(requireX402 || payments ? [{ uri: 'https://github.com/google-a2a/a2a-x402/v0.1', description: 'x402 v2 A2A payment negotiation on a local test chain', required: false }] : []), ...(anonymous ? [{ uri: anonymous.metadata().extension, description: '论文设备绑定匿名凭证支付；独立 echo 仅用于机制检查', required: false, params: { agentCardUrl: `${baseUrl}/dbac/payment/agent-card.json`, endpoint: `${baseUrl}/dbac/payment/a2a`, auxAgentCardUrl: `${baseUrl}/dbac/agent-card.json`, auxEndpoint: `${baseUrl}/dbac/a2a`, paymentEndpoint: `${baseUrl}/dbac/payment/a2a`, paymentChallengeEndpoint: `${baseUrl}/dbac/payment/challenge` } }] : [])] },
    defaultInputModes: ['application/json'], defaultOutputModes: ['text/plain', 'application/json'],
    securitySchemes: { didVc: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT', description: 'Holder-signed DID PoP JWT with embedded VC; see required extension.' } },
    security: [{ didVc: [] }],
    skills: [
      { id: SCOPE, name: '经认证的消息回执', description: '验证凭证和持钥证明并回传文本。', tags: ['did', 'vc', 'echo'], examples: ['核验我的身份并返回消息回执。'] },
      { id: PAYMENT_SCOPE, name: '用户授权的模拟支付', description: 'Owner 单笔授权与设备证明通过后协商 x402，结算本地 TEST_USDC 并返回链上交易回执。', tags: ['payment', 'simulation', 'authorization'] },
    ],
  });
  function admin(req) {
    const supplied = Buffer.from(req.headers['x-demo-admin'] ?? '');
    const expected = Buffer.from(adminToken);
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new AppError('ADMIN_REQUIRED', '需要演示管理授权。', 403);
  }
  function authenticate(req, raw, trace) {
    trace.start('extension');
    if (!(req.headers['x-a2a-extensions'] ?? '').split(',').map(x => x.trim()).includes(EXTENSION)) {
      throw new AppError('EXTENSION_REQUIRED', '必须协商 DID/VC 扩展。', 400);
    }
    trace.pass('extension');
    trace.start('holder_envelope');
    const auth = req.headers.authorization ?? '';
    if (!auth.startsWith('Bearer ') || auth.length > 20000) throw new AppError('AUTHENTICATION_REQUIRED', '缺少持有者签署的 DID/VC 证明。', 401);
    trace.pass('holder_envelope');
    trace.start('holder_signature');
    let payload, signerDid;
    try { ({ payload, signerDid } = verifyJws(auth.slice(7), { typ: POP_TYP, purpose: 'authentication' })); }
    catch (error) { throw new AppError(error.code ?? 'INVALID_PROOF', error.message, 401); }
    trace.pass('holder_signature');
    trace.start('holder_binding');
    if (payload.iss !== signerDid || payload.aud !== identity.did) throw new AppError('PROOF_IDENTITY_MISMATCH', '持钥证明的签发者或接收者不匹配。', 401);
    trace.pass('holder_binding');
    trace.start('proof_time');
    if (!Number.isInteger(payload.iat) || !Number.isInteger(payload.exp) || payload.iat > unix() + 5 || payload.exp <= unix() || payload.exp <= payload.iat || payload.exp - payload.iat > 60 || !stringId(payload.jti)) {
      throw new AppError('PROOF_EXPIRED', '持钥证明时间或编号无效。', 401);
    }
    trace.pass('proof_time');
    trace.start('challenge');
    const challenge = challenges.get(payload.challengeId);
    if (!challenge || challenge.aud !== signerDid || challenge.nonce !== payload.nonce || challenge.target !== payload.target || challenge.exp <= unix() || payload.exp > challenge.exp) {
      throw new AppError('INVALID_CHALLENGE', '挑战不存在、已过期或绑定信息不匹配。', 401);
    }
    trace.pass('challenge');
    trace.start('replay');
    if (challenge.used) throw new AppError('REPLAYED_CHALLENGE', '该挑战已经使用。', 401);
    trace.pass('replay');
    trace.start('request_binding');
    if (payload.method !== 'POST' || payload.target !== `${baseUrl}/a2a` || payload.bodyHash !== digest(raw)) throw new AppError('REQUEST_BINDING_MISMATCH', '持钥证明未绑定此端点与请求正文。', 401);
    trace.pass('request_binding');
    trace.start('credential');
    let credential;
    try {
      credential = verifyCredential(payload.credential, { trustedIssuers, subjectDid: signerDid, audience: identity.did, scope: requestScope(raw, payload.credential), revokedIds: ledger.revokedIds(), requireDevice: true });
    } catch (error) { throw new AppError(error.code ?? 'INVALID_CREDENTIAL', error.message, 403); }
    trace.pass('credential');
    trace.start('device');
    const deviceProof = req.headers['x-a2a-device-proof'];
    const deviceDid = credential.credentialSubject.deviceDid;
    verifyDeviceProof(deviceProof, { holderProof: auth.slice(7), holderPayload: payload, deviceDid });
    trace.pass('device');
    trace.start('consume');
    // Validation + nonce consumption are synchronous with no await in between.
    challenge.used = true;
    trace.pass('consume');
    audit('authenticated', { holderDid: signerDid, deviceDid, credentialId: credential.id, dualSignature: true });
    return { holderDid: signerDid, payload, credential, deviceDid, deviceProof, trace };
  }
  async function execute(rpc, auth, lockedTaskId = null) {
    const id = rpc?.id ?? null;
    if (!isObject(rpc) || rpc.jsonrpc !== '2.0' || !(typeof id === 'string' || Number.isSafeInteger(id)) || rpc.id === undefined || !stringId(rpc.method)) {
      return rpcError(null, -32600, 'Invalid Request');
    }
    // Bound the complete input before any durable side effect. A shallow
    // protocol body may contain metadata too deep for structuredClone later.
    if (!boundedJsonDepth(rpc)) return rpcError(id, -32602, 'JSON nesting exceeds the profile limit of 32');
    if (!['message/send', 'tasks/get', 'tasks/cancel'].includes(rpc.method)) return rpcError(id, -32601, 'Method not found');
    const params = rpc.params;
    if (!isObject(params)) return rpcError(id, -32602, 'Invalid params');
    if (params.metadata !== undefined && !isObject(params.metadata)) return rpcError(id, -32602, 'Invalid metadata');
    if (rpc.method !== 'message/send') {
      if (!stringId(params.id) || (params.historyLength !== undefined && (!Number.isInteger(params.historyLength) || params.historyLength < 0))) return rpcError(id, -32602, 'Invalid task query');
      const entry = tasks.get(params.id);
      if (!entry || entry.holderDid !== auth.holderDid) return rpcError(id, -32001, 'Task not found');
      if (!auth.credential.credentialSubject.scopes.includes(entry.scope)) throw new AppError('CREDENTIAL_SCOPE_DENIED', '当前 VC 未授予此任务的业务权限。', 403);
      if (rpc.method === 'tasks/cancel') return rpcError(id, -32002, 'Task cannot be canceled');
      const result = structuredClone(entry.task);
      if (params.historyLength !== undefined) result.history = params.historyLength === 0 ? [] : result.history.slice(-params.historyLength);
      return { jsonrpc: '2.0', id, result };
    }
    const message = params.message;
    if (!isObject(message) || message.kind !== 'message' || message.role !== 'user' || !stringId(message.messageId) || !Array.isArray(message.parts) || message.parts.length !== 1) {
      return rpcError(id, -32602, 'Invalid user Message');
    }
    if (message.extensions !== undefined && (!Array.isArray(message.extensions) || message.extensions.some(x => typeof x !== 'string'))) return rpcError(id, -32602, 'Invalid message extensions');
    if (message.metadata !== undefined && !isObject(message.metadata)) return rpcError(id, -32602, 'Invalid message metadata');
    if (message.referenceTaskIds !== undefined && (!Array.isArray(message.referenceTaskIds) || message.referenceTaskIds.some(x => !stringId(x)))) return rpcError(id, -32602, 'Invalid referenceTaskIds');
    const part = message.parts[0];
    if (!isObject(part) || part.kind !== 'data' || !isObject(part.data)) return rpcError(id, -32005, 'Content type not supported');
    if (part.metadata !== undefined && !isObject(part.metadata)) return rpcError(id, -32602, 'Invalid part metadata');
    const isPayment = part.data.scope === PAYMENT_SCOPE;
    if (!isPayment && (part.data.scope !== SCOPE || typeof part.data.text !== 'string' || part.data.text.length === 0 || part.data.text.length > 4000)) {
      return rpcError(id, -32602, 'Expected data {scope: "demo:echo", text: string (1..4000)}');
    }
    if (isPayment && Object.keys(part.data).some(key => !['scope', 'payment', 'authorization'].includes(key))) return rpcError(id, -32602, 'Unsupported payment fields');
    if (params.configuration !== undefined) {
      const c = params.configuration;
      if (!isObject(c)) return rpcError(id, -32602, 'Invalid configuration');
      if (c.blocking !== undefined && typeof c.blocking !== 'boolean') return rpcError(id, -32602, 'Invalid blocking');
      if (c.pushNotificationConfig !== undefined) return rpcError(id, -32003, 'Push notifications are not supported');
      if (c.acceptedOutputModes !== undefined && (!Array.isArray(c.acceptedOutputModes) || c.acceptedOutputModes.some(x => typeof x !== 'string'))) return rpcError(id, -32602, 'Invalid acceptedOutputModes');
      if (c.acceptedOutputModes?.length && !['application/json', 'text/plain'].some(x => c.acceptedOutputModes.includes(x))) return rpcError(id, -32005, 'No compatible output mode');
      if (c.historyLength !== undefined && (!Number.isInteger(c.historyLength) || c.historyLength < 0)) return rpcError(id, -32602, 'Invalid historyLength');
    }
    const previous = message.taskId !== undefined ? tasks.get(message.taskId) : null;
    if (message.taskId !== undefined && (!previous || previous.holderDid !== auth.holderDid)) return rpcError(id, -32001, 'Task not found');
    if (previous && (!isPayment || !payments || previous.scope !== PAYMENT_SCOPE || previous.authorizationHash !== digest(part.data.authorization ?? '') || previous.paymentJson !== JSON.stringify(validatePayment(part.data.payment)))) return rpcError(id, -32602, 'Task continuation does not match the approved payment');
    if (previous && message.contextId !== undefined && message.contextId !== previous.task.contextId) return rpcError(id, -32602, 'Task context mismatch');
    if (message.contextId !== undefined && (!stringId(message.contextId) || contexts.get(message.contextId) !== auth.holderDid)) return rpcError(id, -32602, 'Unknown or inaccessible context');
    if (!previous && tasks.size >= maxEntries) return rpcError(id, -32603, 'Demo task capacity reached; restart the demo');
    let paymentResult;
    if (isPayment) {
      const revalidateBusiness = () => {
        verifyCredential(auth.payload.credential, { trustedIssuers, subjectDid: auth.holderDid, audience: identity.did, scope: PAYMENT_SCOPE, revokedIds: ledger.revokedIds(), requireDevice: true });
        return verifyPaymentAuthorization(part.data.authorization, {
          trustedAuthorizers, holderDid: auth.holderDid, deviceDid: auth.deviceDid,
          verifierDid: identity.did, credential: auth.payload.credential, payment: part.data.payment,
        });
      };
      let approval = revalidateBusiness();
      if (requireX402 && !payments) throw new AppError('X402_NOT_READY', 'x402 支付后端尚未就绪。', 503);
      if (payments) {
        if (previous && lockedTaskId !== previous.task.id) {
          // Authenticate and verify Owner authorization before queueing. Read
          // the task again after acquiring its lock: a preceding continuation
          // may have completed while this request was waiting.
          const taskId = previous.task.id;
          const ahead = paymentTaskLocks.get(taskId) ?? Promise.resolve();
          let release;
          const held = new Promise(resolve => { release = resolve; });
          paymentTaskLocks.set(taskId, held);
          await ahead;
          try { return await execute(rpc, auth, taskId); }
          finally {
            release();
            if (paymentTaskLocks.get(taskId) === held) paymentTaskLocks.delete(taskId);
          }
        }
        if (previous && ['completed', 'failed'].includes(previous.task.status.state)) {
          const result = structuredClone(previous.task);
          if (result.status.state === 'completed') {
            // Preserve the stored Task and its historical receipt. This retry
            // only changes the returned current view's business outcome.
            const replayPart = part => part.kind === 'data' && part.data?.paymentResult
              ? { ...part, data: { ...part.data, paymentResult: { ...part.data.paymentResult, outcome: 'ALREADY_PROCESSED' } } }
              : part.kind === 'text' ? { ...part, text: part.text.replace(/\bEXECUTED\b/g, 'ALREADY_PROCESSED') } : part;
            result.artifacts = result.artifacts?.map(artifact => ({ ...artifact, parts: artifact.parts.map(replayPart) }));
            if (result.status.message) result.status.message = { ...result.status.message, parts: result.status.message.parts.map(replayPart) };
          }
          if (params.configuration?.historyLength !== undefined) result.history = params.configuration.historyLength === 0 ? [] : result.history.slice(-params.configuration.historyLength);
          return { jsonrpc: '2.0', id, result };
        }
        const snapshot = await payments.snapshot();
        approval = revalidateBusiness();
        const priorReceipt = snapshot.receipts.find(r => r.orderId === part.data.payment.orderId && r.payerAccount === part.data.payment.payerAccount);
        if (priorReceipt) {
          const keys = ['orderId', 'payerAccount', 'payeeAccount', 'amountMinor', 'currency', 'settlement'];
          const oldPayment = Object.fromEntries(keys.filter(k => priorReceipt[k] !== undefined).map(k => [k, priorReceipt[k]]));
          if (JSON.stringify(validatePayment(oldPayment)) !== JSON.stringify(validatePayment(part.data.payment))) throw new AppError('PAYMENT_ORDER_CONFLICT', '此订单已按不同条款结算。', 409);
          paymentResult = { outcome: 'ALREADY_PROCESSED', receipt: priorReceipt };
        } else {
          const payload = message.metadata?.['x402.payment.payload'];
          if (!payload) {
            const taskId = previous?.task.id ?? randomUUID(), contextId = previous?.task.contextId ?? message.contextId ?? randomUUID();
            const required = await payments.requirements(part.data.payment, { resourceUrl: `${baseUrl}/a2a`, taskId });
            revalidateBusiness();
            const resultMessage = { kind: 'message', role: 'agent', messageId: randomUUID(), contextId, taskId,
              parts: [{ kind: 'text', text: 'Owner 授权与卡端证明已验证。请提交 x402 测试代币付款凭证。' }],
              metadata: { 'x402.payment.status': 'payment-required', 'x402.payment.required': required } };
            const task = { kind: 'task', id: taskId, contextId, status: { state: 'input-required', timestamp: new Date().toISOString(), message: resultMessage }, history: [...(previous?.task.history ?? []), structuredClone(message), resultMessage] };
            contexts.set(contextId, auth.holderDid);
            tasks.set(taskId, { holderDid: auth.holderDid, scope: PAYMENT_SCOPE, task, authorizationHash: digest(part.data.authorization), paymentJson: JSON.stringify(validatePayment(part.data.payment)) });
            audit('x402_payment_required', { taskId, orderId: part.data.payment.orderId });
            return { jsonrpc: '2.0', id, result: task };
          }
          if (!previous || message.metadata?.['x402.payment.status'] !== 'payment-submitted') throw new AppError('X402_TASK_REQUIRED', 'x402 付款必须继续已建立的付款任务。');
          try {
            paymentResult = await payments.execute({ approval, payment: part.data.payment, payload, authorization: part.data.authorization, credential: auth.payload.credential });
          } catch (error) {
            // A backend may recheck a credential or Owner authorization after
            // the initial request check. These rejections are not payment
            // lifecycle events and must not mutate an existing task.
            if (/^(?:CREDENTIAL_|INVALID_CREDENTIAL|PAYMENT_AUTHORIZ|INVALID_PAYMENT_AUTHORIZATION|PAYMENT_TERMS_MISMATCH|X402_DEVICE_BINDING_MISMATCH|AUTHENTICATION_|INVALID_SIGNATURE|INVALID_DID|STATUS_UNAVAILABLE)/.test(error.code ?? '')) throw error;
            const code = typeof error.code === 'string' && error.code.length <= 128 ? error.code : 'X402_PAYMENT_FAILED';
            const reported = error.settlementResponse ?? error.receipt ?? {};
            const transaction = [reported.transaction, error.transaction, error.transactionHash].find(value => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value)) ?? '';
            const uncertain = Boolean(transaction) || /PENDING|TIMEOUT|TIMED_OUT|ECONNRESET|UND_ERR|fetch failed/i.test(`${code} ${error.message ?? ''}`);
            const resultMessage = {
              kind: 'message', role: 'agent', messageId: randomUUID(), contextId: previous.task.contextId, taskId: previous.task.id,
              parts: [{ kind: 'text', text: uncertain
                ? `付款处理未确认（${code}）。交易可能已广播或仍在确认，请用同一订单重新查询回执；这不表示资金已回滚。`
                : `付款处理失败（${code}），未取得成功结算回执。请核对原订单状态后处理。` }],
              metadata: {
                'x402.payment.status': 'payment-failed', 'x402.payment.error': code,
                'x402.payment.receipts': [{ success: false, errorReason: reported.errorReason ?? code, network: part.data.payment.settlement.network, transaction }],
              },
            };
            const failedTask = { ...previous.task, status: { state: 'failed', timestamp: new Date().toISOString(), message: resultMessage }, history: [...(previous.task.history ?? []), structuredClone(message), resultMessage] };
            tasks.set(previous.task.id, { ...previous, task: failedTask });
            audit('x402_payment_failed', { taskId: previous.task.id, orderId: part.data.payment.orderId, code, settlementUnconfirmed: uncertain, ...(transaction ? { transaction } : {}) });
            const result = structuredClone(failedTask);
            if (params.configuration?.historyLength !== undefined) result.history = params.configuration.historyLength === 0 ? [] : result.history.slice(-params.configuration.historyLength);
            return { jsonrpc: '2.0', id, result };
          }
        }
      } else {
      // The final executor verifies original signed evidence before entering
      // the durable transaction. A/device APIs never alter ledger balances.
      paymentResult = ledger.execute({
        authorizationId: approval.authorizationId, authorizationHash: digest(part.data.authorization),
        authorizerDid: approval.iss, holderDid: auth.holderDid, deviceDid: auth.deviceDid,
        verifierDid: identity.did, payment: part.data.payment,
      });
      }
      audit('payment_processed', { outcome: paymentResult.outcome, receiptId: paymentResult.receipt.receiptId, orderId: part.data.payment.orderId });
    }
    const contextId = previous?.task.contextId ?? message.contextId ?? randomUUID(), taskId = previous?.task.id ?? randomUUID();
    contexts.set(contextId, auth.holderDid);
    const acceptedModes = params.configuration?.acceptedOutputModes;
    const allowText = !acceptedModes?.length || acceptedModes.includes('text/plain');
    const allowData = !acceptedModes?.length || acceptedModes.includes('application/json');
    const outputParts = [
      ...(allowText ? [{ kind: 'text', text: isPayment ? `模拟支付 ${paymentResult.outcome}；回执 ${paymentResult.receipt.receiptId}` : `已验证 DID 与 VC。Agent B 收到：${part.data.text}` }] : []),
      ...(allowData ? [{ kind: 'data', data: { holderDid: auth.holderDid, deviceDid: auth.deviceDid, dualSignature: true, verifierDid: identity.did, credentialId: auth.credential.id, scope: part.data.scope, ...(isPayment ? { paymentResult } : { text: part.data.text }) } }] : []),
    ];
    const resultMessage = {
      kind: 'message', role: 'agent', messageId: randomUUID(), contextId, taskId,
      parts: outputParts,
      ...(isPayment && payments ? { metadata: { 'x402.payment.status': 'payment-completed', 'x402.payment.receipts': [paymentResult.receipt.settlementResponse ?? { success: true, transaction: paymentResult.receipt.transactionHash, network: part.data.payment.settlement.network, payer: part.data.payment.settlement.payerAddress }] } } : {}),
    };
    const task = {
      kind: 'task', id: taskId, contextId,
      status: { state: 'completed', timestamp: new Date().toISOString(), message: resultMessage },
      artifacts: [{ artifactId: randomUUID(), name: isPayment ? '模拟支付回执' : '身份核验回执', parts: outputParts }],
      history: [...(previous?.task.history ?? []), structuredClone(message), resultMessage],
    };
    tasks.set(taskId, { holderDid: auth.holderDid, scope: part.data.scope, task, ...(isPayment ? { authorizationHash: digest(part.data.authorization), paymentJson: JSON.stringify(validatePayment(part.data.payment)) } : {}) });
    audit('task_completed', { holderDid: auth.holderDid, deviceDid: auth.deviceDid, taskId, credentialId: auth.credential.id });
    const result = structuredClone(task);
    if (params.configuration?.historyLength !== undefined) result.history = params.configuration.historyLength === 0 ? [] : result.history.slice(-params.configuration.historyLength);
    return { jsonrpc: '2.0', id, result };
  }
  function signedResponse(res, body, auth, raw) {
    if (body.error) auth.trace.fail({ code: body.error.data?.reason ?? body.error.code });
    else if (body.result?.status?.state === 'failed') auth.trace.fail({ code: body.result.status.message?.metadata?.['x402.payment.error'] ?? 'TASK_FAILED' });
    else auth.trace.pass('execution');
    const verificationTrace = auth.trace.snapshot();
    const responseText = JSON.stringify(body);
    const proof = signJws({ iss: identity.did, aud: auth.holderDid, deviceDid: auth.deviceDid, deviceProofHash: digest(auth.deviceProof), requestHash: digest(raw), responseHash: digest(responseText), nonce: auth.payload.nonce, verificationTrace, iat: unix(), exp: unix() + 60 }, identity, RESPONSE_TYP);
    sendJson(res, 200, body, { 'X-A2A-Extensions': EXTENSION, 'X-A2A-DID-Response': proof });
  }
  const server = http.createServer({ maxHeaderSize: 24 * 1024, requestTimeout: 10000, headersTimeout: 10000 }, async (req, res) => {
    let rpcId = null;
    const trace = req.method === 'POST' && req.url === '/a2a' ? createVerificationTrace('identity') : null;
    trace?.start('request');
    try {
      checkLocalRequest(req, baseUrl);
      if (anonymousPayment && req.url.startsWith('/dbac/payment/') && await anonymousPayment.handle(req, res, baseUrl)) return;
      if (anonymous && req.url.startsWith('/dbac/') && await anonymous.handle(req, res, baseUrl)) return;
      if (req.method === 'GET' && req.url === '/health') return sendJson(res, 200, { ok: true, service: 'agent-b', protocolVersion: VERSION, appVersion: '0.5.0', paymentProtocol: dbacOnly ? null : payments ? 'x402-v2' : 'compatibility-fixture', paymentReady: Boolean(payments), localTestOnly: true, securityProfile: dbacOnly ? anonymous.metadata().extension : EXTENSION, deviceRequired: true, paymentApprovalRequired: !dbacOnly, dbacAvailable: Boolean(anonymous), persistentLedger: ledgerPath !== ':memory:', pid: process.pid, did: identity.did });
      if (req.method === 'GET' && req.url === '/.well-known/agent-card.json') return sendJson(res, 200, card());
      if (req.method === 'GET' && req.url === '/did.json') return sendJson(res, 200, resolveDid(identity.did));
      if (req.method === 'GET' && req.url === '/admin/audit') { admin(req); return sendJson(res, 200, { events, stats: { tasks: tasks.size, revoked: ledger.revokedIds().size } }); }
      if (req.method === 'GET' && new URL(req.url, baseUrl).pathname === '/admin/credential-status') {
        admin(req);
        const query = new URL(req.url, baseUrl).searchParams, id = query.get('id');
        if (!stringId(id) || id.trim() !== id || /[\u0000-\u001f\u007f]/.test(id) || query.getAll('id').length !== 1) throw new AppError('INVALID_ID', '查询撤销状态需要唯一有效的凭证 ID。');
        return sendJson(res, 200, { id, revoked: ledger.revokedIds().has(id) });
      }
      if (req.method === 'GET' && req.url === '/admin/ledger') { admin(req); return sendJson(res, 200, payments ? await payments.snapshot() : ledger.snapshot()); }
      if (req.method === 'POST' && req.url === '/admin/revoke') {
        admin(req); const body = parseObject(await readBody(req));
        if (!stringId(body.id)) throw new AppError('INVALID_ID', '撤销需要凭证 ID。');
        ledger.revokeCredential(body.id); audit('credential_revoked', { credentialId: body.id }); return sendJson(res, 200, { revoked: true, id: body.id });
      }
      if (req.method === 'POST' && req.url === '/auth/challenge') {
        const body = parseObject(await readBody(req)); resolveDid(body.holderDid);
        for (const [id, c] of challenges) if (c.exp <= unix()) challenges.delete(id);
        if (challenges.size >= maxEntries) throw new AppError('CAPACITY_REACHED', '挑战请求过多，请稍后重试。', 429);
        const payload = { iss: identity.did, aud: body.holderDid, jti: randomUUID(), nonce: randomBytes(32).toString('base64url'), target: `${baseUrl}/a2a`, iat: unix(), exp: unix() + 60 };
        challenges.set(payload.jti, { ...payload, used: false });
        return sendJson(res, 200, { challenge: signJws(payload, identity, CHALLENGE_TYP) });
      }
      if (req.method === 'POST' && req.url === '/a2a') {
        const raw = await readBody(req);
        // Authenticate exact bytes even for a malformed JSON-RPC body, then report a standard error.
        trace.pass('request');
        const auth = authenticate(req, raw, trace);
        trace.start('execution');
        let rpc;
        try { rpc = JSON.parse(raw); } catch { return signedResponse(res, rpcError(null, -32700, 'Parse error'), auth, raw); }
        rpcId = typeof rpc?.id === 'string' || typeof rpc?.id === 'number' ? rpc.id : null;
        return signedResponse(res, await execute(rpc, auth), auth, raw);
      }
      sendJson(res, 404, { error: { code: 'NOT_FOUND', message: '接口不存在。' } });
    } catch (error) {
      const status = error.status ?? 400;
      trace?.fail(error);
      const verificationTrace = error.verificationTrace ?? trace?.snapshot();
      audit('request_rejected', { code: error.code ?? 'INVALID_REQUEST', ...(verificationTrace ? { verificationTrace } : {}) });
      const headers = status === 401 ? { 'WWW-Authenticate': 'Bearer realm="a2a-did-vc", error="invalid_token"' } : {};
      if (req.url === '/a2a') {
        const body = rpcError(rpcId, error.code === 'EXTENSION_REQUIRED' ? -32602 : -32000, error.message, error.code ?? 'INVALID_REQUEST');
        if (verificationTrace) body.error.data.verificationTrace = verificationTrace;
        return sendJson(res, status, body, headers);
      }
      sendJson(res, status, { error: { code: error.code ?? 'INVALID_REQUEST', message: error.message, ...Object.fromEntries(['transaction', 'transactionHash', 'settlementResponse'].filter(key => error[key] !== undefined).map(key => [key, error[key]])) }, ...(verificationTrace ? { verificationTrace } : {}) }, headers);
    }
  });
  return {
    server, card, get baseUrl() { return baseUrl; },
    setPaymentBackend(backend) { if (payments) throw new Error('Payment backend already configured'); payments = backend; },
    async listen(port = 0) {
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
      baseUrl = `http://127.0.0.1:${server.address().port}`; return baseUrl;
    },
    async close() {
      server.closeAllConnections();
      try { await new Promise((resolve, reject) => server.close(e => e && e.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(e) : resolve())); }
      finally { ledger.close(); }
    },
  };
}
