import http from 'node:http';
import { randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { generateIssuerKey, generateDeviceKey, issueCredential, signDeviceRequest, verifyDeviceResponse, verifyPresentation, DBAC_SUITE, DBAC_VERSION } from './crypto.mjs';
import { signJws, resolveDid } from '../identity.mjs';
import { createVerificationTrace } from '../verification-trace.mjs';
import { AppError, checkLocalRequest, digest, parseObject, readBody, sendJson, unix } from '../protocol.mjs';
import { DBAC_EXTENSION, DBAC_CHALLENGE_TYP, DBAC_RESPONSE_TYP, DBAC_SCHEMA, DBAC_MODES, demoAttributes, paymentAttributes, requiredDisclosures, exact } from './policy.mjs';
import { createW3cBbsIssuer } from '../w3c-bbs.mjs';
import { W3C_PAYMENT_PROFILE, W3C_PAYMENT_SCHEMA } from './w3c-profile.mjs';
import { createCredentialStatusStore } from './credential-status.mjs';

function capability(token) {
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('DBAC requires an independent 32-byte access capability');
  const expected = Buffer.from(token);
  return req => {
    const received = Buffer.from(req.headers['x-dbac-access'] ?? '');
    if (received.length !== expected.length || !timingSafeEqual(received, expected)) throw new AppError('DBAC_ACCESS_DENIED', '缺少该独立角色的调用权限。', 403);
  };
}

function localService(handler) {
  let baseUrl;
  const server = http.createServer({ requestTimeout: 15000 }, async (req, res) => {
    try {
      checkLocalRequest(req, baseUrl);
      if (!await handler(req, res)) sendJson(res, 404, { error: { code: 'NOT_FOUND', message: '接口不存在。' } });
    } catch (error) { sendJson(res, error.status ?? 400, { error: { code: error.code ?? 'DBAC_INVALID_REQUEST', message: error.message } }); }
  });
  return {
    server,
    async listen(port = 0) {
      await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      return baseUrl;
    },
    async close() { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); },
  };
}

export function createDbacDevice({ accessToken }) {
  const authorize = capability(accessToken);
  // Created in this role, never received from A or exported through its API/IPC.
  // Separate keys prevent an unrestricted blind-signing oracle for the key
  // whose ordinary profile is supposed to see presentation contexts.
  const devices = new Map();
  function addDevice(deviceId = `device:${randomUUID()}`) {
    devices.set(deviceId, { keys: Object.fromEntries(DBAC_MODES.map(mode => [mode, generateDeviceKey()])),
      modes: Object.fromEntries(DBAC_MODES.map(mode => [mode, { locked: false, signatures: 0, denied: 0 }])), logs: [] });
    return deviceId;
  }
  addDevice('default');
  const publicInfo = (deviceId = 'default') => {
    const device = devices.get(deviceId);
    if (!device) throw new AppError('DBAC_DEVICE_UNKNOWN', '演示设备不存在。', 404);
    return { deviceId, publicKeys: Object.fromEntries(DBAC_MODES.map(mode => [mode, device.keys[mode].publicKey])), modes: structuredClone(device.modes), backend: 'node-bls12-381', suite: DBAC_SUITE, hardware: false, keyExportable: false, pid: process.pid };
  };
  function audit(device, mode, operation, request, outcome) {
    device.logs.push({ id: randomUUID(), at: new Date().toISOString(), mode, operation, inputHash: digest(JSON.stringify(request)), outcome });
    if (device.logs.length > 100) device.logs.shift();
  }
  const service = localService(async (req, res) => {
    const deviceId = req.headers['x-dbac-device'] ?? 'default';
    if (req.method === 'GET' && req.url === '/health') { sendJson(res, 200, publicInfo(deviceId)); return true; }
    authorize(req);
    if (req.method === 'GET' && req.url === '/devices') { sendJson(res, 200, { devices: [...devices.keys()].map(id => ({ ...publicInfo(id), logs: structuredClone(devices.get(id).logs) })) }); return true; }
    if (req.method === 'POST' && req.url === '/devices') {
      const body = parseObject(await readBody(req));
      if (!exact(body, [])) throw new AppError('DBAC_INVALID_DEVICE', '创建设备不接受调用方私钥或自定义密钥。');
      if (devices.size >= 32) throw new AppError('DBAC_CAPACITY', '演示设备数量已达上限。', 429);
      sendJson(res, 201, publicInfo(addDevice())); return true;
    }
    publicInfo(deviceId);
    const device = devices.get(deviceId), keys = device.keys, status = device.modes;
    if (req.method === 'POST' && req.url === '/lock') {
      const body = parseObject(await readBody(req));
      if (!exact(body, ['locked', 'mode']) || typeof body.locked !== 'boolean' || !DBAC_MODES.includes(body.mode)) throw new AppError('INVALID_LOCK', '需要有效 mode 和布尔 locked。');
      status[body.mode].locked = body.locked; audit(device, body.mode, 'lock', body, body.locked ? 'locked' : 'unlocked'); sendJson(res, 200, publicInfo(deviceId)); return true;
    }
    if (req.method === 'POST' && req.url === '/sign') {
      const request = parseObject(await readBody(req));
      if (!DBAC_MODES.includes(request.mode)) throw new AppError('DBAC_INVALID_MODE', '不支持的签名模式。');
      if (status[request.mode].locked) { status[request.mode].denied++; audit(device, request.mode, 'sign', request, 'DBAC_DEVICE_LOCKED'); throw new AppError('DBAC_DEVICE_LOCKED', 'BLS 软件安全模块已锁定。', 403); }
      // Blind mode accepts only the blinded group point: no hidden out-of-band
      // context, credential, stable holder identity, or registration data.
      const response = signDeviceRequest({ deviceSecretKey: keys[request.mode].secretKey, request });
      status[request.mode].signatures++;
      audit(device, request.mode, 'sign', request, 'signed');
      sendJson(res, 200, response); return true;
    }
    if (req.method === 'POST' && req.url === '/enroll/sign') {
      const body = parseObject(await readBody(req));
      if (!exact(body, ['mode', 'request']) || !DBAC_MODES.includes(body.mode) || body.request?.mode !== 'bbs-bls' || body.request?.context?.purpose !== 'dbac-enrollment-v1' || body.request.context.mode !== body.mode || body.request.randomizedDevicePublicKey !== keys[body.mode].publicKey) throw new AppError('DBAC_ISSUANCE_POLICY', '只能签署与本设备绑定的注册专用挑战。');
      if (status[body.mode].locked) { status[body.mode].denied++; audit(device, body.mode, 'enroll/sign', body.request, 'DBAC_DEVICE_LOCKED'); throw new AppError('DBAC_DEVICE_LOCKED', 'BLS 软件安全模块已锁定。', 403); }
      const response = signDeviceRequest({ deviceSecretKey: keys[body.mode].secretKey, request: body.request });
      status[body.mode].signatures++;
      audit(device, body.mode, 'enroll/sign', body.request, 'signed');
      sendJson(res, 200, response); return true;
    }
    return false;
  });
  return { ...service, publicInfo };
}

export function createDbacIssuer({ accessToken, statusToken, devicePublicKeys, w3c = false, requireHolderProof = false, statePath }) {
  const authorize = capability(accessToken);
  const authorizeStatus = capability(statusToken ?? accessToken);
  const credentialStatus = createCredentialStatusStore({ statePath });
  const registeredDevices = new Map([['default', structuredClone(devicePublicKeys)]]);
  const keys = generateIssuerKey();
  const registrations = new Map();
  let w3cIssuer;
  const ready = w3c ? createW3cBbsIssuer().then(value => { w3cIssuer = value; }) : Promise.resolve();
  const publicInfo = () => ({ publicKey: keys.publicKey, suite: DBAC_SUITE, schema: DBAC_SCHEMA, ...(w3cIssuer ? { w3c: w3cIssuer.publicInfo(), paymentCredentialProfile: W3C_PAYMENT_PROFILE, paymentSchema: W3C_PAYMENT_SCHEMA, holderProofRequired: requireHolderProof, statusPersistence: credentialStatus.persistence } : {}), pid: process.pid });
  const service = localService(async (req, res) => {
    if (req.method === 'GET' && req.url === '/health') { sendJson(res, 200, publicInfo()); return true; }
    if (req.method === 'POST' && req.url === '/credential/status') {
      // The issuer manager may inspect status; B receives only a separate read capability.
      try { authorizeStatus(req); } catch { authorize(req); }
      const body = parseObject(await readBody(req));
      if (!exact(body, ['bindingId']) || typeof body.bindingId !== 'string') throw new AppError('W3C_CREDENTIAL_STATUS_INVALID', '需要有效凭证绑定标识。');
      sendJson(res, 200, { ...credentialStatus.status(body.bindingId), checkedAt: new Date().toISOString() }); return true;
    }
    authorize(req);
    if (req.method === 'GET' && req.url === '/credentials') { sendJson(res, 200, { credentials: credentialStatus.list(), source: 'local-issuer-status-table', persistence: credentialStatus.persistence }); return true; }
    if (req.method === 'POST' && req.url === '/credentials/revoke') {
      const body = parseObject(await readBody(req));
      if (!exact(body, ['bindingId'])) throw new AppError('W3C_CREDENTIAL_STATUS_INVALID', '撤销仅接受凭证绑定标识。');
      sendJson(res, 200, credentialStatus.revoke(body.bindingId)); return true;
    }
    if (req.method === 'POST' && req.url === '/devices/register') {
      const body = parseObject(await readBody(req));
      if (!exact(body, ['deviceId', 'publicKeys']) || typeof body.deviceId !== 'string' || !/^device:[0-9a-f-]{36}$/.test(body.deviceId) || !exact(body.publicKeys, DBAC_MODES) || !DBAC_MODES.every(mode => typeof body.publicKeys[mode] === 'string' && /^[0-9a-f]{96}$/.test(body.publicKeys[mode]))) throw new AppError('DBAC_ISSUANCE_POLICY', '登记设备需要受控设备标识和两种模式的公钥。');
      if (registeredDevices.has(body.deviceId)) throw new AppError('DBAC_DEVICE_ALREADY_REGISTERED', '不支持覆盖设备登记或凭证换绑。', 409);
      registeredDevices.set(body.deviceId, structuredClone(body.publicKeys));
      sendJson(res, 201, { deviceId: body.deviceId, registered: true }); return true;
    }
    if (req.method === 'POST' && req.url === '/enroll/challenge') {
      const body = parseObject(await readBody(req));
      if (!Object.hasOwn(body, 'mode') || Object.keys(body).some(key => !['mode', 'scope', 'holderDid', 'deviceId'].includes(key)) || !DBAC_MODES.includes(body.mode) || (body.scope !== undefined && !['demo:echo', 'payments:pay'].includes(body.scope))) throw new AppError('DBAC_ISSUANCE_POLICY', '注册仅面向预登记的模式、设备及 echo/支付范围。');
      const deviceId = body.deviceId ?? 'default';
      if (!registeredDevices.has(deviceId)) throw new AppError('DBAC_DEVICE_UNKNOWN', '签发方未登记该设备。');
      if (body.holderDid !== undefined) { try { resolveDid(body.holderDid); } catch { throw new AppError('HOLDER_KEY_INVALID', '持有者公钥必须为可解析的本地 did:key。'); } }
      if (requireHolderProof && w3c && body.scope === 'payments:pay' && !body.holderDid) throw new AppError('HOLDER_KEY_REQUIRED', '主线凭证必须在签发时绑定 A 端公钥。');
      for (const [id, entry] of registrations) if (entry.exp <= unix()) registrations.delete(id);
      if (registrations.size >= 32) throw new AppError('DBAC_CAPACITY', '注册挑战过多。', 429);
      const registrationId = randomUUID(), bindingId = w3c && body.scope === 'payments:pay' ? `urn:uuid:${randomUUID()}` : null;
      const attributes = body.scope === 'payments:pay' ? [...paymentAttributes(body.mode), ...(bindingId ? [bindingId] : [])] : demoAttributes(body.mode), exp = unix() + 60;
      const devicePublicKey = registeredDevices.get(deviceId)[body.mode];
      const request = { version: DBAC_VERSION, suite: DBAC_SUITE, mode: 'bbs-bls', randomizedDevicePublicKey: devicePublicKey, context: { purpose: 'dbac-enrollment-v1', mode: body.mode, issuerPublicKey: keys.publicKey, nonce: randomBytes(32).toString('base64url'), attributeHash: digest(JSON.stringify(attributes)), exp } };
      registrations.set(registrationId, { request, attributes, exp, devicePublicKey, bindingId, holderDid: body.holderDid, deviceId });
      sendJson(res, 200, { registrationId, request, ...(bindingId ? { bindingId } : {}) }); return true;
    }
    if (req.method === 'POST' && req.url === '/issue') {
      const body = parseObject(await readBody(req));
      if (!exact(body, ['registrationId', 'response'])) throw new AppError('DBAC_ISSUANCE_POLICY', '签发需要一次性注册挑战及预登记设备的持钥证明。');
      const entry = registrations.get(body.registrationId);
      if (!entry || entry.exp <= unix()) throw new AppError('DBAC_REGISTRATION_EXPIRED', '注册挑战不存在、已使用或已过期。');
      verifyDeviceResponse({ devicePublicKey: entry.devicePublicKey, request: entry.request, response: body.response });
      registrations.delete(body.registrationId);
      const credential = issueCredential({ issuerSecretKey: keys.secretKey, devicePublicKey: entry.devicePublicKey, attributes: entry.attributes });
      let verifiableCredential;
      if (entry.bindingId) {
        const [role, scope, epoch, mode, organization, holderLabel, bindingId] = entry.attributes;
        const validFrom = `${epoch}T00:00:00.000Z`, validUntil = new Date(Date.parse(validFrom) + 86400000).toISOString();
        verifiableCredential = await w3cIssuer.issue({ credentialSubject: { role, scope, epoch, mode, bindingId, organization, holderLabel, ...(entry.holderDid ? { holderDid: entry.holderDid } : {}) }, validFrom, validUntil });
        credentialStatus.issue({ bindingId, issuer: w3cIssuer.publicInfo().issuer, ...(entry.holderDid ? { holderDid: entry.holderDid } : {}), deviceId: entry.deviceId, deviceFingerprint: digest(entry.devicePublicKey), mode, role, scope, validFrom, validUntil });
      }
      sendJson(res, 200, { credential, ...(verifiableCredential ? { verifiableCredential } : {}) }); return true;
    }
    return false;
  });
  return { ...service, async listen(port = 0) { await ready; return service.listen(port); }, publicInfo };
}

export function createDbacVerifier({ identity, issuerPublicKey, maxEntries = 256 }) {
  if (typeof issuerPublicKey !== 'string') throw new Error('DBAC issuer public key required');
  const challenges = new Map();
  let executions = 0;
  const metadata = () => ({ extension: DBAC_EXTENSION, schemes: DBAC_MODES, issuerPublicKey, schema: DBAC_SCHEMA, anonymousEndpoint: '/dbac/a2a', scope: 'demo:echo', paymentSupported: false });
  const card = baseUrl => ({ protocolVersion: '0.3.0', name: 'Agent B · BBS 设备绑定匿名凭证', description: '论文 BBS-BLS / BBS-BlindBLS 的独立认证配置；只执行匿名 echo。', url: `${baseUrl}/dbac/a2a`, preferredTransport: 'JSONRPC', version: '1.0.0', capabilities: { streaming: false, pushNotifications: false, extensions: [{ uri: DBAC_EXTENSION, required: true, description: '论文专用匿名展示封装；不是 bbs-2023 wire 格式。', params: { ...metadata(), challengeUrl: `${baseUrl}/dbac/challenge` } }] }, defaultInputModes: ['application/json'], defaultOutputModes: ['application/json'], skills: [{ id: 'demo:echo', name: '匿名资格验证', description: '核验披露权限、匿名 BBS 凭证与绑定设备的新贡献。', tags: ['bbs', 'dbac', 'echo'] }] });
  return {
    metadata, card,
    async handle(req, res, baseUrl) {
      if (!req.url.startsWith('/dbac/')) return false;
      if (req.method === 'GET' && req.url === '/dbac/metadata') { sendJson(res, 200, metadata()); return true; }
      if (req.method === 'GET' && req.url === '/dbac/agent-card.json') {
        sendJson(res, 200, card(baseUrl)); return true;
      }
      if (req.method === 'POST' && req.url === '/dbac/challenge') {
        const body = parseObject(await readBody(req));
        if (!exact(body, ['bodyHash', 'mode']) || !DBAC_MODES.includes(body.mode) || typeof body.bodyHash !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(body.bodyHash)) throw new AppError('DBAC_INVALID_CHALLENGE_REQUEST', '匿名挑战只接受请求摘要和方案模式，不接收主体 DID。');
        for (const [id, entry] of challenges) if (entry.context.exp <= unix()) challenges.delete(id);
        if (challenges.size >= maxEntries) throw new AppError('DBAC_CAPACITY', '有效挑战过多。', 429);
        const context = { profile: DBAC_EXTENSION, mode: body.mode, verifier: identity.did, target: `${baseUrl}/dbac/a2a`, method: 'POST', bodyHash: body.bodyHash, challengeId: randomUUID(), nonce: randomBytes(32).toString('base64url'), iat: unix(), exp: unix() + 60, schema: [...DBAC_SCHEMA], requiredDisclosures: requiredDisclosures(body.mode) };
        challenges.set(context.challengeId, { context, used: false });
        sendJson(res, 200, { challenge: signJws({ iss: identity.did, context }, identity, DBAC_CHALLENGE_TYP) }); return true;
      }
      if (req.method === 'POST' && req.url === '/dbac/a2a') {
        const trace = createVerificationTrace('dbac');
        try {
          trace.start('extension');
          if (req.headers['x-a2a-extensions'] !== DBAC_EXTENSION) throw new AppError('DBAC_EXTENSION_REQUIRED', '需要协商论文匿名凭证扩展。');
          if (req.headers.authorization || req.headers['x-a2a-device-proof']) throw new AppError('DBAC_IDENTIFIED_HEADERS', '匿名路径不接收具名 DID/VC 请求头。');
          trace.pass('extension');
          trace.start('envelope');
          // Preserve an ordinary A2A JSON-RPC body; the custom authentication
          // extension travels in separate HTTP headers, never a stable bearer DID.
          const rawBody = await readBody(req), encoded = req.headers['x-a2a-dbac-proof'];
          if (rawBody.length > 8192 || typeof encoded !== 'string' || encoded.length > 16384 || !/^[A-Za-z0-9_-]+$/.test(encoded) || Buffer.from(encoded, 'base64url').toString('base64url') !== encoded) throw new AppError('DBAC_INVALID_ENVELOPE', '缺少规范的匿名证明请求头或正文过长。');
          const presentation = parseObject(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(encoded, 'base64url')));
          const body = { rawBody, presentation, challengeId: req.headers['x-a2a-dbac-challenge'] };
          trace.pass('envelope');
          trace.start('challenge');
          const entry = challenges.get(body.challengeId);
          if (!entry || entry.context.exp <= unix()) throw new AppError('DBAC_CHALLENGE_EXPIRED', '挑战不存在或已过期。', 401);
          trace.pass('challenge');
          trace.start('replay');
          if (entry.used) throw new AppError('DBAC_REPLAY', '该匿名挑战已被消费。', 401);
          trace.pass('replay');
          trace.start('request_binding');
          if (entry.context.bodyHash !== digest(body.rawBody)) throw new AppError('DBAC_BODY_MISMATCH', '请求正文与挑战不匹配。');
          trace.pass('request_binding');
          trace.start('policy_context');
          if (JSON.stringify(entry.context.requiredDisclosures) !== JSON.stringify(requiredDisclosures(entry.context.mode))) throw new AppError('DBAC_EPOCH_EXPIRED', '凭证日期已过期，请重新签发。');
          if (body.presentation?.mode !== entry.context.mode) throw new AppError('DBAC_MODE_MISMATCH', '展示与挑战的方案模式不同。');
          trace.pass('policy_context');
          trace.start('scope');
          const rpc = parseObject(body.rawBody);
          const message = rpc.params?.message;
          const data = message?.parts?.[0]?.data;
          // Explicitly no payment/Owner authorization bypass through this profile.
          if (!exact(rpc, ['jsonrpc', 'id', 'method', 'params']) || rpc.jsonrpc !== '2.0' || typeof rpc.id !== 'string' || rpc.id.length > 128 || rpc.method !== 'message/send' || !exact(rpc.params, ['message']) || !exact(message, ['kind', 'role', 'messageId', 'parts']) || message.kind !== 'message' || message.role !== 'user' || typeof message.messageId !== 'string' || message.messageId.length > 128 || !Array.isArray(message.parts) || message.parts.length !== 1 || !exact(message.parts[0], ['kind', 'data']) || message.parts[0].kind !== 'data' || !exact(data, ['scope', 'text']) || data.scope !== 'demo:echo' || typeof data.text !== 'string' || data.text.length > 1000) throw new AppError('DBAC_SCOPE_DENIED', '论文匿名路径仅执行独立的 demo:echo，不处理支付或具名任务。', 403);
          trace.pass('scope');
          trace.start('schema');
          if (body.presentation?.attributeCount !== DBAC_SCHEMA.length) throw new AppError('DBAC_SCHEMA_MISMATCH', '属性数量与固定 schema 不匹配。');
          trace.pass('schema');
          const verified = verifyPresentation({ presentation: body.presentation, issuerPublicKey, context: entry.context, requiredDisclosures: entry.context.requiredDisclosures, trace });
          trace.start('consume');
          // All expensive verification and consumption below are synchronous:
          // concurrent requests cannot both consume a single challenge.
          entry.used = true;
          trace.pass('consume');
          trace.start('execution');
          executions++;
          const task = { kind: 'task', id: randomUUID(), contextId: randomUUID(), status: { state: 'completed', timestamp: new Date().toISOString() }, artifacts: [{ artifactId: randomUUID(), name: '匿名凭证验证回执', parts: [{ kind: 'data', data: { text: data.text, scope: data.scope, anonymousCredentialVerified: true, deviceContributionVerified: true, disclosed: verified.disclosed } }] }] };
          trace.pass('execution');
          const verificationTrace = trace.snapshot();
          const result = { jsonrpc: '2.0', id: rpc.id, result: task };
          const responseProof = signJws({ iss: identity.did, contextHash: digest(JSON.stringify(entry.context)), responseHash: digest(JSON.stringify(result)), verification: verified, verificationTrace, iat: unix(), exp: unix() + 60 }, identity, DBAC_RESPONSE_TYP);
          sendJson(res, 200, result, { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Response': responseProof }); return true;
        } catch (error) {
          trace.fail(error);
          error.verificationTrace = trace.snapshot();
          throw error;
        }
      }
      throw new AppError('NOT_FOUND', '匿名接口不存在。', 404);
    },
    stats: () => ({ executions, challengeCount: challenges.size }),
  };
}
