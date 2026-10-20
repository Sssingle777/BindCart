import http from 'node:http';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { identityFromPublicKey, resolveDid, signJwsWithSigner, verifyJws, verifyCredential } from './identity.mjs';
import { startJCardSim } from './jcardsim.mjs';
import {
  AppError, SCOPE, POP_TYP, CHALLENGE_TYP, MAX_BODY, digest, unix,
  readBody, parseObject, sendJson, checkLocalRequest, requestScope,
} from './protocol.mjs';

export const DEVICE_POP_TYP = 'a2a-esim-pop+jwt';
const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
const identifier = value => typeof value === 'string' && value.length > 0 && value.length <= 256;
const validTime = (payload, now) => Number.isSafeInteger(payload.iat) && Number.isSafeInteger(payload.exp) &&
  payload.iat >= 0 && payload.iat <= now + 5 && payload.exp > now && payload.exp > payload.iat && payload.exp - payload.iat <= 60;
const fail = (code, message, status = 400) => { throw new AppError(code, message, status); };

// The caller provisions an access capability, never a signing key. The private
// P-256 key is generated and used by a Java Card applet in a separate jCardSim
// JVM. Node sees only its public point and APDU signature responses. This is
// still software simulation, with no real eSIM/secure-element hardware claim.
export function createEsim(config = {}) {
  const { accessToken, holderDid, verifierDid, verifierUrl, trustedIssuers, maxEntries = 1000 } = config;
  const allowedConfig = ['accessToken', 'holderDid', 'verifierDid', 'verifierUrl', 'trustedIssuers', 'maxEntries'];
  const tokenIsCanonical = typeof accessToken === 'string' && (
    (/^[A-Za-z0-9_-]{43}$/.test(accessToken) && Buffer.from(accessToken, 'base64url').toString('base64url') === accessToken) ||
    /^[0-9a-f]{64}$/.test(accessToken)
  );
  if (!object(config) || Object.keys(config).some(key => !allowedConfig.includes(key)) || !tokenIsCanonical ||
      !Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 100000 ||
      !(trustedIssuers instanceof Set || Array.isArray(trustedIssuers)) || !trustedIssuers.size && !trustedIssuers.length) {
    fail('ESIM_INVALID_CONFIG', '模拟 eSIM 需要 32 字节随机访问令牌、可信签发者及有效容量配置。');
  }
  let endpoint;
  try {
    resolveDid(holderDid); resolveDid(verifierDid);
    for (const issuer of trustedIssuers) resolveDid(issuer);
    const url = new URL(verifierUrl);
    if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(url.hostname) ||
        url.username || url.password || url.pathname !== '/' || url.search || url.hash || url.origin !== verifierUrl) throw new Error();
    endpoint = `${url.origin}/a2a`;
  } catch { fail('ESIM_INVALID_CONFIG', '模拟 eSIM 需要规范 DID 与本机 Agent B 服务地址。'); }
  const issuerPolicy = new Set(trustedIssuers);
  let identity, card;
  const expectedAccess = Buffer.from(accessToken);
  const usedChallenges = new Map();
  const events = [];
  let baseUrl, locked = false;
  const publicInfo = () => {
    if (!identity || !card) fail('JCARD_NOT_READY', 'jCardSim 尚未启动。', 503);
    return ({
    service: 'simulated-esim', did: identity.did, deviceDid: identity.did,
    didDocument: resolveDid(identity.did), pid: process.pid,
    ...card.publicInfo(), keyExportable: false, hardware: false, locked,
    simulationBoundary: 'Java Card applet on jCardSim; not a carrier eSIM or hardware secure element',
  }); };
  const audit = (event, data = {}) => {
    events.push({ time: new Date().toISOString(), event, ...data });
    if (events.length > 200) events.shift();
  };
  function authorize(req) {
    const value = req.headers['x-esim-access'];
    const supplied = Buffer.from(typeof value === 'string' ? value : '');
    if (supplied.length !== expectedAccess.length || !timingSafeEqual(supplied, expectedAccess)) {
      fail('ESIM_ACCESS_DENIED', '需要独立的模拟 eSIM 调用权限。', 403);
    }
  }
  async function signRequest(body) {
    if (locked) fail('ESIM_LOCKED', '模拟 eSIM 已锁定，拒绝签名。', 403);
    if (!object(body) || Object.keys(body).sort().join(',') !== 'challenge,holderProof,rawBody' ||
        typeof body.holderProof !== 'string' || typeof body.challenge !== 'string' || typeof body.rawBody !== 'string' ||
        Buffer.byteLength(body.rawBody, 'utf8') > MAX_BODY) fail('ESIM_INVALID_REQUEST', '签名请求字段或正文长度无效。');
    let holder, signerDid;
    try { ({ payload: holder, signerDid } = verifyJws(body.holderProof, { typ: POP_TYP })); }
    catch { fail('ESIM_INVALID_REQUEST', 'Agent A 持钥证明无法通过验签。'); }
    if (signerDid !== holderDid || holder.iss !== holderDid) fail('ESIM_HOLDER_MISMATCH', '持钥证明不属于配置的 Agent A。', 403);
    const now = unix();
    if (!validTime(holder, now) || !identifier(holder.jti) || holder.aud !== verifierDid ||
        holder.method !== 'POST' || holder.target !== endpoint || holder.bodyHash !== digest(body.rawBody)) {
      fail('ESIM_INVALID_REQUEST', '持钥证明时间、接收方、方法、端点或正文绑定无效。');
    }
    let credential;
    try {
      credential = verifyCredential(holder.credential, {
        trustedIssuers: issuerPolicy, subjectDid: holderDid, audience: verifierDid, scope: requestScope(body.rawBody, holder.credential), requireDevice: true,
      });
    } catch { fail('ESIM_INVALID_REQUEST', 'VC 无效、过期或不符合模拟 eSIM 的信任策略。', 403); }
    if (credential.credentialSubject.deviceDid !== identity.did) {
      fail('ESIM_DEVICE_MISMATCH', 'VC 未绑定当前模拟 eSIM。', 403);
    }
    let challenge;
    try { ({ payload: challenge } = verifyJws(body.challenge, { typ: CHALLENGE_TYP, expectedDid: verifierDid })); }
    catch { fail('ESIM_INVALID_CHALLENGE', '挑战未由配置的 Agent B 签署。', 401); }
    if (challenge.iss !== verifierDid || challenge.aud !== holderDid || challenge.target !== endpoint ||
        !validTime(challenge, now) || !identifier(challenge.jti) ||
        typeof challenge.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge.nonce) ||
        holder.challengeId !== challenge.jti || holder.nonce !== challenge.nonce || holder.exp > challenge.exp) {
      fail('ESIM_INVALID_CHALLENGE', '挑战过期或未绑定当前持钥证明。', 401);
    }
    for (const [id, expiration] of usedChallenges) if (expiration <= now) usedChallenges.delete(id);
    if (usedChallenges.has(challenge.jti)) fail('ESIM_REPLAYED_CHALLENGE', '该挑战已由模拟 eSIM 签名。', 409);
    if (usedChallenges.size >= maxEntries) fail('ESIM_CAPACITY_EXCEEDED', '有效挑战记录已满，请等待过期后重试。', 503);
    const payload = {
      iss: identity.did, sub: holderDid, aud: verifierDid, iat: now,
      exp: Math.min(now + 60, holder.exp, challenge.exp), jti: randomUUID(),
      holderProofHash: digest(body.holderProof), credentialHash: digest(holder.credential),
      challengeId: challenge.jti, nonce: challenge.nonce, method: holder.method,
      target: holder.target, bodyHash: holder.bodyHash,
    };
    // Reserve synchronously before the first await. An APDU failure leaves the
    // challenge consumed: an unknown signing outcome must not permit a retry.
    usedChallenges.set(challenge.jti, challenge.exp);
    let deviceProof;
    try {
      deviceProof = await signJwsWithSigner(payload, identity, DEVICE_POP_TYP, input => card.sign(input));
    } catch (error) { fail(error.code ?? 'JCARD_SIGN_FAILED', error.message ?? 'jCardSim 签名失败。', 503); }
    audit('signed', { challengeId: challenge.jti, holderDid });
    return { deviceProof };
  }
  const server = http.createServer(async (req, res) => {
    try {
      checkLocalRequest(req, baseUrl);
      if (req.method === 'GET' && req.url === '/health') return sendJson(res, 200, publicInfo());
      if (req.method === 'GET' && req.url === '/did.json') return sendJson(res, 200, resolveDid(identity.did));
      authorize(req);
      if (req.method === 'GET' && req.url === '/audit') return sendJson(res, 200, { entries: structuredClone(events) });
      if (req.method === 'POST' && ['/sign', '/lock'].includes(req.url)) {
        let body;
        try { body = parseObject(await readBody(req)); }
        catch { fail('ESIM_INVALID_REQUEST', '签名服务只接受大小受限的有效 UTF-8 JSON 对象。'); }
        if (req.url === '/sign') return sendJson(res, 200, await signRequest(body));
        if (Object.keys(body).length !== 1 || typeof body.locked !== 'boolean') fail('ESIM_INVALID_REQUEST', '锁定请求必须仅包含 locked 布尔值。');
        if (body.locked) locked = true;
        try { await card.setLocked(body.locked); }
        catch (error) { fail(error.code ?? 'JCARD_UNAVAILABLE', error.message, 503); }
        locked = body.locked;
        audit(locked ? 'locked' : 'unlocked');
        return sendJson(res, 200, publicInfo());
      }
      sendJson(res, 404, { error: { code: 'NOT_FOUND', message: '接口不存在。' } });
    } catch (error) {
      const code = error instanceof AppError ? error.code : 'ESIM_INTERNAL_ERROR';
      audit('rejected', { code });
      sendJson(res, error instanceof AppError ? error.status : 500, {
        error: { code, message: error instanceof AppError ? error.message : '模拟 eSIM 内部错误。' },
      });
    }
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 10000;
  return {
    server, publicInfo,
    async listen(port = 0) {
      if (card) fail('JCARD_ALREADY_STARTED', '设备服务已启动。');
      card = await startJCardSim();
      identity = identityFromPublicKey(card.publicJwk, 'jCardSim P-256 device');
      return new Promise((resolve, reject) => {
        const failed = error => { server.off('listening', ready); reject(error); };
        const ready = () => {
          server.off('error', failed);
          baseUrl = `http://127.0.0.1:${server.address().port}`;
          resolve(baseUrl);
        };
        server.once('error', failed); server.once('listening', ready);
        server.listen(port, '127.0.0.1');
      });
    },
    async close() {
      await Promise.all([new Promise((resolve, reject) => {
        server.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(error) : resolve());
        server.closeAllConnections();
      }), card?.close()]);
    },
  };
}
