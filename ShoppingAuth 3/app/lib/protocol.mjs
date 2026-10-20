import { createHash, createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import { keyId, resolveDid, signJws, verifyJws, VC_TYP } from './identity.mjs';
import { PAYMENT_SCOPE } from './payment.mjs';

export const EXTENSION = 'https://example.org/a2a-did-vc/v2';
export const X402_EXTENSION = 'https://github.com/google-a2a/a2a-x402/v0.1';
export const VERSION = '0.3.0';
export const SCOPE = 'demo:echo';
export const POP_TYP = 'a2a-did-pop+jwt';
export const CHALLENGE_TYP = 'a2a-did-challenge+jwt';
export const RESPONSE_TYP = 'a2a-did-response+jwt';
export const DEVICE_POP_TYP = 'a2a-esim-pop+jwt';
export const MAX_BODY = 64 * 1024;
export const digest = (value) => createHash('sha256').update(value).digest('base64url');
export const unix = () => Math.floor(Date.now() / 1000);
const validTime = (p) => Number.isSafeInteger(p.iat) && Number.isSafeInteger(p.exp) && p.iat <= unix() + 5 && p.exp > unix() && p.exp > p.iat && p.exp - p.iat <= 60;

export class AppError extends Error {
  constructor(code, message, status = 400) { super(message); this.code = code; this.status = status; }
}

// Task queries do not declare a business scope. Authenticate using a granted
// supported scope first; B then checks the stored task's original scope.
export function requestScope(rawBody, credential) {
  let rpc;
  try { rpc = JSON.parse(rawBody); } catch { return SCOPE; }
  if (rpc?.method === 'tasks/get' || rpc?.method === 'tasks/cancel') {
    const { payload } = verifyJws(credential, { typ: VC_TYP, purpose: 'assertionMethod' });
    return payload.credentialSubject?.scopes?.includes(SCOPE) ? SCOPE : PAYMENT_SCOPE;
  }
  return rpc?.method === 'message/send' && rpc.params?.message?.parts?.[0]?.data?.scope === PAYMENT_SCOPE ? PAYMENT_SCOPE : SCOPE;
}

export function serializeIdentity(identity) {
  return { name: identity.name, did: identity.did, privateKey: identity.privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}
export function deserializeIdentity(value) {
  const privateKey = createPrivateKey(value.privateKey);
  return { ...value, kid: keyId(value.did), privateKey, publicKey: createPublicKey(privateKey), didDocument: resolveDid(value.did) };
}

export async function readBody(req) {
  let length = 0;
  const chunks = [];
  for await (const chunk of req) {
    length += chunk.length;
    if (length > MAX_BODY) throw new AppError('BODY_TOO_LARGE', '请求体超过 64 KiB。', 413);
    chunks.push(chunk);
  }
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks)); }
  catch { throw new AppError('INVALID_UTF8', '请求必须是有效 UTF-8。'); }
}
export function parseObject(raw) {
  let result;
  try { result = JSON.parse(raw); } catch { throw new AppError('INVALID_JSON', '请求必须是 JSON 对象。'); }
  if (!result || Array.isArray(result) || typeof result !== 'object') throw new AppError('INVALID_JSON', '请求必须是 JSON 对象。');
  return result;
}
export function sendJson(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(JSON.stringify(body));
}
export function checkLocalRequest(req, origin) {
  const allowed = new URL(origin);
  if (req.headers.host !== allowed.host) throw new AppError('INVALID_HOST', '请求 Host 不匹配。', 403);
  if (req.headers.origin && req.headers.origin !== origin) throw new AppError('CROSS_ORIGIN_DENIED', '演示管理接口只接受同源请求。', 403);
  if (req.method === 'POST' && !/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] ?? '')) {
    throw new AppError('JSON_REQUIRED', 'POST 必须使用 application/json。', 415);
  }
}
export async function fetchWithTimeout(url, options = {}) {
  return fetch(url, { ...options, signal: AbortSignal.timeout(30000), redirect: 'error' });
}
export async function getChallenge({ baseUrl, verifierDid, identity }) {
  const response = await fetchWithTimeout(`${baseUrl}/auth/challenge`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ holderDid: identity.did }),
  });
  const body = await response.json();
  if (!response.ok) throw new AppError(body.error?.code ?? 'CHALLENGE_FAILED', body.error?.message ?? '无法取得挑战。');
  const { payload } = verifyJws(body.challenge, { typ: CHALLENGE_TYP, purpose: 'authentication', expectedDid: verifierDid });
  if (payload.iss !== verifierDid || payload.aud !== identity.did || payload.target !== `${baseUrl}/a2a` || !validTime(payload) || typeof payload.jti !== 'string' || !payload.jti || payload.jti.length > 256 || typeof payload.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(payload.nonce)) {
    throw new AppError('INVALID_CHALLENGE', '挑战签发者、接收者、端点或有效期不匹配。');
  }
  return { ...payload, token: body.challenge };
}
export function makeAuthorization({ identity, verifierDid, baseUrl, credential, rawBody, challenge, overrides = {} }) {
  return signJws({
    iss: identity.did, aud: verifierDid, iat: unix(), exp: Math.min(unix() + 60, challenge.exp), jti: randomUUID(),
    challengeId: challenge.jti, nonce: challenge.nonce, method: 'POST', target: `${baseUrl}/a2a`,
    bodyHash: digest(rawBody), credential, ...overrides,
  }, identity, POP_TYP);
}
export function verifyDeviceProof(deviceProof, { holderProof, holderPayload, deviceDid }) {
  if (!deviceProof) throw new AppError('DEVICE_PROOF_REQUIRED', '此 VC 要求 Agent A 与绑定设备共同签名。', 401);
  let payload;
  try { ({ payload } = verifyJws(deviceProof, { typ: DEVICE_POP_TYP, purpose: 'authentication', expectedDid: deviceDid })); }
  catch (error) { throw new AppError('INVALID_DEVICE_SIGNATURE', `设备签名或绑定设备不匹配：${error.code ?? 'INVALID'}`, 401); }
  const p = holderPayload;
  if (!validTime(payload) || payload.exp > p.exp || typeof payload.jti !== 'string' || !payload.jti || payload.jti.length > 256) throw new AppError('DEVICE_PROOF_EXPIRED', '设备证明时间或编号无效。', 401);
  if (payload.iss !== deviceDid || payload.sub !== p.iss || payload.aud !== p.aud || payload.holderProofHash !== digest(holderProof) || payload.credentialHash !== digest(p.credential) ||
      ['challengeId', 'nonce', 'method', 'target', 'bodyHash'].some(key => payload[key] !== p[key])) {
    throw new AppError('DEVICE_PROOF_BINDING_MISMATCH', '设备证明与持有者、凭证或本次请求不匹配。', 401);
  }
  return payload;
}
export async function attachDeviceProof(request, device) {
  const response = await fetchWithTimeout(`${device.baseUrl}/sign`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-ESIM-Access': device.accessToken },
    body: JSON.stringify({ holderProof: request.token, challenge: request.challenge.token, rawBody: request.rawBody }),
  });
  const data = await response.json();
  if (!response.ok) throw new AppError(data.error?.code ?? 'DEVICE_UNAVAILABLE', data.error?.message ?? '设备签名失败。', response.status);
  const holderPayload = verifyJws(request.token, { typ: POP_TYP, expectedDid: request.identity.did }).payload;
  verifyDeviceProof(data.deviceProof, { holderProof: request.token, holderPayload, deviceDid: device.did });
  return { ...request, deviceProof: data.deviceProof, deviceDid: device.did };
}
export async function prepareRequest({ identity, verifierDid, baseUrl, credential, rpc, overrides, device }) {
  const challenge = await getChallenge({ baseUrl, verifierDid, identity });
  const rawBody = JSON.stringify(rpc);
  const token = makeAuthorization({ identity, verifierDid, baseUrl, credential, rawBody, challenge, overrides });
  const request = { rawBody, token, challenge, identity, verifierDid, baseUrl };
  return device ? attachDeviceProof(request, device) : request;
}
export async function transmit(request) {
  const { baseUrl, rawBody, token, verifierDid, identity, challenge } = request;
  const response = await fetchWithTimeout(`${baseUrl}/a2a`, {
    method: 'POST', body: rawBody,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, 'X-A2A-Extensions': EXTENSION, ...(request.deviceProof ? { 'X-A2A-Device-Proof': request.deviceProof } : {}) },
  });
  const text = await response.text();
  const body = JSON.parse(text);
  if (response.ok && response.status !== 200) throw new AppError('INVALID_AGENT_RESPONSE', '此同步 A2A profile 只接受签名的 HTTP 200 响应。');
  let verificationTrace;
  if (response.status === 200) {
    const { payload } = verifyJws(response.headers.get('X-A2A-DID-Response'), { typ: RESPONSE_TYP, purpose: 'authentication', expectedDid: verifierDid });
    if (payload.iss !== verifierDid || payload.aud !== identity.did || payload.requestHash !== digest(rawBody) || payload.responseHash !== digest(text) || payload.nonce !== challenge.nonce || !validTime(payload)) {
      throw new AppError('INVALID_RESPONSE_PROOF', 'Agent B 响应证明未绑定当前请求。');
    }
    if (response.headers.get('X-A2A-Extensions') !== EXTENSION) throw new AppError('EXTENSION_NOT_ACTIVE', '响应未确认 DID/VC 扩展。');
    if (request.deviceProof && (payload.deviceDid !== request.deviceDid || payload.deviceProofHash !== digest(request.deviceProof))) throw new AppError('INVALID_RESPONSE_PROOF', '响应未绑定本次验证的设备证明。');
    verificationTrace = payload.verificationTrace;
  }
  if (!response.ok || body.error) {
    const e = new AppError(body.error?.data?.reason ?? body.error?.code ?? 'REMOTE_ERROR', body.error?.message ?? '远端请求失败。', response.status);
    e.rpcCode = body.error?.code;
    e.verificationTrace = verificationTrace ?? body.error?.data?.verificationTrace;
    throw e;
  }
  const sent = JSON.parse(rawBody);
  if (body.jsonrpc !== '2.0' || body.id !== sent.id || body.result?.kind !== 'task' || typeof body.result.id !== 'string' || !body.result.id || typeof body.result.contextId !== 'string' || !body.result.contextId || !['completed', 'input-required', 'failed'].includes(body.result.status?.state)) throw new AppError('INVALID_AGENT_RESPONSE', 'A2A 响应结构或请求 ID 不匹配。');
  const result = { task: body.result, ...(verificationTrace ? { verificationTrace } : {}), verification: { verifierDid, responseSignature: true, requestBound: true, deviceSignature: Boolean(request.deviceProof), ...(request.deviceProof ? { deviceDid: request.deviceDid } : {}), extension: EXTENSION, protocolVersion: VERSION } };
  // Forward the signed B attestation privately to the wallet gate. It proves
  // that B checked the Java Card proof for these exact approved order bytes.
  Object.defineProperty(result, 'responseEvidence', { enumerable: false, value: { proof: response.headers.get('X-A2A-DID-Response'), rawResponse: text, rawRequest: rawBody } });
  return result;
}
export function messageRpc(text = '你好，Agent B。请核验我的 DID 和 VC。') {
  return { jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: { message: {
    kind: 'message', role: 'user', messageId: randomUUID(), extensions: [EXTENSION],
    parts: [{ kind: 'data', data: { scope: SCOPE, text } }],
  } } };
}
