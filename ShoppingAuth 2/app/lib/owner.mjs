import http from 'node:http';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { generateIdentity, resolveDid, verifyCredential, verifyJws } from './identity.mjs';
import { PAYMENT_SCOPE, PAYMENT_AUTH_TYP, issuePaymentAuthorization, validatePayment } from './payment.mjs';
import { AppError, checkLocalRequest, digest, parseObject, readBody, sendJson } from './protocol.mjs';
import { DBAC_PAYMENT_PROFILE, DBAC_PAYMENT_RESPONSE_TYP, issueDbacPaymentAuthorization, verifyDbacPaymentAuthorization, verifyDbacPaymentEvidence, credentialBindingOf } from './dbac/payment-policy.mjs';

const PENDING_LIFETIME_MS = 300000;
const CONFIG_KEYS = ['holderDid', 'verifierDid', 'trustedIssuers', 'proposalToken', 'uiToken', 'maxEntries', 'dbacIssuerPublicKey', 'w3cIssuer'];
const PAYMENT_KEYS = ['orderId', 'payerAccount', 'payeeAccount', 'amountMinor', 'currency'];
const exact = (value, keys) => !!value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && Object.keys(value).every(key => keys.includes(key));
const capability = value => typeof value === 'string' && (
  (/^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value) || /^[0-9a-f]{64}$/.test(value)
);
const capabilityBytes = value => Buffer.from(value, /^[0-9a-f]{64}$/.test(value) ? 'hex' : 'base64url');
const fail = (code, message, status = 400) => { throw new AppError(code, message, status); };

// Owner's signing identity is generated here and never exported. The proposing
// Agent receives only a proposal capability; a separate console capability is
// required for an explicit approval of the immutable payment/VC snapshot.
export function createOwner(config = {}) {
  if (!config || typeof config !== 'object' || Array.isArray(config)) fail('OWNER_INVALID_CONFIG', 'Owner 配置必须是对象。');
  const { holderDid, verifierDid, trustedIssuers, proposalToken, uiToken, maxEntries = 1000, dbacIssuerPublicKey, w3cIssuer } = config;
  if (w3cIssuer !== undefined && (typeof w3cIssuer !== 'string' || w3cIssuer.length > 256 || !/^[a-z][a-z0-9+.-]*:\S+$/i.test(w3cIssuer))) fail('OWNER_INVALID_CONFIG', 'W3C 签发方配置必须是非空绝对标识，不能回退旧凭证模式。');
  if (!config || typeof config !== 'object' || Array.isArray(config) || Object.keys(config).some(key => !CONFIG_KEYS.includes(key)) ||
      !capability(proposalToken) || !capability(uiToken) || timingSafeEqual(capabilityBytes(proposalToken), capabilityBytes(uiToken)) ||
      !Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 100000 ||
      (dbacIssuerPublicKey !== undefined && (typeof dbacIssuerPublicKey !== 'string' || !/^[0-9a-f]{192}$/.test(dbacIssuerPublicKey))) ||
      !(trustedIssuers instanceof Set || Array.isArray(trustedIssuers)) || !(trustedIssuers.size || trustedIssuers.length)) {
    fail('OWNER_INVALID_CONFIG', 'Owner 需要互不相同的独立提案及确认凭据、可信签发者和有效容量配置。');
  }
  try {
    resolveDid(holderDid); resolveDid(verifierDid);
    for (const issuer of trustedIssuers) resolveDid(issuer);
  } catch { fail('OWNER_INVALID_CONFIG', 'Owner 配置中的身份必须为规范 Ed25519 did:key。'); }
  const issuerPolicy = new Set(trustedIssuers);
  const identity = generateIdentity('Independent Owner');
  const proposalKey = Buffer.from(proposalToken), uiKey = Buffer.from(uiToken);
  const records = new Map();
  let baseUrl;

  const publicInfo = () => ({
    service: 'owner', did: identity.did, ownerDid: identity.did,
    holderDid, verifierDid, pid: process.pid, hardware: false, keyExportable: false,
  });
  function authorize(req, header, key, code) {
    const value = req.headers[header];
    const supplied = Buffer.from(typeof value === 'string' ? value : '');
    if (supplied.length !== key.length || !timingSafeEqual(supplied, key)) {
      fail(code, header === 'x-owner-ui-key' ? '需要独立 Owner 控制台的确认凭据。' : '需要 Agent 的独立提案凭据。', 403);
    }
  }
  function verifiedCredential(token) {
    try {
      return verifyCredential(token, {
        trustedIssuers: issuerPolicy, subjectDid: holderDid, audience: verifierDid,
        scope: PAYMENT_SCOPE, requireDevice: true,
      });
    } catch (error) { fail(error.code ?? 'INVALID_CREDENTIAL', 'Owner 无法验证提案的 VC：' + error.message, 403); }
  }
  function verifiedDbacProposal(evidence, payment) {
    if (!dbacIssuerPublicKey) fail('DBAC_PAYMENT_NOT_CONFIGURED', 'Owner 尚未配置可信 DBAC 支付签发方。', 403);
    return verifyDbacPaymentEvidence(evidence, { verifierDid, issuerPublicKey: dbacIssuerPublicKey, phase: 'proposal', payment, ...(w3cIssuer ? { w3cIssuer } : {}) });
  }
  function expire(record) {
    if (['PENDING', 'APPROVED'].includes(record.proposal.status) && Date.now() >= record.expiresAtMs) {
      record.proposal.status = 'EXPIRED';
      delete record.proposal.authorization;
    }
    return record;
  }
  function publicProposal(record) { return structuredClone(expire(record).proposal); }
  function find(id) {
    const record = records.get(id);
    if (!record) fail('OWNER_PROPOSAL_NOT_FOUND', '未找到该支付提案。', 404);
    expire(record);
    if (record.proposal.status === 'EXPIRED') fail('OWNER_PROPOSAL_EXPIRED', '该支付提案或已签署授权已过期。', 410);
    return record;
  }
  function pending(id) {
    const record = find(id);
    if (record.proposal.status !== 'PENDING') fail('OWNER_PROPOSAL_NOT_PENDING', '仅待确认提案可以批准或拒绝。', 409);
    return record;
  }
  function propose(body) {
    if (body?.profile === DBAC_PAYMENT_PROFILE) {
      if (!exact(body, ['profile', 'payment', 'dbacEvidence'])) fail('OWNER_INVALID_REQUEST', '匿名支付提案必须且只能包含 profile、payment 与 dbacEvidence。');
      const payment = validatePayment(body.payment);
      const { gate } = verifiedDbacProposal(body.dbacEvidence, payment);
      if (records.size >= maxEntries) fail('OWNER_CAPACITY_REACHED', 'Owner 提案记录已满，请在重启后创建新的演示会话。', 503);
      const { payload: signedEvidence } = verifyJws(body.dbacEvidence.proof, { typ: DBAC_PAYMENT_RESPONSE_TYP, purpose: 'authentication', expectedDid: verifierDid });
      const now = Date.now(), expiresAtMs = Math.min(now + PENDING_LIFETIME_MS, signedEvidence.exp * 1000);
      const proposal = {
        id: randomUUID(), status: 'PENDING', profile: DBAC_PAYMENT_PROFILE, payment,
        mode: gate.mode, orderKey: gate.orderKey, ...credentialBindingOf(gate), credentialHash: digest(JSON.stringify(body.dbacEvidence)), verifierDid,
        createdAt: new Date(now).toISOString(), expiresAt: new Date(expiresAtMs).toISOString(),
      };
      const record = { proposal, dbacEvidence: structuredClone(body.dbacEvidence), expiresAtMs };
      records.set(proposal.id, record);
      return publicProposal(record);
    }
    if (!exact(body, ['credential', 'payment'])) fail('OWNER_INVALID_REQUEST', '提案必须且只能包含 credential 与 payment。');
    const credential = verifiedCredential(body.credential);
    const payment = validatePayment(body.payment);
    if (records.size >= maxEntries) fail('OWNER_CAPACITY_REACHED', 'Owner 提案记录已满，请在重启后创建新的演示会话。', 503);
    const now = Date.now(), expiresAtMs = now + PENDING_LIFETIME_MS;
    const proposal = {
      id: randomUUID(), status: 'PENDING', payment,
      credentialId: credential.id, credentialHash: digest(body.credential),
      holderDid, deviceDid: credential.credentialSubject.deviceDid, verifierDid,
      createdAt: new Date(now).toISOString(), expiresAt: new Date(expiresAtMs).toISOString(),
    };
    const record = { proposal, credential: body.credential, expiresAtMs };
    records.set(proposal.id, record);
    return publicProposal(record);
  }
  function approve(id, body) {
    const record = pending(id);
    if (!exact(body, ['confirmed', 'payment', 'credentialHash']) || body.confirmed !== true) {
      fail('OWNER_CONFIRMATION_REQUIRED', '必须逐笔明确确认当前支付条款及 VC 摘要。');
    }
    const proposal = record.proposal;
    let confirmedPayment;
    try { confirmedPayment = validatePayment(body.payment); } catch { /* Report a confirmation mismatch, not a new proposal error. */ }
    if (!confirmedPayment || JSON.stringify(confirmedPayment) !== JSON.stringify(proposal.payment) || body.credentialHash !== proposal.credentialHash) {
      fail('OWNER_CONFIRMATION_MISMATCH', '确认内容与不可变提案快照不一致。', 409);
    }
    // No await between the final validity check, signature and state change:
    // concurrent confirmations cannot produce multiple signed authorizations.
    let token, document;
    if (proposal.profile === DBAC_PAYMENT_PROFILE) {
      const { gate } = verifiedDbacProposal(record.dbacEvidence, proposal.payment);
      if (gate.mode !== proposal.mode || gate.orderKey !== proposal.orderKey || digest(JSON.stringify(record.dbacEvidence)) !== proposal.credentialHash) {
        fail('OWNER_CONFIRMATION_MISMATCH', '匿名提案的订单公钥或验证证据发生变化。', 409);
      }
      token = issueDbacPaymentAuthorization(identity, {
        verifierDid, mode: proposal.mode, issuerPublicKey: dbacIssuerPublicKey, orderKey: proposal.orderKey, payment: proposal.payment, credentialBinding: credentialBindingOf(gate),
      });
      document = verifyDbacPaymentAuthorization(token, { trustedAuthorizers: [identity.did], verifierDid, issuerPublicKey: dbacIssuerPublicKey, mode: proposal.mode, orderKey: proposal.orderKey, payment: proposal.payment, credentialBinding: credentialBindingOf(gate) });
    } else {
      const credential = verifiedCredential(record.credential);
      if (credential.credentialSubject.deviceDid !== proposal.deviceDid || digest(record.credential) !== proposal.credentialHash) {
        fail('OWNER_CONFIRMATION_MISMATCH', '提案的设备或 VC 绑定信息发生变化。', 409);
      }
      token = issuePaymentAuthorization(identity, {
        holderDid, deviceDid: proposal.deviceDid, verifierDid,
        credential: record.credential, payment: proposal.payment,
      });
      ({ payload: document } = verifyJws(token, { typ: PAYMENT_AUTH_TYP, purpose: 'assertionMethod', expectedDid: identity.did }));
    }
    proposal.status = 'APPROVED';
    proposal.authorization = { id: document.authorizationId, token, document };
    record.expiresAtMs = document.exp * 1000;
    proposal.expiresAt = new Date(record.expiresAtMs).toISOString();
    return publicProposal(record);
  }
  function reject(id, body) {
    const record = pending(id);
    if (!exact(body, ['rejected']) || body.rejected !== true) fail('OWNER_CONFIRMATION_REQUIRED', '拒绝操作必须明确包含 rejected: true。');
    record.proposal.status = 'REJECTED';
    return publicProposal(record);
  }
  function proposalId(segment) {
    try { return decodeURIComponent(segment); }
    catch { fail('OWNER_PROPOSAL_NOT_FOUND', '无效提案编号。', 404); }
  }
  const files = new Map([['/', ['index.html', 'text/html']], ['/app.js', ['app.js', 'text/javascript']], ['/style.css', ['style.css', 'text/css']], ['/tokens.css', ['tokens.css', 'text/css']], ['/platform.css', ['platform.css', 'text/css']]]);
  const server = http.createServer({ requestTimeout: 10000, headersTimeout: 10000 }, async (req, res) => {
    try {
      checkLocalRequest(req, baseUrl);
      if (req.method === 'GET' && ['/health', '/api/health'].includes(req.url)) return sendJson(res, 200, publicInfo());
      if (req.method === 'GET' && req.url === '/did.json') return sendJson(res, 200, resolveDid(identity.did));
      if (req.method === 'GET' && files.has(req.url)) {
        const [name, type] = files.get(req.url);
        let file;
        try { file = await readFile(new URL(`../owner-public/${name}`, import.meta.url)); }
        catch (error) { if (error.code === 'ENOENT') return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Owner 页面文件尚未准备完成。' } }); throw error; }
        res.writeHead(200, {
          'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
          'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        });
        return res.end(file);
      }
      if (req.url === '/proposals' || req.url.startsWith('/proposals/')) {
        authorize(req, 'x-owner-proposal', proposalKey, 'OWNER_PROPOSAL_ACCESS_DENIED');
        if (req.method === 'POST' && req.url === '/proposals') return sendJson(res, 200, propose(parseObject(await readBody(req))));
        const match = /^\/proposals\/([^/]+)$/.exec(req.url);
        if (req.method === 'GET' && match) return sendJson(res, 200, publicProposal(find(proposalId(match[1]))));
      }
      if (req.url.startsWith('/api/')) {
        authorize(req, 'x-owner-ui-key', uiKey, 'OWNER_UI_ACCESS_DENIED');
        if (req.method === 'GET' && req.url === '/api/state') {
          return sendJson(res, 200, { ...publicInfo(), proposals: [...records.values()].map(publicProposal).reverse() });
        }
        const match = /^\/api\/proposals\/([^/]+)\/(approve|reject)$/.exec(req.url);
        if (req.method === 'POST' && match) {
          const body = parseObject(await readBody(req));
          return sendJson(res, 200, match[2] === 'approve' ? approve(proposalId(match[1]), body) : reject(proposalId(match[1]), body));
        }
      }
      sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'Owner 接口不存在。' } });
    } catch (error) {
      const known = typeof error.code === 'string' && Number.isInteger(error.status);
      sendJson(res, known ? error.status : 500, {
        ok: false, error: { code: known ? error.code : 'OWNER_INTERNAL_ERROR', message: known ? error.message : 'Owner 服务内部错误。' },
      });
    }
  });
  return {
    publicInfo,
    listen(port = 0) {
      return new Promise((resolve, reject) => {
        const failed = error => { server.off('listening', ready); reject(error); };
        const ready = () => { server.off('error', failed); baseUrl = `http://127.0.0.1:${server.address().port}`; resolve(baseUrl); };
        server.once('error', failed); server.once('listening', ready); server.listen(port, '127.0.0.1');
      });
    },
    close() {
      server.closeAllConnections();
      return new Promise((resolve, reject) => server.close(error => error && error.code !== 'ERR_SERVER_NOT_RUNNING' ? reject(error) : resolve()));
    },
  };
}
