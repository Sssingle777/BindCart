import { randomUUID } from 'node:crypto';
import { generateIdentity, issueCredential, resolveDid, verifyJws, signJws } from './identity.mjs';
import { AppError, SCOPE, POP_TYP, DEVICE_POP_TYP, digest, unix, fetchWithTimeout, messageRpc, prepareRequest, transmit, attachDeviceProof, makeAuthorization } from './protocol.mjs';
import { PAYMENT_SCOPE } from './payment.mjs';
import { createPaymentSession } from './payment-session.mjs';
import { createRemotePaymentSession } from './remote-payment-session.mjs';
import { preVerificationFailure } from './verification-trace.mjs';

export function createSession({ issuer, agentA, verifierDid, baseUrl, adminToken, device, owner, x402Payer, paymentInfo }) {
  if (!device?.did || !device.baseUrl || !device.accessToken) throw new AppError('DEVICE_CONFIG_REQUIRED', '需要绑定模拟 eSIM 配置。');
  let credential = null;
  const issue = (identity = agentA, options = {}, signer = issuer) => issueCredential(signer, { subjectDid: identity.did, audience: verifierDid, scopes: [SCOPE, PAYMENT_SCOPE], deviceDid: device.did, ...options });
  const unpack = (token) => verifyJws(token, { typ: 'vc+jwt', purpose: 'assertionMethod' }).payload;
  async function jsonRequest(url, headers, body) {
    const response = await fetchWithTimeout(url, {
      method: body === undefined ? 'GET' : 'POST', headers: { ...headers, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const data = await response.json();
    if (!response.ok) throw new AppError(data.error?.code ?? 'REMOTE_ERROR', data.error?.message ?? '远端请求失败。', response.status);
    return data;
  }
  const admin = (path, body) => jsonRequest(`${baseUrl}${path}`, { 'X-Demo-Admin': adminToken }, body);
  const deviceRequest = (path, body) => jsonRequest(`${device.baseUrl}${path}`, { 'X-ESIM-Access': device.accessToken }, body);
  const prepareBare = (rpc = messageRpc(), token = credential?.token, identity = agentA, overrides) => {
    if (!token) throw new AppError('NO_CREDENTIAL', '请先签发 VC。');
    return prepareRequest({ identity, verifierDid, baseUrl, credential: token, rpc, overrides });
  };
  const prepare = async (...args) => attachDeviceProof(await prepareBare(...args), device);
  const invoke = async (...args) => {
    try { return await transmit(await prepare(...args)); }
    catch (error) { error.verificationTrace ??= preVerificationFailure('identity', error); throw error; }
  };
  const invokeBare = async (...args) => transmit(await prepareBare(...args));
  // The network entry point requires remote Owner configuration. The legacy
  // local fixture remains for the original standalone protocol unit tests.
  const payment = (owner ? createRemotePaymentSession : createPaymentSession)({ issuer, agentA, verifierDid, device, owner, getCredential: () => credential, invoke, prepare, invokeBare, admin, x402Payer, paymentInfo });

  // Attack fixtures use only a fresh test device key, never the protected key.
  // B still requires the issuer-signed VC to bind any accepted device key.
  const fixtureProof = (request, fixtureDevice) => {
    const p = verifyJws(request.token, { typ: POP_TYP }).payload;
    return signJws({ iss: fixtureDevice.did, sub: p.iss, aud: p.aud, iat: unix(), exp: p.exp, jti: randomUUID(),
      holderProofHash: digest(request.token), credentialHash: digest(p.credential), challengeId: p.challengeId, nonce: p.nonce,
      method: p.method, target: p.target, bodyHash: p.bodyHash,
    }, fixtureDevice, DEVICE_POP_TYP);
  };
  const session = {
    payment,
    state() {
      return { issuerDid: issuer.did, agentADid: agentA.did, agentBDid: verifierDid, agentBUrl: baseUrl, credential,
        deviceDid: device.did, deviceUrl: device.baseUrl,
        didDocuments: { issuer: resolveDid(issuer.did), agentA: resolveDid(agentA.did), agentB: resolveDid(verifierDid), device: resolveDid(device.did) } };
    },
    issue() {
      const token = issue(), document = unpack(token);
      payment.invalidate();
      credential = { token, document, id: document.id, revoked: false }; return { credential };
    },
    async revoke() {
      if (!credential) throw new AppError('NO_CREDENTIAL', '请先签发 VC。');
      const result = await admin('/admin/revoke', { id: credential.id }); credential.revoked = true; return result;
    },
    deviceStatus: () => deviceRequest('/health'),
    deviceLock: (locked) => deviceRequest('/lock', { locked }),
    invoke, prepare,
    async audit() {
      const [bAudit, dAudit] = await Promise.all([admin('/admin/audit'), deviceRequest('/audit')]);
      return { ...bAudit, events: [...bAudit.events.map(x => ({ ...x, source: 'agent-b' })), ...dAudit.entries.map(x => ({ ...x, event: `device_${x.event}`, source: 'simulated-esim' }))].sort((a, b) => a.time.localeCompare(b.time)) };
    },
    getCard: () => jsonRequest(`${baseUrl}/.well-known/agent-card.json`, {}),
    async demo() {
      await session.deviceLock(false);
      session.issue();
      const results = [];
      const check = async (name, expected, action, detail) => {
        let actual = 'ACCEPTED', verificationTrace;
        try { verificationTrace = (await action())?.verificationTrace; }
        catch (error) { actual = String(error.code ?? 'ERROR'); verificationTrace = error.verificationTrace ?? preVerificationFailure('identity', error); }
        results.push({ name, expected, actual, pass: actual === expected, detail, ...(verificationTrace ? { verificationTrace } : {}) });
      };
      let ownTask;
      await check('正常双签名调用', 'ACCEPTED', async () => { const result = await invoke(); ownTask = result.task; return result; }, 'A 与绑定的模拟 eSIM 对同一请求提供两份独立签名。');
      await check('标准 tasks/get 双签名查询', 'ACCEPTED', () => invoke({ jsonrpc: '2.0', id: randomUUID(), method: 'tasks/get', params: { id: ownTask.id } }), '任务查询同样要求设备证明。');
      const attacker = generateIdentity('attacker'), otherDevice = generateIdentity('demo-other-device');
      await check('仅复制合法 VC', 'CREDENTIAL_SUBJECT_MISMATCH', () => invokeBare(messageRpc(), credential.token, attacker), '攻击者自己的私钥与 VC 主体不匹配。');
      const pieces = credential.token.split('.'), changedVC = unpack(credential.token);
      changedVC.credentialSubject.scopes = ['admin:write']; pieces[1] = Buffer.from(JSON.stringify(changedVC)).toString('base64url');
      await check('篡改 VC 声明', 'INVALID_SIGNATURE', () => invokeBare(messageRpc(), pieces.join('.')), '签发者签名约束全部凭证内容。');
      await check('篡改 A2A 请求正文', 'REQUEST_BINDING_MISMATCH', async () => {
        const request = await prepare(messageRpc('原始文本')); request.rawBody = request.rawBody.replace('原始文本', '被篡改的文本'); await transmit(request);
      }, '双签名均绑定完整请求。');
      await check('错误接收方', 'CREDENTIAL_AUDIENCE_MISMATCH', () => invokeBare(messageRpc(), issue(agentA, { audience: attacker.did })), 'B 仍独立检查 VC 接收方。');
      await check('过期 VC', 'CREDENTIAL_EXPIRED', () => invokeBare(messageRpc(), issue(agentA, { validFrom: Date.now() - 120000, validUntil: Date.now() - 60000 })), '凭证必须在有效期内。');
      await check('不受信任签发者', 'CREDENTIAL_UNTRUSTED_ISSUER', () => invokeBare(messageRpc(), issue(agentA, {}, attacker)), '不能自己签发凭证来替换绑定设备。');
      await check('越权调用', 'CREDENTIAL_SCOPE_DENIED', () => invokeBare(messageRpc(), issue(agentA, { scopes: ['admin:write'] })), '要求 demo:echo 权限。');
      const replay = await prepare(messageRpc('只接受一次的请求')); await transmit(replay);
      await check('原样重放双签名请求', 'REPLAYED_CHALLENGE', () => transmit(replay), '已用挑战在 B 拒绝。');
      await check('重复请求设备签名', 'ESIM_REPLAYED_CHALLENGE', () => deviceRequest('/sign', { holderProof: replay.token, challenge: replay.challenge.token, rawBody: replay.rawBody }), '设备也记录挑战，禁止重复签署。');
      const concurrent = await prepare(messageRpc('并发重放测试'));
      const settled = await Promise.allSettled(Array.from({ length: 8 }, () => transmit(concurrent)));
      const accepted = settled.filter(x => x.status === 'fulfilled').length;
      const rejected = settled.filter(x => x.status === 'rejected' && x.reason.code === 'REPLAYED_CHALLENGE').length;
      results.push({ name: '8 个并发请求复用双签名', expected: '1 accepted / 7 replay rejected', actual: `${accepted} accepted / ${rejected} replay rejected`, pass: accepted === 1 && rejected === 7, detail: 'B 仅在两份证明均有效后同步消费挑战。', verificationTrace: settled.find(x => x.status === 'rejected')?.reason.verificationTrace, verificationTraces: settled.map(x => x.status === 'fulfilled' ? x.value.verificationTrace : x.reason.verificationTrace).filter(Boolean) });
      await check('其他合法 Agent 与设备读取 A 的任务', '-32001', async () => {
        const request = await prepareBare({ jsonrpc: '2.0', id: randomUUID(), method: 'tasks/get', params: { id: ownTask.id } }, issue(attacker, { deviceDid: otherDevice.did }), attacker);
        await transmit({ ...request, deviceDid: otherDevice.did, deviceProof: fixtureProof(request, otherDevice) });
      }, '另一个合法持证者及其自有设备仍不能读取 A 的任务。');
      await check('VC＋A 私钥泄露，无设备权限', 'DEVICE_PROOF_REQUIRED', () => invokeBare(), '攻击者可生成有效 A 签名，但无法补齐绑定设备证明。');
      await check('无权限直接调用设备签名接口', 'ESIM_ACCESS_DENIED', async () => {
        const request = await prepareBare();
        await jsonRequest(`${device.baseUrl}/sign`, {}, { holderProof: request.token, challenge: request.challenge.token, rawBody: request.rawBody });
      }, '仅有 VC 与 A 私钥不能调用设备 API；访问令牌不进入浏览器。');
      await check('用攻击者设备替换绑定设备', 'INVALID_DEVICE_SIGNATURE', async () => {
        const request = await prepareBare(); await transmit({ ...request, deviceDid: otherDevice.did, deviceProof: fixtureProof(request, otherDevice) });
      }, 'B 从签发者签名的 VC 取得设备公钥，不信调用者自报设备。');
      await check('拼接不同请求的设备证明', 'DEVICE_PROOF_BINDING_MISMATCH', async () => {
        const old = await prepare(messageRpc('旧请求')), fresh = await prepareBare(messageRpc('新请求'));
        await transmit({ ...fresh, deviceDid: device.did, deviceProof: old.deviceProof });
      }, '新挑战、新正文不能套用旧设备签名。');
      await check('同一挑战替换另一张 VC', 'DEVICE_PROOF_BINDING_MISMATCH', async () => {
        const old = await prepare();
        const changed = makeAuthorization({ identity: agentA, verifierDid, baseUrl, credential: issue(), rawBody: old.rawBody, challenge: old.challenge });
        await transmit({ ...old, token: changed });
      }, '设备证明还绑定确切的持有者签名和 VC 哈希。');
      await check('降级为无设备绑定的基础 VC', 'CREDENTIAL_DEVICE_REQUIRED', () => invokeBare(messageRpc(), issue(agentA, { deviceDid: undefined })), '网络端 v2 强制设备绑定，不接受单签名降级。');
      try {
        await session.deviceLock(true);
        await check('设备锁定后合法 A 调用', 'ESIM_LOCKED', () => invoke(), '设备即使收到合法 A 证明与访问令牌，也服从锁定策略。');
      } finally { await session.deviceLock(false); }
      await check('设备解锁后恢复调用', 'ACCEPTED', () => invoke(), '重新申请挑战并取得双签名。');
      await check('VC、A 私钥及设备调用权全部泄露（边界）', 'ACCEPTED', () => invoke(), '攻击者若还能使用未锁定设备的签名接口，本软件模型仍无法区分其与合法客户端。');
      await session.revoke();
      await check('撤销后再次双签名调用', 'CREDENTIAL_REVOKED', () => invoke(), '最终由 B 检查本地撤销列表，设备签名不覆盖撤销决定。');
      return { verificationTrace: results[0].verificationTrace, results, passed: results.filter(r => r.pass).length, total: results.length };
    },
  };
  return session;
}
