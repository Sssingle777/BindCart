import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { generateDeviceKey, preparePresentation, finalizePresentation, signDeviceRequest, verifyCredential } from './crypto.mjs';
import { verifyJws } from '../identity.mjs';
import { preVerificationFailure } from '../verification-trace.mjs';
import { AppError, digest, unix } from '../protocol.mjs';
import { DBAC_EXTENSION, DBAC_CHALLENGE_TYP, DBAC_RESPONSE_TYP, DBAC_SCHEMA, DBAC_MODES, requiredDisclosures } from './policy.mjs';

export async function dbacFetch(url, { token, body, rawBody, includeHeaders = false, headers = {} } = {}) {
  const post = body !== undefined || rawBody !== undefined;
  const response = await fetch(url, { method: post ? 'POST' : 'GET', headers: { Accept: 'application/json', ...(post ? { 'Content-Type': 'application/json' } : {}), ...(token ? { 'X-DBAC-Access': token } : {}), ...headers }, ...(post ? { body: rawBody ?? JSON.stringify(body) } : {}), redirect: 'error', signal: AbortSignal.timeout(30000) });
  const data = await response.json();
  if (!response.ok) {
    const error = new AppError(data.error?.code ?? 'DBAC_HTTP_ERROR', data.error?.message ?? `HTTP ${response.status}`, response.status);
    if (data.verificationTrace) error.verificationTrace = data.verificationTrace;
    throw error;
  }
  return includeHeaders ? { data, headers: Object.fromEntries(response.headers) } : data;
}

export function createDbacSession({ baseUrl, verifierDid, issuer, device }) {
  const credentials = new Map();
  let lastResult = null;
  const modeValue = mode => { if (!DBAC_MODES.includes(mode)) throw new AppError('DBAC_INVALID_MODE', '不支持的论文方案。'); return mode; };
  const rpcMessage = text => ({ jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: { message: { kind: 'message', role: 'user', messageId: randomUUID(), parts: [{ kind: 'data', data: { scope: 'demo:echo', text } }] } } });
  async function challengeFor(rawBody, mode) {
    const data = await dbacFetch(`${baseUrl}/dbac/challenge`, { body: { bodyHash: digest(rawBody), mode } });
    const { payload } = verifyJws(data.challenge, { typ: DBAC_CHALLENGE_TYP, expectedDid: verifierDid });
    const ctx = payload.context;
    if (payload.iss !== verifierDid || !ctx || ctx.profile !== DBAC_EXTENSION || ctx.mode !== mode || ctx.verifier !== verifierDid || ctx.target !== `${baseUrl}/dbac/a2a` || ctx.method !== 'POST' || ctx.bodyHash !== digest(rawBody) || typeof ctx.challengeId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(ctx.nonce) || !Number.isSafeInteger(ctx.iat) || !Number.isSafeInteger(ctx.exp) || ctx.iat > unix() + 5 || ctx.exp <= unix() || ctx.exp <= ctx.iat || ctx.exp - ctx.iat > 60 || JSON.stringify(ctx.schema) !== JSON.stringify(DBAC_SCHEMA) || JSON.stringify(ctx.requiredDisclosures) !== JSON.stringify(requiredDisclosures(mode))) throw new AppError('DBAC_BAD_CHALLENGE', 'B 的签名挑战或披露策略不符合本地策略。');
    return ctx;
  }
  async function prepare({ mode = 'bbs-bls', text = '请验证我具有本次服务的调用资格。' } = {}) {
    modeValue(mode);
    const credential = credentials.get(mode);
    if (!credential) throw new AppError('DBAC_CREDENTIAL_REQUIRED', '请先签发 BBS 设备绑定凭证。');
    if (typeof text !== 'string' || text.length > 1000) throw new AppError('INVALID_TEXT', '消息需要是不超过 1000 字的字符串。');
    const started = performance.now(), rawBody = JSON.stringify(rpcMessage(text));
    const context = await challengeFor(rawBody, mode);
    const prepared = preparePresentation({ credential, context, disclosedIndices: [0, 1, 2, 3], mode });
    const beforeDevice = performance.now();
    const response = await dbacFetch(`${device.baseUrl}/sign`, { token: device.accessToken, body: prepared.request });
    const afterDevice = performance.now();
    const presentation = finalizePresentation({ state: prepared.state, response });
    return { context, presentation, rawBody, mode, deviceRequest: prepared.request, timings: { prepareMs: +(performance.now() - started).toFixed(2), deviceRoundTripMs: +(afterDevice - beforeDevice).toFixed(2) } };
  }
  async function transmit(prepared) {
    const headers = { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Challenge': prepared.context.challengeId, 'X-A2A-DBAC-Proof': Buffer.from(JSON.stringify(prepared.presentation)).toString('base64url') };
    const started = performance.now();
    const received = await dbacFetch(`${baseUrl}/dbac/a2a`, { rawBody: prepared.rawBody, headers, includeHeaders: true });
    const { payload } = verifyJws(received.headers['x-a2a-dbac-response'], { typ: DBAC_RESPONSE_TYP, expectedDid: verifierDid });
    if (payload.iss !== verifierDid || payload.contextHash !== digest(JSON.stringify(prepared.context)) || payload.responseHash !== digest(JSON.stringify(received.data)) || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || payload.iat > unix() + 5 || payload.exp <= unix() || payload.exp - payload.iat > 60) throw new AppError('DBAC_BAD_RECEIPT', 'B 的匿名调用回执验签或绑定失败。');
    if (received.data?.jsonrpc !== '2.0' || received.data.id !== JSON.parse(prepared.rawBody).id || received.data.result?.status?.state !== 'completed') throw new AppError('DBAC_BAD_RECEIPT', 'B 未返回对应的已完成任务。');
    const disclosed = prepared.presentation.disclosed.map(entry => ({ ...entry, name: DBAC_SCHEMA[entry.index] }));
    return { accepted: true, verificationTrace: payload.verificationTrace, mode: prepared.mode, task: received.data.result, presentation: prepared.presentation, verification: { ...payload.verification, responseSignature: true, contextBound: true, deviceContribution: true, hardware: false }, disclosed, hiddenFields: DBAC_SCHEMA.filter((_, i) => ![0, 1, 2, 3].includes(i)), wire: { endpoint: `${baseUrl}/dbac/a2a`, headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.parse(prepared.rawBody), proof: prepared.presentation }, timings: { ...prepared.timings, verifierRoundTripMs: +(performance.now() - started).toFixed(2) } };
  }
  const session = {
    async state({ mode = 'bbs-bls' } = {}) {
      modeValue(mode);
      const credential = credentials.get(mode);
      const info = await dbacFetch(`${device.baseUrl}/health`);
      return { available: true, mode, scheme: 'BBS-BLS / BBS-BlindBLS', supportedModes: DBAC_MODES, issuer: { publicKey: issuer.publicKey }, device: { ...info, publicKey: info.publicKeys[mode], ...info.modes[mode] }, credential: credential ? { suite: credential.suite, attributes: credential.attributes.map((value, index) => ({ index, name: DBAC_SCHEMA[index], value, disclosed: [0, 1, 2, 3].includes(index) })) } : null, lastResult: lastResult?.mode === mode ? lastResult : null };
    },
    async issue({ mode = 'bbs-bls' } = {}) {
      modeValue(mode);
      const enrollment = await dbacFetch(`${issuer.baseUrl}/enroll/challenge`, { token: issuer.accessToken, body: { mode } });
      if (enrollment.request?.context?.purpose !== 'dbac-enrollment-v1' || enrollment.request.context.mode !== mode || enrollment.request.context.issuerPublicKey !== issuer.publicKey || enrollment.request.randomizedDevicePublicKey !== device.publicKeys[mode]) throw new AppError('DBAC_ISSUANCE_MISMATCH', '注册挑战未绑定预期签发者和设备。');
      const response = await dbacFetch(`${device.baseUrl}/enroll/sign`, { token: device.accessToken, body: { mode, request: enrollment.request } });
      const result = await dbacFetch(`${issuer.baseUrl}/issue`, { token: issuer.accessToken, body: { registrationId: enrollment.registrationId, response } });
      verifyCredential(result.credential, { issuerPublicKey: issuer.publicKey });
      if (result.credential.devicePublicKey !== device.publicKeys[mode] || result.credential.attributes.length !== DBAC_SCHEMA.length || result.credential.attributes[3] !== mode) throw new AppError('DBAC_ISSUANCE_MISMATCH', '签发凭证未绑定当前模式、设备或 schema。');
      credentials.set(mode, result.credential); lastResult = null;
      return session.state({ mode });
    },
    async deviceLock({ locked, mode = 'bbs-bls' }) {
      modeValue(mode);
      if (typeof locked !== 'boolean') throw new AppError('INVALID_LOCK', 'locked 必须是布尔值。');
      return dbacFetch(`${device.baseUrl}/lock`, { token: device.accessToken, body: { locked, mode } });
    },
    async invoke(options = {}) {
      try { lastResult = await transmit(await prepare(options)); return lastResult; }
      catch (error) { error.verificationTrace ??= preVerificationFailure('dbac', error); throw error; }
    },
    // Exposed only to in-process tests; not an HTTP API or state export.
    prepare, transmit,
    async demo({ mode = 'bbs-bls' } = {}) {
      modeValue(mode);
      if (!credentials.has(mode)) await session.issue({ mode });
      const credential = credentials.get(mode);
      const deviceBefore = await dbacFetch(`${device.baseUrl}/health`);
      if (deviceBefore.modes[mode].locked) throw new AppError('DBAC_DEVICE_LOCKED', '请先解锁 BLS 软件设备再运行完整验收。');
      const results = [];
      async function check(name, expected, action, detail) {
        let actual = 'ACCEPTED', verificationTrace;
        try { verificationTrace = (await action())?.verificationTrace; }
        catch (error) { actual = error.code ?? 'ERROR'; verificationTrace = error.verificationTrace ?? preVerificationFailure('dbac', error); }
        results.push({ name, expected, actual, pass: actual === expected, detail, ...(verificationTrace ? { verificationTrace } : {}) });
      }
      const first = await prepare({ mode }), firstResult = await transmit(first);
      results.push({ name: '正常匿名凭证展示', expected: 'ACCEPTED', actual: 'ACCEPTED', pass: true, detail: 'B 实际验证随机化 BBS、设备贡献和披露策略。', verificationTrace: firstResult.verificationTrace });
      await check('原样重放已接受的展示', 'DBAC_REPLAY', () => transmit(first), '一次性挑战由 B 消费。');
      const second = await prepare({ mode }); await transmit(second);
      const proofText = JSON.stringify(first.presentation);
      const hiddenValues = credential.attributes.filter((_, i) => ![0, 1, 2, 3].includes(i));
      const privacyEvidence = { randomizedKeysDiffer: first.presentation.randomizedDevicePublicKey !== second.presentation.randomizedDevicePublicKey, stableDeviceKeyAbsent: !proofText.includes(credential.devicePublicKey), originalCredentialSignatureAbsent: !proofText.includes(credential.signature.A), hiddenValuesAbsent: hiddenValues.every(value => !proofText.includes(value)), deviceSeesContext: mode === 'bbs-bls', deviceRequestFields: Object.keys(first.deviceRequest), boundary: '这些是报文结构和随机化检查，不是不可关联性或 Unlink 安全证明；IP、时序、公开属性和业务正文仍可能关联。' };
      const privacyPass = privacyEvidence.randomizedKeysDiffer && privacyEvidence.stableDeviceKeyAbsent && privacyEvidence.originalCredentialSignatureAbsent && privacyEvidence.hiddenValuesAbsent;
      results.push({ name: '两次展示随机化及隐藏字段结构', expected: 'PASS', actual: privacyPass ? 'PASS' : 'FAIL', pass: privacyPass, detail: privacyEvidence.boundary,
        verificationTrace: { profile: 'dbac', source: 'agent-a', outcome: privacyPass ? 'pass' : 'fail', steps: [
          ['randomization', '展示随机化', privacyEvidence.randomizedKeysDiffer, '比较两次实际展示中的随机化设备公钥。'],
          ['stable_key_absent', '原设备公钥未披露', privacyEvidence.stableDeviceKeyAbsent, '扫描实际证明序列化内容。'],
          ['original_signature_absent', '原凭证签名未披露', privacyEvidence.originalCredentialSignatureAbsent, '检查实际证明不包含原始凭证签名。'],
          ['hidden_values_absent', '隐藏属性值未披露', privacyEvidence.hiddenValuesAbsent, '检查实际证明不包含隐藏属性的原文。'],
        ].map(([id, title, pass, detail]) => ({ id, title, actor: 'agent-a', status: pass ? 'pass' : 'fail', detail })) },
      });
      await check('复制凭证但用攻击者设备签名', 'DBAC_DEVICE_SIGNATURE_INVALID', async () => {
        const rawBody = JSON.stringify(rpcMessage('缺少绑定设备的攻击'));
        const prepared = preparePresentation({ credential, context: await challengeFor(rawBody, mode), disclosedIndices: [0, 1, 2, 3], mode });
        const other = generateDeviceKey();
        finalizePresentation({ state: prepared.state, response: signDeviceRequest({ deviceSecretKey: other.secretKey, request: prepared.request }) });
      }, '凭证文件本身不能提供绑定设备的秘密。');
      await check('没有设备调用权限', 'DBAC_ACCESS_DENIED', () => dbacFetch(`${device.baseUrl}/sign`, { body: first.deviceRequest }), '设备访问权限独立于凭证。');
      const bodyAttack = await prepare({ mode });
      bodyAttack.rawBody = bodyAttack.rawBody.replace('本次服务', '另一服务');
      await check('篡改请求正文', 'DBAC_BODY_MISMATCH', () => transmit(bodyAttack), '上下文绑定完整业务请求的哈希。');
      const disclosureAttack = await prepare({ mode });
      disclosureAttack.presentation.disclosed[0].value = 'administrator';
      await check('篡改披露权限', 'DBAC_POLICY_REJECTED', () => transmit(disclosureAttack), '匿名并不意味着省略权限策略。');
      const missing = await prepare({ mode }); delete missing.presentation.deviceSignature;
      await check('删除设备贡献', 'DBAC_INVALID_INPUT', () => transmit(missing), 'B 要求完整的论文证明结构。');
      const reuse = await prepare({ mode }); reuse.presentation = structuredClone(first.presentation);
      await check('旧证明套用新挑战', 'DBAC_PROOF_INVALID', () => transmit(reuse), 'Fiat–Shamir transcript 与设备签名绑定当前上下文。');
      const concurrent = await prepare({ mode });
      const raced = await Promise.allSettled(Array.from({ length: 3 }, () => transmit(concurrent)));
      const accepted = raced.filter(x => x.status === 'fulfilled').length;
      const replayed = raced.filter(x => x.status === 'rejected' && x.reason.code === 'DBAC_REPLAY').length;
      const racePass = accepted === 1 && replayed === 2;
      results.push({ name: '并发重复提交', expected: '1 ACCEPTED / 2 DBAC_REPLAY', actual: `${accepted} ACCEPTED / ${replayed} DBAC_REPLAY`, pass: racePass, detail: '验签和消费挑战之间没有异步切换。', verificationTrace: raced.find(x => x.status === 'rejected')?.reason.verificationTrace, verificationTraces: raced.map(x => x.status === 'fulfilled' ? x.value.verificationTrace : x.reason.verificationTrace).filter(Boolean) });
      try {
        await session.deviceLock({ locked: true, mode });
        await check('设备锁定后无法生成新展示', 'DBAC_DEVICE_LOCKED', () => prepare({ mode }), '锁定不追溯撤销已经签出的证明。');
      } finally { await session.deviceLock({ locked: false, mode }); }
      lastResult = firstResult;
      return { mode, verificationTrace: firstResult.verificationTrace, results, passed: results.filter(x => x.pass).length, total: results.length, privacyEvidence };
    },
  };
  return session;
}
