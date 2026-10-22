import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { AppError, digest, unix } from '../protocol.mjs';
import { verifyJws } from '../identity.mjs';
import { deriveCredential } from '../w3c-bbs.mjs';
import { generateDeviceKey, signDeviceRequest, DBAC_VERSION, DBAC_SUITE } from './crypto.mjs';
import { DBAC_EXTENSION } from './policy.mjs';
import { DBAC_PAYMENT_RESPONSE_TYP } from './payment-policy.mjs';
import { bindingContext, presentationHeader } from './w3c-profile.mjs';
import { signHolderProof } from './holder-proof.mjs';

const catalog = [
  ['normal', '合法凭证与两方证明', 'control', 'ACCEPTED', '合法 A 与原设备为当前请求分别提供真实证明。'],
  ['copied-vc', '仅复制合法 VC', 'black-box', 'W3C_DEVICE_PROOF_REQUIRED', '攻击工作区仅取得已签发公开 VC；无 A 私钥、设备会话或 Owner 权限。BBS 派生本身不需要 A 的长期私钥。'],
  ['missing-holder', '缺少 A 侧证明', 'white-box', 'HOLDER_PROOF_REQUIRED', '本地夹具保留有效 VC 与设备材料，仅移除持有者签名。'],
  ['missing-device', '缺少设备侧证明', 'white-box', 'W3C_DEVICE_PROOF_REQUIRED', '本地夹具保留有效 VC，仅移除本次设备签名。'],
  ['invalid-holder', '结构合法的 A 侧无效签名', 'white-box', 'HOLDER_SIGNATURE_INVALID', '保留完整 JWS 三段和 64 字节 Ed25519 签名结构，仅改变签名字节。'],
  ['invalid-device', '结构合法的设备无效签名', 'white-box', 'DBAC_DEVICE_SIGNATURE_INVALID', '以另一真实签名替换合法 G2 编码的设备贡献，检查设备配对验证。'],
  ['wrong-device', '另一台测试设备的贡献', 'white-box', 'DBAC_DEVICE_SIGNATURE_INVALID', '夹具临时生成另一测试设备并真实签名；替换贡献不改变签发者保护的原绑定。'],
  ['cross-challenge', '拼接不同挑战', 'white-box', 'W3C_BBS_INVALID_PROOF', '完整合法证明绑定旧挑战，提交头使用同一正文的新挑战。'],
  ['cross-order', '拼接不同订单', 'white-box', 'DBAC_BODY_MISMATCH', '保留全部有效证明与原挑战，仅把正文订单换成另一个订单。'],
  ['cross-phase', '拼接不同业务阶段', 'white-box', 'DBAC_BODY_MISMATCH', '保留全部有效 proposal 证明，仅把实际正文 phase 改为 authorize。'],
  ['replay', '重放已消费的完整证明', 'white-box', 'DBAC_REPLAY', '先确认完整请求通过，再原样重放同一请求、挑战与证明。'],
  ['expired-challenge', '过期挑战', 'white-box', 'DBAC_CHALLENGE_EXPIRED', '先生成完整有效证明，实际等待服务器挑战过期后才提交；约 61 秒。'],
  ['revoked', '撤销后新挑战与完整证明', 'white-box', 'W3C_CREDENTIAL_REVOKED', '先正常通过，撤销实验专用凭证，再用新挑战、合法 A 与原设备重新生成完整证明。'],
  ['locked-device', '锁定后直接调用签名接口', 'white-box', 'DBAC_DEVICE_LOCKED', '夹具保存原锁状态，锁定模拟设备后直接调用后端 /sign，结束时恢复原锁状态。'],
  ['unknown-issuer', '未知签发方', 'white-box', 'W3C_BBS_UNTRUSTED_ISSUER', '仅改变派生 VC 的签发方标识；B 必须拒绝不在信任配置内的签发方。'],
].map(([id, title, kind, expected, preconditions]) => Object.freeze({ id, title, kind, expected, preconditions, estimatedSeconds: id === 'expired-challenge' ? 65 : 8 }));
const clone = value => value === undefined ? null : structuredClone(value);
const environmentError = code => /(?:TRANSPORT|HTTP_ERROR|NOT_READY|UNAVAILABLE|CAPACITY|TIMEOUT|ECONN|FETCH|INCOMPLETE|LOCKED|CREDENTIAL_REQUIRED|INVALID_MODE)/.test(code ?? '');
const safeError = error => ({ code: error.code ?? 'EXPERIMENT_ENVIRONMENT_ERROR', message: error.message ?? '实验请求未完成。' });
const ledgerView = value => ({ executionCount: value?.executionCount ?? null, accounts: (value?.accounts ?? []).map(({ id, balanceMinor }) => ({ id, balanceMinor })) });
const requestView = prepared => ({ role: '验证者智能体 B 实际收到的公开材料', challengeId: prepared.context.challengeId, authenticationRoundId: prepared.context.challengeId, method: 'POST', endpoint: '/dbac/payment/a2a', body: JSON.parse(prepared.rawBody), proof: { ...clone(prepared.presentation ?? {}), ...(prepared.verifiableCredential ? { verifiableCredential: clone(prepared.verifiableCredential) } : {}), ...(prepared.holderProof ? { holderProof: prepared.holderProof } : {}) } });

// This factory is reachable only from the local console's existing capability
// boundary. initialize MUST select a separate private experiment session. It
// never calls Owner approval, wallet signing, or payment settlement.
export function createFrameworkAttackExperiments({ entry, prepare, prepareCredential, challengeFor, transmit, deviceRequest, deviceHealth, issuerRequest, getLedger, issuer, device, baseUrl, verifierDid, initialize, holderIdentity, signHolder }) {
  let busy = false;
  const history = [];
  const proofSign = prepared => signHolder ? signHolder(prepared) : signHolderProof({ identity: holderIdentity, context: prepared.context, verifiableCredential: prepared.verifiableCredential, presentation: prepared.presentation });
  async function attackerPost(url, body, headers = {}) {
    let response, value;
    try {
      response = await fetch(url, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(30000), headers: { 'Content-Type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });
      value = await response.json();
    } catch { throw new AppError('EXPERIMENT_TRANSPORT', '独立攻击工作区未收到有效 HTTP 响应。', 503); }
    if (!response.ok) throw Object.assign(new AppError(value.error?.code ?? 'EXPERIMENT_HTTP_ERROR', value.error?.message ?? '实验 HTTP 请求未完成。', response.status), { verificationTrace: value.verificationTrace });
    return { value, response };
  }
  async function attackerTransmit(prepared) {
    const proof = { verifiableCredential: prepared.verifiableCredential };
    const { value, response } = await attackerPost(`${baseUrl}/dbac/payment/a2a`, prepared.rawBody, { 'X-A2A-Extensions': DBAC_EXTENSION, 'X-A2A-DBAC-Challenge': prepared.context.challengeId, 'X-A2A-DBAC-Proof': Buffer.from(JSON.stringify(proof)).toString('base64url') });
    const signed = verifyJws(response.headers.get('x-a2a-dbac-payment-response'), { typ: DBAC_PAYMENT_RESPONSE_TYP, purpose: 'authentication', expectedDid: verifierDid }).payload;
    return { accepted: true, task: value.result, verificationTrace: signed.verificationTrace };
  }
  async function run({ mode = 'bbs-bls', scenarioId = 'copied-vc', paymentOrder } = {}) {
    const scenario = catalog.find(value => value.id === scenarioId);
    if (!scenario) throw new AppError('EXPERIMENT_UNKNOWN_SCENARIO', '请选择已有攻击实验。', 400);
    if (busy) throw new AppError('EXPERIMENT_BUSY', '当前实验尚未结束，请等待结果。', 409);
    busy = true;
    const started = Date.now();
    const record = { id: randomUUID(), scenarioId, scenario: scenario.title, kind: scenario.kind, mode, preconditions: scenario.preconditions, startedAt: new Date(started).toISOString(), expected: scenario.expected, actual: null, completion: 'incomplete', expectationMet: false, requestRejected: false, authenticationIssued: false, rejectionStage: null, error: null, control: null, request: null, verificationTrace: null, sideEffects: null };
    let before, after, outcome, restoreLock, attackSubmitted = false;
    try {
      await initialize({ mode, paymentOrder });
      const e = entry(mode);
      before = ledgerView(await getLedger());
      if (!e.verifiableCredential || !issuer.w3c) throw new AppError('EXPERIMENT_PROFILE_UNAVAILABLE', '该实验需要已启用的 W3C 凭证与两方证明配置。', 503);
      const controlPrepared = await prepare({ mode, phase: 'proposal' });
      const controlResult = await transmit(controlPrepared);
      if (controlResult.accepted !== true) throw new AppError('EXPERIMENT_CONTROL_INCOMPLETE', '有效控制组没有获得真实认证通过结果。', 503);
      record.control = { accepted: true, challengeId: controlPrepared.context.challengeId, verificationTrace: clone(controlResult.verificationTrace), paymentExecuted: false };
      let prepared;
      if (scenarioId === 'normal') { prepared = controlPrepared; outcome = controlResult; }
      else if (scenarioId === 'copied-vc') {
        // Copy only the public VC. No legitimate key handle or capability is
        // passed to this independent attacker workspace or its HTTP transport.
        const copiedCredential = clone(e.verifiableCredential);
        const body = JSON.parse(controlPrepared.rawBody); body.id = randomUUID(); body.params.message.messageId = randomUUID();
        const rawBody = JSON.stringify(body);
        const context = await challengeFor(rawBody, mode, e.order.orderId);
        const verifiableCredential = await deriveCredential({ credential: copiedCredential, issuerProfile: issuer.w3c, presentationHeader: presentationHeader(context) });
        prepared = { rawBody, context, mode, phase: 'proposal', payment: clone(e.order), verifiableCredential, presentation: null };
        record.attackerContext = { id: randomUUID(), material: 'copied-public-vc', holderKeyAvailable: false, deviceCapabilityAvailable: false, issuerCapabilityAvailable: false, ownerCapabilityAvailable: false };
        record.accessChecks = [];
        for (const [target, url, body] of [['device-sign', `${device.baseUrl}/sign`, { mode }], ['issuer-revoke', `${issuer.baseUrl}/credentials/revoke`, { bindingId: copiedCredential.credentialSubject.bindingId }]]) {
          try { await attackerPost(url, body); record.accessChecks.push({ target, actual: 'ACCEPTED' }); }
          catch (error) { record.accessChecks.push({ target, ...safeError(error), actual: error.code }); }
        }
      } else if (scenarioId === 'replay') prepared = controlPrepared;
      else if (scenarioId === 'revoked') {
        await issuerRequest('/credentials/revoke', { bindingId: e.verifiableCredential.credentialSubject.bindingId });
        prepared = await prepare({ mode, phase: 'proposal', allowRevokedFixture: true });
        record.revocation = { credential: 'experiment-only', freshChallenge: prepared.context.challengeId !== controlPrepared.context.challengeId, completeHolderProof: Boolean(prepared.holderProof), completeDeviceProof: Boolean(prepared.presentation?.deviceSignature) };
      } else if (scenarioId === 'locked-device') {
        const health = await deviceHealth();
        const deviceId = e.deviceId;
        restoreLock = { mode, locked: Boolean((health.devices?.find(item => item.deviceId === deviceId)?.modes ?? health.modes)?.[mode]?.locked) };
        const context = await challengeFor(controlPrepared.rawBody, mode, e.order.orderId);
        const derived = await prepareCredential(e, context);
        await deviceRequest('/lock', { ...restoreLock, locked: true });
        record.request = { role: '模拟 eSIM 实际收到的材料', endpoint: '/sign', body: clone(derived.prepared.request), challengeId: context.challengeId, authenticationRoundId: context.challengeId };
        attackSubmitted = true;
        await deviceRequest('/sign', derived.prepared.request);
        outcome = { accepted: true, deviceSignatureIssued: true };
      } else prepared = await prepare({ mode, phase: 'proposal' });
      if (prepared) {
        if (scenarioId === 'missing-holder') delete prepared.holderProof;
        if (scenarioId === 'missing-device') delete prepared.presentation.deviceSignature;
        if (scenarioId === 'invalid-holder') {
          const chunks = prepared.holderProof.split('.'), signature = Buffer.from(chunks[2], 'base64url'); signature[0] ^= 1; chunks[2] = signature.toString('base64url'); prepared.holderProof = chunks.join('.');
        }
        if (['invalid-device', 'wrong-device'].includes(scenarioId)) {
          const alternate = generateDeviceKey();
          const request = { version: DBAC_VERSION, suite: DBAC_SUITE, mode: 'bbs-bls', randomizedDevicePublicKey: prepared.presentation.randomizedDevicePublicKey, context: bindingContext(prepared.context, prepared.verifiableCredential) };
          prepared.presentation.deviceSignature = signDeviceRequest({ deviceSecretKey: alternate.secretKey, request }).signature;
          prepared.holderProof = proofSign(prepared);
          record.fixture = { alternateDevicePublicKeyFingerprint: digest(alternate.publicKey), signatureStructure: 'valid compressed G2 point', holderResignedMutatedTranscript: true, note: '故障注入替换组合展示中的设备贡献；不声称外部攻击者能构造通过全部知识关系的材料。' };
        }
        if (scenarioId === 'cross-challenge') prepared.context = await challengeFor(prepared.rawBody, mode, e.order.orderId);
        if (['cross-order', 'cross-phase'].includes(scenarioId)) {
          const body = JSON.parse(prepared.rawBody), data = body.params.message.parts[0].data;
          if (scenarioId === 'cross-order') data.payment.orderId = `urn:uuid:${randomUUID()}`;
          else data.phase = 'authorize';
          prepared.rawBody = JSON.stringify(body);
        }
        if (scenarioId === 'unknown-issuer') prepared.verifiableCredential.issuer = 'did:example:untrusted-experiment-issuer';
        record.request = requestView(prepared);
        if (scenarioId === 'expired-challenge') {
          const milliseconds = Math.max(0, prepared.context.exp * 1000 - Date.now() + 100);
          await delay(milliseconds);
          record.expiry = { serverExpiresAt: prepared.context.exp, submittedAt: unix(), actualWaitMs: milliseconds };
        }
        attackSubmitted = true;
        outcome ??= await (scenarioId === 'copied-vc' ? attackerTransmit(prepared) : transmit(prepared));
      }
      record.actual = outcome?.accepted ? 'ACCEPTED' : 'EXPERIMENT_RESPONSE_INCOMPLETE';
      record.authenticationIssued = outcome?.accepted === true && !outcome.deviceSignatureIssued;
      record.verificationTrace = clone(outcome?.verificationTrace);
      record.completion = record.actual === 'ACCEPTED' ? 'completed' : 'incomplete';
    } catch (error) {
      record.error = safeError(error);
      record.actual = error.code ?? 'EXPERIMENT_ENVIRONMENT_ERROR';
      record.verificationTrace = clone(error.verificationTrace);
      record.rejectionStage = error.verificationTrace?.steps?.find(step => step.status === 'fail')?.id ?? (scenarioId === 'locked-device' && error.code === 'DBAC_DEVICE_LOCKED' ? 'device_access' : null);
      const expectedDeviceDenial = scenarioId === 'locked-device' && record.actual === scenario.expected;
      const verifiedDenial = attackSubmitted && Boolean(record.verificationTrace?.steps?.some(step => step.status === 'fail'));
      record.completion = attackSubmitted && (expectedDeviceDenial || (verifiedDenial && !environmentError(record.actual))) ? 'completed' : 'incomplete';
      record.requestRejected = record.completion === 'completed';
    } finally {
      if (restoreLock) {
        try { await deviceRequest('/lock', restoreLock); record.deviceLockRestored = true; }
        catch (error) { record.deviceLockRestored = false; record.cleanupError = safeError(error); record.completion = 'incomplete'; }
      }
      try { after = ledgerView(await getLedger()); }
      catch (error) { record.observationError = safeError(error); record.completion = 'incomplete'; }
      record.sideEffects = { before: before ?? null, after: after ?? null, paymentExecutionDelta: before?.executionCount !== null && after?.executionCount !== null && before && after ? after.executionCount - before.executionCount : null, balancesUnchanged: Boolean(before && after && JSON.stringify(before.accounts) === JSON.stringify(after.accounts)), ownerApprovalRequested: false, walletSignatureRequested: false };
      record.expectationMet = record.completion === 'completed' && record.actual === record.expected && record.sideEffects.paymentExecutionDelta === 0 && record.sideEffects.balancesUnchanged && (!record.accessChecks || record.accessChecks.every(check => check.actual === 'DBAC_ACCESS_DENIED'));
      record.durationMs = Date.now() - started;
      record.completedAt = new Date().toISOString();
      history.push(clone(record));
      if (history.length > 30) history.shift();
      busy = false;
    }
    return clone(record);
  }
  return { catalog: () => clone(catalog), run, history: () => clone(history), status: () => ({ busy, count: history.length }) };
}
