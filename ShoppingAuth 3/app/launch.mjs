import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { generateIdentity } from './lib/identity.mjs';
import { serializeIdentity } from './lib/protocol.mjs';
import { createLocalX402Environment } from './lib/x402-payment.mjs';

function port(value, fallback) {
  const result = Number(value ?? fallback);
  if (!Number.isInteger(result) || result < 0 || result > 65535) throw new Error('PORT / AGENT_B_PORT / ESIM_PORT / OWNER_PORT 必须是 0–65535 的整数。');
  return result;
}
const children = [];
let stopping = false;
let paymentEnvironment;
async function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  for (const child of children) child.kill('SIGTERM');
  process.exitCode = code;
  const timeout = setTimeout(() => { for (const child of children) child.kill('SIGKILL'); }, 2000);
  timeout.unref();
  try { await paymentEnvironment?.close(); } catch (error) { console.error(`支付环境关闭失败：${error.message}`); }
}
function launch(file, config) {
  return new Promise((resolve, reject) => {
    const child = fork(new URL(file, import.meta.url), [], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
    children.push(child);
    const timer = setTimeout(() => reject(new Error(`${file} 启动超时`)), 45000);
    child.on('error', error => { clearTimeout(timer); reject(error); stop(1); });
    child.on('exit', code => { clearTimeout(timer); reject(new Error(`${file} 提前退出 (${code})`)); if (!stopping) stop(code || 1); });
    child.once('message', message => { clearTimeout(timer); if (message.error) reject(new Error(message.error)); else resolve({ ...message, child }); });
    child.send(config);
  });
}
process.on('SIGINT', () => stop()); process.on('SIGTERM', () => stop());
try {
  const issuer = generateIdentity('Credential Issuer'), agentA = generateIdentity('Agent A'), agentB = generateIdentity('Agent B');
  const adminToken = randomBytes(32).toString('base64url');
  const deviceAccessToken = randomBytes(32).toString('base64url');
  const uiToken = randomBytes(32).toString('base64url');
  const ownerUiToken = randomBytes(32).toString('base64url');
  const proposalToken = randomBytes(32).toString('base64url');
  const dbacDeviceToken = randomBytes(32).toString('base64url'), dbacIssuerToken = randomBytes(32).toString('base64url'), dbacStatusToken = randomBytes(32).toString('base64url');
  const dbacDevice = await launch('./dbac-role.mjs', { role: 'device', accessToken: dbacDeviceToken, port: 0 });
  const dbacIssuer = await launch('./dbac-role.mjs', { role: 'issuer', w3c: true, requireHolderProof: true, statusToken: dbacStatusToken, statePath: resolve(process.env.X402_STATE_DIR ?? fileURLToPath(new URL('./var/x402', import.meta.url)), 'credential-status.json'), accessToken: dbacIssuerToken, devicePublicKeys: dbacDevice.publicKeys, port: 0 });
  const ledgerPath = process.env.PAYMENT_DB ? resolve(process.env.PAYMENT_DB) : fileURLToPath(new URL('./var/payment.sqlite', import.meta.url));
  const o = await launch('./owner.mjs', { holderDid: agentA.did, verifierDid: agentB.did, trustedIssuers: [issuer.did], dbacIssuerPublicKey: dbacIssuer.publicKey, w3cIssuer: dbacIssuer.w3c.issuer, proposalToken, uiToken: ownerUiToken, port: port(process.env.OWNER_PORT, 4343) });
  const b = await launch('./agent-b.mjs', { identity: serializeIdentity(agentB), trustedIssuers: [issuer.did], trustedAuthorizers: [o.did], adminToken, ledgerPath, port: port(process.env.AGENT_B_PORT, 4341), dbac: { issuerPublicKey: dbacIssuer.publicKey, w3cIssuer: dbacIssuer.w3c, requireHolderProof: true, statusSource: { baseUrl: dbacIssuer.baseUrl, accessToken: dbacStatusToken } } });
  const d = await launch('./esim.mjs', { accessToken: deviceAccessToken, holderDid: agentA.did, verifierDid: agentB.did, verifierUrl: b.baseUrl, trustedIssuers: [issuer.did], port: port(process.env.ESIM_PORT, 4342) });
  console.log('jCardSim 设备已就绪；正在启动本地 x402 测试链与支付服务…');
  paymentEnvironment = await createLocalX402Environment({
    stateDir: process.env.X402_STATE_DIR ? resolve(process.env.X402_STATE_DIR) : fileURLToPath(new URL('./var/x402', import.meta.url)),
    trustedIssuers: [issuer.did], trustedAuthorizers: [o.did], dbacIssuerPublicKey: dbacIssuer.publicKey, w3cIssuer: dbacIssuer.w3c.issuer, holderDid: agentA.did, deviceDid: d.deviceDid, verifierDid: agentB.did,
    async isDbacCredentialRevoked(bindingId) {
      const response = await fetch(`${dbacIssuer.baseUrl}/credential/status`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-DBAC-Access': dbacStatusToken }, body: JSON.stringify({ bindingId }), signal: AbortSignal.timeout(3000), redirect: 'error' });
      const status = await response.json();
      if (!response.ok || status.bindingId !== bindingId || !['valid', 'revoked'].includes(status.status)) throw new Error('无法确认可信本地签发方的凭证状态。');
      return status.status === 'revoked';
    },
    async isCredentialRevoked(id) {
      const response = await fetch(`${b.baseUrl}/admin/credential-status?id=${encodeURIComponent(id)}`, { headers: { 'X-Demo-Admin': adminToken }, signal: AbortSignal.timeout(3000), redirect: 'error' });
      const state = await response.json();
      if (!response.ok || state.id !== id || typeof state.revoked !== 'boolean') throw new Error('无法确认 B 的当前凭证撤销状态。');
      return state.revoked;
    },
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('B 配置 x402 超时')), 10000);
    b.child.once('message', value => { clearTimeout(timer); value.stage === 'x402-ready' ? resolve() : reject(new Error(value.error ?? 'B x402 未就绪')); });
    b.child.send({ stage: 'configure-x402', backendConfig: paymentEnvironment.backendConfig });
  });
  const a = await launch('./agent-a.mjs', { issuer: serializeIdentity(issuer), agentA: serializeIdentity(agentA), verifierDid: agentB.did, baseUrl: b.baseUrl, adminToken, uiToken, device: { did: d.deviceDid, baseUrl: d.baseUrl, accessToken: deviceAccessToken }, owner: { did: o.did, baseUrl: o.baseUrl, proposalToken }, payerConfig: paymentEnvironment.payerConfig, port: port(process.env.PORT, 4340), dbac: { issuer: { publicKey: dbacIssuer.publicKey, w3c: dbacIssuer.w3c, baseUrl: dbacIssuer.baseUrl, accessToken: dbacIssuerToken }, device: { publicKeys: dbacDevice.publicKeys, baseUrl: dbacDevice.baseUrl, accessToken: dbacDeviceToken } } });
  console.log(`\n统一演示链接: ${a.baseUrl}/#key=${uiToken}&ownerKey=${ownerUiToken}&view=guide\n默认打开三场景演示平台；按阶段或逐条消息操作，Owner 仍逐笔明确批准。\n自动流程辅助入口：${a.baseUrl}/dbac.html`);
  console.log(`\nW3C DID + VC × A2A 0.3.0 · jCardSim + x402 v2 · 0.5.0\n演示页面 / Agent A: ${a.baseUrl} (PID ${a.pid})\n验证服务 / Agent B: ${b.baseUrl}/a2a (PID ${b.pid})\njCardSim / eSIM: ${d.baseUrl} (PID ${d.pid})\n确认服务 / Owner: ${o.baseUrl} (PID ${o.pid})\nAgent Card: ${b.baseUrl}/.well-known/agent-card.json\n控制台链接: ${a.baseUrl}/#key=${uiToken}\nOwner 确认链接: ${o.baseUrl}/#key=${ownerUiToken}\nVC 撤销库: ${ledgerPath}\n支付: 本地 Ganache / ${paymentEnvironment.publicInfo.network} / TEST_USDC（6 位小数，无真实价值）\n代币合约: ${paymentEnvironment.publicInfo.asset}\nA 只能提交提案；请使用独立 Owner 链接核对并批准。两个链接均为本次本地会话的私有控制入口。\n按 Ctrl+C 退出。重启会重新生成身份和访问凭据；本地测试链、钱包、订单回执与 VC 撤销记录持久保留。\n`);
} catch (error) { console.error(`启动失败：${error.message}`); stop(1); }
