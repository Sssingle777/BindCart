import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { generateIdentity } from './lib/identity.mjs';
import { serializeIdentity } from './lib/protocol.mjs';

const children = [];
let closing = false;
const token = () => randomBytes(32).toString('base64url');
const metadataPath = new URL('./var/adyen-runtime.json', import.meta.url);
async function stop() {
  if (closing) return;
  closing = true;
  const stopped = children.map(child => new Promise(resolve => {
    if (child.exitCode !== null || child.signalCode !== null) return resolve();
    child.once('exit', resolve);
    if (child.connected) child.send({ action: 'shutdown' });
  }));
  const timeout = setTimeout(() => { for (const child of children) if (child.exitCode === null) child.kill(); }, 2500);
  await Promise.all(stopped);
  clearTimeout(timeout);
  await rm(metadataPath, { force: true });
}
async function launch(relativePath, config) {
  return new Promise((resolve, reject) => {
    const child = fork(new URL(relativePath, import.meta.url), [], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
    children.push(child);
    const timer = setTimeout(() => reject(new Error(`${relativePath} 启动超时。`)), 30000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); if (!closing) { reject(new Error(`${relativePath} 提前退出。`)); void stop(); } });
    child.on('message', data => { if (data.action === 'shutdown-requested') void stop(); });
    child.once('message', data => { clearTimeout(timer); data.error ? reject(new Error(data.error)) : resolve(data); });
    child.send(config);
  });
}
try {
  const deviceToken = token(), issuerToken = token(), statusToken = token(), serviceKey = token(), ownerKey = token(), uiToken = token();
  const device = await launch('./dbac-role.mjs', { role: 'device', accessToken: deviceToken, port: 0 });
  const issuer = await launch('./dbac-role.mjs', { role: 'issuer', w3c: true, requireHolderProof: true, devicePublicKeys: device.publicKeys, accessToken: issuerToken, statusToken, port: 0 });
  const verifierIdentity = generateIdentity('MyStore checkout gate / Agent B');
  const verifier = await launch('./lib/adyen-shop/verifier-process.mjs', { identity: serializeIdentity(verifierIdentity), issuer: { publicKey: issuer.publicKey, w3c: issuer.w3c }, statusSource: { baseUrl: issuer.baseUrl, accessToken: statusToken }, serviceKey, ownerKey });
  const actors = { issuer: { pid: issuer.pid, did: issuer.w3c.issuer }, device: { pid: device.pid, type: 'Node BLS12-381 software eSIM' }, verifier: { pid: verifier.pid, did: verifier.did } };
  const a = await launch('./lib/adyen-shop/server-process.mjs', { uiToken, serviceKey, actors, verifierDid: verifier.did, verifierUrl: verifier.baseUrl, issuer: { baseUrl: issuer.baseUrl, publicKey: issuer.publicKey, w3c: issuer.w3c, accessToken: issuerToken }, device: { baseUrl: device.baseUrl, publicKeys: device.publicKeys, accessToken: deviceToken }, port: Number(process.env.SHOP_PORT ?? 4380), evidenceDir: fileURLToPath(new URL('./var/adyen-orders/', import.meta.url)) });
  await mkdir(new URL('./var/', import.meta.url), { recursive: true });
  const url = `${a.baseUrl}/shop.html#key=${uiToken}&ownerKey=${ownerKey}`;
  await writeFile(metadataPath, JSON.stringify({ url, baseUrl: a.baseUrl, pid: process.pid, children: children.map(x => x.pid), startedAt: new Date().toISOString() }, null, 2), { mode: 0o600 });
  console.log(`Adyen 购物接入已启动：${a.baseUrl}\n使用“启动 Adyen 购物演示.cmd”打开本次会话。\n凭证、持有者与软件 eSIM 验证在本地执行；付款使用官方商城测试页面。\nCtrl+C 关闭。`);
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
} catch (error) { console.error(error.message); await stop(); process.exitCode = 1; }
