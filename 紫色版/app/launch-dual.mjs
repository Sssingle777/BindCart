import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { generateIdentity } from './lib/identity.mjs';
import { serializeIdentity } from './lib/protocol.mjs';
import { createLocalX402Environment } from './lib/x402-payment.mjs';
import { loadMerchantIdentity } from './lib/storefront/merchant.mjs';

const children = [];
const root = resolve(process.env.DUAL_STATE_DIR ?? fileURLToPath(new URL('./var/dual-live/', import.meta.url)));
const metadataPath = process.env.DUAL_RUNTIME_PATH ? resolve(process.env.DUAL_RUNTIME_PATH) : new URL('./var/dual-runtime.json', import.meta.url);
const token = () => randomBytes(32).toString('base64url');
let closing = false, environment;
async function stop() {
  if (closing) return; closing = true;
  const stopped = children.map(child => new Promise(done => {
    if (child.exitCode !== null || child.signalCode !== null) return done();
    child.once('exit', done);
    if (child.connected) child.disconnect(); else child.kill();
  }));
  const timer = setTimeout(() => { for (const child of children) if (child.exitCode === null) child.kill(); }, 3000);
  await Promise.all(stopped); clearTimeout(timer);
  await environment?.close(); await rm(metadataPath, { force: true });
}
async function launch(path, config) {
  return new Promise((ready, reject) => {
    const child = fork(new URL(path, import.meta.url), [], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
    children.push(child);
    const timer = setTimeout(() => reject(new Error(`${path} startup timeout`)), 30000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', () => { clearTimeout(timer); if (!closing) { reject(new Error(`${path} stopped`)); void stop(); } });
    child.on('message', data => { if (data.action === 'shutdown-requested') void stop(); });
    child.once('message', data => { clearTimeout(timer); data.error ? reject(new Error(data.error)) : ready({ ...data, child }); });
    child.send(config);
  });
}
try {
  const stageDelayMs = Number(process.env.DUAL_STAGE_DELAY_MS ?? 0);
  if (!Number.isSafeInteger(stageDelayMs) || stageDelayMs < 0 || stageDelayMs > 2000) throw new Error('DUAL_STAGE_DELAY_MS must be an integer between 0 and 2000 milliseconds');
  await mkdir(root, { recursive: true });
  const merchantDirectory = resolve(root, 'merchant');
  const merchantIdentity = await loadMerchantIdentity(merchantDirectory);
  const trustedMerchant = { did: merchantIdentity.did, merchantId: 'mystore', payeeAccount: 'merchant:keyboard' };
  const legacyIssuer = generateIdentity('legacy policy issuer'), holder = generateIdentity('local holder policy'), inactiveDevice = generateIdentity('inactive named-device policy'), verifierIdentity = generateIdentity('Agent B');
  const deviceToken = token(), issuerToken = token(), statusToken = token(), adminToken = token(), proposalToken = token(), ownerKey = token(), uiToken = token();
  const device = await launch('./dbac-role.mjs', { role: 'device', accessToken: deviceToken, port: 0 });
  const issuer = await launch('./dbac-role.mjs', { role: 'issuer', w3c: true, requireHolderProof: true, accessToken: issuerToken, statusToken, statePath: resolve(root, 'credential-status.json'), devicePublicKeys: device.publicKeys, port: 0 });
  const owner = await launch('./owner.mjs', { holderDid: holder.did, verifierDid: verifierIdentity.did, trustedIssuers: [legacyIssuer.did], dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer, proposalToken, uiToken: ownerKey, port: 0 });
  const verifier = await launch('./agent-b.mjs', { identity: serializeIdentity(verifierIdentity), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], adminToken, ledgerPath: resolve(root, 'verifier.sqlite'), port: 0, dbac: { trustedMerchant, issuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c, requireHolderProof: true, statusSource: { baseUrl: issuer.baseUrl, accessToken: statusToken } } });
  environment = await createLocalX402Environment({ stateDir: resolve(root, 'x402'), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], holderDid: holder.did, deviceDid: inactiveDevice.did, verifierDid: verifierIdentity.did, dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer,
    // This entry exposes only the original DBAC/W3C payment path. No legacy VC
    // is issued and its unused policy identity is never a substitute device.
    isCredentialRevoked: async () => true,
    async isDbacCredentialRevoked(bindingId) {
      const response = await fetch(`${issuer.baseUrl}/credential/status`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-DBAC-Access': statusToken }, body: JSON.stringify({ bindingId }), signal: AbortSignal.timeout(3000), redirect: 'error' });
      const status = await response.json();
      if (!response.ok || status.bindingId !== bindingId || !['valid', 'revoked'].includes(status.status)) throw new Error('Credential status cannot be confirmed');
      return status.status === 'revoked';
    },
  });
  await new Promise((ready, reject) => {
    const timer = setTimeout(() => reject(new Error('x402 configuration timeout')), 10000);
    verifier.child.once('message', message => { clearTimeout(timer); message.stage === 'x402-ready' ? ready() : reject(new Error(message.error)); });
    verifier.child.send({ stage: 'configure-x402', backendConfig: environment.backendConfig });
  });
  const actors = { issuer: { pid: issuer.pid, did: issuer.w3c.issuer }, device: { pid: device.pid, type: 'original Node BLS software eSIM' }, verifier: { pid: verifier.pid, did: verifierIdentity.did }, owner: { pid: owner.pid, did: owner.did } };
  const app = await launch('./lib/storefront/live-server-process.mjs', { port: Number(process.env.DUAL_PORT ?? 4384), stageDelayMs, uiToken, adminToken, actors, merchant: { directory: merchantDirectory, trusted: trustedMerchant }, verifierUrl: verifier.baseUrl, verifierDid: verifierIdentity.did, payerConfig: environment.payerConfig, owner: { baseUrl: owner.baseUrl, did: owner.did, proposalToken }, orderDirectory: resolve(root, 'orders'), eventDirectory: resolve(root, 'events'), dbac: { issuer: { publicKey: issuer.publicKey, w3c: issuer.w3c, baseUrl: issuer.baseUrl, accessToken: issuerToken }, device: { publicKeys: device.publicKeys, baseUrl: device.baseUrl, accessToken: deviceToken } } });
  await writeFile(metadataPath, JSON.stringify({ baseUrl: app.baseUrl, url: `${app.baseUrl}/demo/#key=${uiToken}&ownerKey=${ownerKey}`, pid: process.pid, children: children.map(child => child.pid), startedAt: new Date().toISOString(), stateDirectory: root, stageDelayMs }, null, 2), { mode: 0o600 });
  console.log(`Shopping + original mechanism live view ready at ${app.baseUrl}\nLocal software eSIM and original x402 simulated payment. No external payment account required.`);
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
} catch (error) { console.error(error.stack); await stop(); process.exitCode = 1; }
