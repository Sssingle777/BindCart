import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { generateIdentity } from '../identity.mjs';
import { serializeIdentity } from '../protocol.mjs';

// The same agent-a / agent-b implementations used by npm start, configured
// without the identified wallet/Owner/payment profile for paper-only demos.
export async function startDbacDemo({ aPort = 0, bPort = 0 } = {}) {
  const children = [];
  let closing = false;
  const token = () => randomBytes(32).toString('base64url');
  async function close() {
    if (closing) return;
    closing = true;
    const waits = children.map(child => child.exitCode === null && child.signalCode === null ? once(child, 'exit').catch(() => {}) : Promise.resolve());
    for (const child of children) if (child.exitCode === null) child.kill('SIGTERM');
    const timer = setTimeout(() => { for (const child of children) if (child.exitCode === null) child.kill('SIGKILL'); }, 2000);
    timer.unref();
    await Promise.all(waits); clearTimeout(timer);
  }
  function launch(file, config) {
    return new Promise((resolve, reject) => {
      const child = fork(new URL(`../../${file}`, import.meta.url), [], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
      children.push(child);
      let diagnostics = '';
      child.stderr.on('data', data => { diagnostics = (diagnostics + data).slice(-3000); });
      const timer = setTimeout(() => reject(new Error(`${file}: readiness timed out`)), 30000);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('exit', code => { clearTimeout(timer); if (!closing) { reject(new Error(`${file} exited ${code}: ${diagnostics}`)); void close(); } });
      child.once('message', value => { clearTimeout(timer); value.error ? reject(new Error(`${file}: ${value.error}`)) : resolve(value); });
      child.send(config);
    });
  }
  try {
    const deviceToken = token(), issuerToken = token(), uiToken = token();
    const device = await launch('dbac-role.mjs', { role: 'device', accessToken: deviceToken, port: 0 });
    const issuer = await launch('dbac-role.mjs', { role: 'issuer', accessToken: issuerToken, devicePublicKeys: device.publicKeys, port: 0 });
    const bIdentity = generateIdentity('DBAC verifier / Agent B');
    const b = await launch('agent-b.mjs', { dbacOnly: true, identity: serializeIdentity(bIdentity), trustedIssuers: [], trustedAuthorizers: [], adminToken: token(), ledgerPath: ':memory:', port: bPort, dbac: { issuerPublicKey: issuer.publicKey } });
    const profile = { issuer: { baseUrl: issuer.baseUrl, publicKey: issuer.publicKey, accessToken: issuerToken }, device: { baseUrl: device.baseUrl, publicKeys: device.publicKeys, accessToken: deviceToken } };
    const a = await launch('agent-a.mjs', { dbacOnly: true, uiToken, verifierDid: bIdentity.did, baseUrl: b.baseUrl, port: aPort, dbac: profile });
    return { a, b, issuer, device, verifierDid: bIdentity.did, uiToken, profile, close, pids: children.map(child => child.pid) };
  } catch (error) { await close(); throw error; }
}
