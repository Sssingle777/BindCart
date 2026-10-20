import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { generateIdentity } from '../../lib/identity.mjs';
import { sendJson } from '../../lib/protocol.mjs';
import { createDbacDevice, createDbacIssuer } from '../../lib/dbac/services.mjs';
import { createDbacPaymentVerifier } from '../../lib/dbac/payment-verifier.mjs';
import { createDbacPaymentSession } from '../../lib/dbac/payment-session.mjs';

const capability = () => randomBytes(32).toString('base64url');
const address = n => `0x${n.repeat(40)}`;

// Actual issuer, BBS/Ed25519/BLS operations, HTTP transports and production B.
// No payer backend is installed: these authentication scenarios cannot submit
// payments. Existing x402 suites separately cover real test-chain settlement.
export async function frameworkFixture(t, options = {}) {
  const deviceToken = capability(), issuerToken = capability(), statusToken = capability();
  const deviceService = createDbacDevice({ accessToken: deviceToken });
  const deviceUrl = await deviceService.listen();
  t.after(() => deviceService.close());
  const issuerService = createDbacIssuer({ accessToken: issuerToken, statusToken, devicePublicKeys: deviceService.publicInfo().publicKeys, w3c: true, requireHolderProof: true });
  const issuerUrl = await issuerService.listen();
  t.after(() => issuerService.close());
  const issuer = { ...issuerService.publicInfo(), baseUrl: issuerUrl, accessToken: issuerToken };
  const device = { ...deviceService.publicInfo(), baseUrl: deviceUrl, accessToken: deviceToken };
  const identity = generateIdentity('Framework test verifier'), owner = generateIdentity('Unused test Owner');
  const verifier = createDbacPaymentVerifier({ identity, issuerPublicKey: issuer.publicKey, trustedAuthorizers: [owner.did], w3cIssuer: issuer.w3c, requireHolderProof: true, statusSource: { baseUrl: issuerUrl, accessToken: statusToken }, getBackend: options.getBackend ?? (() => null) });
  let baseUrl;
  const server = http.createServer({ maxHeaderSize: 24 * 1024 }, async (req, res) => {
    try { if (!await verifier.handle(req, res, baseUrl)) sendJson(res, 404, { error: { code: 'NOT_FOUND' } }); }
    catch (error) { sendJson(res, error.status ?? 400, { error: { code: error.code, message: error.message }, verificationTrace: error.verificationTrace }); }
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const ledger = { executionCount: 0, accounts: [{ id: 'demo:alice', balanceMinor: 10000000 }, { id: 'merchant:keyboard', balanceMinor: 0 }] };
  const session = createDbacPaymentSession({ baseUrl, verifierDid: identity.did, issuer, device, owner: { did: owner.did, baseUrl: 'http://127.0.0.1:1', proposalToken: capability() }, x402Payer: options.x402Payer ?? { createPayload: () => assert.fail('Authentication experiments may not request wallet signatures') }, paymentInfo: options.paymentInfo ?? { network: 'eip155:31337', asset: address('1'), payerAddress: address('2'), payees: { 'merchant:keyboard': address('3'), 'merchant:other': address('4') } }, getLedger: options.getLedger ?? (async () => structuredClone(ledger)) });
  return { session, deviceService, issuerService, issuer, device, ledger, baseUrl, verifier, identity, owner, issuerToken, deviceToken, statusToken };
}

