import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { generateIdentity, issueCredential, signJws, verifyJws } from '../lib/identity.mjs';
import { createVerifier } from '../lib/verifier.mjs';
import { createLocalX402Environment, createX402Backend, createX402Payer, paymentSettlement } from '../lib/x402-payment.mjs';
import { issuePaymentAuthorization, PAYMENT_SCOPE, paymentRpc } from '../lib/payment.mjs';
import { prepareRequest, transmit, POP_TYP, DEVICE_POP_TYP, digest } from '../lib/protocol.mjs';

test('wallet checks live B revocation before releasing payment signatures and submitting settlement', { timeout: 90_000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'a2a-x402-revocation-'));
  const issuer = generateIdentity('revocation issuer'), owner = generateIdentity('revocation owner');
  const holder = generateIdentity('revocation holder'), verifier = generateIdentity('revocation B');
  // This test targets B-attestation and wallet-status boundaries; the separate
  // Java Card suite covers actual APDU transport to the simulated P-256 applet.
  const device = generateIdentity('independent device signature fixture');
  const adminToken = randomUUID();
  let server, environment, statusOverride, statusCalls = 0;
  const statusIds = [];
  t.after(async () => {
    try { await server?.close(); await environment?.close(); }
    finally { await rm(directory, { recursive: true, force: true }); }
  });
  server = createVerifier({ identity: verifier, trustedIssuers: [issuer.did], trustedAuthorizers: [owner.did], adminToken, requireX402: true });
  const baseUrl = await server.listen();
  const config = {
    stateDir: directory, trustedIssuers: [issuer.did], trustedAuthorizers: [owner.did],
    holderDid: holder.did, deviceDid: device.did, verifierDid: verifier.did,
    async isCredentialRevoked(id) {
      statusCalls++;
      statusIds.push(id);
      if (statusOverride) return statusOverride(id, statusCalls);
      const response = await fetch(`${baseUrl}/admin/credential-status?id=${encodeURIComponent(id)}`, {
        headers: { 'X-Demo-Admin': adminToken }, signal: AbortSignal.timeout(3000), redirect: 'error',
      });
      const state = await response.json();
      if (!response.ok || state.id !== id || typeof state.revoked !== 'boolean') throw new Error('B status unavailable');
      return state.revoked;
    },
  };
  environment = await createLocalX402Environment(config);
  const backend = createX402Backend(environment.backendConfig), payer = createX402Payer(environment.payerConfig);
  server.setPaymentBackend(backend);
  const initial = await backend.snapshot();
  const resetStatus = override => { statusOverride = override; statusCalls = 0; statusIds.length = 0; };
  async function prepared(credential, payment, authorization) {
    const request = await prepareRequest({ identity: holder, verifierDid: verifier.did, baseUrl, credential, rpc: paymentRpc(payment, authorization) });
    const p = verifyJws(request.token, { typ: POP_TYP }).payload;
    const claims = {
      iss: device.did, sub: p.iss, aud: p.aud, iat: p.iat, exp: p.exp, jti: randomUUID(),
      holderProofHash: digest(request.token), credentialHash: digest(credential),
    };
    for (const field of ['challengeId', 'nonce', 'method', 'target', 'bodyHash']) claims[field] = p[field];
    return { ...request, deviceDid: device.did, deviceProof: signJws(claims, device, DEVICE_POP_TYP) };
  }
  async function sample() {
    const credential = issueCredential(issuer, { subjectDid: holder.did, deviceDid: device.did, audience: verifier.did, scopes: [PAYMENT_SCOPE] });
    const credentialId = verifyJws(credential, { typ: 'vc+jwt', purpose: 'assertionMethod' }).payload.id;
    const payment = {
      orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard',
      amountMinor: 2_990_000, currency: 'TEST_USDC', settlement: paymentSettlement(environment.publicInfo),
    };
    const authorization = issuePaymentAuthorization(owner, { holderDid: holder.did, deviceDid: device.did, verifierDid: verifier.did, credential, payment });
    const response = await transmit(await prepared(credential, payment, authorization));
    assert.equal(response.task.status.state, 'input-required');
    return { credentialId, input: { credential, payment, authorization, paymentRequired: response.task.status.message.metadata['x402.payment.required'], ...response.responseEvidence } };
  }
  async function revoke(id) {
    const response = await fetch(`${baseUrl}/admin/revoke`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Demo-Admin': adminToken }, body: JSON.stringify({ id }),
    });
    assert.equal(response.status, 200);
  }
  function signedOrderCount(orderId) {
    // Read only this test's temporary journal, never the user's wallet file.
    const db = new DatabaseSync(join(directory, 'payments.sqlite'), { readOnly: true });
    try { return db.prepare('SELECT COUNT(*) AS n FROM x402_orders WHERE order_id=?').get(orderId).n; }
    finally { db.close(); }
  }

  await t.test('missing live-status provider is a configuration failure', async () => {
    await assert.rejects(createLocalX402Environment({ ...config, isCredentialRevoked: undefined }), { code: 'INVALID_X402_CONFIGURATION' });
  });

  await t.test('a fresh authentic B attestation cannot create a signature after VC revocation', async () => {
    resetStatus();
    const { credentialId, input } = await sample();
    await revoke(credentialId);
    await assert.rejects(transmit(await prepared(input.credential, input.payment, input.authorization)), { code: 'CREDENTIAL_REVOKED' });
    await assert.rejects(payer.createPayload(input), { code: 'CREDENTIAL_REVOKED' });
    assert.deepEqual(statusIds, [credentialId]);
    assert.equal(signedOrderCount(input.payment.orderId), 0);
  });

  await t.test('revocation detected after signing prevents both release and persistence of the payload', async () => {
    const { credentialId, input } = await sample();
    resetStatus((id, count) => { assert.equal(id, credentialId); return count >= 2; });
    await assert.rejects(payer.createPayload(input), { code: 'CREDENTIAL_REVOKED' });
    assert.equal(statusCalls, 2);
    assert.equal(signedOrderCount(input.payment.orderId), 0);
  });

  await t.test('unavailable or ambiguous status fails closed at the first check', async () => {
    for (const answer of [null, undefined, 'false', { revoked: false }, new Error('status service offline')]) {
      const { input } = await sample();
      resetStatus(() => { if (answer instanceof Error) throw answer; return answer; });
      await assert.rejects(payer.createPayload(input), { code: 'STATUS_UNAVAILABLE' });
      assert.equal(signedOrderCount(input.payment.orderId), 0);
    }
  });

  await t.test('a status outage after signing still returns no payment signature', async () => {
    const { input } = await sample();
    resetStatus((id, count) => { if (count === 2) throw new Error('status unavailable after signing'); return false; });
    await assert.rejects(payer.createPayload(input), { code: 'STATUS_UNAVAILABLE' });
    assert.equal(statusCalls, 2);
    assert.equal(signedOrderCount(input.payment.orderId), 0);
  });

  await t.test('revoked credentials cannot retrieve a previously cached payload', async () => {
    resetStatus();
    const { credentialId, input } = await sample();
    const payload = await payer.createPayload(input);
    assert.match(payload.payload.signature, /^0x[0-9a-f]+$/i);
    assert.equal(statusCalls, 2);
    await revoke(credentialId);
    resetStatus();
    await assert.rejects(payer.createPayload(input), { code: 'CREDENTIAL_REVOKED' });
    await assert.rejects(backend.execute({ ...input, payload }), { code: 'CREDENTIAL_REVOKED' });
  });

  await t.test('revocation detected after facilitator verification stops transaction submission', async () => {
    resetStatus();
    const { input } = await sample();
    const payload = await payer.createPayload(input);
    resetStatus((id, count) => count >= 2);
    await assert.rejects(backend.execute({ ...input, payload }), { code: 'CREDENTIAL_REVOKED' });
    assert.equal(statusCalls, 2);
    const after = await backend.snapshot();
    assert.deepEqual(after.accounts, initial.accounts);
    assert.equal(after.executionCount, 0);
  });

  await t.test('status outage immediately before settlement fails closed without a transfer', async () => {
    resetStatus();
    const { input } = await sample();
    const payload = await payer.createPayload(input);
    resetStatus((id, count) => { if (count === 2) throw new Error('status offline before broadcast'); return false; });
    await assert.rejects(backend.execute({ ...input, payload }), { code: 'STATUS_UNAVAILABLE' });
    assert.equal(statusCalls, 2);
    const after = await backend.snapshot();
    assert.deepEqual(after.accounts, initial.accounts);
    assert.equal(after.executionCount, 0);
  });
});
