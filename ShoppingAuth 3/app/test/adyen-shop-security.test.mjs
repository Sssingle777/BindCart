import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { fork } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createDbacDevice, createDbacIssuer } from '../lib/dbac/services.mjs';
import { generateIdentity } from '../lib/identity.mjs';
import { createShopHolder, createShopVerifier, verifyShopPermit, SHOP_ORIGIN } from '../lib/adyen-shop/credentials.mjs';

const token = () => randomBytes(32).toString('base64url');
test('MyStore gate enforces actual W3C, device, holder, order and owner checks', async t => {
  const deviceToken = token(), issuerToken = token(), statusToken = token(), ownerKey = token();
  const device = createDbacDevice({ accessToken: deviceToken });
  const deviceUrl = await device.listen(0);
  const issuer = createDbacIssuer({ accessToken: issuerToken, statusToken, w3c: true, requireHolderProof: true, devicePublicKeys: device.publicInfo().publicKeys });
  const issuerUrl = await issuer.listen(0);
  t.after(async () => { await device.close(); await issuer.close(); });
  const issuerInfo = { ...issuer.publicInfo(), baseUrl: issuerUrl, accessToken: issuerToken };
  const identity = generateIdentity('test shop verifier');
  const holder = createShopHolder({ issuer: issuerInfo, device: { ...device.publicInfo(), baseUrl: deviceUrl, accessToken: deviceToken }, verifierDid: identity.did });
  const verifier = createShopVerifier({ identity, issuer: issuerInfo, statusSource: { baseUrl: issuerUrl, accessToken: statusToken }, ownerKey });
  await holder.issue();
  const order = () => ({ id: `urn:uuid:${randomUUID()}`, provider: 'adyen-mystore', origin: SHOP_ORIGIN, productId: '02', productName: 'Headphones', quantity: 1, amountMinor: 1999, currency: 'EUR', providerReference: 'official-test-reference' });
  async function proof(terms = order(), options) { return holder.prove(verifier.challenge(terms).context, terms, options); }
  await t.test('valid proof and explicit owner confirmation issue an exact-order permit', async () => {
    const prepared = await proof();
    const receipt = await verifier.verify(prepared);
    assert.equal(receipt.accepted, true);
    assert.equal(receipt.steps.length, 6);
    assert.throws(() => verifier.approve({ order: prepared.order, receipt: receipt.receipt, suppliedOwnerKey: 'missing' }), { code: 'OWNER_CONFIRMATION_REQUIRED' });
    const { permit } = verifier.approve({ order: prepared.order, receipt: receipt.receipt, suppliedOwnerKey: ownerKey });
    assert.equal(verifyShopPermit(permit, prepared.order, identity.did).testOnly, true);
    assert.throws(() => verifyShopPermit(permit, { ...prepared.order, amountMinor: 2000 }, identity.did), { code: 'SHOP_PERMIT_INVALID' });
    assert.throws(() => verifier.approve({ order: { ...prepared.order, providerReference: 'other-order' }, receipt: receipt.receipt, suppliedOwnerKey: ownerKey }), { code: 'SHOP_APPROVAL_MISMATCH' });
  });
  await t.test('copied valid VC without device possession is rejected', async () => {
    await assert.rejects(() => proof(undefined, { omitDevice: true }).then(value => verifier.verify(value)), { code: 'W3C_DEVICE_PROOF_REQUIRED' });
  });
  await t.test('a valid device proof cannot replace the holder signature', async () => {
    await assert.rejects(() => proof(undefined, { omitHolder: true }).then(value => verifier.verify(value)), { code: 'HOLDER_PROOF_REQUIRED' });
  });
  await t.test('changing amount after producing a proof is rejected', async () => {
    const prepared = await proof(); prepared.order.amountMinor++;
    await assert.rejects(() => verifier.verify(prepared), { code: 'SHOP_ORDER_CHANGED' });
  });
  await t.test('tampered standard VC fails real BBS verification', async () => {
    const prepared = await proof(); prepared.verifiableCredential.credentialSubject.scope = 'administrator';
    await assert.rejects(() => verifier.verify(prepared));
  });
  await t.test('old proof cannot be transplanted to a new challenge', async () => {
    const prepared = await proof(); prepared.challengeId = verifier.challenge(prepared.order).context.challengeId;
    await assert.rejects(() => verifier.verify(prepared));
  });
  await t.test('concurrent submission consumes a challenge exactly once', async () => {
    const prepared = await proof();
    const results = await Promise.allSettled([verifier.verify(prepared), verifier.verify(structuredClone(prepared))]);
    assert.equal(results.filter(x => x.status === 'fulfilled').length, 1);
    assert.equal(results.find(x => x.status === 'rejected').reason.code, 'SHOP_REPLAY');
    await assert.rejects(() => verifier.verify(prepared), { code: 'SHOP_REPLAY' });
  });
  await t.test('revocation blocks an otherwise valid pending proof', async () => {
    const prepared = await proof();
    await holder.revoke();
    await assert.rejects(() => verifier.verify(prepared), { code: 'W3C_CREDENTIAL_REVOKED' });
    await holder.issue();
  });
  await t.test('locked software eSIM cannot produce a fresh use proof', async () => {
    await holder.lock(true);
    try { await assert.rejects(() => proof(), { code: 'DBAC_DEVICE_LOCKED' }); }
    finally { await holder.lock(false); }
  });
  await t.test('unexpected merchant and currency cannot enter the demo', () => {
    assert.throws(() => verifier.challenge({ ...order(), currency: 'USD' }), { code: 'SHOP_ORDER_INVALID' });
    assert.throws(() => verifier.challenge({ ...order(), origin: 'https://example.com' }), { code: 'SHOP_ORDER_INVALID' });
  });
  await t.test('a restart preserves an unresolved payment and refuses a new cart', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'adyen-shop-recovery-'));
    const pending = { phase: 'paying', order: order(), result: null, verification: { accepted: true } };
    await writeFile(join(directory, 'latest-order.json'), JSON.stringify(pending));
    const uiToken = token();
    const child = fork(new URL('../lib/adyen-shop/server-process.mjs', import.meta.url), [], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    try {
      const ready = new Promise((resolveReady, reject) => {
        const timeout = setTimeout(() => reject(new Error('Recovery server timed out')), 15000);
        child.once('error', error => { clearTimeout(timeout); reject(error); });
        child.once('message', value => { clearTimeout(timeout); value.error ? reject(new Error(value.error)) : resolveReady(value); });
      });
      child.send({ port: 0, evidenceDir: directory, uiToken, actors: {}, issuer: issuerInfo, device: { ...device.publicInfo(), baseUrl: deviceUrl, accessToken: deviceToken }, verifierDid: identity.did });
      const { baseUrl } = await ready;
      const headers = { 'X-Demo-UI-Key': uiToken, 'Content-Type': 'application/json' };
      const recovered = await fetch(`${baseUrl}/api/adyen/state`, { headers }).then(r => r.json());
      assert.equal(recovered.phase, 'unknown'); assert.equal(recovered.order.id, pending.order.id);
      const blocked = await fetch(`${baseUrl}/api/adyen/connect`, { method: 'POST', headers, body: '{}' });
      assert.equal(blocked.status, 409); assert.equal((await blocked.json()).error.code, 'SHOP_OUTCOME_UNRESOLVED');
    } finally {
      if (child.exitCode === null) {
        const closed = new Promise(resolveClosed => child.once('exit', resolveClosed));
        child.kill(); await closed;
      }
      if (resolve(directory).startsWith(`${resolve(tmpdir())}\\adyen-shop-recovery-`) || resolve(directory).startsWith(`${resolve(tmpdir())}/adyen-shop-recovery-`)) await rm(directory, { recursive: true, force: true });
    }
  });
});
