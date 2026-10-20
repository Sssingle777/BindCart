import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateIdentity, signJws } from '../lib/identity.mjs';
import { digest, unix } from '../lib/protocol.mjs';
import { generateIssuerKey, generateDeviceKey, issueCredential, createPaymentBinding, signDeviceRequest } from '../lib/dbac/crypto.mjs';
import { DBAC_EXTENSION, DBAC_MODES, DBAC_SCHEMA, paymentAttributes, paymentDisclosures } from '../lib/dbac/policy.mjs';
import { createDbacPaymentManual } from '../lib/dbac/payment-manual.mjs';
import { DBAC_PAYMENT_RESPONSE_TYP, issueDbacPaymentAuthorization } from '../lib/dbac/payment-policy.mjs';

function fixture() {
  const issuerKey = generateIssuerKey(), b = generateIdentity('B'), owner = generateIdentity('Owner');
  const devices = Object.fromEntries(DBAC_MODES.map(mode => [mode, generateDeviceKey()]));
  const entries = Object.fromEntries(DBAC_MODES.map(mode => {
    const payment = { orderId: randomUUID(), payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 100, currency: 'CNY' };
    const credential = issueCredential({ issuerSecretKey: issuerKey.secretKey, devicePublicKey: devices[mode].publicKey, attributes: paymentAttributes(mode) });
    return [mode, { mode, order: payment, credential, binding: createPaymentBinding({ credential, mode, orderId: payment.orderId }), orderKey: null, proposal: null, authorization: null }];
  }));
  let signatures = 0, transportCalls = 0, nextHealth = null, nextChallenge = null, transport = null, wallet = null;
  const api = createDbacPaymentManual({
    entry: mode => entries[mode], requireCredential: e => e.credential,
    async challengeFor(rawBody, mode, orderId) {
      if (nextChallenge) { const gate = nextChallenge; nextChallenge = null; await gate; }
      return { profile: DBAC_EXTENSION, purpose: 'dbac-payment-v1', scope: 'payments:pay', mode, verifier: b.did, target: 'http://127.0.0.1:4567/dbac/payment/a2a', method: 'POST', bodyHash: digest(rawBody), paymentOrderId: orderId, challengeId: randomUUID(), nonce: randomBytes(32).toString('base64url'), iat: unix(), exp: unix() + 60, schema: [...DBAC_SCHEMA], requiredDisclosures: paymentDisclosures(mode) };
    },
    async deviceRequest(path, request) { assert.equal(path, '/sign'); signatures++; return signDeviceRequest({ deviceSecretKey: devices[request.mode].secretKey, request }); },
    async deviceHealth() {
      if (nextHealth) { const gate = nextHealth; nextHealth = null; await gate; }
      return { backend: 'node-bls12-381', hardware: false, keyExportable: false, publicKeys: Object.fromEntries(DBAC_MODES.map(mode => [mode, devices[mode].publicKey])), modes: Object.fromEntries(DBAC_MODES.map(mode => [mode, { locked: false, signatures }])) };
    },
    async transmit(prepared) { transportCalls++; if (transport) return transport(prepared); throw Object.assign(new Error('Missing proof fixture'), { code: 'DBAC_INVALID_ENVELOPE' }); },
    ownerRequest() { assert.fail('This core test never submits an Owner request.'); }, acceptProposal() {}, syncOwner() {},
    issuer: { publicKey: issuerKey.publicKey }, verifierDid: b.did, owner, x402Payer: { createPayload: input => wallet(input) },
    state: async ({ mode }) => ({ manual: await api.snapshot(entries[mode]) }),
  });
  return { api, entries, signatures: () => signatures, transportCalls: () => transportCalls,
    approve(mode) { const e = entries[mode]; e.authorization = { token: issueDbacPaymentAuthorization(owner, { verifierDid: b.did, mode, issuerPublicKey: issuerKey.publicKey, orderKey: e.orderKey, payment: e.order }) }; },
    usePendingResponses() { transport = prepared => ({ task: { kind: 'task', id: 'fixture-task', contextId: 'fixture-context', status: { state: prepared.phase === 'authorize' ? 'input-required' : 'working', message: { metadata: { 'x402.payment.required': { accepts: [] } } } } }, responseEvidence: { proof: signJws({ exp: unix() + 60 }, b, DBAC_PAYMENT_RESPONSE_TYP) } }); },
    setWallet(action) { wallet = action; },
    delayNextHealth(value) { nextHealth = value; }, delayNextChallenge(value) { nextChallenge = value; } };
}

test('manual expiry requires an explicit new challenge and never silently repeats a device signature', async t => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const f = fixture(), mode = 'bbs-bls';
  const begun = (await f.api.act({ mode, action: 'begin-proposal' })).manual;
  assert.equal(begun.stage, 'CHALLENGE_READY');
  assert.equal(f.signatures(), 0);
  await assert.rejects(f.api.act({ mode, action: 'device-sign' }), { code: 'DBAC_MANUAL_ATTEMPT_MISMATCH' });
  const wrong = (await f.api.act({ mode, action: 'test-wrong-device', attemptId: begun.attemptId })).manual;
  assert.equal(wrong.lastAttack.actual, 'DBAC_DEVICE_SIGNATURE_INVALID');
  assert.equal(wrong.lastAttack.source, 'agent-a');
  assert.equal(wrong.lastAttack.verificationTrace.source, 'agent-a');
  assert.equal(wrong.stage, 'CHALLENGE_READY');
  assert.equal(f.signatures(), 0);
  const signed = (await f.api.act({ mode, action: 'device-sign', attemptId: begun.attemptId })).manual;
  assert.equal(signed.stage, 'DEVICE_SIGNED');
  assert.equal(signed.lastAttack, null);
  assert.equal(f.signatures(), 1);
  const proved = (await f.api.act({ mode, action: 'prove', attemptId: begun.attemptId })).manual;
  assert.equal(proved.stage, 'PROOF_READY');
  assert.ok(proved.presentation);
  assert.equal(f.transportCalls(), 0);
  t.mock.timers.tick(61000);
  const stale = await f.api.snapshot(f.entries[mode]);
  assert.equal(stale.expired, true);
  assert.equal(stale.stage, 'EXPIRED');
  assert.ok(stale.availableActions.includes('begin-proposal'));
  assert.ok(!stale.availableActions.includes('verify'));
  await assert.rejects(f.api.act({ mode, action: 'verify', attemptId: begun.attemptId }), { code: 'DBAC_CHALLENGE_EXPIRED' });
  assert.equal(f.transportCalls(), 0);
  const refreshed = (await f.api.act({ mode, action: 'begin-proposal', attemptId: begun.attemptId })).manual;
  assert.notEqual(refreshed.attemptId, begun.attemptId);
  assert.equal(refreshed.stage, 'CHALLENGE_READY');
  assert.equal(refreshed.deviceResponse, null);
  assert.equal(refreshed.presentation, null);
  assert.equal(f.signatures(), 1);
  await assert.rejects(f.api.act({ mode, action: 'discard', attemptId: begun.attemptId }), { code: 'DBAC_MANUAL_ATTEMPT_MISMATCH' });
  assert.throws(() => f.api.guard(f.entries[mode]), { code: 'DBAC_MANUAL_ACTIVE' });
  await f.api.act({ mode, action: 'discard', attemptId: refreshed.attemptId });
  f.api.guard(f.entries[mode]);
});

async function authorizeFixture(f) {
  const mode = 'bbs-bls';
  let current = (await f.api.act({ mode, action: 'begin-proposal' })).manual;
  for (const action of ['device-sign', 'prove', 'discard']) current = (await f.api.act({ mode, action, attemptId: current.attemptId })).manual;
  f.approve(mode); f.usePendingResponses();
  current = (await f.api.act({ mode, action: 'begin-authorize', attemptId: current.attemptId })).manual;
  for (const action of ['device-sign', 'prove', 'verify']) current = (await f.api.act({ mode, action, attemptId: current.attemptId })).manual;
  return current;
}

test('an unknown wallet-sign response preserves the original order even after explicit discard', async () => {
  const f = fixture(), mode = 'bbs-bls', current = await authorizeFixture(f);
  f.setWallet(() => { throw Object.assign(new Error('Wallet connection lost after request'), { code: 'DBAC_PAYMENT_TRANSPORT' }); });
  await assert.rejects(f.api.act({ mode, action: 'wallet-sign', attemptId: current.attemptId }), { code: 'DBAC_PAYMENT_TRANSPORT' });
  const uncertain = await f.api.snapshot(f.entries[mode]);
  assert.equal(uncertain.stage, 'VERIFIED');
  assert.equal(uncertain.walletSigningUnconfirmed, true);
  assert.equal(uncertain.walletSigned, false);
  await f.api.act({ mode, action: 'discard', attemptId: current.attemptId });
  assert.throws(() => f.api.guard(f.entries[mode]), { code: 'DBAC_PAYMENT_PENDING' });
  assert.ok((await f.api.snapshot(f.entries[mode])).availableActions.includes('begin-authorize'));
});

test('a working settlement gate cannot be presented as a completed payment', async () => {
  const f = fixture(), mode = 'bbs-bls';
  let current = await authorizeFixture(f);
  f.setWallet(() => ({ signature: 'fixture-existing-wallet-payload' }));
  current = (await f.api.act({ mode, action: 'wallet-sign', attemptId: current.attemptId })).manual;
  current = (await f.api.act({ mode, action: 'begin-settle', attemptId: current.attemptId })).manual;
  for (const action of ['device-sign', 'prove']) current = (await f.api.act({ mode, action, attemptId: current.attemptId })).manual;
  await assert.rejects(f.api.act({ mode, action: 'verify', attemptId: current.attemptId }), { code: 'DBAC_PAYMENT_RECEIPT_INVALID' });
  const unconfirmed = await f.api.snapshot(f.entries[mode]);
  assert.equal(unconfirmed.settled, false);
  assert.equal(unconfirmed.walletSigned, true);
  assert.equal(unconfirmed.stage, 'PROOF_READY');
  await f.api.act({ mode, action: 'discard', attemptId: current.attemptId });
  assert.throws(() => f.api.guard(f.entries[mode]), { code: 'DBAC_PAYMENT_PENDING' });
});

test('manual attempts are mode-isolated and direct concurrent actions fail closed', async () => {
  const f = fixture();
  let release;
  f.delayNextChallenge(new Promise(resolve => { release = resolve; }));
  const pending = f.api.act({ mode: 'bbs-bls', action: 'begin-proposal' });
  await assert.rejects(f.api.act({ mode: 'bbs-bls', action: 'begin-proposal' }), { code: 'DBAC_MANUAL_BUSY' });
  release();
  const first = (await pending).manual;
  await assert.rejects(f.api.act({ mode: 'bbs-blind-bls', action: 'begin-proposal', attemptId: first.attemptId }), { code: 'DBAC_MANUAL_ATTEMPT_MISMATCH' });
  const second = (await f.api.act({ mode: 'bbs-blind-bls', action: 'begin-proposal' })).manual;
  assert.notEqual(first.attemptId, second.attemptId);
  assert.equal((await f.api.snapshot(f.entries['bbs-bls'])).attemptId, first.attemptId);
  assert.equal(f.signatures(), 0);
});

test('a slow device health read snapshots the current attempt after a replacement', async () => {
  const f = fixture(), mode = 'bbs-bls';
  const first = (await f.api.act({ mode, action: 'begin-proposal' })).manual;
  let release;
  f.delayNextHealth(new Promise(resolve => { release = resolve; }));
  const staleRead = f.api.snapshot(f.entries[mode]);
  const current = (await f.api.act({ mode, action: 'begin-proposal', attemptId: first.attemptId })).manual;
  release();
  const returned = await staleRead;
  assert.equal(returned.attemptId, current.attemptId);
  assert.equal(returned.challenge.challengeId, current.challenge.challengeId);
  assert.deepEqual(returned.log, current.log);
  assert.equal(f.signatures(), 0);
});
