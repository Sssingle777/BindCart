import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { generateIdentity } from '../lib/identity.mjs';
import { AppError } from '../lib/protocol.mjs';
import { createLocalX402Environment, createX402Backend, createX402Payer } from '../lib/x402-payment.mjs';
import { DBAC_PAYMENT_PROFILE, issueDbacPaymentAuthorization, credentialBindingOf } from '../lib/dbac/payment-policy.mjs';
import { frameworkFixture } from './fixtures/framework.mjs';

test('W3C wallet rechecks issuer status after real B authorization and before real local-chain settlement', { timeout: 120000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'framework-wallet-status-'));
  let environment, backend, payer, captureSettlement = false, capturedSettlement, statusOverride, statusCalls = 0;
  const paymentInfo = {};
  const evidenceLengths = [];
  const measureEvidence = (phase, evidence) => { const bytes = Buffer.byteLength(evidence.proof); evidenceLengths.push({ phase, bytes }); assert.ok(bytes < 15360, `${phase} response evidence must leave space for HTTP headers below the 16 KiB client budget`); };
  const f = await frameworkFixture(t, { paymentInfo, getLedger: () => backend.snapshot(), getBackend: () => ({
    requirements: (...args) => backend.requirements(...args),
    async execute(input) {
      // Pause only the external payment boundary. B has already run real BBS,
      // holder, device, status and Owner checks and produced authentic evidence.
      if (captureSettlement) { capturedSettlement = input; throw new AppError('TEST_SETTLEMENT_HELD', 'Test pauses before wallet submission.', 503); }
      return backend.execute(input);
    },
  }) });
  t.after(async () => { try { await environment?.close(); } finally { await rm(directory, { recursive: true, force: true }); } });
  const legacyIssuer = generateIdentity('Unused named issuer'), legacyHolder = generateIdentity('Unused named holder'), legacyDevice = generateIdentity('Unused named device');
  async function liveStatus(bindingId) {
    statusCalls++;
    if (statusOverride) return statusOverride(bindingId, statusCalls);
    const response = await fetch(`${f.issuer.baseUrl}/credential/status`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-DBAC-Access': f.statusToken }, body: JSON.stringify({ bindingId }), signal: AbortSignal.timeout(3000) });
    const status = await response.json();
    if (!response.ok || status.bindingId !== bindingId || !['valid', 'revoked'].includes(status.status)) throw new Error('Trusted issuer status unavailable or unknown');
    return status.status === 'revoked';
  }
  environment = await createLocalX402Environment({ stateDir: directory, trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [f.owner.did], holderDid: legacyHolder.did, deviceDid: legacyDevice.did,
    verifierDid: f.identity.did, dbacIssuerPublicKey: f.issuer.publicKey, w3cIssuer: f.issuer.w3c.issuer, isCredentialRevoked: async () => false, isDbacCredentialRevoked: liveStatus });
  backend = createX402Backend(environment.backendConfig); payer = createX402Payer(environment.payerConfig);
  Object.assign(paymentInfo, environment.publicInfo);
  const initial = await backend.snapshot();
  const reset = override => { statusOverride = override; statusCalls = 0; };
  async function sample(mode = 'bbs-bls') {
    reset();
    await f.session.newOrder({ mode }); await f.session.issue({ mode });
    const state = await f.session.state({ mode });
    const proposal = await f.session.transmit(await f.session.prepare({ mode, phase: 'proposal' }));
    const authorization = issueDbacPaymentAuthorization(f.owner, { verifierDid: f.identity.did, issuerPublicKey: f.issuer.publicKey, mode, orderKey: proposal.gate.orderKey, payment: state.order, credentialBinding: credentialBindingOf(proposal.gate) });
    const authorized = await f.session.transmit(await f.session.prepare({ mode, phase: 'authorize', authorization }));
    assert.equal(authorized.task.status.state, 'input-required');
    measureEvidence('proposal', proposal.responseEvidence); measureEvidence('authorize', authorized.responseEvidence);
    for (const step of ['w3c_bbs', 'holder_signature', 'device_pairing', 'credential_status', 'owner_authorization']) assert.equal(authorized.verificationTrace.steps.find(value => value.id === step).status, 'pass');
    return { mode, bindingId: state.currentCredentialId, authorized, input: { profile: DBAC_PAYMENT_PROFILE, payment: state.order, authorization, paymentRequired: authorized.task.status.message.metadata['x402.payment.required'], responseEvidence: authorized.responseEvidence } };
  }
  async function revoke(bindingId) {
    const response = await fetch(`${f.issuer.baseUrl}/credentials/revoke`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-DBAC-Access': f.issuerToken }, body: JSON.stringify({ bindingId }) });
    assert.equal(response.status, 200);
  }
  function signedOrderCount(orderId) {
    const db = new DatabaseSync(join(directory, 'payments.sqlite'), { readOnly: true });
    try { return db.prepare('SELECT COUNT(*) AS n FROM x402_orders WHERE order_id=?').get(orderId).n; }
    finally { db.close(); }
  }
  async function heldSettlement(value, payload) {
    captureSettlement = true; capturedSettlement = undefined;
    try {
      const prepared = await f.session.prepare({ mode: value.mode, phase: 'settle', authorization: value.input.authorization, payload, continuation: value.authorized.task });
      await assert.rejects(f.session.transmit(prepared), { code: 'TEST_SETTLEMENT_HELD' });
      assert.ok(capturedSettlement?.responseEvidence?.proof);
      measureEvidence('settle-gate', capturedSettlement.responseEvidence);
      return capturedSettlement;
    } finally { captureSettlement = false; }
  }

  for (const mode of ['bbs-bls', 'bbs-blind-bls']) await t.test(`${mode}: revoke after genuine authorize evidence refuses wallet signature`, async () => {
    const value = await sample(mode);
    await revoke(value.bindingId);
    await assert.rejects(payer.createPayload(value.input), { code: 'W3C_CREDENTIAL_REVOKED' });
    assert.equal(signedOrderCount(value.input.payment.orderId), 0);
  });

  await t.test('unknown, non-boolean and unavailable status never release a wallet signature', async () => {
    const value = await sample();
    for (const answer of [null, undefined, 'false', { revoked: false }, new Error('status network offline')]) {
      reset(() => { if (answer instanceof Error) throw answer; return answer; });
      await assert.rejects(payer.createPayload(value.input), { code: 'W3C_STATUS_UNAVAILABLE' });
      assert.equal(signedOrderCount(value.input.payment.orderId), 0);
    }
  });

  await t.test('revocation during wallet signing refuses signature release and persistence', async () => {
    const value = await sample();
    reset(async (bindingId, count) => { assert.equal(bindingId, value.bindingId); if (count === 2) { await revoke(bindingId); return true; } return false; });
    await assert.rejects(payer.createPayload(value.input), { code: 'W3C_CREDENTIAL_REVOKED' });
    assert.equal(statusCalls, 2);
    assert.equal(signedOrderCount(value.input.payment.orderId), 0);
  });

  await t.test('a previously signed payload and genuine settle evidence cannot create a transfer after revocation', async () => {
    const value = await sample('bbs-blind-bls'), payload = await payer.createPayload(value.input);
    assert.match(payload.payload.signature, /^0x[0-9a-f]+$/i);
    const settlement = await heldSettlement(value, payload);
    await revoke(value.bindingId);
    await assert.rejects(payer.createPayload(value.input), { code: 'W3C_CREDENTIAL_REVOKED' });
    await assert.rejects(backend.execute(settlement), { code: 'W3C_CREDENTIAL_REVOKED' });
    const snapshot = await backend.snapshot();
    assert.equal(snapshot.executionCount, initial.executionCount);
    assert.deepEqual(snapshot.accounts, initial.accounts);
  });

  await t.test('status failure immediately before broadcast preserves balances and execution count', async () => {
    const value = await sample(), payload = await payer.createPayload(value.input);
    const settlement = await heldSettlement(value, payload);
    reset((bindingId, count) => { if (count === 2) throw new Error('status service unavailable before broadcast'); return false; });
    await assert.rejects(backend.execute(settlement), { code: 'W3C_STATUS_UNAVAILABLE' });
    assert.equal(statusCalls, 2);
    const snapshot = await backend.snapshot();
    assert.equal(snapshot.executionCount, initial.executionCount);
    assert.deepEqual(snapshot.accounts, initial.accounts);
  });

  await t.test('unrevoked control completes one actual local-chain payment with the same production proofs', async () => {
    const value = await sample(), payload = await payer.createPayload(value.input);
    const result = await f.session.transmit(await f.session.prepare({ mode: value.mode, phase: 'settle', authorization: value.input.authorization, payload, continuation: value.authorized.task }));
    assert.equal(result.paymentResult.outcome, 'EXECUTED');
    measureEvidence('settle-completed', result.responseEvidence);
    assert.match(result.paymentResult.receipt.transactionHash, /^0x[0-9a-f]{64}$/i);
    const snapshot = await backend.snapshot();
    assert.equal(snapshot.executionCount, initial.executionCount + 1);
    const balance = (ledger, id) => ledger.accounts.find(item => item.id === id).balanceMinor;
    assert.equal(balance(snapshot, 'demo:alice'), balance(initial, 'demo:alice') - value.input.payment.amountMinor);
    assert.equal(balance(snapshot, 'merchant:keyboard'), balance(initial, 'merchant:keyboard') + value.input.payment.amountMinor);
  });
  t.diagnostic(`Actual signed B evidence header sizes: ${JSON.stringify(Object.fromEntries([...new Set(evidenceLengths.map(value => value.phase))].map(phase => [phase, Math.max(...evidenceLengths.filter(value => value.phase === phase).map(value => value.bytes))])))}`);
});
