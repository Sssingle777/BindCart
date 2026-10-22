import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { x402Client } from '@x402/core/client';
import { x402Facilitator } from '@x402/core/facilitator';
import { generateIdentity, issueCredential, signJws } from '../lib/identity.mjs';
import { createOwner } from '../lib/owner.mjs';
import { issuePaymentAuthorization, PAYMENT_SCOPE } from '../lib/payment.mjs';
import { digest } from '../lib/protocol.mjs';
import { generateIssuerKey, generateDeviceKey } from '../lib/dbac/crypto.mjs';
import { DBAC_EXTENSION, DBAC_SCHEMA, paymentDisclosures } from '../lib/dbac/policy.mjs';
import { DBAC_PAYMENT_PROFILE, DBAC_PAYMENT_RESPONSE_TYP, dbacPaymentHash, issueDbacPaymentAuthorization, verifyDbacPaymentAuthorization } from '../lib/dbac/payment-policy.mjs';
import { createLocalX402Environment, createX402Backend, createX402Payer, paymentSettlement } from '../lib/x402-payment.mjs';

const rejectsCode = (promise, code) => assert.rejects(promise, error => { assert.equal(error.code, code, error.message); return true; });
const unix = () => Math.floor(Date.now() / 1000);
const capability = () => randomBytes(32).toString('base64url');
const snapshotBalances = snapshot => Object.fromEntries(snapshot.accounts.map(account => [account.id, account.balanceMinor]));

// This is the wallet trust-boundary fixture: it signs authentic B evidence, but
// it does not replace the real BLS proof/verifier integration tests. Transfers,
// Owner approvals, wallet signatures and receipt recovery below all run live.
function dbacEvidence({ verifier, issuerPublicKey, orderKey, mode, phase, payment, authorization, paymentRequired, payload, signer = verifier, issuedAt = unix() }) {
  const taskId = randomUUID(), contextId = randomUUID();
  const request = { jsonrpc: '2.0', id: randomUUID(), method: 'message/send', params: { message: {
    kind: 'message', role: 'user', messageId: randomUUID(), ...(phase === 'settle' ? { taskId, contextId } : {}), parts: [{ kind: 'data', data: {
      scope: PAYMENT_SCOPE, phase, payment, ...(phase === 'proposal' ? {} : { authorization }), ...(phase === 'settle' ? { payload } : {}),
    } }],
  } } };
  const rawRequest = JSON.stringify(request);
  const context = {
    profile: DBAC_EXTENSION, purpose: 'dbac-payment-v1', scope: PAYMENT_SCOPE, mode, verifier: verifier.did,
    target: 'http://127.0.0.1:12345/dbac/payment/a2a', method: 'POST', bodyHash: digest(rawRequest), paymentOrderId: payment.orderId,
    challengeId: randomUUID(), nonce: capability(), iat: issuedAt, exp: issuedAt + 60,
    schema: DBAC_SCHEMA, requiredDisclosures: paymentDisclosures(mode),
  };
  const rawResponse = JSON.stringify({ jsonrpc: '2.0', id: request.id, result: {
    kind: 'task', id: taskId, contextId, status: {
      state: phase === 'proposal' ? 'completed' : phase === 'authorize' ? 'input-required' : 'working',
      ...(phase === 'proposal' ? {} : { message: { metadata: phase === 'authorize' ? { 'x402.payment.status': 'payment-required', 'x402.payment.required': paymentRequired } : { 'dbac.payment.status': 'settlement-authorized' } } }),
    },
  } });
  const paymentGate = { profile: DBAC_PAYMENT_PROFILE, phase, mode, issuerPublicKey, orderKey, paymentHash: dbacPaymentHash(payment),
    ...(phase === 'proposal' ? {} : { authorizationHash: digest(authorization) }), ...(phase === 'settle' ? { payloadHash: dbacPaymentHash(payload) } : {}),
  };
  const proof = signJws({ iss: signer.did, requestHash: digest(rawRequest), responseHash: digest(rawResponse), contextHash: digest(JSON.stringify(context)),
    iat: issuedAt, exp: issuedAt + (phase === 'proposal' ? 300 : 60), paymentGate,
    verificationTrace: { profile: DBAC_PAYMENT_PROFILE, source: 'agent-b', outcome: 'pass', steps: [] },
  }, signer, DBAC_PAYMENT_RESPONSE_TYP);
  return { proof, rawRequest, rawResponse, context };
}

function identifiedEvidence({ verifier, holder, device, payment, authorization, paymentRequired }) {
  const id = randomUUID();
  const rawRequest = JSON.stringify({ jsonrpc: '2.0', id, method: 'message/send', params: { message: { parts: [{ kind: 'data', data: { scope: PAYMENT_SCOPE, payment, authorization } }] } } });
  const rawResponse = JSON.stringify({ jsonrpc: '2.0', id, result: { kind: 'task', id: randomUUID(), status: { state: 'input-required', message: { metadata: { 'x402.payment.status': 'payment-required', 'x402.payment.required': paymentRequired } } } } });
  const proof = signJws({ iss: verifier.did, aud: holder.did, deviceDid: device.did, deviceProofHash: digest('isolated fixture device proof'),
    requestHash: digest(rawRequest), responseHash: digest(rawResponse), nonce: digest(id), iat: unix(), exp: unix() + 60,
  }, verifier, 'a2a-did-response+jwt');
  return { proof, rawRequest, rawResponse };
}

test('DBAC Owner and wallet enforce separate payment gates with live local-chain settlement and preserved legacy state', { timeout: 120_000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'a2a-dbac-wallet-'));
  const issuer = generateIdentity('legacy issuer'), holder = generateIdentity('legacy holder'), device = generateIdentity('legacy device'), verifier = generateIdentity('verifier');
  const outsider = generateIdentity('untrusted Owner'), dbacIssuer = generateIssuerKey();
  const ownerConfig = { holderDid: holder.did, verifierDid: verifier.did, trustedIssuers: [issuer.did], proposalToken: capability(), uiToken: capability(), dbacIssuerPublicKey: dbacIssuer.publicKey };
  const owner = createOwner(ownerConfig);
  const ownerUrl = await owner.listen();
  let environment, revocationReads = 0;
  const config = { stateDir: directory, trustedIssuers: [issuer.did], trustedAuthorizers: [owner.publicInfo().did], holderDid: holder.did, deviceDid: device.did,
    verifierDid: verifier.did, dbacIssuerPublicKey: dbacIssuer.publicKey, isCredentialRevoked: async () => { revocationReads += 1; return false; } };
  t.after(async () => { try { await environment?.close(); await owner.close(); } finally { await rm(directory, { recursive: true, force: true }); } });
  environment = await createLocalX402Environment(config);
  let backend = createX402Backend(environment.backendConfig), payer = createX402Payer(environment.payerConfig);
  const payment = () => ({ orderId: `urn:uuid:${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 2_990_000,
    currency: 'TEST_USDC', settlement: paymentSettlement(environment.publicInfo) });
  const requestOwner = async (path, body, key = ownerConfig.proposalToken) => {
    const response = await fetch(`${ownerUrl}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', [path.startsWith('/api/') ? 'X-Owner-UI-Key' : 'X-Owner-Proposal']: key }, body: JSON.stringify(body) });
    const result = await response.json();
    if (!response.ok) Object.assign(result, { httpStatus: response.status });
    return result;
  };
  const confirm = proposal => requestOwner(`/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }, ownerConfig.uiToken);
  const vc = issueCredential(issuer, { subjectDid: holder.did, deviceDid: device.did, audience: verifier.did, scopes: [PAYMENT_SCOPE] });
  const legacyPayment = payment();
  let legacyAuthorization, legacyPayload, legacyReceipt;
  const legacySignInput = () => { const paymentRequired = backend.requirements(legacyPayment); return { payment: legacyPayment, paymentRequired, credential: vc, authorization: legacyAuthorization,
    ...identifiedEvidence({ verifier, holder, device, payment: legacyPayment, authorization: legacyAuthorization, paymentRequired }) }; };

  await t.test('existing identified payment remains valid and migrates without changing signed bytes or receipts', async () => {
    const proposal = await requestOwner('/proposals', { credential: vc, payment: legacyPayment });
    legacyAuthorization = (await confirm(proposal)).authorization.token;
    legacyPayload = await payer.createPayload(legacySignInput());
    legacyReceipt = (await backend.execute({ payment: legacyPayment, payload: legacyPayload, credential: vc, authorization: legacyAuthorization })).receipt;
    await environment.close();
    const db = new DatabaseSync(join(directory, 'payments.sqlite'));
    db.exec('ALTER TABLE x402_orders DROP COLUMN security_binding; ALTER TABLE x402_orders DROP COLUMN security_profile');
    const oldRows = db.prepare('SELECT * FROM x402_orders').all().map(row => ({ ...row }));
    const oldAuthorizations = db.prepare('SELECT * FROM x402_authorizations').all().map(row => ({ ...row }));
    db.close();
    environment = await createLocalX402Environment(config);
    backend = createX402Backend(environment.backendConfig); payer = createX402Payer(environment.payerConfig);
    const migrated = new DatabaseSync(join(directory, 'payments.sqlite'));
    const rows = migrated.prepare('SELECT * FROM x402_orders').all().map(row => ({ ...row }));
    assert.deepEqual(rows.map(({ security_profile, security_binding, ...original }) => original), oldRows);
    assert.equal(rows[0].security_profile, 'identified'); assert.equal(rows[0].security_binding, null);
    assert.deepEqual(migrated.prepare('SELECT * FROM x402_authorizations').all().map(row => ({ ...row })), oldAuthorizations);
    migrated.close();
    assert.deepEqual(await payer.createPayload(legacySignInput()), legacyPayload);
    assert.equal((await backend.execute({ payment: legacyPayment, payload: legacyPayload, credential: vc, authorization: legacyAuthorization })).receipt.transactionHash, legacyReceipt.transactionHash);
  });

  let lastInput, lastSettle;
  await t.test('Owner without a trusted DBAC issuer never signs an anonymous proposal', async () => {
    const { dbacIssuerPublicKey: omitted, ...identifiedOwnerConfig } = ownerConfig;
    const identifiedOwner = createOwner(identifiedOwnerConfig);
    const url = await identifiedOwner.listen();
    try {
      const p = payment();
      const evidence = dbacEvidence({ verifier, issuerPublicKey: dbacIssuer.publicKey, orderKey: generateDeviceKey().publicKey, mode: 'bbs-bls', phase: 'proposal', payment: p });
      const result = await fetch(`${url}/proposals`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Owner-Proposal': ownerConfig.proposalToken }, body: JSON.stringify({ profile: DBAC_PAYMENT_PROFILE, payment: p, dbacEvidence: evidence }) });
      assert.equal(result.status, 403);
      assert.equal((await result.json()).error.code, 'DBAC_PAYMENT_NOT_CONFIGURED');
    } finally { await identifiedOwner.close(); }
  });
  for (const mode of ['bbs-bls', 'bbs-blind-bls']) {
    await t.test(`${mode}: Owner confirmation, fresh gates, tamper rejection and one real debit`, async st => {
      const p = payment(), orderKey = generateDeviceKey().publicKey;
      const base = { verifier, issuerPublicKey: dbacIssuer.publicKey, orderKey, mode, payment: p };
      const proposalEvidence = dbacEvidence({ ...base, phase: 'proposal' });
      const proposed = await requestOwner('/proposals', { profile: DBAC_PAYMENT_PROFILE, payment: p, dbacEvidence: proposalEvidence });
      assert.equal(proposed.status, 'PENDING'); assert.equal(proposed.mode, mode); assert.equal(proposed.orderKey, orderKey);
      assert.equal(proposed.holderDid, undefined); assert.equal(proposed.deviceDid, undefined); assert.equal(proposed.credential, undefined); assert.equal(proposed.credentialId, undefined);
      assert.equal((await requestOwner(`/api/proposals/${proposed.id}/approve`, { confirmed: true, payment: { ...p, amountMinor: 1 }, credentialHash: proposed.credentialHash }, ownerConfig.uiToken)).error.code, 'OWNER_CONFIRMATION_MISMATCH');
      const approved = await confirm(proposed);
      const authorization = approved.authorization.token, paymentRequired = backend.requirements(p);
      const grant = verifyDbacPaymentAuthorization(authorization, { trustedAuthorizers: [owner.publicInfo().did], verifierDid: verifier.did, issuerPublicKey: dbacIssuer.publicKey, payment: p, mode, orderKey });
      for (const forbidden of ['sub', 'holderDid', 'deviceDid', 'credential', 'credentialHash', 'credentialId']) assert.equal(Object.hasOwn(grant, forbidden), false);
      const makeEvidence = (phase, extra = {}) => dbacEvidence({ ...base, authorization, paymentRequired, phase, ...extra });
      const input = { profile: DBAC_PAYMENT_PROFILE, payment: p, authorization, paymentRequired, responseEvidence: makeEvidence('authorize') };
      const readsBefore = revocationReads;
      const balancesBefore = await backend.snapshot();
      await rejectsCode(payer.createPayload({ ...input, authorization: undefined }), 'PAYMENT_AUTHORIZATION_REQUIRED');
      const fakeGrant = issueDbacPaymentAuthorization(outsider, { verifierDid: verifier.did, issuerPublicKey: dbacIssuer.publicKey, mode, orderKey, payment: p });
      await rejectsCode(payer.createPayload({ ...input, authorization: fakeGrant }), 'PAYMENT_AUTHORIZER_UNTRUSTED');
      await rejectsCode(payer.createPayload({ ...input, payment: { ...p, amountMinor: p.amountMinor + 1 } }), 'PAYMENT_TERMS_MISMATCH');
      await rejectsCode(payer.createPayload({ ...input, responseEvidence: undefined }), 'DBAC_PAYMENT_EVIDENCE_REQUIRED');
      await rejectsCode(payer.createPayload({ ...input, responseEvidence: proposalEvidence }), 'DBAC_PAYMENT_EVIDENCE_INVALID');
      await rejectsCode(payer.createPayload({ ...input, responseEvidence: makeEvidence('authorize', { signer: outsider }) }), 'DBAC_PAYMENT_EVIDENCE_INVALID');
      await rejectsCode(payer.createPayload({ ...input, responseEvidence: { ...input.responseEvidence, rawResponse: `${input.responseEvidence.rawResponse} ` } }), 'DBAC_PAYMENT_EVIDENCE_INVALID');
      await rejectsCode(payer.createPayload({ ...input, responseEvidence: makeEvidence('authorize', { orderKey: generateDeviceKey().publicKey }) }), 'PAYMENT_AUTHORIZATION_BINDING_MISMATCH');
      await rejectsCode(payer.createPayload({ ...input, paymentRequired: { ...paymentRequired, accepts: [{ ...paymentRequired.accepts[0], amount: '1' }] } }), 'DBAC_PAYMENT_EVIDENCE_MISMATCH');
      const oldEvidence = identifiedEvidence({ verifier, holder, device, payment: p, authorization, paymentRequired });
      await rejectsCode(payer.createPayload({ ...input, responseEvidence: { ...oldEvidence, context: input.responseEvidence.context } }), 'DBAC_PAYMENT_EVIDENCE_INVALID');

      if (mode === 'bbs-bls') await st.test('a gate expiring while the wallet signer runs never releases or persists a payload', async sst => {
        const original = x402Client.prototype.createPaymentPayload, wallTime = Date.now;
        sst.mock.method(x402Client.prototype, 'createPaymentPayload', async function (...args) { const result = await original.apply(this, args); sst.mock.method(Date, 'now', () => wallTime() + 120000); return result; });
        await rejectsCode(payer.createPayload(input), 'DBAC_PAYMENT_EVIDENCE_INVALID');
        const db = new DatabaseSync(join(directory, 'payments.sqlite'));
        assert.equal(db.prepare('SELECT * FROM x402_orders WHERE order_id=?').get(p.orderId), undefined); db.close();
      });

      const payload = await payer.createPayload(input);
      assert.match(payload.payload.signature, /^0x[0-9a-f]+$/i);
      assert.deepEqual(snapshotBalances(await backend.snapshot()), snapshotBalances(balancesBefore));
      assert.deepEqual(await payer.createPayload({ ...input, responseEvidence: makeEvidence('authorize') }), payload);
      const settle = { profile: DBAC_PAYMENT_PROFILE, payment: p, authorization, payload, responseEvidence: makeEvidence('settle', { payload }) };
      await rejectsCode(backend.execute({ ...settle, responseEvidence: undefined }), 'DBAC_PAYMENT_EVIDENCE_REQUIRED');
      await rejectsCode(backend.execute({ ...settle, responseEvidence: input.responseEvidence }), 'DBAC_PAYMENT_EVIDENCE_MISMATCH');
      const changedPayload = structuredClone(payload); changedPayload.payload.authorization.nonce = `0x${'2'.repeat(64)}`;
      await rejectsCode(backend.execute({ ...settle, payload: changedPayload }), 'DBAC_PAYMENT_EVIDENCE_MISMATCH');
      await rejectsCode(backend.execute({ ...settle, payload: changedPayload, responseEvidence: makeEvidence('settle', { payload: changedPayload }) }), 'X402_UNAPPROVED_PAYLOAD');
      let result;
      if (mode === 'bbs-bls') {
        await st.test('expiration after broadcast retains the transaction so a fresh gate recovers the same debit', async sst => {
          const original = x402Facilitator.prototype.settle, wallTime = Date.now;
          sst.mock.method(x402Facilitator.prototype, 'settle', async function (...args) { const settled = await original.apply(this, args); sst.mock.method(Date, 'now', () => wallTime() + 120000); return settled; });
          await assert.rejects(backend.execute(settle), error => { assert.equal(error.code, 'DBAC_PAYMENT_EVIDENCE_INVALID'); assert.match(error.transaction, /^0x[0-9a-f]{64}$/); return true; });
        });
        result = await backend.execute({ ...settle, responseEvidence: makeEvidence('settle', { payload }) });
        assert.equal(result.outcome, 'ALREADY_PROCESSED');
      } else {
        const runs = await Promise.all(Array.from({ length: 3 }, () => backend.execute(settle)));
        assert.equal(runs.filter(run => run.outcome === 'EXECUTED').length, 1);
        assert.equal(runs.filter(run => run.outcome === 'ALREADY_PROCESSED').length, 2);
        assert.equal(new Set(runs.map(run => run.receipt.transactionHash)).size, 1);
        result = runs[0];
      }
      const balancesAfter = await backend.snapshot();
      assert.equal(balancesAfter.executionCount, balancesBefore.executionCount + 1);
      assert.equal(snapshotBalances(balancesAfter)['demo:alice'], snapshotBalances(balancesBefore)['demo:alice'] - p.amountMinor);
      assert.equal(snapshotBalances(balancesAfter)['merchant:keyboard'], snapshotBalances(balancesBefore)['merchant:keyboard'] + p.amountMinor);
      assert.equal(result.receipt.transactionStatus, 'success');
      assert.equal((await backend.execute({ ...settle, responseEvidence: makeEvidence('settle', { payload }) })).receipt.transactionHash, result.receipt.transactionHash);
      assert.equal(revocationReads, readsBefore, 'DBAC never pretends to look up a named credential revocation status');

      const newKey = generateDeviceKey().publicKey;
      const changedProposal = await requestOwner('/proposals', { profile: DBAC_PAYMENT_PROFILE, payment: p, dbacEvidence: makeEvidence('proposal', { orderKey: newKey }) });
      const changedAuthorization = (await confirm(changedProposal)).authorization.token;
      await rejectsCode(payer.createPayload({ ...input, authorization: changedAuthorization, responseEvidence: makeEvidence('authorize', { orderKey: newKey, authorization: changedAuthorization }) }), 'X402_ORDER_BINDING_MISMATCH');
      const identifiedProposal = await requestOwner('/proposals', { credential: vc, payment: p });
      const identifiedGrant = (await confirm(identifiedProposal)).authorization.token;
      await rejectsCode(payer.createPayload({ payment: p, authorization: identifiedGrant, credential: vc, paymentRequired, ...identifiedEvidence({ verifier, holder, device, payment: p, authorization: identifiedGrant, paymentRequired }) }), 'X402_SECURITY_PROFILE_MISMATCH');
      lastInput = input; lastSettle = settle;
    });
  }

  await t.test('an existing identified order cannot be upgraded through a different DBAC gate', async () => {
    const mode = 'bbs-bls', orderKey = generateDeviceKey().publicKey;
    const base = { verifier, issuerPublicKey: dbacIssuer.publicKey, mode, orderKey, payment: legacyPayment };
    const proposal = await requestOwner('/proposals', { profile: DBAC_PAYMENT_PROFILE, payment: legacyPayment, dbacEvidence: dbacEvidence({ ...base, phase: 'proposal' }) });
    const authorization = (await confirm(proposal)).authorization.token;
    const paymentRequired = backend.requirements(legacyPayment);
    await rejectsCode(payer.createPayload({ profile: DBAC_PAYMENT_PROFILE, payment: legacyPayment, authorization, paymentRequired,
      responseEvidence: dbacEvidence({ ...base, phase: 'authorize', authorization, paymentRequired }) }), 'X402_SECURITY_PROFILE_MISMATCH');
  });

  await t.test('Owner rechecks proposal evidence expiry, and an unconfigured wallet refuses DBAC even for a cached order', async st => {
    const p = payment(), mode = 'bbs-bls', orderKey = generateDeviceKey().publicKey;
    const evidence = dbacEvidence({ verifier, issuerPublicKey: dbacIssuer.publicKey, mode, orderKey, phase: 'proposal', payment: p });
    const proposal = await requestOwner('/proposals', { profile: DBAC_PAYMENT_PROFILE, payment: p, dbacEvidence: evidence });
    const wallTime = Date.now;
    const clock = st.mock.method(Date, 'now', () => wallTime() + 301000);
    try { assert.equal((await confirm(proposal)).error.code, 'OWNER_PROPOSAL_EXPIRED'); } finally { clock.mock.restore(); }
    await environment.close();
    const { dbacIssuerPublicKey: omitted, ...legacyConfig } = config;
    environment = await createLocalX402Environment(legacyConfig);
    payer = createX402Payer(environment.payerConfig); backend = createX402Backend(environment.backendConfig);
    await rejectsCode(payer.createPayload(lastInput), 'DBAC_PAYMENT_NOT_CONFIGURED');
    await rejectsCode(backend.execute(lastSettle), 'DBAC_PAYMENT_NOT_CONFIGURED');
    assert.equal((await backend.snapshot()).executionCount, 3);
  });
});
