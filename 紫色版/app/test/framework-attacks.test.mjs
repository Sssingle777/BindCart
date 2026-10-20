import test from 'node:test';
import assert from 'node:assert/strict';
import { createFrameworkAttackExperiments } from '../lib/dbac/attack-experiments.mjs';
import { frameworkFixture as fixture } from './fixtures/framework.mjs';

for (const mode of ['bbs-bls', 'bbs-blind-bls']) {
  test(`${mode}: each framework experiment uses actual B and distinguishes rejection from experiment success`, { timeout: 180000 }, async t => {
    const f = await fixture(t);
    await f.session.issue({ mode });
    const untouched = await f.session.state({ mode });
    const catalog = f.session.experimentScenarios();
    assert.ok(catalog.some(item => item.id === 'copied-vc' && item.kind === 'black-box'));
    for (const scenario of catalog.filter(value => value.id !== 'expired-challenge')) await t.test(scenario.id, async () => {
      const result = await f.session.experiments({ mode, scenarioId: scenario.id });
      assert.equal(result.completion, 'completed', `${scenario.id}: ${result.error?.code ?? result.actual}`);
      assert.equal(result.actual, scenario.expected);
      assert.equal(result.expectationMet, true, JSON.stringify({ scenario: scenario.id, actual: result.actual, error: result.error, effects: result.sideEffects }));
      assert.equal(result.control.accepted, true);
      assert.equal(result.sideEffects.paymentExecutionDelta, 0);
      assert.equal(result.sideEffects.balancesUnchanged, true);
      assert.equal(result.sideEffects.ownerApprovalRequested, false);
      assert.equal(result.sideEffects.walletSignatureRequested, false);
      assert.equal(result.authenticationIssued, scenario.id === 'normal');
      assert.equal(result.requestRejected, scenario.id !== 'normal');
      if (scenario.id !== 'locked-device') assert.ok(result.verificationTrace.steps.length > 0);
      if (scenario.id === 'copied-vc') {
        assert.deepEqual(result.accessChecks.map(check => check.actual), ['DBAC_ACCESS_DENIED', 'DBAC_ACCESS_DENIED']);
        assert.equal(result.attackerContext.holderKeyAvailable, false);
        assert.equal(result.attackerContext.deviceCapabilityAvailable, false);
        assert.deepEqual(Object.keys(result.request.proof), ['verifiableCredential']);
      }
      if (scenario.id === 'revoked') {
        assert.equal(result.revocation.freshChallenge, true);
        assert.equal(result.revocation.completeHolderProof, true);
        assert.equal(result.revocation.completeDeviceProof, true);
        const status = result.verificationTrace.steps.find(step => step.id === 'credential_status');
        assert.equal(status.status, 'fail');
        assert.equal(status.code, 'W3C_CREDENTIAL_REVOKED');
        assert.equal(status.evidence.length, 1);
        const comparison = status.evidence[0];
        assert.equal(comparison.label, 'issuer status / source / checked at');
        assert.equal(comparison.expected, 'valid');
        assert.equal(comparison.observed[0], 'revoked');
        assert.equal(comparison.observed[1], 'trusted-local-issuer');
        assert.ok(Number.isFinite(Date.parse(comparison.observed[2])));
        assert.equal(comparison.match, false);
        assert.equal(result.verificationTrace.steps.find(step => step.id === 'consume').status, 'skipped', 'a revoked credential never consumes the challenge');
      }
      if (scenario.id === 'invalid-device' || scenario.id === 'wrong-device') assert.equal(result.rejectionStage, 'device_pairing');
      if (scenario.id === 'invalid-holder') {
        assert.equal(result.rejectionStage, 'holder_signature');
        assert.equal(Buffer.from(result.request.proof.holderProof.split('.')[2], 'base64url').length, 64);
      }
      if (scenario.id === 'locked-device') assert.equal(result.deviceLockRestored, true);
      const serialized = JSON.stringify(result);
      assert.doesNotMatch(serialized, /privateKey|secretKey|accessToken|proposalToken|Competition team|Alice \/ Agent A/);
      assert.ok(!serialized.includes(f.issuerToken)); assert.ok(!serialized.includes(f.statusToken));
      const after = await f.session.state({ mode });
      assert.equal(after.order.orderId, untouched.order.orderId, 'experiments preserve user order');
      assert.deepEqual(after.w3c.originalCredential, untouched.w3c.originalCredential, 'experiments preserve the exact user VC');
      assert.equal(after.currentCredentialId, untouched.currentCredentialId);
      assert.equal(after.credentialStatus?.status, untouched.credentialStatus?.status);
      assert.equal(after.lastResult, untouched.lastResult);
    });
  });
}

test('valid holder signature from another round is refused, failure preserves the correct challenge, and concurrent success consumes once', { timeout: 60000 }, async t => {
  const f = await fixture(t), mode = 'bbs-bls';
  await f.session.issue({ mode });
  const first = await f.session.prepare({ mode, phase: 'proposal' });
  const other = await f.session.prepare({ mode, phase: 'proposal' });
  await assert.rejects(f.session.transmit({ ...first, holderProof: other.holderProof }), error => error.code === 'HOLDER_BINDING_MISMATCH' && error.verificationTrace.steps.find(step => step.id === 'holder_signature').status === 'fail');
  const success = await f.session.transmit(first);
  assert.equal(success.accepted, true, 'invalid holder transcript did not consume another round');
  const concurrent = await Promise.allSettled([f.session.transmit(other), f.session.transmit(other)]);
  assert.equal(concurrent.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(concurrent.filter(result => result.status === 'rejected' && result.reason.code === 'DBAC_REPLAY').length, 1);
  assert.equal(f.ledger.executionCount, 0);
});

test('a status-service outage rejects a complete genuine proof without issuing authentication', { timeout: 30000 }, async t => {
  const f = await fixture(t), mode = 'bbs-bls';
  await f.session.issue({ mode });
  const control = await f.session.prepare({ mode, phase: 'proposal' });
  assert.equal((await f.session.transmit(control)).accepted, true);
  const complete = await f.session.prepare({ mode, phase: 'proposal' });
  await f.issuerService.close();
  await assert.rejects(f.session.transmit(complete), error => {
    assert.equal(error.code, 'W3C_CREDENTIAL_STATUS_UNAVAILABLE');
    const status = error.verificationTrace.steps.find(step => step.id === 'credential_status');
    assert.equal(status.status, 'fail');
    assert.equal(status.evidence, undefined, 'query outage has no observed issuer status');
    return true;
  });
  assert.equal(f.ledger.executionCount, 0);
});

test('a genuine proof waits for the server challenge deadline before expiry rejection', { timeout: 100000 }, async t => {
  const f = await fixture(t);
  const result = await f.session.experiments({ mode: 'bbs-bls', scenarioId: 'expired-challenge' });
  assert.equal(result.actual, 'DBAC_CHALLENGE_EXPIRED');
  assert.equal(result.expectationMet, true);
  assert.ok(result.expiry.submittedAt >= result.expiry.serverExpiresAt);
  assert.ok(result.expiry.actualWaitMs > 50000, 'time was actually allowed to expire, without mocking cryptographic verification');
  assert.equal(result.authenticationIssued, false);
});

test('unavailable setup and rejected transport are incomplete rather than successful attack interception', async () => {
  const ledger = async () => ({ executionCount: 0, accounts: [] });
  const experiments = createFrameworkAttackExperiments({ initialize: async () => { throw Object.assign(new Error('service offline'), { code: 'EXPERIMENT_TRANSPORT' }); }, getLedger: ledger });
  const result = await experiments.run({ scenarioId: 'copied-vc' });
  assert.equal(result.completion, 'incomplete'); assert.equal(result.expectationMet, false); assert.equal(result.requestRejected, false); assert.equal(result.authenticationIssued, false);
  assert.equal(result.control, null);
});

test('a concurrent run cannot replace the experiment being executed', async () => {
  let release;
  const wait = new Promise(resolve => { release = resolve; });
  const experiments = createFrameworkAttackExperiments({ initialize: async () => { await wait; throw Object.assign(new Error('fixture initialization ended'), { code: 'EXPERIMENT_TRANSPORT' }); }, getLedger: async () => ({ executionCount: 0, accounts: [] }) });
  const pending = experiments.run({ scenarioId: 'normal' });
  await assert.rejects(experiments.run({ scenarioId: 'normal' }), { code: 'EXPERIMENT_BUSY' });
  release(); await pending;
  assert.equal(experiments.history().length, 1);
});
