import test from 'node:test';
import assert from 'node:assert/strict';
import { protocolSnapshot, protocolChecks } from '../public/protocol-model.js';

const secret = 'DO_NOT_PROJECT_PRIVATE_MATERIAL';
const step = (id, status = 'pass', evidence = []) => ({ id, title: id, actor: 'agent-b', status, evidence });
const vc = () => ({ '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiableCredential'],
  issuer: 'did:example:issuer', credentialSubject: { role: 'payer', bindingId: 'urn:uuid:binding', organization: 'demo-only', secret },
  proof: { type: 'DataIntegrityProof', cryptosuite: 'bbs-2023', proofValue: 'public-standard-proof', secret }, extra: { secret } });
function fixture() {
  return {
    available: true, mode: 'bbs-bls', order: { orderId: 'order-1', amountMinor: 2990000, currency: 'TEST_USDC',
      payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', settlement: { network: 'eip155:31337', asset: 'public-token', payTo: 'public-payee', payerAddress: 'public-payer', secret }, secret },
    authorization: { token: secret }, proposal: { id: 'proposal-1', status: 'APPROVED', authorization: { token: secret } },
    credential: { suite: 'public-suite', signature: { e: secret }, attributes: [{ index: 0, name: 'role', value: 'payer', disclosed: true, privateRandomizer: secret }] },
    w3c: { issuerProfile: { issuer: 'did:example:issuer', verificationMethod: { id: 'did:example:issuer#key', type: 'Multikey', publicKeyMultibase: 'public-key', secretKeyMultibase: secret } },
      originalCredential: vc(), disclosedPaths: ['/credentialSubject/role'], hiddenPaths: ['/credentialSubject/organization'] },
    manual: {
      active: true, phase: 'proposal', stage: 'VERIFIED', attemptId: 'attempt-1', expired: false,
      walletPayload: { signature: secret }, ownerApproved: true, walletSigned: false, walletSigningUnconfirmed: false, settled: false,
      device: { backend: 'node-bls12-381', publicKey: 'public-device-key', publicKeyFingerprint: 'public-fingerprint', secretKey: secret,
        modes: { 'bbs-bls': { signatures: 2, locked: false, secret }, arbitraryMode: { secret } } },
      cryptography: { presentationHeader: 'public-PH', w3cPresentationHash: 'public-hVC', privateRandomizer: secret },
      challenge: { challengeId: 'challenge-1', nonce: 'public-nonce', bodyHash: 'public-body-hash', requiredDisclosures: { 0: 'payer', secret }, secret },
      deviceRequest: { mode: 'bbs-bls', randomizedDevicePublicKey: 'public-randomized-key', context: { challengeId: 'challenge-1', w3cPresentationHash: 'public-hVC', secret }, privateState: { secret } },
      deviceResponse: { mode: 'bbs-bls', signature: 'public-device-contribution', secretKey: secret },
      verifiableCredential: vc(), sentCredential: vc(),
      presentation: { randomizedDevicePublicKey: 'public-randomized-key', deviceSignature: 'public-adapted-signature',
        Abar: 'public-Abar', Bbar: 'public-Bbar', Cbar: 'public-Cbar', disclosed: [{ index: 6, value: 'urn:uuid:binding', secret }],
        proof: { challenge: 'public-c', responses: { inverseR1: 'public-zw', keyRandomizer: 'public-zk', r2: 'public-zr', e: 'public-ze',
          hidden: [{ index: 4, response: 'public-z-hidden', secret }], privateRandomizer: secret }, privateWitness: secret }, privateState: { secret } },
      verificationResult: { verificationTrace: { profile: 'dbac-payment', source: 'agent-b', outcome: 'pass',
        steps: [step('knowledge', 'pass', [{ label: 'Fiat-Shamir challenge', expected: 'public-c', observed: 'public-c', match: true, secret },
          { label: 'reconstructed T1 / T2 (G1)', observed: ['public-T1', 'public-T2'] }]),
        step('credential_pairing', 'pass', [{ label: 'e(Abar,W) = e(Bbar,G2)', expected: true, observed: true, match: true }]),
        step('device_pairing', 'pass', [{ label: 'hash-to-curve point Q (G2)', observed: 'public-Q' }])], secret },
        responseEvidence: { proof: secret }, paymentResult: { outcome: 'EXECUTED', receipt: { orderId: 'order-1', transactionHash: 'public-transaction', transactionStatus: 'success', localTestOnly: true, secret }, walletPayload: { signature: secret } } },
      log: [{ data: { walletPayload: secret } }],
    },
  };
}

test('protocol snapshots retain only the documented public protocol and payment observations', () => {
  const state = fixture(), snapshot = protocolSnapshot(state);
  assert.equal(JSON.stringify(snapshot).includes(secret), false, 'unknown nested values, secret keys, Owner tokens and wallet payloads must be absent');
  assert.equal(snapshot.issuerProfile.verificationMethod.publicKeyMultibase, 'public-key');
  assert.equal(snapshot.originalCredential.proof.proofValue, 'public-standard-proof');
  assert.equal(snapshot.derivedCredential.credentialSubject.organization, 'demo-only', 'retain an actually exposed field so the view can detect unexpected disclosure');
  assert.equal(snapshot.credential.attributes[0].value, 'payer');
  assert.equal(snapshot.device.publicKeyFingerprint, 'public-fingerprint');
  assert.equal(snapshot.device.modes['bbs-bls'].signatures, 2);
  assert.equal(snapshot.cryptography.presentationHeader, 'public-PH');
  assert.equal(snapshot.deviceRequest.context.w3cPresentationHash, 'public-hVC');
  assert.equal(snapshot.presentation.proof.responses.keyRandomizer, 'public-zk', 'public proof response is retained; private randomizer is not');
  assert.deepEqual(snapshot.verificationTrace.steps[0].evidence[1].observed, ['public-T1', 'public-T2']);
  assert.equal(snapshot.paymentResult.receipt.transactionHash, 'public-transaction');
  assert.equal(snapshot.ownerApproved, true);
  state.manual.presentation.Abar = 'later-point';
  state.manual.verificationResult.verificationTrace.steps[0].evidence[1].observed[0] = 'later-commitment';
  assert.equal(snapshot.presentation.Abar, 'public-Abar');
  assert.equal(snapshot.verificationTrace.steps[0].evidence[1].observed[0], 'public-T1', 'a retained observation cannot be rewritten by later state mutation');
});

test('blind device observations never acquire the local cleartext context', () => {
  const state = fixture();
  state.manual.deviceRequest = { version: 1, suite: 'public-suite', mode: 'bbs-blind-bls', blindedPoint: 'public-Q-prime', context: { bodyHash: 'should-not-be-device-input' } };
  const snapshot = protocolSnapshot(state);
  assert.equal(snapshot.deviceRequest.blindedPoint, 'public-Q-prime');
  assert.equal(Object.hasOwn(snapshot.deviceRequest, 'context'), false);
  assert.equal(snapshot.cryptography.w3cPresentationHash, 'public-hVC', 'the separate A-local hash remains available without being labelled a device input');
});

test('missing state and malformed nested evidence do not create data or passing checks', () => {
  const empty = protocolSnapshot(undefined);
  assert.equal(empty.device, null); assert.equal(empty.cryptography, null); assert.equal(empty.presentation, null);
  assert.equal(empty.ownerApproved, null); assert.equal(empty.walletSigned, null); assert.equal(empty.verificationTrace, null);
  assert.ok(Object.values(protocolChecks(empty)).every(group => group.status === 'skipped'));
  const state = fixture();
  state.manual.verificationResult.verificationTrace.steps[0].evidence.push({ label: 'Unexpected object', observed: { token: secret }, expected: [[secret]], match: 'true' });
  const row = protocolSnapshot(state).verificationTrace.steps[0].evidence.at(-1);
  assert.deepEqual(row, { label: 'Unexpected object' });
  assert.equal(JSON.stringify(row).includes(secret), false);
});

test('group checks require each actual Agent B check and preserve its expected, observed and match values', () => {
  const state = fixture();
  state.manual.verificationResult.verificationTrace.steps.push(step('w3c_bbs'), step('request_binding'), step('vc_device_binding'));
  const checks = protocolChecks(protocolSnapshot(state));
  assert.ok(Object.values(checks).every(group => group.status === 'pass'));
  assert.deepEqual(checks.knowledge.evidence[0], { stepId: 'knowledge', label: 'Fiat-Shamir challenge', expected: 'public-c', observed: 'public-c', match: true });
  state.manual.verificationResult.verificationTrace.steps = [step('knowledge')];
  assert.equal(protocolChecks(protocolSnapshot(state)).knowledge.status, 'skipped', 'NIZK alone does not establish the credential pairing');
  state.manual.verificationResult.verificationTrace.source = 'agent-a';
  state.manual.verificationResult.verificationTrace.steps = [step('w3c_bbs')];
  assert.equal(protocolChecks(protocolSnapshot(state)).standard.status, 'skipped', 'A cannot assert that a B check actually ran');
});

test('a real missing-device rejection preserves the earlier standard pass and leaves later equations unexecuted', () => {
  const state = fixture();
  state.manual.lastAttack = { expected: 'W3C_DEVICE_PROOF_REQUIRED', pass: true, actual: 'W3C_DEVICE_PROOF_REQUIRED',
    verificationTrace: { source: 'agent-b', outcome: 'fail', steps: [step('w3c_bbs'), step('request_binding'),
      step('vc_device_binding', 'fail', [{ label: 'bindingId / mode / device contribution', expected: ['id', 'bbs-bls', true], observed: [null, null, false] }]),
      step('knowledge', 'skipped'), step('credential_pairing', 'skipped'), step('device_pairing', 'skipped')] } };
  const checks = protocolChecks(protocolSnapshot(state));
  assert.equal(checks.standard.status, 'pass'); assert.equal(checks.binding.status, 'fail');
  assert.equal(checks.knowledge.status, 'skipped'); assert.equal(checks.device.status, 'skipped');
  delete state.manual.lastAttack.verificationTrace;
  assert.equal(protocolSnapshot(state).verificationTrace, null, 'do not replace a missing negative-case trace with an old positive result');
});

test('a preparation failure and contradictory or duplicate results cannot be promoted to success', () => {
  const state = fixture();
  state.manual.lastError = { code: 'DBAC_DEVICE_LOCKED', message: 'Device is locked' };
  assert.equal(protocolSnapshot(state).verificationTrace, null);
  assert.ok(Object.values(protocolChecks(protocolSnapshot(state))).every(group => group.status === 'skipped'));
  delete state.manual.lastError;
  state.manual.verificationResult.verificationTrace.steps = [step('device_pairing', 'pass', [{ label: 'pairing comparison', expected: true, observed: false, match: false }])];
  assert.equal(protocolChecks(protocolSnapshot(state)).device.status, 'fail');
  state.manual.verificationResult.verificationTrace.steps = [step('w3c_bbs'), step('w3c_bbs')];
  assert.equal(protocolChecks(protocolSnapshot(state)).standard.status, 'pending', 'ambiguous duplicate steps do not establish one observed check');
});
