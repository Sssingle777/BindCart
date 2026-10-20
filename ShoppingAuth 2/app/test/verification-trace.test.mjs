import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { generateIdentity, issueCredential, signJws, verifyJws } from '../lib/identity.mjs';
import { createVerifier } from '../lib/verifier.mjs';
import { createSession } from '../lib/session.mjs';
import { createDbacDevice, createDbacIssuer } from '../lib/dbac/services.mjs';
import { createDbacSession } from '../lib/dbac/session.mjs';
import { SCOPE, POP_TYP, DEVICE_POP_TYP, digest, unix, messageRpc, prepareRequest, transmit } from '../lib/protocol.mjs';

function accepted(trace, profile) {
  assert.equal(trace.profile, profile);
  assert.equal(trace.source, 'agent-b');
  assert.equal(trace.outcome, 'pass');
  assert.ok(trace.steps.length > 10);
  assert.ok(trace.steps.every(step => step.status === 'pass'));
  assert.doesNotMatch(JSON.stringify(trace), /secretKey|privateKey|accessToken|Bearer [A-Za-z0-9_-]+\./);
}
function stopped(trace, id, code) {
  assert.equal(trace.outcome, 'fail');
  const position = trace.steps.findIndex(step => step.id === id);
  assert.notEqual(position, -1);
  assert.ok(trace.steps.slice(0, position).every(step => step.status === 'pass'));
  assert.equal(trace.steps[position].status, 'fail');
  assert.equal(trace.steps[position].code, code);
  assert.ok(trace.steps.slice(position + 1).every(step => step.status === 'skipped'));
}
async function rejection(action, id, code) {
  await assert.rejects(action, error => { assert.equal(error.code, code); stopped(error.verificationTrace, id, String(code)); return true; });
}

test('identity trace describes actual check order, failures and untouched challenges', async t => {
  const issuer = generateIdentity('Issuer'), agentA = generateIdentity('A'), b = generateIdentity('B'), device = generateIdentity('fixture');
  const adminToken = randomUUID();
  const verifier = createVerifier({ identity: b, trustedIssuers: new Set([issuer.did]), adminToken });
  const baseUrl = await verifier.listen(); t.after(() => verifier.close());
  const credential = issueCredential(issuer, { subjectDid: agentA.did, audience: b.did, scopes: [SCOPE], deviceDid: device.did });
  const prepare = async (rpc = messageRpc('trace verification')) => {
    const request = await prepareRequest({ identity: agentA, verifierDid: b.did, baseUrl, credential, rpc });
    const p = verifyJws(request.token, { typ: POP_TYP }).payload;
    return { ...request, deviceDid: device.did, deviceProof: signJws({ iss: device.did, sub: p.iss, aud: p.aud, iat: unix(), exp: p.exp, jti: randomUUID(), holderProofHash: digest(request.token), credentialHash: digest(p.credential), challengeId: p.challengeId, nonce: p.nonce, method: p.method, target: p.target, bodyHash: p.bodyHash }, device, DEVICE_POP_TYP) };
  };
  const request = await prepare();
  await rejection(() => transmit({ ...request, rawBody: request.rawBody.replace('trace verification', 'tampered') }), 'request_binding', 'REQUEST_BINDING_MISMATCH');
  const noDevice = { ...request }; delete noDevice.deviceProof;
  await rejection(() => transmit(noDevice), 'device', 'DEVICE_PROOF_REQUIRED');
  const result = await transmit(request);
  accepted(result.verificationTrace, 'identity');
  assert.ok(!JSON.stringify(result.verificationTrace).includes(credential));
  assert.ok(!JSON.stringify(result.verificationTrace).includes(request.token));
  await rejection(() => transmit(request), 'replay', 'REPLAYED_CHALLENGE');
  const invalidRpc = await prepare({ jsonrpc: '2.0', id: 'unsupported', method: 'unsupported/method', params: {} });
  await rejection(() => transmit(invalidRpc), 'execution', -32601);
  const session = createSession({ issuer, agentA, verifierDid: b.did, baseUrl, adminToken, device: { did: device.did, baseUrl, accessToken: randomBytes(32).toString('base64url') } });
  await assert.rejects(() => session.invoke(), error => {
    assert.equal(error.code, 'NO_CREDENTIAL');
    assert.equal(error.verificationTrace.source, 'agent-a');
    stopped(error.verificationTrace, 'preparation', 'NO_CREDENTIAL'); return true;
  });
});

test('both DBAC modes retain actual disclosure, proof and replay failure boundaries', { timeout: 30000 }, async t => {
  const accessToken = randomBytes(32).toString('base64url');
  const device = createDbacDevice({ accessToken }), deviceUrl = await device.listen(); t.after(() => device.close());
  const devicePublicKeys = device.publicInfo().publicKeys;
  const issuer = createDbacIssuer({ accessToken, devicePublicKeys }), issuerUrl = await issuer.listen(); t.after(() => issuer.close());
  const b = generateIdentity('B'), publicKey = issuer.publicInfo().publicKey;
  const verifier = createVerifier({ identity: b, trustedIssuers: new Set(), adminToken: randomUUID(), dbac: { issuerPublicKey: publicKey }, dbacOnly: true });
  const baseUrl = await verifier.listen(); t.after(() => verifier.close());
  const session = createDbacSession({ baseUrl, verifierDid: b.did, issuer: { baseUrl: issuerUrl, accessToken, publicKey }, device: { baseUrl: deviceUrl, accessToken, publicKeys: devicePublicKeys } });
  for (const mode of ['bbs-bls', 'bbs-blind-bls']) {
    await t.test(mode, async () => {
      await session.issue({ mode });
      const prepared = await session.prepare({ mode, text: 'trace verification' });
      const bodyTampered = structuredClone(prepared); bodyTampered.rawBody = bodyTampered.rawBody.replace('trace verification', 'tampered');
      await rejection(() => session.transmit(bodyTampered), 'request_binding', 'DBAC_BODY_MISMATCH');
      const policyTampered = structuredClone(prepared); policyTampered.presentation.disclosed[0].value = 'administrator';
      await rejection(() => session.transmit(policyTampered), 'disclosure', 'DBAC_POLICY_REJECTED');
      const proofTampered = structuredClone(prepared);
      const scalar = proofTampered.presentation.proof.responses.inverseR1;
      proofTampered.presentation.proof.responses.inverseR1 = scalar.slice(0, -1) + (scalar.at(-1) === '0' ? '1' : '0');
      await rejection(() => session.transmit(proofTampered), 'knowledge', 'DBAC_PROOF_INVALID');
      const missing = structuredClone(prepared); delete missing.presentation.deviceSignature;
      await rejection(() => session.transmit(missing), 'proof_structure', 'DBAC_INVALID_INPUT');
      const result = await session.transmit(prepared);
      accepted(result.verificationTrace, 'dbac');
      assert.ok(!JSON.stringify(result.verificationTrace).includes(devicePublicKeys[mode]));
      await rejection(() => session.transmit(prepared), 'replay', 'DBAC_REPLAY');
      await session.deviceLock({ mode, locked: true });
      await rejection(() => session.invoke({ mode }), 'preparation', 'DBAC_DEVICE_LOCKED');
      await session.deviceLock({ mode, locked: false });
    });
  }
});
