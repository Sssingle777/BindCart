import test from 'node:test';
import assert from 'node:assert/strict';
import { frameworkFixture } from './fixtures/framework.mjs';

const mode = 'bbs-bls';
const act = async (session, action) => { const state = await session.state({mode}); return session.manual({mode,action,...(state.manual.attemptId ? {attemptId:state.manual.attemptId}: {})}); };
async function prove(session) { for(const action of ['begin-proposal','derive-vc','device-sign','prove']) await act(session,action); return act(session,'verify'); }

test('management creates real independent devices, selects credentials, counts calls and enforces revocation with fresh complete proofs', async t => {
 const {session}=await frameworkFixture(t);
 let inventory=await session.inventory({mode}); assert.equal(inventory.devices.length,1);
 await session.issue({mode}); const first=(await session.state({mode})).currentCredentialId;
 let verified=await prove(session); assert.equal(verified.manual.verificationResult.accepted,true);
 assert.ok(verified.manual.holderProof); assert.equal(verified.manual.verificationResult.wire.proof.verifiableCredential.credentialSubject.holderDid,verified.holder.did);
 await session.manage({mode,action:'create-device'}); inventory=await session.inventory({mode});
 const secondDevice=inventory.devices.find(d=>d.id!=='default'); assert.ok(secondDevice);
 await session.manage({mode,action:'select-device',deviceId:secondDevice.id});
 let state=await session.state({mode}); assert.equal(state.manual.verificationResult,null); assert.equal(state.credential,null); assert.equal(state.authorization,null);
 await session.issue({mode}); const second=(await session.state({mode})).currentCredentialId; assert.notEqual(first,second);
 verified=await prove(session); assert.equal(verified.manual.verificationResult.accepted,true);
 inventory=await session.inventory({mode}); assert.ok(inventory.devices.find(d=>d.id===secondDevice.id).signCount>=2);
 assert.ok(inventory.devices.find(d=>d.id===secondDevice.id).logs.some(l=>l.operation==='sign'));
 await session.manage({mode,action:'select-credential',credentialId:first}); state=await session.state({mode});
 assert.equal(state.currentDeviceId,'default'); assert.equal(state.currentCredentialId,first); assert.equal(state.manual.stage,'IDLE');
 await session.manage({mode,action:'revoke',credentialId:first}); assert.equal((await session.state({mode})).credentialStatus.status,'revoked');
 await assert.rejects(prove(session),{code:'W3C_CREDENTIAL_REVOKED'});
 state=await session.state({mode}); assert.ok(state.manual.holderProof); assert.ok(state.manual.presentation.deviceSignature); assert.equal(state.manual.verificationResult,null);
 assert.equal(state.ledger.executionCount,0);
 const json=JSON.stringify(state); assert.doesNotMatch(json,/"(?:privateKey|secretKey|holderIdentity|cancelToken|accessToken)"\s*:/);
});

test('changing disclosure invalidates proof, optional values enter only explicitly derived B requests, required holder binding cannot be removed', async t=>{
 const {session}=await frameworkFixture(t); await session.issue({mode});
 let valid=await prove(session), wire=valid.manual.verificationResult.wire;
 assert.equal(wire.proof.verifiableCredential.credentialSubject.organization,undefined);
 assert.equal(wire.proof.verifiableCredential.credentialSubject.holderLabel,undefined);
 const oldAttempt=valid.manual.attemptId;
 await session.manage({mode,action:'disclosure',optionalFields:['organization']});
 let state=await session.state({mode}); assert.equal(state.manual.verificationResult,null); assert.equal(state.manual.holderProof,null);
 valid=await prove(session); wire=valid.manual.verificationResult.wire;
 assert.notEqual(valid.manual.attemptId,oldAttempt); assert.equal(typeof wire.proof.verifiableCredential.credentialSubject.organization,'string');
 assert.equal(wire.proof.verifiableCredential.credentialSubject.holderLabel,undefined);
 assert.equal(typeof wire.proof.verifiableCredential.credentialSubject.holderDid,'string');
 await assert.rejects(session.manage({mode,action:'disclosure',optionalFields:['holderDid']}),{code:'DISCLOSURE_POLICY_INVALID'});
 await assert.rejects(session.manual({mode,action:'verify',attemptId:oldAttempt}),{code:'DBAC_MANUAL_ATTEMPT_MISMATCH'});
});

test('concurrent use of one real proof issues one authentication result, failures preserve challenge for valid control',async t=>{
 const {session}=await frameworkFixture(t); await session.issue({mode});
 const prepared=await session.prepare({mode,phase:'proposal'}); const missing={...prepared}; delete missing.holderProof;
 await assert.rejects(session.transmit(missing),{code:'HOLDER_PROOF_REQUIRED'});
 const results=await Promise.allSettled([session.transmit(prepared),session.transmit(prepared)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
 assert.equal(results.find(r=>r.status==='rejected').reason.code,'DBAC_REPLAY');
});

test('discard after successful verification stays usable even after the consumed challenge expires and is pruned', async t => {
  const { session } = await frameworkFixture(t);
  await session.issue({ mode });
  const verified = await prove(session), previousId = verified.manual.attemptId;
  const realFetch = globalThis.fetch, initialTime = Date.now();
  let cancellationCalls = 0;
  t.mock.method(globalThis, 'fetch', async (...args) => {
    if (String(args[0]).endsWith('/dbac/payment/cancel')) cancellationCalls++;
    return realFetch(...args);
  });
  // Clock fault injection only: no real wait and no synthetic crypto verdict.
  // A fresh real challenge makes B prune the expired consumed one.
  t.mock.method(Date, 'now', () => initialTime + 61000);
  await session.prepare({ mode, phase: 'proposal' });
  const discarded = await act(session, 'discard');
  assert.equal(discarded.manual.stage, 'DISCARDED');
  assert.equal(discarded.manual.active, false);
  assert.equal(discarded.manual.verificationResult, null);
  assert.equal(cancellationCalls, 0, 'a confirmed successful response already removed its cancellation capability');
  const next = await act(session, 'begin-proposal');
  assert.notEqual(next.manual.attemptId, previousId);
  assert.equal(next.manual.stage, 'CHALLENGE_READY');
});

test('discarding a fully expired unconsumed challenge succeeds without confusing expiry with a missing cancellation permission', async t => {
  const { session } = await frameworkFixture(t);
  await session.issue({ mode });
  await act(session, 'begin-proposal');
  const initialTime = Date.now();
  t.mock.method(Date, 'now', () => initialTime + 61000);
  assert.equal((await session.state({ mode })).manual.stage, 'EXPIRED');
  const discarded = await act(session, 'discard');
  assert.equal(discarded.manual.stage, 'DISCARDED');
  assert.equal(discarded.manual.active, false);
  assert.equal(discarded.manual.lastError, null);
});

test('a cancelled transport failure preserves the private cancellation handle for a real retry', async t => {
  const { session } = await frameworkFixture(t);
  await session.issue({ mode }); await act(session, 'begin-proposal');
  const realFetch = globalThis.fetch;
  let cancellationCalls = 0, firstPrivateHandle;
  t.mock.method(globalThis, 'fetch', async (...args) => {
    if (String(args[0]).endsWith('/dbac/payment/cancel')) {
      const body = JSON.parse(args[1].body); cancellationCalls++;
      if (cancellationCalls === 1) { firstPrivateHandle = body.cancelToken; throw new TypeError('TEST_CANCEL_NETWORK_FAILURE'); }
      assert.equal(body.cancelToken, firstPrivateHandle, 'retry keeps the same per-attempt cancellation capability');
    }
    return realFetch(...args);
  });
  await assert.rejects(act(session, 'discard'), { code: 'DBAC_PAYMENT_TRANSPORT' });
  const pending = await session.state({ mode });
  assert.equal(pending.manual.active, true);
  assert.equal(pending.manual.stage, 'CHALLENGE_READY');
  assert.doesNotMatch(JSON.stringify(pending), /"cancelToken"\s*:/);
  const discarded = await act(session, 'discard');
  assert.equal(discarded.manual.stage, 'DISCARDED');
  assert.equal(cancellationCalls, 2, 'second discard actually reached B and did not merely clear local state');
});

test('an in-flight issue prevents mode-local device, credential and order mutations until the signed result is installed', async t => {
  const { session } = await frameworkFixture(t);
  const realFetch = globalThis.fetch;
  let release, entered;
  const gate = new Promise(resolve => { release = resolve; });
  const enrollmentStarted = new Promise(resolve => { entered = resolve; });
  t.after(() => release());
  let delayed = false;
  t.mock.method(globalThis, 'fetch', async (...args) => {
    if (!delayed && String(args[0]).endsWith('/enroll/challenge')) { delayed = true; entered(); await gate; }
    return realFetch(...args);
  });
  const issuing = session.issue({ mode });
  await enrollmentStarted;
  try {
    await assert.rejects(session.manage({ mode, action: 'select-device', deviceId: 'default' }), { code: 'DBAC_OPERATION_BUSY' });
    await assert.rejects(session.manage({ mode, action: 'select-credential', credentialId: 'not-yet-issued' }), { code: 'DBAC_OPERATION_BUSY' });
    await assert.rejects(session.newOrder({ mode }), { code: 'DBAC_OPERATION_BUSY' });
    await assert.rejects(session.issue({ mode }), { code: 'DBAC_OPERATION_BUSY' });
  } finally { release(); }
  const issued = await issuing;
  assert.equal(issued.currentDeviceId, 'default');
  assert.equal(issued.w3c.originalCredential.credentialSubject.holderDid, issued.holder.did);
  assert.equal((await prove(session)).manual.verificationResult.accepted, true);
  await act(session, 'discard');
  const next = await session.manage({ mode, action: 'issue' });
  assert.notEqual(next.currentCredentialId, issued.currentCredentialId, 'management issue may call its internal issue action without self-deadlocking');
});
