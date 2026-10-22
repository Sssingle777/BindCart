import test from 'node:test';
import assert from 'node:assert/strict';
import { appendFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { frameworkFixture } from '../../作品源码/BindCart/app/test/fixtures/framework.mjs';

const output = new URL('./consistency-observations.jsonl', import.meta.url);
if (existsSync(output)) throw new Error('Preserve existing observations; run from a fresh directory.');
const record = row => appendFile(output, JSON.stringify({ at: new Date().toISOString(), ...row })+'\n');
const step = (trace, id) => trace.steps.find(s => s.id === id);
for (const mode of ['bbs-bls', 'bbs-blind-bls']) {
  test(`${mode}: full holder profile consumes one concurrent challenge exactly once`, async t => {
    const f = await frameworkFixture(t);
    await f.session.issue({mode});
    const prepared = await f.session.prepare({mode,phase:'proposal'});
    const results = await Promise.allSettled([f.session.transmit(prepared),f.session.transmit(prepared)]);
    assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
    const denied=results.find(r=>r.status==='rejected');
    assert.equal(denied.reason.code,'DBAC_REPLAY');
    await record({mode,scenario:'concurrent-challenge',expectationMet:true,accepted:1,rejected:1,
      rejectionCode:denied.reason.code,scope:'proposal authentication; no settlement backend configured'});
  });
  test(`${mode}: invalid holder transcript leaves the legitimate challenge usable`, async t => {
    const f=await frameworkFixture(t);
    await f.session.issue({mode});
    const first=await f.session.prepare({mode,phase:'proposal'});
    const other=await f.session.prepare({mode,phase:'proposal'});
    let rejection;
    await assert.rejects(f.session.transmit({...first,holderProof:other.holderProof}),error=>{
      rejection=error;assert.equal(error.code,'HOLDER_BINDING_MISMATCH');
      assert.equal(step(error.verificationTrace,'holder_signature').status,'fail');
      assert.equal(step(error.verificationTrace,'consume').status,'skipped');return true;
    });
    assert.equal((await f.session.transmit(first)).accepted,true);
    await record({mode,scenario:'invalid-proof-recovery',expectationMet:true,
      rejectionCode:rejection.code,consumeOnInvalid:'skipped',originalChallengeAcceptedAfter:true});
  });
  test(`${mode}: actual issuer outage rejects an otherwise valid joint proof`, async t => {
    const f=await frameworkFixture(t);
    await f.session.issue({mode});
    const control=await f.session.prepare({mode,phase:'proposal'});
    assert.equal((await f.session.transmit(control)).accepted,true);
    const prepared=await f.session.prepare({mode,phase:'proposal'});
    await f.issuerService.close();
    let rejection;
    await assert.rejects(f.session.transmit(prepared),error=>{
      rejection=error;assert.equal(error.code,'W3C_CREDENTIAL_STATUS_UNAVAILABLE');
      for(const id of ['w3c_bbs','device_pairing','holder_signature'])assert.equal(step(error.verificationTrace,id).status,'pass');
      assert.equal(step(error.verificationTrace,'credential_status').status,'fail');
      assert.equal(step(error.verificationTrace,'consume').status,'skipped');
      assert.equal(step(error.verificationTrace,'execution').status,'skipped');return true;
    });
    await record({mode,scenario:'issuer-outage',expectationMet:true,rejectionCode:rejection.code,
      genuineCryptoChecks:'pass',consume:'skipped',execution:'skipped',authenticationIssued:false});
  });
}
