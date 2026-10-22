import { existsSync } from 'node:fs';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import { mkdtemp, rm, writeFile, appendFile } from 'node:fs/promises';
import { tmpdir, cpus, totalmem, platform, release, arch } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateIdentity } from '../../作品源码/BindCart/app/lib/identity.mjs';
import { serializeIdentity } from '../../作品源码/BindCart/app/lib/protocol.mjs';
import { createLocalX402Environment, createX402Backend, createX402Payer } from '../../作品源码/BindCart/app/lib/x402-payment.mjs';
import { createDbacPaymentSession } from '../../作品源码/BindCart/app/lib/dbac/payment-session.mjs';
import { DBAC_PAYMENT_PROFILE } from '../../作品源码/BindCart/app/lib/dbac/payment-policy.mjs';

// Dedicated test services and local TEST_USDC only. Never read app/var or log capabilities.
const output = fileURLToPath(new URL('./', import.meta.url));
const root = new URL('../../作品源码/BindCart/app/', import.meta.url);
const kind='payment-consistency';
if(existsSync(join(output,'payment-consistency.json')))throw new Error('Existing evidence must be preserved.');
const modes = ['bbs-bls', 'bbs-blind-bls'];
const directory = await mkdtemp(join(tmpdir(), 'shoppingauth-figure-audit-'));
const children = [], tokens = [];
const token = () => { const value = randomBytes(32).toString('base64url'); tokens.push(value); return value; };
const clean = value => { let s = String(value); for (const t of tokens) s = s.replaceAll(t, '[redacted]'); return s; };
let environment, closing = false;
async function close() {
  if (closing) return; closing = true;
  await Promise.all(children.map(child => new Promise(done => {
    if (child.exitCode !== null || child.signalCode !== null) return done();
    child.once('exit', done); child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 3000); timer.unref();
  })));
  await environment?.close();
  await rm(directory, { recursive: true, force: true });
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => close().then(() => process.exit(130)));
async function launch(file, config) {
  return new Promise((resolve, reject) => {
    const child = fork(new URL(file, root), [], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
    children.push(child); let diagnostics = '';
    child.stderr.on('data', v => { diagnostics = (diagnostics + v).slice(-2500); });
    const timer = setTimeout(() => reject(new Error(`${file}: startup timeout`)), 30000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); if (!closing) reject(new Error(clean(`${file}: ${code}: ${diagnostics}`))); });
    child.once('message', value => { clearTimeout(timer); value.error ? reject(new Error(clean(value.error))) : resolve({ ...value, child }); });
    child.send(config);
  });
}

async function json(url,body,headers){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(body),signal:AbortSignal.timeout(90000)});const v=await r.json();if(!r.ok)throw Object.assign(new Error(v.error?.message),{code:v.error?.code});return v;}
const save=(name,data)=>writeFile(join(output,name),JSON.stringify(data,null,2));
try {
  const deviceToken = token(), issuerToken = token(), statusToken = token(), proposalToken = token(), ownerKey = token();
  const device = await launch('dbac-role.mjs', { role: 'device', accessToken: deviceToken, port: 0 });
  const issuer = await launch('dbac-role.mjs', { role: 'issuer', w3c: true, requireHolderProof: true, accessToken: issuerToken, statusToken, statePath: join(directory, 'status.json'), devicePublicKeys: device.publicKeys, port: 0 });
  const legacyIssuer = generateIdentity('test legacy issuer'), holder = generateIdentity('test holder policy'), inactiveDevice = generateIdentity('inactive device policy'), verifierIdentity = generateIdentity('test Agent B');
  const owner = await launch('owner.mjs', { holderDid: holder.did, verifierDid: verifierIdentity.did, trustedIssuers: [legacyIssuer.did], dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer, proposalToken, uiToken: ownerKey, port: 0 });
  const verifier = await launch('agent-b.mjs', { identity: serializeIdentity(verifierIdentity), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], adminToken: token(), ledgerPath: join(directory, 'verifier.sqlite'), port: 0, dbac: { issuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c, requireHolderProof: true, statusSource: { baseUrl: issuer.baseUrl, accessToken: statusToken } } });
  environment = await createLocalX402Environment({ stateDir: join(directory, 'chain'), trustedIssuers: [legacyIssuer.did], trustedAuthorizers: [owner.did], holderDid: holder.did, deviceDid: inactiveDevice.did, verifierDid: verifierIdentity.did, dbacIssuerPublicKey: issuer.publicKey, w3cIssuer: issuer.w3c.issuer, isCredentialRevoked: async () => true,
    async isDbacCredentialRevoked(bindingId) {
      const state = await json(`${issuer.baseUrl}/credential/status`, { bindingId }, { 'X-DBAC-Access': statusToken });
      if (state.bindingId !== bindingId || !['valid', 'revoked'].includes(state.status)) throw new Error('Unconfirmed credential status');
      return state.status === 'revoked';
    },
  });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('x402 configure timeout')), 10000);
    verifier.child.once('message', value => { clearTimeout(timer); value.stage === 'x402-ready' ? resolve() : reject(new Error(value.error)); });
    verifier.child.send({ stage: 'configure-x402', backendConfig: environment.backendConfig });
  });
  const backend = createX402Backend(environment.backendConfig), payer = createX402Payer(environment.payerConfig);
  const session = () => createDbacPaymentSession({ baseUrl: verifier.baseUrl, verifierDid: verifierIdentity.did,
    issuer: { publicKey: issuer.publicKey, w3c: issuer.w3c, baseUrl: issuer.baseUrl, accessToken: issuerToken },
    device: { publicKeys: device.publicKeys, baseUrl: device.baseUrl, accessToken: deviceToken },
    owner: { did: owner.did, baseUrl: owner.baseUrl, proposalToken }, x402Payer: payer, paymentInfo: environment.publicInfo, getLedger: () => backend.snapshot() });

 const observations=[];const initial=await backend.snapshot();
 for(const mode of modes){
   const s=session();await s.issue({mode});const state=await s.newOrder({mode,amountMinor:10000});const before=await backend.snapshot();
   const proposed=await s.transmit(await s.prepare({mode,phase:'proposal'}));
   const proposal=await json(`${owner.baseUrl}/proposals`,{profile:DBAC_PAYMENT_PROFILE,payment:state.order,dbacEvidence:proposed.responseEvidence},{'X-Owner-Proposal':proposalToken});
   const approved=await json(`${owner.baseUrl}/api/proposals/${proposal.id}/approve`,{confirmed:true,payment:proposal.payment,credentialHash:proposal.credentialHash},{'X-Owner-UI-Key':ownerKey});
   const authorization=approved.authorization.token;
   const authorized=await s.transmit(await s.prepare({mode,phase:'authorize',authorization}));
   const payload=await payer.createPayload({profile:DBAC_PAYMENT_PROFILE,payment:state.order,authorization,paymentRequired:authorized.task.status.message.metadata['x402.payment.required'],responseEvidence:authorized.responseEvidence});
   const options={mode,phase:'settle',authorization,payload,continuation:authorized.task};
   const prepared=await s.prepare(options);const settled=await s.transmit(prepared);assert.equal(settled.paymentResult.outcome,'EXECUTED');
   const afterPaid=await backend.snapshot();assert.equal(afterPaid.executionCount,before.executionCount+1);
   let replayCode;await assert.rejects(s.transmit(prepared),e=>{replayCode=e.code;return e.code==='DBAC_REPLAY';});
   const fresh=await s.prepare(options);const retried=await s.transmit(fresh);assert.notEqual(fresh.context.challengeId,prepared.context.challengeId);
   assert.equal(retried.paymentResult.outcome,'ALREADY_PROCESSED');assert.deepEqual(retried.paymentResult.receipt,settled.paymentResult.receipt);
   const afterRetry=await backend.snapshot();assert.equal(afterRetry.executionCount,afterPaid.executionCount);assert.deepEqual(afterRetry.accounts,afterPaid.accounts);
   const payerBefore=before.accounts.find(x=>x.id===state.order.payerAccount).balanceMinor,payerAfter=afterRetry.accounts.find(x=>x.id===state.order.payerAccount).balanceMinor;
   const payeeBefore=before.accounts.find(x=>x.id===state.order.payeeAccount).balanceMinor,payeeAfter=afterRetry.accounts.find(x=>x.id===state.order.payeeAccount).balanceMinor;
   assert.equal(payerBefore-payerAfter,10000);assert.equal(payeeAfter-payeeBefore,10000);
   observations.push({mode,orderId:state.order.orderId,expectationMet:true,firstOutcome:settled.paymentResult.outcome,exactReplayCode:replayCode,freshRetryOutcome:retried.paymentResult.outcome,sameReceipt:true,freshChallenge:true,executionDelta:afterRetry.executionCount-before.executionCount,payerDebitMinor:payerBefore-payerAfter,payeeCreditMinor:payeeAfter-payeeBefore,transactionHash:settled.paymentResult.receipt.transactionHash});
   await save('payment-consistency.json',{observations,initial,latest:afterRetry});console.log(`${mode}: EXECUTED -> replay DBAC_REPLAY -> fresh retry ALREADY_PROCESSED; 1 debit`);
 }
 const final=await backend.snapshot();assert.equal(final.executionCount-initial.executionCount,2);await save('payment-consistency.json',{observations,initial,final,allPassed:true});
}catch(error){await save('payment-consistency-fatal.json',{code:error.code??error.name,message:clean(error.message),stack:clean(error.stack)});console.error(clean(error.stack));process.exitCode=1;}finally{await close();}
