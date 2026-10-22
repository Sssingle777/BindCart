import { existsSync } from 'node:fs';
import { bench } from './instrument.mjs';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
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
const kind = 'compute';
if (['samples.jsonl','stages.jsonl','orders.jsonl','results.json'].some(p=>existsSync(join(output,p)))) throw new Error('Existing evidence: use a fresh output directory.');
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
    const child = fork(new URL(file, root), [], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'], execArgv: ['--import',new URL('./instrument.mjs',import.meta.url).href], env: {...process.env,SHOPPINGAUTH_BENCH_ROLE:config.role??(file==='agent-b.mjs'?'agent-b':'owner')} });
    children.push(child); let diagnostics = '';
    child.stderr.on('data', v => { diagnostics = (diagnostics + v).slice(-2500); });
    const timer = setTimeout(() => reject(new Error(`${file}: startup timeout`)), 30000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('exit', code => { clearTimeout(timer); if (!closing) reject(new Error(clean(`${file}: ${code}: ${diagnostics}`))); });
    child.once('message', value => { clearTimeout(timer); value.error ? reject(new Error(clean(value.error))) : resolve({ ...value, child }); });
    child.send(config);
  });
}

async function json(url, body, headers) {
  const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json',...headers},body:JSON.stringify(body),signal:AbortSignal.timeout(90000)});
  const value=await response.json();
  if(!response.ok)throw Object.assign(new Error(value.error?.message??'HTTP error'),{code:value.error?.code,status:response.status});
  return value;
}
const save=(name,value)=>writeFile(join(output,name),JSON.stringify(value,null,2));
function control(child,action,context=null) {
  return new Promise((resolve,reject)=>{
    const id=randomUUID();
    const handle=message=>{if(message?.kind!=='compute-control-reply'||message.id!==id)return;clearTimeout(timer);child.off('message',handle);resolve(message);};
    const timer=setTimeout(()=>{child.off('message',handle);reject(new Error('Instrumentation control timed out'));},10000);
    child.on('message',handle);child.send({kind:'compute-control',id,action,context});
  });
}
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

  assert.equal(globalThis.__shoppingAuthComputeBench,bench,'Run using --import ./instrument.mjs');
  const metadata={startedAt:new Date().toISOString(),node:process.version,cpu:cpus()[0]?.model,logicalCpus:cpus().length,memoryGiB:totalmem()/1024**3,platform:platform(),release:release(),arch:arch(),
    samplePlan:'Two warm-up orders per mode excluded, then 10 sequential measured orders per mode. Modes alternate; the first mode alternates every pair. 30 measured invocations per operation per mode.',
    measurement:'In-memory wrappers time original production function calls during real prepare/transmit, independent software eSIM, Agent B, Owner and Ganache. performance.now elapsed time plus process.cpuUsage user/system deltas. Wrappers append in-memory samples after timing; IPC and evidence writes happen after each phase.',
    scope:'Function-level local computation includes function-internal hashing, parsing, validation, RDF canonicalization, encoding, random generation and trace writes. No HTTP wait, credential-status network query, Owner approval, wallet, chain RPC or receipt signing included in the selected operations. B crypto sum is vcVerify + bindingVerify + holderVerify; it is not all B service logic.',
    cpuCaveat:'process.cpuUsage is per-process accounting and may include GC/runtime/background worker activity; it is supporting data, not exclusive single-thread CPU time. Wall-clock function time is the primary metric. No concurrent workload is deliberately launched.',
    sourceUnmodified:true,temporaryLoader:true,paymentAmountMinor:10000,optionalDisclosures:[],localTestOnly:true};
  await save('environment.json',metadata);
  const samples=[],stages=[],orders=[],sourceMap=new Map();
  async function stage(s,mode,name,options,group,index) {
    const context={group,index,mode,phase:name};
    await Promise.all(children.map(c=>control(c,'context',context)));
    bench.context=context;
    const row={...context,success:false};let result;
    const started=performance.now();
    try {
      const prepared=await s.prepare({mode,phase:name,...options});
      result=await s.transmit(prepared);
      row.wallMs=performance.now()-started;
      assert.equal(result.accepted,true);assert.equal(result.verificationTrace.outcome,'pass');
      Object.assign(row,{success:true,orderId:prepared.payment.orderId,challengeId:prepared.context.challengeId,verificationTrace:result.verificationTrace});
    } catch(error) {row.wallMs=performance.now()-started;row.error={code:error.code??error.name,message:clean(error.message)};throw error;}
    finally {
      bench.context=null;
      await Promise.all(children.map(c=>control(c,'context',null)));
      const batches=[bench.drain(),...await Promise.all(children.map(c=>control(c,'drain')))];
      const current=batches.flatMap(x=>x.samples);
      for(const batch of batches)for(const source of batch.sources)sourceMap.set(source.url,source);
      for(const sample of current){samples.push(sample);await appendFile(join(output,'samples.jsonl'),JSON.stringify(sample)+'\n');}
      stages.push(row);await appendFile(join(output,'stages.jsonl'),JSON.stringify(row)+'\n');
      if(row.success){
        const wanted=['agent-a:bindingFinalize','agent-a:bindingPrepare','agent-a:holderSign','agent-a:vcDerive','agent-b:bindingVerify','agent-b:holderVerify','agent-b:vcVerify','device:deviceSign'].sort();
        assert.deepEqual(current.map(x=>x.role+':'+x.operation).sort(),wanted,'Every production operation must be observed exactly once');
        assert(current.every(x=>x.success));
      }
    }
    return result;
  }
  async function order(s,mode,group,index) {
    const state=await s.newOrder({mode,amountMinor:10000});
    const row={mode,group,index,orderId:state.order.orderId,success:false};
    try {
      const proposed=await stage(s,mode,'proposal',{},group,index);
      const proposal=await json(`${owner.baseUrl}/proposals`,{profile:DBAC_PAYMENT_PROFILE,payment:state.order,dbacEvidence:proposed.responseEvidence},{'X-Owner-Proposal':proposalToken});
      const approved=await json(`${owner.baseUrl}/api/proposals/${proposal.id}/approve`,{confirmed:true,payment:proposal.payment,credentialHash:proposal.credentialHash},{'X-Owner-UI-Key':ownerKey});
      const authorization=approved.authorization.token;
      const authorized=await stage(s,mode,'authorize',{authorization},group,index);
      const payload=await payer.createPayload({profile:DBAC_PAYMENT_PROFILE,payment:state.order,authorization,paymentRequired:authorized.task.status.message.metadata['x402.payment.required'],responseEvidence:authorized.responseEvidence});
      const settled=await stage(s,mode,'settle',{authorization,payload,continuation:authorized.task},group,index);
      assert.equal(settled.paymentResult.outcome,'EXECUTED');assert.equal(settled.paymentResult.receipt.orderId,state.order.orderId);assert.equal(settled.paymentResult.receipt.transactionStatus,'success');
      Object.assign(row,{success:true,transactionHash:settled.paymentResult.receipt.transactionHash});
    }catch(error){row.error={code:error.code??error.name,message:clean(error.message)};throw error;}
    finally{orders.push(row);await appendFile(join(output,'orders.jsonl'),JSON.stringify(row)+'\n');console.log(`${mode} ${group} ${index}: ${row.success?'PASS':'FAIL'}`);}
  }
  const before=await backend.snapshot(),sessions={};
  for(const mode of modes){sessions[mode]=session();await sessions[mode].issue({mode});for(let i=1;i<=2;i++)await order(sessions[mode],mode,'warmup',i);}
  for(let i=1;i<=10;i++)for(const mode of (i%2?modes:[...modes].reverse()))await order(sessions[mode],mode,'measured',i);
  const after=await backend.snapshot();
  assert.equal(orders.length,24);assert(orders.every(x=>x.success));assert.equal(after.executionCount-before.executionCount,24);assert.equal(new Set(orders.map(x=>x.transactionHash)).size,24);
  await save('ledger.json',{before,after,executionDelta:after.executionCount-before.executionCount});
  await save('instrumentation.json',[...sourceMap.values()]);
  await save('results.json',{metadata,orders,stages,samples});
  console.log(`Complete: ${orders.length} orders, ${stages.length} phases, ${samples.length} operation samples; excluded 4 warm-ups.`);
}catch(error){await save('fatal.json',{code:error.code??error.name,message:clean(error.message),stack:clean(error.stack)});console.error(clean(error.stack));process.exitCode=1;}
finally{bench.context=null;await close();}
