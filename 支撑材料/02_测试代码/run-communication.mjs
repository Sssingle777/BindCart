import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import { mkdtemp, rm, writeFile, appendFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
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
if (['results.json', 'samples.jsonl', 'orders.jsonl'].some(name => existsSync(join(output, name)))) {
  throw new Error('Evidence already exists. Copy this test directory to a NEW sibling directory before rerunning; existing measurements must not be overwritten.');
}
const root = new URL('../../作品源码/BindCart/app/', import.meta.url);
const kind = 'communication';
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
const timing = new AsyncLocalStorage(), originalFetch = globalThis.fetch;
const corePaths = ['/dbac/payment/challenge', '/sign', '/dbac/payment/a2a'];
const protocolHeaders = headers => [...new Headers(headers)].filter(([key]) => /^(x-a2a-|x-dbac-|payment-)/.test(key)).map(([name, value]) => ({ name, valueBytes: Buffer.byteLength(value, 'utf8') }));
const sum = xs => xs.reduce((a,b) => a+b,0);
globalThis.fetch = async (input, options = {}) => {
  const ctx = timing.getStore();
  const url = new URL(typeof input === 'string' ? input : input.url ?? input);
  if (!ctx || !corePaths.includes(url.pathname)) return originalFetch(input, options);
  assert.equal(typeof options.body, 'string', 'Measured requests must use the actual serialized string');
  const requestHeaderFields = protocolHeaders(options.headers);
  const row = {path:url.pathname,method:options.method,requestBodyBytes:Buffer.byteLength(options.body,'utf8'),requestHeaderFields,
    requestProtocolHeaderValueBytes:sum(requestHeaderFields.map(x=>x.valueBytes))};
  ctx.requests.push(row);
  try {
    const response = await originalFetch(input,options);
    assert(!response.headers.get('content-encoding') || response.headers.get('content-encoding')==='identity','Compressed responses require a different accounting rule');
    const responseBytes = Buffer.from(await response.clone().arrayBuffer());
    const contentLength = response.headers.get('content-length');
    if (contentLength !== null) assert.equal(responseBytes.length,Number(contentLength));
    const responseHeaderFields = protocolHeaders(response.headers);
    Object.assign(row,{status:response.status,responseBodyBytes:responseBytes.length,responseHeaderFields,
      responseProtocolHeaderValueBytes:sum(responseHeaderFields.map(x=>x.valueBytes))});
    row.sentBytes=row.requestBodyBytes+row.requestProtocolHeaderValueBytes;
    row.receivedBytes=row.responseBodyBytes+row.responseProtocolHeaderValueBytes;
    row.totalBytes=row.sentBytes+row.receivedBytes;
    if (url.pathname === '/dbac/payment/a2a') {
      const header = new Headers(options.headers).get('x-a2a-dbac-proof');
      const decoded=Buffer.from(header,'base64url');
      const proof=JSON.parse(decoded);
      row.proofComponents={requestProofEncodedBytes:Buffer.byteLength(header),requestProofDecodedJsonBytes:decoded.length,
        vcJsonBytes:Buffer.byteLength(JSON.stringify(proof.verifiableCredential)),holderProofJsonBytes:Buffer.byteLength(JSON.stringify(proof.holderProof)),
        responseEvidenceEncodedBytes:Buffer.byteLength(response.headers.get('x-a2a-dbac-payment-response')??'')};
    }
    return response;
  } catch(error) {row.error={code:error.code??error.name,message:clean(error.message)};throw error;}
};
async function json(url, body, headers) {
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(90000) });
  const value = await response.json();
  if (!response.ok) throw Object.assign(new Error(value.error?.message ?? 'HTTP error'), { code: value.error?.code, status: response.status });
  return value;
}
const save = (name, data) => writeFile(join(output, name), JSON.stringify(data, null, 2));
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
  const metadata = {startedAt:new Date().toISOString(),node:process.version,cpu:cpus()[0]?.model,logicalCpus:cpus().length,memoryGiB:totalmem()/1024**3,platform:platform(),release:release(),arch:arch(),
    scope:'A-facing authentication main path only: A-B challenge, A-device sign, A-B a2a. Includes actual JSON bodies and UTF-8 values of x-a2a-*, x-dbac-*, payment-* protocol headers in both directions. Counts serialized/base64url representations as sent; never adds decoded proof sizes again.',
    excluded:'HTTP generic headers, header names/separators, request/status lines, TCP/IP/TLS, device registration/credential issuance, Owner UI/approval, wallet signing, B/Owner/wallet-Issuer status queries, facilitator and blockchain RPC, browser assets and merchant confirmation. Not whole-system network traffic.',
    unit:'Bytes (B), KiB = B / 1024. An exchange is one request plus one response; each phase has three sequential exchanges on this measured path.',
    samplePlan:'Per mode: one excluded warm-up order and ten measured sequential orders, each unique and paying 0.01 TEST_USDC. Default optional disclosure fields empty. Real crypto, production services, isolated Ganache; no retries.',
    paymentAmountMinor:10000,optionalDisclosures:[],failuresRetained:true,localTestOnly:true};
  await save('environment.json',metadata);
  const samples=[],orders=[];
  async function phase(s,mode,name,options,group,index) {
    const row={group,index,mode,phase:name,requests:[],success:false};
    try {
      const result=await timing.run(row,async()=>s.transmit(await s.prepare({mode,phase:name,...options})));
      assert.equal(result.accepted,true);assert.equal(result.verificationTrace.outcome,'pass');
      assert.deepEqual(row.requests.map(x=>x.path),corePaths);
      assert(row.requests.every(x=>x.status===200));
      Object.assign(row,{success:true,sentBytes:sum(row.requests.map(x=>x.sentBytes)),receivedBytes:sum(row.requests.map(x=>x.receivedBytes)),
        totalBytes:sum(row.requests.map(x=>x.totalBytes)),exchanges:row.requests.length,messages:row.requests.length*2,
        deviceExchanges:row.requests.filter(x=>x.path==='/sign').length});
      return result;
    } catch(error) {row.error={code:error.code??error.name,message:clean(error.message)};throw error;}
    finally {samples.push(row);await appendFile(join(output,'samples.jsonl'),JSON.stringify(row)+'\n');}
  }
  async function order(s,mode,group,index) {
    const state=await s.newOrder({mode,amountMinor:10000});
    const row={mode,group,index,orderId:state.order.orderId,success:false};
    try {
      const proposed=await phase(s,mode,'proposal',{},group,index);
      const proposal=await json(`${owner.baseUrl}/proposals`,{profile:DBAC_PAYMENT_PROFILE,payment:state.order,dbacEvidence:proposed.responseEvidence},{'X-Owner-Proposal':proposalToken});
      const approved=await json(`${owner.baseUrl}/api/proposals/${proposal.id}/approve`,{confirmed:true,payment:proposal.payment,credentialHash:proposal.credentialHash},{'X-Owner-UI-Key':ownerKey});
      const authorization=approved.authorization.token;
      const authorized=await phase(s,mode,'authorize',{authorization},group,index);
      const payload=await payer.createPayload({profile:DBAC_PAYMENT_PROFILE,payment:state.order,authorization,paymentRequired:authorized.task.status.message.metadata['x402.payment.required'],responseEvidence:authorized.responseEvidence});
      const settled=await phase(s,mode,'settle',{authorization,payload,continuation:authorized.task},group,index);
      assert.equal(settled.paymentResult.outcome,'EXECUTED');
      assert.equal(settled.paymentResult.receipt.orderId,state.order.orderId);
      assert.equal(settled.paymentResult.receipt.transactionStatus,'success');
      const rows=samples.filter(x=>x.mode===mode&&x.group===group&&x.index===index);
      assert.equal(rows.length,3);
      Object.assign(row,{success:true,transactionHash:settled.paymentResult.receipt.transactionHash,sentBytes:sum(rows.map(x=>x.sentBytes)),receivedBytes:sum(rows.map(x=>x.receivedBytes)),totalBytes:sum(rows.map(x=>x.totalBytes)),exchanges:sum(rows.map(x=>x.exchanges)),deviceExchanges:sum(rows.map(x=>x.deviceExchanges))});
    } catch(error) {row.error={code:error.code??error.name,message:clean(error.message)};}
    finally {orders.push(row);await appendFile(join(output,'orders.jsonl'),JSON.stringify(row)+'\n');console.log(`${mode} ${group} ${index}: ${row.success?'PASS':'FAIL'} ${row.totalBytes??'-'} B`);}
    return row;
  }
  const before=await backend.snapshot();
  for(const mode of modes) {
    const s=session();await s.issue({mode});
    assert((await order(s,mode,'warmup',0)).success,'Warm-up failed');
    for(let i=1;i<=10;i++) await order(s,mode,'measured',i);
  }
  const after=await backend.snapshot();
  await save('ledger.json',{before,after,executionDelta:after.executionCount-before.executionCount});
  await save('results.json',{metadata,orders,samples});
  assert(orders.every(x=>x.success),'Some orders failed; retain all evidence');
  assert.equal(after.executionCount-before.executionCount,orders.length);
  assert.equal(new Set(orders.map(x=>x.transactionHash)).size,orders.length);
  console.log(`Completed ${orders.length} isolated orders; ${samples.length} phases; ledger delta ${after.executionCount-before.executionCount}`);
} catch(error) {
  await save('fatal.json',{code:error.code??error.name,message:clean(error.message),stack:clean(error.stack)});
  console.error(clean(error.stack));process.exitCode=1;
} finally {await close();globalThis.fetch=originalFetch;}
