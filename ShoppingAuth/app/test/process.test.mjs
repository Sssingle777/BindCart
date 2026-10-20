import assert from 'node:assert/strict';
import { fork, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateIdentity } from '../lib/identity.mjs';
import { serializeIdentity } from '../lib/protocol.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));

function isAlive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}

function assertPublicResponse(value, path = '$') {
  const secretFields = new Set([
    'privatekey', 'privatekeyjwk', 'privatejwk', 'privatepem', 'privatekeypem',
    'secretkey', 'secret', 'seed', 'accesstoken', 'deviceaccesstoken', 'admintoken',
    'xesimaccess', 'uitoken', 'uikey', 'demouikey', 'xdemouikey',
    'owneruikey', 'owneruitoken', 'xowneruikey', 'proposaltoken',
  ]);
  if (typeof value === 'string') {
    assert.doesNotMatch(value, /-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/, `${path} must not expose PEM private material`);
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, item] of Object.entries(value)) {
    const field = key.replace(/[-_]/g, '').toLowerCase();
    assert.equal(secretFields.has(field), false, `${path}.${key} must not expose a signing key or access capability`);
    if (key === 'd' && typeof value.kty === 'string') assert.fail(`${path} must not expose a private JWK`);
    // The signed VC itself is public demonstration data; access capabilities are not.
    if (field === 'token') assert.match(`${path}.${key}`, /\.(credential|authorization)\.token$/, 'only signed VC or payment evidence may be exposed');
    if (field === 'authorization' && item !== null) {
      if (typeof item === 'object' && typeof item.from === 'string' && typeof item.nonce === 'string') {
        assert.deepEqual(Object.keys(item).sort(), ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce'].sort(), `${path} only exposes EIP-3009 signed public fields`);
      } else {
        const signed = typeof item === 'string' ? item : item.token;
        assert.equal(typeof signed, 'string', path);
        assert.equal(JSON.parse(Buffer.from(signed.split('.')[0], 'base64url')).typ, 'a2a-payment-authorization+jwt');
      }
    }
    assertPublicResponse(item, `${path}.${key}`);
  }
}

async function assertStartupRejected(t, file, config, expectedError) {
  const child = fork(new URL(`../${file}`, import.meta.url), [], {
    cwd: root, execArgv: [], stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  const messages = [];
  let stderr = '', timer, abort;
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => { stderr = (stderr + chunk).slice(-8192); });
  try {
    const outcome = await new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`${file} did not reject its unsafe startup configuration. ${stderr}`)), 4000);
      abort = () => reject(new Error(`${file} startup rejection test aborted.`));
      t.signal.addEventListener('abort', abort, { once: true });
      child.once('error', reject);
      child.on('message', message => {
        messages.push(message);
        if (message?.ready === true) reject(new Error(`${file} became ready with an unsafe Owner configuration.`));
      });
      closed.then(resolve);
      child.send(config, error => { if (error) reject(error); });
    });
    assert.equal(outcome.code, 1, `${file} must exit unsuccessfully; ${stderr}`);
    assert.equal(outcome.signal, null, 'startup must reject itself without being terminated by the test');
    assert.equal(messages.some(message => message?.ready === true), false, 'no ready IPC message may be sent');
    assert.ok(messages.some(message => typeof message?.error === 'string' && expectedError.test(message.error)),
      `expected the explicit Owner configuration error over IPC, received ${JSON.stringify(messages)}; ${stderr}`);
    assert.equal(isAlive(child.pid), false, 'rejected service must leave no running child');
  } finally {
    clearTimeout(timer);
    if (abort) t.signal.removeEventListener('abort', abort);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await closed;
  }
}

test('network services reject missing or issuer-controlled Owner configuration before readiness', { timeout: 25000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'owner-startup-'));
  const issuer = generateIdentity('Startup VC issuer');
  const agentA = generateIdentity('Startup Agent A');
  const agentB = generateIdentity('Startup Agent B');
  const device = generateIdentity('Startup simulated device');
  const owner = generateIdentity('Startup independent Owner');
  const token = () => randomBytes(32).toString('base64url');
  const bConfig = {
    identity: serializeIdentity(agentB), trustedIssuers: [issuer.did], adminToken: token(),
    ledgerPath: join(directory, 'ledger.sqlite'), port: 0,
  };
  try {
    await t.test('Agent A cannot fall back to local payment confirmation when Owner is absent', async (subtest) => {
      await assertStartupRejected(subtest, 'agent-a.mjs', {
        issuer: serializeIdentity(issuer), agentA: serializeIdentity(agentA), verifierDid: agentB.did,
        baseUrl: 'http://127.0.0.1:1', adminToken: token(), uiToken: token(), port: 0,
        device: { did: device.did, baseUrl: 'http://127.0.0.1:2', accessToken: token() },
      }, /网络服务必须配置独立 Owner/);
    });
    for (const [name, authorizers] of [
      ['missing Owner authorizers', undefined],
      ['empty Owner authorizers', []],
      ['the VC issuer as the only Owner', [issuer.did]],
      ['the VC issuer alongside an independent Owner', [owner.did, issuer.did]],
    ]) {
      await t.test(`Agent B rejects ${name}`, async (subtest) => {
        await assertStartupRejected(subtest, 'agent-b.mjs', {
          ...bConfig, ...(authorizers === undefined ? {} : { trustedAuthorizers: authorizers }),
        }, /B requires explicit Owner authorizers distinct from credential issuers/);
      });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('separate Owner/Agent A/Agent B/eSIM processes enforce independent payment confirmation and dual signatures', { timeout: 90000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'payment-process-'));
  const launcher = spawn(process.execPath, ['launch.mjs'], {
    cwd: root,
    env: { ...process.env, PORT: '0', AGENT_B_PORT: '0', ESIM_PORT: '0', OWNER_PORT: '0', PAYMENT_DB: join(directory, 'ledger.sqlite'), X402_STATE_DIR: join(directory, 'x402') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '', stopped = false;
  const childPids = [];
  const exited = new Promise((resolve) => {
    launcher.once('exit', (code, signal) => { stopped = true; resolve({ code, signal }); });
    launcher.once('error', () => { stopped = true; resolve({ code: null, signal: null }); });
  });
  launcher.stdout.setEncoding('utf8');
  launcher.stderr.setEncoding('utf8');
  launcher.stderr.on('data', (chunk) => { stderr += chunk; });

  try {
    const addresses = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => finish(new Error(`Launcher readiness timeout.\n${stderr}`)), 45000);
      const abort = () => finish(new Error('Process test aborted before launcher became ready.'));
      const failed = (error) => finish(error);
      const prematureExit = (code, signal) => finish(new Error(`Launcher exited before readiness (code=${code}, signal=${signal}).\n${stderr}`));
      const data = (chunk) => {
        stdout += chunk;
        const a = stdout.match(/Agent A:\s*(http:\/\/127\.0\.0\.1:\d+)\s*\(PID (\d+)\)/);
        const b = stdout.match(/Agent B:\s*(http:\/\/127\.0\.0\.1:\d+)\/a2a\s*\(PID (\d+)\)/);
        const d = stdout.match(/eSIM:\s*(http:\/\/127\.0\.0\.1:\d+)\s*\(PID (\d+)\)/);
        const o = stdout.match(/Owner:\s*(http:\/\/127\.0\.0\.1:\d+)\s*\(PID (\d+)\)/);
        const ui = stdout.match(/控制台链接:\s*(http:\/\/127\.0\.0\.1:\d+)\/#key=([A-Za-z0-9_-]{43})/);
        const ownerUi = stdout.match(/Owner 确认链接:\s*(http:\/\/127\.0\.0\.1:\d+)\/#key=([A-Za-z0-9_-]{43})/);
        if (a && b && d && o && ui && ownerUi) finish(null, {
          a: a[1], b: b[1], d: d[1], o: o[1],
          aPid: Number(a[2]), bPid: Number(b[2]), dPid: Number(d[2]), oPid: Number(o[2]),
          uiKey: ui[2], ownerUiKey: ownerUi[2],
        });
      };
      function finish(error, result) {
        clearTimeout(timer);
        launcher.stdout.off('data', data);
        launcher.off('error', failed);
        launcher.off('exit', prematureExit);
        t.signal.removeEventListener('abort', abort);
        if (error) reject(error); else resolve(result);
      }
      launcher.stdout.on('data', data);
      launcher.once('error', failed);
      launcher.once('exit', prematureExit);
      t.signal.addEventListener('abort', abort, { once: true });
    });
    childPids.push(addresses.aPid, addresses.bPid, addresses.dPid, addresses.oPid);
    const request = (base, path, options = {}) => {
      const { authenticate = true, ...fetchOptions } = options;
      return fetch(`${base}${path}`, {
        ...fetchOptions,
        headers: {
          ...(authenticate && base === addresses.a && path.startsWith('/api/') && path !== '/api/health' ? { 'X-Demo-UI-Key': addresses.uiKey } : {}),
          ...(authenticate && base === addresses.o && path.startsWith('/api/') ? { 'X-Owner-UI-Key': addresses.ownerUiKey } : {}),
          ...fetchOptions.headers,
        },
        redirect: 'error',
        signal: AbortSignal.any([t.signal, AbortSignal.timeout(8000)]),
      });
    };
    const checkPublic = (body) => {
      assertPublicResponse(body);
      assert.equal(JSON.stringify(body).includes(addresses.uiKey), false, 'public responses must not expose the UI capability');
      assert.equal(JSON.stringify(body).includes(addresses.ownerUiKey), false, 'responses must never expose the independent Owner confirmation capability');
    };
    const get = async (base, path) => {
      const response = await request(base, path);
      assert.equal(response.status, 200, `GET ${path}`);
      const body = await response.json();
      checkPublic(body);
      return body;
    };
    const post = async (path, options = {}) => {
      const response = await request(addresses.a, path, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', ...options,
      });
      const body = await response.json();
      checkPublic(body);
      return { status: response.status, body };
    };
    const postOwner = async (path, body, options = {}) => {
      const response = await request(addresses.o, path, {
        method: 'POST', body: JSON.stringify(body), headers: { 'Content-Type': 'application/json' }, ...options,
      });
      const result = await response.json();
      checkPublic(result);
      return { status: response.status, body: result };
    };

    await t.test('Owner, Agent and device identities are hosted by four distinct live operating-system processes', async () => {
      const a = await get(addresses.a, '/api/health');
      const b = await get(addresses.b, '/health');
      const d = await get(addresses.d, '/health');
      const o = await get(addresses.o, '/health');
      assert.equal(a.service, 'agent-a');
      assert.equal(b.service, 'agent-b');
      assert.equal(d.service, 'simulated-esim');
      assert.equal(a.pid, addresses.aPid);
      assert.equal(b.pid, addresses.bPid);
      assert.equal(d.pid, addresses.dPid);
      assert.equal(o.pid, addresses.oPid);
      assert.equal(new Set([a.pid, b.pid, d.pid, o.pid, launcher.pid]).size, 5);
      assert.ok(childPids.every(isAlive));
      assert.notEqual(addresses.uiKey, addresses.ownerUiKey);
      assert.notEqual(addresses.a, addresses.o);
      assert.equal(typeof o.did, 'string');
      const state = await get(addresses.a, '/api/state');
      assert.notEqual(o.did, state.issuerDid, 'the VC issuer cannot be the separately controlled payment Owner');
      assert.notEqual(o.did, state.agentADid);
      assert.equal(d.hardware, false);
      assert.equal(d.keyExportable, false);
      assert.equal(d.backend, 'jcardsim');
      assert.equal(d.algorithm, 'ES256');
      assert.equal(d.curve, 'P-256');
      assert.ok(isAlive(d.javaPid), 'the actual jCardSim JVM must be running');
      assert.equal(a.paymentProtocol, 'x402-v2');
      assert.equal(b.paymentReady, true);
      assert.equal(d.locked, false);
      assert.equal(d.did, d.deviceDid);
      assert.deepEqual(await get(addresses.a, '/api/device'), d);
    });

    await t.test('HTML, JavaScript and CSS are served from Agent A', async () => {
      for (const [path, contentType, marker] of [
        ['/', 'text/html', '演示平台'],
        ['/app.js', 'text/javascript', '/api/'],
        ['/style.css', 'text/css', '.identity-flow'],
      ]) {
        const response = await request(addresses.a, path);
        assert.equal(response.status, 200, path);
        assert.ok(response.headers.get('content-type').startsWith(contentType), path);
        const content = await response.text();
        assert.ok(content.includes(marker), path);
        assert.equal(content.includes(addresses.ownerUiKey), false, `${path} cannot expose the Owner capability`);
        assert.equal(content.includes(addresses.uiKey), false, `${path} cannot embed a console capability in a public asset`);
      }
    });

    await t.test('missing or incorrect console capabilities cannot read or mutate the control plane', async () => {
      const initial = await get(addresses.a, '/api/state');
      const deviceBefore = await get(addresses.a, '/api/device');
      for (const suppliedKey of [undefined, 'incorrect']) {
        for (const [method, path, body] of [
          ['GET', '/api/state'],
          ['GET', '/api/device'],
          ['GET', '/api/audit'],
          ['GET', '/api/card'],
          ['GET', '/api/payment'],
          ['POST', '/api/issue', '{}'],
          ['POST', '/api/invoke', '{}'],
          ['POST', '/api/payment/approve', '{}'],
          ['POST', '/api/payment/propose', '{}'],
          ['POST', '/api/payment/sync', '{}'],
          ['POST', '/api/payment/pay', '{}'],
          ['POST', '/api/payment/demo', '{}'],
          ['POST', '/api/device/lock', JSON.stringify({ locked: true })],
        ]) {
          const response = await request(addresses.a, path, {
            authenticate: false, method, body,
            headers: { 'Content-Type': 'application/json', ...(suppliedKey ? { 'X-Demo-UI-Key': suppliedKey } : {}) },
          });
          assert.equal(response.status, 401, `${method} ${path} must require the console capability`);
          const rejected = await response.json();
          assert.equal(rejected.error.code, 'UI_ACCESS_DENIED');
          checkPublic(rejected);
        }
      }
      assert.deepEqual(await get(addresses.a, '/api/state'), initial, 'unauthorized requests must not change the VC or identities');
      assert.deepEqual(await get(addresses.a, '/api/device'), deviceBefore, 'unauthorized requests must not change the device state');
    });

    await t.test('Agent A and Owner console capabilities cannot authorize each other', async () => {
      const response = await request(addresses.a, '/api/state', {
        authenticate: false, headers: { 'X-Demo-UI-Key': addresses.ownerUiKey },
      });
      assert.equal(response.status, 401);
      const rejected = await response.json();
      assert.equal(rejected.error.code, 'UI_ACCESS_DENIED');
      checkPublic(rejected);
      for (const key of [undefined, addresses.uiKey]) {
        const ownerResponse = await request(addresses.o, '/api/state', {
          authenticate: false, headers: key ? { 'X-Owner-UI-Key': key } : {},
        });
        assert.equal(ownerResponse.status, 403);
        const ownerRejected = await ownerResponse.json();
        assert.equal(ownerRejected.error.code, 'OWNER_UI_ACCESS_DENIED');
        checkPublic(ownerRejected);
      }
      const ownerState = await get(addresses.o, '/api/state');
      assert.ok(Array.isArray(ownerState.proposals));
      assert.equal(ownerState.proposals.length, 0);
    });

    await t.test('fresh session starts without a VC and rejects unsafe management requests', async () => {
      const initial = await get(addresses.a, '/api/state');
      assert.equal(initial.credential, null);
      assert.notEqual(initial.agentADid, initial.agentBDid);
      assert.equal(initial.agentBUrl, addresses.b);
      assert.equal(initial.deviceUrl, addresses.d);
      assert.equal(initial.deviceDid, (await get(addresses.a, '/api/device')).did);
      assert.equal(initial.didDocuments.device.id, initial.deviceDid);
      assert.notEqual(initial.deviceDid, initial.agentADid);
      assert.notEqual(initial.deviceDid, initial.agentBDid);
      const crossOrigin = await post('/api/issue', { headers: { 'Content-Type': 'application/json', Origin: 'https://untrusted.example' } });
      assert.equal(crossOrigin.status, 403);
      assert.equal(crossOrigin.body.error.code, 'CROSS_ORIGIN_DENIED');
      const withoutJSON = await post('/api/issue', { headers: {}, body: Buffer.from('{}') });
      assert.equal(withoutJSON.status, 415);
      assert.equal(withoutJSON.body.error.code, 'JSON_REQUIRED');
      assert.equal((await get(addresses.a, '/api/state')).credential, null);
    });

    await t.test('VC binds the device and A2A task execution verifies both signatures', async () => {
      const issue = await post('/api/issue');
      assert.equal(issue.status, 200);
      assert.equal(issue.body.credential.revoked, false);
      assert.equal(typeof issue.body.credential.token, 'string');
      const device = await get(addresses.a, '/api/device');
      assert.equal(issue.body.credential.document.credentialSubject.deviceDid, device.did);
      assert.equal((await get(addresses.a, '/api/state')).deviceDid, device.did);
      const card = await get(addresses.a, '/api/card');
      assert.equal(card.protocolVersion, '0.3.0');
      assert.equal(card.url, `${addresses.b}/a2a`);
      const invoke = await post('/api/invoke');
      assert.equal(invoke.status, 200, JSON.stringify(invoke.body));
      assert.equal(invoke.body.ok, true);
      assert.equal(invoke.body.task.kind, 'task');
      assert.equal(invoke.body.task.status.state, 'completed');
      assert.ok(invoke.body.task.id);
      assert.equal(invoke.body.verification.deviceSignature, true);
      assert.equal(invoke.body.verification.deviceDid, device.did);
    });

    await t.test('locking the device rejects invocation and unlocking restores double-signature execution', async () => {
      const lock = await post('/api/device/lock', { body: JSON.stringify({ locked: true }) });
      assert.equal(lock.status, 200);
      assert.equal(lock.body.locked, true);
      assert.equal((await get(addresses.a, '/api/device')).locked, true);
      const denied = await post('/api/invoke');
      assert.equal(denied.status, 403);
      assert.equal(denied.body.ok, false);
      assert.equal(denied.body.error.code, 'ESIM_LOCKED');
      const unlock = await post('/api/device/lock', { body: JSON.stringify({ locked: false }) });
      assert.equal(unlock.status, 200);
      assert.equal(unlock.body.locked, false);
      const resumed = await post('/api/invoke');
      assert.equal(resumed.status, 200, JSON.stringify(resumed.body));
      assert.equal(resumed.body.ok, true);
      assert.equal(resumed.body.verification.deviceSignature, true);
      assert.equal(resumed.body.verification.deviceDid, unlock.body.did);
    });

    await t.test('unauthorized clients cannot sign, lock, read device audit, or request key export', async () => {
      for (const [method, path, body] of [
        ['POST', '/sign', '{}'],
        ['POST', '/lock', JSON.stringify({ locked: true })],
        ['GET', '/audit'],
        ['GET', '/export'],
        ['POST', '/export', '{}'],
      ]) {
        const response = await request(addresses.d, path, {
          method, headers: { 'Content-Type': 'application/json' }, body,
        });
        assert.equal(response.status, 403, `${method} ${path}`);
        const rejected = await response.json();
        assert.equal(rejected.error.code, 'ESIM_ACCESS_DENIED', `${method} ${path}`);
        checkPublic(rejected);
      }
      assert.equal((await get(addresses.a, '/api/device')).locked, false);
    });

    await t.test('Agent A can propose but only the independent Owner can approve, then retries never debit twice', async () => {
      const initial = await get(addresses.a, '/api/payment');
      assert.equal(initial.authorization, null);
      assert.equal(initial.ledger.executionCount, 0);
      assert.equal(initial.owner.baseUrl, addresses.o);
      assert.equal(initial.owner.did, (await get(addresses.o, '/health')).did);
      for (const path of ['/api/payment/pay', '/api/payment/demo']) {
        const denied = await post(path);
        assert.equal(denied.status, 403);
        assert.equal(denied.body.error.code, 'OWNER_CONFIRMATION_REQUIRED');
      }
      for (const body of [{}, { confirmed: true, payment: initial.order }]) {
        const legacy = await post('/api/payment/approve', { body: JSON.stringify(body) });
        assert.equal(legacy.status, 403);
        assert.equal(legacy.body.error.code, 'OWNER_CONFIRMATION_REQUIRED', 'legacy A-side confirmation never creates Owner approval');
      }
      const proposed = await post('/api/payment/propose', { body: JSON.stringify({ payment: initial.order }) });
      assert.equal(proposed.status, 200, JSON.stringify(proposed.body));
      assert.equal(proposed.body.authorization, null);
      assert.deepEqual(proposed.body.ledger, initial.ledger, 'sending the proposal does not debit or credit any account');
      assert.equal(typeof proposed.body.proposal.id, 'string');
      const proposalId = proposed.body.proposal.id;
      const ownerState = await get(addresses.o, '/api/state');
      const proposal = ownerState.proposals.find(item => item.id === proposalId);
      assert.ok(proposal, 'the independently running Owner received the actual proposal');
      assert.equal(proposal.status, 'PENDING');
      assert.deepEqual(proposal.payment, initial.order);
      assert.equal(typeof proposal.credentialHash, 'string');
      assert.ok(!proposal.authorization, 'pending Owner proposals have no signed authorization');
      const confirmation = { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash };
      const forgedConfirmation = await postOwner(`/api/proposals/${encodeURIComponent(proposalId)}/approve`, confirmation, {
        authenticate: false, headers: { 'Content-Type': 'application/json', 'X-Owner-UI-Key': addresses.uiKey },
      });
      assert.equal(forgedConfirmation.status, 403, 'even a fully valid Agent A console key cannot approve an Owner proposal');
      assert.equal(forgedConfirmation.body.error.code, 'OWNER_UI_ACCESS_DENIED');
      assert.equal((await get(addresses.o, '/api/state')).proposals.find(item => item.id === proposalId).status, 'PENDING');
      assert.equal((await post('/api/payment/sync')).body.authorization, null, 'synchronizing a pending proposal cannot fabricate authorization');
      for (const path of ['/api/payment/pay', '/api/payment/demo']) {
        const pending = await post(path);
        assert.equal(pending.status, 403);
        assert.equal(pending.body.error.code, 'OWNER_APPROVAL_PENDING');
      }
      assert.deepEqual((await get(addresses.a, '/api/payment')).ledger, initial.ledger);
      const approved = await postOwner(`/api/proposals/${encodeURIComponent(proposalId)}/approve`, confirmation);
      assert.equal(approved.status, 200, JSON.stringify(approved.body));
      assert.equal((await get(addresses.o, '/api/state')).proposals.find(item => item.id === proposalId).status, 'APPROVED');
      const synced = await post('/api/payment/sync');
      assert.equal(synced.status, 200, JSON.stringify(synced.body));
      assert.equal(typeof synced.body.authorization.token, 'string');
      const approvalClaims = JSON.parse(Buffer.from(synced.body.authorization.token.split('.')[1], 'base64url'));
      assert.equal(approvalClaims.iss, initial.owner.did, 'the approved token is signed for the pinned independent Owner identity');
      assert.deepEqual(synced.body.ledger, initial.ledger, 'Owner approval and Agent A sync are not payment execution');
      await post('/api/device/lock', { body: JSON.stringify({ locked: true }) });
      assert.equal((await post('/api/payment/pay')).body.error.code, 'ESIM_LOCKED');
      assert.equal((await get(addresses.a, '/api/payment')).ledger.executionCount, 0);
      await post('/api/device/lock', { body: JSON.stringify({ locked: false }) });
      const first = await post('/api/payment/pay');
      assert.equal(first.status, 200, JSON.stringify(first.body));
      assert.equal(first.body.paymentResult.outcome, 'EXECUTED');
      assert.equal(first.body.verification.deviceSignature, true);
      assert.deepEqual(first.body.paymentFlow, ['input-required', 'payment-submitted', 'completed']);
      assert.match(first.body.paymentResult.receipt.transactionHash, /^0x[0-9a-fA-F]{64}$/);
      assert.equal(first.body.paymentResult.receipt.settlementResponse.success, true);
      const repeated = await post('/api/payment/retry');
      assert.equal(repeated.body.paymentResult.outcome, 'ALREADY_PROCESSED');
      assert.deepEqual(repeated.body.paymentResult.receipt, first.body.paymentResult.receipt);
      const paid = await get(addresses.a, '/api/payment');
      assert.equal(paid.ledger.executionCount, 1);
      assert.equal(paid.ledger.accounts.find(account => account.id === 'demo:alice').balanceMinor, 997010000);
      assert.equal(paid.ledger.accounts.find(account => account.id === 'merchant:keyboard').balanceMinor, 2990000);
      const demo = await post('/api/payment/demo');
      assert.equal(demo.status, 200, JSON.stringify(demo.body));
      assert.equal(demo.body.total, 13);
      assert.equal(demo.body.passed, demo.body.total, JSON.stringify(demo.body.results));
      const selfSignedOwner = demo.body.results.find(item => item.name === 'A 自行签发 Owner 付款授权');
      assert.ok(selfSignedOwner, 'the acceptance demo includes an Agent A attempt to forge independent Owner approval');
      assert.equal(selfSignedOwner.expected, 'PAYMENT_AUTHORIZER_UNTRUSTED');
      assert.equal(selfSignedOwner.actual, 'PAYMENT_AUTHORIZER_UNTRUSTED');
      assert.equal((await get(addresses.a, '/api/payment')).ledger.executionCount, 1, 'acceptance reruns reuse current order');
      await post('/api/issue');
      assert.equal((await get(addresses.a, '/api/payment')).authorization, null, 'a replacement VC requires a new confirmation');
      await post('/api/payment/new');
      const newOrder = await get(addresses.a, '/api/payment');
      assert.notEqual(newOrder.order.orderId, initial.order.orderId);
      assert.equal(newOrder.authorization, null);
      assert.equal(newOrder.ledger.executionCount, 1);
    });

    await t.test('security demo checks every expected result and leaves its VC revoked with the device unlocked', async () => {
      // Starting locked verifies that the demo establishes its documented device state.
      assert.equal((await post('/api/device/lock', { body: JSON.stringify({ locked: true }) })).body.locked, true);
      const demo = await post('/api/demo');
      assert.equal(demo.status, 200, JSON.stringify(demo.body));
      assert.equal(demo.body.total, 23, 'the original Echo security demonstration remains unchanged');
      assert.equal(demo.body.passed, demo.body.total, JSON.stringify(demo.body.results));
      assert.equal(demo.body.results.length, demo.body.total);
      assert.ok(demo.body.results.every((result) => result.pass && result.expected === result.actual));
      const missingDevice = demo.body.results.find((result) => result.name === 'VC＋A 私钥泄露，无设备权限');
      assert.ok(missingDevice, 'the stolen VC + A key case must be included');
      assert.equal(missingDevice.actual, 'DEVICE_PROOF_REQUIRED');
      const allAccess = demo.body.results.find((result) => result.name === 'VC、A 私钥及设备调用权全部泄露（边界）');
      assert.ok(allAccess, 'the complete-authority compromise boundary must be included');
      assert.equal(allAccess.actual, 'ACCEPTED');
      const state = await get(addresses.a, '/api/state');
      assert.equal(state.credential.revoked, true);
      assert.equal(state.credential.document.credentialSubject.deviceDid, state.deviceDid);
      assert.equal((await get(addresses.a, '/api/device')).locked, false);
      const revoked = await post('/api/invoke');
      assert.equal(revoked.body.ok, false);
      assert.equal(revoked.body.error.code, 'CREDENTIAL_REVOKED');
      const audit = await get(addresses.a, '/api/audit');
      assert.ok(audit.events.some((event) => event.event === 'task_completed'));
      assert.ok(audit.events.some((event) => event.event === 'credential_revoked'));
      assert.ok(audit.events.some((event) => event.code === 'CREDENTIAL_REVOKED'));
    });
  } finally {
    if (!stopped) launcher.kill('SIGTERM');
    let timer;
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Launcher did not stop after SIGTERM.')), 5000); });
    try {
      await Promise.race([exited, timeout]);
      for (let attempt = 0; attempt < 40 && childPids.some(isAlive); attempt++) await delay(25);
      const survivors = childPids.filter(isAlive);
      assert.deepEqual(survivors, [], 'launcher SIGTERM must also stop Owner, Agent A, Agent B and the simulated eSIM');
    } finally {
      clearTimeout(timer);
      if (!stopped) launcher.kill('SIGKILL');
      for (const pid of childPids) {
        if (isAlive(pid)) process.kill(pid, 'SIGKILL');
      }
      await rm(directory, { recursive: true, force: true });
    }
  }
});
