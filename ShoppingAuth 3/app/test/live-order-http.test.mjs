import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtemp, mkdir, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { sendJson } from '../lib/protocol.mjs';

const orderId = 'urn:uuid:abcdef12-0000-4000-8000-000000000001';
const mismatchId = 'urn:uuid:abcdef12-0000-4000-8000-000000000002';
const missingId = 'urn:uuid:abcdef12-0000-4000-8000-000000000003';
const brokenId = 'urn:uuid:abcdef12-0000-4000-8000-000000000004';
const malformed = ['%', '%2', '%GG', '%E0%A4%A', '%C0%AF', '%ED%A0%80'];
const route = id => '/api/live/orders/' + id;

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'shopping-live-order-http-'));
  const orderDirectory = join(directory, 'orders'), eventDirectory = join(directory, 'events');
  const uiToken = randomBytes(32).toString('base64url'), upstreamCalls = [];
  let child, exited, stderr = '';
  // These read-only upstream responses support the real HTTP handler's error-state
  // projection. No wallet, cryptographic service, chain or existing demo is used.
  const upstream = http.createServer((req, res) => {
    upstreamCalls.push({ method: req.method, path: req.url });
    if (req.method === 'GET' && req.url === '/admin/ledger') return sendJson(res, 200, { executionCount: 0, accounts: [] });
    if (req.method === 'GET' && req.url === '/health') return sendJson(res, 200, { publicKeys: { 'bbs-bls': 'fixture-public-key' }, hardware: false, modes: {} });
    if (req.method === 'GET' && req.url === '/devices') return sendJson(res, 200, { devices: [] });
    sendJson(res, 500, { error: { code: 'UNEXPECTED_UPSTREAM_CALL' } });
  });
  t.after(async () => {
    try {
      if (child?.pid && child.exitCode === null && child.signalCode === null) {
        child.kill('SIGTERM');
        const closed = await Promise.race([exited.then(() => true), delay(2000, false, { ref: false })]);
        if (!closed) { child.kill('SIGKILL'); await exited; }
      }
    } finally {
      upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve));
      await rm(directory, { recursive: true, force: true });
    }
  });
  await mkdir(orderDirectory); await mkdir(eventDirectory);
  const saved = { version: 1, phase: 'paid', revision: 2, cart: { '02': 1 }, boundOrder: { orderId, amountMinor: 19990000, currency: 'TEST_USDC' },
    receipt: { orderId, transactionHash: 'fixture-saved-receipt' }, events: [], authorization: { token: 'fixture-owner-secret', id: 'public-authorization-id' } };
  await writeFile(join(orderDirectory, `${orderId.slice(9)}.json`), JSON.stringify(saved));
  await writeFile(join(orderDirectory, `${mismatchId.slice(9)}.json`), JSON.stringify(saved));
  await writeFile(join(orderDirectory, `${brokenId.slice(9)}.json`), '{broken json');
  await writeFile(join(orderDirectory, 'current.json'), JSON.stringify({ version: 1, phase: 'cart', revision: 0, cart: {}, boundOrder: null, events: [] }));
  await new Promise((resolve, reject) => { upstream.once('error', reject); upstream.listen(0, '127.0.0.1', resolve); });
  const upstreamUrl = `http://127.0.0.1:${upstream.address().port}`;
  child = fork(new URL('../lib/storefront/live-server-process.mjs', import.meta.url), [], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
  child.stderr.on('data', data => { stderr = (stderr + data).slice(-4000); });
  exited = new Promise(resolve => { child.once('exit', resolve); child.once('error', resolve); });
  const ready = new Promise((resolve, reject) => {
    const finish = (error, value) => {
      clearTimeout(timer); child.off('message', onMessage); child.off('error', onError); child.off('exit', onExit);
      error ? reject(error) : resolve(value);
    };
    const onMessage = value => finish(value.error ? new Error(value.error) : null, value);
    const onError = error => finish(error);
    const onExit = () => finish(new Error(`Live HTTP fixture exited before readiness: ${stderr}`));
    const timer = setTimeout(() => finish(new Error(`Live HTTP fixture startup timed out: ${stderr}`)), 10000);
    child.once('message', onMessage); child.once('error', onError); child.once('exit', onExit);
  });
  child.send({ port: 0, uiToken, adminToken: 'fixture-admin', actors: {}, orderDirectory, eventDirectory,
    verifierUrl: upstreamUrl, verifierDid: 'did:example:fixture-verifier', owner: { baseUrl: upstreamUrl, did: 'did:example:fixture-owner', proposalToken: 'fixture-proposal' },
    dbac: { issuer: { baseUrl: upstreamUrl, publicKey: 'fixture-issuer', accessToken: 'fixture-issuer-token' },
      device: { baseUrl: upstreamUrl, publicKeys: { 'bbs-bls': 'fixture-public-key' }, accessToken: 'fixture-device-token' } },
    payerConfig: { url: upstreamUrl, accessToken: 'fixture-payer', publicInfo: { network: 'eip155:31337', asset: '0x' + '1'.repeat(40),
      payerAddress: '0x' + '2'.repeat(40), payees: { 'merchant:keyboard': '0x' + '3'.repeat(40) } } } });
  const { baseUrl } = await ready, address = new URL(baseUrl);
  function get(path, { token = uiToken, headers = {} } = {}) {
    // Use path directly so the HTTP client cannot normalize the malformed input.
    return new Promise((resolve, reject) => {
      const request = http.request({ hostname: address.hostname, port: address.port, method: 'GET', path,
        headers: { ...(token === null ? {} : { 'X-Demo-UI-Key': token }), ...headers } }, response => {
        let raw = ''; response.setEncoding('utf8'); response.on('data', chunk => { raw += chunk; });
        response.once('error', reject);
        response.once('end', () => { try { resolve({ status: response.statusCode, body: JSON.parse(raw) }); } catch (error) { reject(error); } });
      });
      request.once('error', reject); request.setTimeout(5000, () => request.destroy(new Error('Live order HTTP request timed out'))); request.end();
    });
  }
  async function diskState() {
    const result = {};
    for (const subdirectory of ['orders', 'events']) {
      for (const name of (await readdir(join(directory, subdirectory))).sort()) result[`${subdirectory}/${name}`] = await readFile(join(directory, subdirectory, name), 'utf8');
    }
    return result;
  }
  return { get, saved, upstreamCalls, diskState };
}
function errorIs(result, status, code, label) {
  assert.equal(result.status, status, label); assert.equal(result.body.error.code, code, label);
  assert.equal(JSON.stringify(result.body).includes('URI malformed'), false);
}

test('live order HTTP reads reject malformed URLs without changing auth, records or payment state', { timeout: 30000 }, async t => {
  const f = await fixture(t);
  // A successful record read flushes the startup journal before the read-only baseline.
  assert.equal((await f.get(route(orderId))).status, 200);
  const before = (await f.get('/api/live/state')).body, diskBefore = await f.diskState();
  await t.test('malformed percent encoding and invalid UTF-8 return the existing not-found error', async () => {
    for (const input of malformed) errorIs(await f.get(route(input)), 404, 'ORDER_NOT_FOUND', input);
  });
  await t.test('raw and once-encoded order IDs return the same read-only record', async () => {
    for (const input of [orderId, encodeURIComponent(orderId), encodeURIComponent(orderId).replaceAll('%3A', '%3a')]) {
      const result = await f.get(route(input)); assert.equal(result.status, 200, input);
      assert.equal(result.body.readOnly, true); assert.deepEqual(result.body.order, f.saved.boundOrder);
      assert.deepEqual(result.body.receipt, f.saved.receipt); assert.equal(result.body.cart[0].id, '02');
      assert.equal(result.body.cart[0].amountMinor, 19990000);
      assert.equal(JSON.stringify(result.body).includes('fixture-owner-secret'), false);
    }
  });
  await t.test('invalid IDs, traversal and double encoding remain rejected', async () => {
    for (const input of ['', orderId.toUpperCase(), encodeURIComponent(encodeURIComponent(orderId)),
      '%2e%2e%2fcurrent.json', encodeURIComponent(orderId + '/../current.json'), encodeURIComponent(orderId + '/'),
      encodeURIComponent(orderId) + '%00']) errorIs(await f.get(route(input)), 404, 'ORDER_NOT_FOUND', input);
  });
  await t.test('missing and wrong capabilities are rejected before decoding and expose no state', async () => {
    for (const input of [...malformed, encodeURIComponent(orderId)]) for (const token of [null, 'wrong-key']) {
      const result = await f.get(route(input), { token }); errorIs(result, 401, 'UI_ACCESS_DENIED', input);
      assert.equal(result.body.state, undefined);
    }
  });
  await t.test('Host and Origin validation still precede malformed order decoding', async () => {
    for (const [headers, code] of [[{ Host: 'untrusted.example' }, 'INVALID_HOST'], [{ Origin: 'https://untrusted.example' }, 'CROSS_ORIGIN_DENIED']]) {
      const result = await f.get(route('%'), { headers }); errorIs(result, 403, code); assert.equal(result.body.state, undefined);
    }
  });
  await t.test('missing, mismatched and unreadable records still return not found', async () => {
    for (const input of [missingId, mismatchId, brokenId]) errorIs(await f.get(route(encodeURIComponent(input))), 404, 'ORDER_NOT_FOUND', input);
  });
  await t.test('all reads preserve records and event sequence without business upstream calls', async () => {
    const after = (await f.get('/api/live/state')).body;
    assert.equal(after.sequence, before.sequence); assert.deepEqual(after.store, before.store);
    assert.deepEqual(after.core.ledger, before.core.ledger); assert.deepEqual(after.history, before.history);
    assert.deepEqual(await f.diskState(), diskBefore);
    assert.ok(f.upstreamCalls.length > 0);
    assert.ok(f.upstreamCalls.every(call => call.method === 'GET' && ['/admin/ledger', '/health', '/devices'].includes(call.path)), JSON.stringify(f.upstreamCalls));
    assert.equal((await f.get('/api/health', { token: null })).body.ok, true);
  });
});
