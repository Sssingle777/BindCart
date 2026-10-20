import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { createLiveSystem, publicEvidence, orderIdValid } from '../lib/storefront/live-system.mjs';

const firstOrder = 'urn:uuid:00000000-0000-4000-8000-000000000001';
const secondOrder = 'urn:uuid:00000000-0000-4000-8000-000000000002';
async function temporary(t) {
  const directory = await mkdtemp(join(tmpdir(), 'shopping-live-journal-'));
  t.after(async () => {
    const target = resolve(directory), expectedRoot = `${resolve(tmpdir())}${sep}shopping-live-journal-`;
    if (!target.startsWith(expectedRoot)) throw new Error('Temporary journal cleanup target is outside test directory');
    await rm(target, { recursive: true, force: true });
  });
  return directory;
}

test('observer projection removes actual capability/Owner/wallet shapes while retaining public credential evidence', () => {
  const secrets = ['ACCESS_SECRET', 'OWNER_UI_SECRET', 'OWNER_JWT_SECRET', 'WALLET_SIGNATURE_SECRET', 'RAW_AUTHORIZATION_SECRET', 'DEVICE_SECRET'];
  const input = {
    credentials: [{ verifiableCredential: { id: 'public-vc', credentialSubject: { role: 'buyer' }, proof: { proofValue: 'PUBLIC_BBS_PROOF' } } }],
    config: { accessToken: secrets[0], ownerKey: secrets[1], privateKey: secrets[5] },
    authorization: { id: 'authorization-public-id', token: secrets[2], document: { payment: { orderId: firstOrder } } },
    manual: {
      walletPayload: { payload: { signature: secrets[3] } },
      holderProof: 'PUBLIC_HOLDER_PROOF',
      log: [{ from: 'wallet', data: { x402Version: 2, payload: { signature: secrets[3] } } }],
      verificationResult: { wire: { body: { authorization: secrets[2], payload: { signature: secrets[3] } },
        headers: { Authorization: secrets[4], 'X-Demo-UI-Key': secrets[0], 'X-A2A-DBAC-Proof': 'PUBLIC_OUTBOUND_PROOF', 'Content-Type': 'application/json', 'X-A2A-Extensions': 'public-extension' } },
        responseEvidence: { rawRequest: JSON.stringify({ authorization: secrets[4] }), rawResponse: JSON.stringify({ authorization: secrets[2] }) } },
    },
  };
  const before = structuredClone(input), safe = publicEvidence(input), serialized = JSON.stringify(safe);
  for (const secret of secrets) assert.equal(serialized.includes(secret), false, `must omit ${secret}`);
  assert.deepEqual(input, before, 'projection cannot mutate authoritative state');
  assert.equal(safe.manual.holderProof, 'PUBLIC_HOLDER_PROOF');
  assert.equal(safe.credentials[0].verifiableCredential.proof.proofValue, 'PUBLIC_BBS_PROOF');
  assert.equal(safe.authorization.id, 'authorization-public-id');
  assert.equal(safe.authorization.token, undefined); assert.match(safe.authorization.tokenDigest, /^[a-f0-9]{64}$/);
  assert.equal(safe.manual.walletPayload.present, true); assert.match(safe.manual.walletPayload.sha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(safe.manual.verificationResult.wire.headers, { 'Content-Type': 'application/json', 'X-A2A-Extensions': 'public-extension' });
});

test('events have ordered cursors and can be replayed without consumers changing stored history', async t => {
  const directory = await temporary(t), live = await createLiveSystem({ directory });
  const received = [], unsubscribe = live.subscribe(event => received.push(event.seq));
  live.publish({ type: 'business', action: 'checkout', status: 'start', orderId: firstOrder });
  live.publish({ type: 'protocol', action: 'device-sign', status: 'complete', orderId: firstOrder });
  live.publish({ type: 'business', action: 'checkout', status: 'complete', orderId: firstOrder });
  assert.deepEqual(received, [1, 2, 3]);
  assert.deepEqual(live.events(1).map(event => event.seq), [2, 3]);
  const detached = live.events(); detached[0].action = 'consumer-change';
  assert.equal(live.events()[0].action, 'checkout');
  unsubscribe(); live.publish({ action: 'unsubscribed' }); assert.deepEqual(received, [1, 2, 3]);
  await live.flush();
});

test('restart resumes sequence from a durable journal while issuing a new runtime instance', async t => {
  const directory = await temporary(t), before = await createLiveSystem({ directory });
  before.publish({ action: 'one', orderId: firstOrder }); before.publish({ action: 'two', orderId: firstOrder }); await before.flush();
  const after = await createLiveSystem({ directory });
  assert.notEqual(after.instanceId, before.instanceId); assert.equal(after.sequence, 2);
  const event = after.publish({ action: 'three', orderId: firstOrder }); assert.equal(event.seq, 3); await after.flush();
  assert.deepEqual((await after.orderEvents(firstOrder)).map(row => row.action), ['one', 'two', 'three']);
});

test('per-order history remains separate after global memory retention has rolled over', async t => {
  const directory = await temporary(t), live = await createLiveSystem({ directory, limit: 2 });
  live.publish({ action: 'first-start', orderId: firstOrder });
  live.publish({ action: 'second-start', orderId: secondOrder });
  live.publish({ action: 'first-receipt', orderId: firstOrder, data: { transactionHash: '0x-first' } });
  live.publish({ action: 'second-rejected', orderId: secondOrder });
  live.publish({ action: 'no-order' });
  await live.flush(); assert.equal(live.events().length, 2);
  const first = await live.orderEvents(firstOrder), second = await live.orderEvents(secondOrder);
  assert.deepEqual(first.map(row => row.action), ['first-start', 'first-receipt']);
  assert.deepEqual(second.map(row => row.action), ['second-start', 'second-rejected']);
  assert.ok(first.every(row => row.orderId === firstOrder)); assert.ok(second.every(row => row.orderId === secondOrder));
});

test('a published secret is projected before subscribers or either journal can see it', async t => {
  const directory = await temporary(t), live = await createLiveSystem({ directory });
  let delivered; live.subscribe(event => { delivered = event; });
  live.publish({ action: 'redaction', orderId: firstOrder, data: { accessToken: 'ACCESS_PRIVATE_VALUE', authorization: { token: 'OWNER_PRIVATE_VALUE' }, walletPayload: { signature: 'WALLET_PRIVATE_VALUE' } } });
  await live.flush();
  const systemJournal = await readFile(join(directory, 'system-events.jsonl'), 'utf8');
  const orderJournal = await readFile(join(directory, `${firstOrder.slice(9)}.events.jsonl`), 'utf8');
  const outputs = [JSON.stringify(delivered), JSON.stringify(live.events()), systemJournal, orderJournal];
  for (const output of outputs) for (const secret of ['ACCESS_PRIVATE_VALUE', 'OWNER_PRIVATE_VALUE', 'WALLET_PRIVATE_VALUE']) assert.equal(output.includes(secret), false);
  assert.equal(delivered.orderId, firstOrder);
});

test('malformed complete journal records are ignored and valid record sequence is retained', async t => {
  const directory = await temporary(t);
  await writeFile(join(directory, 'system-events.jsonl'), `${JSON.stringify({ seq: 5, action: 'good-before' })}\ninvalid JSON\n${JSON.stringify({ seq: 6, action: 'good-after' })}\n`);
  const live = await createLiveSystem({ directory });
  assert.equal(live.sequence, 6); assert.deepEqual(live.events().map(row => row.action), ['good-before', 'good-after']);
  live.publish({ action: 'next' }); await live.flush();
  assert.equal((await createLiveSystem({ directory })).sequence, 7);
});

test('restart repairs an unterminated partial tail before appending the next durable event', async t => {
  const directory = await temporary(t);
  await writeFile(join(directory, 'system-events.jsonl'), `${JSON.stringify({ seq: 1, action: 'before-crash' })}\n{"seq":2,"action":"partial`);
  const live = await createLiveSystem({ directory }); assert.equal(live.sequence, 1);
  live.publish({ action: 'after-crash' }); await live.flush();
  const restored = await createLiveSystem({ directory });
  assert.equal(restored.sequence, 2);
  assert.deepEqual(restored.events().map(row => row.action), ['before-crash', 'after-crash']);
});

test('invalid order identifiers cannot create a path outside the event directory', async t => {
  const directory = await temporary(t), live = await createLiveSystem({ directory });
  const invalid = ['../outside', `${firstOrder}/../outside`, null, '', firstOrder.toUpperCase()];
  for (const orderId of invalid) { assert.equal(orderIdValid(orderId), false); live.publish({ orderId, action: 'invalid-id' }); assert.deepEqual(await live.orderEvents(orderId), []); }
  await live.flush(); assert.deepEqual(await readdir(directory), ['system-events.jsonl']);
});

test('snapshot subscriptions can detach and receive the explicitly projected snapshot only', async t => {
  const directory = await temporary(t), live = await createLiveSystem({ directory });
  const values = [], unsubscribe = live.subscribeSnapshots(value => values.push(value));
  live.snapshot(publicEvidence({ core: { authorization: { token: 'OWNER_PRIVATE_VALUE', id: 'public-id' } } }));
  unsubscribe(); live.snapshot({ sequence: 2 });
  assert.equal(values.length, 1); assert.equal(values[0].core.authorization.id, 'public-id');
  assert.equal(JSON.stringify(values).includes('OWNER_PRIVATE_VALUE'), false);
});
