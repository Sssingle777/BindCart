import assert from 'node:assert/strict';
import { createPublicKey, verify, randomBytes } from 'node:crypto';
import test from 'node:test';
import { startJCardSim, derToP1363 } from '../lib/jcardsim.mjs';
import { identityFromPublicKey, signJwsWithSigner, verifyJws } from '../lib/identity.mjs';

test('actual Java Card applet signs streamed APDUs and concurrent transactions stay separate', async t => {
  const card = await startJCardSim(); t.after(() => card.close());
  assert.equal(card.publicInfo().backend, 'jcardsim');
  assert.notEqual(card.publicInfo().javaPid, process.pid);
  assert.equal(card.publicInfo().keyExportable, false);
  assert.deepEqual(Object.keys(card.publicJwk).sort(), ['crv', 'kty', 'x', 'y']);
  const publicKey = createPublicKey({ key: card.publicJwk, format: 'jwk' });
  const inputs = [Buffer.from('small input'), randomBytes(221), randomBytes(15000)];
  const signatures = await Promise.all(inputs.map(input => card.sign(input)));
  for (let i = 0; i < inputs.length; i++) {
    assert.equal(signatures[i].length, 64);
    assert.equal(verify('sha256', inputs[i], { key: publicKey, dsaEncoding: 'ieee-p1363' }, signatures[i]), true);
    assert.equal(verify('sha256', Buffer.concat([inputs[i], Buffer.from('tampered')]), { key: publicKey, dsaEncoding: 'ieee-p1363' }, signatures[i]), false);
  }
  assert.equal(card.publicInfo().signatures, 3);
  assert.ok(card.publicInfo().apduCommands > 70);
  const repeated = await card.sign(inputs[0]);
  assert.notDeepEqual(repeated, signatures[0], 'separate ECDSA invocations must not reuse simulator nonces');
});

test('applet exposes public point but rejects private-key export, wrong CLA and uninitialized signing', async t => {
  const card = await startJCardSim(); t.after(() => card.close());
  const point = await card.transmitApdu(Buffer.from('8010000000', 'hex'));
  assert.equal(point.length, 67);
  assert.equal(point[0], 4);
  assert.equal(point.subarray(-2).toString('hex'), '9000');
  for (const ins of ['11', '12', '13', 'ff']) {
    assert.equal((await card.transmitApdu(Buffer.from(`80${ins}000000`, 'hex'))).toString('hex'), '6d00');
  }
  assert.equal((await card.transmitApdu(Buffer.from('0020000000', 'hex'))).toString('hex'), '6e00');
  assert.equal((await card.transmitApdu(Buffer.from('80220000010100', 'hex'))).toString('hex'), '6985');
  await card.setLocked(true);
  await assert.rejects(card.sign(Buffer.from('must refuse')), { code: 'ESIM_LOCKED' });
  const status = await card.transmitApdu(Buffer.from('8040000000', 'hex'));
  assert.equal(status.toString('hex'), '010101019000');
  await card.setLocked(false);
  assert.equal((await card.sign(Buffer.from('after unlock'))).length, 64);
});

test('jCardSim public identity signs verifiable ES256 JWS with no private key crossing into Node', async t => {
  const card = await startJCardSim(); t.after(() => card.close());
  const identity = identityFromPublicKey(card.publicJwk, 'Java Card device');
  assert.equal(identity.privateKey, undefined);
  assert.equal(identity.publicJwk.d, undefined);
  const payload = { iss: identity.did, text: 'APDU-backed JWS' };
  const token = await signJwsWithSigner(payload, identity, 'test-card+jwt', input => card.sign(input));
  const verified = verifyJws(token, { typ: 'test-card+jwt', expectedDid: identity.did });
  assert.equal(verified.header.alg, 'ES256');
  assert.deepEqual(verified.payload, payload);
  assert.equal(card.publicInfo().signatures, 1);
});

test('new simulated card session generates a different public key', async () => {
  const first = await startJCardSim(); const key = first.publicJwk.x;
  await first.close();
  const second = await startJCardSim();
  try { assert.notEqual(second.publicJwk.x, key); }
  finally { await second.close(); }
});

test('DER conversion rejects malformed, negative and non-canonical integer encodings', () => {
  for (const bytes of ['00', '30060201010201ff', '300702020001020101', '3006020101020101ff']) {
    assert.throws(() => derToP1363(Buffer.from(bytes, 'hex')), { code: 'JCARD_BAD_SIGNATURE' });
  }
});
