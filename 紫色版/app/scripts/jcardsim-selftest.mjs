import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { startJCardSim } from '../lib/jcardsim.mjs';
import { identityFromPublicKey, signJwsWithSigner, verifyJws } from '../lib/identity.mjs';

const card = await startJCardSim();
try {
  const identity = identityFromPublicKey(card.publicJwk, 'self-test Java Card');
  const payload = { iss: identity.did, nonce: randomBytes(32).toString('base64url'), purpose: 'jCardSim APDU self-test' };
  const token = await signJwsWithSigner(payload, identity, 'jcard-selftest+jwt', input => card.sign(input));
  assert.deepEqual(verifyJws(token, { typ: 'jcard-selftest+jwt', expectedDid: identity.did }).payload, payload);
  const unavailableExport = await card.transmitApdu(Buffer.from('8011000000', 'hex'));
  assert.equal(unavailableExport.toString('hex'), '6d00');
  await card.setLocked(true);
  await assert.rejects(card.sign(Buffer.from('must refuse')), { code: 'ESIM_LOCKED' });
  await card.setLocked(false);
  console.log(JSON.stringify({ ok: true, marker: 'JCARD_APDU_ES256_VERIFIED', deviceDid: identity.did, noPrivateExportStatus: '6d00', ...card.publicInfo() }, null, 2));
} finally { await card.close(); }
