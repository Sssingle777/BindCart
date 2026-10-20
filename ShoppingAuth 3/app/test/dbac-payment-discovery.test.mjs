import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import Ajv from 'ajv';
import { generateIdentity } from '../lib/identity.mjs';
import { digest, parseObject, readBody, sendJson } from '../lib/protocol.mjs';
import { createVerifier } from '../lib/verifier.mjs';
import { createDbacIssuer, createDbacDevice } from '../lib/dbac/services.mjs';
import { createDbacPaymentSession } from '../lib/dbac/payment-session.mjs';
import { DBAC_EXTENSION } from '../lib/dbac/policy.mjs';
import { DBAC_PAYMENT_PROFILE, DBAC_PAYMENT_CHALLENGE_TYP, DBAC_PAYMENT_RESPONSE_TYP, verifyDbacPaymentEvidence } from '../lib/dbac/payment-policy.mjs';

const ajv = new Ajv({ strict: false, allErrors: true, validateFormats: false });
ajv.addSchema(JSON.parse(readFileSync(new URL('../vendor/a2a-v0.3.0.schema.json', import.meta.url))), 'a2a-0.3.0');
const officialCard = ajv.compile({ $ref: 'a2a-0.3.0#/definitions/AgentCard' });
const token = () => randomBytes(32).toString('base64url');

async function runtime(t) {
  const b = generateIdentity('B'), owner = generateIdentity('Owner'), identifiedIssuer = generateIdentity('Legacy issuer');
  const deviceToken = token(), issuerToken = token();
  const device = createDbacDevice({ accessToken: deviceToken }), deviceUrl = await device.listen();
  t.after(() => device.close());
  const issuer = createDbacIssuer({ accessToken: issuerToken, devicePublicKeys: device.publicInfo().publicKeys }), issuerUrl = await issuer.listen();
  t.after(() => issuer.close());
  const verifier = createVerifier({ identity: b, trustedIssuers: [identifiedIssuer.did], trustedAuthorizers: [owner.did], adminToken: token(), dbac: { issuerPublicKey: issuer.publicInfo().publicKey } });
  const baseUrl = await verifier.listen();
  t.after(() => verifier.close());
  return { b, owner, baseUrl, issuer: { baseUrl: issuerUrl, publicKey: issuer.publicInfo().publicKey, accessToken: issuerToken }, device: { baseUrl: deviceUrl, publicKeys: device.publicInfo().publicKeys, accessToken: deviceToken } };
}

test('A2A discovery points to the DBAC payment card while retaining the auxiliary echo card', async t => {
  const f = await runtime(t);
  const read = async path => { const response = await fetch(`${f.baseUrl}${path}`); assert.equal(response.status, 200); return response.json(); };
  const main = await read('/.well-known/agent-card.json');
  const extension = main.capabilities.extensions.find(item => item.uri === DBAC_EXTENSION);
  assert.equal(extension.params.agentCardUrl, `${f.baseUrl}/dbac/payment/agent-card.json`);
  assert.equal(extension.params.endpoint, `${f.baseUrl}/dbac/payment/a2a`);
  assert.equal(extension.params.auxAgentCardUrl, `${f.baseUrl}/dbac/agent-card.json`);
  const payment = await read('/dbac/payment/agent-card.json');
  assert.equal(officialCard(payment), true, ajv.errorsText(officialCard.errors));
  assert.equal(payment.url, `${f.baseUrl}/dbac/payment/a2a`);
  assert.deepEqual(payment.skills.map(skill => skill.id), ['payments:pay']);
  const policy = payment.capabilities.extensions.find(item => item.uri === DBAC_EXTENSION);
  assert.equal(policy.required, true);
  assert.equal(policy.params.paymentSupported, true);
  assert.equal(policy.params.ownerApprovalRequired, true);
  assert.equal(policy.params.anonymousSettlement, false);
  assert.equal(policy.params.devicePseudonymScope, 'one-order');
  assert.deepEqual(policy.params.phases, ['proposal', 'authorize', 'settle']);
  assert.equal(policy.params.challengeUrl, `${f.baseUrl}/dbac/payment/challenge`);
  assert.equal(policy.params.challengeType, DBAC_PAYMENT_CHALLENGE_TYP);
  assert.equal(policy.params.responseType, DBAC_PAYMENT_RESPONSE_TYP);
  assert.equal(policy.params.responseHeader, 'X-A2A-DBAC-Payment-Response');
  assert.equal(payment.security, undefined, 'the DBAC payment endpoint does not require the identified bearer credential');
  const auxiliary = await read('/dbac/agent-card.json');
  assert.equal(officialCard(auxiliary), true, ajv.errorsText(officialCard.errors));
  assert.deepEqual(auxiliary.skills.map(skill => skill.id), ['demo:echo']);
  assert.equal(auxiliary.capabilities.extensions[0].params.paymentSupported, false);
});

test('late Owner HTTP responses cannot replace a new payment order or mark its absent proposal expired', { timeout: 30000 }, async t => {
  const f = await runtime(t);
  let proposal, blocked = null;
  const ownerServer = http.createServer(async (req, res) => {
    try {
      if (req.method === 'POST' && req.url === '/proposals') {
        const body = parseObject(await readBody(req));
        const { gate } = verifyDbacPaymentEvidence(body.dbacEvidence, { verifierDid: f.b.did, issuerPublicKey: f.issuer.publicKey, phase: 'proposal', payment: body.payment });
        proposal = { id: randomUUID(), status: 'PENDING', profile: DBAC_PAYMENT_PROFILE, mode: gate.mode, orderKey: gate.orderKey, payment: body.payment, credentialHash: digest(JSON.stringify(body.dbacEvidence)), verifierDid: f.b.did };
        return sendJson(res, 200, proposal);
      }
      if (req.method === 'GET' && req.url === `/proposals/${proposal?.id}`) {
        const snapshot = structuredClone(proposal), wait = blocked;
        if (wait) { wait.arrived(); await wait.release; }
        if (wait?.expired) return sendJson(res, 410, { error: { code: 'OWNER_PROPOSAL_EXPIRED', message: 'Old fixture proposal expired.' } });
        return sendJson(res, 200, snapshot);
      }
      sendJson(res, 404, { error: { code: 'NOT_FOUND' } });
    } catch (error) { sendJson(res, error.status ?? 400, { error: { code: error.code, message: error.message } }); }
  });
  await new Promise((resolve, reject) => { ownerServer.once('error', reject); ownerServer.listen(0, '127.0.0.1', resolve); });
  t.after(async () => { ownerServer.closeAllConnections(); await new Promise(resolve => ownerServer.close(resolve)); });
  const session = createDbacPaymentSession({ baseUrl: f.baseUrl, verifierDid: f.b.did, issuer: f.issuer, device: f.device,
    owner: { did: f.owner.did, baseUrl: `http://127.0.0.1:${ownerServer.address().port}`, proposalToken: token() },
    x402Payer: { createPayload() { assert.fail('This synchronization test must never request a wallet signature.'); } },
    paymentInfo: { network: 'eip155:31337', asset: `0x${'1'.repeat(40)}`, payerAddress: `0x${'2'.repeat(40)}`, payees: { 'merchant:keyboard': `0x${'3'.repeat(40)}` } },
    getLedger: async () => ({ accounts: [], receipts: [], executionCount: 0 }),
  });
  await session.issue();
  for (const expired of [false, true]) {
    await session.propose();
    let arrived, release;
    const arrivedPromise = new Promise(resolve => { arrived = resolve; });
    blocked = { expired, arrived, release: new Promise(resolve => { release = resolve; }) };
    const oldState = session.state();
    try {
      await arrivedPromise;
      const fresh = await session.newOrder();
      release();
      const returned = await oldState;
      assert.equal(returned.order.orderId, fresh.order.orderId);
      assert.equal(returned.proposal, null);
      assert.equal(returned.authorization, null);
      assert.equal(returned.owner.available, true);
      assert.equal(returned.owner.error, undefined);
    } finally { release(); blocked = null; }
  }
});
