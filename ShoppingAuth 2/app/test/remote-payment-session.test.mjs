import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { generateIdentity } from '../lib/identity.mjs';
import { createOwner } from '../lib/owner.mjs';
import { createVerifier } from '../lib/verifier.mjs';
import { createEsim } from '../lib/esim.mjs';
import { createSession } from '../lib/session.mjs';
import { AppError } from '../lib/protocol.mjs';

const capability = () => randomBytes(32).toString('base64url');

async function fixture(t, { x402Backend, x402Payer, paymentInfo } = {}) {
  const issuer = generateIdentity('remote-session-issuer');
  const agentA = generateIdentity('remote-session-A');
  const agentB = generateIdentity('remote-session-B');
  const proposalToken = capability(), ownerUiToken = capability(), adminToken = capability(), accessToken = capability();
  const owner = createOwner({ holderDid: agentA.did, verifierDid: agentB.did, trustedIssuers: [issuer.did], proposalToken, uiToken: ownerUiToken });
  t.after(() => owner.close());
  const ownerUrl = await owner.listen();
  const verifier = createVerifier({ identity: agentB, trustedIssuers: new Set([issuer.did]), trustedAuthorizers: new Set([owner.publicInfo().did]), adminToken, x402Backend, requireX402: Boolean(x402Backend) });
  t.after(() => verifier.close());
  const baseUrl = await verifier.listen();
  const esim = createEsim({ accessToken, holderDid: agentA.did, verifierDid: agentB.did, verifierUrl: baseUrl, trustedIssuers: [issuer.did] });
  t.after(() => esim.close());
  const deviceUrl = await esim.listen();
  const session = createSession({
    issuer, agentA, verifierDid: agentB.did, baseUrl, adminToken,
    device: { did: esim.publicInfo().did, baseUrl: deviceUrl, accessToken },
    owner: { did: owner.publicInfo().did, baseUrl: ownerUrl, proposalToken },
    x402Payer, paymentInfo,
  });
  session.issue();
  const ledger = async () => {
    const response = await fetch(`${baseUrl}/admin/ledger`, { headers: { 'X-Demo-Admin': adminToken }, signal: AbortSignal.timeout(5000) });
    assert.equal(response.status, 200);
    return response.json();
  };
  const decide = async (proposal, action) => {
    const body = action === 'approve'
      ? { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }
      : { rejected: true };
    const response = await fetch(`${ownerUrl}/api/proposals/${proposal.id}/${action}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Owner-UI-Key': ownerUiToken },
      body: JSON.stringify(body), signal: AbortSignal.timeout(5000),
    });
    const result = await response.json();
    assert.equal(response.status, 200, JSON.stringify(result.error));
    return result;
  };
  const propose = async () => {
    const current = await session.payment.state();
    const result = await session.payment.propose({ payment: current.order });
    assert.equal(result.proposal.status, 'PENDING');
    assert.equal(result.authorization, null);
    return result.proposal;
  };
  return { session, ownerUrl, ledger, propose, approve: proposal => decide(proposal, 'approve'), reject: proposal => decide(proposal, 'reject') };
}

function assertUnspent(snapshot) {
  assert.equal(snapshot.executionCount, 0);
  assert.deepEqual(Object.fromEntries(snapshot.accounts.map(account => [account.id, account.balanceMinor])), {
    'demo:alice': 100000, 'merchant:keyboard': 0, 'merchant:other': 0,
  });
}

test('remote Owner rejection remains authoritative after A sync and cannot turn into a payment', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  const proposal = await f.propose();
  assert.equal((await f.reject(proposal)).status, 'REJECTED');
  const synced = await f.session.payment.sync();
  assert.equal(synced.proposal.id, proposal.id);
  assert.equal(synced.proposal.status, 'REJECTED');
  assert.equal(synced.authorization, null);
  await assert.rejects(f.session.payment.pay(), { code: 'OWNER_APPROVAL_REJECTED' });
  await assert.rejects(f.session.payment.retry(), { code: 'OWNER_APPROVAL_REJECTED' });
  assertUnspent(await f.ledger());
});

test('new order and newly issued VC discard old proposals; later old approvals cannot revive them', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  const oldOrderProposal = await f.propose();
  const newOrderState = await f.session.payment.newOrder();
  assert.notEqual(newOrderState.order.orderId, oldOrderProposal.payment.orderId);
  assert.equal(newOrderState.proposal, null);
  assert.equal(newOrderState.authorization, null);
  await f.approve(oldOrderProposal);
  const afterOldOrderApproval = await f.session.payment.sync();
  assert.equal(afterOldOrderApproval.order.orderId, newOrderState.order.orderId);
  assert.equal(afterOldOrderApproval.proposal, null);
  assert.equal(afterOldOrderApproval.authorization, null);
  await assert.rejects(f.session.payment.pay(), { code: 'OWNER_CONFIRMATION_REQUIRED' });

  const oldCredentialProposal = await f.propose();
  const oldCredentialId = f.session.state().credential.id;
  f.session.issue();
  assert.notEqual(f.session.state().credential.id, oldCredentialId);
  await f.approve(oldCredentialProposal);
  const afterOldCredentialApproval = await f.session.payment.sync();
  assert.equal(afterOldCredentialApproval.order.orderId, newOrderState.order.orderId);
  assert.equal(afterOldCredentialApproval.proposal, null);
  assert.equal(afterOldCredentialApproval.authorization, null);
  await assert.rejects(f.session.payment.pay(), { code: 'OWNER_CONFIRMATION_REQUIRED' });
  assertUnspent(await f.ledger());

  const currentProposal = await f.propose();
  const approved = await f.approve(currentProposal);
  const accepted = await f.session.payment.sync();
  assert.equal(accepted.authorization.id, approved.authorization.id);
  const paid = await f.session.payment.pay();
  assert.equal(paid.paymentResult.outcome, 'EXECUTED');
  assert.equal(paid.paymentResult.receipt.orderId, newOrderState.order.orderId);
  assert.equal((await f.ledger()).executionCount, 1);
});

test('late delivery of a real approved Owner response cannot overwrite state invalidated by order or VC changes', { timeout: 25000 }, async t => {
  for (const mutation of ['invalidate', 'newOrder', 'issue']) {
    const f = await fixture(t);
    const previous = await f.propose();
    await f.approve(previous);
    const target = `${f.ownerUrl}/proposals/${encodeURIComponent(previous.id)}`;
    const networkFetch = globalThis.fetch;
    let intercepted = false, release, arrived;
    const deliveryGate = new Promise(resolve => { release = resolve; });
    const responseArrived = new Promise(resolve => { arrived = resolve; });
    // Every byte comes from a real HTTP service. Only delivery of this one
    // already-completed GET is delayed; no signature or response is fabricated.
    const wrapper = t.mock.method(globalThis, 'fetch', async (url, options) => {
      const shouldHold = !intercepted && String(url) === target && (options?.method ?? 'GET') === 'GET';
      if (shouldHold) intercepted = true;
      const response = await networkFetch(url, options);
      if (shouldHold) {
        arrived(response.status);
        await deliveryGate;
      }
      return response;
    });
    const syncing = f.session.payment.sync();
    // Install rejection handling immediately while awaiting the network barrier.
    syncing.catch(() => {});
    let timer;
    try {
      const status = await Promise.race([
        responseArrived,
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`Approved Owner response did not arrive (${mutation}).`)), 5000); }),
      ]);
      clearTimeout(timer);
      assert.equal(status, 200);
      const beforeToken = f.session.state().credential.token;
      if (mutation === 'newOrder') await f.session.payment.newOrder();
      else if (mutation === 'issue') f.session.issue();
      else f.session.payment.invalidate();
      const currentOrder = (await f.session.payment.state()).order;
      const currentToken = f.session.state().credential.token;
      if (mutation === 'newOrder') assert.notEqual(currentOrder.orderId, previous.payment.orderId);
      if (mutation === 'issue') assert.notEqual(currentToken, beforeToken);
      const replacement = await f.propose();
      assert.notEqual(replacement.id, previous.id);
      release();
      const settled = await syncing;
      assert.equal(settled.order.orderId, currentOrder.orderId, mutation);
      assert.equal(settled.proposal.id, replacement.id, mutation);
      assert.equal(settled.proposal.status, 'PENDING', mutation);
      assert.equal(settled.authorization, null, mutation);
      assert.equal(settled.owner.available, true, mutation);
      assert.equal(f.session.state().credential.token, currentToken, mutation);
      assertUnspent(await f.ledger());
      wrapper.mock.restore();

      const approval = await f.approve(replacement);
      const fresh = await f.session.payment.sync();
      assert.equal(fresh.authorization.id, approval.authorization.id, mutation);
      const paid = await f.session.payment.pay();
      assert.equal(paid.paymentResult.outcome, 'EXECUTED', mutation);
      assert.equal(paid.paymentResult.receipt.orderId, currentOrder.orderId, mutation);
      assert.equal((await f.ledger()).executionCount, 1, mutation);
    } finally {
      clearTimeout(timer);
      release();
      await syncing.catch(() => {});
      wrapper.mock.restore();
      assert.equal(globalThis.fetch, networkFetch, 'the original network client is restored');
    }
  }
});

for (const earlierResponse of ['pending', 'failure']) {
  test(`a late real ${earlierResponse} Owner response cannot overwrite a newer approved sync for the same proposal`, { timeout: 15000 }, async t => {
    const f = await fixture(t);
    const proposal = await f.propose();
    const target = `${f.ownerUrl}/proposals/${encodeURIComponent(proposal.id)}`;
    const networkFetch = globalThis.fetch;
    let intercepted = false, release, arrived;
    const deliveryGate = new Promise(resolve => { release = resolve; });
    const responseArrived = new Promise(resolve => { arrived = resolve; });
    const wrapper = t.mock.method(globalThis, 'fetch', async (url, options) => {
      const shouldHold = !intercepted && String(url) === target && (options?.method ?? 'GET') === 'GET';
      if (shouldHold) intercepted = true;
      let forwarded = options;
      if (shouldHold && earlierResponse === 'failure') {
        // Ask the real Owner to reject one request. The response, including its
        // error code and HTTP status, is neither mocked nor rewritten.
        const headers = new Headers(options?.headers);
        headers.set('X-Owner-Proposal', capability());
        forwarded = { ...options, headers };
      }
      const response = await networkFetch(url, forwarded);
      if (shouldHold) {
        arrived({ status: response.status, body: await response.clone().json() });
        await deliveryGate;
      }
      return response;
    });
    // state() does one GET. sync() would do another GET after the delayed one,
    // potentially repairing the stale state and hiding the race under test.
    const earlierState = f.session.payment.state();
    earlierState.catch(() => {});
    let timer;
    try {
      const response = await Promise.race([
        responseArrived,
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`Earlier ${earlierResponse} Owner response did not arrive.`)), 5000); }),
      ]);
      clearTimeout(timer);
      if (earlierResponse === 'pending') {
        assert.equal(response.status, 200);
        assert.equal(response.body.id, proposal.id);
        assert.equal(response.body.status, 'PENDING');
      } else {
        assert.equal(response.status, 403);
        assert.equal(response.body.error.code, 'OWNER_PROPOSAL_ACCESS_DENIED');
      }

      const approved = await f.approve(proposal);
      const latest = await f.session.payment.sync();
      assert.equal(latest.proposal.id, proposal.id);
      assert.equal(latest.proposal.status, 'APPROVED');
      assert.equal(latest.authorization.token, approved.authorization.token);
      assert.equal(latest.owner.available, true);
      assert.equal(latest.owner.error, undefined);

      release();
      const settled = await earlierState;
      assert.equal(settled.proposal.id, proposal.id);
      assert.equal(settled.proposal.status, 'APPROVED');
      assert.equal(settled.authorization.token, approved.authorization.token);
      assert.equal(settled.owner.available, true);
      assert.equal(settled.owner.error, undefined);
      assertUnspent(await f.ledger());
      wrapper.mock.restore();

      const paid = await f.session.payment.pay();
      assert.equal(paid.paymentResult.outcome, 'EXECUTED');
      assert.equal(paid.paymentResult.receipt.orderId, proposal.payment.orderId);
      assert.equal((await f.ledger()).executionCount, 1);
    } finally {
      clearTimeout(timer);
      release();
      await earlierState.catch(() => {});
      wrapper.mock.restore();
      assert.equal(globalThis.fetch, networkFetch, 'the original network client is restored');
    }
  });
}


test('payment acceptance keeps successful, rejected and concurrent verifier traces', { timeout: 15000 }, async t => {
  const f = await fixture(t);
  await f.approve(await f.propose());
  await f.session.payment.sync();
  const report = await f.session.payment.demo();
  assert.equal(report.passed, report.total, JSON.stringify(report.results));
  assert.equal(report.total, 13);
  assert.equal(report.verificationTrace.outcome, 'pass');
  const invocationRows = report.results.slice(0, 10);
  assert.ok(invocationRows.every(row => row.verificationTrace?.source === 'agent-b'));
  for (const row of invocationRows) {
    const trace = row.verificationTrace;
    if (['EXECUTED', 'ALREADY_PROCESSED'].includes(row.actual) || row.verificationTraces) {
      assert.equal(trace.outcome, 'pass', row.name);
      assert.ok(trace.steps.every(step => step.status === 'pass'), row.name);
    } else {
      assert.equal(trace.outcome, 'fail', row.name);
      const position = trace.steps.findIndex(step => step.status === 'fail');
      assert.ok(position >= 0, row.name);
      assert.equal(trace.steps[position].code, row.actual, row.name);
      assert.ok(trace.steps.slice(position + 1).every(step => step.status === 'skipped'), row.name);
    }
  }
  const concurrent = invocationRows.find(row => row.verificationTraces);
  assert.equal(concurrent.verificationTraces.length, 8);
  assert.ok(concurrent.verificationTraces.every(trace => trace.outcome === 'pass' && trace.steps.every(step => step.status === 'pass')));
  assert.ok(report.results.slice(10).every(row => !row.verificationTrace), 'ledger comparisons must not invent B verification traces');
  assert.equal(report.afterLedger.executionCount, report.beforeLedger.executionCount + 1);
});

test('a signed failed x402 continuation keeps its verifier trace when the payment client throws', { timeout: 15000 }, async t => {
  const paymentInfo = { network: 'eip155:31337', asset: `0x${'1'.repeat(40)}`, payees: { 'merchant:keyboard': `0x${'2'.repeat(40)}` }, payerAddress: `0x${'3'.repeat(40)}` };
  let executions = 0;
  // Fault injection is limited to settlement and payer payload creation. The
  // Owner approval, device signatures, A2A exchanges and B response are real.
  const x402Backend = {
    async snapshot() { return { receipts: [], accounts: [], executionCount: 0 }; },
    async requirements(payment, { resourceUrl }) {
      return { x402Version: 2, resource: { url: resourceUrl }, accepts: [{ scheme: 'exact', network: payment.settlement.network, amount: String(payment.amountMinor), asset: payment.settlement.asset, payTo: payment.settlement.payTo, maxTimeoutSeconds: 60 }] };
    },
    async execute() { executions++; throw new AppError('X402_VERIFICATION_FAILED', 'Injected settlement rejection', 403); },
  };
  const f = await fixture(t, { paymentInfo, x402Backend, x402Payer: { async createPayload() { return { fixture: 'signed-failure-test' }; } } });
  await f.approve(await f.propose());
  await f.session.payment.sync();
  await assert.rejects(() => f.session.payment.pay(), error => {
    assert.equal(error.code, 'X402_VERIFICATION_FAILED');
    assert.equal(error.verificationTrace.source, 'agent-b');
    assert.equal(error.verificationTrace.outcome, 'fail');
    const steps = error.verificationTrace.steps;
    assert.ok(steps.slice(0, -1).every(step => step.status === 'pass'));
    assert.equal(steps.at(-1).id, 'execution');
    assert.equal(steps.at(-1).status, 'fail');
    assert.equal(steps.at(-1).code, error.code);
    return true;
  });
  assert.equal(executions, 1);
});
