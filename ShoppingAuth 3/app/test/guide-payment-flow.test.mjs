import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { planPayment, paymentMilestones, verificationVerdict } from '../public/guide-model.js';

async function launch(t) {
  const directory = await mkdtemp(join(tmpdir(), 'guide-payment-flow-'));
  const child = spawn(process.execPath, ['launch.mjs'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)), detached: true, stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PORT: '0', AGENT_B_PORT: '0', ESIM_PORT: '0', OWNER_PORT: '0', PAYMENT_DB: join(directory, 'ledger.sqlite'), X402_STATE_DIR: join(directory, 'x402') },
  });
  let output = '', stopped = false;
  const exited = new Promise(resolve => { child.once('exit', () => { stopped = true; resolve(); }); child.once('error', () => { stopped = true; resolve(); }); });
  child.stdout.on('data', chunk => { output = (output + chunk).slice(-100000); });
  child.stderr.on('data', () => {});
  t.after(async () => {
    try { process.kill(-child.pid, 'SIGTERM'); } catch {}
    await Promise.race([exited, delay(5000, undefined, { ref: false })]);
    try { process.kill(-child.pid, 'SIGKILL'); } catch {}
    await exited; output = '';
    await rm(directory, { recursive: true, force: true });
  });
  for (let i = 0; i < 1000; i++) {
    if (stopped) throw new Error('Isolated guide payment launcher exited before readiness');
    const match = output.match(/(http:\/\/127\.0\.0\.1:\d+)\/#key=([A-Za-z0-9_-]{43})&ownerKey=([A-Za-z0-9_-]{43})/);
    if (match) {
      const [, baseUrl, uiKey, ownerKey] = match;
      return async (path, body, owner = false) => {
        const response = await fetch(`${baseUrl}${path}`, { method: body === undefined ? 'GET' : 'POST', signal: AbortSignal.timeout(90000),
          headers: { [owner ? 'X-Owner-UI-Key' : 'X-Demo-UI-Key']: owner ? ownerKey : uiKey, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
        const data = await response.json();
        assert.equal(response.status, 200, `${path}: ${data.error?.code ?? 'HTTP failure'}`);
        return data;
      };
    }
    await delay(50, undefined, { signal: t.signal });
  }
  throw new Error('Isolated guide payment launcher did not become ready');
}

test('guide model completes both real payment modes with explicit Owner, wallet and final settlement boundaries', { timeout: 180000 }, async t => {
  const api = await launch(t);
  for (const mode of ['bbs-bls', 'bbs-blind-bls']) await t.test(mode, async () => {
    let state = await api(`/api/dbac/payment/state?mode=${mode}`);
    const startingExecutions = state.ledger.executionCount;
    const plan = () => planPayment(state, { ownerAvailable: true });
    async function step(expected) {
      const next = plan();
      assert.equal(next.id, expected, `guide next action after ${state.manual.stage}/${state.manual.phase}`);
      assert.equal(next.enabled, true, next.reason);
      state = ['issue', 'new', 'sync'].includes(expected)
        ? await api(`/api/dbac/payment/${expected}`, { mode })
        : await api('/api/dbac/payment/manual', { mode, action: expected, ...(state.manual.attemptId ? { attemptId: state.manual.attemptId } : {}) });
      return state;
    }
    async function proof(phase, finish = true) {
      await step(`begin-${phase}`);
      for (const action of ['derive-vc', 'device-sign', 'prove']) await step(action);
      assert.equal(plan().id, 'verify');
      if (finish) {
        await step('verify');
        assert.equal(verificationVerdict(state.manual.verificationResult.verificationTrace, { phase }).status, 'pass');
      }
    }
    await step('issue');
    await proof('proposal');
    await step('submit-owner');
    assert.equal(plan().id, 'owner-review');
    assert.equal(state.ledger.executionCount, startingExecutions);
    const ownerState = await api('/owner/api/state', undefined, true);
    const proposal = ownerState.proposals.find(p => p.id === state.proposal.id);
    assert.ok(proposal);
    // This is the exact guard used by guide.js, including key order.
    assert.equal(JSON.stringify(proposal.payment, null, 2), JSON.stringify(state.order, null, 2), 'Owner and session currently normalize payment key order consistently');
    await api(`/owner/api/proposals/${proposal.id}/approve`, { confirmed: true, payment: proposal.payment, credentialHash: proposal.credentialHash }, true);
    state = await api(`/api/dbac/payment/state?mode=${mode}`);
    assert.equal(state.proposal.status, 'PENDING', 'active manual state does not silently synchronize an external Owner decision');
    assert.equal(plan().id, 'owner-review');
    assert.ok(state.manual.availableActions.includes('sync-owner'), 'recovery must explicitly read the original Owner decision');
    state = await api('/api/dbac/payment/manual', { mode, action: 'sync-owner', attemptId: state.manual.attemptId });
    assert.equal(state.proposal.status, 'APPROVED');
    assert.equal(state.ledger.executionCount, startingExecutions, 'Owner approval does not pay');
    await proof('authorize');
    assert.equal(plan().id, 'wallet-sign');
    assert.equal(state.manual.walletSigned, false);
    assert.equal(state.ledger.executionCount, startingExecutions, 'authorize proof does not request wallet or pay');
    await step('wallet-sign');
    // A browser losing the returned response can recover the actual server
    // state without issuing another wallet-sign action.
    state = await api(`/api/dbac/payment/state?mode=${mode}`);
    assert.equal(state.manual.walletSigned, true);
    assert.equal(plan().id, 'begin-settle');
    assert.equal(state.ledger.executionCount, startingExecutions, 'wallet signature is not settlement');
    await proof('settle', false);
    assert.equal(state.ledger.executionCount, startingExecutions, 'preparing a settle proof never executes the final submission');
    assert.equal(state.manual.settled, false);
    assert.match(plan().label, /模拟支付/);
    await step('verify');
    assert.equal(state.manual.settled, true);
    assert.equal(state.manual.verificationResult.paymentResult.outcome, 'EXECUTED');
    assert.equal(state.ledger.executionCount, startingExecutions + 1);
    assert.ok(paymentMilestones(state).every(item => item.status === 'pass'));
    const orderId = state.order.orderId;
    state = await api(`/api/dbac/payment/state?mode=${mode}`);
    assert.equal(state.ledger.executionCount, startingExecutions + 1, 'refresh reads the original receipt, without paying again');
    await step('discard');
    assert.equal(state.ledger.receipts.some(receipt => receipt.orderId === orderId), true);
    await step('new');
    assert.notEqual(state.order.orderId, orderId);
    assert.equal(state.manual.walletSigned, false);
    assert.equal(plan().id, 'begin-proposal');
    assert.equal(state.ledger.executionCount, startingExecutions + 1);
    assert.equal(state.ledger.receipts.some(receipt => receipt.orderId === orderId), true, 'reset preserves the original test-chain receipt');
  });
});
