import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, lstatSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { createLedger, LedgerError } from '../lib/ledger.mjs';

const digest = value => createHash('sha256').update(value).digest('base64url');
const authorizerDid = 'did:example:authorizer';
const holderDid = 'did:example:holder';
const deviceDid = 'did:example:device';
const verifierDid = 'did:example:verifier';
function input(overrides = {}) {
  const authorizationId = overrides.authorizationId ?? `urn:uuid:${randomUUID()}`;
  return {
    authorizationId, authorizationHash: digest(authorizationId), authorizerDid, holderDid, deviceDid, verifierDid,
    payment: { orderId: `order-${randomUUID()}`, payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', amountMinor: 12500, currency: 'CNY' },
    ...overrides,
  };
}
function failWith(code, action, status = 400) {
  assert.throws(action, error => error instanceof LedgerError && error.code === code && error.status === status, code);
}
function memory(t) { const ledger = createLedger(); t.after(() => ledger.close()); return ledger; }
function temporary(t) {
  const dir = mkdtempSync(join(tmpdir(), 'a2a-payment-ledger-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
function balances(ledger) { return Object.fromEntries(ledger.snapshot().accounts.map(account => [account.id, account.balanceMinor])); }

test('simulated ledger atomically debits and credits integer minor units without changing total funds', t => {
  const ledger = memory(t);
  assert.deepEqual(balances(ledger), { 'demo:alice': 100000, 'merchant:keyboard': 0, 'merchant:other': 0 });
  const authorization = input();
  const result = ledger.execute(authorization);
  assert.equal(result.outcome, 'EXECUTED');
  assert.match(result.receipt.receiptId, /^urn:uuid:/);
  for (const field of ['authorizationId', 'authorizerDid', 'holderDid', 'deviceDid', 'verifierDid']) assert.equal(result.receipt[field], authorization[field]);
  for (const [field, value] of Object.entries(authorization.payment)) assert.equal(result.receipt[field], value);
  assert.ok(Number.isFinite(Date.parse(result.receipt.executedAt)));
  assert.equal(result.receipt.payerBalanceMinor, 87500);
  assert.equal(result.receipt.payeeBalanceMinor, 12500);
  const snapshot = ledger.snapshot();
  assert.equal(snapshot.currency, 'CNY');
  assert.equal(snapshot.executionCount, 1);
  assert.deepEqual(snapshot.receipts, [result.receipt]);
  assert.equal(snapshot.accounts.reduce((sum, account) => sum + account.balanceMinor, 0), 100000);
});

test('insufficient funds rolls back all balances, execution and authorization consumption', t => {
  const ledger = memory(t);
  const authorization = input(); authorization.payment.amountMinor = 100001;
  const before = ledger.snapshot();
  failWith('INSUFFICIENT_FUNDS', () => ledger.execute(authorization), 409);
  assert.deepEqual(ledger.snapshot(), before);
  authorization.payment.amountMinor = 100000;
  const result = ledger.execute(authorization);
  assert.equal(result.outcome, 'EXECUTED');
  assert.equal(balances(ledger)['demo:alice'], 0);
  assert.equal(balances(ledger)['merchant:keyboard'], 100000);
});

test('same authorization retry returns the exact original receipt despite later balance changes', t => {
  const ledger = memory(t);
  const authorization = input();
  const first = ledger.execute(authorization);
  ledger.execute(input());
  const repeat = ledger.execute(structuredClone(authorization));
  assert.equal(repeat.outcome, 'ALREADY_PROCESSED');
  assert.deepEqual(repeat.receipt, first.receipt);
  assert.equal(ledger.snapshot().executionCount, 2);
  assert.equal(balances(ledger)['demo:alice'], 75000);
  const reordered = { ...authorization, payment: { currency: 'CNY', amountMinor: 12500, payeeAccount: 'merchant:keyboard', payerAccount: 'demo:alice', orderId: authorization.payment.orderId } };
  assert.deepEqual(ledger.execute(reordered).receipt, first.receipt);
});

test('a new authorization and new identities for an already paid order reuse its receipt and consume the new authorization', t => {
  const ledger = memory(t);
  const firstInput = input();
  const first = ledger.execute(firstInput);
  const secondInput = input({ payment: structuredClone(firstInput.payment), authorizerDid: 'did:example:new-owner', holderDid: 'did:example:new-holder', deviceDid: 'did:example:new-device', verifierDid: 'did:example:new-verifier' });
  const second = ledger.execute(secondInput);
  assert.equal(second.outcome, 'ALREADY_PROCESSED');
  assert.deepEqual(second.receipt, first.receipt);
  assert.deepEqual(ledger.execute(secondInput).receipt, first.receipt);
  assert.equal(ledger.snapshot().executionCount, 1);
  assert.equal(balances(ledger)['demo:alice'], 87500);
  const reused = structuredClone(secondInput); reused.payment.orderId = 'another-order';
  failWith('AUTHORIZATION_CONFLICT', () => ledger.execute(reused), 409);
  assert.equal(ledger.snapshot().executionCount, 1);
});

test('one authorization cannot change its hash, identities or any valid payment term', t => {
  const ledger = memory(t);
  const authorization = input(); ledger.execute(authorization);
  const before = ledger.snapshot();
  const changes = [
    value => { value.authorizationHash = digest('other authorization'); },
    ...['authorizerDid', 'holderDid', 'deviceDid', 'verifierDid'].map(field => value => { value[field] = 'did:example:different'; }),
    value => { value.payment.orderId = 'other-order'; },
    value => { value.payment.amountMinor = 1; },
    value => { value.payment.payeeAccount = 'merchant:other'; },
  ];
  for (const mutate of changes) {
    const changed = structuredClone(authorization); mutate(changed);
    failWith('AUTHORIZATION_CONFLICT', () => ledger.execute(changed), 409);
    assert.deepEqual(ledger.snapshot(), before);
  }
});

test('the same payer/order cannot change amount or merchant through a new authorization', t => {
  const ledger = memory(t);
  const authorization = input(); const first = ledger.execute(authorization);
  for (const change of [{ amountMinor: 1 }, { payeeAccount: 'merchant:other' }]) {
    const another = input({ payment: { ...authorization.payment, ...change } });
    failWith('PAYMENT_ORDER_CONFLICT', () => ledger.execute(another), 409);
    // A rejected new authorization was not consumed by the failed transaction.
    another.payment = { ...authorization.payment };
    assert.deepEqual(ledger.execute(another).receipt, first.receipt);
  }
  assert.equal(ledger.snapshot().executionCount, 1);
});

test('invalid account directions, currencies, amounts and malformed structures never mutate the ledger', t => {
  const ledger = memory(t);
  const before = ledger.snapshot();
  const base = input();
  const invalidPayments = [
    null, [], {}, { ...base.payment, extra: true },
    ...[0, -0, -1, 0.1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, '100', 1n, true, null].map(amountMinor => ({ ...base.payment, amountMinor })),
    ...[
      { payerAccount: 'merchant:keyboard', payeeAccount: 'demo:alice' },
      { payerAccount: 'demo:alice', payeeAccount: 'demo:alice' },
      { payerAccount: 'unknown' }, { payeeAccount: 'unknown' }, { currency: 'USD' }, { currency: 'cny' }, { orderId: '' },
    ].map(change => ({ ...base.payment, ...change })),
  ];
  for (const payment of invalidPayments) failWith('INVALID_PAYMENT', () => ledger.execute({ ...base, payment }));
  for (const malformed of [null, [], {}, { ...base, extra: true }, { ...base, authorizationId: '' }, { ...base, authorizationHash: 'bad' }, { ...base, holderDid: 'holder' }]) {
    failWith('INVALID_AUTHORIZATION', () => ledger.execute(malformed));
  }
  assert.deepEqual(ledger.snapshot(), before);
});

test('file-backed receipt, authorization aliases, balances and credential revocations survive reopen', t => {
  const dir = temporary(t);
  const path = join(dir, 'private', 'payment.sqlite');
  const firstInput = input();
  const secondInput = input({ payment: firstInput.payment });
  let ledger = createLedger({ path });
  const first = ledger.execute(firstInput);
  ledger.execute(secondInput);
  ledger.revokeCredential('urn:uuid:revoked-vc');
  ledger.revokeCredential('urn:uuid:revoked-vc');
  const snapshot = ledger.snapshot();
  ledger.close();
  assert.equal(lstatSync(join(dir, 'private')).mode & 0o777, 0o700);
  assert.equal(lstatSync(path).mode & 0o777, 0o600);
  ledger = createLedger({ path });
  try {
    assert.deepEqual(ledger.snapshot(), snapshot);
    assert.equal(ledger.execute(firstInput).outcome, 'ALREADY_PROCESSED');
    assert.deepEqual(ledger.execute(secondInput).receipt, first.receipt);
    assert.deepEqual(ledger.revokedIds(), new Set(['urn:uuid:revoked-vc']));
    const returned = ledger.revokedIds(); returned.clear();
    assert.equal(ledger.revokedIds().has('urn:uuid:revoked-vc'), true);
    failWith('INVALID_CREDENTIAL_ID', () => ledger.revokeCredential(''));
    const reused = structuredClone(secondInput); reused.payment.orderId = 'different-after-reopen';
    failWith('AUTHORIZATION_CONFLICT', () => ledger.execute(reused), 409);
  } finally { ledger.close(); }
});

test('two live SQLite connections see one durable execution of the same authorization', t => {
  const dir = temporary(t); const path = join(dir, 'payment.sqlite');
  const first = createLedger({ path }); const second = createLedger({ path });
  try {
    const authorization = input();
    const executed = first.execute(authorization);
    const retry = second.execute(authorization);
    assert.equal(retry.outcome, 'ALREADY_PROCESSED');
    assert.deepEqual(retry.receipt, executed.receipt);
    assert.deepEqual(second.snapshot(), first.snapshot());
    second.revokeCredential('revoked-by-second');
    assert.ok(first.revokedIds().has('revoked-by-second'));
  } finally { second.close(); first.close(); }
});

test('a storage failure while recording authorization consumption rolls back debit, credit and receipt together', t => {
  const dir = temporary(t); const path = join(dir, 'payment.sqlite');
  const ledger = createLedger({ path });
  const database = new DatabaseSync(path);
  try {
    database.exec("CREATE TRIGGER inject_storage_failure BEFORE INSERT ON authorizations BEGIN SELECT RAISE(ABORT, 'injected test failure'); END;");
    const before = ledger.snapshot();
    const authorization = input();
    failWith('LEDGER_STORAGE_ERROR', () => ledger.execute(authorization), 500);
    assert.deepEqual(ledger.snapshot(), before);
    database.exec('DROP TRIGGER inject_storage_failure');
    assert.equal(ledger.execute(authorization).outcome, 'EXECUTED');
    assert.equal(ledger.snapshot().executionCount, 1);
  } finally { database.close(); ledger.close(); }
});

test('initial WAL setup waits for an independent process to release its reserved write lock', { timeout: 10000 }, async t => {
  const dir = temporary(t); const path = join(dir, 'payment.sqlite');
  const source = `
    import { DatabaseSync } from 'node:sqlite';
    import { setTimeout as delay } from 'node:timers/promises';
    const db = new DatabaseSync(process.env.LEDGER_TEST_PATH);
    db.exec('CREATE TABLE init_lock (id INTEGER); BEGIN IMMEDIATE; SELECT * FROM init_lock;');
    process.stdout.write('READY\\n');
    await delay(250);
    db.exec('COMMIT'); db.close();
  `;
  const child = spawn(process.execPath, ['--input-type=module', '-e', source], {
    env: { ...process.env, LEDGER_TEST_PATH: path }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '', stderr = '', readyResolve, readyReject;
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const readinessTimeout = setTimeout(() => readyReject(new Error(`Lock worker did not become ready: ${stderr}`)), 5000);
  readinessTimeout.unref();
  const exited = new Promise((resolve, reject) => {
    child.stdout.on('data', data => { stdout += data; if (stdout.includes('READY\n')) readyResolve(); });
    child.stderr.on('data', data => { stderr += data; });
    child.once('error', error => { readyReject(error); reject(error); });
    child.once('close', (code, signal) => {
      if (code !== 0 || !stdout.includes('READY\n')) {
        const error = new Error(`Lock worker exited ${code} (signal ${signal ?? 'none'}): ${stderr}`);
        readyReject(error); reject(error);
      } else resolve();
    });
  });
  exited.catch(() => {});
  try {
    await ready;
    clearTimeout(readinessTimeout);
    const ledger = createLedger({ path });
    try {
      assert.equal(ledger.execute(input()).outcome, 'EXECUTED');
      assert.equal(ledger.snapshot().executionCount, 1);
    } finally { ledger.close(); }
    await exited;
  } finally {
    clearTimeout(readinessTimeout);
    if (child.exitCode === null) child.kill('SIGKILL');
    await Promise.allSettled([exited]);
  }
});

test('two independent processes racing the same authorization produce exactly one debit', { timeout: 20000 }, async t => {
  const dir = temporary(t); const path = join(dir, 'payment.sqlite'); const gate = join(dir, 'start');
  const authorization = input();
  const moduleUrl = new URL('../lib/ledger.mjs', import.meta.url).href;
  const source = `
    import { createLedger } from ${JSON.stringify(moduleUrl)};
    import { existsSync } from 'node:fs';
    import { setTimeout as delay } from 'node:timers/promises';
    const ledger = createLedger({ path: process.env.LEDGER_TEST_PATH });
    process.stdout.write('READY\\n');
    while (!existsSync(process.env.LEDGER_TEST_GATE)) await delay(5);
    try { process.stdout.write(JSON.stringify(ledger.execute(JSON.parse(process.env.LEDGER_TEST_INPUT))) + '\\n'); }
    finally { ledger.close(); }
  `;
  const children = [];
  function worker() {
    const child = spawn(process.execPath, ['--input-type=module', '-e', source], {
      env: { ...process.env, LEDGER_TEST_PATH: path, LEDGER_TEST_GATE: gate, LEDGER_TEST_INPUT: JSON.stringify(authorization) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    children.push(child);
    let stdout = '', stderr = '';
    const result = new Promise((resolve, reject) => {
      child.stdout.on('data', data => { stdout += data; });
      child.stderr.on('data', data => { stderr += data; });
      child.once('error', reject);
      child.once('close', (code, signal) => {
        if (code !== 0) reject(new Error(`Ledger worker ${child.pid} exited ${code} (signal ${signal ?? 'none'}): ${stderr}`));
        else {
          try { resolve(JSON.parse(stdout.trim().split('\n').at(-1))); }
          catch (error) { reject(error); }
        }
      });
    });
    // Attach a handler immediately while readiness is being awaited.
    result.catch(() => {});
    return { child, result, ready: () => stdout.includes('READY\n'), diagnostic: () => `PID ${child.pid}: exit=${child.exitCode}, signal=${child.signalCode}, stdout=${stdout}, stderr=${stderr}` };
  }
  const workers = [worker(), worker()];
  try {
    for (let retry = 0; retry < 600 && !workers.every(item => item.ready()); retry++) {
      const exited = workers.find(item => item.child.exitCode !== null || item.child.signalCode !== null);
      if (exited) {
        await exited.result;
        assert.fail(`worker exited before the concurrent start: ${exited.diagnostic()}`);
      }
      await delay(10);
    }
    assert.ok(workers.every(item => item.ready()), `both processes reached the start barrier: ${workers.map(item => item.diagnostic()).join('\n')}`);
    writeFileSync(gate, 'go', { mode: 0o600 });
    const results = await Promise.all(workers.map(item => item.result));
    assert.deepEqual(results.map(item => item.outcome).sort(), ['ALREADY_PROCESSED', 'EXECUTED']);
    assert.deepEqual(results[0].receipt, results[1].receipt);
    const ledger = createLedger({ path });
    try {
      assert.equal(ledger.snapshot().executionCount, 1);
      assert.equal(balances(ledger)['demo:alice'], 87500);
      assert.equal(balances(ledger)['merchant:keyboard'], 12500);
    } finally { ledger.close(); }
  } finally {
    for (const child of children) if (child.exitCode === null) child.kill('SIGKILL');
    await Promise.allSettled(workers.map(item => item.result));
  }
});

test('ledger refuses database-file and immediate-parent symlinks', t => {
  const dir = temporary(t); const target = join(dir, 'target.sqlite');
  const ledger = createLedger({ path: target }); ledger.close();
  const link = join(dir, 'linked.sqlite'); symlinkSync(target, link);
  failWith('INVALID_LEDGER_PATH', () => createLedger({ path: link }));
  const directory = join(dir, 'actual'); mkdirSync(directory);
  const linkedDirectory = join(dir, 'linked'); symlinkSync(directory, linkedDirectory);
  failWith('INVALID_LEDGER_PATH', () => createLedger({ path: join(linkedDirectory, 'payment.sqlite') }));
});

test('close is idempotent and closed ledgers cannot execute or expose stale snapshots', () => {
  const ledger = createLedger(); ledger.close(); ledger.close();
  failWith('LEDGER_CLOSED', () => ledger.execute(input()), 503);
  failWith('LEDGER_CLOSED', () => ledger.snapshot(), 503);
  failWith('LEDGER_CLOSED', () => ledger.revokedIds(), 503);
});
