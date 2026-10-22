import { randomUUID } from 'node:crypto';
import { constants, closeSync, fchmodSync, fstatSync, lstatSync, mkdirSync, openSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { configureSqlite, isSqliteBusy } from './sqlite-init.mjs';

const CURRENCY = 'CNY';
const PAYER = 'demo:alice';
const MERCHANTS = new Set(['merchant:keyboard', 'merchant:other']);
const INITIAL_BALANCE = 100000;
const INPUT_KEYS = ['authorizationId', 'authorizationHash', 'authorizerDid', 'holderDid', 'deviceDid', 'verifierDid', 'payment'];
const PAYMENT_KEYS = ['orderId', 'payerAccount', 'payeeAccount', 'amountMinor', 'currency'];

export class LedgerError extends Error {
  constructor(code, message, status = 400, options) {
    super(message, options);
    this.name = 'LedgerError';
    this.code = code;
    this.status = status;
  }
}

function fail(code, message, status = 400) { throw new LedgerError(code, message, status); }
function exactObject(value, keys) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === keys.length && actual.every(key => typeof key === 'string' && keys.includes(key) && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
}
function identifier(value, maxLength = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxLength && value.trim() === value && !/[\u0000-\u001f\u007f]/.test(value);
}
function did(value) { return identifier(value, 2048) && /^did:[a-z0-9]+:[^\s?#]+$/.test(value); }
function hash(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value) && Buffer.from(value, 'base64url').toString('base64url') === value;
}

// The caller verifies signatures and authorization policy. This independent
// boundary validates the immutable execution input and the simulated accounts.
function normalizeInput(input) {
  if (!exactObject(input, INPUT_KEYS) || !identifier(input.authorizationId) || !hash(input.authorizationHash) ||
      !['authorizerDid', 'holderDid', 'deviceDid', 'verifierDid'].every(key => did(input[key]))) {
    fail('INVALID_AUTHORIZATION', '支付授权标识、摘要或身份字段无效。');
  }
  const payment = input.payment;
  if (!exactObject(payment, PAYMENT_KEYS) || !identifier(payment.orderId) || payment.currency !== CURRENCY ||
      payment.payerAccount !== PAYER || !MERCHANTS.has(payment.payeeAccount) ||
      !Number.isSafeInteger(payment.amountMinor) || payment.amountMinor <= 0) {
    fail('INVALID_PAYMENT', '仅支持 demo:alice 向已知模拟商户支付正安全整数分，币种必须为 CNY。');
  }
  return {
    authorizationId: input.authorizationId,
    authorizationHash: input.authorizationHash,
    authorizerDid: input.authorizerDid,
    holderDid: input.holderDid,
    deviceDid: input.deviceDid,
    verifierDid: input.verifierDid,
    payment: {
      orderId: payment.orderId,
      payerAccount: payment.payerAccount,
      payeeAccount: payment.payeeAccount,
      amountMinor: payment.amountMinor,
      currency: payment.currency,
    },
  };
}

function preparePath(path) {
  if (path === ':memory:') return path;
  if (typeof path !== 'string' || !path || path.length > 4096 || path.includes('\0') || path.startsWith('file:')) {
    fail('INVALID_LEDGER_PATH', '账本必须使用普通文件路径或 :memory:。');
  }
  const file = resolve(path);
  const parent = dirname(file);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const parentInfo = lstatSync(parent);
  if (parentInfo.isSymbolicLink() || !parentInfo.isDirectory()) fail('INVALID_LEDGER_PATH', '账本父目录不可为符号链接。');
  let fd;
  try {
    try { fd = openSync(file, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
    catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const info = lstatSync(file);
      if (info.isSymbolicLink() || !info.isFile() || info.nlink !== 1) fail('INVALID_LEDGER_PATH', '账本必须是未共享硬链接的普通文件，不可为符号链接。');
      fd = openSync(file, constants.O_RDWR | constants.O_NOFOLLOW);
    }
    const info = fstatSync(fd);
    if (!info.isFile() || info.nlink !== 1) fail('INVALID_LEDGER_PATH', '账本文件类型无效。');
    fchmodSync(fd, 0o600);
  } finally { if (fd !== undefined) closeSync(fd); }
  return file;
}

function storageError(error) {
  if (error instanceof LedgerError) return error;
  if (isSqliteBusy(error) || (error.errcode & 0xff) === 6 || /(?:database is locked|database is busy)/i.test(error.message ?? '')) {
    return new LedgerError('LEDGER_BUSY', '账本忙，请使用相同授权重试。', 503, { cause: error });
  }
  return new LedgerError('LEDGER_STORAGE_ERROR', '账本存储操作失败，未确认支付执行结果。', 500, { cause: error });
}


export function createLedger({ path = ':memory:' } = {}) {
  let db;
  let closed = false;
  function transaction(begin, action) {
    if (closed) fail('LEDGER_CLOSED', '账本已经关闭。', 503);
    let begun = false;
    try {
      db.exec(begin);
      begun = true;
      const result = action();
      db.exec('COMMIT');
      return result;
    } catch (error) {
      if (begun) { try { db.exec('ROLLBACK'); } catch { /* Preserve the originating error. */ } }
      throw storageError(error);
    }
  }
  try {
    db = new DatabaseSync(preparePath(path));
    db.exec('PRAGMA foreign_keys = ON;');
    configureSqlite(db);
    transaction('BEGIN IMMEDIATE', () => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS accounts (
          id TEXT PRIMARY KEY,
          balance_minor INTEGER NOT NULL CHECK (typeof(balance_minor) = 'integer' AND balance_minor >= 0 AND balance_minor <= 9007199254740991)
        );
        CREATE TABLE IF NOT EXISTS executions (
          receipt_id TEXT PRIMARY KEY,
          payer_account TEXT NOT NULL REFERENCES accounts(id),
          order_id TEXT NOT NULL,
          payment_terms TEXT NOT NULL,
          receipt_json TEXT NOT NULL,
          UNIQUE (payer_account, order_id)
        );
        CREATE TABLE IF NOT EXISTS authorizations (
          authorization_id TEXT PRIMARY KEY,
          authorization_hash TEXT NOT NULL,
          immutable_input TEXT NOT NULL,
          receipt_id TEXT NOT NULL REFERENCES executions(receipt_id)
        );
        CREATE TABLE IF NOT EXISTS revoked_credentials (
          credential_id TEXT PRIMARY KEY,
          revoked_at TEXT NOT NULL
        );
      `);
      const seed = db.prepare('INSERT OR IGNORE INTO accounts (id, balance_minor) VALUES (?, ?)');
      seed.run(PAYER, INITIAL_BALANCE);
      for (const account of MERCHANTS) seed.run(account, 0);
    });
  } catch (error) {
    if (db) { try { db.close(); } catch { /* Preserve the initialization error. */ } }
    throw storageError(error);
  }

  const findAuthorization = db.prepare(`SELECT a.authorization_hash, a.immutable_input, e.receipt_json
    FROM authorizations a JOIN executions e ON e.receipt_id = a.receipt_id WHERE a.authorization_id = ?`);
  const findOrder = db.prepare('SELECT receipt_id, payment_terms, receipt_json FROM executions WHERE payer_account = ? AND order_id = ?');
  const saveAuthorization = db.prepare('INSERT INTO authorizations (authorization_id, authorization_hash, immutable_input, receipt_id) VALUES (?, ?, ?, ?)');
  const findBalance = db.prepare('SELECT balance_minor FROM accounts WHERE id = ?');
  const updateBalance = db.prepare('UPDATE accounts SET balance_minor = ? WHERE id = ?');
  const saveExecution = db.prepare('INSERT INTO executions (receipt_id, payer_account, order_id, payment_terms, receipt_json) VALUES (?, ?, ?, ?, ?)');

  return {
    execute(input) {
      const normalized = normalizeInput(input);
      const immutable = JSON.stringify(normalized);
      const payment = normalized.payment;
      const terms = JSON.stringify(payment);
      return transaction('BEGIN IMMEDIATE', () => {
        const authorization = findAuthorization.get(normalized.authorizationId);
        if (authorization) {
          if (authorization.authorization_hash !== normalized.authorizationHash || authorization.immutable_input !== immutable) {
            fail('AUTHORIZATION_CONFLICT', '该授权标识已绑定不同的不可变支付输入。', 409);
          }
          return { outcome: 'ALREADY_PROCESSED', receipt: JSON.parse(authorization.receipt_json) };
        }
        const previous = findOrder.get(payment.payerAccount, payment.orderId);
        if (previous) {
          if (previous.payment_terms !== terms) fail('PAYMENT_ORDER_CONFLICT', '该付款账户的订单已按不同支付条款执行。', 409);
          // Remember this fresh authorization even when the order already has
          // a receipt, so it cannot later be reused to execute another order.
          saveAuthorization.run(normalized.authorizationId, normalized.authorizationHash, immutable, previous.receipt_id);
          return { outcome: 'ALREADY_PROCESSED', receipt: JSON.parse(previous.receipt_json) };
        }
        const payer = findBalance.get(payment.payerAccount);
        const payee = findBalance.get(payment.payeeAccount);
        if (!payer || !payee) fail('INVALID_PAYMENT', '模拟支付账户不存在。');
        if (payer.balance_minor < payment.amountMinor) fail('INSUFFICIENT_FUNDS', '模拟付款账户余额不足。', 409);
        const payerBalanceMinor = payer.balance_minor - payment.amountMinor;
        const payeeBalanceMinor = payee.balance_minor + payment.amountMinor;
        if (!Number.isSafeInteger(payerBalanceMinor) || !Number.isSafeInteger(payeeBalanceMinor)) fail('INVALID_PAYMENT', '支付后余额超出安全整数范围。');
        const receipt = {
          receiptId: `urn:uuid:${randomUUID()}`,
          authorizationId: normalized.authorizationId,
          ...payment,
          executedAt: new Date().toISOString(),
          payerBalanceMinor,
          payeeBalanceMinor,
          authorizerDid: normalized.authorizerDid,
          holderDid: normalized.holderDid,
          deviceDid: normalized.deviceDid,
          verifierDid: normalized.verifierDid,
        };
        updateBalance.run(payerBalanceMinor, payment.payerAccount);
        updateBalance.run(payeeBalanceMinor, payment.payeeAccount);
        saveExecution.run(receipt.receiptId, payment.payerAccount, payment.orderId, terms, JSON.stringify(receipt));
        saveAuthorization.run(normalized.authorizationId, normalized.authorizationHash, immutable, receipt.receiptId);
        return { outcome: 'EXECUTED', receipt };
      });
    },
    snapshot() {
      return transaction('BEGIN', () => ({
        currency: CURRENCY,
        accounts: db.prepare('SELECT id, balance_minor AS balanceMinor FROM accounts ORDER BY id').all().map(row => ({ ...row })),
        executionCount: db.prepare('SELECT COUNT(*) AS count FROM executions').get().count,
        receipts: db.prepare('SELECT receipt_json FROM executions ORDER BY rowid DESC LIMIT 100').all().map(row => JSON.parse(row.receipt_json)),
      }));
    },
    revokeCredential(id) {
      if (!identifier(id, 2048)) fail('INVALID_CREDENTIAL_ID', '撤销需要非空、长度受限的凭证标识。');
      return transaction('BEGIN IMMEDIATE', () => {
        db.prepare('INSERT OR IGNORE INTO revoked_credentials (credential_id, revoked_at) VALUES (?, ?)').run(id, new Date().toISOString());
        return { revoked: true, id };
      });
    },
    revokedIds() {
      return transaction('BEGIN', () => new Set(db.prepare('SELECT credential_id FROM revoked_credentials ORDER BY credential_id').all().map(row => row.credential_id)));
    },
    close() {
      if (closed) return;
      try { db.close(); closed = true; }
      catch (error) { throw storageError(error); }
    },
  };
}
