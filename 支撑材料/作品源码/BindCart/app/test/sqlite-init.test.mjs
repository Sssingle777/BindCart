import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { configureSqlite, isSqliteBusy } from '../lib/sqlite-init.mjs';

test('SQLite BUSY classification includes extended codes without treating other errors as contention', () => {
  for (const errcode of [5, 261, 517, 773]) assert.equal(isSqliteBusy({ errcode }), true);
  for (const errcode of [undefined, null, '5', 6, 10, 14, 19]) assert.equal(isSqliteBusy({ errcode }), false);
});

test('transient and extended WAL contention retry initialization only', () => {
  const statements = [];
  let attempts = 0;
  const db = { exec(sql) {
    statements.push(sql);
    if (sql.includes('journal_mode') && ++attempts <= 2) {
      throw Object.assign(new Error('database is locked'), { errcode: attempts === 1 ? 5 : 261 });
    }
  } };
  configureSqlite(db, { busyTimeoutMs: 1000 });
  assert.equal(attempts, 3);
  assert.ok(statements.every(sql => sql.startsWith('PRAGMA ')), 'must not replay any application SQL');
  assert.equal(statements.at(-2), 'PRAGMA busy_timeout = 1000;');
  assert.equal(statements.at(-1), 'PRAGMA synchronous = FULL;');
});

test('non-BUSY initialization failures propagate immediately without retry', () => {
  const failure = Object.assign(new Error('disk I/O error'), { errcode: 10 });
  let attempts = 0;
  const db = { exec(sql) {
    if (sql.includes('journal_mode')) { attempts++; throw failure; }
  } };
  assert.throws(() => configureSqlite(db), error => error === failure);
  assert.equal(attempts, 1);
});

test('persistent WAL contention expires without modifying rows and a later explicit initialization succeeds', t => {
  const dir = mkdtempSync(join(tmpdir(), 'bindcart-sqlite-init-'));
  const path = join(dir, 'locked.sqlite');
  const holder = new DatabaseSync(path), candidate = new DatabaseSync(path);
  t.after(() => { candidate.close(); holder.close(); rmSync(dir, { recursive: true, force: true }); });
  holder.exec("CREATE TABLE sentinel (value TEXT); INSERT INTO sentinel VALUES ('preserve'); BEGIN IMMEDIATE;");
  const started = performance.now();
  try {
    assert.throws(() => configureSqlite(candidate, { busyTimeoutMs: 80 }), isSqliteBusy);
    assert.ok(performance.now() - started < 3000, 'contention has a bounded retry window');
    assert.equal(candidate.prepare('PRAGMA busy_timeout').get().timeout, 80);
  } finally { holder.exec('ROLLBACK'); }
  configureSqlite(candidate);
  assert.equal(candidate.prepare('PRAGMA journal_mode').get().journal_mode, 'wal');
  assert.equal(candidate.prepare('PRAGMA synchronous').get().synchronous, 2);
  assert.equal(candidate.prepare('PRAGMA busy_timeout').get().timeout, 5000);
  assert.deepEqual(candidate.prepare('SELECT value FROM sentinel').all().map(row => row.value), ['preserve']);
});
