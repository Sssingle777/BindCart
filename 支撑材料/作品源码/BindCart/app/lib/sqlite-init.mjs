export const SQLITE_BUSY_TIMEOUT_MS = 5000;

export function isSqliteBusy(error) {
  // Extended codes such as SQLITE_BUSY_RECOVERY and SQLITE_BUSY_SNAPSHOT
  // retain the primary result code in the low byte.
  return Number.isInteger(error?.errcode) && (error.errcode & 0xff) === 5;
}

export function configureSqlite(db, { busyTimeoutMs = SQLITE_BUSY_TIMEOUT_MS } = {}) {
  if (!Number.isSafeInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > 60_000) {
    throw new RangeError('SQLite busy timeout must be an integer from 0 to 60000 ms');
  }
  // A journal-mode lock upgrade may return BUSY immediately, bypassing
  // SQLite's busy handler. Bound the entire WAL setup retry window instead
  // of giving every attempt a new native busy timeout.
  db.exec('PRAGMA busy_timeout = 0;');
  const deadline = performance.now() + busyTimeoutMs;
  const sleeper = new Int32Array(new SharedArrayBuffer(4));
  try {
    for (;;) {
      try { db.exec('PRAGMA journal_mode = WAL;'); break; }
      catch (error) {
        const remaining = deadline - performance.now();
        if (!isSqliteBusy(error) || remaining <= 0) throw error;
        Atomics.wait(sleeper, 0, 0, Math.min(10, remaining));
      }
    }
  } finally {
    db.exec(`PRAGMA busy_timeout = ${busyTimeoutMs};`);
  }
  db.exec('PRAGMA synchronous = FULL;');
  // Only WAL initialization is retried here. Callers must never wrap a
  // payment, debit, broadcast or uncertain commit in this retry loop.
}
