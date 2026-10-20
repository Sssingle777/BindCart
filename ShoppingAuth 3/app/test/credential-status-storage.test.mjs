import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createCredentialStatusStore } from '../lib/dbac/credential-status.mjs';

const record = () => ({ bindingId: `urn:uuid:${randomUUID()}`, issuer: 'did:example:issuer', holderDid: 'did:example:holder' });
const encoded = records => JSON.stringify({ version: 1, records });
const unsafe = error => error.code === 'UNSAFE_CREDENTIAL_STATUS_STORAGE' && error.status === 500;

function fixture(t) {
  const directory = fs.mkdtempSync(join(tmpdir(), 'credential-status-storage-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return { directory, statePath: join(directory, 'state', 'credential-status.json') };
}

function symlink(t, target, path, type = 'file') {
  try { fs.symlinkSync(target, path, type); return true; }
  catch (error) {
    if (process.platform === 'win32' && ['EPERM', 'EACCES', 'ENOSYS'].includes(error.code)) {
      t.skip('This Windows account cannot create symbolic links');
      return false;
    }
    throw error;
  }
}

function seed(path, records = []) {
  fs.mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const bytes = encoded(records);
  fs.writeFileSync(path, bytes, { mode: 0o600 });
  return bytes;
}

function withFsOverride(name, replacement, run) {
  const original = fs[name];
  fs[name] = replacement(original);
  syncBuiltinESMExports();
  try { return run(); }
  finally { fs[name] = original; syncBuiltinESMExports(); }
}

test('session-memory status preserves cloning, issue and revoke semantics', () => {
  const store = createCredentialStatusStore(), input = record();
  assert.equal(store.persistence, 'session-memory');
  const issued = store.issue(input);
  issued.status = 'revoked'; input.issuer = 'changed';
  assert.equal(store.status(input.bindingId).status, 'valid');
  assert.equal(store.status(input.bindingId).issuer, 'did:example:issuer');
  assert.equal(store.revoke(input.bindingId).status, 'revoked');
  assert.equal(store.status(record().bindingId).status, 'unknown');
});

test('nested persistent store survives restart and saves private file/directory modes', t => {
  const { directory } = fixture(t), statePath = join(directory, 'new', 'nested', 'status.json'), input = record();
  const store = createCredentialStatusStore({ statePath });
  assert.equal(store.persistence, 'local-json-public-metadata');
  const issued = store.issue(input);
  assert.deepEqual(createCredentialStatusStore({ statePath }).status(input.bindingId), issued);
  const revoked = store.revoke(input.bindingId);
  assert.deepEqual(createCredentialStatusStore({ statePath }).status(input.bindingId), revoked);
  assert.deepEqual(fs.readdirSync(dirname(statePath)), ['status.json']);
  if (process.platform !== 'win32') {
    assert.equal(fs.statSync(statePath).mode & 0o777, 0o600);
    assert.equal(fs.statSync(dirname(statePath)).mode & 0o777, 0o700);
    assert.equal(fs.statSync(join(directory, 'new')).mode & 0o777, 0o700);
  }
});

for (const kind of ['symlink', 'dangling symlink', 'hardlink', 'directory']) {
  test(`startup rejects a ${kind} status path without changing its target`, t => {
    const { directory, statePath } = fixture(t), outside = join(directory, 'outside.json');
    fs.mkdirSync(dirname(statePath));
    const bytes = kind === 'dangling symlink' ? null : seed(outside);
    if (kind.includes('symlink') && !symlink(t, outside, statePath)) return;
    if (kind === 'hardlink') fs.linkSync(outside, statePath);
    if (kind === 'directory') fs.mkdirSync(statePath);
    assert.throws(() => createCredentialStatusStore({ statePath }), unsafe);
    if (bytes === null) assert.equal(fs.existsSync(outside), false);
    else assert.equal(fs.readFileSync(outside, 'utf8'), bytes);
  });
}

test('startup rejects an immediate parent directory symlink', t => {
  const { directory, statePath } = fixture(t), outside = join(directory, 'outside');
  fs.mkdirSync(outside);
  const outsidePath = join(outside, 'credential-status.json'), bytes = seed(outsidePath);
  if (!symlink(t, outside, dirname(statePath), 'dir')) return;
  assert.throws(() => createCredentialStatusStore({ statePath }), unsafe);
  assert.equal(fs.readFileSync(outsidePath, 'utf8'), bytes);
  assert.deepEqual(fs.readdirSync(outside), ['credential-status.json']);
});

test('startup preserves malformed existing JSON instead of replacing it', t => {
  const { statePath } = fixture(t);
  seed(statePath);
  const bytes = '{ corrupt status table';
  fs.writeFileSync(statePath, bytes);
  assert.throws(() => createCredentialStatusStore({ statePath }));
  assert.equal(fs.readFileSync(statePath, 'utf8'), bytes);
});

for (const replacement of ['symlink', 'hardlink']) {
  test(`startup rejects a ${replacement} swapped in immediately before opening the table`, t => {
    const { directory, statePath } = fixture(t), outside = join(directory, 'outside.json');
    seed(statePath);
    const bytes = seed(outside);
    if (replacement === 'symlink') {
      const probe = join(directory, 'symlink-probe');
      if (!symlink(t, outside, probe)) return;
      fs.unlinkSync(probe);
    }
    let swapped = false;
    withFsOverride('openSync', original => (path, ...args) => {
      if (path === statePath && !swapped) {
        swapped = true;
        fs.unlinkSync(statePath);
        if (replacement === 'symlink') fs.symlinkSync(outside, statePath);
        else fs.linkSync(outside, statePath);
      }
      return original(path, ...args);
    }, () => assert.throws(() => createCredentialStatusStore({ statePath }), unsafe));
    assert.equal(swapped, true, 'the race must reach the actual file-open boundary');
    assert.equal(fs.readFileSync(outside, 'utf8'), bytes);
  });
}

for (const operation of ['issue', 'revoke']) {
  for (const replacement of ['symlink', 'hardlink', 'directory']) {
    test(`${operation} rejects a status path replaced with a ${replacement} and rolls back memory`, t => {
      const { directory, statePath } = fixture(t), store = createCredentialStatusStore({ statePath });
      const original = record(), pending = record();
      store.issue(original);
      const before = store.list(), outside = join(directory, 'outside.json'), bytes = seed(outside);
      fs.unlinkSync(statePath);
      if (replacement === 'symlink' && !symlink(t, outside, statePath)) return;
      if (replacement === 'hardlink') fs.linkSync(outside, statePath);
      if (replacement === 'directory') fs.mkdirSync(statePath);
      assert.throws(() => operation === 'issue' ? store.issue(pending) : store.revoke(original.bindingId), unsafe);
      assert.deepEqual(store.list(), before);
      assert.equal(store.status(pending.bindingId).status, 'unknown');
      assert.equal(fs.readFileSync(outside, 'utf8'), bytes);
      assert.deepEqual(fs.readdirSync(dirname(statePath)), ['credential-status.json']);
    });
  }
}

test('exclusive temporary-file collision preserves the other file and rolls back issuance', t => {
  const { statePath } = fixture(t), store = createCredentialStatusStore({ statePath });
  store.issue(record());
  const before = store.list(), bytes = fs.readFileSync(statePath, 'utf8'), pending = record();
  const sentinel = 'file owned by another writer';
  let collision;
  withFsOverride('openSync', original => (path, ...args) => {
    if (typeof path === 'string' && path.startsWith(`${statePath}.`) && path.endsWith('.tmp') && !collision) {
      collision = path;
      const fd = original(path, 'wx', 0o600);
      try { fs.writeFileSync(fd, sentinel); }
      finally { fs.closeSync(fd); }
    }
    return original(path, ...args);
  }, () => assert.throws(() => store.issue(pending), error => error.code === 'EEXIST'));
  assert.ok(collision, 'the collision must occur on the pending snapshot file');
  assert.deepEqual(store.list(), before);
  assert.equal(fs.readFileSync(statePath, 'utf8'), bytes);
  assert.equal(fs.readFileSync(collision, 'utf8'), sentinel);
  assert.equal(store.issue(pending).status, 'valid');
});

for (const operation of ['issue', 'revoke']) {
  for (const replacement of ['symlink', 'new directory']) {
    test(`${operation} rejects a replaced parent ${replacement} and preserves both directories`, t => {
      const { directory, statePath } = fixture(t), store = createCredentialStatusStore({ statePath });
      const original = record(), pending = record();
      store.issue(original);
      const before = store.list(), savedBytes = fs.readFileSync(statePath, 'utf8');
      const parent = dirname(statePath), moved = join(directory, 'saved-state'), outside = join(directory, 'outside');
      fs.renameSync(parent, moved);
      if (replacement === 'symlink') {
        fs.mkdirSync(outside);
        if (!symlink(t, outside, parent, 'dir')) return;
      } else fs.mkdirSync(parent);
      const bytes = seed(statePath);
      assert.throws(() => operation === 'issue' ? store.issue(pending) : store.revoke(original.bindingId), unsafe);
      assert.deepEqual(store.list(), before);
      assert.equal(fs.readFileSync(statePath, 'utf8'), bytes);
      assert.equal(fs.readFileSync(join(moved, 'credential-status.json'), 'utf8'), savedBytes);
      assert.deepEqual(fs.readdirSync(parent), ['credential-status.json']);
      assert.deepEqual(fs.readdirSync(moved), ['credential-status.json']);
    });
  }
}

for (const operation of ['issue', 'revoke']) {
  for (const failure of ['writeFileSync', 'renameSync']) {
    test(`${operation} rolls back on ${failure} failure, cleans its temporary file and can retry`, t => {
      const { statePath } = fixture(t), store = createCredentialStatusStore({ statePath });
      const original = record(), pending = record();
      store.issue(original);
      const before = store.list(), bytes = fs.readFileSync(statePath, 'utf8');
      const injected = Object.assign(new Error(`injected ${failure} failure`), { code: 'EIO' });
      withFsOverride(failure, original => (...args) => {
        if (failure === 'writeFileSync') original(args[0], '{ partially written snapshot');
        throw injected;
      }, () => {
        assert.throws(() => operation === 'issue' ? store.issue(pending) : store.revoke(original.bindingId), error => error === injected);
      });
      assert.deepEqual(store.list(), before);
      assert.equal(fs.readFileSync(statePath, 'utf8'), bytes);
      assert.deepEqual(fs.readdirSync(dirname(statePath)), ['credential-status.json']);
      const result = operation === 'issue' ? store.issue(pending) : store.revoke(original.bindingId);
      assert.equal(result.status, operation === 'issue' ? 'valid' : 'revoked');
      assert.deepEqual(createCredentialStatusStore({ statePath }).list(), store.list());
      assert.deepEqual(fs.readdirSync(dirname(statePath)), ['credential-status.json']);
    });
  }
}

test('a temporary snapshot gaining a hardlink is rejected and only the owned name is cleaned', t => {
  const { directory, statePath } = fixture(t), store = createCredentialStatusStore({ statePath });
  store.issue(record());
  const before = store.list(), bytes = fs.readFileSync(statePath, 'utf8'), pending = record();
  const alias = join(directory, 'snapshot-alias.json');
  let linked = false;
  withFsOverride('writeFileSync', original => (...args) => {
    const result = original(...args);
    const snapshots = fs.readdirSync(dirname(statePath)).filter(name => name.endsWith('.tmp'));
    assert.equal(snapshots.length, 1);
    fs.linkSync(join(dirname(statePath), snapshots[0]), alias);
    linked = true;
    return result;
  }, () => assert.throws(() => store.issue(pending), unsafe));
  assert.equal(linked, true, 'the extra hardlink must be created before committing the snapshot');
  assert.deepEqual(store.list(), before);
  assert.equal(fs.readFileSync(statePath, 'utf8'), bytes);
  assert.deepEqual(fs.readdirSync(dirname(statePath)), ['credential-status.json']);
  assert.equal(fs.lstatSync(alias).isFile(), true, 'the other name must not be deleted during cleanup');
  assert.equal(JSON.parse(fs.readFileSync(alias, 'utf8')).records.some(entry => entry.bindingId === pending.bindingId), true);
  assert.equal(store.issue(pending).status, 'valid', 'the failed issue can be retried after the race stops');
});
