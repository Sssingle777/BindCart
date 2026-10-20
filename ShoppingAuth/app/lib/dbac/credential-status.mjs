import { constants, closeSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { AppError } from '../protocol.mjs';

const fail = (code, message, status = 403) => { throw new AppError(code, message, status); };
const clone = value => structuredClone(value);
const binding = value => typeof value === 'string' && /^urn:uuid:[0-9a-f-]{36}$/.test(value);

// The table stores public issuer-side metadata only. Startup never discards an
// unreadable existing table; status failures are not interpreted as "valid".
export function createCredentialStatusStore({ statePath } = {}) {
  const records = new Map(), file = statePath ? resolve(statePath) : null, parent = file ? dirname(file) : null;
  let directoryInfo;
  const unsafe = () => fail('UNSAFE_CREDENTIAL_STATUS_STORAGE', '凭证状态必须使用独立普通文件和非符号链接父目录。', 500);
  const sameFile = (left, right) => left && right && left.dev === right.dev && left.ino === right.ino;
  function entry(path) {
    try { return lstatSync(path); }
    catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  function regular(info) {
    if (!info?.isFile() || info.isSymbolicLink() || info.nlink !== 1) unsafe();
  }
  // Check the immediate parent and pin its identity between operations. This
  // does not replace OS access controls against concurrent ancestor replacement.
  function directory(create = false) {
    let info = entry(parent);
    if (!info && directoryInfo) unsafe();
    if (!info && create) { mkdirSync(parent, { recursive: true, mode: 0o700 }); info = entry(parent); }
    if (!info) return false;
    if (!info.isDirectory() || info.isSymbolicLink() || directoryInfo && !sameFile(info, directoryInfo)) unsafe();
    directoryInfo ??= info;
    return true;
  }
  function destination() {
    const info = entry(file);
    if (info) regular(info);
    return info;
  }
  if (file && directory()) {
    const info = destination();
    if (info) {
      let fd;
      try { fd = openSync(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)); }
      catch (error) { if (error.code === 'ELOOP') unsafe(); throw error; }
      let saved;
      try {
        const opened = fstatSync(fd); regular(opened);
        if (!sameFile(info, opened)) unsafe();
        saved = JSON.parse(readFileSync(fd, 'utf8'));
      } finally { closeSync(fd); }
      if (saved?.version !== 1 || !Array.isArray(saved.records)) throw new Error('Invalid credential status store');
      for (const record of saved.records) {
        if (!binding(record.bindingId) || !['valid', 'revoked'].includes(record.status)) throw new Error('Invalid credential status record');
        records.set(record.bindingId, record);
      }
    }
  }
  function persist() {
    if (!file) return;
    directory(true); destination();
    const temporary = `${file}.${randomUUID()}.tmp`;
    let created = false, temporaryInfo;
    try {
      const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
      created = true;
      try {
        temporaryInfo = fstatSync(fd); regular(temporaryInfo);
        writeFileSync(fd, JSON.stringify({ version: 1, records: [...records.values()] }, null, 2));
      } finally { closeSync(fd); }
      // Close before rename for Windows, then reject replaced path entries.
      if (!directory()) unsafe();
      destination();
      const pending = entry(temporary); regular(pending);
      if (!sameFile(pending, temporaryInfo)) unsafe();
      renameSync(temporary, file); created = false;
    } finally {
      if (created) {
        try {
          // Never delete an existing name after failed exclusive creation, or a
          // replacement file/directory that this write does not own.
          if (directory() && sameFile(entry(temporary), temporaryInfo)) unlinkSync(temporary);
        } catch { /* Keep the original write failure; do not touch untrusted paths. */ }
      }
    }
  }
  return {
    issue(record) {
      if (!binding(record.bindingId) || records.has(record.bindingId)) fail('W3C_CREDENTIAL_STATUS_INVALID', '凭证状态编号无效或已存在。');
      const entry = { ...clone(record), status: 'valid', issuedAt: new Date().toISOString(), revokedAt: null };
      records.set(record.bindingId, entry);
      try { persist(); } catch (error) { records.delete(record.bindingId); throw error; }
      return clone(entry);
    },
    revoke(bindingId) {
      const record = records.get(bindingId);
      if (!record) fail('W3C_CREDENTIAL_STATUS_UNKNOWN', '签发方没有此凭证状态记录。');
      if (record.status === 'revoked') return clone(record);
      const previous = clone(record);
      record.status = 'revoked'; record.revokedAt = new Date().toISOString();
      try { persist(); } catch (error) { records.set(bindingId, previous); throw error; }
      return clone(record);
    },
    status(bindingId) { return clone(records.get(bindingId) ?? { bindingId, status: 'unknown' }); },
    list() { return clone([...records.values()]); },
    persistence: statePath ? 'local-json-public-metadata' : 'session-memory',
  };
}

// Read authority is separate from issuance/revocation authority in production.
// The URL comes from the trusted launch configuration, never from a submitted VC.
export function createCredentialStatusReader(source) {
  if (!source || !/^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/.test(source.baseUrl) || typeof source.accessToken !== 'string') throw new Error('A trusted local credential status source is required');
  return async ({ bindingId, issuer, holderDid }, { onStatus } = {}) => {
    let result;
    try {
      const response = await fetch(`${source.baseUrl}/credential/status`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-DBAC-Access': source.accessToken },
        body: JSON.stringify({ bindingId }), signal: AbortSignal.timeout(3000), redirect: 'error' });
      if (!response.ok) throw new Error('status HTTP failure');
      result = await response.json();
    } catch { fail('W3C_CREDENTIAL_STATUS_UNAVAILABLE', '无法确认签发方当前凭证状态，本阶段停止。', 503); }
    if (result?.bindingId !== bindingId || !['valid', 'revoked', 'unknown'].includes(result.status)) fail('W3C_CREDENTIAL_STATUS_UNAVAILABLE', '签发方状态响应不完整，本阶段停止。', 503);
    if (result.status !== 'unknown' && (result.issuer !== issuer || (holderDid && result.holderDid !== holderDid))) fail('W3C_CREDENTIAL_STATUS_MISMATCH', '状态记录没有绑定已验证的签发方和持有者。');
    // Preserve the trusted query observation before rejecting revoked/unknown.
    // No callback runs for transport, malformed-response or identity failures.
    const status = { status: result.status, bindingId, source: 'trusted-local-issuer', checkedAt: new Date().toISOString() };
    onStatus?.({ ...status });
    if (result.status === 'unknown') fail('W3C_CREDENTIAL_STATUS_UNKNOWN', '签发方没有此凭证的可信状态记录。');
    if (result.status === 'revoked') fail('W3C_CREDENTIAL_REVOKED', '签发方已撤销此凭证；完整合法两方证明也不能继续使用。');
    return status;
  };
}
