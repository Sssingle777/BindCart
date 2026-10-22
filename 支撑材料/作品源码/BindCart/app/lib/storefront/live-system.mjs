import { EventEmitter } from 'node:events';
import { appendFile, mkdir, readFile, truncate } from 'node:fs/promises';
import { randomUUID, createHash } from 'node:crypto';
import { resolve } from 'node:path';

const hash = value => createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
const secretNames = /^(?:privateKey|secretKey|accessToken|adminToken|uiToken|ownerKey|proposalToken|cancelToken|token)$/i;
export const orderIdValid = value => typeof value === 'string' && /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);

// This is a public observer projection. Signed public VC/device proofs remain
// inspectable; access capabilities, Owner tokens and wallet payloads do not.
export function publicEvidence(value) {
  if (Array.isArray(value)) return value.map(publicEvidence);
  if (!value || typeof value !== 'object') return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (secretNames.test(key)) { if (item) result[`${key}Digest`] = hash(item); continue; }
    if (key === 'authorization' && typeof item === 'string') { result.authorizationDigest = hash(item); continue; }
    if (['walletPayload', 'payload'].includes(key) && item) { result[key] = { present: true, sha256: hash(item) }; continue; }
    if (['rawRequest', 'rawResponse', 'rawBody'].includes(key) && typeof item === 'string') { result[`${key}Hash`] = hash(item); continue; }
    if (key === 'headers' && item) { result.headers = Object.fromEntries(Object.entries(item).filter(([name]) => ['content-type', 'x-a2a-extensions'].includes(name.toLowerCase()))); continue; }
    result[key] = publicEvidence(item);
  }
  return result;
}

export async function createLiveSystem({ directory, limit = 1600 }) {
  await mkdir(directory, { recursive: true });
  const emitter = new EventEmitter(); emitter.setMaxListeners(40);
  const journal = resolve(directory, 'system-events.jsonl');
  let events = [], sequence = 0, pending = Promise.resolve(), journalError = null;
  try {
    let previous = await readFile(journal, 'utf8');
    if (previous && !previous.endsWith('\n')) {
      const cut = previous.lastIndexOf('\n') + 1;
      let complete = false;
      try { complete = Number.isSafeInteger(JSON.parse(previous.slice(cut)).seq); } catch { /* A crash may leave an incomplete final append. */ }
      if (complete) { await appendFile(journal, '\n'); previous += '\n'; }
      else { previous = previous.slice(0, cut); await truncate(journal, Buffer.byteLength(previous)); }
    }
    const lines = previous.trim().split('\n').slice(-limit);
    events = lines.flatMap(line => { try { const row = JSON.parse(line); return Number.isSafeInteger(row.seq) ? [row] : []; } catch { return []; } });
    sequence = events.at(-1)?.seq ?? 0;
  } catch (error) { if (error.code !== 'ENOENT') journalError = error.message; }
  const instanceId = randomUUID();
  function publish(input) {
    const event = publicEvidence({ ...input, seq: ++sequence, at: new Date().toISOString(), instanceId });
    events.push(event); if (events.length > limit) events = events.slice(-limit);
    const line = `${JSON.stringify(event)}\n`;
    pending = pending.then(async () => {
      await appendFile(journal, line, { mode: 0o600 });
      if (orderIdValid(event.orderId)) await appendFile(resolve(directory, `${event.orderId.slice(9)}.events.jsonl`), line, { mode: 0o600 });
    }).catch(error => { journalError = error.message; });
    emitter.emit('system', event);
    return event;
  }
  return {
    instanceId, publish,
    get sequence() { return sequence; },
    get journalError() { return journalError; },
    events: (after = 0) => structuredClone(events.filter(row => row.seq > after)),
    subscribe(listener) { emitter.on('system', listener); return () => emitter.off('system', listener); },
    snapshot(snapshot) { emitter.emit('snapshot', snapshot); },
    subscribeSnapshots(listener) { emitter.on('snapshot', listener); return () => emitter.off('snapshot', listener); },
    async orderEvents(orderId) {
      if (!orderIdValid(orderId)) return [];
      await pending;
      try { return (await readFile(resolve(directory, `${orderId.slice(9)}.events.jsonl`), 'utf8')).trim().split('\n').flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } }); }
      catch (error) { if (error.code === 'ENOENT') return []; throw error; }
    },
    flush: () => pending,
  };
}
