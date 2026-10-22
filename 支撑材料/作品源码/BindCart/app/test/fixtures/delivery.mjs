import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

export async function deliveryFixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'BindCart 中文 delivery '));
  const runtimePath = join(directory, 'runtime.json');
  const child = fork(new URL('../../launch-dual.mjs', import.meta.url), [], {
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
    env: { ...process.env, DUAL_PORT: '0', DUAL_STAGE_DELAY_MS: '0', DUAL_STATE_DIR: join(directory, 'state'), DUAL_RUNTIME_PATH: runtimePath, UWS_USE_FALLBACK: '1' },
  });
  let stopped = false, denied = false, diagnostics = '';
  const exited = new Promise(resolve => {
    child.once('exit', () => { stopped = true; resolve(); });
    child.once('error', () => { stopped = true; resolve(); });
  });
  child.stderr.on('data', bytes => {
    if (/EPERM|EACCES/.test(String(bytes))) denied = true;
    diagnostics = (diagnostics + String(bytes).replace(/[A-Za-z0-9_-]{43,}/g, '[redacted]')).slice(-3000);
  });
  let runtime;
  t.after(async () => {
    if (!stopped && child.connected) child.send({ action: 'shutdown' });
    const done = await Promise.race([exited.then(() => true), delay(10000, false, { ref: false })]);
    if (!done) { child.kill('SIGTERM'); await Promise.race([exited, delay(5000, null, { ref: false })]); }
    assert(stopped, 'isolated launcher must stop');
    for (const pid of runtime?.children ?? []) {
      let alive = true;
      try { process.kill(pid, 0); } catch { alive = false; }
      assert.equal(alive, false, 'isolated child process must stop');
    }
    await rm(directory, { recursive: true, force: true });
  });
  for (let i = 0; i < 600; i++) {
    assert(!stopped, denied ? 'Loopback permission denied by environment' : 'Delivery launcher stopped before readiness');
    try { runtime = JSON.parse(await readFile(runtimePath, 'utf8')); break; } catch {}
    await delay(100);
  }
  assert(runtime, denied ? 'Loopback permission denied by environment' : `delivery launcher readiness: ${diagnostics}`);
  assert.equal(runtime.pid, child.pid);
  const caps = new URLSearchParams(new URL(runtime.url).hash.slice(1));
  async function api(path, body, { owner = false, expected = 200 } = {}) {
    const response = await fetch(runtime.baseUrl + path, {
      method: body === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(90000),
      headers: { 'X-Demo-UI-Key': caps.get('key'), ...(owner ? { 'X-Owner-UI-Key': caps.get('ownerKey') } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const value = await response.json();
    assert.equal(response.status, expected, `${path}: ${value.error?.code ?? 'HTTP status'}`);
    return value;
  }
  return { api, runtime, directory, live: () => api('/api/live/state') };
}
