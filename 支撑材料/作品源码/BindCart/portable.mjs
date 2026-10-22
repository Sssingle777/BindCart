#!/usr/bin/env node
// Portable entry only. Protocol progress is controlled by explicit console actions.
import { spawn } from 'node:child_process';
import { preflight } from './verify-package.mjs';
import { mkdir, readFile, writeFile, open, rm, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const packageDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(packageDirectory, 'app');
const varDirectory = resolve(appDirectory, 'var');
const stateDirectory = resolve(varDirectory, 'dual-live');
const runtimePath = resolve(varDirectory, 'dual-runtime.json');
const supervisorPath = resolve(varDirectory, 'portable-supervisor.json');
const lockDirectory = resolve(varDirectory, 'portable-start.lock');
const lockOwnerPath = resolve(lockDirectory, 'owner.json');
const stdoutPath = resolve(varDirectory, 'dual-start.log');
const stderrPath = resolve(varDirectory, 'dual-error.log');
const serviceName = 'shopping-live-system';
const normalizePath = path => process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path);
const samePath = (left, right) => typeof left === 'string' && normalizePath(left) === normalizePath(right);
const validPid = pid => Number.isInteger(pid) && pid > 0;

async function readJson(path) {
  try { return JSON.parse(await readFile(path, 'utf8')); } catch { return null; }
}

function isAlive(pid) {
  if (!validPid(pid)) return false;
  try { process.kill(pid, 0); return true; } catch (error) { return error.code === 'EPERM'; }
}

async function healthyRuntime() {
  const runtime = await readJson(runtimePath);
  // A copied metadata file must never let this package control a different copy.
  if (!runtime || !samePath(runtime.stateDirectory, stateDirectory) || !validPid(runtime.pid)) return null;
  if (!/^http:\/\/127\.0\.0\.1:[0-9]+$/.test(runtime.baseUrl ?? '')) return null;
  const port = Number(new URL(runtime.baseUrl).port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  let url;
  try { url = new URL(runtime.url); } catch { return null; }
  if (url.origin !== runtime.baseUrl || url.pathname !== '/demo/' || !new URLSearchParams(url.hash.slice(1)).get('key')) return null;
  try {
    const response = await fetch(`${runtime.baseUrl}/api/health`, { signal: AbortSignal.timeout(1600), redirect: 'error' });
    const health = await response.json();
    if (!response.ok || health.service !== serviceName || !isAlive(runtime.pid)) return null;
    if (!Array.isArray(runtime.children) || !runtime.children.includes(health.pid)) return null;
    return runtime;
  } catch { return null; }
}

async function acquireLock() {
  await mkdir(varDirectory, { recursive: true });
  for (let attempt = 0; attempt < 240; attempt++) {
    try {
      await mkdir(lockDirectory);
      await writeFile(lockOwnerPath, JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() }), { mode: 0o600 });
      return;
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const owner = await readJson(lockOwnerPath);
      let age = 0;
      try { age = Date.now() - (await stat(lockDirectory)).mtimeMs; } catch { continue; }
      // Allow the first process time to write owner.json after the atomic mkdir.
      if ((owner && !isAlive(owner.pid)) || (!owner && age > 15000)) {
        await rm(lockDirectory, { recursive: true, force: true });
        continue;
      }
      await delay(500);
    }
  }
  throw new Error('Another start or stop is still running. Wait for it to finish, then try again.');
}

async function releaseLock() {
  const owner = await readJson(lockOwnerPath);
  if (owner?.pid === process.pid) await rm(lockDirectory, { recursive: true, force: true });
}

async function openBrowser(url) {
  const executable = process.platform === 'win32' ? 'explorer.exe' : process.platform === 'darwin' ? 'open' : null;
  if (!executable) throw new Error('This bundle supports Windows and macOS.');
  // Use an argument array; the URL fragment contains a private UI key and is never printed.
  await new Promise((done, reject) => {
    const browser = spawn(executable, [url], { detached: true, stdio: 'ignore', windowsHide: true });
    browser.once('error', reject);
    browser.once('spawn', () => { browser.unref(); done(); });
  });
}

async function supervise() {
  // This detached Node process owns only the launcher started for this package.
  await mkdir(varDirectory, { recursive: true });
  const stdout = await open(stdoutPath, 'a');
  const stderr = await open(stderrPath, 'a');
  let child;
  try {
    await stdout.write(`\n--- Portable start ${new Date().toISOString()} ---\n`);
    child = spawn(process.execPath, [resolve(appDirectory, 'launch-dual.mjs')], {
      cwd: appDirectory,
      env: { ...process.env, DUAL_PORT: '0', DUAL_STAGE_DELAY_MS: '0', DUAL_STATE_DIR: stateDirectory, DUAL_RUNTIME_PATH: runtimePath, UWS_USE_FALLBACK: '1' },
      stdio: ['ignore', stdout.fd, stderr.fd],
      windowsHide: true,
    });
    const exited = new Promise((done, reject) => {
      child.once('error', reject);
      child.once('exit', (code, signal) => done({ code, signal }));
    });
    await writeFile(supervisorPath, JSON.stringify({ supervisorPid: process.pid, launcherPid: child.pid, stateDirectory, startedAt: new Date().toISOString() }, null, 2), { mode: 0o600 });
    const result = await exited;
    if (result.code && result.code !== 0) await stderr.write(`Application exited with code ${result.code}.\n`);
    process.exitCode = result.code ?? 1;
  } catch (error) {
    await stderr.write(`Portable supervisor: ${error.stack ?? error}\n`);
    process.exitCode = 1;
  } finally {
    const metadata = await readJson(supervisorPath);
    if (metadata?.supervisorPid === process.pid) await rm(supervisorPath, { force: true });
    await stdout.close();
    await stderr.close();
  }
}

async function start(noBrowser) {
  process.env.UWS_USE_FALLBACK ??= '1';
  await preflight();
  await acquireLock();
  let runtime;
  try {
    runtime = await healthyRuntime();
    if (!runtime) {
      const previous = await readJson(supervisorPath);
      if (previous && samePath(previous.stateDirectory, stateDirectory) && isAlive(previous.supervisorPid)) {
        throw new Error('This copy is already starting or is still closing. Please wait a moment and try again.');
      }
      console.log('Starting shopping and authorization demo...');
      const supervisor = spawn(process.execPath, [fileURLToPath(import.meta.url), 'supervise'], {
        cwd: packageDirectory, detached: true, stdio: 'ignore', windowsHide: true,
      });
      await new Promise((done, reject) => { supervisor.once('spawn', done); supervisor.once('error', reject); });
      const supervisorPid = supervisor.pid;
      supervisor.unref();
      for (let attempt = 0; attempt < 180; attempt++) {
        const metadata = await readJson(supervisorPath);
        const candidate = await healthyRuntime();
        if (metadata?.supervisorPid === supervisorPid && candidate?.pid === metadata.launcherPid) { runtime = candidate; break; }
        if (!isAlive(supervisorPid)) throw new Error('The application did not start.');
        await delay(500);
      }
      if (!runtime) throw new Error('Startup timed out. The startup may still be running; check the logs before trying again.');
    }
    console.log(`Ready: ${runtime.baseUrl}/intro/`);
    console.log('Keep this copy of the folder in place while the demo is running.');
    if (!noBrowser) {
      try {
        // Keep runtime.url and health/stop semantics unchanged; only choose a new first view.
        const introduction = new URL(runtime.url);
        introduction.pathname = '/intro/';
        await openBrowser(introduction.href);
      }
      catch { throw new Error('The demo is running, but the browser could not open. Run Start again to reopen it.'); }
    }
  } finally { await releaseLock(); }
}

async function stop() {
  await acquireLock();
  try {
    const runtime = await healthyRuntime();
    if (!runtime) {
      const supervisor = await readJson(supervisorPath);
      if (supervisor && samePath(supervisor.stateDirectory, stateDirectory) && isAlive(supervisor.supervisorPid)) {
        throw new Error('This copy is still starting or closing. Wait a moment, then run Stop again.');
      }
      console.log('No running demo was found for this copy.');
      return;
    }
    const uiKey = new URLSearchParams(new URL(runtime.url).hash.slice(1)).get('key');
    const response = await fetch(`${runtime.baseUrl}/api/shutdown`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Demo-UI-Key': uiKey },
      body: '{}', signal: AbortSignal.timeout(5000), redirect: 'error',
    });
    if (!response.ok) throw new Error('The demo refused the shutdown request.');
    for (let attempt = 0; attempt < 80; attempt++) {
      if (!isAlive(runtime.pid)) { console.log('This copy of the demo has stopped.'); return; }
      await delay(250);
    }
    throw new Error('Shutdown is taking longer than expected. No processes were forcefully terminated.');
  } finally { await releaseLock(); }
}

const [command = 'start', ...options] = process.argv.slice(2);
try {
  if (command === 'supervise' && options.length === 0) await supervise();
  else if (command === 'start' && options.every(option => option === '--no-browser')) await start(options.includes('--no-browser'));
  else if (command === 'stop' && options.length === 0) await stop();
  else throw new Error('Usage: portable.mjs start [--no-browser] | stop');
} catch (error) {
  console.error(`\n${error.message}`);
  console.error(`Startup log: ${stdoutPath}`);
  console.error(`Error log: ${stderrPath}`);
  process.exitCode = 1;
}
