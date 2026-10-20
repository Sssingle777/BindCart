import { spawn } from 'node:child_process';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile, mkdir, rename, rm } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const vendor = path.join(root, 'vendor', 'jcardsim');
const sources = ['DeviceSignerApplet.java', 'SimulatorBridge.java', 'SecureRandomNullProvider.java'].map(name => path.join(root, 'javacard', 'src', name));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const APPLET_AID = 'F00000000144494401';
export const JCARD_DISTRIBUTION = 'com.klinec:jcardsim:3.0.6.0';
function failure(code, message) { return Object.assign(new Error(message), { code, status: 503 }); }
function javaEnvironment() {
  const result = { ...process.env };
  // Do not let inherited JVM instrumentation inject an agent into the signer.
  delete result.JAVA_TOOL_OPTIONS; delete result._JAVA_OPTIONS; delete result.JDK_JAVA_OPTIONS;
  return result;
}
function javaHome() {
  if (process.env.JCARD_JAVA_HOME) return process.env.JCARD_JAVA_HOME;
  const bundled = path.join(root, '.runtime', 'jdk', 'Contents', 'Home');
  if (existsSync(path.join(bundled, 'bin', 'java'))) return bundled;
  const portable = path.join(root, '.runtime', 'jdk');
  if (existsSync(path.join(portable, 'bin', 'java'))) return portable;
  throw failure('JCARD_JAVA_REQUIRED', '缺少局部 JDK；运行 node scripts/setup-jcardsim.mjs 或设置 JCARD_JAVA_HOME。不会回退到 Node 私钥。');
}
function run(binary, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args, { env: javaEnvironment(), stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(failure('JCARD_BUILD_TIMEOUT', 'Java applet 编译超时。')); }, 30000);
    child.stderr.on('data', value => { stderr = (stderr + value).slice(-6000); });
    child.once('error', () => { clearTimeout(timer); reject(failure('JCARD_BUILD_FAILED', '无法启动指定的局部 JDK 编译器。')); });
    child.once('exit', code => {
      clearTimeout(timer);
      if (code === 0) resolve(); else reject(failure('JCARD_BUILD_FAILED', `Java applet 编译失败：${stderr.trim()}`));
    });
  });
}
let buildPromise;
export function buildJCardSim() {
  if (buildPromise) return buildPromise;
  buildPromise = (async () => {
    const home = javaHome();
    const manifestBytes = await readFile(path.join(vendor, 'manifest.json'));
    const manifest = JSON.parse(manifestBytes);
    for (const artifact of manifest.artifacts) {
      if (path.basename(artifact.file) !== artifact.file) throw failure('JCARD_INTEGRITY_FAILED', '依赖清单包含非法文件名。');
      const bytes = await readFile(path.join(vendor, artifact.file));
      if (hash(bytes) !== artifact.sha256) throw failure('JCARD_INTEGRITY_FAILED', `依赖 ${artifact.file} 的 SHA-256 不匹配。`);
    }
    const sourceBytes = await Promise.all(sources.map(file => readFile(file)));
    const buildHash = hash(Buffer.concat([manifestBytes, ...sourceBytes])).slice(0, 24);
    const classes = path.join(root, '.runtime', `jcardsim-classes-${buildHash}`);
    if (!existsSync(path.join(classes, 'demo', 'jcard', 'SimulatorBridge.class'))) {
      const temporary = `${classes}-${process.pid}-${Date.now()}`;
      await mkdir(temporary, { recursive: true });
      try {
        await run(path.join(home, 'bin', 'javac'), ['--release', '11', '-encoding', 'UTF-8', '-cp', path.join(vendor, '*'), '-d', temporary, ...sources]);
        try { await rename(temporary, classes); }
        catch (error) { if (!['EEXIST', 'ENOTEMPTY'].includes(error.code)) throw error; }
      } finally { await rm(temporary, { recursive: true, force: true }); }
    }
    return { java: path.join(home, 'bin', 'java'), classpath: [classes, path.join(vendor, '*')].join(path.delimiter), buildHash };
  })();
  buildPromise.catch(() => { buildPromise = undefined; });
  return buildPromise;
}

export function derToP1363(signature) {
  const bytes = Buffer.from(signature);
  if (bytes.length < 8 || bytes.length > 72 || bytes[0] !== 0x30 || bytes[1] !== bytes.length - 2) throw failure('JCARD_BAD_SIGNATURE', '卡片返回了无效 ECDSA DER 签名。');
  let cursor = 2;
  const integer = () => {
    if (bytes[cursor++] !== 0x02) throw failure('JCARD_BAD_SIGNATURE', 'ECDSA 分量类型无效。');
    const length = bytes[cursor++];
    if (length < 1 || length > 33 || cursor + length > bytes.length || (bytes[cursor] & 0x80)) throw failure('JCARD_BAD_SIGNATURE', 'ECDSA 分量长度或符号无效。');
    let part = bytes.subarray(cursor, cursor + length); cursor += length;
    if (part.length > 1 && part[0] === 0) {
      if (!(part[1] & 0x80)) throw failure('JCARD_BAD_SIGNATURE', 'ECDSA DER 非规范整数。');
      part = part.subarray(1);
    }
    if (part.length > 32) throw failure('JCARD_BAD_SIGNATURE', 'ECDSA 分量超出 P-256。');
    return Buffer.concat([Buffer.alloc(32 - part.length), part]);
  };
  const result = Buffer.concat([integer(), integer()]);
  if (cursor !== bytes.length) throw failure('JCARD_BAD_SIGNATURE', 'ECDSA DER 含额外数据。');
  return result;
}

// This module holds only a public key and APDU transport. All ECDSA signing and
// key generation take place in DeviceSignerApplet inside the separate JVM.
export async function startJCardSim() {
  const build = await buildJCardSim();
  const child = spawn(build.java, ['-Xms16m', '-Xmx128m', '-cp', build.classpath, 'demo.jcard.SimulatorBridge'], {
    env: javaEnvironment(), stdio: ['pipe', 'pipe', 'pipe'],
  });
  let alive = true, closing = false, counter = 0, commands = 0, signatures = 0, queue = Promise.resolve(), stderr = '';
  let resolveReady, rejectReady;
  const ready = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  const pending = new Map();
  const exited = new Promise(resolve => child.once('exit', resolve));
  const abort = error => {
    alive = false; rejectReady(error);
    for (const request of pending.values()) { clearTimeout(request.timer); request.reject(error); }
    pending.clear();
  };
  const timeout = setTimeout(() => { abort(failure('JCARD_START_TIMEOUT', 'jCardSim 启动超时；不会回退到软件私钥。')); child.kill('SIGKILL'); }, 10000);
  child.stderr.on('data', bytes => { stderr = (stderr + bytes).slice(-4000); });
  child.stdin.on('error', () => abort(failure('JCARD_UNAVAILABLE', 'jCardSim APDU 管道不可用。')));
  child.once('error', () => { clearTimeout(timeout); abort(failure('JCARD_UNAVAILABLE', '无法启动 jCardSim JVM。')); });
  child.once('exit', code => {
    clearTimeout(timeout);
    abort(failure('JCARD_UNAVAILABLE', closing ? 'jCardSim 已关闭。' : `jCardSim JVM 已退出 (${code})；不会回退到 Node 私钥。`));
  });
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
  lines.on('line', line => {
    const parts = line.split('\t');
    if (parts.length === 3 && parts[0] === 'READY') {
      if (Number(parts[1]) !== child.pid || !/^04[\da-f]{128}$/.test(parts[2])) {
        abort(failure('JCARD_INVALID_READY', 'jCardSim 公钥握手无效。')); child.kill('SIGKILL'); return;
      }
      clearTimeout(timeout); resolveReady(Buffer.from(parts[2], 'hex')); return;
    }
    const id = Number(parts[0]), request = pending.get(id);
    if (!request) { abort(failure('JCARD_PROTOCOL_ERROR', 'jCardSim 响应请求编号不匹配。')); child.kill('SIGKILL'); return; }
    clearTimeout(request.timer); pending.delete(id);
    if (parts.length !== 3 || parts[1] !== 'OK' || !/^(?:[\da-f]{2}){2,260}$/.test(parts[2])) {
      request.reject(failure('JCARD_APDU_FAILED', 'jCardSim APDU 处理失败。')); return;
    }
    commands++;
    request.resolve(Buffer.from(parts[2], 'hex'));
  });
  let publicPoint;
  try { publicPoint = await ready; }
  catch (error) { child.kill('SIGKILL'); error.message += stderr ? ` JVM: ${stderr.trim()}` : ''; throw error; }
  const publicJwk = { kty: 'EC', crv: 'P-256', x: publicPoint.subarray(1, 33).toString('base64url'), y: publicPoint.subarray(33).toString('base64url') };
  const publicKey = createPublicKey({ key: publicJwk, format: 'jwk' });
  function rawApdu(bytes) {
    if (!alive || closing) return Promise.reject(failure('JCARD_UNAVAILABLE', 'jCardSim 不可用；不会回退到 Node 私钥。'));
    return new Promise((resolve, reject) => {
      const id = ++counter;
      const timer = setTimeout(() => { abort(failure('JCARD_APDU_TIMEOUT', 'jCardSim APDU 超时，签名结果未知。')); child.kill('SIGKILL'); }, 5000);
      pending.set(id, { resolve, reject, timer });
      child.stdin.write(`${id}\t${Buffer.from(bytes).toString('hex')}\n`);
    });
  }
  function serialized(action) {
    const result = queue.then(action);
    queue = result.catch(() => {});
    return result;
  }
  async function command(ins, bytes = Buffer.alloc(0), p1 = 0) {
    const apdu = bytes.length ? Buffer.concat([Buffer.from([0x80, ins, p1, 0, bytes.length]), bytes, Buffer.from([0])]) : Buffer.from([0x80, ins, p1, 0, 0]);
    const result = await rawApdu(apdu);
    const status = result.readUInt16BE(result.length - 2);
    if (status !== 0x9000) throw failure(status === 0x6982 ? 'ESIM_LOCKED' : 'JCARD_APDU_REJECTED', `Java Card 拒绝 APDU，状态字 ${status.toString(16)}。`);
    return result.subarray(0, -2);
  }
  return {
    publicJwk: Object.freeze({ ...publicJwk }),
    publicInfo: () => ({ backend: 'jcardsim', distribution: JCARD_DISTRIBUTION, applet: 'demo.jcard.DeviceSignerApplet', appletAid: APPLET_AID,
      javaPid: child.pid, algorithm: 'ES256', curve: 'P-256', ready: alive && !closing, keyStorage: 'Java Card applet in jCardSim JVM',
      entropySource: 'JDK SecureRandom (local simulator RNG patch)',
      keyExportable: false, hardware: false, apduCommands: commands, signatures, buildHash: build.buildHash }),
    sign(input) {
      const bytes = Buffer.from(input);
      if (!bytes.length || bytes.length > 32768) return Promise.reject(failure('JCARD_INVALID_INPUT', 'JWS 签名输入长度无效。'));
      return serialized(async () => {
        await command(0x20);
        let offset = 0;
        for (; offset + 220 < bytes.length; offset += 220) await command(0x21, bytes.subarray(offset, offset + 220));
        const result = derToP1363(await command(0x22, bytes.subarray(offset)));
        if (!verify('sha256', bytes, { key: publicKey, dsaEncoding: 'ieee-p1363' }, result)) throw failure('JCARD_BAD_SIGNATURE', '卡片签名不能通过公钥验证。');
        signatures++;
        return result;
      });
    },
    setLocked(locked) { return serialized(() => command(0x30, Buffer.alloc(0), locked ? 1 : 0)); },
    // Diagnostic access is module-local to the device process/tests, never HTTP.
    transmitApdu(bytes) { return serialized(() => rawApdu(bytes)); },
    async close() {
      if (closing) return exited;
      closing = true;
      child.stdin.end();
      const timer = setTimeout(() => child.kill('SIGKILL'), 2000);
      try { await exited; } finally { clearTimeout(timer); lines.close(); }
    },
  };
}
