// Test-only loader: wrap the shipped functions in memory; never edit source.
import { registerHooks } from 'node:module';
import { performance } from 'node:perf_hooks';
import { createHash } from 'node:crypto';

const digest = s => createHash('sha256').update(s).digest('hex');
const samples = [], sources = [];
export const bench = globalThis.__shoppingAuthComputeBench = {
  context: null,
  finish(context, operation, start, cpu, success) {
    const wallMs = performance.now() - start;
    const usage = process.cpuUsage(cpu);
    samples.push({ ...context, role: process.env.SHOPPINGAUTH_BENCH_ROLE ?? 'agent-a',
      operation, success, wallMs, cpuUserMs: usage.user/1000,
      cpuSystemMs: usage.system/1000, cpuMs: (usage.user+usage.system)/1000 });
  },
  sync(operation, fn) {
    const context = this.context;
    if (!context) return fn();
    const cpu = process.cpuUsage(), start = performance.now(); let success = false;
    try { const value = fn(); success = true; return value; }
    finally { this.finish(context, operation, start, cpu, success); }
  },
  async async(operation, fn) {
    const context = this.context;
    if (!context) return await fn();
    const cpu = process.cpuUsage(), start = performance.now(); let success = false;
    try { const value = await fn(); success = true; return value; }
    finally { this.finish(context, operation, start, cpu, success); }
  },
  drain() { return { samples: samples.splice(0), sources: [...sources] }; },
};

const root = new URL('../../作品源码/BindCart/app/lib/', import.meta.url);
const spec = new Map([
  [new URL('w3c-bbs.mjs', root).href, [
    ['deriveCredential', true, true, 'vcDerive'],
    ['verifyDerived', true, false, 'vcVerify'],
  ]],
  [new URL('dbac/crypto.mjs', root).href, [
    ['preparePresentation', false, true, 'bindingPrepare'],
    ['signDeviceRequest', false, true, 'deviceSign'],
    ['finalizePresentation', false, true, 'bindingFinalize'],
    ['verifyPresentation', false, true, 'bindingVerify'],
  ]],
  [new URL('dbac/holder-proof.mjs', root).href, [
    ['signHolderProof', false, true, 'holderSign'],
    ['verifyHolderProof', false, true, 'holderVerify'],
  ]],
]);
registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    if (!spec.has(url)) return result;
    const original = typeof result.source === 'string' ? result.source : Buffer.from(result.source).toString('utf8');
    let source = original;
    for (const [name, async, exported, operation] of spec.get(url)) {
      const prefix = `${exported ? 'export ' : ''}${async ? 'async ' : ''}function `;
      const needle = `${prefix}${name}(`;
      if (source.split(needle).length !== 2) throw new Error(`Instrumentation anchor mismatch: ${name}`);
      const hidden = `__computeOriginal_${name}`;
      const wrapper = `${prefix}${name}(...args) { return ${async ? 'await ' : ''}globalThis.__shoppingAuthComputeBench.${async ? 'async' : 'sync'}(${JSON.stringify(operation)}, () => ${hidden}(...args)); }\n${async ? 'async ' : ''}function ${hidden}(`;
      source = source.replace(needle, wrapper);
    }
    sources.push({ url, originalSha256: digest(original), instrumentedSha256: digest(source),
      operations: spec.get(url).map(v => v[3]) });
    return { ...result, source };
  },
});
if (process.send) process.on('message', message => {
  if (message?.kind !== 'compute-control') return;
  if (message.action === 'context') bench.context = message.context;
  const result = message.action === 'drain' ? bench.drain() : {};
  process.send({ kind: 'compute-control-reply', id: message.id, ...result });
});
