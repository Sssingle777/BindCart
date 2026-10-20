import { startDbacDemo } from './lib/dbac/runtime.mjs';

function port(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 0 || value > 65535) throw new Error(`${name} 必须是 0–65535 的整数。`);
  return value;
}
let runtime;
async function stop() { await runtime?.close(); process.exitCode = 0; }
try {
  runtime = await startDbacDemo({ aPort: port('DBAC_PORT', 4350), bPort: port('DBAC_AGENT_B_PORT', 4351) });
  console.log(`BBS-BLS / BBS-BlindBLS 论文复现\n统一演示链接: ${runtime.a.baseUrl}/#key=${runtime.uiToken}&view=diagnostic\n控制台：${runtime.a.baseUrl}/dbac.html#key=${runtime.uiToken}\n匿名 A2A 验证端：${runtime.b.baseUrl}/dbac/a2a\n四个独立进程：Agent A、Agent B、Issuer、BLS 软件设备。\n两方案使用不同设备密钥；所有身份与凭证仅在本次进程内。\n不启动 jCardSim 或支付链，不读取默认 var 数据。Ctrl+C 退出。`);
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
} catch (error) { await runtime?.close(); console.error(error.message); process.exitCode = 1; }
