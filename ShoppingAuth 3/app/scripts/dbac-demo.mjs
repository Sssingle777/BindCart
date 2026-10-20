import { startDbacDemo } from '../lib/dbac/runtime.mjs';
import { DBAC_MODES } from '../lib/dbac/policy.mjs';

const runtime = await startDbacDemo();
try {
  const reports = [];
  for (const mode of DBAC_MODES) {
    const response = await fetch(`${runtime.a.baseUrl}/api/dbac/demo`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Demo-UI-Key': runtime.uiToken }, body: JSON.stringify({ mode }) });
    const result = await response.json();
    if (!response.ok || result.passed !== result.total) throw new Error(JSON.stringify(result));
    reports.push(result);
  }
  console.log(JSON.stringify({ date: new Date().toISOString(), environment: { node: process.version, platform: process.platform, arch: process.arch }, processCount: runtime.pids.length, reports }, null, 2));
} finally { await runtime.close(); }
