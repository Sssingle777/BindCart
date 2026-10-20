try {
  const url = new URL(process.env.DEMO_URL ?? 'http://127.0.0.1:4340');
  const key = process.env.DEMO_UI_KEY ?? new URLSearchParams(url.hash.slice(1)).get('key');
  if (!key) throw new Error('请通过 DEMO_URL 传入启动终端显示的完整控制台链接，或设置 DEMO_UI_KEY。');
  const response = await fetch(`${url.origin}/api/demo`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Demo-UI-Key': key }, body: '{}', signal: AbortSignal.timeout(30000) });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error?.message ?? `HTTP ${response.status}`);
  for (const result of data.results) console.log(`${result.pass ? 'PASS' : 'FAIL'} ${result.name}: ${result.actual}`);
  console.log(`\n${data.passed}/${data.total} 符合预期（VC＋A 私钥不足以通过；全部签名权限泄露仍可能通过）。`);
  if (data.passed !== data.total) process.exitCode = 1;
} catch (error) { console.error(`演示失败：${error.message}\n请先在另一个终端运行 npm start。`); process.exitCode = 1; }
