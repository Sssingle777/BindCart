// This command only executes an order already approved in the independent UI.
try {
  const url = new URL(process.env.DEMO_URL ?? 'http://127.0.0.1:4340');
  const key = process.env.DEMO_UI_KEY ?? new URLSearchParams(url.hash.slice(1)).get('key');
  if (!key) throw new Error('请通过 DEMO_URL 传入启动终端显示的完整控制台链接，或设置 DEMO_UI_KEY。');
  async function api(path, body) {
    const response = await fetch(`${url.origin}${path}`, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'X-Demo-UI-Key': key, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(30000), redirect: 'error',
    });
    const value = await response.json();
    if (!response.ok) throw new Error(`${value.error?.code}: ${value.error?.message}`);
    return value;
  }
  const { order } = await api('/api/payment');
  console.log(`验收已由 Owner 批准的订单 ${order.orderId}：${order.payerAccount} → ${order.payeeAccount}，${order.amountMinor / (order.currency === 'TEST_USDC' ? 1000000 : 100)} ${order.currency}。`);
  const data = await api('/api/payment/demo', {});
  for (const result of data.results) console.log(`${result.pass ? 'PASS' : 'FAIL'} ${result.name}: ${result.actual}`);
  console.log(`\n${data.passed}/${data.total} 符合预期。`);
  console.log(JSON.stringify((await api('/api/payment')).ledger, null, 2));
  if (!data.total || data.passed !== data.total) process.exitCode = 1;
} catch (error) { console.error(`支付验收失败：${error.message}\n请先签发 VC、解锁设备、提交提案并在独立 Owner 页面确认；此命令不会自动批准付款。`); process.exitCode = 1; }
