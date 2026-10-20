import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';

const output = resolve('../evidence/native-restart');
await mkdir(output, { recursive: true });
const runtime = JSON.parse(await readFile(new URL('../var/dual-runtime.json', import.meta.url)));
const caps = new URLSearchParams(new URL(runtime.url).hash.slice(1));
async function get(path) {
  const response = await fetch(runtime.baseUrl + path, { headers: { 'X-Demo-UI-Key': caps.get('key') } });
  assert.equal(response.status, 200);
  return response.json();
}
const ledger = state => ({ executions: state.backend.ledger.executionCount,
  balances: state.backend.ledger.accounts.map(({ id, balanceMinor }) => ({ id, balanceMinor })) });
const snapshot = await get('/api/live/state');
if (process.argv[2] === 'before') {
  const paid = snapshot.history.find(row => row.phase === 'paid');
  assert(paid, 'Need an actually paid order from the UI verification');
  const record = await get(`/api/live/orders/${encodeURIComponent(paid.orderId)}`);
  assert.equal(record.merchant.status, 'confirmed');
  await writeFile(resolve(output, 'before.json'), JSON.stringify({ at: new Date().toISOString(),
    instanceId: snapshot.instanceId, pid: runtime.pid, ledger: ledger(snapshot.store),
    orderId: paid.orderId, receiptHash: record.receipt.transactionHash,
    merchantDid: record.order.merchantOrder.snapshot.merchantDid,
    snapshotHash: record.order.merchantOrder.snapshotHash }, null, 2));
  console.log('Captured completed order and balances before restarting this copy.');
} else if (process.argv[2] === 'after') {
  const before = JSON.parse(await readFile(resolve(output, 'before.json')));
  assert.notEqual(runtime.pid, before.pid);
  assert.notEqual(snapshot.instanceId, before.instanceId);
  assert.deepEqual(ledger(snapshot.store), before.ledger);
  const record = await get(`/api/live/orders/${encodeURIComponent(before.orderId)}`);
  assert.equal(record.readOnly, true);
  assert.equal(record.merchant.status, 'confirmed');
  assert.equal(record.receipt.transactionHash, before.receiptHash);
  assert.equal(record.order.merchantOrder.snapshotHash, before.snapshotHash);
  assert.equal(record.order.merchantOrder.snapshot.merchantDid, before.merchantDid);
  const browser = await launchAcceptanceBrowser({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
    const writes = [], errors = [];
    page.on('request', request => { if (request.method() === 'POST') writes.push(new URL(request.url()).pathname); });
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(`${runtime.baseUrl}/mechanism/#key=${caps.get('key')}`);
    await page.locator('#live-connection[data-state="connected"]').waitFor();
    await page.locator('#live-history').selectOption(before.orderId);
    await page.waitForFunction(hash => document.querySelector('#live-receipt')?.textContent.includes(hash), before.receiptHash);
    assert((await page.locator('#live-merchant-status').innerText()).includes('商户已确认'));
    assert((await page.locator('#live-merchant').innerText()).includes(before.snapshotHash));
    assert.deepEqual(writes, []);
    assert.deepEqual(errors, []);
    await page.locator('#live-merchant').scrollIntoViewIfNeeded();
    await page.screenshot({ path: resolve(output, 'history-after-restart.png') });
    assert.deepEqual(ledger((await get('/api/live/state')).store), before.ledger);
    await writeFile(resolve(output, 'verification.json'), JSON.stringify({ status: 'passed',
      at: new Date().toISOString(), checks: ['new process and observer instance', 'same chain balances and execution count',
        'same merchant DID and signed order hash', 'same confirmed receipt', 'history rendered read-only without POST requests or page errors'],
      orderId: before.orderId, receiptHash: before.receiptHash, writes, errors }, null, 2));
    console.log('PASS Restart preserves original paid order, merchant identity, receipt and balances; history UI is read-only.');
  } finally { await browser.close(); }
} else throw new Error('Use before or after around the copy-only Stop/Start launchers.');
