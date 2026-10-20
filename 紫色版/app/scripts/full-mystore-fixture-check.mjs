import http from 'node:http';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';
import { createNativeRenderer } from '../lib/storefront/native-render.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = resolve(process.env.FULL_MYSTORE_FIXTURE_OUTPUT_PATH || resolve(root, '../evidence/full-mystore-fixture'));
await mkdir(output, { recursive: true });
const sourceManifest = JSON.parse(await readFile(resolve(root, 'third-party/mystore-web/SOURCE-MANIFEST.json')));
for (const file of sourceManifest.files) {
  const raw = await readFile(resolve(root, 'third-party/mystore-web', file.path));
  const published = await readFile(resolve(root, 'public/store/mystore', file.path));
  assert.equal(createHash('sha256').update(raw).digest('hex'), file.sha256); assert.deepEqual(raw, published);
}
const sku = [['01', 'Polo 衫', 24990000], ['02', '耳机', 19990000], ['03', '太阳镜', 14990000]];
const products = sku.map(([id, name, unitAmountMinor]) => ({ id, name, unitAmountMinor, currency: 'TEST_USDC' }));
let state = { phase: 'cart', revision: 0, cart: [], totalMinor: 0, currency: 'TEST_USDC', order: null, backend: {}, merchant: { status: 'none' }, busy: false, error: null };
let calls = [], payments = 0, owners = 0, resets = 0; const streams = new Set();
const publicState = () => JSON.parse(JSON.stringify(state));
const emit = () => { for (const res of streams) res.write(`event: snapshot\ndata: ${JSON.stringify({ sequence: calls.length, store: publicState() })}\n\n`); };
const render = await createNativeRenderer();
const server = http.createServer(async (req, res) => {
  try {
    const path = new URL(req.url, 'http://localhost').pathname;
    if (path === '/api/live/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.flushHeaders(); streams.add(res); emit(); req.on('close', () => streams.delete(res)); return;
    }
    if (path === '/api/store/state') { res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify(publicState())); }
    if (req.method === 'POST') {
      let data = ''; for await (const part of req) data += part;
      const body = JSON.parse(data); calls.push({ path, body });
      if (path === '/api/store/cart') {
        assert.equal(body.revision, state.revision); assert.equal(state.phase, 'cart');
        state.cart = state.cart.filter(item => item.id !== body.productId);
        if (body.quantity) { const product = products.find(item => item.id === body.productId); state.cart.push({ ...product, quantity: 1, amountMinor: product.unitAmountMinor }); }
        state.totalMinor = state.cart.reduce((sum, item) => sum + item.amountMinor, 0); state.revision++;
      } else if (path === '/api/store/checkout') {
        state.busy = true; emit(); await new Promise(done => setTimeout(done, 300)); state.busy = false;
        state.phase = 'checkout'; state.order = { orderId: 'fixture-order', amountMinor: state.totalMinor, merchantOrder: { snapshotHash: 'fixture' } };
        state.backend.proposal = { id: 'fixture-proposal', status: 'PENDING', payment: { ...state.order }, credentialHash: 'fixture-only' };
      } else if (path.startsWith('/owner/api/')) { owners++; state.backend.proposal.status = 'APPROVED'; }
      else if (path === '/api/store/pay') {
        assert.equal(state.backend.proposal.status, 'APPROVED'); payments++;
        state.busy = true; state.phase = 'paying'; emit(); await new Promise(done => setTimeout(done, 300));
        state.busy = false; state.phase = 'confirming'; state.receipt = { transactionHash: 'fixture-original-receipt' }; state.merchant.status = 'pending';
      } else if (path === '/api/store/query') { state.phase = 'paid'; state.merchant.status = 'confirmed'; }
      else if (path === '/api/store/new') { resets++; state = { ...state, phase: 'cart', revision: state.revision + 1, cart: [], totalMinor: 0, order: null, error: null, receipt: null, merchant: { status: 'none' }, backend: {} }; }
      else throw new Error('Unexpected mutation ' + path);
      emit(); res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify(publicState()));
    }
    if (path === '/store/' || path === '/') { res.setHeader('Content-Type', 'text/html; charset=utf-8'); return res.end(render()); }
    const file = resolve(root, 'public', path.slice(1));
    if (!file.startsWith(resolve(root, 'public'))) throw new Error('Invalid path');
    const mime = { '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' }[extname(file)] ?? 'application/octet-stream';
    res.setHeader('Content-Type', mime); res.end(await readFile(file));
  } catch (error) { res.statusCode = 500; res.end(JSON.stringify({ error: { message: error.message } })); }
});
await new Promise(done => server.listen(0, '127.0.0.1', done));
const origin = `http://127.0.0.1:${server.address().port}`;
let browser;
try {
  browser = await launchAcceptanceBrowser({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1024, height: 1000 } }); const errors = [], external = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => { if (new URL(route.request().url()).origin !== origin) { external.push(route.request().url()); return route.abort(); } return route.continue(); });
  await page.goto(origin + '/store/#key=' + 'a'.repeat(43) + '&ownerKey=' + 'b'.repeat(43));
  await page.locator('.products__list__list-item').nth(8).waitFor();
  // A copied PSP return URL must remain a normal local storefront load. It
  // cannot instantiate the unused Adyen redirect/session recovery SDK.
  await page.goto(origin + '/store/?redirectResult=fixture-result&sessionId=fixture-session');
  await page.locator('.products__list__list-item').nth(8).waitFor();
  await page.waitForTimeout(300);
  assert.deepEqual(errors, []); assert.deepEqual(external, []);
  assert.equal(await page.locator('.products__list__list-item').count(), 9);
  assert.equal(await page.locator('.products__list__list-item__item__title').first().innerText(), 'Polo 衫');
  await page.locator('a[href="#/product/01"]').first().click(); await page.locator('.product-detail__title').waitFor();
  assert.equal(await page.locator('.product-detail__title').innerText(), 'Polo 衫');
  assert.match(await page.locator('.product-detail__description').innerText(), /经典/);
  await page.locator('.product-detail__button').click();
  await page.waitForFunction(() => document.body.dataset.revision === '1' && document.body.dataset.busy === 'false');
  await page.locator('.shopping-cart__link').click(); await page.locator('.cart__title').waitFor();
  assert.equal(await page.locator('.ctp-toggle,#field-checkbox,#field-email').count(), 0);
  await page.locator('.order-summary__list__list-item__remove-product').click(); await page.locator('.cart--empty').waitFor();
  await page.locator('a[href="#/"]').last().click(); await page.locator('a[href="#/product/02"]').first().click();
  await page.locator('.product-detail__button').click(); await page.waitForFunction(() => document.body.dataset.revision === '3' && document.body.dataset.busy === 'false');
  await page.locator('.shopping-cart__link').click(); await page.locator('.cart_checkout-button').click();
  await page.locator('#local-payment-confirm').waitFor();
  assert.equal(state.phase, 'checkout'); assert.equal(state.backend.proposal.status, 'PENDING'); assert.equal(payments, 0); assert.equal(owners, 0);
  assert.equal(await page.locator('.ctp-toggle,#field-checkbox,#field-email,.checkout__order-summary__shopper-email').count(), 0);
  assert.match(await page.locator('#local-payment-confirm').innerText(), /19\.99 测试币/);
  await page.screenshot({ path: resolve(output, '01-official-checkout-chinese.png'), fullPage: true });
  await page.locator('#local-payment-confirm').evaluate(button => { button.dispatchEvent(new MouseEvent('click', { bubbles: true })); button.dispatchEvent(new MouseEvent('click', { bubbles: true })); });
  await page.waitForFunction(() => document.body.dataset.phase === 'confirming' && document.body.dataset.busy === 'false');
  assert.equal(await page.locator('.status__message').count(), 0); assert.equal(payments, 1); assert.equal(owners, 1);
  assert.equal(await page.locator('#local-payment-confirm').innerText(), '查询支付结果');
  await page.reload(); await page.locator('#local-payment-confirm').waitFor();
  assert.equal(resets, 0); assert.equal(payments, 1);
  await page.locator('#local-payment-confirm').click(); await page.locator('.status__message').waitFor();
  assert.equal(await page.locator('.status__message').innerText(), '订单已成功提交。'); assert.equal(payments, 1); assert.equal(owners, 1);
  await page.reload(); await page.locator('.status__message').waitFor(); assert.equal(resets, 0); assert.equal(payments, 1);
  await page.locator('.status a.button').click(); await page.locator('.products__list__list-item').nth(8).waitFor();
  assert.equal(resets, 1); assert.equal(state.cart.length, 0);
  await page.screenshot({ path: resolve(output, '02-official-products-chinese.png'), fullPage: true });
  assert.deepEqual(errors, []); assert.deepEqual(external, []);
  const report = { status: 'passed', fixtureOnly: true, realCryptoOrChainTest: false, officialProducts: 9, originalFilesByteVerified: sourceManifest.files.length,
    checks: ['official nine-product grid and unchanged styles', 'Chinese details and original recommendation layout', 'backend-authoritative add/remove/cart',
      'checkout waits for qualification before explicit payment', 'explicit exact Owner then payment', 'pending never shows success', 'query uses original result without payment',
      'refresh preserves pending and paid orders', 'return home resets only explicit safe order', 'PSP query redirect never starts remote SDK',
      'unsupported Click to Pay and shopper email are absent', 'no external requests or browser errors'], payments, owners, resets };
  await writeFile(resolve(output, 'verification.json'), JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify(report));
} finally {
  try { await browser?.close(); }
  finally { for (const stream of streams) stream.end(); server.closeAllConnections(); await new Promise(done => server.close(done)); }
}
