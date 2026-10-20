import http from 'node:http';
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';
import { createNativeRenderer } from '../lib/storefront/native-render.mjs';
import { CATALOG } from '../lib/storefront/catalog.mjs';

// Isolated browser fixtures only: no live demo, credentials, ledger or signing service.
const render = await createNativeRenderer();
const publicRoot = fileURLToPath(new URL('../public/', import.meta.url));
const output = resolve(process.env.NATIVE_INITIALIZATION_OUTPUT_PATH || fileURLToPath(new URL('../../evidence/native-mystore/', import.meta.url)));
const key = 'A'.repeat(43), ownerKey = 'B'.repeat(43);
const cart = CATALOG.filter(product => ['02', '03'].includes(product.id)).map(product => ({ ...product, quantity: 1, amountMinor: product.unitAmountMinor }));
function savedState(phase) {
  const totalMinor = cart.reduce((sum, item) => sum + item.amountMinor, 0);
  const order = phase === 'cart' ? null : { orderId: 'urn:uuid:11111111-1111-4111-8111-111111111111', amountMinor: totalMinor, currency: 'TEST_USDC' };
  return { phase, revision: 2, cart: structuredClone(cart), totalMinor, currency: 'TEST_USDC', busy: false, error: null,
    backend: { paymentPending: phase === 'confirming' }, order,
    receipt: order ? { ...order, transactionStatus: 'success', transactionHash: 'fixture-original-receipt' } : null,
    merchant: { status: phase === 'paid' ? 'confirmed' : phase === 'confirming' ? 'pending' : 'none' } };
}

async function fixture(browser, { name, phase, route, earlySnapshot }, check) {
  let state = savedState(phase), firstRequest = true, initialResolved = false, releaseInitial;
  const initialGate = new Promise(resolve => { releaseInitial = resolve; });
  const streams = new Set(), mutations = [], pageErrors = [], consoleErrors = [], externalRequests = [], httpErrors = [], serverErrors = [];
  let stateReads = 0, snapshots = 0, context;
  const server = http.createServer(async (req, res) => {
    try {
      const path = new URL(req.url, 'http://localhost').pathname;
      if (req.method === 'GET' && path === '/store/') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8'); return res.end(render());
      }
      if (path.startsWith('/api/') || path.startsWith('/owner/')) assert.equal(req.headers['x-demo-ui-key'], key);
      if (req.method === 'GET' && path === '/api/live/events') {
        res.writeHead(200, { 'Content-Type': 'text/event-stream' }); res.flushHeaders(); streams.add(res);
        if (earlySnapshot || initialResolved) {
          snapshots++; res.write(`event: snapshot\ndata: ${JSON.stringify({ sequence: mutations.length, store: state })}\n\n`);
        }
        res.on('close', () => streams.delete(res)); return;
      }
      if (req.method === 'GET' && path === '/api/store/state') {
        stateReads++;
        if (firstRequest) { firstRequest = false; await initialGate; initialResolved = true; }
        res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify(state));
      }
      if (req.method === 'POST') {
        let raw = ''; for await (const chunk of req) raw += chunk;
        const body = JSON.parse(raw); mutations.push({ path, body });
        assert.ok(initialResolved, 'No POST may arrive before the initial GET resolves');
        assert.equal(path, '/api/store/new', `Unexpected business mutation: ${path}`);
        assert.equal(state.phase, 'paid', 'Only an explicitly completed order can reset in this fixture');
        assert.deepEqual(body, { revision: state.revision });
        state = { ...state, phase: 'cart', revision: state.revision + 1, cart: [], totalMinor: 0,
          backend: {}, order: null, receipt: null, merchant: { status: 'none' } };
        res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify(state));
      }
      if (req.method === 'GET' && (path.startsWith('/store/mystore/') || ['/store/app.js', '/live-feed.js'].includes(path))) {
        const file = resolve(publicRoot, '.' + decodeURIComponent(path));
        assert.ok(file.startsWith(publicRoot.endsWith(sep) ? publicRoot : publicRoot + sep), 'Static path must stay inside public/');
        const bytes = await readFile(file);
        const mime = { '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png',
          '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.woff': 'font/woff', '.woff2': 'font/woff2' }[extname(file)];
        res.setHeader('Content-Type', mime ?? 'application/octet-stream'); return res.end(bytes);
      }
      res.writeHead(404); res.end('Unknown fixture route');
    } catch (error) {
      serverErrors.push(error.message);
      res.writeHead(500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: { message: error.message } }));
    }
  });
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const origin = `http://127.0.0.1:${server.address().port}`;
    context = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'zh-CN' });
    await context.addInitScript(({ key, ownerKey }) => {
      sessionStorage.setItem('storefront-key', key); sessionStorage.setItem('storefront-ownerKey', ownerKey);
    }, { key, ownerKey });
    await context.route('**/*', route => {
      if (new URL(route.request().url()).origin !== origin) { externalRequests.push(route.request().url()); return route.abort(); }
      return route.continue();
    });
    const page = await context.newPage(); page.setDefaultTimeout(10000);
    page.on('pageerror', error => pageErrors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
    page.on('response', response => { if (response.status() >= 400) httpErrors.push({ path: new URL(response.url()).pathname, status: response.status() }); });
    const started = page.waitForRequest(request => new URL(request.url()).pathname === '/api/store/state');
    // Attach rejection handling before navigation so a navigation failure cannot leave an unhandled waiter.
    const opened = page.goto(`${origin}/store/#${route}`, { waitUntil: 'load' });
    await Promise.all([started, opened]);
    await check({ page, getState: () => structuredClone(state), mutations, releaseInitial,
      assertHeld() { assert.equal(initialResolved, false); assert.equal(stateReads, 1); assert.deepEqual(mutations, []); } });
    await page.waitForLoadState('load');
    assert.ok(initialResolved); assert.ok(stateReads >= 2, 'Every scenario must verify a reload');
    assert.deepEqual(pageErrors, []); assert.deepEqual(consoleErrors, []); assert.deepEqual(externalRequests, []);
    assert.deepEqual(httpErrors, []); assert.deepEqual(serverErrors, []);
    return { name, status: 'passed', stateReads, snapshots, phase: state.phase, revision: state.revision,
      cartIds: state.cart.map(item => item.id), orderId: state.order?.orderId ?? null, mutations,
      pageErrors, consoleErrors, externalRequests, httpErrors, serverErrors };
  } finally {
    releaseInitial();
    try { await context?.close(); }
    finally {
      for (const stream of streams) stream.end(); server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  }
}

async function waitState(page, phase, revision, route) {
  await page.waitForFunction(({ phase, revision, route }) => document.body.dataset.phase === phase &&
    document.body.dataset.revision === String(revision) && document.body.dataset.busy === 'false' && location.hash === '#' + route,
  { phase, revision, route });
}
async function assertCart(page) {
  await page.locator('.order-summary__list__list-item__title').nth(1).waitFor();
  assert.deepEqual(await page.locator('.order-summary__list__list-item__title').allTextContents(), ['耳机', '太阳镜']);
  assert.equal(await page.locator('.shopping-cart__notifications').innerText(), '2');
}

let browser;
try {
  // Launch before opening fixture listeners, so a missing browser cannot leave a server alive.
  browser = await launchAcceptanceBrowser({ headless: true });
  const scenarios = [];
  scenarios.push(await fixture(browser, { name: 'paid-early-return-home', phase: 'paid', route: '/', earlySnapshot: true }, async f => {
    const { page } = f;
    await waitState(page, 'paid', 2, '/confirmation');
    const home = page.locator('.status a.button[href="#/"]');
    assert.equal(await home.innerText(), '返回首页'); f.assertHeld();
    await home.click();
    await page.waitForFunction(() => document.body.dataset.busy === 'true');
    // The first click disables the link; inject one duplicate DOM event to test the queued action.
    await home.dispatchEvent('click');
    await page.waitForTimeout(100); f.assertHeld();
    f.releaseInitial();
    await waitState(page, 'cart', 3, '/');
    await page.locator('.products__list__list-item').nth(8).waitFor();
    assert.equal(await page.locator('.products__list__list-item').count(), 9);
    await page.locator('.shopping-cart__link').click(); await page.locator('.cart--empty').waitFor();
    await page.reload(); await waitState(page, 'cart', 3, '/cart');
    await page.locator('.cart--empty').waitFor();
    assert.deepEqual(f.mutations, [{ path: '/api/store/new', body: { revision: 2 } }]);
    assert.deepEqual(f.getState().cart, []); assert.equal(f.getState().order, null); assert.equal(f.getState().receipt, null);
  }));
  scenarios.push(await fixture(browser, { name: 'saved-cart-checkout-route', phase: 'cart', route: '/checkout', earlySnapshot: false }, async f => {
    const { page } = f;
    await page.locator('.products__list__list-item').nth(8).waitFor(); f.assertHeld();
    assert.equal(await page.locator('#local-payment-confirm').count(), 0);
    const saved = f.getState(); f.releaseInitial();
    await waitState(page, 'cart', 2, '/cart'); await assertCart(page);
    assert.deepEqual(f.mutations, []); assert.deepEqual(f.getState(), saved);
    await page.reload(); await waitState(page, 'cart', 2, '/cart'); await assertCart(page);
    assert.deepEqual(f.mutations, []); assert.deepEqual(f.getState(), saved);
  }));
  scenarios.push(await fixture(browser, { name: 'pending-order-early-navigation', phase: 'confirming', route: '/', earlySnapshot: true }, async f => {
    const { page } = f;
    await waitState(page, 'confirming', 2, '/checkout');
    await page.locator('#local-payment-confirm').waitFor();
    assert.equal(await page.locator('#local-payment-confirm').innerText(), '查询支付结果');
    assert.equal(await page.locator('.status__message').count(), 0); f.assertHeld();
    const saved = f.getState();
    await page.locator('.header__link[href="#/"]').click();
    await page.waitForFunction(() => document.body.dataset.busy === 'true');
    await page.waitForTimeout(100); f.assertHeld();
    f.releaseInitial(); await waitState(page, 'confirming', 2, '/checkout');
    assert.deepEqual(f.mutations, []); assert.deepEqual(f.getState(), saved);
    await page.reload(); await waitState(page, 'confirming', 2, '/checkout');
    await page.locator('#local-payment-confirm').waitFor();
    assert.equal(await page.locator('#local-payment-confirm').innerText(), '查询支付结果');
    assert.equal(await page.locator('.status__message').count(), 0);
    assert.equal(await page.getAttribute('body', 'data-order-id'), saved.order.orderId);
    assert.deepEqual(f.mutations, []); assert.deepEqual(f.getState(), saved);
  }));
  const report = { status: 'passed', finishedAt: new Date().toISOString(), fixtureOnly: true, realCryptoOrChainTest: false,
    browserVersion: browser.version(),
    scope: 'Isolated browser fixtures; no live demo state, actual payment or cryptographic service was accessed.',
    checks: ['SSE paid snapshot renders while initial GET remains held', 'User click plus duplicate DOM click waits for initialization',
      'Exactly one reset with the original revision; completed cart stays empty after reload',
      'Current two-product cart restores without implicit checkout or reset', 'Pending order survives early home navigation and reload',
      'No implicit payment, query, Owner approval or signing', 'No page/console/server/HTTP errors or external requests'], scenarios };
  await mkdir(output, { recursive: true });
  await writeFile(resolve(output, 'initialization-race-verification.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} finally { await browser?.close(); }
