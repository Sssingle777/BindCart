import http from 'node:http';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { createDbacPaymentSession } from '../dbac/payment-session.mjs';
import { createX402Payer } from '../x402-payment.mjs';
import { createStorefrontController } from './controller.mjs';
import { catalogProduct } from './catalog.mjs';
import { createLivePaymentSession } from './live-payment-session.mjs';
import { createLiveSystem, publicEvidence, orderIdValid } from './live-system.mjs';
import { createNativeRenderer, nativeView } from './native-render.mjs';
import { checkLocalRequest, readBody, parseObject, sendJson, AppError } from '../protocol.mjs';

process.once('message', async config => {
  try {
    const live = await createLiveSystem({ directory: config.eventDirectory });
    let baseUrl, busy = false, operation = null, snapshotRunning = false, snapshotWanted = false, closing = false, controller;
    const streams = new Set();
    const rawSession = createDbacPaymentSession({ ...config.dbac, baseUrl: config.verifierUrl, verifierDid: config.verifierDid, owner: config.owner,
      x402Payer: createX402Payer(config.payerConfig), paymentInfo: config.payerConfig.publicInfo,
      async getLedger() {
        const response = await fetch(`${config.verifierUrl}/admin/ledger`, { headers: { 'X-Demo-Admin': config.adminToken }, signal: AbortSignal.timeout(10000) });
        if (!response.ok) throw new AppError('LEDGER_UNAVAILABLE', '无法读取原控制器的支付账本。', 503);
        return response.json();
      },
    });
    const paymentSession = createLivePaymentSession({ paymentSession: rawSession, stageDelayMs: config.stageDelayMs ?? 0, emit: event => { live.publish({ operationId: operation?.id ?? null, ...event }); requestSnapshot(); } });
    controller = await createStorefrontController({ paymentSession, directory: config.orderDirectory,
      merchant: config.merchant, paymentInfo: config.payerConfig.publicInfo,
      emit: event => { live.publish({ operationId: operation?.id ?? null, ...event }); requestSnapshot(); } });
    const renderNativePage = await createNativeRenderer();
    function publicState(value) {
      const safe = publicEvidence(value);
      // A step token is a short-lived replay guard for an already-authenticated
      // UI, not an Owner authorization. Other token fields stay redacted.
      if (value?.manualControl?.token) safe.manualControl.token = value.manualControl.token;
      if (value?.store?.manualControl?.token) safe.store.manualControl.token = value.store.manualControl.token;
      if (value?.state?.manualControl?.token) safe.state.manualControl.token = value.state.manualControl.token;
      return safe;
    }
    async function history() {
      const names = (await readdir(config.orderDirectory)).filter(name => /^[0-9a-f-]{36}\.json$/.test(name));
      const records = await Promise.all(names.map(async name => {
        try {
          const row = JSON.parse(await readFile(resolve(config.orderDirectory, name), 'utf8'));
          if (!orderIdValid(row.boundOrder?.orderId)) return null;
          return { orderId: row.boundOrder.orderId, phase: row.phase, totalMinor: row.boundOrder.amountMinor, updatedAt: row.events?.at(-1)?.at ?? null, receiptHash: row.receipt?.transactionHash ?? null };
        } catch { return null; }
      }));
      return records.filter(Boolean).sort((a, b) => (b.updatedAt ?? '').localeCompare(a.updatedAt ?? ''));
    }
    async function snapshot() {
      const core = await rawSession.state();
      const [store, inventory, orders] = await Promise.all([controller.state(core), rawSession.inventory(), history()]);
      return publicState({ instanceId: live.instanceId, sequence: live.sequence, at: new Date().toISOString(), store: { ...store, busy }, core, inventory,
        actors: { ...config.actors, controller: { pid: process.pid } }, events: live.events(), operation, history: orders, journalError: live.journalError });
    }
    function requestSnapshot() {
      snapshotWanted = true;
      if (!controller || snapshotRunning || closing) return;
      snapshotRunning = true;
      setImmediate(async () => {
        try {
          while (snapshotWanted && !closing) {
            snapshotWanted = false;
            try { live.snapshot(await snapshot()); }
            catch (error) { live.publish({ type: 'observer', source: 'live-service', action: 'snapshot', status: 'fail', title: '状态读取失败', detail: error.message }); }
          }
        } finally { snapshotRunning = false; }
      });
    }
    function businessEvent(action, status, state, detail) {
      live.publish({ type: 'business', source: 'storefront-controller', action, status, operationId: operation?.id ?? null,
        title: ({ changeCart: '购物车更新', checkout: '消费资格验证', pay: '用户确认后的模拟付款', reset: '开始下一笔购物', security: '凭证与设备状态', owner: '用户逐笔授权', queryPayment: '查询原支付与商家确认', experiment: '凭证复制与撤销对照实验', fault: '商家确认故障设置' })[action] ?? action,
        orderId: state?.order?.orderId ?? null, phase: state?.phase ?? null, detail,
        data: state ? { totalMinor: state.totalMinor, cartCount: state.cart?.reduce((n, item) => n + item.quantity, 0), receiptHash: state.receipt?.transactionHash ?? null, error: state.error ?? null } : undefined });
      requestSnapshot();
    }
    function writeStream(res, type, data) {
      if (res.destroyed || res.writableEnded) return;
      if (res.writableLength > 4 * 1024 * 1024) { res.destroy(); return; }
      res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
    }
    async function openStream(req, res, after) {
      if (streams.size >= 16) throw new AppError('LIVE_CAPACITY', '同时打开的观察页面过多。', 429);
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff' });
      res.flushHeaders(); streams.add(res);
      const unsubscribe = live.subscribe(event => writeStream(res, 'system', event));
      const unsubscribeSnapshots = live.subscribeSnapshots(value => writeStream(res, 'snapshot', value));
      let timer, cleaned = false;
      const cleanup = () => { if (cleaned) return; cleaned = true; clearInterval(timer); unsubscribe(); unsubscribeSnapshots(); streams.delete(res); };
      res.once('close', cleanup); res.once('error', cleanup); req.once('aborted', cleanup);
      try {
        for (const event of live.events(after)) writeStream(res, 'system', event);
        const initial = await snapshot();
        if (cleaned) return;
        writeStream(res, 'snapshot', initial);
        timer = setInterval(() => { if (!res.destroyed) res.write(': heartbeat\n\n'); }, 12000);
      } catch (error) { cleanup(); throw error; }
    }
    const files = new Map([
      ['/intro/', ['intro.html', 'text/html']], ['/intro/app.js', ['intro.js', 'text/javascript']], ['/intro/style.css', ['intro.css', 'text/css']],
      ['/demo/', ['dual.html', 'text/html']], ['/demo/app.js', ['dual.js', 'text/javascript']], ['/demo/style.css', ['dual.css', 'text/css']],
      ['/mechanism/', ['mechanism.html', 'text/html']], ['/mechanism.js', ['mechanism.js', 'text/javascript']], ['/mechanism.css', ['mechanism.css', 'text/css']],
      ['/favicon.svg', ['favicon.svg', 'image/svg+xml']],
    ]);
    for (const name of ['app.js', 'adyen-application.css', 'bootstrap-4.3.1.min.css']) files.set(`/store/${name}`, [`store/${name}`, name.endsWith('.css') ? 'text/css' : 'text/javascript']);
    for (const name of ['mystore-logo.svg', 'headphones.png', 'sunglasses.png', 'success.svg', 'pending.svg', 'failed.svg', 'error.svg', 'thank-you.svg']) files.set(`/store/images/${name}`, [`store/images/${name}`, name.endsWith('.svg') ? 'image/svg+xml' : 'image/png']);
    // Serve only enumerated local assets, without resolving request paths on disk.
    const storeTypes = { js: 'text/javascript', css: 'text/css', svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp', woff2: 'font/woff2', woff: 'font/woff', ico: 'image/x-icon' };
    for (const name of await readdir(new URL('../../public/store/mystore/', import.meta.url), { recursive: true })) {
      const mime = storeTypes[name.split('.').at(-1)];
      if (mime) files.set(`/store/mystore/${name.replaceAll('\\', '/')}`, [`store/mystore/${name.replaceAll('\\', '/')}`, mime]);
    }
    for (const name of await readdir(new URL('../../public/', import.meta.url))) if (/^[a-z][a-z0-9-]*\.(css|js)$/.test(name)) files.set(`/${name}`, [name, name.endsWith('.css') ? 'text/css' : 'text/javascript']);
    const server = http.createServer({ requestTimeout: 120000 }, async (req, res) => {
      let acquired = false, authenticated = false, actionName = null;
      try {
        checkLocalRequest(req, baseUrl);
        const url = new URL(req.url, baseUrl), path = url.pathname;
        if (req.method === 'GET' && path === '/') { res.writeHead(302, { Location: '/store/', 'Cache-Control': 'no-store' }); return res.end(); }
        if (req.method === 'GET' && ['/store/', '/store/checkout', '/store/result'].includes(path)) {
          const view = nativeView(await controller.state(), path);
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'" });
          return res.end(renderNativePage(...view));
        }
        if (req.method === 'GET' && path === '/favicon.ico') { res.writeHead(302, { Location: '/favicon.svg', 'Cache-Control': 'no-store' }); return res.end(); }
        if (req.method === 'GET' && files.has(path)) {
          const [file, mime] = files.get(path), bytes = await readFile(new URL(`../../public/${file}`, import.meta.url));
          const frameAncestors = ['/demo/', '/intro/'].includes(path) ? "'none'" : "'self'";
          res.writeHead(200, { 'Content-Type': `${mime}${mime.startsWith('text/') ? '; charset=utf-8' : ''}`, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'; frame-ancestors ${frameAncestors}; base-uri 'none'; form-action 'self'` });
          return res.end(bytes);
        }
        if (req.method === 'GET' && path === '/api/health') return sendJson(res, 200, { ok: true, service: 'shopping-live-system', pid: process.pid, instanceId: live.instanceId, controller: 'lib/dbac/payment-session.mjs', localTestOnly: true, realtime: 'original-manual-actions + SSE', browserAutomation: false });
        if (path.startsWith('/owner/api/')) {
          if (req.method !== 'POST' || !/^\/owner\/api\/proposals\/[A-Za-z0-9_-]+\/(approve|reject)$/.test(path)) throw new AppError('NOT_FOUND', '授权接口不存在。', 404);
          if (busy) throw new AppError('STORE_BUSY', '请等待当前订单处理完成。', 409);
          busy = true; acquired = true; actionName = 'owner';
          const body = await readBody(req);
          const upstream = await fetch(`${config.owner.baseUrl}${path.slice('/owner'.length)}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Owner-UI-Key': req.headers['x-owner-ui-key'] ?? '' }, body, signal: AbortSignal.timeout(10000), redirect: 'error' });
          const result = await upstream.json();
          if (upstream.ok) {
            await controller.observeOwnerDecision(result);
            live.publish({ type: 'business', source: 'owner-service', action: path.endsWith('/approve') ? 'owner-approve' : 'owner-reject', status: 'complete', title: path.endsWith('/approve') ? '用户明确批准当前订单' : '用户拒绝当前订单', from: 'owner', to: 'agent-a', orderId: result.payment?.orderId ?? null, data: { proposalId: result.id, status: result.status } });
            requestSnapshot();
          }
          return sendJson(res, upstream.status, publicEvidence(result));
        }
        const supplied = Buffer.from(req.headers['x-demo-ui-key'] ?? ''), expected = Buffer.from(config.uiToken);
        if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new AppError('UI_ACCESS_DENIED', '请从本次双击启动生成的入口访问。', 401);
        authenticated = true;
        if (req.method === 'GET' && path === '/api/store/catalog') return sendJson(res, 200, { products: controller.catalog(), localTestOnly: true });
        if (req.method === 'GET' && path === '/api/store/state') return sendJson(res, 200, publicState({ ...await controller.state(), busy, actors: config.actors }));
        if (req.method === 'GET' && path === '/api/live/state') return sendJson(res, 200, await snapshot());
        if (req.method === 'GET' && path === '/api/live/events') {
          const after = Number(url.searchParams.get('after') ?? 0);
          if (!Number.isSafeInteger(after) || after < 0) throw new AppError('LIVE_CURSOR_INVALID', '观察记录位置无效。', 400);
          await openStream(req, res, after); return;
        }
        if (req.method === 'GET' && path.startsWith('/api/live/orders/')) {
          let orderId;
          try { orderId = decodeURIComponent(path.slice('/api/live/orders/'.length)); }
          catch { throw new AppError('ORDER_NOT_FOUND', '订单记录不存在。', 404); }
          if (!orderIdValid(orderId)) throw new AppError('ORDER_NOT_FOUND', '订单记录不存在。', 404);
          let record;
          try { record = JSON.parse(await readFile(resolve(config.orderDirectory, `${orderId.slice(9)}.json`), 'utf8')); }
          catch { throw new AppError('ORDER_NOT_FOUND', '订单记录不存在。', 404); }
          if (record.boundOrder?.orderId !== orderId) throw new AppError('ORDER_NOT_FOUND', '订单记录不匹配。', 404);
          const cart = Object.entries(record.cart ?? {}).flatMap(([id, quantity]) => { const product = catalogProduct(id); return product ? [{ ...product, quantity, amountMinor: product.unitAmountMinor * quantity }] : []; });
          return sendJson(res, 200, publicEvidence({ ...record, order: record.boundOrder, cart, events: await live.orderEvents(orderId), businessEvents: record.events, readOnly: true }));
        }
        if (req.method === 'POST' && path === '/api/shutdown') { sendJson(res, 200, { ok: true }); process.send?.({ action: 'shutdown-requested' }); return; }
        const actions = { '/api/store/cart': 'changeCart', '/api/store/checkout': 'checkout', '/api/store/pay': 'pay', '/api/store/new': 'reset', '/api/store/security': 'security',
          '/api/store/query': 'queryPayment', '/api/store/experiment': 'experiment', '/api/store/fault': 'fault', '/api/store/manual': 'manual' };
        if (req.method !== 'POST' || !actions[path]) throw new AppError('NOT_FOUND', '商城接口不存在。', 404);
        if (busy) throw new AppError('STORE_BUSY', '订单正在处理中，请稍候。', 409);
        busy = true; acquired = true; actionName = actions[path];
        const body = parseObject(await readBody(req)), before = await controller.state();
        operation = { id: randomUUID(), action: actionName, status: 'start', title: actionName, startedAt: new Date().toISOString(), orderId: before.order?.orderId ?? null };
        businessEvent(actionName, 'start', before, '已收到页面操作，正在调用同一原控制器。');
        const result = await controller[actionName](body);
        operation = { ...operation, status: 'complete', orderId: result.order?.orderId ?? operation.orderId, finishedAt: new Date().toISOString() };
        businessEvent(actionName, 'complete', result, result.message);
        sendJson(res, 200, publicState({ ...result, busy: false, actors: config.actors }));
      } catch (error) {
        const state = authenticated ? await controller.state().catch(() => null) : null;
        if (acquired && authenticated) { operation = { ...operation, action: actionName, status: 'fail', finishedAt: new Date().toISOString() }; businessEvent(actionName, 'fail', state, error.message); }
        if (res.headersSent) { res.destroy(); return; }
        sendJson(res, error.status ?? 500, publicState({ error: { code: error.code ?? 'STORE_ERROR', message: error.message }, ...(state ? { state: { ...state, busy: acquired ? false : busy, actors: config.actors } } : {}) }));
      } finally { if (acquired) { busy = false; requestSnapshot(); } }
    });
    const shutdown = async () => {
      if (closing) return; closing = true;
      for (const response of streams) response.end();
      server.closeAllConnections(); await live.flush(); server.close(() => process.exit());
    };
    process.on('disconnect', shutdown); process.on('SIGTERM', shutdown);
    process.on('message', message => { if (message.action === 'shutdown') void shutdown(); });
    server.on('error', error => process.send?.({ error: error.message }));
    server.listen(config.port ?? 4382, '127.0.0.1', () => {
      baseUrl = `http://127.0.0.1:${server.address().port}`;
      live.publish({ type: 'system', source: 'live-service', action: 'startup', status: 'complete', title: '商城与机制观察页已连接同一控制器', data: { instanceId: live.instanceId } });
      process.send?.({ baseUrl, pid: process.pid });
    });
  } catch (error) { process.send?.({ error: error.message }); process.exitCode = 1; process.disconnect?.(); }
});
