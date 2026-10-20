import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createDbacPaymentSession } from '../dbac/payment-session.mjs';
import { createX402Payer } from '../x402-payment.mjs';
import { createStorefrontController } from './controller.mjs';
import { checkLocalRequest, readBody, parseObject, sendJson, AppError } from '../protocol.mjs';
import { timingSafeEqual } from 'node:crypto';

process.once('message', async config => {
  try {
    const paymentSession = createDbacPaymentSession({ ...config.dbac, baseUrl: config.verifierUrl, verifierDid: config.verifierDid, owner: config.owner,
      x402Payer: createX402Payer(config.payerConfig), paymentInfo: config.payerConfig.publicInfo,
      async getLedger() {
        const response = await fetch(`${config.verifierUrl}/admin/ledger`, { headers: { 'X-Demo-Admin': config.adminToken }, signal: AbortSignal.timeout(10000) });
        if (!response.ok) throw new AppError('LEDGER_UNAVAILABLE', '无法读取原控制器的支付账本。', 503);
        return response.json();
      },
    });
    const controller = await createStorefrontController({ paymentSession, directory: config.orderDirectory });
    let baseUrl, busy = false;
    const files = new Map([['/', ['index.html', 'text/html']], ['/store/', ['index.html', 'text/html']], ['/store/app.js', ['app.js', 'text/javascript']], ['/store/adyen-application.css', ['adyen-application.css', 'text/css']], ['/store/integration.css', ['integration.css', 'text/css']]]);
    for (const name of ['mystore-logo.svg', 'headphones.png', 'sunglasses.png', 'success.svg', 'thank-you.svg']) files.set(`/store/images/${name}`, [`images/${name}`, name.endsWith('.svg') ? 'image/svg+xml' : 'image/png']);
    const server = http.createServer({ requestTimeout: 120000 }, async (req, res) => {
      let acquired = false, authenticated = false;
      try {
        checkLocalRequest(req, baseUrl);
        const path = new URL(req.url, baseUrl).pathname;
        if (req.method === 'GET' && files.has(path)) {
          const [file, mime] = files.get(path);
          const bytes = await readFile(new URL(`../../public/store/${file}`, import.meta.url));
          res.writeHead(200, { 'Content-Type': `${mime}${mime.startsWith('text/') ? '; charset=utf-8' : ''}`, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" });
          return res.end(bytes);
        }
        if (req.method === 'GET' && path === '/api/health') return sendJson(res, 200, { ok: true, service: 'adyen-front-original-controller', pid: process.pid, controller: 'lib/dbac/payment-session.mjs', localTestOnly: true, browserAutomation: false });
        if (path.startsWith('/owner/api/')) {
          if (req.method !== 'POST' || !/^\/owner\/api\/proposals\/[A-Za-z0-9_-]+\/(approve|reject)$/.test(path)) throw new AppError('NOT_FOUND', '授权接口不存在。', 404);
          if (busy) throw new AppError('STORE_BUSY', '请等待当前订单处理完成。', 409);
          busy = true; acquired = true;
          const upstream = await fetch(`${config.owner.baseUrl}${path.slice('/owner'.length)}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Owner-UI-Key': req.headers['x-owner-ui-key'] ?? '' }, body: await readBody(req), signal: AbortSignal.timeout(10000), redirect: 'error' });
          return sendJson(res, upstream.status, await upstream.json());
        }
        const supplied = Buffer.from(req.headers['x-demo-ui-key'] ?? ''), expected = Buffer.from(config.uiToken);
        if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) throw new AppError('UI_ACCESS_DENIED', '请从本次双击启动生成的入口访问。', 401);
        authenticated = true;
        if (req.method === 'GET' && path === '/api/store/catalog') return sendJson(res, 200, { products: controller.catalog(), localTestOnly: true });
        if (req.method === 'GET' && path === '/api/store/state') return sendJson(res, 200, { ...await controller.state(), busy, actors: config.actors });
        if (req.method === 'POST' && path === '/api/shutdown') { sendJson(res, 200, { ok: true }); process.send?.({ action: 'shutdown-requested' }); return; }
        const actions = { '/api/store/cart': 'changeCart', '/api/store/checkout': 'checkout', '/api/store/pay': 'pay', '/api/store/new': 'reset', '/api/store/security': 'security' };
        if (req.method !== 'POST' || !actions[path]) throw new AppError('NOT_FOUND', '商城接口不存在。', 404);
        if (busy) throw new AppError('STORE_BUSY', '订单正在处理中，请稍候。', 409);
        busy = true; acquired = true;
        const body = parseObject(await readBody(req));
        const result = await controller[actions[path]](body);
        sendJson(res, 200, { ...result, busy: false, actors: config.actors });
      } catch (error) {
        const state = authenticated ? await controller.state().catch(() => null) : null;
        sendJson(res, error.status ?? 500, { error: { code: error.code ?? 'STORE_ERROR', message: error.message }, ...(state ? { state: { ...state, busy: acquired ? false : busy, actors: config.actors } } : {}) });
      } finally { if (acquired) busy = false; }
    });
    const shutdown = () => { server.closeAllConnections(); server.close(() => process.exit()); };
    process.on('disconnect', shutdown); process.on('SIGTERM', shutdown);
    process.on('message', message => { if (message.action === 'shutdown') shutdown(); });
    server.on('error', error => process.send?.({ error: error.message }));
    server.listen(config.port ?? 4381, '127.0.0.1', () => { baseUrl = `http://127.0.0.1:${server.address().port}`; process.send?.({ baseUrl, pid: process.pid }); });
  } catch (error) { process.send?.({ error: error.message }); process.exitCode = 1; process.disconnect?.(); }
});
