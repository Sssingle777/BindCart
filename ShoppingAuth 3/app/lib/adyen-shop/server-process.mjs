import http from 'node:http';
import { readFile, mkdir, writeFile, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import { verifyJws } from '../identity.mjs';
import { checkLocalRequest, readBody, parseObject, sendJson, AppError } from '../protocol.mjs';
import { createShopHolder, postJson, sameSecret, verifyShopPermit, orderHash } from './credentials.mjs';
import { MyStoreBrowser } from './browser.mjs';

process.once('message', async config => {
  const holder = createShopHolder(config);
  const directory = resolve(config.evidenceDir);
  await mkdir(directory, { recursive: true });
  let browser, baseUrl, busy = false, closing = false;
  let state = { phase: 'idle', product: null, order: null, credential: null, verification: null, result: null, message: '连接官方演示商城，开始一次耳机购物。' };
  try {
    const previous = JSON.parse(await readFile(resolve(directory, 'latest-order.json'), 'utf8'));
    if (['paying', 'unknown'].includes(previous.phase)) {
      state = { ...previous, phase: 'unknown', message: '上次测试付款的结果尚未确认。已保留原订单，不会因重启而重复付款。' };
    }
  } catch (error) {
    if (error.code !== 'ENOENT') {
      state = { ...state, phase: 'unknown', message: '无法读取上次订单记录。请先核对本地记录，当前不会自动提交付款。' };
    }
  }
  const remote = (path, body, headers) => postJson(`${config.verifierUrl}${path}`, body, { 'X-Shop-Service': config.serviceKey, ...headers });
  const view = () => ({ ...state, busy, localTestOnly: true, connectionType: 'official-demo-browser', actors: config.actors });
  async function save() {
    const report = JSON.stringify({ ...view(), savedAt: new Date().toISOString() }, null, 2);
    await writeFile(resolve(directory, 'latest-order.json.tmp'), report);
    await rename(resolve(directory, 'latest-order.json.tmp'), resolve(directory, 'latest-order.json'));
    if (state.order) await writeFile(resolve(directory, `${state.order.id.slice(9)}.json`), report);
  }
  async function verifyOrder(options) {
    const { context, signature } = await remote('/challenge', { order: state.order, mode: 'bbs-bls' });
    const signed = verifyJws(signature, { typ: 'adyen-mystore-challenge+jwt', expectedDid: config.verifierDid, purpose: 'authentication' }).payload;
    if (JSON.stringify(signed.context) !== JSON.stringify(context) || context.orderHash !== orderHash(state.order)) throw new AppError('SHOP_BAD_CHALLENGE', '验证方挑战签名或订单不匹配。', 403);
    const result = await remote('/verify', await holder.prove(context, state.order, options));
    state.verification = { accepted: result.accepted, steps: result.steps, orderHash: result.orderHash, bindingId: result.bindingId, checkedAt: new Date().toISOString() };
    return result;
  }
  const files = new Map([['/', ['shop.html', 'text/html']], ['/shop.html', ['shop.html', 'text/html']], ['/shop.js', ['shop.js', 'text/javascript']], ['/shop.css', ['shop.css', 'text/css']]]);
  const server = http.createServer({ requestTimeout: 120000 }, async (req, res) => {
    let acquired = false;
    try {
      checkLocalRequest(req, baseUrl);
      const pathname = new URL(req.url, baseUrl).pathname;
      if (req.method === 'GET' && files.has(pathname)) {
        const [filename, type] = files.get(pathname);
        res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: https://www.mystoredemo.io; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'" });
        return res.end(await readFile(new URL(`../../public/${filename}`, import.meta.url)));
      }
      if (req.method === 'GET' && pathname === '/health') return sendJson(res, 200, { ok: true, service: 'credentialpay-adyen-shop', pid: process.pid });
      if (!sameSecret(req.headers['x-demo-ui-key'], config.uiToken)) return sendJson(res, 401, { error: { code: 'UI_ACCESS_DENIED', message: '请使用本次启动生成的商城入口。' } });
      if (req.method === 'GET' && pathname === '/api/adyen/state') return sendJson(res, 200, view());
      if (req.method === 'GET' && pathname === '/api/adyen/preview') {
        if (!browser?.page) throw new AppError('SHOP_NOT_CONNECTED', '尚未连接商城。', 409);
        res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'no-store' });
        return res.end(await browser.screenshot());
      }
      if (req.method !== 'POST') throw new AppError('NOT_FOUND', '接口不存在。', 404);
      if (busy) throw new AppError('SHOP_BUSY', '当前操作尚未结束，请稍候。', 409);
      const body = parseObject(await readBody(req));
      if (Object.keys(body).length) throw new AppError('SHOP_INPUT_INVALID', '商品与金额由官方商城读取，不接受前端覆盖。', 400);
      busy = true; acquired = true;
      delete state.error;
      if (pathname === '/api/adyen/connect') {
        if (['paying', 'unknown'].includes(state.phase)) throw new AppError('SHOP_OUTCOME_UNRESOLVED', '上一笔测试付款尚未核清，不能新建订单。', 409);
        await browser?.close();
        browser = new MyStoreBrowser();
        state = { phase: 'loading', product: null, order: null, credential: holder.info(), verification: null, result: null, message: '正在读取 MyStore 商品和购物车…' };
        const quote = await browser.quote();
        if (!holder.info()) await holder.issue();
        state = { ...state, ...quote, credential: holder.info(), phase: 'cart', message: '商品与价格来自官方演示商城。确认后，Agent 将验证本次付款资格。' };
      } else if (pathname === '/api/adyen/checkout') {
        if (state.phase !== 'cart') throw new AppError('SHOP_STATE_INVALID', '请先准备购物车。', 409);
        state.phase = 'verifying'; state.message = '正在验证凭证、持有者签名和软件 eSIM 证明…';
        await verifyOrder();
        const session = await browser.openCheckout(state.order);
        state.order.providerReference = session.reference;
        state.providerSession = { id: session.id, reference: session.reference, amount: session.amount };
        state.phase = 'checkout'; state.message = '资格验证通过，官方 Adyen 测试付款窗口已就绪。';
        await writeFile(resolve(directory, 'checkout.png'), await browser.screenshot());
      } else if (pathname === '/api/adyen/pay') {
        if (state.phase !== 'checkout') throw new AppError('SHOP_STATE_INVALID', '需要先验证资格并打开测试付款窗口。', 409);
        // A fresh use proof includes the official provider reference, so neither
        // an earlier qualification nor a changed cart can authorize this payment.
        const verified = await verifyOrder();
        const { permit } = await remote('/approve', { receipt: verified.receipt, order: state.order }, { 'X-Owner-UI-Key': req.headers['x-owner-ui-key'] ?? '' });
        verifyShopPermit(permit, state.order, config.verifierDid);
        const result = await browser.pay(state.order, async () => {
          verifyShopPermit(permit, state.order, config.verifierDid);
          state.phase = 'paying'; state.message = '已确认订单，正在提交一次官方测试付款…';
          await save();
        });
        state.result = result;
        state.phase = result.status === 'authorised' ? 'paid' : 'not-authorised';
        state.message = result.status === 'authorised' ? 'Adyen 测试环境已返回 Authorised。没有真实扣款或发货。' : `官方测试支付返回 ${result.resultCode}，未标记为支付成功。`;
        await writeFile(resolve(directory, 'payment-result.png'), await browser.screenshot());
      } else if (pathname === '/api/adyen/attack') {
        if (state.phase !== 'cart') throw new AppError('SHOP_STATE_INVALID', '在打开付款窗口之前运行防冒用演示。', 409);
        try {
          await verifyOrder({ omitDevice: true });
          throw new Error('Unexpected acceptance of a missing device proof');
        } catch (error) {
          if (error.code !== 'W3C_DEVICE_PROOF_REQUIRED') throw error;
          state.verification = { accepted: false, steps: error.steps, error: error.code, checkedAt: new Date().toISOString() };
          state.message = '复制的标准凭证通过验签，但缺少绑定设备证明，已拒绝打开付款窗口。';
        }
      } else if (pathname === '/api/adyen/revoke') {
        if (['paying', 'paid', 'unknown'].includes(state.phase)) throw new AppError('SHOP_STATE_INVALID', '请为新订单执行凭证管理。', 409);
        await holder.revoke(); state.credential.revoked = true; state.message = '演示凭证已撤销。下一次验证将实际向签发方查询并拒绝。';
      } else if (pathname === '/api/adyen/reissue') {
        if (state.phase !== 'cart') throw new AppError('SHOP_STATE_INVALID', '请在购物车阶段重新签发。', 409);
        state.credential = await holder.issue(); state.verification = null; state.message = '已重新签发绑定本地持有者与设备的演示支付凭证。';
      } else if (pathname === '/api/shutdown') {
        sendJson(res, 200, { ok: true });
        process.send?.({ action: 'shutdown-requested' });
        return;
      } else throw new AppError('NOT_FOUND', '接口不存在。', 404);
      await save();
      sendJson(res, 200, { ...view(), busy: false });
    } catch (error) {
      if (acquired && !(state.phase === 'paid' && error.code === 'SHOP_STATE_INVALID')) {
        if (browser?.paymentAttempted && !state.result) {
          state.phase = 'unknown'; state.message = '测试付款已尝试提交，但结果未确认。不会自动重复付款。';
        } else {
          if (state.phase === 'verifying') state.phase = 'cart';
          if (state.phase === 'loading') state.phase = 'error';
          state.message = error.message;
        }
        state.error = { code: error.code ?? 'SHOP_CONNECTION_ERROR', message: error.message };
        if (error.steps) state.verification = { accepted: false, steps: error.steps, error: error.code };
        await save().catch(() => {});
      }
      sendJson(res, error.status ?? 502, { error: { code: error.code ?? 'SHOP_CONNECTION_ERROR', message: error.message }, state: { ...view(), busy: false } });
    } finally { if (acquired) busy = false; }
  });
  async function shutdown() {
    if (closing) return;
    closing = true;
    await browser?.close();
    server.close(() => process.exit());
  }
  process.on('message', message => { if (message.action === 'shutdown') void shutdown(); });
  process.on('disconnect', shutdown);
  process.on('SIGTERM', shutdown);
  server.on('error', error => process.send?.({ error: error.message }));
  server.listen(config.port ?? 4380, '127.0.0.1', () => {
    baseUrl = `http://127.0.0.1:${server.address().port}`;
    process.send?.({ baseUrl, pid: process.pid });
  });
});
