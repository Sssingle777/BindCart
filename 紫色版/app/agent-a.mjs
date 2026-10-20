import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createSession } from './lib/session.mjs';
import { createX402Payer } from './lib/x402-payment.mjs';
import { createDbacSession } from './lib/dbac/session.mjs';
import { createDbacPaymentSession } from './lib/dbac/payment-session.mjs';
import { DBAC_EXTENSION } from './lib/dbac/policy.mjs';
import { AppError, VERSION, EXTENSION, deserializeIdentity, readBody, parseObject, sendJson, checkLocalRequest, messageRpc } from './lib/protocol.mjs';

process.once('message', async (config) => {
  try {
    if (typeof config.uiToken !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(config.uiToken)) throw new Error('缺少有效控制台访问凭据。');
    const uiKey = Buffer.from(config.uiToken);
    if (!config.dbacOnly && !config.owner) throw new Error('网络服务必须配置独立 Owner，不允许退回本地付款确认。');
    if (!config.dbacOnly && !config.payerConfig) throw new Error('新版必须配置真实 x402 SDK 支付服务，不允许回退 SQLite 模拟扣款。');
    if (config.dbacOnly && !config.dbac) throw new Error('缺少论文匿名方案配置。');
    const session = config.dbacOnly ? null : createSession({ issuer: deserializeIdentity(config.issuer), agentA: deserializeIdentity(config.agentA), verifierDid: config.verifierDid, baseUrl: config.baseUrl, adminToken: config.adminToken, device: config.device, owner: config.owner, x402Payer: createX402Payer(config.payerConfig), paymentInfo: config.payerConfig.publicInfo });
    const anonymous = config.dbac ? createDbacSession({ ...config.dbac, verifierDid: config.verifierDid, baseUrl: config.baseUrl }) : null;
    const dbacPayment = !config.dbacOnly && config.dbac ? createDbacPaymentSession({ ...config.dbac, verifierDid: config.verifierDid, baseUrl: config.baseUrl, owner: config.owner, x402Payer: createX402Payer(config.payerConfig), paymentInfo: config.payerConfig.publicInfo, async getLedger() {
      const response = await fetch(`${config.baseUrl}/admin/ledger`, { headers: { 'X-Demo-Admin': config.adminToken }, signal: AbortSignal.timeout(10000), redirect: 'error' });
      if (!response.ok) throw new AppError('DBAC_LEDGER_UNAVAILABLE', '无法读取当前链上余额与回执。', 503);
      return response.json();
    } }) : null;
    let baseUrl, busy = false;
    const files = new Map([['/', ['demo.html', 'text/html']], ['/console.html', ['index.html', 'text/html']], ['/app.js', ['app.js', 'text/javascript']], ['/style.css', ['style.css', 'text/css']], ['/dbac.html', ['dbac.html', 'text/html']], ['/dbac-app.js', ['dbac-app.js', 'text/javascript']], ['/dbac-style.css', ['dbac-style.css', 'text/css']]]);
    for (const name of ['demo', 'embed', 'verification']) for (const [extension, type] of [['js', 'text/javascript'], ['css', 'text/css']]) files.set(`/${name}.${extension}`, [`${name}.${extension}`, type]);
    files.set('/guide-stage.css', ['guide-stage.css', 'text/css']);
    files.set('/tokens.css', ['tokens.css', 'text/css']);
    files.set('/platform.css', ['platform.css', 'text/css']);
    files.set('/navigation-model.js', ['navigation-model.js', 'text/javascript']);
    files.set('/dbac-payment.js', ['dbac-payment.js', 'text/javascript']);
    for (const name of ['core-model', 'protocol-model']) files.set(`/${name}.js`, [`${name}.js`, 'text/javascript']);
    for (const [extension, type] of [['html', 'text/html'], ['js', 'text/javascript'], ['css', 'text/css']]) files.set(`/workspace.${extension}`, [`workspace.${extension}`, type]);
    for (const [extension, type] of [['html', 'text/html'], ['js', 'text/javascript'], ['css', 'text/css']]) files.set(`/guide.${extension}`, [`guide.${extension}`, type]);
    for (const name of ['guide-model', 'guide-experiments', 'guide-progress', 'guide-evidence', 'guide-step-detail', 'guide-scene', 'guide-stage-ui']) files.set(`/${name}.js`, [`${name}.js`, 'text/javascript']);
    for (const scenario of ['normal', 'copied-vc', 'revoked']) files.set(`/guide/${scenario}.html`, ['guide.html', 'text/html']);
    const ownerFiles = new Map([['/owner/', ['index.html', 'text/html']], ['/owner/app.js', ['app.js', 'text/javascript']], ['/owner/style.css', ['style.css', 'text/css']], ['/owner/tokens.css', ['tokens.css', 'text/css']], ['/owner/platform.css', ['platform.css', 'text/css']]]);
    const server = http.createServer({ requestTimeout: 15000, headersTimeout: 10000 }, async (req, res) => {
      let lock = false;
      try {
        checkLocalRequest(req, baseUrl);
        const assetPath = new URL(req.url, baseUrl).pathname;
        if (req.method === 'GET' && ['/manual-demo.html', '/payment-detail.html'].includes(assetPath)) {
          // No fragment in Location: browsers retain an existing local access fragment.
          res.writeHead(302, { Location: '/', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
          return res.end();
        }
        if (req.method === 'GET' && (files.has(assetPath) || ownerFiles.has(assetPath))) {
          const ownerFile = ownerFiles.has(assetPath);
          if (ownerFile && !config.owner) throw new AppError('OWNER_NOT_AVAILABLE', '论文独立模式不启动 Owner 确认服务。', 404);
          const [name, type] = (ownerFile ? ownerFiles : files).get(assetPath);
          const file = await readFile(new URL(`./${ownerFile ? 'owner-public' : 'public'}/${name}`, import.meta.url));
          res.writeHead(200, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors ${req.url === '/' ? "'none'" : "'self'"}; form-action 'self'` });
          return res.end(file);
        }
        if (req.method === 'GET' && req.url === '/api/health') return sendJson(res, 200, { ok: true, service: 'agent-a', protocolVersion: VERSION, appVersion: '0.5.0', securityProfile: config.dbacOnly ? DBAC_EXTENSION : EXTENSION, independentOwner: !config.dbacOnly, deviceRuntime: config.dbacOnly ? 'node-bls12-381' : 'jCardSim', paymentProtocol: config.dbacOnly ? null : 'x402-v2', dbacAvailable: Boolean(anonymous), namedAvailable: Boolean(session), ownerAvailable: Boolean(config.owner), localTestOnly: true, pid: process.pid });
        // Same-origin presentation only: Owner still checks the separate capability
        // supplied by the browser. Agent A never receives it from the launcher.
        if (req.url.startsWith('/owner/api/')) {
          if (!config.owner) throw new AppError('OWNER_NOT_AVAILABLE', '论文独立模式不启动 Owner 确认服务。', 404);
          const path = req.url.slice('/owner'.length);
          if (!(req.method === 'GET' && path === '/api/state') && !(req.method === 'POST' && /^\/api\/proposals\/[A-Za-z0-9_-]+\/(approve|reject)$/.test(path))) throw new AppError('NOT_FOUND', 'Owner 接口不存在。', 404);
          const supplied = req.headers['x-owner-ui-key'];
          if (typeof supplied !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(supplied)) throw new AppError('OWNER_UI_ACCESS_DENIED', '请通过统一演示链接或 Owner 专用链接载入确认权限。', 401);
          if (req.method === 'POST' && dbacPayment?.experimentRunBusy()) throw new AppError('BUSY', '实验正在执行，请等待原运行完成后再操作。', 409);
          const body = req.method === 'POST' ? await readBody(req) : undefined;
          let upstream;
          try {
            upstream = await fetch(`${config.owner.baseUrl}${path}`, { method: req.method, headers: { Accept: 'application/json', 'X-Owner-UI-Key': supplied, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, body, redirect: 'error', signal: AbortSignal.timeout(10000) });
            return sendJson(res, upstream.status, await upstream.json());
          } catch { throw new AppError('OWNER_UNAVAILABLE', 'Owner 服务暂时无法连接；请刷新提案核对实际批准状态。', 503); }
        }
        if (req.url.startsWith('/api/')) {
          const supplied = Buffer.from(req.headers['x-demo-ui-key'] ?? '');
          if (supplied.length !== uiKey.length || !timingSafeEqual(supplied, uiKey)) throw new AppError('UI_ACCESS_DENIED', '请使用启动终端提供的本次控制台链接进入。', 401);
        }
        if (req.url.startsWith('/api/dbac/payment/')) {
          if (req.method === 'GET' && new URL(req.url, baseUrl).pathname === '/api/dbac/payment/state') return sendJson(res, 200, dbacPayment ? await dbacPayment.state({ mode: new URL(req.url, baseUrl).searchParams.get('mode') ?? 'bbs-bls' }) : { available: false, reason: '此启动模式仅提供机制检查；请用 npm start 启动论文支付、Owner 与本地链。' });
          if (!dbacPayment) throw new AppError('DBAC_PAYMENT_NOT_CONFIGURED', '论文支付需要完整启动本地链与 Owner。', 503);
          if (new URL(req.url, baseUrl).pathname === '/api/dbac/payment/experiment-runs') {
            if (req.method === 'GET') {
              const runId = new URL(req.url, baseUrl).searchParams.get('runId');
              return sendJson(res, 200, runId === null ? dbacPayment.experimentRuns() : dbacPayment.experimentRun(runId));
            }
            if (req.method !== 'POST' || req.url !== '/api/dbac/payment/experiment-runs') throw new AppError('NOT_FOUND', '实验运行接口不存在。', 404);
            return sendJson(res, 200, dbacPayment.startExperimentRun(parseObject(await readBody(req)), busy));
          }
          if (req.method === 'GET' && new URL(req.url, baseUrl).pathname === '/api/dbac/payment/manage') return sendJson(res, 200, await dbacPayment.inventory({ mode: new URL(req.url, baseUrl).searchParams.get('mode') ?? 'bbs-bls' }));
          if (req.method === 'GET' && new URL(req.url, baseUrl).pathname === '/api/dbac/payment/experiments') return sendJson(res, 200, { scenarios: dbacPayment.experimentScenarios() });
          const actions = { manage: 'manage', experiments: 'experiments', issue: 'issue', new: 'newOrder', propose: 'propose', sync: 'sync', pay: 'pay', retry: 'retry', demo: 'demo', manual: 'manual' };
          const action = req.url.slice('/api/dbac/payment/'.length);
          if (req.method !== 'POST' || !Object.hasOwn(actions, action)) throw new AppError('NOT_FOUND', '论文支付接口不存在。', 404);
          const body = parseObject(await readBody(req));
          const allowedFields = action === 'manage' ? ['mode', 'action', 'deviceId', 'credentialId', 'optionalFields'] : action === 'experiments' ? ['mode', 'scenarioId'] : action === 'manual' ? ['mode', 'action', 'attemptId'] : action === 'new' ? ['mode', 'amountMinor', 'payeeAccount'] : ['mode'];
          if (Object.keys(body).some(key => !allowedFields.includes(key))) throw new AppError('DBAC_PAYMENT_INVALID_INPUT', '支付操作包含不支持的参数。');
          if (action === 'manual' && (typeof body.action !== 'string' || (body.attemptId !== undefined && typeof body.attemptId !== 'string'))) throw new AppError('DBAC_PAYMENT_INVALID_INPUT', '手动消息需要有效 action 和 attemptId。');
          if (busy || dbacPayment.experimentRunBusy()) throw new AppError('BUSY', '演示正在运行，请稍后操作。', 409);
          busy = true; lock = true;
          return sendJson(res, 200, await dbacPayment[actions[action]](body));
        }
        if (req.url.startsWith('/api/dbac/')) {
          if (!anonymous) throw new AppError('DBAC_NOT_CONFIGURED', '请使用更新后的启动器运行论文复现。', 503);
          if (req.method === 'GET' && new URL(req.url, baseUrl).pathname === '/api/dbac/state') return sendJson(res, 200, await anonymous.state({ mode: new URL(req.url, baseUrl).searchParams.get('mode') ?? 'bbs-bls' }));
          const actions = { '/api/dbac/issue': 'issue', '/api/dbac/invoke': 'invoke', '/api/dbac/demo': 'demo', '/api/dbac/device/lock': 'deviceLock' };
          if (req.method !== 'POST' || !actions[req.url]) throw new AppError('NOT_FOUND', '匿名演示接口不存在。', 404);
          const body = parseObject(await readBody(req));
          if (busy || dbacPayment?.experimentRunBusy()) throw new AppError('BUSY', '演示正在运行，请稍后操作。', 409);
          busy = true; lock = true;
          return sendJson(res, 200, await anonymous[actions[req.url]](body));
        }
        if (!session) throw new AppError('DBAC_ONLY', '此启动模式只提供论文匿名凭证接口。', 404);
        if (req.method === 'GET' && req.url === '/api/state') return sendJson(res, 200, session.state());
        if (req.method === 'GET' && req.url === '/api/card') return sendJson(res, 200, await session.getCard());
        if (req.method === 'GET' && req.url === '/api/device') return sendJson(res, 200, await session.deviceStatus());
        if (req.method === 'GET' && req.url === '/api/audit') return sendJson(res, 200, await session.audit());
        if (req.method === 'GET' && req.url === '/api/payment') return sendJson(res, 200, await session.payment.state());
        if (req.method === 'POST' && ['/api/issue', '/api/revoke', '/api/invoke', '/api/demo', '/api/device/lock', '/api/payment/new', '/api/payment/approve', '/api/payment/propose', '/api/payment/sync', '/api/payment/pay', '/api/payment/retry', '/api/payment/demo'].includes(req.url)) {
          const body = parseObject(await readBody(req));
          if (busy || dbacPayment?.experimentRunBusy()) throw new AppError('BUSY', '演示正在运行，请稍后操作。', 409);
          busy = true; lock = true;
          if (req.url === '/api/issue') return sendJson(res, 200, session.issue());
          if (req.url === '/api/revoke') return sendJson(res, 200, await session.revoke());
          if (req.url === '/api/demo') return sendJson(res, 200, await session.demo());
          const paymentActions = { '/api/payment/new': 'newOrder', '/api/payment/approve': 'approve', '/api/payment/propose': 'propose', '/api/payment/sync': 'sync', '/api/payment/pay': 'pay', '/api/payment/retry': 'retry', '/api/payment/demo': 'demo' };
          if (paymentActions[req.url]) return sendJson(res, 200, await session.payment[paymentActions[req.url]](body));
          if (req.url === '/api/device/lock') {
            if (typeof body.locked !== 'boolean') throw new AppError('INVALID_LOCK', 'locked 必须是布尔值。');
            return sendJson(res, 200, await session.deviceLock(body.locked));
          }
          if (body.text !== undefined && typeof body.text !== 'string') throw new AppError('INVALID_TEXT', 'text 必须是字符串。');
          return sendJson(res, 200, { ok: true, ...await session.invoke(messageRpc(body.text)) });
        }
        sendJson(res, 404, { error: { code: 'NOT_FOUND', message: '接口不存在。' } });
      } catch (error) { sendJson(res, error.status && error.status >= 400 ? error.status : 400, { ok: false, error: { code: error.code ?? 'ERROR', message: error.message, ...Object.fromEntries(['transaction', 'transactionHash', 'settlementResponse'].filter(key => error[key] !== undefined).map(key => [key, error[key]])) }, ...(error.verificationTrace ? { verificationTrace: error.verificationTrace } : {}) }); }
      finally { if (lock) busy = false; }
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(config.port, '127.0.0.1', () => { server.off('error', reject); resolve(); }); });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
    process.send?.({ ready: true, baseUrl, pid: process.pid });
    const shutdown = () => { server.closeAllConnections(); server.close(() => process.exit()); };
    process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown); process.on('disconnect', shutdown);
  } catch (error) { process.send?.({ error: error.message }); process.exitCode = 1; process.disconnect?.(); }
});
