import http from 'node:http';
import { createShopVerifier, sameSecret } from './credentials.mjs';
import { deserializeIdentity, checkLocalRequest, readBody, parseObject, sendJson } from '../protocol.mjs';

process.once('message', config => {
  const verifier = createShopVerifier({ ...config, identity: deserializeIdentity(config.identity) });
  let baseUrl;
  const server = http.createServer(async (req, res) => {
    try {
      checkLocalRequest(req, baseUrl);
      if (req.method !== 'POST' || !sameSecret(req.headers['x-shop-service'], config.serviceKey)) return sendJson(res, 401, { error: { code: 'SHOP_SERVICE_DENIED', message: '需要本地服务权限。' } });
      const body = parseObject(await readBody(req));
      const result = req.url === '/challenge' ? verifier.challenge(body.order, body.mode)
        : req.url === '/verify' ? await verifier.verify(body)
        : req.url === '/approve' ? verifier.approve({ ...body, suppliedOwnerKey: req.headers['x-owner-ui-key'] })
        : null;
      sendJson(res, result ? 200 : 404, result ?? { error: { code: 'NOT_FOUND', message: '接口不存在。' } });
    } catch (error) { sendJson(res, error.status ?? 400, { error: { code: error.code ?? 'SHOP_VERIFICATION_FAILED', message: error.message }, steps: error.steps ?? [] }); }
  });
  server.listen(0, '127.0.0.1', () => {
    baseUrl = `http://127.0.0.1:${server.address().port}`;
    process.send?.({ baseUrl, did: verifier.did, pid: process.pid });
  });
  process.on('disconnect', () => server.close(() => process.exit()));
  process.on('SIGTERM', () => server.close(() => process.exit()));
});
