import { createDbacDevice, createDbacIssuer } from './lib/dbac/services.mjs';

process.once('message', async config => {
  let service;
  try {
    if (!['device', 'issuer'].includes(config.role)) throw new Error('Unknown DBAC role');
    service = config.role === 'device' ? createDbacDevice(config) : createDbacIssuer(config);
    const baseUrl = await service.listen(config.port ?? 0);
    process.send?.({ ready: true, role: config.role, baseUrl, ...service.publicInfo() });
    let closing = false;
    const shutdown = () => { if (closing) return; closing = true; service.close().finally(() => process.exit()); };
    process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown); process.on('disconnect', shutdown);
  } catch (error) { process.send?.({ error: error.message, code: error.code ?? 'DBAC_ROLE_FAILED' }); await service?.close(); process.exitCode = 1; process.disconnect?.(); }
});
