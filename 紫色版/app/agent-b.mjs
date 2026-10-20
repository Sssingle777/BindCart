import { createVerifier } from './lib/verifier.mjs';
import { deserializeIdentity } from './lib/protocol.mjs';
import { createX402Backend } from './lib/x402-payment.mjs';

process.once('message', async (config) => {
  try {
    if (!config.dbacOnly && (!Array.isArray(config.trustedAuthorizers) || !config.trustedAuthorizers.length || config.trustedAuthorizers.some(did => config.trustedIssuers.includes(did)))) throw new Error('B requires explicit Owner authorizers distinct from credential issuers');
    if (config.dbacOnly && (!config.dbac || config.trustedIssuers?.length || config.trustedAuthorizers?.length)) throw new Error('DBAC-only B must have no legacy credential or payment authorizers');
    const service = createVerifier({ identity: deserializeIdentity(config.identity), trustedIssuers: new Set(config.trustedIssuers), trustedAuthorizers: new Set(config.trustedAuthorizers), adminToken: config.adminToken, ledgerPath: config.ledgerPath, requireX402: !config.dbacOnly, dbac: config.dbac, dbacOnly: config.dbacOnly });
    const baseUrl = await service.listen(config.port);
    process.send?.({ ready: true, baseUrl, pid: process.pid });
    if (!config.dbacOnly) process.once('message', setup => {
      try {
        if (setup.stage !== 'configure-x402' || !setup.backendConfig) throw new Error('Missing x402 backend configuration');
        service.setPaymentBackend(createX402Backend(setup.backendConfig));
        process.send?.({ stage: 'x402-ready' });
      } catch (error) { process.send?.({ error: error.message }); service.close().finally(() => process.exit(1)); }
    });
    const shutdown = () => service.close().finally(() => process.exit());
    process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown); process.on('disconnect', shutdown);
  } catch (error) { process.send?.({ error: error.message }); process.exitCode = 1; process.disconnect?.(); }
});
