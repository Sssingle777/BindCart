import { createOwner } from './lib/owner.mjs';

// The launcher supplies public identity/trust configuration and two separate
// capabilities. Owner generates its signing key inside this process.
process.once('message', async (config) => {
  let service;
  try {
    service = createOwner({
      holderDid: config.holderDid, verifierDid: config.verifierDid,
      trustedIssuers: config.trustedIssuers,
      proposalToken: config.proposalToken, uiToken: config.uiToken,
      maxEntries: config.maxEntries ?? 1000,
      ...(config.dbacIssuerPublicKey === undefined ? {} : { dbacIssuerPublicKey: config.dbacIssuerPublicKey }),
      ...(config.w3cIssuer === undefined ? {} : { w3cIssuer: config.w3cIssuer }),
    });
    let stopping = false;
    const shutdown = () => {
      if (stopping) return;
      stopping = true;
      service.close().finally(() => process.exit());
    };
    process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown); process.on('disconnect', shutdown);
    const baseUrl = await service.listen(config.port ?? 0);
    process.send?.({ ready: true, baseUrl, did: service.publicInfo().did, pid: process.pid });
  } catch (error) {
    process.send?.({ error: error.message, code: error.code ?? 'OWNER_START_FAILED' });
    await service?.close();
    process.exitCode = 1;
    process.disconnect?.();
  }
});
