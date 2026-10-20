import { createEsim } from './lib/esim.mjs';

// Only public provisioning data and an access capability arrive over IPC.
// Its jCardSim JVM creates the key inside the applet; Node never receives it.
process.once('message', async (config) => {
  let service;
  try {
    service = createEsim({
      accessToken: config.accessToken, holderDid: config.holderDid,
      verifierDid: config.verifierDid, verifierUrl: config.verifierUrl,
      trustedIssuers: config.trustedIssuers, maxEntries: config.maxEntries ?? 1000,
    });
    let shuttingDown = false;
    const shutdown = () => {
      if (shuttingDown) return;
      shuttingDown = true;
      service.close().finally(() => process.exit());
    };
    process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown); process.on('disconnect', shutdown);
    const baseUrl = await service.listen(config.port ?? 0);
    process.send?.({ ready: true, baseUrl, deviceDid: service.publicInfo().deviceDid, pid: process.pid, javaPid: service.publicInfo().javaPid, backend: 'jcardsim' });
  } catch (error) {
    process.send?.({ error: error.message, code: error.code ?? 'ESIM_START_FAILED' });
    await service?.close();
    process.exitCode = 1;
    process.disconnect?.();
  }
});
