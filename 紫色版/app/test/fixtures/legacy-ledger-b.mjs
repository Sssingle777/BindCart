// Compatibility fixture for the original local ledger tests only.
// The production agent-b.mjs always requires the x402 backend.
import { createVerifier } from '../../lib/verifier.mjs';
import { deserializeIdentity } from '../../lib/protocol.mjs';
process.once('message', async config => {
  try {
    const service = createVerifier({ ...config, identity: deserializeIdentity(config.identity), trustedIssuers: new Set(config.trustedIssuers), trustedAuthorizers: new Set(config.trustedAuthorizers) });
    const baseUrl = await service.listen(config.port);
    process.send?.({ ready: true, baseUrl, pid: process.pid });
    const close = () => service.close().finally(() => process.exit());
    process.on('SIGTERM', close); process.on('disconnect', close);
  } catch (error) { process.send?.({ error: error.message }); process.exitCode = 1; process.disconnect?.(); }
});
