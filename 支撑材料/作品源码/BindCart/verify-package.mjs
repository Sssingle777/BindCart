import { access, readFile } from 'node:fs/promises';
import { constants, createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve, sep } from 'node:path';

const root = fileURLToPath(new URL('./', import.meta.url));
export async function preflight({ integrity = false } = {}) {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major < 22 || major === 22 && minor < 13) throw new Error('Node.js 22.13+ is required. Use the bundled Start script.');
  if (!((process.platform === 'win32' && process.arch === 'x64') ||
    (process.platform === 'darwin' && ['x64', 'arm64'].includes(process.arch)))) {
    throw new Error('This delivery supports Windows x64 and macOS Intel/Apple Silicon.');
  }
  await access(root, constants.W_OK);
  for (const name of ['app/launch-dual.mjs','app/public/intro.html','app/public/dual.html','app/public/mechanism.html',
    'app/third-party/mystore-web/index.html','app/public/store/mystore/main.local.bundle.js']) await access(new URL(name, import.meta.url));
  const { DatabaseSync } = await import('node:sqlite');
  const db = new DatabaseSync(':memory:'); db.exec('SELECT 1'); db.close();
  try {
    await import('./app/lib/x402-payment.mjs');
    await import('./app/lib/dbac/services.mjs');
    await import('./app/lib/storefront/native-render.mjs');
  } catch (error) {
    throw new Error(`Dependencies cannot load (${error.code ?? error.name}). Fully extract the delivery ZIP, or run npm ci in app for a source-only checkout.`, { cause: error });
  }
  let checked = 0;
  if (integrity) {
    const entries = JSON.parse(await readFile(new URL('FILE-SHA256.json', import.meta.url), 'utf8'));
    for (const entry of entries) {
      const path = resolve(root, entry.path);
      if (!path.startsWith(resolve(root) + sep)) throw new Error('Invalid integrity manifest path');
      const hash = createHash('sha256'); let bytes = 0;
      for await (const chunk of createReadStream(path)) { hash.update(chunk); bytes += chunk.length; }
      if (bytes !== entry.bytes || hash.digest('hex') !== entry.sha256) throw new Error(`File missing or modified: ${entry.path}`);
      checked++;
    }
  }
  return { ok: true, node: process.version, platform: process.platform, arch: process.arch, checkedFiles: checked };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.env.UWS_USE_FALLBACK ??= '1';
  try { console.log(JSON.stringify(await preflight({ integrity: process.argv.includes('--integrity') }), null, 2)); }
  catch (error) { console.error(`CHECK FAILED: ${error.message}`); process.exitCode = 1; }
}
