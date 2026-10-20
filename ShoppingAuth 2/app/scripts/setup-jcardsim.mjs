import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile, writeFile, mkdir, rename, symlink } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const runtime = path.join(root, '.runtime');
const vendor = path.join(root, 'vendor', 'jcardsim');
const exec = promisify(execFile);
const sha256 = data => createHash('sha256').update(data).digest('hex');
const jdk = {
  vendor: 'Eclipse Adoptium Temurin', version: '21.0.12.1+1', platform: 'macOS-aarch64',
  url: 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.12.1_1.tar.gz',
  sha256: '3623232f33a9c3baadf304480b2535f9a3cba8a58d42ecbb438ba267315d9998',
  javaHome: 'jdk/Contents/Home', license: 'GPL-2.0-with-Classpath-exception; see jdk/Contents/Home/legal',
};
async function ensureFile(file, url, expectedHash) {
  if (existsSync(file)) {
    if (sha256(await readFile(file)) !== expectedHash) throw new Error(`Existing file hash mismatch: ${file}`);
    return;
  }
  console.log(`Download ${path.basename(file)}`);
  const response = await fetch(url, { signal: AbortSignal.timeout(180000) });
  if (!response.ok) throw new Error(`Download failed (${response.status}): ${url}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  if (sha256(bytes) !== expectedHash) throw new Error(`Downloaded file hash mismatch: ${url}`);
  await writeFile(`${file}.part`, bytes);
  await rename(`${file}.part`, file);
}
await mkdir(runtime, { recursive: true });
const manifest = JSON.parse(await readFile(path.join(vendor, 'manifest.json'), 'utf8'));
for (const artifact of manifest.artifacts) {
  if (path.basename(artifact.file) !== artifact.file) throw new Error('Unsafe dependency manifest path');
  await ensureFile(path.join(vendor, artifact.file), artifact.source, artifact.sha256);
}
if (!process.env.JCARD_JAVA_HOME && !existsSync(path.join(runtime, jdk.javaHome, 'bin', 'java'))) {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') {
    throw new Error('This pinned JDK bundle targets macOS Apple Silicon. Set JCARD_JAVA_HOME to an installed JDK 11+ on this platform; no global Java settings are changed.');
  }
  const archive = path.join(runtime, 'temurin-21.0.12.1-macos-aarch64.tar.gz');
  await ensureFile(archive, jdk.url, jdk.sha256);
  const output = path.join(runtime, 'temurin');
  await mkdir(output, { recursive: true });
  // A checksum-pinned official distribution; never evaluate downloaded code here.
  await exec('tar', ['-xzf', archive, '-C', output]);
  if (!existsSync(path.join(runtime, 'jdk'))) await symlink('temurin/jdk-21.0.12.1+1', path.join(runtime, 'jdk'), 'dir');
  await writeFile(path.join(runtime, 'jdk-source.json'), `${JSON.stringify(jdk, null, 2)}\n`);
}
const { buildJCardSim } = await import('../lib/jcardsim.mjs');
const result = await buildJCardSim();
console.log(`JCARD_BUILD_OK ${result.buildHash}`);
console.log('Run: node scripts/jcardsim-selftest.mjs');
