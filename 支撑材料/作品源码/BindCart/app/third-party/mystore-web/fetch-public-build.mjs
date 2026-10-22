import { mkdir, writeFile, copyFile } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const root = dirname(fileURLToPath(import.meta.url));
const published = resolve(root, '../../public/store/mystore');
const origin = 'https://www.mystoredemo.io/';
const queue = ['index.html', 'runtime.bundle.js', 'vendors.bundle.js', 'main.bundle.js', 'vendors.css', 'main.css'];
const seen = new Set();
const manifest = [];
const unavailable = [];

function enqueue(path) {
  if (!path || path.includes('${') || path.startsWith('data:') || path.startsWith('#') || path.startsWith('//')) return;
  if (/^https?:/.test(path)) return;
  const name = path.replace(/^\.\//, '').replace(/^\//, '').split(/[?#]/)[0];
  if (name && !name.includes('..') && !seen.has(name) && !queue.includes(name)) queue.push(name);
}

for (let idx = 0; idx < queue.length; idx++) {
  const path = queue[idx];
  if (seen.has(path)) continue;
  seen.add(path);
  const url = new URL(path === 'index.html' ? './' : path, origin).href;
  const response = await fetch(url);
  if (!response.ok) {
    if (idx < 6) throw new Error(`${response.status}: ${url}`);
    unavailable.push({ path, url, status: response.status });
    process.stdout.write(`Unavailable upstream ${path} (${response.status})\n`);
    continue;
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  await mkdir(dirname(resolve(root, path)), { recursive: true });
  await writeFile(resolve(root, path), bytes);
  await mkdir(dirname(resolve(published, path)), { recursive: true });
  await copyFile(resolve(root, path), resolve(published, path));
  manifest.push({ path, url, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), contentType: response.headers.get('content-type') });
  if (/\.(js|css|html)$/.test(path)) {
    const text = bytes.toString('utf8');
    for (const match of text.matchAll(/\b\w+\.p\+"([^"\s]+)"/g)) enqueue(match[1]);
    for (const match of text.matchAll(/url\(\s*['"]?([^)'"\s]+)['"]?\s*\)/g)) enqueue(match[1]);
    if (path.endsWith('.html')) for (const match of text.matchAll(/(?:src|href)="([^"\s]+)"/g)) enqueue(match[1]);
    for (const match of text.matchAll(/please see ([^*\s]+\.LICENSE\.txt)/g)) enqueue(match[1]);
  }
  process.stdout.write(`Saved ${path} (${bytes.length})\n`);
}

const interUrl = 'https://rsms.me/inter/inter.css';
const interResponse = await fetch(interUrl);
if (!interResponse.ok) throw new Error(`Inter CSS: ${interResponse.status}`);
const interBytes = Buffer.from(await interResponse.arrayBuffer());
const interPath = 'fonts/inter.css';
await mkdir(resolve(root, 'fonts'), { recursive: true });
await mkdir(resolve(published, 'fonts'), { recursive: true });
await writeFile(resolve(root, interPath), interBytes);
await copyFile(resolve(root, interPath), resolve(published, interPath));
manifest.push({ path: interPath, url: interUrl, bytes: interBytes.length, sha256: createHash('sha256').update(interBytes).digest('hex'), contentType: interResponse.headers.get('content-type') });
const savedFonts = new Set();
for (const match of interBytes.toString('utf8').matchAll(/url\(\s*['"]?([^)'"\s]+)['"]?\s*\)/g)) {
  const url = new URL(match[1], interUrl).href;
  if (savedFonts.has(url)) continue;
  savedFonts.add(url);
  const name = 'fonts/' + match[1].replace(/^\.\//, '').split(/[?#]/)[0];
  if (name.includes('..') || /^https?:/.test(match[1])) throw new Error(`Unexpected font path ${match[1]}`);
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Inter font: ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  await mkdir(dirname(resolve(root, name)), { recursive: true });
  await mkdir(dirname(resolve(published, name)), { recursive: true });
  await writeFile(resolve(root, name), bytes);
  await copyFile(resolve(root, name), resolve(published, name));
  manifest.push({ path: name, url, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), contentType: response.headers.get('content-type') });
  process.stdout.write(`Saved ${name} (${bytes.length})\n`);
}

const fontLicenseUrl = 'https://raw.githubusercontent.com/rsms/inter/master/LICENSE.txt';
const fontLicenseResponse = await fetch(fontLicenseUrl);
if (!fontLicenseResponse.ok) throw new Error(`Inter license: ${fontLicenseResponse.status}`);
const fontLicense = Buffer.from(await fontLicenseResponse.arrayBuffer());
await writeFile(resolve(root, 'fonts/LICENSE.txt'), fontLicense);
await copyFile(resolve(root, 'fonts/LICENSE.txt'), resolve(published, 'fonts/LICENSE.txt'));
manifest.push({ path: 'fonts/LICENSE.txt', url: fontLicenseUrl, bytes: fontLicense.length, sha256: createHash('sha256').update(fontLicense).digest('hex'), contentType: fontLicenseResponse.headers.get('content-type') });

await writeFile(resolve(root, 'SOURCE-MANIFEST.json'), JSON.stringify({ fetchedAt: new Date().toISOString(), source: origin, status: 'MyStore Demo, an online payment demonstration platform provided by Adyen, is used as a third-party demonstration and testing environment. It is not part of the core technical implementation or counted as team-developed work. Original deployed resources and separate dependency and font license notices are preserved.', originalBytesPreserved: true, files: manifest, unavailableUpstream: unavailable }, null, 2) + '\n');
await writeFile(resolve(root, 'SOURCE-NOTES.txt'), 'Source: https://www.mystoredemo.io/\nMyStore Demo is an online payment demonstration platform provided by Adyen. This project uses it as a third-party demonstration and testing environment to simulate product selection and payment flows in an e-commerce scenario. The platform serves only to present the business scenario; it is not part of the core technical implementation and is not counted as team-developed work. The project team independently designs and implements the core functionality and innovations. These files preserve the original bytes of the publicly deployed build. Source URLs and SHA-256 hashes are recorded in SOURCE-MANIFEST.json. Dependency license notices and the Inter font license are retained. Local controller adaptation and Chinese translations live outside this preserved source directory.\nThe public demo includes product list, product detail, cart, checkout, confirmation, error, and donation/collaborate routes. Adyen payment SDK calls are not a local payment backend and need a separate integration.\n');
process.stdout.write(`Complete: ${manifest.length} resources\n`);
