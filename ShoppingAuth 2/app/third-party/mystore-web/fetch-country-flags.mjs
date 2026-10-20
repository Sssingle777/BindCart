import { mkdir, readFile, writeFile, copyFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
const root = dirname(fileURLToPath(import.meta.url));
const publicPath = resolve(root, '../../public/store/mystore');
const source = await readFile(resolve(root, 'main.bundle.js'), 'utf8');
const countryList = source.match(/const it=(\[.*?\]);/)?.[1];
if (!countryList) throw new Error('Public country list not found');
const codes = [...countryList.matchAll(/id:"([A-Z]{2})"/g)].map(match => match[1].toLowerCase());
if (codes.length < 30) throw new Error('Unexpected country list');
await mkdir(resolve(root, 'flags'), { recursive: true });
await mkdir(resolve(publicPath, 'flags'), { recursive: true });
const entries = [];
let next = 0;
await Promise.all(Array.from({ length: 4 }, async () => {
  while (next < codes.length) {
    const code = codes[next++], path = `flags/${code}.svg`;
    const url = `https://ca-test.adyen.com/ca/adl/img/flags/${code}.svg`;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${response.status}: ${url}`);
    const bytes = Buffer.from(await response.arrayBuffer());
    await writeFile(resolve(root, path), bytes);
    await copyFile(resolve(root, path), resolve(publicPath, path));
    entries.push({ path, url, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), contentType: response.headers.get('content-type') });
    process.stdout.write(`Saved ${path}\n`);
  }
}));
const manifestPath = resolve(root, 'SOURCE-MANIFEST.json');
const manifest = JSON.parse((await readFile(manifestPath, 'utf8')).replace(/^\uFEFF/, ''));
manifest.files = [...manifest.files.filter(entry => !entry.path.startsWith('flags/')), ...entries].sort((a, b) => a.path.localeCompare(b.path));
await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
process.stdout.write(`Complete: ${entries.length} flags; manifest ${manifest.files.length} resources\n`);
