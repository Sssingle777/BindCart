import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createNativeRenderer, nativeView } from '../lib/storefront/native-render.mjs';

const root = new URL('../', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('third-party/adyen-checkout/source.json', root), 'utf8'));
for (const item of manifest.files) {
  const bytes = await readFile(new URL(item.local, root));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), item.sha256, `${item.local}: upstream bytes changed`);
  assert.equal(createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${bytes.length}\0`), bytes])).digest('hex'), item.gitBlobSha1, `${item.local}: Git blob mismatch`);
}
const bootstrap = await readFile(new URL('public/store/bootstrap-4.3.1.min.css', root));
assert.equal(createHash('sha384').update(bootstrap).digest('base64'), 'ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T');
const render = await createNativeRenderer();
const page = render();
assert.equal(typeof page, 'string');
assert.ok(page.startsWith('<!doctype html>'), 'renderer must return the preserved application shell');
for (const copy of [
  '<html lang="zh-CN">',
  '<title>MyStore 商城</title>',
  'href="/store/mystore/fonts/inter.css"',
  'href="/store/mystore/vendors.css"',
  'href="/store/mystore/main.css"',
  'src="/store/mystore/runtime.bundle.js"',
  'src="/store/mystore/vendors.bundle.js"',
  'src="/store/app.js"',
  'src="/store/mystore/main.local.bundle.js"',
]) assert.ok(page.includes(copy), `rendered shell is missing ${copy}`);
for (const removed of [
  'checkoutshopper-live.adyen.com',
  'googletagmanager.com',
  'window.dataLayer',
  'rel="preconnect"',
  'https://rsms.me/inter/inter.css',
  'src="runtime.bundle.js"',
  'src="vendors.bundle.js"',
  'src="main.bundle.js"',
  'integration.css',
  'https://stackpath.bootstrapcdn.com',
]) assert.ok(!page.includes(removed), `removed storefront resource remains: ${removed}`);
for (const viewArgs of [
  [],
  [{ phase: 'cart' }, '/store/'],
  [{ phase: 'checkout' }, '/store/checkout'],
  [{ phase: 'paid' }, '/store/result'],
]) assert.deepEqual(nativeView(...viewArgs), ['application']);
console.log(`MyStore provenance passed: ${manifest.files.length} upstream files, exact Bootstrap SRI, original copy and guarded views.`);
