import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import http from 'node:http';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { extname, isAbsolute, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

// HISTORICAL PRE-2026-10-18 BASELINE: the six-role diagram was intentionally
// re-laid out as an A-centred hub. The byte/style/pixel comparisons below
// target the old geometry and are expected to differ for the current build.
// Current geometry, arrow clearance and message routing are covered by
// test/guide-scene.test.mjs.
//
// Visual preservation fixture only. The supplied public snapshot must come from
// a separately recorded integration run. This script never starts the backend,
// signs a proof, approves an order, calls payment or reads runtime credentials.
// Both pages receive the identical saved snapshot through intercepted read-only
// API requests. A passing image comparison is not a cryptographic acceptance.

const appRoot = fileURLToPath(new URL('../', import.meta.url));
const options = Object.fromEntries(process.argv.slice(2).filter(value => value.startsWith('--')).map(value => {
  const index = value.indexOf('='); return index === -1 ? [value.slice(2), true] : [value.slice(2, index), value.slice(index + 1)];
}));
const input = process.argv.slice(2).find(value => !value.startsWith('--')) || '../evidence/native-integration/paid-snapshot.json';
const snapshotPath = resolve(process.cwd(), input);
const baselineRoot = resolve(String(options.baseline || resolve(appRoot, '../../phase3-dual-live/a2a-jcardsim-x402')));
const output = resolve(String(options.output || resolve(appRoot, '../evidence/scene-preservation')));
const widths = String(options.widths || '520,900,1280').split(',').map(Number);
const fixtureKey = 'scene-visual-fixture-not-a-runtime-credential';
const sha256 = value => createHash('sha256').update(value).digest('hex');
const hosts = [], violations = [], pageErrors = [];
let browser;
const report = {
  startedAt: new Date().toISOString(),
  scope: 'strict role-diagram visual preservation only; identical recorded public snapshot supplied to both UIs',
  notCryptoAcceptance: true, notPaymentAcceptance: true,
  baselineRoot, candidateRoot: appRoot, snapshotPath,
  fixtureLabel: String(options.label || 'recorded integration snapshot'),
  viewportWidths: widths, checks: [], cases: [],
  normalization: 'Pin only #live-scene to viewport origin at its baseline natural width, and hide its siblings so surrounding content cannot show through rounded corners. Do not override inherited styles, descendants, fonts, animation rules or rendering data. Normalize scroll position before capture.',
};
const pass = (name, value = {}) => report.checks.push({ name, passed: true, ...value });
const mime = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.woff2': 'font/woff2',
};

function section(bytes, start, end) {
  const left = bytes.indexOf(start), right = bytes.indexOf(end, left + start.length);
  assert(left >= 0 && right > left, `protected source section missing: ${start}`);
  return bytes.subarray(left, right);
}

async function checkSourceProtection() {
  const originalJs = await readFile(resolve(baselineRoot, 'public/mechanism.js'));
  const candidateJs = await readFile(resolve(appRoot, 'public/mechanism.js'));
  const frozen = [
    ['renderScene', 'function renderScene()', 'function renderSummary()'],
    ['openRole', 'function openRole(', "$('live-history').addEventListener"],
  ];
  for (const [name, start, end] of frozen) {
    const original = section(originalJs, Buffer.from(start), Buffer.from(end));
    const candidate = section(candidateJs, Buffer.from(start), Buffer.from(end));
    assert(original.equals(candidate), `protected ${name} function changed`);
    pass(`${name} original bytes preserved`, { sha256: sha256(original), bytes: original.length });
  }
  const graphClick = "$('live-scene').addEventListener('click', event => { const target = event.target.closest('[data-scene-evidence]'); if (target) openRole(target.dataset.sceneEvidence); });";
  assert(originalJs.includes(Buffer.from(graphClick)) && candidateJs.includes(Buffer.from(graphClick)), 'role-diagram click interaction changed');
  pass('role-diagram click interaction original bytes preserved', { sha256: sha256(graphClick) });

  const originalCss = await readFile(resolve(baselineRoot, 'public/mechanism.css'));
  const candidateCss = await readFile(resolve(appRoot, 'public/mechanism.css'));
  assert(candidateCss.subarray(0, originalCss.length).equals(originalCss), 'original mechanism CSS prefix changed');
  const sceneRules = [...originalCss.toString('utf8').matchAll(/[^{}]*\.scene-[^{}]*\{[^{}]*\}/g)].map(match => match[0]);
  assert(sceneRules.length > 0, 'no original scene CSS rules found');
  for (const rule of sceneRules) assert(candidateCss.includes(Buffer.from(rule)), 'an original scene CSS rule changed');
  const additions = candidateCss.subarray(originalCss.length).toString('utf8');
  assert(!/\.scene-|#live-scene\b/.test(additions), 'new mechanism CSS directly targets the protected diagram');
  pass('all original scene CSS retained in exact unchanged CSS prefix', {
    originalCssSha256: sha256(originalCss), originalCssBytes: originalCss.length,
    sceneRuleCount: sceneRules.length, sceneRulesSha256: sha256(sceneRules.join('\n')),
    additionsDoNotDirectlyTargetDiagram: true,
  });

  for (const name of ['guide-scene.js', 'guide-stage.css', 'guide.css', 'tokens.css', 'platform.css']) {
    const original = await readFile(resolve(baselineRoot, 'public', name));
    const candidate = await readFile(resolve(appRoot, 'public', name));
    assert(original.equals(candidate), `shared diagram asset changed: ${name}`);
    pass(`${name} original bytes preserved`, { sha256: sha256(original), bytes: original.length });
  }
  const originalHtml = await readFile(resolve(baselineRoot, 'public/mechanism.html'));
  const candidateHtml = await readFile(resolve(appRoot, 'public/mechanism.html'));
  for (const [name, start, end] of [
    ['role dialog markup', '<dialog id="live-role-dialog"', '</dialog>'],
    ['role diagram mount', '<section id="live-scene"', '</section>'],
  ]) {
    const original = section(originalHtml, Buffer.from(start), Buffer.from(end));
    const candidate = section(candidateHtml, Buffer.from(start), Buffer.from(end));
    assert(original.equals(candidate), `protected ${name} changed`);
    pass(`${name} original bytes preserved`, { sha256: sha256(original) });
  }
}

async function staticHost(root, label) {
  const publicRoot = resolve(root, 'public');
  const server = http.createServer(async (request, response) => {
    try {
      const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname);
      if (request.method !== 'GET') {
        violations.push({ label, method: request.method, pathname, kind: 'mutation reached read-only static host' });
        response.writeHead(405); response.end(); return;
      }
      if (pathname.startsWith('/api/')) {
        violations.push({ label, method: request.method, pathname, kind: 'API escaped browser fixture interception' });
        response.writeHead(502); response.end(); return;
      }
      if (pathname === '/favicon.ico') { response.writeHead(204); response.end(); return; }
      const relative = ['/mechanism', '/mechanism/'].includes(pathname) ? '/mechanism.html' : pathname;
      const target = resolve(publicRoot, `.${relative}`);
      if (!target.startsWith(publicRoot + sep) || !(await stat(target)).isFile()) { response.writeHead(404); response.end(); return; }
      response.writeHead(200, { 'Content-Type': mime[extname(target)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
      response.end(await readFile(target));
    } catch { response.writeHead(404); response.end(); }
  });
  await new Promise((ready, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', ready); });
  const port = server.address().port;
  assert(![4381, 4382, 4383].includes(port), 'visual host must not use a business service port');
  const host = { server, label, origin: `http://127.0.0.1:${port}` };
  hosts.push(host); return host;
}

async function openFixture(host, snapshot, width) {
  const context = await browser.newContext({ viewport: { width, height: 1600 }, deviceScaleFactor: 1, locale: 'zh-CN', timezoneId: 'Asia/Shanghai', colorScheme: 'light' });
  const intercepted = [];
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== host.origin) { violations.push({ label: host.label, kind: 'external request', origin: url.origin }); await route.abort(); return; }
    if (!url.pathname.startsWith('/api/')) { await route.continue(); return; }
    intercepted.push({ method: request.method(), pathname: url.pathname });
    if (request.method() !== 'GET') {
      violations.push({ label: host.label, kind: 'unexpected UI mutation', method: request.method(), pathname: url.pathname });
      await route.fulfill({ status: 405, json: { error: { message: 'visual fixture rejects all mutations' } } }); return;
    }
    if (request.headers()['x-demo-ui-key'] !== fixtureKey) {
      violations.push({ label: host.label, kind: 'missing visual fixture access header', pathname: url.pathname });
      await route.fulfill({ status: 401, json: { error: { message: 'visual fixture header required' } } }); return;
    }
    if (url.pathname === '/api/live/state') { await route.fulfill({ status: 200, json: snapshot }); return; }
    if (url.pathname === '/api/live/events') {
      await route.fulfill({ status: 200, headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store' }, body: `: explicit visual-only snapshot fixture\n\nevent: snapshot\ndata: ${JSON.stringify(snapshot)}\n\n` }); return;
    }
    violations.push({ label: host.label, kind: 'unimplemented read-only fixture endpoint', pathname: url.pathname });
    await route.fulfill({ status: 404, json: { error: { message: 'only saved live state is available in this visual fixture' } } });
  });
  const page = await context.newPage(); page.setDefaultTimeout(10000);
  page.on('pageerror', error => pageErrors.push({ label: host.label, width, message: error.message }));
  await page.goto(`${host.origin}/mechanism/#key=${fixtureKey}`, { waitUntil: 'domcontentloaded' });
  await page.waitForFunction(() => document.querySelectorAll('#live-scene .scene-node').length === 6 && document.querySelector('#live-scene')?.dataset.html);
  await page.evaluate(() => document.fonts.ready);
  return { context, page, intercepted };
}

async function sceneMetrics(page) {
  return page.locator('#live-scene').evaluate(root => {
    const properties = ['font-family', 'font-size', 'font-weight', 'font-style', 'line-height', 'letter-spacing', 'color', 'background-color',
      'display', 'position', 'width', 'height', 'top', 'right', 'bottom', 'left', 'transform', 'box-sizing', 'opacity',
      'padding-top', 'padding-right', 'padding-bottom', 'padding-left', 'margin-top', 'margin-right', 'margin-bottom', 'margin-left',
      'border-top-width', 'border-right-width', 'border-bottom-width', 'border-left-width', 'border-top-color', 'border-radius', 'box-shadow',
      'stroke', 'stroke-width', 'fill', 'animation-name', 'animation-duration', 'text-align', 'white-space', 'overflow'];
    const nodePath = node => {
      if (node === root) return '#live-scene';
      const siblings = [...node.parentElement.children];
      return `${nodePath(node.parentElement)}/${node.tagName.toLowerCase()}:${siblings.indexOf(node)}`;
    };
    return { html: root.innerHTML, nodes: [root, ...root.querySelectorAll('*')].map(node => {
      const computed = getComputedStyle(node), rect = node.getBoundingClientRect(), origin = root.getBoundingClientRect();
      return { path: nodePath(node), tag: node.tagName.toLowerCase(), className: node.getAttribute('class') || '',
        rect: { x: rect.x - origin.x, y: rect.y - origin.y, width: rect.width, height: rect.height },
        styles: Object.fromEntries(properties.map(property => [property, computed.getPropertyValue(property)])) };
    }) };
  });
}

function styleDifferences(original, candidate) {
  const differences = [];
  if (original.nodes.length !== candidate.nodes.length) differences.push({ kind: 'element count', original: original.nodes.length, candidate: candidate.nodes.length });
  for (let index = 0; index < Math.max(original.nodes.length, candidate.nodes.length); index++) {
    const before = original.nodes[index], after = candidate.nodes[index];
    if (!before || !after) continue;
    if (before.path !== after.path || before.tag !== after.tag || before.className !== after.className) differences.push({ kind: 'element identity', index, original: before.path, candidate: after.path });
    for (const property of Object.keys(before.styles)) if (before.styles[property] !== after.styles[property]) differences.push({ kind: 'computed style', path: before.path, property, original: before.styles[property], candidate: after.styles[property] });
    for (const property of Object.keys(before.rect)) if (before.rect[property] !== after.rect[property]) differences.push({ kind: 'relative geometry', path: before.path, property, original: before.rect[property], candidate: after.rect[property] });
  }
  return differences;
}

async function comparePixels(page, original, candidate) {
  return page.evaluate(async ({ left, right }) => {
    const decode = async value => { const image = new Image(); image.src = `data:image/png;base64,${value}`; await image.decode(); const canvas = document.createElement('canvas'); canvas.width = image.width; canvas.height = image.height; const context = canvas.getContext('2d', { willReadFrequently: true }); context.drawImage(image, 0, 0); return { width: image.width, height: image.height, bytes: context.getImageData(0, 0, image.width, image.height).data }; };
    const a = await decode(left), b = await decode(right);
    if (a.width !== b.width || a.height !== b.height) return { equal: false, reason: 'image dimensions differ', original: { width: a.width, height: a.height }, candidate: { width: b.width, height: b.height } };
    const canvas = document.createElement('canvas'); canvas.width = a.width; canvas.height = a.height;
    const context = canvas.getContext('2d'), diff = context.createImageData(a.width, a.height);
    let changedPixels = 0, maximumChannelDifference = 0, totalAbsoluteChannelDifference = 0;
    for (let index = 0; index < a.bytes.length; index += 4) {
      let changed = false;
      for (let channel = 0; channel < 4; channel++) { const delta = Math.abs(a.bytes[index + channel] - b.bytes[index + channel]); if (delta) changed = true; maximumChannelDifference = Math.max(maximumChannelDifference, delta); totalAbsoluteChannelDifference += delta; }
      if (changed) changedPixels++;
      diff.data[index] = changed ? 255 : a.bytes[index]; diff.data[index + 1] = changed ? 0 : a.bytes[index + 1]; diff.data[index + 2] = changed ? 80 : a.bytes[index + 2]; diff.data[index + 3] = 255;
    }
    context.putImageData(diff, 0, 0);
    return { equal: changedPixels === 0, width: a.width, height: a.height, pixelCount: a.width * a.height, changedPixels, maximumChannelDifference, totalAbsoluteChannelDifference, differencePng: changedPixels ? canvas.toDataURL('image/png').split(',')[1] : null };
  }, { left: original.toString('base64'), right: candidate.toString('base64') });
}

async function run() {
  assert(widths.length && widths.every(width => Number.isSafeInteger(width) && width >= 320 && width <= 2400), 'widths must be comma-separated viewport widths between 320 and 2400');
  assert(isAbsolute(snapshotPath), 'snapshot path must resolve absolutely');
  const snapshotBytes = await readFile(snapshotPath), snapshot = JSON.parse(snapshotBytes);
  assert(snapshot && typeof snapshot === 'object' && snapshot.core && snapshot.store, 'snapshot must contain the actual public live snapshot envelope with core and store');
  assert(typeof snapshot.instanceId === 'string' && Number.isFinite(Date.parse(snapshot.at)), 'snapshot must retain its instance ID and capture time');
  report.snapshot = { sha256: sha256(snapshotBytes), instanceId: snapshot.instanceId, sequence: snapshot.sequence, capturedAt: snapshot.at, phase: snapshot.store.phase, orderId: snapshot.store.order?.orderId ?? null };
  await mkdir(output, { recursive: true }); await checkSourceProtection();
  const originalHost = await staticHost(baselineRoot, 'original'), candidateHost = await staticHost(appRoot, 'candidate');
  report.staticHosts = hosts.map(({ label, origin }) => ({ label, origin, readOnly: true }));
  const launchErrors = [];
  for (const channel of options.browser ? [String(options.browser)] : ['chrome', 'msedge']) {
    try { browser = await chromium.launch({ channel, headless: true }); report.browser = { channel, version: browser.version() }; break; }
    catch (error) { launchErrors.push({ channel, message: error.message }); }
  }
  assert(browser, `no available local browser: ${JSON.stringify(launchErrors)}`);
  let failed = false;
  for (const width of widths) {
    const original = await openFixture(originalHost, snapshot, width), candidate = await openFixture(candidateHost, snapshot, width);
    try {
      const beforeBox = await original.page.locator('#live-scene').boundingBox(), afterBox = await candidate.page.locator('#live-scene').boundingBox();
      assert(beforeBox && afterBox, 'diagram bounding boxes unavailable');
      const sameNaturalWidth = beforeBox.width === afterBox.width;
      const normalization = { position: 'fixed', left: '0px', top: '0px', width: `${beforeBox.width}px`, margin: '0px', zIndex: '2147483647' };
      for (const target of [original, candidate]) {
        await target.page.evaluate(() => window.scrollTo(0, 0));
        await target.page.addStyleTag({ content: '.mechanism-shell > :not(#live-scene){visibility:hidden!important}' });
        await target.page.locator('#live-scene').evaluate((root, styles) => { for (const [name, value] of Object.entries(styles)) root.style.setProperty(name.replace(/[A-Z]/g, character => `-${character.toLowerCase()}`), value, 'important'); }, normalization);
        await target.page.evaluate(() => new Promise(ready => requestAnimationFrame(() => requestAnimationFrame(ready))));
      }
      const originalMetrics = await sceneMetrics(original.page), candidateMetrics = await sceneMetrics(candidate.page);
      const computedDifferences = styleDifferences(originalMetrics, candidateMetrics);
      const originalPng = await original.page.locator('#live-scene').screenshot(), candidatePng = await candidate.page.locator('#live-scene').screenshot();
      const pixel = await comparePixels(candidate.page, originalPng, candidatePng);
      const prefix = `${width}px`;
      await writeFile(resolve(output, `${prefix}-original.png`), originalPng);
      await writeFile(resolve(output, `${prefix}-candidate.png`), candidatePng);
      if (pixel.differencePng) await writeFile(resolve(output, `${prefix}-difference.png`), Buffer.from(pixel.differencePng, 'base64'));
      delete pixel.differencePng;
      await writeFile(resolve(output, `${prefix}-computed-styles.json`), JSON.stringify({ original: originalMetrics, candidate: candidateMetrics, differences: computedDifferences }, null, 2) + '\n');
      const current = { viewportWidth: width, sameNaturalWidth, naturalBoundingBoxes: { original: beforeBox, candidate: afterBox }, normalizedBoundingBox: await candidate.page.locator('#live-scene').boundingBox(),
        graphHtmlIdentical: originalMetrics.html === candidateMetrics.html,
        originalHtmlSha256: sha256(originalMetrics.html), candidateHtmlSha256: sha256(candidateMetrics.html),
        computedStyleDifferences: computedDifferences.length, computedDifferences: computedDifferences.slice(0, 40),
        screenshots: { original: `${prefix}-original.png`, candidate: `${prefix}-candidate.png`, originalSha256: sha256(originalPng), candidateSha256: sha256(candidatePng) }, pixel,
        readOnlyApiRequests: { original: original.intercepted, candidate: candidate.intercepted } };
      current.passed = sameNaturalWidth && current.graphHtmlIdentical && computedDifferences.length === 0 && pixel.equal;
      report.cases.push(current); if (!current.passed) failed = true;
    } finally { await original.context.close(); await candidate.context.close(); }
  }
  report.violations = violations; report.pageErrors = pageErrors;
  assert.equal(violations.length, 0, 'unexpected network request or mutation in visual fixture');
  assert.equal(pageErrors.length, 0, 'page JavaScript error in visual fixture');
  pass('both read-only hosts receive the same recorded state; no application backend or payment endpoint started');
  assert(!failed, 'role diagram preservation failed; inspect per-width pixels and computed styles');
  report.status = 'passed';
}

try { await run(); }
catch (error) { report.status = 'failed'; report.error = { name: error.name, message: error.message }; process.exitCode = 1; }
finally {
  await browser?.close().catch(() => {});
  for (const { server } of hosts) { server.closeAllConnections(); await new Promise(ready => server.close(ready)); }
  report.finishedAt = new Date().toISOString();
  await mkdir(output, { recursive: true });
  await writeFile(resolve(output, 'verification.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ status: report.status, scope: report.scope, report: resolve(output, 'verification.json'), cases: report.cases.map(({ viewportWidth, passed, pixel, computedStyleDifferences }) => ({ viewportWidth, passed, changedPixels: pixel.changedPixels, computedStyleDifferences })), ...(report.error ? { error: report.error.message } : {}) }, null, 2));
}
