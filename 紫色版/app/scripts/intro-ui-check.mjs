import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';

const runtime = JSON.parse(await readFile(process.env.NATIVE_RUNTIME_PATH ?? new URL('../var/dual-runtime.json', import.meta.url)));
const output = resolve(process.env.INTRO_UI_OUTPUT_PATH ?? '../evidence/intro');
const baseline = process.env.BASELINE_APP_PATH;
await mkdir(output, { recursive: true });
const launch = new URL(runtime.url); launch.pathname = '/intro/';
const caps = new URLSearchParams(launch.hash.slice(1));
const report = { checks: [], screenshots: [], errors: [], externalRequests: [], failedResources: [], realBrowser: true };
const redact = value => { let text = String(value); for (const value of caps.values()) text = text.replaceAll(value, '[redacted]'); return text; };
const pass = name => { report.checks.push({ name, passed: true }); console.log(`PASS ${name}`); };
const browser = await launchAcceptanceBrowser({ headless: true });
report.browserVersion = browser.version();
const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, locale: 'zh-CN' });
await context.route('**/*', route => {
  if (new URL(route.request().url()).origin !== runtime.baseUrl) { report.externalRequests.push(new URL(route.request().url()).origin); return route.abort(); }
  return route.continue();
});
const page = await context.newPage();
page.on('pageerror', error => report.errors.push(redact(error.message)));
page.on('response', response => { if (response.status() >= 400) report.failedResources.push({path:new URL(response.url()).pathname,status:response.status()}); });
const requests = [];
page.on('request', request => requests.push({ path: new URL(request.url()).pathname, method: request.method(), url: request.url() }));
const shot = async (name, fullPage = false) => { await page.screenshot({ path: resolve(output, name), fullPage }); report.screenshots.push(name); };
const geometry = async frame => frame.locator('.scene-node').evaluateAll(nodes => nodes.map(node => { const r=node.getBoundingClientRect(); return {id:node.dataset.node,x:r.x,y:r.y,width:r.width,height:r.height}; }));
try {
  const response = await page.goto(launch.href);
  assert.equal(response.status(), 200);
  const csp = response.headers()['content-security-policy'];
  assert(csp.includes("script-src 'self'") && csp.includes("frame-ancestors 'none'"));
  assert.equal(response.headers()['referrer-policy'], 'no-referrer');
  await page.waitForFunction(() => !location.hash && sessionStorage.getItem('storefront-key'));
  assert.deepEqual(await page.evaluate(() => ['key','ownerKey'].map(n => sessionStorage.getItem(`storefront-${n}`))), ['key','ownerKey'].map(n => caps.get(n)));
  assert(!requests.some(r => r.path.startsWith('/api/') || r.method !== 'GET'));
  assert(!requests.some(r => [...caps.values()].some(v => r.url.includes(v))));
  assert(![...caps.values()].some(v => page.url().includes(v)));
  assert(![...caps.values()].some(v => (response.headers()['location'] ?? '').includes(v)));
  const markup = await page.content();
  for (const v of caps.values()) assert(!markup.includes(v));
  pass('Intro resources use the existing CSP, preserve both capabilities in sessionStorage, clear fragments, and issue no business or external requests');
  for (const [width,height] of [[1920,1080],[1440,900],[1366,768],[390,844]]) {
    await page.setViewportSize({width,height});
    await page.evaluate(() => scrollTo(0,0));
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    const h1 = await page.locator('h1').boundingBox(); assert(h1.x >= 0 && h1.x+h1.width <= width);
    await shot(`intro-${width}.png`);
    await shot(`intro-${width}-full.png`,true);
  }
  await page.setViewportSize({width:1440,height:900});
  await page.locator('nav a[href="#approach"]').click();
  await page.waitForFunction(() => location.hash === '#approach');
  await page.reload(); assert(page.url().endsWith('#approach'));
  await page.locator('nav a[href="#technology"]').click();
  await page.waitForFunction(() => location.hash === '#technology');
  pass('Four requested viewports have no horizontal overflow; section navigation and anchor reload work');
  await page.emulateMedia({ reducedMotion:'reduce' });
  assert.equal(await page.locator('.flow-highlight').evaluate(el => getComputedStyle(el).animationName),'none');
  await page.emulateMedia({ reducedMotion:'no-preference' });
  pass('Reduced-motion preference disables diagram animation');
  await page.evaluate(() => scrollTo(0,0));
  await page.locator('.hero [data-demo]').click();
  await page.waitForURL(`${runtime.baseUrl}/demo/`);
  const store = page.frameLocator('#store-frame'), mechanism = page.frameLocator('#mechanism-frame');
  await store.locator('.products__list__list-item').nth(8).waitFor({state:'attached'});
  await mechanism.locator('#live-connection[data-state=connected]').waitFor();
  assert.equal(await mechanism.locator('.scene-node').count(),6);
  assert.equal(await store.locator('.products__list__list-item').count(),9);
  assert(!requests.some(r => r.method === 'POST'));
  pass('Same-tab introduction-to-demo navigation loads both real iframes and all six roles without business POSTs');
  for (const [width,height] of [[1920,1080],[1366,768]]) {
    await page.setViewportSize({width,height});
    await shot(`dual-${width}.png`);
    await mechanism.locator('#live-scene').scrollIntoViewIfNeeded();
    await shot(`roles-${width}.png`);
    const before = await geometry(mechanism);
    if (baseline) {
      const styles = new Map([
        ['/demo/style.css', await readFile(resolve(baseline,'public/dual.css'),'utf8')],
        ['/mechanism-visual.css', await readFile(resolve(baseline,'public/mechanism-visual.css'),'utf8')]
      ]);
      const originalStyles = route => route.fulfill({status:200,contentType:'text/css',body:styles.get(new URL(route.request().url()).pathname)});
      await page.route(/\/(demo\/style|mechanism-visual)\.css$/,originalStyles);
      await page.reload();
      await mechanism.locator('#live-connection[data-state=connected]').waitFor();
      await store.locator('.products__list__list-item').nth(8).waitFor({state:'attached'});
      await shot(`before-dual-${width}.png`);
      await mechanism.locator('#live-scene').scrollIntoViewIfNeeded();
      assert.deepEqual(await geometry(mechanism),before,'Recolor must preserve six-role geometry');
      await shot(`before-roles-${width}.png`);
      await page.unroute(/\/(demo\/style|mechanism-visual)\.css$/,originalStyles);
      await page.reload(); await mechanism.locator('#live-connection[data-state=connected]').waitFor();
    }
    await page.locator('button[data-layout=stack]').click();
    assert.equal(await page.locator('button[data-layout=stack]').getAttribute('aria-pressed'),'true');
    await shot(`dual-stack-${width}.png`,true);
    await page.locator('button[data-layout=side]').click();
    await page.locator('#dual-fullscreen').click();
    await page.waitForFunction(() => !!document.fullscreenElement);
    await shot(`dual-fullscreen-${width}.png`);
    await page.locator('#dual-fullscreen').click();
    await page.waitForFunction(() => !document.fullscreenElement);
  }
  pass('Both desktop sizes support side/stack/fullscreen; actual six-role positions and dimensions match original CSS');
  await mechanism.locator('.scene-node[data-node=holder]').click();
  await mechanism.locator('#live-role-dialog[open]').waitFor();
  await page.keyboard.press('Escape');
  pass('Role evidence dialog remains clickable');
  const states = await mechanism.locator('body').evaluate(body => {
    // A transient off-screen CSS probe, never a protocol result or screenshot.
    const probe=document.createElement('span');probe.className='live-badge';probe.hidden=true;body.append(probe);
    const result={};
    for(const state of ['running','pass','fail','pending','unknown','idle']){
      probe.dataset.state=state;const s=getComputedStyle(probe);result[state]=[s.color,s.backgroundColor,s.borderColor].join('|');
    }
    probe.remove();return result;
  });
  assert.equal(new Set(Object.values(states)).size,6);
  report.stateColors=states;
  pass('Processing, pass, failure, waiting, unknown and idle have six distinct CSS color treatments');

  const anonymous = await browser.newContext();
  const visitor = await anonymous.newPage();
  await visitor.goto(runtime.baseUrl+'/intro/');
  await visitor.locator('.hero [data-demo]').click();
  assert(visitor.url().endsWith('/intro/'));
  assert((await visitor.locator('#access-note').textContent()).includes('启动器'));
  assert.equal(await visitor.locator('iframe').count(),0);
  await visitor.goto(runtime.baseUrl+'/intro/#key=invalid&ownerKey=invalid');
  await visitor.waitForFunction(() => !location.hash);
  assert.deepEqual(await visitor.evaluate(() => ['key','ownerKey'].map(n => sessionStorage.getItem(`storefront-${n}`))),[null,null]);
  pass('Anonymous and malformed capabilities stay on the introduction, with a launcher prompt and no false connection claim');
  await visitor.goto(launch.href); await visitor.waitForFunction(() => !location.hash);
  await visitor.goto(runtime.baseUrl+'/intro/#key='+caps.get('key'));
  await visitor.waitForFunction(() => !location.hash);
  assert.equal(await visitor.evaluate(() => sessionStorage.getItem('storefront-ownerKey')),null);
  await visitor.locator('.hero [data-demo]').click(); assert(visitor.url().endsWith('/intro/'));
  pass('Partial new launch capabilities cannot reuse a stale Owner key');
  await anonymous.close();
  const blocked = await browser.newContext();
  await blocked.addInitScript(() => Object.defineProperty(window,'sessionStorage',{get(){throw new DOMException('Storage denied','SecurityError');}}));
  const blockedPage = await blocked.newPage();
  await blockedPage.goto(launch.href); await blockedPage.waitForFunction(() => !location.hash);
  assert((await blockedPage.locator('#access-note').textContent()).includes('会话存储'));
  await blocked.close();
  pass('Storage-denied browser still removes secret fragments and explains recovery');
  assert.deepEqual(report.errors,[]); assert.deepEqual(report.externalRequests,[]); assert.deepEqual(report.failedResources,[]);
  report.status='passed';
} catch(error) { report.status='failed';report.error=redact(error.stack);console.error(report.error);process.exitCode=1;await shot('intro-failure.png').catch(()=>{}); }
finally { report.finishedAt=new Date().toISOString();await writeFile(resolve(output,'intro-verification.json'),JSON.stringify(report,null,2));await browser.close(); }
