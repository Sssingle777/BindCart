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
const report = { checks: [], screenshots: [], technologyLayouts: [], errors: [], externalRequests: [], failedResources: [], realBrowser: true };
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
const technologyGeometry = () => page.locator('#technology').evaluate(section => {
  const rect = element => {
    const r = element.getBoundingClientRect();
    return { x:r.x, y:r.y, width:r.width, height:r.height, bottom:r.bottom };
  };
  const cards = [...section.querySelectorAll('.tech-card')];
  return {
    section: rect(section),
    heading: rect(section.querySelector('.technology-heading')),
    summary: rect(section.querySelector('.technology-summary')),
    cards: cards.map(rect),
    overflow: cards.flatMap(card => [...card.querySelectorAll('*')].filter(element => {
      if (element.closest('svg') || element.classList.contains('sr-only')) return false;
      const r = element.getBoundingClientRect(), box = card.getBoundingClientRect();
      return r.left < box.left - 1 || r.right > box.right + 1 || r.top < box.top - 1 || r.bottom > box.bottom + 1;
    }).map(element => element.className)),
  };
});
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
    await page.locator('.hero a[href="#technology"]').click();
    await page.waitForFunction(() => location.hash === '#technology' && Math.abs(document.querySelector('#technology').getBoundingClientRect().top - parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop)) < 2);
    const layout = await technologyGeometry();
    assert.equal(layout.cards.length,3);
    assert.equal(await page.locator('#technology .tech-visual').count(),3);
    assert.equal(await page.locator('#technology .tech-row').count(),0);
    assert.deepEqual(layout.overflow,[],`${width}: all card content stays inside its card`);
    if (width >= 1200) {
      assert(layout.heading.y >= 0 && layout.summary.bottom <= height,`${width}: entire technology chapter fits in one viewport`);
      for (const card of layout.cards) {
        assert(Math.abs(card.y-layout.cards[0].y)<1);
        assert(Math.abs(card.width-layout.cards[0].width)<1);
        assert(Math.abs(card.height-layout.cards[0].height)<1);
        assert(card.bottom<=height);
      }
      for(let i=1;i<3;i++) assert(layout.cards[i].x>layout.cards[i-1].x+layout.cards[i-1].width);
    } else {
      for(let i=1;i<3;i++) assert(layout.cards[i].y>layout.cards[i-1].bottom);
    }
    report.technologyLayouts.push({width,height,...layout});
    await shot(`technology-${width}.png`);
    if(width<1200) {
      const name=`technology-${width}-full.png`;
      await page.locator('#technology').screenshot({path:resolve(output,name)});
      report.screenshots.push(name);
    }
  }
  pass('Three equal desktop cards, original diagrams and chapter summary fit in one screen at 1920×1080, 1440×900 and 1366×768; mobile cards stack without content overflow');
  for (const width of [320,768,1024]) {
    await page.setViewportSize({width,height:900});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    const layout=await technologyGeometry();
    assert.deepEqual(layout.overflow,[],`${width}: narrow-screen content is not clipped`);
  }
  pass('Narrow mobile and tablet layouts at 320, 768 and 1024 pixels have no horizontal or card-content overflow');
  for (const [width,height] of [[1366,768],[390,844]]) {
    await page.setViewportSize({width,height});
    for (const trigger of await page.locator('[data-tech-detail]').all()) {
      await trigger.scrollIntoViewIfNeeded();
      const before=await technologyGeometry();
      await trigger.click();
      const dialog=page.locator('.tech-dialog[open]');
      assert.equal(await dialog.count(),1);
      assert(await dialog.locator('.tech-detail-copy .tech-note').isVisible());
      assert(await dialog.evaluate(el=>el.contains(document.activeElement)));
      await page.keyboard.press('Tab');
      // A native dialog may hand focus to browser chrome before wrapping.
      // It must never focus another control in the inert document underneath.
      assert(await dialog.evaluate(el=>el.matches(':modal') && (el.contains(document.activeElement) || document.activeElement===document.body)));
      if(await page.evaluate(()=>document.activeElement===document.body)) {
        await page.keyboard.press('Tab');
        assert(await dialog.evaluate(el=>el.contains(document.activeElement)));
      }
      const box=await dialog.boundingBox();
      assert(box.x>=0 && box.y>=0 && box.x+box.width<=width && box.y+box.height<=height);
      assert.deepEqual((await technologyGeometry()).cards,before.cards,'Opening details must not resize or move the cards');
      if((await trigger.getAttribute('data-tech-detail'))==='tech-binding-detail') await shot(`technology-details-${width}.png`);
      await page.keyboard.press('Escape');
      assert.equal(await page.locator('.tech-dialog[open]').count(),0);
      assert(await trigger.evaluate(el=>el===document.activeElement));
      await trigger.click();
      await page.locator('.tech-dialog[open] .tech-dialog-close').click();
      assert.equal(await page.locator('.tech-dialog[open]').count(),0);
    }
  }
  pass('All three principle dialogs preserve card geometry, contain keyboard focus, close with Escape or the close button and restore focus on desktop and mobile');
  await page.setViewportSize({width:1440,height:900});
  await page.locator('nav a[href="#approach"]').click();
  await page.waitForFunction(() => location.hash === '#approach' && Math.abs(document.querySelector('#approach').getBoundingClientRect().top - 40) < 2);
  await page.reload(); assert(page.url().endsWith('#approach'));
  await page.locator('nav a[href="#technology"]').click();
  await page.waitForFunction(() => location.hash === '#technology' && Math.abs(document.querySelector('#technology').getBoundingClientRect().top - 40) < 2);
  await page.reload();
  await page.waitForFunction(() => Math.abs(document.querySelector('#technology').getBoundingClientRect().top - 40) < 2);
  await page.goBack();
  await page.waitForFunction(() => location.hash === '#approach');
  await page.goForward();
  await page.waitForFunction(() => location.hash === '#technology');
  await page.locator('#demo').scrollIntoViewIfNeeded();
  assert(await page.locator('#demo-title').isVisible());
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
  pass(baseline
    ? 'Both desktop sizes support side/stack/fullscreen; actual six-role positions and dimensions match original CSS'
    : 'Both desktop sizes support side/stack/fullscreen with all six roles rendered');
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
