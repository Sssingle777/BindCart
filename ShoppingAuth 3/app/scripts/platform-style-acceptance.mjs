// Isolated visual/read-only platform acceptance. Capability values never enter reports.
// node scripts/platform-style-acceptance.mjs --phase before --access <private access.json>
// node scripts/platform-style-acceptance.mjs --phase after --access <private access.json> --owner-url <isolated Owner origin>
// Narrow follow-ups: --guide-only, --settings-only, --geometry-only (preserves the original screenshots).
// GET rendering fixtures are confined to separate browser contexts, visibly labelled, and never mutate a service.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
const root = fileURLToPath(new URL('..', import.meta.url));
const option = name => { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; };
const phase = option('--phase') || 'before';
const guideOnly = process.argv.includes('--guide-only');
const settingsOnly = process.argv.includes('--settings-only');
const geometryOnly = process.argv.includes('--geometry-only');
assert.ok(['before', 'after'].includes(phase));
const access = JSON.parse(await readFile(resolve(root, option('--access')), 'utf8'));
const modulePath = process.env.SCENARIO_PLAYWRIGHT_MODULE || '/Users/single/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs';
const { chromium } = await import(pathToFileURL(modulePath).href);
const output = join(root, 'docs/platform-style-acceptance');
const pictures = join(output, phase);
if(phase==='before') assert.equal(await readFile(join(output,'before.json')).then(()=>true,()=>false),false,'An existing pre-change baseline is protected; compare against it instead of overwriting it.');
await mkdir(pictures, { recursive: true });
const report = { phase, source: 'real isolated local services, fresh read-only browser context; no business actions', screenshots: [], measurements: [], checks: [], errors: [], failures: [], writes: [], fixtures: [] };
report.capturedAt = new Date().toISOString();
report.sourceHashes = Object.fromEntries(await Promise.all(['public/demo.html','public/demo.css','public/demo.js','public/platform.css','public/tokens.css','public/workspace.html','public/workspace.css','public/workspace.js','public/index.html','public/dbac.html','owner-public/index.html','owner-public/style.css','owner-public/app.js','owner-public/platform.css'].map(async file => [file, createHash('sha256').update(await readFile(join(root,file))).digest('hex')])));
const secrets = [access.uiKey, access.ownerKey].filter(Boolean);
const redact = value => secrets.reduce((text, secret) => text.split(secret).join('[private capability omitted]'), String(value));
const browser = await chromium.launch({ headless: true, channel: 'chrome' });
const contexts = [];
async function contextFor(owner = true) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
  contexts.push(context);
  await context.addInitScript(({ origin, uiKey, ownerKey }) => {
    if (location.origin !== origin) return;
    sessionStorage.setItem('a2a-did-vc-ui-key', uiKey);
    if (ownerKey) sessionStorage.setItem('a2a-owner-ui-key', ownerKey);
  }, { origin: access.baseUrl, uiKey: access.uiKey, ownerKey: owner ? access.ownerKey : null });
  const page = await context.newPage();
  page.on('pageerror', error => report.errors.push(redact(error.message)));
  page.on('response', response => { if (response.status() >= 400) report.failures.push({ path: new URL(response.url()).pathname, status: response.status() }); });
  page.on('request', request => { if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method())) report.writes.push({ method: request.method(), path: new URL(request.url()).pathname }); });
  return { context, page };
}
async function ready(page, view) {
  await page.locator(`#panel-${view}`).waitFor({ state: 'visible' });
  const frame = page.frameLocator(`#frame-${view}`);
  if (view === 'guide') await frame.locator('#guide-normal[aria-busy="false"]').waitFor({ state: 'attached' });
  else await frame.locator('body').waitFor();
  await page.waitForTimeout(650);
}
async function snapshot(page, label, width = 1440, height = 900, source = report.source) {
  await page.setViewportSize({ width, height });
  await page.evaluate(() => scrollTo(0, 0));
  for (const frame of page.frames().slice(1)) await frame.evaluate(() => scrollTo(0, 0)).catch(() => {});
  await page.waitForTimeout(180);
  for (const frame of page.frames()) {
    const body = await frame.locator('body').textContent().catch(() => '');
    assert.ok(!secrets.some(secret => body.includes(secret)), 'screenshots cannot expose private capabilities');
  }
  const measure = async frame => frame.evaluate(() => {
    const pick = selector => {
      const node = [...document.querySelectorAll(selector)].find(value => value.getClientRects().length);
      if (!node) return null;
      const box = node.getBoundingClientRect(), css = getComputedStyle(node);
      return { selector, rect: { x: box.x, y: box.y, width: box.width, height: box.height }, styles: Object.fromEntries(['padding','margin','gap','fontSize','fontWeight','lineHeight','color','backgroundColor','borderRadius','border','boxShadow','maxWidth'].map(name => [name, css[name]])) };
    };
    const ids = [...document.querySelectorAll('[id]')].map(node => node.id);
    return { viewport: { width: innerWidth, height: innerHeight, scrollWidth: document.documentElement.scrollWidth, scrollHeight: document.documentElement.scrollHeight }, duplicateIds: ids.filter((id,index) => ids.indexOf(id)!==index), presentation: document.body.dataset.presentation || null,
      topbar: pick('.workspace-topbar, .topbar'), brand: pick('.compact-brand, .brand'), topbarBrand: pick('.workspace-topbar .compact-brand'), moduleContext:pick('#shell-scenarios, #shell-module-context'), ownerCanvas:pick('.owner-access-workspace'), tools: pick('#platform-tools-toggle'), toggle: pick('#presentation-toggle'), service: pick('#service-state, #status'), content: pick('.guide-shell, .workspace-page, .page-shell, .shell, .owner-shell, main'),
      heading: pick('h1'), card: pick('.guide-step-panel, .workspace-card, .proposal, .proposal-card, .panel, .identity-card'), action: pick('#guide-main, #attack-run, #workspace-refresh, button.primary, .primary, button'), primaryAction: pick('#guide-main, #attack-run, #invoke-button, .decision-actions .primary'), context: pick('.stage-context-bar, .workspace-heading, .owner-heading, .hero, .module-heading') };
  });
  const view = await page.evaluate(() => document.body.dataset.module || 'standalone');
  const shell = await measure(page.mainFrame());
  const visibleFrame = page.frames().find(frame => frame !== page.mainFrame() && frame === page.frame({ name: `frame-${view}` }));
  const handle = await page.locator(`#frame-${view}`).count() ? await page.locator(`#frame-${view}`).elementHandle() : null;
  const frame = handle ? await handle.contentFrame() : visibleFrame;
  const inner = frame ? await measure(frame) : null;
  const file = join(pictures, `${geometryOnly?'current-':''}${label}-${width}x${height}.png`);
  if(!geometryOnly||width===1366) {
    await page.screenshot({ path: file, fullPage: true });
    report.screenshots.push({ file: relative(root, file), label, width, height, source:geometryOnly?source+'; current live data after the preserved empty-state baseline':source });
  }
  report.measurements.push({ label, view, width, height, shell, inner });
  console.log(`${geometryOnly&&width!==1366?'Measured':'Captured'} ${phase}/${label} ${width}x${height}`);
}
async function check(name, operation) {
  try { const detail = await operation(); report.checks.push({ check: name, passed: true, ...(detail ? { detail } : {}) }); }
  catch (error) { report.checks.push({ check: name, passed: false, error: redact(error.message) }); }
}
const views = ['guide', 'manage', 'attacks', 'owner', 'identity', 'diagnostic'];
async function selectView(page, view) {
  if (await page.locator('body').getAttribute('data-presentation') === 'compact' && !await page.locator('#platform-navigation').isVisible()) await page.locator('#platform-tools-toggle').click();
  if (['identity', 'diagnostic'].includes(view) && !await page.locator('.platform-tools').getAttribute('open').then(value => value !== null)) await page.locator('.platform-tools > summary').click();
  await page.locator(`[data-view="${view}"]`).click();
  await ready(page, view);
}
async function interactionChecks(page) {
  await page.setViewportSize({ width: 1440, height: 900 });
  if (await page.locator('body').getAttribute('data-presentation') !== 'compact') await page.locator('#presentation-toggle').click();
  await selectView(page, 'guide');
  await page.locator('#scenario-copied-vc').click();
  const frame = page.frameLocator('#frame-guide');
  await frame.locator('#guide-progress').filter({hasText:'合法控制组'}).waitFor();
  await page.evaluate(() => {
    window.__platformQaFrames = new Map([...document.querySelectorAll('iframe')].filter(frame => frame.src).map(frame => [frame.id, { node: frame, document: frame.contentDocument, src: frame.getAttribute('src') }]));
    window.__platformQaSrcChanges = 0;
    new MutationObserver(records => { window.__platformQaSrcChanges += records.filter(record => record.attributeName === 'src').length; }).observe(document.querySelector('.workspace-panels'), { subtree: true, attributes: true, attributeFilter: ['src'] });
  });
  const progress = await frame.locator('#guide-progress').innerText();
  await check('compact navigation, Escape and focus restoration', async () => {
    await page.locator('#platform-tools-toggle').click();
    assert.equal(await page.locator('#platform-navigation').isVisible(), true);
    assert.equal(await page.locator('#platform-tools-toggle').getAttribute('aria-expanded'), 'true');
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('#platform-navigation').isVisible(), false);
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'platform-tools-toggle');
  });
  await check('core module path preserves compact preference and existing iframe documents', async () => {
    for (const view of ['manage','attacks','owner','identity','diagnostic','guide']) {
      await selectView(page, view);
      assert.equal(await page.locator('body').getAttribute('data-presentation'), 'compact');
      assert.equal(await page.locator('#platform-navigation').isVisible(), false);
      assert.equal(await page.locator('#presentation-toggle').isVisible(), true);
    }
    assert.equal(await page.locator('#scenario-copied-vc').getAttribute('aria-pressed'), 'true');
    assert.equal(await frame.locator('#guide-progress').innerText(), progress);
    const reuse = await page.evaluate(() => ({ sameDocuments: [...window.__platformQaFrames.values()].every(({node,document,src}) => node.contentDocument === document && node.getAttribute('src') === src), srcChanges: window.__platformQaSrcChanges }));
    assert.deepEqual(reuse, { sameDocuments: true, srcChanges: 0 });
    return reuse;
  });
  await check('history backward and forward selects view while keeping compact preference', async () => {
    await page.goBack(); await ready(page, 'diagnostic');
    assert.equal(await page.locator('body').getAttribute('data-presentation'), 'compact');
    await page.goForward(); await ready(page, 'guide');
    assert.equal(await page.locator('#scenario-copied-vc').getAttribute('aria-pressed'), 'true');
  });
  await check('expanded navigation persists across all modules and refresh', async () => {
    await page.locator('#presentation-toggle').click();
    for (const view of views) {
      await selectView(page, view);
      assert.equal(await page.locator('body').getAttribute('data-presentation'), 'platform');
      assert.equal(await page.locator('#platform-navigation').isVisible(), true);
    }
    await page.reload(); await ready(page, 'diagnostic');
    assert.equal(await page.locator('body').getAttribute('data-presentation'), 'platform');
    await page.locator('#presentation-toggle').click();
    await selectView(page, 'guide');
  });
  await check('evidence and settings dialogs close with Escape and return focus', async () => {
    await page.locator('#scenario-normal').click();
    const evidence = frame.locator('[data-scene-evidence="current"]').first();
    await evidence.click();
    assert.equal(await frame.locator('#guide-evidence-dialog').isVisible(), true);
    await snapshot(page, 'guide-evidence-dialog');
    await page.keyboard.press('Escape');
    assert.equal(await frame.locator('#guide-evidence-dialog').isVisible(), false);
    assert.equal(await evidence.evaluate(node => document.activeElement === node), true);
    await frame.locator('#guide-settings-open').click();
    assert.equal(await frame.locator('#guide-settings-dialog').isVisible(), true);
    await page.keyboard.press('Escape');
    assert.equal(await frame.locator('#guide-settings-open').evaluate(node => document.activeElement === node), true);
  });
  await check('message origin/source guards and busy history deferral remain active', async () => {
    await page.evaluate(() => {
      window.dispatchEvent(new MessageEvent('message', { origin: 'https://invalid.example', source: document.querySelector('#frame-guide').contentWindow, data: { type: 'demo:navigate', view: 'owner' } }));
      window.dispatchEvent(new MessageEvent('message', { origin: location.origin, source: window, data: { type: 'demo:navigate', view: 'owner' } }));
    });
    assert.equal(await page.locator('body').getAttribute('data-module'), 'guide');
    await frame.locator('body').evaluate(() => parent.postMessage({ type: 'demo:busy', busy: true }, location.origin));
    await page.waitForFunction(() => document.querySelector('#tab-manage').disabled);
    await page.evaluate(() => { location.hash = 'view=manage'; });
    await page.waitForTimeout(100);
    assert.equal(await page.locator('body').getAttribute('data-module'), 'guide');
    await frame.locator('body').evaluate(() => parent.postMessage({ type: 'demo:busy', busy: false }, location.origin));
    await ready(page, 'manage');
  });
}
async function preferenceChecks() {
  for (const unavailable of [false, true]) await check(`${unavailable ? 'unavailable' : 'invalid'} localStorage defaults to compact with working in-memory toggle`, async () => {
    const { context, page } = await contextFor();
    await context.addInitScript(unavailable => {
      if (unavailable) Object.defineProperty(window, 'localStorage', { configurable: true, get() { throw new DOMException('Storage disabled for isolated QA', 'SecurityError'); } });
      else localStorage.setItem('a2a-demo-display', 'invalid-qa-value');
    }, unavailable);
    await page.goto(`${access.baseUrl}/#view=manage`); await ready(page, 'manage');
    assert.equal(await page.locator('body').getAttribute('data-presentation'), 'compact');
    await page.locator('#presentation-toggle').click();
    assert.equal(await page.locator('body').getAttribute('data-presentation'), 'platform');
    await selectView(page, 'attacks');
    assert.equal(await page.locator('body').getAttribute('data-presentation'), 'platform');
    await context.close();
  });
}
async function fixtureChecks() {
  const fixtureSource = 'isolated browser GET interception for rendering only; synthetic public values; no backend mutation or business validation';
  const fixtureBadge = async page => page.evaluate(() => {
    const badge = document.createElement('div'); badge.textContent = '隔离渲染夹具 · 非真实业务结果'; badge.style.cssText = 'position:fixed;right:8px;bottom:8px;z-index:99999;padding:5px 9px;border:1px solid #aaa;background:white;color:#444;font:12px sans-serif'; document.body.append(badge);
  });
  await check('management loading and network error render without false success', async () => {
    const { context, page } = await contextFor();
    let release; const gate = new Promise(resolve => { release = resolve; });
    await page.route('**/api/dbac/payment/manage?*', async route => { await gate; await route.abort('failed'); });
    await page.goto(`${access.baseUrl}/#view=manage`);
    const frame = page.frameLocator('#frame-manage');
    await frame.locator('.workspace-page[aria-busy="true"]').waitFor();
    await fixtureBadge(page); await snapshot(page, 'fixture-manage-loading',1440,900,fixtureSource);
    assert.equal(await frame.locator('#workspace-refresh').isDisabled(), true);
    release();
    await frame.locator('.workspace-page[aria-busy="false"]').waitFor();
    assert.match(await frame.locator('#manage-content').innerText(), /无法读取/);
    assert.doesNotMatch(await frame.locator('#manage-content').innerText(), /验证通过|已完成付款/);
    await snapshot(page, 'fixture-manage-network-error',1440,900,fixtureSource);
    await context.close();
  });
  await check('experiment API error clears scenes and keeps run disabled', async () => {
    const { context, page } = await contextFor();
    await page.route('**/api/dbac/payment/experiments?*', route => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ ok:false,error:{code:'QA_ISOLATED_SERVICE_ERROR',message:'隔离渲染检查：服务暂不可用'} }) }));
    await page.goto(`${access.baseUrl}/#view=attacks`); await ready(page,'attacks');
    const frame = page.frameLocator('#frame-attacks');
    assert.equal(await frame.locator('#attack-run').isDisabled(),true);
    assert.match(await frame.locator('#attack-result').innerText(),/无法读取/);
    assert.doesNotMatch(await frame.locator('#attack-result').innerText(),/符合预期|验证通过/);
    await fixtureBadge(page); await snapshot(page,'fixture-attacks-api-error',1440,900,fixtureSource);
    await context.close();
  });
  await check('Owner pending, approved and expired terms remain explicit with decisions bound to pending card', async () => {
    const { context, page } = await contextFor();
    const proposal = { id:'qa-render-proposal', status:'PENDING', profile:'dbac-payment', mode:'bbs-bls', credentialProfile:'w3c-bbs-esim-v1', credentialHash:'qa-public-evidence-hash', createdAt:'2026-10-12T00:00:00Z', expiresAt:'2099-01-01T00:00:00Z', orderKey:'qa-public-order-key', w3cIssuer:'did:example:qa-issuer',vcBindingId:'qa-public-binding', payment:{orderId:'qa-render-order',payerAccount:'demo:qa-payer',payeeAccount:'demo:qa-payee',amountMinor:2990000,currency:'TEST_USDC',settlement:{network:'eip155:31337',asset:'0x1111111111111111111111111111111111111111',payTo:'0x2222222222222222222222222222222222222222',payerAddress:'0x3333333333333333333333333333333333333333'}} };
    await page.route('**/owner/api/state', route => route.fulfill({ status:200,contentType:'application/json',body:JSON.stringify({ownerDid:'did:example:qa-owner',holderDid:'did:example:qa-holder',verifierDid:'did:example:qa-verifier',proposals:[proposal,{...proposal,id:'qa-approved-proposal',status:'APPROVED'},{...proposal,id:'qa-expired-proposal',status:'EXPIRED',expiresAt:'2020-01-01T00:00:00Z'}]}) }));
    await page.goto(`${access.baseUrl}/#view=owner`); await ready(page,'owner');
    const frame=page.frameLocator('#frame-owner'), card=frame.locator('.proposal.pending');
    assert.equal(await card.locator('.decision-actions button').count(),2);
    assert.equal(await card.locator('.decision-actions .primary').isEnabled(),true);
    for(const value of Object.values(proposal.payment.settlement)) assert.ok((await card.innerText()).includes(value), 'settlement values stay visible outside collapsed details');
    const fullAddress=card.getByText(proposal.payment.settlement.payTo,{exact:true});
    assert.equal(await fullAddress.isVisible(),true);
    const expired=frame.locator('.proposal').filter({has:frame.locator('.status-tag.expired')});
    assert.equal(await expired.locator('.decision-actions button').count(),0);
    assert.doesNotMatch(await frame.locator('.proposal').filter({has:frame.locator('.status-tag.approved')}).innerText(), /支付完成|付款完成/);
    await fixtureBadge(page);
    for (const [width,height] of [[1440,900],[390,844]]) await snapshot(page,'fixture-owner-public-proposals',width,height,fixtureSource);
    await frame.locator('.proposal.pending > details').first().locator('summary').click();
    await snapshot(page,'fixture-owner-evidence-expanded',1440,900,fixtureSource);
    await page.route('**/owner/api/state', route => route.fulfill({status:403,contentType:'application/json',body:JSON.stringify({ok:false,error:{code:'OWNER_UI_KEY_INVALID',message:'隔离渲染检查：授权权限已失效'}})}));
    await frame.locator('#refresh-button').click();
    await frame.locator('#proposals-panel[aria-busy="false"]').waitFor();
    assert.equal(await card.locator('.decision-actions .primary').isDisabled(),true);
    assert.equal(await card.locator('.decision-actions .danger').isDisabled(),true);
    assert.match(await frame.locator('#feedback-message').innerText(),/权限不可用/);
    await snapshot(page,'fixture-owner-permission-error',1440,900,fixtureSource);
    await context.close();
    report.fixtures.push({name:'Owner proposal states',source:fixtureSource,states:['PENDING','APPROVED','EXPIRED'], businessActions:0});
  });
}
async function standaloneChecks() {
  for(const [view,path] of [['owner','/owner/'],['identity','/console.html'],['diagnostic','/dbac.html']]) await check(`${view} standalone retains identity and service context`,async()=>{
    const { context,page }=await contextFor();
    await page.goto(`${access.baseUrl}${path}`); await page.waitForTimeout(800);
    assert.equal(await page.locator('.topbar').isVisible(),true);
    assert.equal(await page.locator('#connection').isVisible(),true);
    await snapshot(page,`${view}-standalone`);
    await snapshot(page,`${view}-standalone`,390,844);
    if(view==='owner') {
      const sources=await page.locator('link[rel="stylesheet"]').evaluateAll(nodes=>nodes.map(node=>new URL(node.href).pathname));
      assert.ok(sources.includes('/owner/tokens.css')&&sources.includes('/owner/platform.css'));
    }
    await context.close();
  });
  if(option('--owner-url')) await check('Owner independent service port uses local styles and current authorization role',async()=>{
    const context=await browser.newContext({viewport:{width:1440,height:900}});
    const ownerUrl=option('--owner-url');
    await context.addInitScript(({origin,key})=>{if(location.origin===origin)sessionStorage.setItem('a2a-owner-ui-key',key);},{origin:new URL(ownerUrl).origin,key:access.ownerKey});
    const page=await context.newPage();
    page.on('pageerror',error=>report.errors.push(redact(error.message)));
    const requests=[];page.on('response',response=>{if(response.request().resourceType()==='stylesheet')requests.push({url:response.url(),status:response.status()});});
    await page.goto(ownerUrl);await page.waitForTimeout(800);
    assert.match(await page.locator('#connection').innerText(),/已连接/);
    assert.ok(requests.every(request=>new URL(request.url).origin===new URL(ownerUrl).origin&&request.status===200));
    await snapshot(page,'owner-independent-service');
    await context.close();
    return {origin:new URL(ownerUrl).origin,styles:requests};
  });
}
function layoutChecks() {
  for(const measurement of report.measurements) {
    report.checks.push({check:`no horizontal overflow: ${measurement.label} ${measurement.width}x${measurement.height}`,passed:measurement.shell.viewport.scrollWidth<=measurement.shell.viewport.width+1&&(!measurement.inner||measurement.inner.viewport.scrollWidth<=measurement.inner.viewport.width+1)});
    report.checks.push({check:`unique DOM ids: ${measurement.label} ${measurement.width}x${measurement.height}`,passed:measurement.shell.duplicateIds.length===0&&(!measurement.inner||measurement.inner.duplicateIds.length===0)});
  }
  for(const mode of ['compact','platform']) for(const [width,height] of [[1920,1080],[1440,900],[1366,768],[390,844]]) {
    const group=report.measurements.filter(item=>item.width===width&&item.height===height&&views.some(view=>item.label===`${view}-${mode}`));
    const reference=group.find(item=>item.view==='guide');
    if(!reference)continue;
    for(const current of group) {
      const close=(a,b)=>Math.abs(a-b)<0.75;
      const shellMatches=['x','y','width','height'].every(key=>close(current.shell.topbar.rect[key],reference.shell.topbar.rect[key]));
      const stableItems=['brand','topbarBrand','tools','toggle','service'];
      const matchedItems=Object.fromEntries(stableItems.map(name=>[name,(!current.shell[name]&&!reference.shell[name])||Boolean(current.shell[name]&&reference.shell[name]&&['x','y','height'].every(key=>close(current.shell[name].rect[key],reference.shell[name].rect[key])))]));
      const padding=current.inner?.content?.styles.padding, referencePadding=reference.inner?.content?.styles.padding;
      const currentContent=current.inner?.content,referenceContent=reference.inner?.content;
      const contentMatches=Boolean(currentContent&&referenceContent&&padding===referencePadding&&currentContent.styles.maxWidth===referenceContent.styles.maxWidth&&['x','width'].every(key=>close(currentContent.rect[key],referenceContent.rect[key])));
      report.checks.push({check:`shell geometry and presentation: ${current.view}/${mode} ${width}x${height}`,passed:shellMatches&&Object.values(matchedItems).every(Boolean)&&contentMatches&&current.shell.presentation===mode,detail:{topbar:current.shell.topbar.rect,reference:reference.shell.topbar.rect,matchedItems,contentMatches,content:currentContent,referenceContent}});
    }
  }
}
try {
  const { page } = await contextFor();
  await page.goto(`${access.baseUrl}/#view=guide&scenario=normal`);
  await ready(page, 'guide');
  if(settingsOnly) {
    await page.setViewportSize({width:390,height:844});
    const frame=page.frameLocator('#frame-guide');
    await check('390px guide settings retain original 42px select target and Escape focus',async()=>{
      await frame.locator('#guide-settings-open').click();
      const styles=await frame.locator('#guide-settings-dialog select').evaluateAll(nodes=>nodes.map(node=>({id:node.id,minHeight:getComputedStyle(node).minHeight,height:node.getBoundingClientRect().height})));
      assert.ok(styles.length>=2&&styles.every(style=>style.minHeight==='42px'&&style.height>=42));
      await snapshot(page,'guide-settings-dialog',390,844);
      await page.keyboard.press('Escape');
      assert.equal(await frame.locator('#guide-settings-open').evaluate(node=>document.activeElement===node),true);
      return styles;
    });
  } else if(!geometryOnly) {
  for (const scenario of ['normal', 'copied-vc', 'revoked']) {
    await page.locator(`#scenario-${scenario}`).click();
    await page.waitForTimeout(250);
    for (const [width, height] of [[1920,1080],[1440,900],[1366,768],[390,844]]) await snapshot(page, `guide-${scenario}-compact`, width, height);
  }
  }
  if(!guideOnly&&!settingsOnly) {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator('#scenario-normal').click();
  for (const mode of ['compact', 'platform']) {
    await page.evaluate(mode => localStorage.setItem('a2a-demo-display', mode), mode);
    await page.goto(`${access.baseUrl}/#view=guide&scenario=normal`);
    await page.reload(); await ready(page, 'guide');
    for (const view of ['guide', 'manage', 'attacks', 'owner', 'identity', 'diagnostic']) {
      await page.evaluate(view => { location.hash = `view=${view}${view === 'guide' ? '&scenario=normal' : ''}`; }, view);
      await ready(page, view);
      if (phase === 'before') await snapshot(page, `${view}-${mode}`);
      else for (const [width, height] of [[1920,1080],[1440,900],[1366,768],[390,844]]) await snapshot(page, `${view}-${mode}`, width, height);
    }
  }
  if(!geometryOnly) {
  const missing = await contextFor(false);
  await missing.page.goto(`${access.baseUrl}/#view=owner`);
  await missing.page.locator('#owner-access').waitFor({ state: 'visible' });
  await missing.page.waitForTimeout(300);
  await snapshot(missing.page, 'owner-unloaded-compact');
  if(phase==='after') {
    await snapshot(missing.page,'owner-unloaded-compact',390,844);
    await interactionChecks(page);
    await preferenceChecks();
    await fixtureChecks();
    await standaloneChecks();
    layoutChecks();
  }
  } else {
    const missing=await contextFor(false);
    for(const mode of ['compact','platform']) {
      await missing.page.goto(`${access.baseUrl}/#view=owner`);
      await missing.page.evaluate(mode=>localStorage.setItem('a2a-demo-display',mode),mode);
      await missing.page.reload();await missing.page.locator('#owner-access').waitFor({state:'visible'});
      for(const [width,height] of [[1920,1080],[1440,900],[1366,768],[390,844]])await snapshot(missing.page,`owner-unloaded-${mode}`,width,height);
    }
    layoutChecks();
    for(const current of report.measurements.filter(item=>item.label.startsWith('owner-unloaded-'))) {
      const mode=current.label.replace('owner-unloaded-',''),reference=report.measurements.find(item=>item.width===current.width&&item.label===`guide-${mode}`);
      const canvas=current.shell.ownerCanvas,ref=reference.inner.content,close=(a,b)=>Math.abs(a-b)<0.75;
      const passed=Boolean(canvas&&canvas.styles.padding===ref.styles.padding&&canvas.styles.maxWidth===ref.styles.maxWidth&&close(canvas.rect.x,reference.shell.topbar.rect.x+ref.rect.x)&&close(canvas.rect.width,ref.rect.width)&&close(canvas.rect.y,reference.shell.topbar.rect.y+reference.shell.topbar.rect.height));
      report.checks.push({check:`Owner unloaded canvas matches guide: ${mode} ${current.width}x${current.height}`,passed,detail:{canvas,referenceContent:ref,referenceTopbar:reference.shell.topbar.rect}});
    }
  }
  }
  assert.equal(report.writes.length, 0, 'visual baseline/navigation never sends business writes');
  report.checks.push({ check: 'all scene switches, module switches, resize and preference reloads are read-only', passed: true });
  report.passed = report.errors.length === 0 && report.checks.every(item=>item.passed);
  if(!report.passed)process.exitCode=1;
} catch (error) {
  report.errors.push(redact(error.stack)); report.passed = false;
  process.exitCode = 1;
} finally {
  await writeFile(join(output, `${phase}${guideOnly?'-guide':settingsOnly?'-settings':geometryOnly?'-lowheight':''}.json`), redact(JSON.stringify(report, null, 2)) + '\n');
  await browser.close();
}
