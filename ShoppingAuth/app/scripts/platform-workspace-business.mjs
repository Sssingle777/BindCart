// Real isolated UI acceptance for management and individual Owner approval.
// node scripts/platform-workspace-business.mjs --access <ignored private access.json>
// No business APIs are called directly; mutations below are explicit visible UI clicks.
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, join, relative } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { planPayment } from '../public/guide-model.js';
const root = fileURLToPath(new URL('..', import.meta.url));
const option = name => { const index = process.argv.indexOf(name); return index < 0 ? undefined : process.argv[index + 1]; };
assert.ok(option('--access'), 'provide the private access artifact of an isolated acceptance server');
const access = JSON.parse(await readFile(resolve(root, option('--access')), 'utf8'));
assert.match(access.baseUrl, /^http:\/\/127\.0\.0\.1:\d+$/, 'only a local acceptance server is permitted');
assert.ok(access.stateDirectory?.includes('/.runtime/scenario-stage-'), 'require the isolated scenario acceptance state directory');
const secrets = [access.uiKey, access.ownerKey].filter(Boolean);
const redact = value => secrets.reduce((text, secret) => text.split(secret).join('[private capability omitted]'), String(value));
const output = join(root, 'docs/platform-style-acceptance/workspace-business');
await mkdir(output, { recursive: true });
const report = { source:'real isolated local services and explicit browser clicks; no rendering fixtures', checks:[], screenshots:[], actions:[], requests:[], errors:[], passed:false };
const modulePath = process.env.SCENARIO_PLAYWRIGHT_MODULE || '/Users/single/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright/index.mjs';
const { chromium } = await import(pathToFileURL(modulePath).href);
const browser = await chromium.launch({ headless:true, channel:'chrome' });
const context = await browser.newContext({ viewport:{width:1440,height:900}, reducedMotion:'reduce' });
await context.grantPermissions(['clipboard-read','clipboard-write'], { origin:access.baseUrl });
await context.addInitScript(({origin,uiKey,ownerKey}) => {
  if(location.origin!==origin)return;
  sessionStorage.setItem('a2a-did-vc-ui-key',uiKey);sessionStorage.setItem('a2a-owner-ui-key',ownerKey);
}, {origin:access.baseUrl,uiKey:access.uiKey,ownerKey:access.ownerKey});
const page = await context.newPage();
page.on('pageerror', error => report.errors.push(redact(error.message)));
page.on('request', request => {
  if(request.method()!=='POST')return;
  const path=new URL(request.url()).pathname;let body;try{body=request.postDataJSON();}catch{}
  report.requests.push({path,...(path==='/api/dbac/payment/manual'||path==='/api/dbac/payment/manage'?{action:body?.action,mode:body?.mode}:{})});
});
async function api(path,owner=false){
  const response=await fetch(`${access.baseUrl}${path}`,{headers:{[owner?'X-Owner-UI-Key':'X-Demo-UI-Key']:owner?access.ownerKey:access.uiKey},cache:'no-store',signal:AbortSignal.timeout(20000)});
  assert.equal(response.status,200,`read-only ${path.split('?')[0]} status`);return response.json();
}
const read=()=>api('/api/dbac/payment/state?mode=bbs-bls');
const inventory=()=>api('/api/dbac/payment/manage?mode=bbs-bls');
async function until(check,label,timeout=45000){const end=Date.now()+timeout;while(Date.now()<end){const value=await check();if(value)return value;await delay(80);}throw Error(`Timed out: ${label}`);}
async function ready(view){
  await page.locator(`#panel-${view}`).waitFor({state:'visible'});const frame=page.frameLocator(`#frame-${view}`);
  if(view==='guide')await frame.locator('#guide-normal[aria-busy="false"]').waitFor();
  if(view==='manage')await frame.locator('.workspace-page[aria-busy="false"]').waitFor();
  if(view==='owner')await frame.locator('#proposals-panel[aria-busy="false"]').waitFor();
  return frame;
}
async function select(view){
  if(await page.locator('body').getAttribute('data-presentation')==='compact'&&!await page.locator('#platform-navigation').isVisible())await page.locator('#platform-tools-toggle').click();
  await page.locator(`[data-view="${view}"]`).click();return ready(view);
}
async function shot(label,view,{width=1440,height=900,target}={}){
  await page.setViewportSize({width,height});const frame=page.frameLocator(`#frame-${view}`);
  if(target)await frame.locator(target).scrollIntoViewIfNeeded();else await frame.locator('body').evaluate(()=>scrollTo(0,0));
  await page.waitForTimeout(100);
  for(const current of page.frames()){const text=await current.locator('body').textContent().catch(()=>'');assert.ok(!secrets.some(secret=>text.includes(secret)),'no capability in screenshot text');}
  const layout=await frame.locator('body').evaluate(()=>({viewport:innerWidth,scrollWidth:document.documentElement.scrollWidth}));
  assert.ok(layout.scrollWidth<=layout.viewport+1,`${label}: no horizontal overflow`);
  const path=join(output,`${label}-${width}x${height}.png`);await page.screenshot({path,fullPage:true});
  report.screenshots.push({file:relative(root,path),label,width,height,layout,source:report.source});
}
try{
  await page.goto(`${access.baseUrl}/#view=guide&scenario=normal`);const guide=await ready('guide');
  const initial=await read();assert.equal(Boolean(initial.credential),false,'start on the previously captured empty isolated instance');
  const originalOrder=initial.order.orderId,executions=initial.ledger.executionCount;
  assert.equal(report.requests.length,0,'opening guide has no business write');
  async function act(expected){
    const state=await read(),plan=planPayment(state,{ownerAvailable:true});assert.equal(plan.id,expected);assert.equal(plan.enabled,true,plan.reason);
    const before=report.requests.length;await guide.locator('#guide-main').click();await ready('guide');
    const result=await until(async()=>{const value=await read();return planPayment(value,{ownerAvailable:true}).id!==expected?value:null;},`explicit ${expected}`);
    assert.ok(!result.manual?.lastError,`${expected} backend returned no error`);
    report.actions.push({action:expected,stage:result.manual?.stage,orderId:result.order.orderId,requests:report.requests.slice(before)});return result;
  }
  await act('issue');const issued=await read();assert.ok(issued.credential);assert.equal(issued.ledger.executionCount,executions);
  let writes=report.requests.length;const manage=await select('manage');let assets=await inventory();
  assert.equal(report.requests.length,writes,'navigation to management does not issue/select/lock');
  const currentCredential=assets.credentials.find(item=>item.id===assets.currentCredentialId),currentDevice=assets.devices.find(item=>item.id===assets.currentDeviceId);
  assert.ok(currentCredential&&currentDevice);assert.equal(currentDevice.locked,false);
  assert.equal(await manage.locator('.certificate.current [data-manage-action="select-credential"]').isDisabled(),true);
  assert.equal(await manage.locator('.certificate.current [data-manage-action="revoke"]').isEnabled(),true);
  await shot('manage-current','manage');await shot('manage-current','manage',{width:390,height:844});await page.setViewportSize({width:1440,height:900});
  const publicDetails=manage.locator('.certificate.current .asset-public-details');await publicDetails.locator(':scope > summary').click();
  const copy=publicDetails.locator('[data-copy-value]').first(),full=await copy.getAttribute('data-copy-value');assert.ok(full.length>48);
  await copy.locator('..').locator(':scope > summary').click();await copy.click();
  assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),full,'copy preserves the complete public identifier');
  assert.ok([currentCredential.id,currentCredential.issuer,currentCredential.holderDid,currentCredential.deviceId,currentCredential.bindingId].includes(full),'copied original belongs to the actual credential');
  assert.equal(report.requests.length,writes,'disclosure and copy are read-only');
  await shot('manage-public-evidence','manage',{target:'.certificate.current .asset-public-details'});
  await manage.locator('.device-module.current [data-manage-action="lock"]').click();
  await manage.locator('.device-module.current [data-manage-action="unlock"]:enabled').waitFor();assets=await inventory();assert.equal(assets.devices.find(item=>item.id===currentDevice.id).locked,true);
  await shot('manage-device-locked','manage',{target:'.device-module.current'});
  await manage.locator('.device-module.current [data-manage-action="unlock"]').click();
  await manage.locator('.device-module.current [data-manage-action="lock"]:enabled').waitFor();assets=await inventory();assert.equal(assets.devices.find(item=>item.id===currentDevice.id).locked,false);
  assert.equal(assets.currentCredentialId,currentCredential.id);assert.equal(assets.currentDeviceId,currentDevice.id);
  report.checks.push({check:'actual current credential, complete public copy, explicit lock/unlock with no implicit selection',passed:true,credentialId:currentCredential.id,deviceId:currentDevice.id,copiedCharacters:full.length});
  writes=report.requests.length;await select('guide');assert.equal(report.requests.length,writes,'return to guide is read-only');assert.equal((await read()).order.orderId,originalOrder);
  for(const action of ['begin-proposal','device-sign','prove','verify','submit-owner'])await act(action);
  const pending=await read();assert.equal(pending.proposal.status,'PENDING');assert.equal(pending.ledger.executionCount,executions);
  writes=report.requests.length;const owner=await select('owner');await owner.locator('.proposal.pending .decision-actions .primary:enabled').waitFor();
  assert.equal(report.requests.length,writes,'opening Owner does not sign or pay');
  const proposal=(await api('/owner/api/state',true)).proposals.find(item=>item.id===pending.proposal.id);assert.ok(proposal);
  const card=owner.locator('.proposal.pending').filter({hasText:originalOrder});assert.equal(await card.count(),1);
  const rendered=await card.locator('.settlement-facts').innerText();
  for(const value of [proposal.payment.orderId,proposal.payment.currency,...Object.values(proposal.payment.settlement)])assert.ok(rendered.includes(value),'all exact key terms are visible outside disclosure panels');
  const partyText=await card.locator('.proposal-payment').innerText();assert.ok(partyText.includes(proposal.payment.payerAccount));assert.ok(partyText.includes(proposal.payment.payeeAccount));
  assert.equal(await card.locator('.decision-actions .danger').isEnabled(),true);assert.match(await owner.locator('.notice').innerText(),/不会直接执行付款/);
  await shot('owner-pending','owner');await shot('owner-actual-terms','owner',{target:'.proposal.pending .settlement-facts'});await shot('owner-explicit-decision','owner',{target:'.proposal.pending .decision-actions'});
  await shot('owner-actual-parties','owner',{width:390,height:844,target:'.proposal.pending .proposal-payment'});await shot('owner-actual-terms','owner',{width:390,height:844,target:'.proposal.pending .settlement-facts'});await shot('owner-explicit-decision','owner',{width:390,height:844,target:'.proposal.pending .decision-actions'});
  await page.setViewportSize({width:1440,height:900});await card.locator('.decision-actions .primary').click();
  const approved=await until(async()=>{const value=(await api('/owner/api/state',true)).proposals.find(item=>item.id===proposal.id);return value?.status==='APPROVED'?value:null;},'explicit single Owner approval');
  await owner.locator('.proposal.pending').waitFor({state:'hidden'});assert.equal(approved.status,'APPROVED');
  const afterApproval=await read();assert.equal(afterApproval.ledger.executionCount,executions,'approval cannot execute payment');assert.equal(afterApproval.order.orderId,originalOrder);
  await shot('owner-approved-unpaid','owner');
  writes=report.requests.length;await select('guide');const returned=await read();assert.equal(report.requests.length,writes,'returning to guide after approval does not pay or generate proof');assert.equal(returned.order.orderId,originalOrder);assert.equal(returned.ledger.executionCount,executions);
  await shot('guide-returned-same-order','guide');
  report.checks.push({check:'real Owner terms match backend, explicit one-proposal approval never executes payment, return preserves order',passed:true,orderId:originalOrder,proposalId:proposal.id,ownerStatus:approved.status,executionCountBefore:executions,executionCountAfter:returned.ledger.executionCount});
  writes=report.requests.length;const attacks=await select('attacks');await attacks.locator('#attack-scenario').selectOption('copied-vc');
  assert.equal(report.requests.length,writes,'opening and selecting security experiment never runs it');
  const experimentResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/dbac/payment/experiments'&&response.request().method()==='POST');
  await attacks.locator('#attack-run').click();const experiment=await (await experimentResponse).json();
  await attacks.locator('.workspace-page[aria-busy="false"]').waitFor();
  assert.equal(experiment.completion,'completed');assert.equal(experiment.control.accepted,true);assert.equal(experiment.requestRejected,true);assert.equal(experiment.expectationMet,true);assert.equal(experiment.actual,experiment.expected);assert.equal(experiment.sideEffects.paymentExecutionDelta,0);
  assert.match(await attacks.locator('.result-verdict').innerText(),/本次请求已被拒绝/);assert.match(await attacks.locator('.request-outcome').innerText(),/实验结果符合预期/);
  await shot('experiment-rejected-as-expected','attacks');await shot('experiment-rejected-as-expected','attacks',{width:390,height:844,target:'.result-panel'});
  await attacks.locator('[data-open-evidence]').click();assert.equal(await attacks.locator('#attack-evidence-details').getAttribute('open'),'');
  await shot('experiment-real-evidence','attacks',{width:1440,height:900,target:'#attack-evidence-details'});
  const final=await read();assert.equal(final.order.orderId,originalOrder);assert.equal(final.ledger.executionCount,executions);
  report.checks.push({check:'security workspace shows request rejection separately from expected experiment result, backed by actual control and trace',passed:true,scenarioId:experiment.scenarioId,requestRejected:experiment.requestRejected,expectationMet:experiment.expectationMet,actual:experiment.actual,expected:experiment.expected,rejectionStage:experiment.rejectionStage,controlAccepted:experiment.control.accepted,paymentExecutionDelta:experiment.sideEffects.paymentExecutionDelta});
  assert.deepEqual(report.errors,[]);report.passed=true;
}catch(error){report.errors.push(redact(error.stack||error.message));process.exitCode=1;}
finally{await writeFile(join(output,'results.json'),redact(JSON.stringify(report,null,2))+'\n');await browser.close();}
console.log(`Workspace business acceptance ${report.passed?'passed':'failed'}; ${report.screenshots.length} screenshots; ${report.checks.length} checks. See docs/platform-style-acceptance/workspace-business/results.json`);
