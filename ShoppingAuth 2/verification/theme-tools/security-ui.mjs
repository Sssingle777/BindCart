import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {launchAcceptanceBrowser} from '../../app/scripts/lib/acceptance-browser.mjs';
const root=new URL('../../',import.meta.url);
const runtime=JSON.parse(await readFile(new URL('app/var/dual-runtime.json',root)));
const caps=new URLSearchParams(new URL(runtime.url).hash.slice(1));
const live=async()=>{const r=await fetch(runtime.baseUrl+'/api/live/state',{headers:{'X-Demo-UI-Key':caps.get('key')}});assert.equal(r.status,200);return r.json();};
const ledger=s=>({executionCount:s.core.ledger.executionCount,accounts:s.core.ledger.accounts.map(({id,balanceMinor})=>({id,balanceMinor}))});
const report={realBrowser:true,checks:[],errors:[]};
const browser=await launchAcceptanceBrowser({headless:true});
const page=await browser.newPage({viewport:{width:1366,height:768},locale:'zh-CN',reducedMotion:'reduce'});
page.setDefaultTimeout(120000);
page.on('pageerror',e=>report.errors.push(e.message));
const save=()=>writeFile(new URL('verification/security-ui.json',root),JSON.stringify(report,null,2));
try{
  const initial=await live();assert.equal(initial.store.phase,'paid');assert.equal(initial.core.ledger.executionCount,1);
  const url=new URL(runtime.url);url.pathname='/intro/';
  await page.goto(url.href);await page.locator('.hero [data-demo]').click();
  const store=page.frameLocator('#store-frame'),frame=page.frameLocator('#mechanism-frame');
  await frame.locator('#live-connection[data-state=connected]').waitFor();
  const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/store/new'&&r.request().method()==='POST');
  await store.locator('.header__link').click();
  assert.equal((await response).status(),200);
  assert.equal((await live()).store.phase,'cart');
  assert.deepEqual(ledger(await live()),ledger(initial));
  await page.goto(runtime.baseUrl+'/mechanism/');
  await page.locator('#live-connection[data-state=connected]').waitFor();
  await page.locator('#live-experiment-details>summary').click();
  for(const scenario of ['copied-vc','revoked']){
    const before=await live();
    await page.waitForFunction(s=>!document.querySelector(`[data-experiment="${s}"]`).disabled,scenario);
    const done=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/store/experiment'&&r.request().method()==='POST');
    await page.locator(`[data-experiment="${scenario}"]`).click();
    const returned=await done;assert.equal(returned.status(),200);await returned.json();
    await page.waitForFunction(()=>document.querySelector('#live-experiment-note').dataset.result==='true');
    const after=await live(), exp=after.store.experiment;
    assert.equal(exp.scenario,scenario);assert.equal(exp.expectationMet,true);
    assert.equal(exp.control.accepted,true);assert.equal(exp.requestRejected,true);
    assert.equal(exp.sideEffects.paymentExecutionDelta,0);assert.equal(exp.sideEffects.balancesUnchanged,true);
    assert.deepEqual(ledger(after),ledger(before));
    assert.match(await page.locator('#live-experiment-result').innerText(),/符合预期/);
    await page.locator('#live-experiment-details').screenshot({path:fileURLToPath(new URL(`screenshots/security-${scenario}-1366.png`,root))});
    const check={scenario,passed:true,completion:exp.completion,actual:exp.actual,rejectionStage:exp.rejectionStage,
      controlAccepted:exp.control.accepted,requestRejected:exp.requestRejected,sideEffects:exp.sideEffects};
    report.checks.push(check);
    await writeFile(new URL(`verification/security-${scenario}.json`,root),JSON.stringify(exp,null,2));
    await save(); console.log(JSON.stringify(check));
  }
  assert.deepEqual(report.errors,[]);report.status='passed';
}catch(e){report.status='failed';report.error=e.stack;process.exitCode=1;console.error(e.stack);}
finally{await save();await browser.close();}
