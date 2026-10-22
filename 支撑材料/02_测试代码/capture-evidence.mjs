import assert from 'node:assert/strict';
import {spawn,fork} from 'node:child_process';
import {mkdtemp, readFile, writeFile, mkdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {launchAcceptanceBrowser} from '../../作品源码/BindCart/app/scripts/lib/acceptance-browser.mjs';
const out=fileURLToPath(new URL('./ui-evidence/',import.meta.url));
const app=fileURLToPath(new URL('../../作品源码/BindCart/app/',import.meta.url));
await mkdir(out,{recursive:true});
const temp=await mkdtemp(join(tmpdir(),'shoppingauth-support-ui-'));
const runtimePath=join(temp,'runtime.json');
const child=fork(new URL('../../作品源码/BindCart/app/launch-dual.mjs',import.meta.url),[],{cwd:app,stdio:['ignore','ignore','pipe','ipc'],env:{...process.env,DUAL_PORT:'0',DUAL_STAGE_DELAY_MS:'0',DUAL_STATE_DIR:join(temp,'state'),DUAL_RUNTIME_PATH:runtimePath,UWS_USE_FALLBACK:'1'}});
let diagnostics='', browser;
child.stderr.on('data',v=>diagnostics=(diagnostics+v).slice(-2000));
try {
 let runtime;
 for(let i=0;i<600;i++){try{runtime=JSON.parse(await readFile(runtimePath));break;}catch{} if(child.exitCode!==null)throw new Error('Isolated service failed: '+diagnostics);await delay(100);}
 assert(runtime,'Isolated service readiness');
 const code=await new Promise((done,reject)=>{const p=spawn(process.execPath,['scripts/manual-mystore-dual-ui-check.mjs'],{cwd:app,stdio:'inherit',env:{...process.env,NATIVE_RUNTIME_PATH:runtimePath,MANUAL_UI_OUTPUT_PATH:join(out,'raw-browser'),MANUAL_EXPIRY_CHECK:'0'}});p.once('error',reject);p.once('exit',done);});
 assert.equal(code,0,'Existing browser acceptance script passes');
 const caps=new URLSearchParams(new URL(runtime.url).hash.slice(1));
 async function api(path,body){const r=await fetch(runtime.baseUrl+path,{method:body===undefined?'GET':'POST',headers:{'X-Demo-UI-Key':caps.get('key'),...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body)});assert.equal(r.status,200,path);return r.json();}
 browser=await launchAcceptanceBrowser({headless:true});
 const context=await browser.newContext({viewport:{width:1920,height:1080},locale:'zh-CN',deviceScaleFactor:1.5});
 const page=await context.newPage(); page.setDefaultTimeout(120000);
 await page.goto(runtime.url);
 const store=await(await page.locator('#store-frame').elementHandle()).contentFrame();
 const mechanism=await(await page.locator('#mechanism-frame').elementHandle()).contentFrame();
 await mechanism.locator('#live-connection[data-state="connected"]').waitFor();
 await store.locator('.status__message').waitFor();
 const screenshots=[];
 async function shot(locator,name){await locator.scrollIntoViewIfNeeded();await locator.screenshot({path:join(out,name)});screenshots.push(name);}
 await shot(store.locator('body'),'运行_商城支付完成.png');
 await shot(mechanism.locator('#live-receipt'),'运行_结算回执.png');
 await shot(mechanism.locator('#live-verification-details'),'测试_结算验证通过.png');
 const state=await api('/api/live/state');
 assert.equal(state.store.phase,'paid');assert.equal(state.core.ledger.executionCount,1);
 const report={payment:{phase:state.store.phase,merchantStatus:state.store.merchant.status,executionCount:state.core.ledger.executionCount,receipt:state.store.receipt},experiments:[],screenshots};
 await api('/api/store/new',{revision:state.store.revision});
 await mechanism.locator('#live-experiment-details > summary').click();
 for(const scenario of ['copied-vc','revoked']){
   const response=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/store/experiment'&&r.request().method()==='POST');
   await mechanism.locator(`[data-experiment="${scenario}"]`).click();
   const r=await response;assert.equal(r.status(),200);const result=await r.json();
   await mechanism.waitForFunction(()=>document.querySelector('#live-experiment-result')?.textContent.includes('符合预期'));
   const after=await api('/api/live/state');
   assert.equal(after.core.ledger.executionCount,1,'Security experiment must not transfer');
   report.experiments.push({scenario,result});
   await shot(mechanism.locator('#live-experiment-details'),scenario==='copied-vc'?'测试_复制凭证拒绝.png':'测试_撤销凭证拒绝.png');
 }
 // Keep public test evidence; capabilities and temporary runtime files are never exported.
 function redact(value){if(Array.isArray(value))return value.map(redact);if(value&&typeof value==='object')return Object.fromEntries(Object.entries(value).filter(([k])=>!/(?:token|privateKey|secret|ownerKey|accessKey)/i.test(k)).map(([k,v])=>[k,redact(v)]));if(typeof value==='string'){for(const token of [caps.get('key'),caps.get('ownerKey')])if(token)value=value.replaceAll(token,'[redacted]');}return value;}
 await writeFile(join(out,'public-results.json'),JSON.stringify(redact(report),null,2));
 console.log('PASS evidence screenshots: paid once, verification passed, copied and revoked credential experiments completed.');
} finally {
 await browser?.close();try{if(child.connected)child.send({action:'shutdown'});else child.kill('SIGTERM');}catch{}
 for(let i=0;i<30&&child.exitCode===null&&child.signalCode===null;i++)await delay(100);
 if(child.exitCode===null&&child.signalCode===null){try{child.kill('SIGTERM');}catch{}await delay(1000);}
 await rm(temp,{recursive:true,force:true});
}
