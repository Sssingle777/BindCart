import assert from 'node:assert/strict';
import {fork} from 'node:child_process';
import {mkdtemp, readFile, writeFile, mkdir, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {setTimeout as delay} from 'node:timers/promises';
import {launchAcceptanceBrowser} from '../../作品源码/BindCart/app/scripts/lib/acceptance-browser.mjs';
const out=fileURLToPath(new URL('./normal-evidence/',import.meta.url));await mkdir(out,{recursive:true});
const app=fileURLToPath(new URL('../../作品源码/BindCart/app/',import.meta.url));
const temp=await mkdtemp(join(tmpdir(),'shoppingauth-normal-shot-'));const runtimePath=join(temp,'runtime.json');
const child=fork(new URL('../../作品源码/BindCart/app/launch-dual.mjs',import.meta.url),[],{cwd:app,stdio:['ignore','ignore','pipe','ipc'],env:{...process.env,DUAL_PORT:'0',DUAL_STAGE_DELAY_MS:'0',DUAL_STATE_DIR:join(temp,'state'),DUAL_RUNTIME_PATH:runtimePath,UWS_USE_FALLBACK:'1'}});
let browser;
try{
 let runtime;for(let i=0;i<600;i++){try{runtime=JSON.parse(await readFile(runtimePath));break;}catch{}assert.equal(child.exitCode,null);await delay(100);}assert(runtime);
 const caps=new URLSearchParams(new URL(runtime.url).hash.slice(1));
 async function api(path,body,owner=false){const r=await fetch(runtime.baseUrl+path,{method:body===undefined?'GET':'POST',headers:{'X-Demo-UI-Key':caps.get('key'),...(owner?{'X-Owner-UI-Key':caps.get('ownerKey')} :{}),...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body)});assert.equal(r.status,200,path);return r.json();}
 const live=()=>api('/api/live/state');
 browser=await launchAcceptanceBrowser({headless:true});const page=await browser.newPage({viewport:{width:1280,height:1500},deviceScaleFactor:1.5,locale:'zh-CN'});
 await page.goto(runtime.baseUrl+'/store/#'+new URLSearchParams({key:caps.get('key'),ownerKey:caps.get('ownerKey')}));
 await page.locator('.products__list__list-item').nth(8).waitFor();
 await page.locator('main').screenshot({path:join(out,'运行_商品目录.png')});
 let s=await live();const catalog=await api('/api/store/catalog');
 await api('/api/store/cart',{productId:catalog.products[0].id,quantity:1,revision:s.store.revision});
 await api('/api/store/checkout',{revision:(await live()).store.revision});
 async function step(action){s=await live();return api('/api/store/manual',{action,orderId:s.store.order.orderId,revision:s.store.revision,attemptId:s.core.manual.attemptId,controlToken:s.store.manualControl.token});}
 for(const action of ['issue','begin-proposal','derive-vc','device-sign','prove','verify','submit-owner'])await step(action);
 s=await live();const proposal=s.core.proposal;
 await api(`/owner/api/proposals/${proposal.id}/approve`,{confirmed:true,payment:proposal.payment,credentialHash:proposal.credentialHash},true);
 s=await live();await api('/api/store/pay',{orderId:s.store.order.orderId,revision:s.store.revision});
 for(let i=0;i<30;i++){s=await live();if(s.store.phase==='paid')break;assert(s.store.manualControl.nextAction);await step(s.store.manualControl.nextAction);}
 s=await live();assert.equal(s.store.phase,'paid');assert.equal(s.core.ledger.executionCount,1);
 await page.goto(runtime.baseUrl+'/mechanism/#'+new URLSearchParams({key:caps.get('key')}));
 await page.locator('#live-connection[data-state="connected"]').waitFor();
 const verification=page.locator('#live-verification-details');
 await page.waitForFunction(()=>document.querySelector('#live-proof-status')?.textContent.includes('通过'));
 await verification.evaluate(el=>el.scrollIntoView({block:'start'}));
 const box=await verification.boundingBox();
 // Capture only the visible verification results. The existing application leaves
 // a large trailing blank area in this details element; no DOM content is changed.
 const height=950;
 await page.screenshot({path:join(out,'测试_结算验证通过.png'),clip:{x:box.x,y:Math.max(0,box.y),width:box.width,height}});
 await writeFile(join(out,'public-results.json'),JSON.stringify({phase:s.store.phase,executionCount:s.core.ledger.executionCount,transactionHash:s.store.receipt.transactionHash,verificationTrace:s.core.manual.verificationResult.verificationTrace,screenshotBounds:box},null,2));
 console.log('PASS normal payment proof and catalog captured from standalone application pages.');
}finally{await browser?.close();try{if(child.connected)child.send({action:'shutdown'});else child.kill('SIGTERM');}catch{}for(let i=0;i<30&&child.exitCode===null&&child.signalCode===null;i++)await delay(100);if(child.exitCode===null&&child.signalCode===null){try{child.kill('SIGTERM');}catch{}await delay(1000);}await rm(temp,{recursive:true,force:true});}
