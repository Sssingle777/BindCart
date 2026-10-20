import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {mkdir,readFile,readdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';

// Read-only visual acceptance against actual product files. Recorded public state
// only; there is no runtime file/key access, CSS injection, or payment service.
const app=resolve(import.meta.dirname,'..');
const baseline=process.env.BASELINE_APP_PATH ? resolve(process.env.BASELINE_APP_PATH) : resolve(app,'../../phase3-dual-live/a2a-jcardsim-x402');
const output=process.env.LAYOUT_OUTPUT_PATH ? resolve(process.env.LAYOUT_OUTPUT_PATH) : resolve(app,'../evidence/backend-restore/layout');
const snapshotPath=process.env.LAYOUT_SNAPSHOT_PATH ? resolve(process.env.LAYOUT_SNAPSHOT_PATH) : resolve(app,'../evidence/full-mystore-integration/paid-snapshot.json');
await mkdir(output,{recursive:true});
const snapshotBytes=await readFile(snapshotPath),snapshot=JSON.parse(snapshotBytes);
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const report={scope:'Actual product layout with recorded public paid state; no CSS injection and no business service access',snapshot:{path:snapshotPath,sha256:hash(snapshotBytes),at:snapshot.at,sequence:snapshot.sequence},checks:[],cases:[],wideComparisons:[],violations:[],pageErrors:[],sources:{}};
const hosts=[];let browser;
const fixtureKey='isolated-layout-fixture-only';
async function host(root,label){
 const files=new Map();report.sources[label]={};
 for(const name of await readdir(resolve(root,'public'))){
  if(!/\.(?:html|css|js)$/.test(name))continue;
  const bytes=await readFile(resolve(root,'public',name));files.set('/'+name,bytes);report.sources[label][name]=hash(bytes);
 }
 const server=http.createServer((req,res)=>{
  const url=new URL(req.url,'http://127.0.0.1');
  if(req.method!=='GET'){report.violations.push({label,path:url.pathname,method:req.method});res.writeHead(405).end();return;}
  if(url.pathname==='/api/live/events'){
   if(req.headers['x-demo-ui-key']!==fixtureKey){report.violations.push({label,path:url.pathname,kind:'invalid isolated fixture key'});res.writeHead(401).end();return;}
   res.writeHead(200,{'Content-Type':'text/event-stream','Cache-Control':'no-store','Connection':'keep-alive'});res.write('event: snapshot\ndata: '+JSON.stringify(snapshot)+'\n\n');return;
  }
  if(url.pathname==='/favicon.ico'){res.writeHead(204).end();return;}
  const path=url.pathname==='/mechanism/'?'/mechanism.html':url.pathname;
  const content=files.get(path);if(!content){report.violations.push({label,path,kind:'unhandled static path'});res.writeHead(404).end();return;}
  res.writeHead(200,{'Content-Type':({'.html':'text/html','.css':'text/css','.js':'text/javascript'}[extname(path)])+'; charset=utf-8','Cache-Control':'no-store'}).end(content);
 });
 await new Promise(ready=>server.listen(0,'127.0.0.1',ready));
 const current={server,label,origin:'http://127.0.0.1:'+server.address().port};hosts.push(current);return current;
}
async function fixture(host,config){
 const context=await browser.newContext({viewport:{width:config.width,height:1800},deviceScaleFactor:config.deviceScaleFactor||1,locale:'zh-CN',timezoneId:'Asia/Shanghai',colorScheme:'light'});
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.origin!==host.origin){report.violations.push({label:host.label,path:req.url(),kind:'external request'});await route.abort();return;}
  if(!url.pathname.startsWith('/api/')){await route.continue();return;}
  if(req.method()!=='GET'){report.violations.push({label:host.label,path:url.pathname,method:req.method()});await route.fulfill({status:405,body:'fixture rejects mutations'});return;}
  assert.equal(req.headers()['x-demo-ui-key'],fixtureKey,'only isolated fixture key can be used');
  if(url.pathname==='/api/live/state'){await route.fulfill({json:snapshot});return;}
  if(url.pathname==='/api/live/events'){await route.continue();return;}
  report.violations.push({label:host.label,path:url.pathname,kind:'unhandled read-only fixture API'});await route.fulfill({status:404,json:{error:{message:'Only recorded state is available'}}});
 });
 const page=await context.newPage();page.setDefaultTimeout(15000);
 page.on('pageerror',e=>report.pageErrors.push({label:host.label,width:config.width,message:e.message}));
 await page.goto(host.origin+'/mechanism/#key='+fixtureKey,{waitUntil:'domcontentloaded'});
 await page.waitForFunction(()=>document.querySelectorAll('#live-scene .scene-node').length===6);
 await page.evaluate(()=>document.fonts.ready);
 return {context,page};
}
async function metrics(page){
 return page.evaluate(()=>{
  const root=document.querySelector('#live-scene'),canvas=root.querySelector('.scene-canvas'),stage=root.querySelector('.scene-stage'),wires=root.querySelector('.scene-wires');
  const box=node=>{const b=node.getBoundingClientRect();return {x:b.x,y:b.y,width:b.width,height:b.height,right:b.right,bottom:b.bottom};};
  const style=(node,props)=>Object.fromEntries(props.map(p=>[p,getComputedStyle(node).getPropertyValue(p)]));
  const nodes=[...root.querySelectorAll('.scene-node')].map(node=>({id:node.dataset.node,box:box(node),position:getComputedStyle(node).position,parts:Object.fromEntries(['icon','title','role','status'].map(part=>[part,box(node.querySelector('.scene-node-'+part))]))}));
  const fields=['color','background-color','border-top-width','border-top-style','border-top-color','border-radius','display','grid-template-columns','padding-top','padding-right','padding-bottom','padding-left','box-shadow','font-size'];
  return {viewport:{innerWidth,devicePixelRatio,documentWidth:document.documentElement.scrollWidth,bodyWidth:document.body.scrollWidth},header:document.querySelector('.mechanism-header h1').textContent,eyebrow:document.querySelector('.mechanism-header .mechanism-eyebrow')?.textContent,stage:{box:box(stage),display:getComputedStyle(stage).display},canvas:box(canvas),wires:{display:getComputedStyle(wires).display,box:box(wires),actualWireCount:root.querySelectorAll('.scene-wire').length,pathCount:root.querySelectorAll('.scene-wire path').length,markerCount:root.querySelectorAll('.scene-wire path[marker-end]').length},labels:[...root.querySelectorAll('.scene-wire .scene-message')].map(label=>({text:label.textContent,box:box(label),style:style(label,['display','visibility','opacity','color','font-size'])})),nodes,outer:{current:style(document.querySelector('.live-current'),fields),summary:style(document.querySelector('.live-summary-grid'),fields),fact:style(document.querySelector('.live-fact-panel'),fields)}};
 });
}
const overlap=(a,b)=>Math.max(0,Math.min(a.right,b.right)-Math.max(a.x,b.x))*Math.max(0,Math.min(a.bottom,b.bottom)-Math.max(a.y,b.y));
function assertLayout(m,config){
 assert.equal(m.stage.display,'block','role scene must preserve spatial layout');
 assert.equal(m.nodes.length,6);assert(m.nodes.every(n=>n.position==='absolute'),'six roles must use original absolute positions');
 assert.notEqual(m.wires.display,'none','arrows must remain visible');assert(m.wires.actualWireCount>0&&m.wires.pathCount>0&&m.wires.markerCount>0,'actual recorded arrow with marker must exist');
 assert(m.labels.length>0&&m.labels.every(l=>l.text.trim()&&l.style.display!=='none'&&l.style.visibility!=='hidden'&&l.box.width>0&&l.box.height>0),'recorded arrow labels must be visible');
 assert(m.viewport.documentWidth<=m.viewport.innerWidth+1,'document must not overflow horizontally');assert(m.viewport.bodyWidth<=m.viewport.innerWidth+1,'body must not overflow horizontally');
 for(const node of m.nodes){
  assert(node.box.x>=m.canvas.x-1&&node.box.right<=m.canvas.right+1,`${node.id} leaves canvas horizontally`);
  for(const part of ['icon','title','role'])assert(overlap(node.parts.status,node.parts[part])<=.1,`${node.id} status overlaps ${part}`);
 }
 for(let i=0;i<m.nodes.length;i++)for(let j=i+1;j<m.nodes.length;j++)assert(overlap(m.nodes[i].box,m.nodes[j].box)<=.1,`${m.nodes[i].id} overlaps ${m.nodes[j].id}`);
 const n=Object.fromEntries(m.nodes.map(n=>[n.id,n.box]));
 assert(n.issuer.bottom<n.holder.y&&n.device.bottom<n.verifier.y,'issuer and device must be above A and B');
 assert(n.holder.bottom<n.owner.y&&n.verifier.bottom<n.ledger.y,'A and B must be above Owner and ledger');
 assert(n.issuer.x<n.device.x&&n.holder.x<n.verifier.x&&n.owner.x<n.ledger.x,'original left/right roles must remain');
 assert.equal(m.header,'认证与支付控制台');assert.equal(m.eyebrow,'认证与支付');
 assert.equal(m.outer.current['background-color'],'rgb(255, 255, 255)');assert.equal(m.outer.current['border-top-width'],'1px');assert.equal(m.outer.current['border-top-style'],'solid');assert.equal(m.outer.current['border-radius'],'17px');
 assert.equal(m.outer.summary.display,'grid');assert.equal(m.outer.fact['background-color'],'rgb(255, 255, 255)');assert.equal(m.outer.fact['border-top-width'],'1px');
 const columns=m.outer.summary['grid-template-columns'].split(/\s+/);assert.equal(columns.length,config.width<=620?1:3,'original summary cards grid');
}
async function sceneComparable(page){
 return page.locator('#live-scene').evaluate(root=>{
  const origin=root.getBoundingClientRect();
  const props=['font-family','font-size','font-weight','font-style','line-height','letter-spacing','color','background-color','display','position','width','height','top','right','bottom','left','transform','box-sizing','opacity','padding-top','padding-right','padding-bottom','padding-left','margin-top','margin-right','margin-bottom','margin-left','border-top-width','border-right-width','border-bottom-width','border-left-width','border-top-color','border-radius','box-shadow','stroke','stroke-width','fill','animation-name','animation-duration','text-align','white-space','overflow'];
  return {html:root.innerHTML,elements:[root,...root.querySelectorAll('*')].map(node=>{const b=node.getBoundingClientRect(),s=getComputedStyle(node);return {tag:node.tagName,className:node.getAttribute('class'),geometry:{x:b.x-origin.x,y:b.y-origin.y,width:b.width,height:b.height},styles:Object.fromEntries(props.map(p=>[p,s.getPropertyValue(p)]))};})};
 });
}
try{
 const currentHost=await host(app,'current'),oldHost=await host(baseline,'old');browser=await launchAcceptanceBrowser({ headless: true });report.browser=browser.version();
 for(const config of [{width:430},{width:520},{width:540,deviceScaleFactor:2,label:'540-csspx-dsf2'},{width:620},{width:700},{width:900},{width:1280}]){
  const {context,page}=await fixture(currentHost,config);const label=config.label||String(config.width);
  try{
   const m=await metrics(page);const record={config,...m};report.cases.push(record);
   await page.locator('#live-scene').screenshot({path:resolve(output,label+'-scene.png')});
   if(config.width===520||config.width===540){
    const scene=await page.locator('#live-scene').boundingBox();await page.screenshot({path:resolve(output,label+'-header-and-scene.png'),clip:{x:0,y:0,width:config.width,height:Math.ceil(scene.y+scene.height+12)}});
   }
   assertLayout(m,config);record.passed=true;
   if([900,1280].includes(config.width)){
    const old=await fixture(oldHost,config);
    try{
     const before=await sceneComparable(old.page),after=await sceneComparable(page);const compare={width:config.width,htmlEqual:before.html===after.html,elementCount:after.elements.length,differences:[]};
     for(let i=0;i<Math.max(before.elements.length,after.elements.length);i++)if(JSON.stringify(before.elements[i])!==JSON.stringify(after.elements[i]))compare.differences.push({index:i,before:before.elements[i],after:after.elements[i]});
     await writeFile(resolve(output,label+'-old-and-current-computed.json'),JSON.stringify({before,after,differences:compare.differences},null,2));
     report.wideComparisons.push(compare);assert(compare.htmlEqual,'old graph HTML must match');assert.equal(compare.differences.length,0,'wide graph styles and relative geometry must exactly match old version');compare.passed=true;
     await old.page.locator('#live-scene').screenshot({path:resolve(output,label+'-old-scene.png')});
    }finally{await old.context.close();}
   }
  }finally{await context.close();}
 }
 assert.equal(report.violations.length,0);assert.equal(report.pageErrors.length,0);report.status='passed';
}catch(e){report.status='failed';report.error={name:e.name,message:e.message,stack:e.stack};process.exitCode=1;}
finally{
 await browser?.close();for(const {server}of hosts){server.closeAllConnections();await new Promise(r=>server.close(r));}
 report.finishedAt=new Date().toISOString();await writeFile(resolve(output,'verification.json'),JSON.stringify(report,null,2));
 console.log(JSON.stringify({status:report.status,report:resolve(output,'verification.json'),cases:report.cases.map(c=>({width:c.config.width,dsf:c.config.deviceScaleFactor||1,passed:c.passed,wiresDisplay:c.wires.display,actualWireCount:c.wires.actualWireCount,documentWidth:c.viewport.documentWidth})),wideComparisons:report.wideComparisons.map(c=>({width:c.width,passed:c.passed,differences:c.differences.length})),error:report.error?.message,violations:report.violations,pageErrors:report.pageErrors},null,2));
}
