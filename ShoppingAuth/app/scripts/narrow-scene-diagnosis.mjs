import http from 'node:http';
import {mkdir,readFile,readdir,writeFile} from 'node:fs/promises';
import {resolve,extname} from 'node:path';
import { launchAcceptanceBrowser } from './lib/acceptance-browser.mjs';

// Static recorded-state layout diagnosis only: no live backend, keys, or payments.
const app=resolve(import.meta.dirname,'..');
const output=resolve(app,'../evidence/narrow-diagram-diagnosis');
await mkdir(output,{recursive:true});
const files=new Map();
for (const name of await readdir(resolve(app,'public'))) {
 if (!/\.(?:js|css|html)$/.test(name)) continue;
 const bytes=await readFile(resolve(app,'public',name)); files.set('/'+name,bytes);
 if (['mechanism.css','guide-stage.css','guide.css'].includes(name)) await writeFile(resolve(output,name),bytes);
}
const snapshot=JSON.parse(await readFile(resolve(app,'../evidence/full-mystore-integration/paid-snapshot.json'),'utf8'));
const report={scope:'read-only isolated layout diagnosis using recorded public state',snapshotAt:snapshot.at,cases:[],violations:[]};
const server=http.createServer((req,res)=>{
 const pathname=new URL(req.url,'http://127.0.0.1').pathname;
 if(req.method!=='GET'){report.violations.push(req.method+' '+pathname);res.writeHead(405).end();return;}
 const target=pathname==='/mechanism/'?'/mechanism.html':pathname;
 const content=files.get(target); if(!content){res.writeHead(404).end();return;}
 const type={'.html':'text/html','.css':'text/css','.js':'text/javascript'}[extname(target)];
 res.writeHead(200,{'Content-Type':type+'; charset=utf-8'}).end(content);
});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const origin='http://127.0.0.1:'+server.address().port;
const browser=await launchAcceptanceBrowser({ headless: true });
const candidateCss=`
@media(max-width:620px){
 .mechanism-page #live-scene .scene-canvas{overflow-x:auto}
 .mechanism-page #live-scene .scene-stage{display:block;width:auto;height:305px;min-height:305px}
 .mechanism-page #live-scene .scene-wires{display:block}
 .mechanism-page #live-scene .scene-node{position:absolute;left:var(--node-x);top:var(--node-y);transform:translate(-50%,-50%);width:138px;min-height:88px;grid-template-columns:20px minmax(0,1fr)}
 .mechanism-page #live-scene .scene-node-icon{grid-column:1;grid-row:1/3}
 .mechanism-page #live-scene .scene-node-title{grid-column:2;grid-row:1}
 .mechanism-page #live-scene .scene-node-role{grid-column:2;grid-row:2}
 .mechanism-page #live-scene .scene-node-status{grid-column:1/-1;grid-row:3;max-width:none;align-self:auto;margin-top:4px}
 .mechanism-page #live-scene .scene-messages-list{display:none}
}`;
try{
 for(const config of [{width:520},{width:620},{width:700},{width:900},{width:540,deviceScaleFactor:2,label:'1080-device-pixels-at-200-percent-layout-equivalent'},{width:520,fix:true,label:'520-proposed-original-geometry-natural-width'}]){
  const context=await browser.newContext({viewport:{width:config.width,height:1600},deviceScaleFactor:config.deviceScaleFactor||1});
  await context.route('**/api/**',async route=>{
   const req=route.request(), path=new URL(req.url()).pathname;
   if(req.method()!=='GET'){report.violations.push(req.method()+' '+path);await route.fulfill({status:405,body:'denied'});return;}
   if(path==='/api/live/state'){await route.fulfill({json:snapshot});return;}
   if(path==='/api/live/events'){await route.fulfill({headers:{'Content-Type':'text/event-stream'},body:'event: snapshot\ndata: '+JSON.stringify(snapshot)+'\n\n'});return;}
   report.violations.push(path);await route.fulfill({status:404,body:'not in fixture'});
  });
  const page=await context.newPage();await page.goto(origin+'/mechanism/#key=public-visual-fixture',{waitUntil:'domcontentloaded'});
  await page.waitForFunction(()=>document.querySelectorAll('.scene-node').length===6);
  if(config.fix) await page.addStyleTag({content:candidateCss});
  const metrics=await page.locator('#live-scene').evaluate(root=>{
   const box=node=>{const b=node.getBoundingClientRect();return {x:b.x,y:b.y,width:b.width,height:b.height};};
   const intersects=(a,b)=>Math.max(0,Math.min(a.x+a.width,b.x+b.width)-Math.max(a.x,b.x))*Math.max(0,Math.min(a.y+a.height,b.y+b.height)-Math.max(a.y,b.y));
   return {viewport:{innerWidth,devicePixelRatio},stageDisplay:getComputedStyle(root.querySelector('.scene-stage')).display,wiresDisplay:getComputedStyle(root.querySelector('.scene-wires')).display,wiresCount:root.querySelectorAll('.scene-wire').length,scene:box(root),canvasClientWidth:root.querySelector('.scene-canvas').clientWidth,canvasScrollWidth:root.querySelector('.scene-canvas').scrollWidth,nodes:[...root.querySelectorAll('.scene-node')].map(node=>{
    const icon=node.querySelector('.scene-node-icon'),title=node.querySelector('.scene-node-title'),role=node.querySelector('.scene-node-role'),status=node.querySelector('.scene-node-status');
    return {id:node.dataset.node,position:getComputedStyle(node).position,node:box(node),title:box(title),status:box(status),statusGridRow:getComputedStyle(status).gridRow,statusGridColumn:getComputedStyle(status).gridColumn,statusMaxWidth:getComputedStyle(status).maxWidth,iconStatusOverlap:intersects(box(icon),box(status)),roleStatusOverlap:intersects(box(role),box(status))};
   })};
  });
  const label=config.label||String(config.width);
  await page.locator('#live-scene').screenshot({path:resolve(output,label+'.png')});
  report.cases.push({config,...metrics});await context.close();
 }
 await writeFile(resolve(output,'candidate-css-only-for-review.txt'),candidateCss);
}finally{await browser.close();await new Promise(r=>server.close(r));await writeFile(resolve(output,'verification.json'),JSON.stringify(report,null,2));}
console.log(JSON.stringify({report:resolve(output,'verification.json'),cases:report.cases.map(c=>({config:c.config,wiresDisplay:c.wiresDisplay,wiresCount:c.wiresCount,stageDisplay:c.stageDisplay,overlapNodes:c.nodes.filter(n=>n.iconStatusOverlap>0).map(n=>n.id),canvasClientWidth:c.canvasClientWidth,canvasScrollWidth:c.canvasScrollWidth})),violations:report.violations},null,2));
