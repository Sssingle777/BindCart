import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { launchAcceptanceBrowser } from '../../app/scripts/lib/acceptance-browser.mjs';
const root=new URL('../../',import.meta.url);
const runtime=JSON.parse(await readFile(new URL('app/var/dual-runtime.json',root)));
const browser=await launchAcceptanceBrowser({headless:true});
const page=await browser.newPage({viewport:{width:1920,height:1080},locale:'zh-CN',reducedMotion:'reduce'});
const report={realBrowser:true,viewports:[],contrast:[],errors:[]};
page.on('pageerror',e=>report.errors.push(e.message));
const shot=async name=>page.screenshot({path:fileURLToPath(new URL(`screenshots/${name}.png`,root))});
async function contrast(label){
  const result=await page.evaluate(()=>{
    const rgb=s=>{
      const values=s.match(/[\d.]+/g)?.map(Number);
      if(s.startsWith('color(srgb '))return values.map((v,i)=>i<3?v*255:v);
      if(!s.startsWith('rgb'))throw new Error(`Unsupported computed color: ${s}`);
      return values;
    };
    const blend=(fg,bg)=>fg.slice(0,3).map((v,i)=>v*(fg[3]??1)+bg[i]*(1-(fg[3]??1)));
    const lum=c=>c.map(x=>x/255).map(x=>x<=.04045?x/12.92:((x+.055)/1.055)**2.4).reduce((s,x,i)=>s+x*[.2126,.7152,.0722][i],0);
    const ratio=(a,b)=>(Math.max(lum(a),lum(b))+.05)/(Math.min(lum(a),lum(b))+.05);
    const results=[];
    for(const el of document.querySelectorAll('body *')){
      if(el instanceof SVGElement||el.closest('svg,button:disabled,[hidden]')||!el.checkVisibility())continue;
      const direct=[...el.childNodes].filter(n=>n.nodeType===3).map(n=>n.textContent.trim()).join('').trim();
      if(!direct)continue;
      const st=getComputedStyle(el); if(Number(st.opacity)<1)continue;
      let bg=[228,240,255], chain=[];
      for(let n=el;n;n=n.parentElement)chain.unshift(n);
      for(const n of chain){const c=rgb(getComputedStyle(n).backgroundColor);if(c)bg=blend(c,bg);}
      const color=blend(rgb(st.color),bg), value=ratio(color,bg);
      const large=parseFloat(st.fontSize)>=24||(parseFloat(st.fontSize)>=18.66&&parseInt(st.fontWeight)>=700);
      results.push({selector:el.id?`#${el.id}`:`${el.tagName.toLowerCase()}.${String(el.className).replaceAll(' ','.')}`,text:direct.slice(0,55),ratio:Number(value.toFixed(2)),minimum:large?3:4.5,foreground:st.color,background:bg.map(Math.round)});
    }
    return {count:results.length,failures:results.filter(x=>x.ratio<x.minimum),minimum:Math.min(...results.map(x=>x.ratio))};
  });
  report.contrast.push({page:label,...result});
}
try{
  const url=new URL(runtime.url); url.pathname='/intro/';
  await page.goto(url.href);await page.waitForFunction(()=>!location.hash);
  for(const [width,height]of [[1920,1080],[1440,900],[1366,768],[390,844]]){
    await page.setViewportSize({width,height});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    assert.equal(await page.locator('html').evaluate(e=>getComputedStyle(e).colorScheme),'light');
    await shot(`after-intro-${width}`);
    await page.screenshot({path:fileURLToPath(new URL(`screenshots/after-intro-${width}-full.png`,root)),fullPage:true});
    report.viewports.push({page:'intro',width,height,overflow:false});
  }
  await contrast('intro (gradient evaluated conservatively at #e4f0ff)');
  await page.setViewportSize({width:1920,height:1080});
  await page.locator('.hero [data-demo]').click();
  const frame=page.frameLocator('#mechanism-frame');
  await frame.locator('#live-connection[data-state=connected]').waitFor();
  const storeFrame=await(await page.locator('#store-frame').elementHandle()).contentFrame();
  await storeFrame.waitForFunction(()=>{
    const images=[...document.querySelectorAll('.products__list__list-item img')];
    return images.length>=9&&images.every(img=>{
      if(!img.complete||!img.naturalWidth)return false;
      for(let n=img;n;n=n.parentElement)if(Number(getComputedStyle(n).opacity)<1)return false;
      return true;
    });
  });
  for(const [width,height]of [[1920,1080],[1440,900],[1366,768],[390,844]]){
    await page.setViewportSize({width,height});
    await page.evaluate(()=>scrollTo(0,0));
    await frame.locator('body').evaluate(el=>el.ownerDocument.defaultView.scrollTo(0,0));
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    assert(await frame.locator('html').evaluate(el=>el.scrollWidth<=el.ownerDocument.defaultView.innerWidth));
    await shot(`after-dual-${width}`);
    await frame.locator('#live-scene').screenshot({path:fileURLToPath(new URL(`screenshots/after-role-canvas-${width}.png`,root))});
    await shot(`after-roles-${width}`);
    report.viewports.push({page:'dual',width,height,overflow:false});
  }
  await page.setViewportSize({width:1920,height:1080});
  await contrast('dual shell');
  await page.goto(`${runtime.baseUrl}/mechanism/`);
  await page.locator('#live-connection[data-state=connected]').waitFor();
  for(const[width,height]of [[1920,1080],[1366,768],[390,844]]){
    await page.setViewportSize({width,height});await page.evaluate(()=>scrollTo(0,0));
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    await shot(`after-console-${width}`);
    await page.locator('#live-scene').screenshot({path:fileURLToPath(new URL(`screenshots/after-console-roles-${width}.png`,root))});
    const boxes=await page.locator('.scene-node').evaluateAll(nodes=>nodes.map(n=>{const r=n.getBoundingClientRect();return{id:n.dataset.node,width:r.width,height:r.height,x:r.x,y:r.y}}));
    assert.equal(boxes.length,6);
    report.viewports.push({page:'console',width,height,overflow:false,roles:boxes});
  }
  await contrast('console');
  await page.setViewportSize({width:1366,height:768});
  await page.locator('.scene-node[data-node=holder]').click();
  await page.locator('#live-role-dialog .role-public-material>summary').click();
  await page.locator('#live-role-dialog pre').waitFor();
  await shot('after-role-evidence-1366');
  await contrast('role evidence dialog');
  assert.deepEqual(report.errors,[]);
  report.status=report.contrast.some(c=>c.failures.length)?'contrast-review-needed':'passed';
}catch(e){report.status='failed';report.error=e.stack;process.exitCode=1;}
finally{
  await writeFile(new URL('verification/theme-ui.json',root),JSON.stringify(report,null,2));
  console.log(JSON.stringify(report,null,2));
  await browser.close();
}
