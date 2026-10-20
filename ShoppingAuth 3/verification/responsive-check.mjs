import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {launchAcceptanceBrowser} from '../app/scripts/lib/acceptance-browser.mjs';
const root=new URL('../',import.meta.url);
const runtime=JSON.parse(await readFile(new URL('app/var/dual-runtime.json',root)));
const entry=new URL(runtime.url);entry.pathname='/intro/';
const browser=await launchAcceptanceBrowser({headless:true});
const context=await browser.newContext({locale:'zh-CN',reducedMotion:'reduce'});
const page=await context.newPage();
const posts=[];page.on('request',r=>{if(r.method()==='POST')posts.push(new URL(r.url()).pathname)});
const report={status:'running',viewports:[],actions:[],businessPostCount:0};
try {
  for(const [width,height] of [[1920,1080],[1440,900],[1366,768],[390,844]]){
    await page.setViewportSize({width,height});await page.goto(entry.href);await page.waitForFunction(()=>!location.hash);
    const result=await page.evaluate(()=>{
      const title=document.querySelector('h1');
      const range=document.createRange();range.selectNodeContents(title);
      const rects=[...range.getClientRects()].map(r=>({left:r.left,right:r.right,top:r.top,bottom:r.bottom}));
      return {width:innerWidth,overflow:document.documentElement.scrollWidth>innerWidth,titleSize:parseFloat(getComputedStyle(title).fontSize),titleWhiteSpace:getComputedStyle(title).whiteSpace,titleRects:rects,buttonBackground:getComputedStyle(document.querySelector('.hero .primary')).backgroundColor,figureBottom:document.querySelector('.trust-figure').getBoundingClientRect().bottom};
    });
    assert.equal(result.overflow,false);assert.notEqual(result.titleWhiteSpace,'nowrap');
    assert(result.titleRects.every(r=>r.left>=0&&r.right<=width));
    if(width===1920){assert(result.titleSize>=56&&result.titleSize<=68);assert(result.figureBottom<=height);}
    assert.equal(result.buttonBackground,'rgb(247, 245, 250)');
    if(width===390){await page.locator('.technology-heading').scrollIntoViewIfNeeded();await page.screenshot({path:fileURLToPath(new URL('screenshots/technology-mobile.png',root))});}
    const cta=page.locator('.hero [data-demo]');await cta.click();
    await page.waitForURL(runtime.baseUrl+'/demo/');
    const mechanism=page.frameLocator('#mechanism-frame');
    await mechanism.locator('#live-connection[data-state=connected]').waitFor();
    assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
    assert(await mechanism.locator('body').evaluate(el=>el.ownerDocument.documentElement.scrollWidth<=el.ownerDocument.defaultView.innerWidth));
    await page.frameLocator('#store-frame').locator('.products__list__list-item').nth(8).waitFor({state:'attached'});
    await page.screenshot({path:fileURLToPath(new URL(`screenshots/responsive-dual-${width}.png`,root)),fullPage:width===390});
    report.viewports.push({...result,height,shellNoOverflow:true,consoleNoOverflow:true,heroCtaNavigates:true});
  }
  // Exercise the other two introduction entry points with real capabilities.
  for(const selector of ['nav [data-demo]','.demo-section [data-demo]']){
    await page.goto(entry.href);await page.waitForFunction(()=>!location.hash);await page.locator(selector).click();await page.waitForURL(runtime.baseUrl+'/demo/');
    await page.frameLocator('#mechanism-frame').locator('#live-connection[data-state=connected]').waitFor();report.actions.push({selector,navigated:true});
  }
  assert.deepEqual(posts,[]);report.status='passed';
} catch(error){report.status='failed';report.error=error.message;process.exitCode=1;console.error(error.message);}
finally{await writeFile(new URL('verification/responsive.json',root),JSON.stringify(report,null,2));await browser.close();}
console.log(JSON.stringify({status:report.status,viewports:report.viewports.length,otherEntryLinks:report.actions.length,businessPosts:posts.length}));
