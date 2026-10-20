import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
const source=await readFile(new URL('../public/guide.js',import.meta.url),'utf8');
const between=(start,end)=>source.slice(source.indexOf(start),source.indexOf(end,source.indexOf(start)));
for(const scenario of ['copied-vc','revoked'])test(`${scenario} cannot approve, reject, review Owner or create a normal order from a stale dialog`,async()=>{
  const calls=[];
  const context={scenario,busy:false,experimentBusy:false,refreshing:false,uncertain:false,ownerProposal:{status:'PENDING'},api:()=>calls.push('api'),invoke:()=>calls.push('invoke'),$:()=>{throw Error('must stop before reading a stale dialog');}};
  runInNewContext(between('async function openOwner(){',"document.querySelectorAll('[data-scenario]').forEach(button=>{\n  button.onclick").split('const showEvidence=')[0],context);
  await context.openOwner();await context.decide('approve');await context.decide('reject');await context.restart();
  assert.deepEqual(calls,[]);
});
test('a scene switch closes all old dialogs and discards the pending local review without a business call',()=>{
  const closed=[],elements=new Map();
  const get=id=>{if(!elements.has(id))elements.set(id,{open:id.endsWith('-dialog'),close(){closed.push(id);this.open=false;}});return elements.get(id);};
  const context={scenario:'revoked',renderModeDescription(){},renderScene(){},$:get,ownerProposal:{id:'old-normal-approval'},document:{querySelectorAll:()=>[]},scenarios:{revoked:['03','撤销后使用','说明']},location:{pathname:'/guide/revoked.html'},history:{replaceState(){throw Error('unchanged route');}},parent:{postMessage(){}},window:{}};
  runInNewContext(between('function showScenario(', 'async function selectScenario('),context);
  context.showScenario();
  assert.deepEqual(closed,['guide-evidence-dialog','guide-owner-dialog','guide-reset-dialog','guide-settings-dialog']);
  assert.equal(context.ownerProposal,null);
  assert.equal(get('guide-normal').hidden,true);assert.equal(get('guide-experiment').hidden,false);
});

for(const scenario of ['copied-vc','revoked'])test(`${scenario} ignores the retained normal challenge clock and hidden normal primary action`,async()=>{
  const calls=[],clock={textContent:'挑战有效期 1 秒'},state={manual:{active:true,stage:'CHALLENGE_READY',expiresAtUnix:100}};
  const context={scenario,state,busy:false,experimentBusy:false,refreshing:false,uncertain:false,
    Date:{now:()=>101000},done:()=>false,expired:()=>true,$:()=>{calls.push('normal-dom');return clock;},
    currentPlan(){calls.push('normal-plan');return {id:'verify',enabled:true};},
    render(){calls.push('render');},api(){calls.push('api');},invoke(){calls.push('invoke');}};
  runInNewContext(between('function tick(){','async function invoke(id){')+between('async function run(){','async function openOwner(){'),context);
  context.tick();await context.run();
  assert.equal(state.manual.stage,'CHALLENGE_READY');assert.equal(state.manual.expired,undefined);
  assert.equal(clock.textContent,'挑战有效期 1 秒');
  assert.deepEqual(calls,[],'neither the interval nor a stale hidden button can touch normal controls or invoke business actions');
});

for(const scenario of ['copied-vc','revoked'])test(`${scenario} render retains experiment progress when an old normal challenge has expired`,()=>{
  const elements=new Map(),get=id=>{if(!elements.has(id))elements.set(id,{textContent:'',innerHTML:'',dataset:{},querySelector:()=>({}),querySelectorAll:()=>[]});return elements.get(id);};
  const context={scenario,state:{manual:{active:true,stage:'CHALLENGE_READY',expiresAtUnix:100}},$:get,
    busy:false,experimentBusy:false,refreshing:false,uncertain:false,actionId:'',actionRunning:'',feedback:'',feedbackState:'',pause:false,
    detailPlanKey:'',traceKey:'',mode:()=> 'bbs-bls',ownerKey:()=>'',keyPattern:/^valid-key$/,
    renderModeDescription(){},renderScene(){get('guide-progress').innerHTML=`${scenario}:experiment-control-and-request`;},
    currentPlan:()=>({id:'device-sign',enabled:true}),expired:()=>true,done:()=>false,receipt:()=>null,protectedOrder:()=>false,
    currentStepPanel:()=>({key:'normal-attempt',title:'正常流程旧步骤',description:'normal',kind:'device',phase:'proposal'}),
    guideProgress:()=>({steps:[{title:'正常资格认证',status:'pending'}],currentIndex:0}),
    escape:String,renderStepBrief:()=>'',renderStepSummary:()=>'',renderDeviceParticipation:()=>'',renderStepDetail:()=>'',
    replaceDetails(element,html){element.innerHTML=html;},phaseName:()=> '资格认证',verificationVerdict:()=>({status:'pending'}),
    renderOperationFeedback(){},primaryLabel:()=> '正常支付下一步',paymentMilestones:()=>[],latestTrace:()=>null,
    traceView:{render(){}},json:JSON.stringify,raw:()=>'',lock(){},
  };
  runInNewContext(between('function render(){','async function invoke(id){'),context);
  context.render();
  assert.equal(get('guide-progress').innerHTML,`${scenario}:experiment-control-and-request`);
  assert.equal(context.state.manual.stage,'CHALLENGE_READY','render must not let a normal clock mutate the retained snapshot in an experiment');
});

test('returning to normal reads the original order and then observes its real expired challenge without renewing it',async()=>{
  const requests=[],elements=new Map(),get=id=>{if(!elements.has(id))elements.set(id,{textContent:'下一步',dataset:{}});return elements.get(id);};
  const context={scenario:'copied-vc',state:{manual:{active:true,stage:'CHALLENGE_READY',expiresAtUnix:100}},
    busy:false,uncertain:false,generation:0,mode:()=> 'bbs-bls',$:get,Date:{now:()=>101000},done:()=>false,
    expired(){return context.state.manual.expiresAtUnix*1000<=101000;},
    async api(path,body){requests.push({path,body});return {available:true,order:{orderId:'retained-order'},manual:{active:true,stage:'CHALLENGE_READY',expiresAtUnix:100}};},
    render(){context.tick();},
  };
  runInNewContext(between('function tick(){','async function invoke(id){')+between('async function read(){','async function refresh(){'),context);
  context.tick();assert.equal(context.state.manual.stage,'CHALLENGE_READY');
  context.scenario='normal';await context.read();
  assert.deepEqual(requests,[{path:'/api/dbac/payment/state?mode=bbs-bls',body:undefined}]);
  assert.equal(context.state.order.orderId,'retained-order');
  assert.equal(context.state.manual.stage,'EXPIRED');assert.equal(context.state.manual.expired,true);
  assert.match(get('guide-clock').textContent,/已过期 0 秒/);
});
