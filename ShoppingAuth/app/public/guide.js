import { planPayment, paymentMilestones, verificationVerdict, currentVerificationCompletion } from './guide-model.js';
import { createExperimentGuide } from './guide-experiments.js';
import { renderVerificationChecks } from './guide-evidence.js';
import { renderStepDetail, renderStepMaterial, currentStepPanel, currentVerificationTrace, renderStepSummary, renderDeviceParticipation } from './guide-step-detail.js';
import { deriveScene, renderSceneCanvas, renderSceneSummary } from './guide-scene.js';
import { renderCheckPreview, renderStepBrief, installDialogFocus } from './guide-stage-ui.js';
import { guideProgress, guidePaymentReceipt } from './guide-progress.js';

const $ = id => document.getElementById(id);
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const json = value => JSON.stringify(value ?? null, null, 2);
const store = {get(key){try{return sessionStorage.getItem(key)||'';}catch{return '';}},set(key,value){try{sessionStorage.setItem(key,value);}catch{}}};
const keyPattern = /^[A-Za-z0-9_-]{43}$/;
const entry = new URLSearchParams(location.hash.slice(1));
if(keyPattern.test(entry.get('key')||''))store.set('a2a-did-vc-ui-key',entry.get('key'));
const scenarios = {normal:['01','正常支付','原绑定模拟 eSIM 与持有者 A 共同参与认证，再由用户明确授权本笔模拟支付。'],'copied-vc':['02','凭证复制冒用','仅持公开 VC 副本的攻击者发起请求，核对实际结果与阻断位置。'],revoked:['03','撤销后使用','原持有者和原设备生成新证明，查看已撤销凭证的状态核验。']};
const pathScenario=()=>location.pathname.match(/\/guide\/(normal|copied-vc|revoked)\.html$/)?.[1];
history.replaceState(null,'',location.pathname);
const selectedMode = store.get('a2a-manual-mode');
if(['bbs-bls','bbs-blind-bls'].includes(selectedMode))$('guide-mode').value=selectedMode;
const selectedPace=store.get('a2a-guide-pace');
if(['guided','step'].includes(selectedPace))$('guide-pace').value=selectedPace;
let scenario=pathScenario()||'normal', state=null, busy=false, experimentBusy=false, uncertain=false, pause=false, actionRunning='', actionId='', feedback='', feedbackState='', ownerProposal=null, generation=0;
let experimentView=null, canvasKey='';
let refreshing=false, traceKey='', detailPlanKey='', pendingGuideRoute=null;
const mode=()=>$('guide-mode').value;
const ownerKey=()=>store.get('a2a-owner-ui-key');
const traceView=window.DemoVerification.create($('guide-trace'));
const labels={pass:'通过',fail:'未通过',skipped:'未执行',pending:'待确认',running:'执行中'};
const short=value=>typeof value==='string'&&value.length>22?value.slice(0,10)+'…'+value.slice(-6):value||'尚无';
const money=payment=>payment&&Number.isSafeInteger(payment.amountMinor)?`${(payment.amountMinor/1000000).toLocaleString('zh-CN',{maximumFractionDigits:6})} ${payment.currency||'TEST_USDC'}`:'尚未读取';
const facts=rows=>`<dl class="guide-facts">${rows.map(([name,value])=>`<dt>${escape(name)}</dt><dd>${escape(value??'未提供')}</dd>`).join('')}</dl>`;
const raw=(title,value)=>`<details><summary>${escape(title)}</summary><pre>${escape(json(value))}</pre></details>`;
const changed=()=>parent.postMessage({type:'demo:changed'},location.origin);
function lock(){
  const locked=busy||experimentBusy||refreshing;
  $('guide-normal').setAttribute('aria-busy',String(busy||refreshing));
  document.querySelectorAll('[data-scenario]').forEach(button=>button.disabled=locked);
  $('guide-mode').disabled=locked;$('guide-pace').disabled=locked;$('guide-refresh').disabled=busy||experimentBusy||refreshing;
  parent.postMessage({type:'demo:busy',busy:locked},location.origin);
  drainGuideRoute();
}
async function api(path,body,owner=false){
  const key=owner?ownerKey():store.get('a2a-did-vc-ui-key');
  if(!keyPattern.test(key)){const error=new Error(owner?'缺少用户授权权限，请使用本次启动的统一演示链接或载入 Owner 权限。':'尚未载入操作权限，请使用启动终端中的统一演示链接。');error.code=owner?'OWNER_UI_ACCESS_DENIED':'UI_ACCESS_DENIED';error.notSubmitted=true;throw error;}
  let response;
  try{response=await fetch(path,{method:body===undefined?'GET':'POST',headers:{Accept:'application/json',[owner?'X-Owner-UI-Key':'X-Demo-UI-Key']:key,...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),cache:'no-store',signal:AbortSignal.timeout(90000)});}
  catch{const error=new Error('暂未收到确定响应。请核对原订单或原实验，不要重复创建。');error.uncertain=true;throw error;}
  let data;try{data=await response.json();}catch{const error=new Error('服务未返回有效状态，请核对原操作结果。');error.uncertain=true;throw error;}
  if(!response.ok||data.ok===false){const error=new Error(data.error?.message||`请求未完成（HTTP ${response.status}）`);error.code=data.error?.code;error.status=response.status;error.data=data;if([401,403].includes(response.status))error.notSubmitted=true;throw error;}
  return data;
}
const experiment=createExperimentGuide({root:$('guide-experiment'),evidenceRoot:$('guide-experiment-evidence'),api,mode,canStart:()=>keyPattern.test(store.get('a2a-did-vc-ui-key')),onBusy(value){experimentBusy=value;lock();},onChange(event){
  if(event.type==='view'){experimentView=event.view;renderScene();}
  if(event.type==='evidence')openEvidence(event.target||'experiment');
  if(event.type==='normal')void selectScenario('normal');
  if(event.type==='resume'){
    scenario=event.scenarioId;$('guide-mode').value=event.mode;store.set('a2a-manual-mode',event.mode);showScenario();
    $('guide-environment').textContent='已恢复原实验，正在按原运行编号核对后端记录；不会创建新一轮。';
    $('guide-environment').dataset.state='pending';
  }
  if(event.type==='result'){
    $('guide-environment').textContent='已取得本轮后端记录 · 实验使用专用订单与凭证，原正常支付订单保留。';
    $('guide-environment').dataset.state='pass';$('guide-environment').hidden=true;changed();
  }
}});
function showScenario({fromHistory=false}={}){
  renderModeDescription();
  for(const id of ['guide-evidence-dialog','guide-owner-dialog','guide-reset-dialog','guide-settings-dialog'])if($(id).open)$(id).close();
  ownerProposal=null;
  $('guide-normal-evidence').hidden=scenario!=='normal';$('guide-experiment-evidence').hidden=scenario==='normal';
  $('guide-normal').hidden=scenario!=='normal';$('guide-experiment').hidden=scenario==='normal';
  $('guide-pace-setting').hidden=scenario!=='normal';
  document.querySelectorAll('[data-scenario]').forEach(button=>{const selected=button.dataset.scenario===scenario;button.setAttribute('aria-pressed',String(selected));if(selected)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');});
  const [number,title,description]=scenarios[scenario];
  $('guide-page-number').textContent=`场景 ${number}`;$('guide-page-title').textContent=title;$('guide-page-description').textContent=description;
  document.title=`${title} · 场景化交互演示台`;renderScene();
  const path=`/guide/${scenario}.html`;
  if(!fromHistory&&location.pathname!==path)history.replaceState({scenario},'',path);
  if(parent!==window)parent.postMessage({type:'demo:scenario-selected',scenario},location.origin);
}
async function selectScenario(value, {fromHistory=false}={}){
  if(busy||experimentBusy||refreshing||!['normal','copied-vc','revoked'].includes(value))return;
  if(parent===window&&!fromHistory&&value!==scenario)history.pushState({scenario:value},'',`/guide/${value}.html`);
  const pageChanged=scenario!==value;scenario=value;showScenario({fromHistory});
  if(pageChanged){generation++;detailPlanKey='';feedback='';feedbackState='';window.scrollTo({top:0});$('guide-page-title').focus({preventScroll:true});}
  if(scenario==='normal')await refresh();else {await experiment.select(scenario);$('guide-environment').textContent='安全实验使用专用订单与凭证，原正常支付订单保留。准备和提交均由后端执行。';$('guide-environment').hidden=true;}
}
async function read(){
  const requested=mode(),requestedScenario=scenario,current=++generation;
  const value=await api(`/api/dbac/payment/state?mode=${encodeURIComponent(requested)}`);
  if(current!==generation||requested!==mode()||requestedScenario!==scenario)return;
  state=value;uncertain=false;
  $('guide-environment').textContent=value.available?'已读取后端状态 · 当前为'+(requested==='bbs-bls'?'普通 BLS':'盲化 BLS')+' · 公开详情可展开核对':'完整演示环境尚不可用，请使用 npm start 启动。';
  $('guide-environment').dataset.state=value.available?'pass':'pending';$('guide-environment').hidden=value.available===true;render();return value;
}
async function refresh(){
  if(busy||experimentBusy||refreshing)return;
  refreshing=true;render();
  try{await read();feedback='已核对原订单状态；没有重新签名、重新认证或付款。';feedbackState='';}
  catch(error){uncertain=true;feedback=error.message;feedbackState='fail';$('guide-environment').textContent=error.message;$('guide-environment').dataset.state='fail';$('guide-environment').hidden=false;}
  finally{refreshing=false;render();lock();}
}
function sameOrder(a,b){return a&&b&&['orderId','amountMinor','currency','payerAccount','payeeAccount'].every(k=>a[k]===b[k])&&['network','asset','payerAddress','payTo'].every(k=>a.settlement?.[k]===b.settlement?.[k]);}
function latestTrace(){return currentVerificationTrace(state);}
function receipt(){return guidePaymentReceipt(state,{uncertain});}
function done(){return Boolean(receipt());}
function protectedOrder(){const m=state?.manual||{};return !done()&&Boolean(state?.paymentPending||m.walletSigned||m.walletSigningUnconfirmed);}
function expired(){const m=state?.manual;return Boolean(m?.expired||m?.stage==='EXPIRED'||m?.active&&Number.isFinite(m.expiresAtUnix)&&m.expiresAtUnix*1000<=Date.now());}
function currentPlan(){return planPayment(state,{ownerAvailable:keyPattern.test(ownerKey())});}
function phaseName(){return {proposal:'资格认证',authorize:'付款资格复核',settle:'结算验证'}[state?.manual?.phase]||'准备材料';}
function primaryLabel(plan){
  if(busy)return `${actionRunning||'操作'}处理中…`;
  if(done())return '查看回执';
  if(plan.id==='prove')return '由持有者 A 核验并组合证明';
  if(plan.id==='verify')return state?.manual?.phase==='settle'?'提交验证者 B 验证并执行模拟支付':'提交验证者 B 验证';
  if($('guide-pace').value==='step')return plan.label;
  if(['begin-proposal','begin-authorize','begin-settle'].includes(plan.id)){
    const phase=plan.id.startsWith('begin-')?plan.id.slice(6):state?.manual?.phase;
    return phase==='proposal'?'准备本次请求与披露材料':phase==='authorize'?'准备付款前复核材料':'准备结算复核材料';
  }
  return plan.label;
}
// Expansion belongs to one order/attempt/action, and never invokes the protocol.
function replaceDetails(element, html, preserve) {
  const key = item => item.dataset.detailKey || [item.closest('[data-check-id]')?.dataset.checkId, item.closest('.guide-evidence-row')?.querySelector('strong')?.textContent, item.querySelector('summary')?.textContent].filter(Boolean).join('::');
  const saved = new Map(preserve ? [...element.querySelectorAll('details')].map(item => [key(item),item.open]) : []);
  element.innerHTML = html;
  if(preserve)for (const item of element.querySelectorAll('details'))if(saved.has(key(item)))item.open = saved.get(key(item));
}
function renderScene(){
  const model=deriveScene({state,scenario,mode:mode(),busy:scenario==='normal'?busy:experimentBusy,uncertain:scenario==='normal'?uncertain:false,actionId,experiment:experimentView,plan:currentPlan()});
  const html=renderSceneCanvas(model);
  if(html!==canvasKey){canvasKey=html;const active=document.activeElement?.dataset?.node;$('guide-scene').innerHTML=html;if(active)$('guide-scene').querySelector(`[data-node="${active}"]`)?.focus({preventScroll:true});}
  $('guide-business-summary').innerHTML=renderSceneSummary(model);
  if(scenario!=='normal')$('guide-progress').innerHTML=['合法控制组',scenario==='copied-vc'?'复制公开 VC':'撤销实验凭证','新挑战下提交','核对实际结果'].map((title,index)=>`<li class="guide-progress-item" data-state="pending"><strong>${index+1}. ${title}</strong></li>`).join('');
  $('guide-mode-badge').textContent=mode()==='bbs-blind-bls'?'盲化 BLS':'普通 BLS';
}
function renderModeDescription(){
  $('guide-mode-description').textContent=mode()==='bbs-blind-bls'
    ? '盲化 BLS：模拟 eSIM 只接收盲化点和公开协议标识；请求明文保留在持有者 A，持有者 A 去盲并核验设备贡献。'
    : '普通 BLS：模拟 eSIM 接收本次挑战、请求摘要与派生 VC 摘要，再为这些材料生成设备贡献。';
  $('guide-mode-description').textContent+=' 此设置改变设备贡献方式；VC 的 BBS 选择性披露证明仍单独验证。';
}
function renderOperationFeedback(){
  const element=$('guide-feedback');
  element.textContent=feedback;
  element.hidden=!feedback;
  element.dataset.state=feedbackState==='fail'?'fail':busy?'running':'info';
}
function render(){
  renderModeDescription();renderScene();
  const m=state?.manual||{},plan=currentPlan(),stale=expired(),complete=done();
  const panel=currentStepPanel(state,{plan,action:actionId,uncertain,complete});
  const progress=guideProgress(state,plan,{uncertain});
  const contextKey=[scenario,panel.key].join(':'),sameContext=contextKey===detailPlanKey;
  if(scenario==='normal')$('guide-progress').innerHTML=progress.steps.map((item,index)=>`<li class="guide-progress-item" data-state="${escape(item.status)}" ${index===progress.currentIndex?'aria-current="step"':''}><strong>${item.status==='pass'?'✓ ':item.status==='fail'?'× ':''}${index+1}. ${escape(item.title)}</strong></li>`).join('');
  $('guide-step').textContent=complete?'本笔测试支付回执':panel.title;
  $('guide-step-brief').innerHTML=complete?`<div class="stage-receipt-finish"><strong>${escape(money(state.order))}</strong><p>${escape(state.order?.payerAccount)} → ${escape(state.order?.payeeAccount)}</p><p>本笔测试链付款已完成；交易哈希、网络、资产与完整回执可展开核对。</p></div>`:renderStepBrief(panel);
  $('guide-check-summary').innerHTML=panel.verification&&!complete?renderCheckPreview(panel.trace,{phase:panel.phase,running:actionId==='verify'}):'';
  $('guide-evidence-context').textContent=`${mode()==='bbs-blind-bls'?'盲化 BLS':'普通 BLS'} · ${phaseName()} · 订单 ${state?.order?.orderId||'尚未准备'} · 认证尝试 ${m.attemptId||'尚未开始'}`;
  $('guide-environment-detail').textContent=state?.available?'当前项目后端已连接。主线为独立 Node BLS12-381 软件模拟 eSIM；本地 TEST_USDC 无真实资金价值。':'完整环境尚未确认；请核对本次启动服务及权限。';
  $('guide-action-description').textContent=panel.description;
  replaceDetails($('guide-step-summary'),renderStepSummary(panel),sameContext);
  replaceDetails($('guide-device-participation'),renderDeviceParticipation(state,{panel,action:actionId,uncertain,mode:mode()}),sameContext);
  const materialState=panel.starting?{...state,manual:{...m,challenge:null,attemptId:null,cryptography:null,verifiableCredential:null,sentCredential:null}}:state;
  replaceDetails($('guide-step-detail'),renderStepDetail(materialState,{plan,mode:mode(),panel,action:actionId}),sameContext);
  $('guide-checks').hidden=!panel.verification;
  replaceDetails($('guide-checks'),panel.verification?renderVerificationChecks(panel.trace,{phase:panel.phase,running:actionId==='verify',recheck:panel.recheck}):'',sameContext);
  let resultState='pending',resultTitle='○ 等待本步操作',resultDetail=plan.reason||'';
  const verdict=verificationVerdict(panel.trace,{phase:panel.phase});
  const error=m.lastError;
  if(complete){resultTitle='✓ 本笔测试支付已完成';resultDetail=`${money(state.order)} · 已取得匹配当前订单与条款的真实成功回执。`;resultState='pass';}
  else if(actionId){resultTitle=`◌ ${actionRunning||'本步操作进行中'}`;resultDetail='请求已发起，等待本次返回；不会据此预先显示通过。';resultState='running';}
  else if(panel.trace){resultTitle=`${verdict.status==='pass'?'✓':verdict.status==='fail'?'×':'○'} ${verdict.title}`;resultDetail=verdict.detail;resultState=verdict.status;}
  else if(panel.kind==='owner'){
    resultTitle=state?.proposal?.status==='REJECTED'?'× 用户已拒绝本笔授权':state?.authorization?'▣ 本笔授权已同步':state?.proposal?.status==='PENDING'?'○ 等待用户决定':'○ 尚未提交付款授权申请';
    resultDetail=state?.proposal?'批准只授权本笔订单；钱包签名和模拟支付仍需分别操作。':'资格认证结果可在前置记录回看；下一步将本笔条款提交给用户。';
  }
  else if(panel.kind==='wallet'){resultTitle='○ 等待钱包签署本笔材料';resultDetail='付款前复核已返回；签名本身不转账。';}
  else if(panel.kind==='device'&&m.verifiableCredential){resultTitle='▣ 本次派生凭证已生成';resultDetail='下一步请求模拟 eSIM 为本次材料提供贡献。';}
  else if(panel.kind==='holder'&&m.deviceResponse){resultTitle='▣ 模拟 eSIM 贡献已返回';resultDetail='下一步由持有者 A 核验贡献并生成持有者证明。';}
  else if(panel.kind==='verification'){resultTitle='○ 本次证明待验证';resultDetail=panel.recheck?`${panel.recheck}使用本次新挑战，前一步结果不能代替。`:'材料已准备，验证者 B 尚未返回本次验证结论。';}
  if(!actionId&&error){resultTitle=panel.trace?.outcome==='fail'?'× 本次请求被阻断':'! 本步操作未完成';resultDetail=`停在${panel.title}：${error.code?error.code+' · ':''}${error.message||'请核对本轮记录。'}`;resultState=panel.trace?.outcome==='fail'?'fail':'pending';}
  if(!actionId&&feedbackState==='fail'&&!error){resultTitle='! 操作结果需核对';resultDetail=feedback;resultState='pending';}
  if(uncertain){resultTitle='! 当前请求结果未确认';resultDetail=feedback||'通信异常，尚未取得确定结果。请核对原订单；不能判定凭证无效或支付完成。';resultState='pending';}
  if(stale&&!complete&&!actionId){resultTitle='! 本次挑战或证据已过期';resultDetail='已返回记录只供回看；继续需要新挑战和新证明。';resultState='pending';}
  if(panel.trace?.outcome==='pass'&&verdict.status==='fail'||complete&&panel.trace&&verdict.status!=='pass'){
    resultTitle='! 返回结果存在异常';resultDetail=`整体结果与逐项记录不一致。${verdict.detail}${complete?' 已保留实际回执，请核对。':''}`;resultState='fail';
  }
  const recent=['owner','wallet'].includes(panel.kind)&&!complete?currentVerificationCompletion(state,{uncertain}):null;
  $('guide-recent-completion').hidden=!recent;
  $('guide-recent-completion').textContent=recent?`✓ 本轮已完成：${recent.title}。${recent.detail}`:'';
  renderOperationFeedback();
  if(feedback&&resultDetail.includes(feedback))$('guide-feedback').hidden=true;
  $('guide-result-title').textContent=resultTitle;$('guide-result-detail').textContent=resultDetail;$('guide-result').dataset.state=resultState;
  const block=uncertain?'请先核对当前状态，再决定后续操作。':plan.reason||'';
  $('guide-block').textContent=block;$('guide-block').hidden=!block||resultDetail.includes(block);
  $('guide-owner-help').hidden=!(state?.proposal?.status==='PENDING'&&!keyPattern.test(ownerKey()));
  $('guide-main').textContent=primaryLabel(plan);$('guide-main').hidden=complete;
  $('guide-normal').querySelector('[data-scene-evidence="current"]').hidden=complete;
  $('guide-main').disabled=busy||experimentBusy||refreshing||uncertain||!plan.enabled;
  $('guide-stop').hidden=!busy||!actionRunning;$('guide-stop').disabled=pause;
  $('guide-show-receipt').hidden=!complete;
  const result=receipt();
  $('guide-receipt').hidden=!complete;
  if(!sameContext)$('guide-receipt').open=false;
  replaceDetails($('guide-receipt-content'),complete?`<div class="guide-receipt"><h4>${escape(money(state.order))} · ${result.outcome==='ALREADY_PROCESSED'?'原订单回执':'本地测试链结算已执行'}</h4>${facts([['订单',state.order.orderId],['收款方',state.order.payeeAccount],['执行结果',result.outcome],['交易编号',result.receipt.transactionHash||result.transactionHash||result.receipt.transaction?.hash||'查看完整回执'],['网络',state.order.settlement?.network]])}<p class="guide-muted">TEST_USDC 测试代币，不涉及真实资金。</p>${raw('完整模拟支付回执',result)}</div>`:'',sameContext);
  $('guide-restart').disabled=busy||experimentBusy||refreshing||uncertain||!state?.available||protectedOrder();
  $('guide-discard').disabled=busy||experimentBusy||refreshing||uncertain||protectedOrder()||!m.availableActions?.includes('discard');
  $('guide-reset-note').textContent=protectedOrder()?'原订单已有钱包签名或待确认结算，请继续原订单核对。':'结束认证保留原订单和授权；开始新一笔保留旧回执。';
  // Current public records only. Raw proof/credential JSON is no longer repeated
  // here: selected material fields live with their operation/check above.
  $('guide-order').textContent=state?.order?`${money(state.order)} · 订单 ${short(state.order.orderId)} · 轮次 ${short(m.attemptId)}`:'等待读取订单';
  $('guide-milestones').innerHTML=paymentMilestones(state).map((item,index)=>`<li data-state="${escape(item.status)}"><strong>${index+1}. ${escape(item.title)}</strong><span>${escape(item.detail||labels[item.status]||'待执行')}</span></li>`).join('');
  const trace=latestTrace(),nextTraceKey=json(trace);
  if(nextTraceKey!==traceKey||!sameContext){traceKey=nextTraceKey;traceView.render(trace,{label:'本轮验证者 B 返回记录 · 只读回看'});}
  replaceDetails($('guide-technical'),raw('只读消息目录（历史记录不代表本步已执行）',(m.log||[]).map(({id,time,from,to,action,status,summary})=>({id,time,from,to,action,status,summary})))+raw('本轮公开错误信息',m.lastError?{code:m.lastError.code,message:m.lastError.message}:null),sameContext);
  if(!sameContext)$('guide-normal-evidence').querySelector('.guide-tech-details').open=false;
  detailPlanKey=contextKey;
  tick();lock();
}
function tick(){
  if(scenario!=='normal')return;
  const m=state?.manual||{},end=m.expiresAtUnix;
  $('guide-clock').textContent=Number.isFinite(end)&&m.active&&!done()?`${expired()?'已过期':m.verificationResult?'证据有效期':'挑战有效期'} ${Math.max(0,Math.ceil(end-Date.now()/1000))} 秒`:'';
  if(!busy&&!uncertain&&expired()&&!$('guide-main').textContent.includes('新挑战')&&state?.manual?.stage!=='EXPIRED'){state.manual.stage='EXPIRED';state.manual.expired=true;render();}
}
async function invoke(id){
  const m=state?.manual||{},payload={mode:mode()},requestGeneration=generation,requestScenario=scenario;
  let value;
  if(['issue','new','sync'].includes(id))value=await api(`/api/dbac/payment/${id}`,payload);
  else value=await api('/api/dbac/payment/manual',{...payload,action:id,...(m.attemptId?{attemptId:m.attemptId}:{})});
  if(requestGeneration!==generation||requestScenario!==scenario||payload.mode!==mode()){pause=true;return;}
  state=value;uncertain=false;actionId='';changed();render();
  if(value.manual?.lastError){const error=new Error(value.manual.lastError.message);error.code=value.manual.lastError.code;throw error;}
}
async function run(){
  if(scenario!=='normal'||busy||experimentBusy||refreshing||uncertain)return;
  let plan=currentPlan();if(!plan.enabled)return;
  if(plan.id==='owner-review'){await openOwner();return;}
  if(plan.id==='refresh'){await refresh();return;}
  busy=true;pause=false;feedback='';feedbackState='';
  const guided=$('guide-pace').value==='guided';
  // Guided preparation may derive the VC after obtaining its challenge. Device
  // contribution, A composition, B verification and consent remain separate clicks.
  const preparation=new Set(['begin-proposal','begin-authorize','begin-settle']);
  try{
    for(let count=0;count<2;count++){
      actionId=plan.id;actionRunning=plan.label;feedback=`正在执行：${plan.label}。尚未取得这一步的结果。`;render();
      await invoke(plan.id);
      feedback='';render();
      if(!guided||pause||!preparation.has(plan.id)||done())break;
      const next=currentPlan();
      if(!next.enabled||next.id!=='derive-vc')break;
      plan=next;
    }
    if(pause)feedback='已暂停后续自动准备。当前已发送请求已返回；继续下一步需再次点击，已发请求不会被撤回。';
  }catch(error){
    feedback=`${error.code?error.code+'：':''}${error.message}`;feedbackState='fail';
    try{await read();}catch{uncertain=true;}
  }finally{busy=false;actionRunning='';actionId='';render();}
}
async function openOwner(){
  if(scenario!=='normal')return;
  if(busy||experimentBusy||refreshing)return;
  ownerProposal=null;$('guide-owner-terms').innerHTML='';$('guide-owner-feedback').textContent='正在读取本订单的实际付款授权申请。';$('guide-owner-approve').disabled=true;$('guide-owner-reject').disabled=true;
  $('guide-owner-access').hidden=keyPattern.test(ownerKey());$('guide-owner-dialog').showModal();
  busy=true;lock();
  try{
    const value=await api('/owner/api/state',undefined,true),p=value.proposals?.find(p=>p.id===state?.proposal?.id);
    if(!p||p.profile!=='dbac-payment'||p.mode!==mode()||p.payment?.orderId!==state?.order?.orderId||!sameOrder(p.payment,state.order))throw new Error('授权申请与当前订单或模式不一致，请重新核对状态。');
    if(p.status!=='PENDING'){await invoke(state?.manual?.availableActions?.includes('sync-owner')?'sync-owner':'sync');}
    ownerProposal=structuredClone(p);
    $('guide-owner-terms').innerHTML=`<h3>${escape(money(p.payment))}</h3>`+facts([['收款账户',p.payment.payeeAccount],['订单编号',p.payment.orderId],['测试网络',p.payment.settlement?.network],['代币合约',p.payment.settlement?.asset],['付款地址',p.payment.settlement?.payerAddress],['收款地址',p.payment.settlement?.payTo],['有效期',p.expiresAt],['凭证绑定',p.vcBindingId]])+raw('完整授权条款与公开证据',p);
    $('guide-owner-feedback').textContent=p.status==='PENDING'?'请核对以上条款。批准后会读取并同步授权，仍不会自动付款。':`当前申请状态：${p.status}。请关闭弹窗并核对原订单。`;
    $('guide-owner-approve').disabled=p.status!=='PENDING';$('guide-owner-reject').disabled=p.status!=='PENDING';
  }catch(error){$('guide-owner-feedback').textContent=error.message;}
  finally{busy=false;lock();}
}
async function decide(action){
  if(scenario!=='normal')return;
  if(busy||experimentBusy||!ownerProposal||ownerProposal.status!=='PENDING')return;
  const p=ownerProposal;
  if(p.id!==state?.proposal?.id||p.payment.orderId!==state?.order?.orderId||p.mode!==mode()){ownerProposal=null;$('guide-owner-feedback').textContent='当前订单已变化，请关闭后重新核对。';return;}
  busy=true;lock();$('guide-owner-approve').disabled=true;$('guide-owner-reject').disabled=true;
  $('guide-owner-feedback').textContent='正在提交用户的明确决定…';
  try{
    const result=await api(`/owner/api/proposals/${encodeURIComponent(p.id)}/${action}`,action==='approve'?{confirmed:true,payment:p.payment,credentialHash:p.credentialHash}:{rejected:true},true);
    if(result.status!==(action==='approve'?'APPROVED':'REJECTED'))throw new Error('尚未取得预期的授权状态，请核对原申请。');
    ownerProposal=null;changed();
    await invoke(state?.manual?.availableActions?.includes('sync-owner')?'sync-owner':'sync');
    feedback=action==='approve'?'用户已批准并同步本笔授权。尚未付款；下一步核验本次付款资格。':'用户已拒绝本笔授权。不会继续钱包签名或付款。';feedbackState='';$('guide-owner-dialog').close();
  }catch(error){ownerProposal=null;$('guide-owner-feedback').textContent=error.message+' 请关闭后核对原订单，不要重复批准。';uncertain=true;}
  finally{busy=false;render();}
}
async function restart(){
  if(scenario!=='normal')return;
  if(busy||experimentBusy||uncertain||protectedOrder())return;
  busy=true;lock();$('guide-reset-confirm').disabled=true;$('guide-reset-feedback').textContent='正在保留原记录并创建新订单…';
  try{
    await read();if(protectedOrder())throw new Error('原订单尚待结算核对，不能创建新订单。');
    if(state?.manual?.active)await invoke('discard');
    await invoke('new');
    detailPlanKey='';feedback='';feedbackState='';
    if(state.credential&&(state.credentialStatus?.status==='revoked'||state.credentialStatus?.status==='expired'||state.w3c?.originalCredential?.credentialSubject?.epoch!==new Date().toISOString().slice(0,10)))await invoke('issue');
    feedback='新订单已创建。旧回执保留；请按下一步继续本轮演示。';feedbackState='';$('guide-reset-dialog').close();
  }catch(error){$('guide-reset-feedback').textContent=error.message;feedback=error.message;feedbackState='fail';try{await read();}catch{uncertain=true;}}
  finally{busy=false;$('guide-reset-confirm').disabled=false;render();}
}
const showEvidence=installDialogFocus($('guide-evidence-dialog'),()=>scenario==='normal'?$('guide-main'):$('guide-experiment').querySelector('button'));
const showSettings=installDialogFocus($('guide-settings-dialog'),()=>$('guide-settings-open'));
$('guide-settings-open').onclick=showSettings;
function openEvidence(target='current'){
  $('guide-normal-evidence').hidden=scenario!=='normal';$('guide-experiment-evidence').hidden=scenario==='normal';
  $('guide-evidence-title').textContent=scenario==='normal'?'本次公开材料与检查':'本轮实验记录回看';
  if(scenario!=='normal')$('guide-evidence-context').textContent=`只读记录 · ${mode()==='bbs-blind-bls'?'盲化 BLS':'普通 BLS'} · runId ${experimentView?.context?.runId||'尚未运行'}`;
  const focused=$('guide-focused-evidence');focused.hidden=true;focused.innerHTML='';
  if(scenario==='normal'&&['credential','holder','device','owner','verification'].includes(target)){
    $('guide-normal-evidence').hidden=true;focused.hidden=false;
    focused.innerHTML=`<p class="guide-muted">${phaseName()} · 只读记录；仅查看当前订单与认证尝试的公开材料，不执行该角色动作。</p>`+(target==='verification'?renderVerificationChecks(currentVerificationTrace(state),{phase:state?.manual?.phase}):renderStepMaterial(state,target,mode(),{open:true}));
  }
  showEvidence();
  const container=scenario==='normal'?$('guide-normal-evidence'):$('guide-experiment-evidence');
  const id=target.startsWith('check:')?target.slice(6):null;
  const node=id?container.querySelector(`${scenario==='normal'?'':'[data-experiment-request-checks] '}[data-check-id="${CSS.escape(id)}"]`):target==='receipt'?$('guide-receipt'):null;
  if(node){for(let element=node;element&&element!==container;element=element.parentElement)if(element.tagName==='DETAILS')element.open=true;node.scrollIntoView({block:'nearest'});}
}
document.addEventListener('click',event=>{const button=event.target.closest('[data-scene-evidence]');if(button&&!button.disabled)openEvidence(button.dataset.sceneEvidence);});
document.querySelectorAll('[data-scenario]').forEach(button=>{
  button.onclick=()=>void selectScenario(button.dataset.scenario);
  button.onkeydown=event=>{const buttons=[...document.querySelectorAll('[data-scenario]')],index=buttons.indexOf(button);let next;if(['ArrowDown','ArrowRight'].includes(event.key))next=(index+1)%buttons.length;else if(['ArrowUp','ArrowLeft'].includes(event.key))next=(index+buttons.length-1)%buttons.length;else if(event.key==='Home')next=0;else if(event.key==='End')next=buttons.length-1;else return;event.preventDefault();buttons[next].focus();};
});
function restoreScenarioFromHistory(){
  const destination=pathScenario()||'normal';
  if(busy||experimentBusy||refreshing){pendingGuideRoute={scenario:destination,activate:false,fromHistory:true};return;}
  void selectScenario(destination,{fromHistory:true});
}
window.addEventListener('popstate',restoreScenarioFromHistory);
$('guide-main').onclick=()=>void run();$('guide-show-receipt').onclick=()=>openEvidence('receipt');$('guide-stop').onclick=()=>{pause=true;feedback='将在当前请求返回后暂停，不撤回已发送请求。';render();};
$('guide-refresh').onclick=()=>void (scenario==='normal'?refresh():experiment.refresh());
$('guide-mode').onchange=async()=>{renderModeDescription();state=null;uncertain=false;ownerProposal=null;feedback='';feedbackState='';detailPlanKey='';generation++;store.set('a2a-manual-mode',mode());if(scenario==='normal')await refresh();else await experiment.select(scenario);};
$('guide-pace').onchange=()=>{store.set('a2a-guide-pace',$('guide-pace').value);render();};
$('guide-owner-approve').onclick=()=>void decide('approve');$('guide-owner-reject').onclick=()=>void decide('reject');
$('guide-restart').onclick=()=>{$('guide-reset-feedback').textContent='';$('guide-reset-dialog').showModal();};$('guide-reset-confirm').onclick=()=>void restart();
$('guide-discard').onclick=async()=>{if(busy||experimentBusy||uncertain||protectedOrder())return;busy=true;render();try{await invoke('discard');feedback='已结束本次认证尝试，原订单、授权及记录保留。';feedbackState='';}catch(error){feedback=error.message;feedbackState='fail';try{await read();}catch{uncertain=true;}}finally{busy=false;render();}};
// Apply the shared mode and destination together before reading any state.
// An activation cannot race a separate scenario message and lose mode sync.
function activateGuideRoute({scenario:destination=scenario,activate=true,fromHistory=false}={}) {
  const nextScenario=Object.hasOwn(scenarios,destination)?destination:scenario;
  const saved=store.get('a2a-manual-mode');
  const modeChanged=['bbs-bls','bbs-blind-bls'].includes(saved)&&saved!==mode();
  const scenarioChanged=nextScenario!==scenario;
  if(!modeChanged&&!scenarioChanged&&!activate){pendingGuideRoute=null;return;}
  if(busy||experimentBusy||refreshing){
    // An in-flight read already covers an unchanged activation. Preserve only
    // an actual route/mode change, including navigation during the first load.
    pendingGuideRoute=modeChanged||scenarioChanged?{scenario:nextScenario,activate,fromHistory}:null;
    return;
  }
  pendingGuideRoute=null;
  if(modeChanged){
    state=null;ownerProposal=null;generation++;$('guide-mode').value=saved;renderModeDescription();
    if($('guide-owner-dialog').open)$('guide-owner-dialog').close();
  }
  if(scenarioChanged)return selectScenario(nextScenario,{fromHistory:true});
  return scenario==='normal'?refresh():experiment.refresh();
}
function drainGuideRoute(){
  if(busy||experimentBusy||refreshing||!pendingGuideRoute)return;
  const next=pendingGuideRoute;pendingGuideRoute=null;
  queueMicrotask(()=>void activateGuideRoute(next));
}
window.addEventListener('demo:activate',()=>void activateGuideRoute());
window.addEventListener('message',event=>{
  if(event.origin!==location.origin||event.source!==parent)return;
  if(event.data?.type==='demo:guide-route')void activateGuideRoute(event.data);
  if(event.data?.type==='demo:invalidate'){
    if(busy||experimentBusy)return;
    ownerProposal=null;if($('guide-owner-dialog').open)$('guide-owner-dialog').close();
    void(scenario==='normal'?refresh():experiment.refresh());
  }
});
setInterval(tick,1000);
showScenario();render();void (async()=>{if(!await experiment.resumePending()){if(scenario==='normal')await refresh();else await experiment.select(scenario);}})();
