import { DEFAULT_INPUT, parseInput, formatUnits, inputMatches, pendingPayment, recoveryPhase, metrics, difference, noDeviceEvidence, receiptFor, errorState } from './core-model.js';
import { protocolSnapshot } from './protocol-model.js';
import { renderProtocol } from './protocol-view.js';

const $ = id => document.getElementById(id);
const storeKey = 'credential-core-demo-v1';
const labels = { idle:'未运行', running:'运行中', success:'成功', failure:'失败', timeout:'超时 / 结果待核对', stale:'旧结果已失效', pending:'等待明确操作', blocked:'未接入' };
const names = { 'merchant:keyboard':'键盘商户', 'merchant:other':'备用商户' };
const modeName = mode => mode === 'bbs-blind-bls' ? '盲化设备模式' : '普通设备模式';
const text = (id, value) => { $(id).textContent = value; };
let bridge, run = null, operating = false, invalidated = false, checking = false, connectionError = null;
let currentStep = null;
let protocolView = 'issue';
const protocolViews = ['issue','derive','device','verify','payment'];
const draft = () => ({ amount:$('core-amount').value, payeeAccount:$('core-payee').value, mode:$('core-mode').value });
const applyDraft = input => { $('core-amount').value=input.amount; $('core-payee').value=input.payeeAccount; $('core-mode').value=input.mode; };
const state = () => bridge?.state();
function config() { return parseInput(draft(), Object.keys(state()?.paymentInfo?.payees || { 'merchant:keyboard':true, 'merchant:other':true })); }
function save() {
  // Retain only explicitly projected protocol observations and public proof
  // bytes; never access capabilities, private witnesses, Owner tokens or
  // signed wallet payloads.
  try { sessionStorage.setItem(storeKey, JSON.stringify({ draft:draft(), run, invalidated, protocolView })); } catch {}
}
function restore() {
  try { const saved=JSON.parse(sessionStorage.getItem(storeKey)); if(saved?.draft)applyDraft(saved.draft);if(protocolViews.includes(saved?.protocolView))protocolView=saved.protocolView; if([1,2].includes(saved?.run?.version)){run=saved.run;run.restored=true;invalidated=Boolean(saved.invalidated);if(run.status==='running'){run.status='timeout';run.message='页面在操作期间刷新，执行结果未确认。请先核对本次状态。';run.uncertain=true;}} } catch {}
}
function related() { return Boolean(run?.order && inputMatches(run.config,state()) && run.order.orderId===state()?.order?.orderId && (!run.bindingId || run.bindingId===state()?.w3c?.originalCredential?.credentialSubject?.bindingId)); }
function facts(id, entries) {
  $(id).replaceChildren();
  for(const [label,value] of entries) { const row=document.createElement('div'), title=document.createElement('span'), content=document.createElement('strong'); title.textContent=label;content.textContent=value;row.append(title,content);$(id).append(row); }
}
function stepStatus(id) { return run?.steps?.find(step=>step.id===id); }
function recordStep(id, label, status, detail='') {
  let step=stepStatus(id);if(!step){step={id,label};run.steps.push(step);}Object.assign(step,{status,detail,time:new Date().toISOString()});render();save();
}
async function action(id,label,operation) {
  if(run.restored)run.continuedAfterRestore=true;
  currentStep=id;recordStep(id,label,'running');
  const result=await operation();
  recordStep(id,label,'success');currentStep=null;return result;
}
function captureProtocol(actionName) {
  if(!related())return;
  run.protocol ||= {};
  const s=state(), snapshot={...protocolSnapshot(s),ownerApprovalObserved:Boolean(bridge.ownerApproved()),observedAt:new Date().toISOString()};
  let key;
  if(actionName==='issue')key='issue';
  else if(actionName==='test-no-device')key='negative';
  else if(s.manual?.phase==='proposal'&&!['submit-owner','sync-owner','owner-observed'].includes(actionName))key=({'begin-proposal':'derive','derive-vc':'derive','device-sign':'device',prove:'proof',verify:'verify'})[actionName];
  else key='payment';
  if(!key)return;
  run.protocol[key]=snapshot;
  protocolView=key==='proof'?'device':key==='negative'?'derive':key;
  run.protocolActive=protocolView;
  save();render();
}
const manualAction = async (actionName,id,label) => {
  const result=await action(id,label,()=>bridge.action(actionName));
  captureProtocol(actionName);return result;
};
function selectedSnapshot() {
  const snapshots=run?.protocol||{};
  if(protocolView==='device')return snapshots.proof||snapshots.device||snapshots.derive||snapshots.issue||null;
  if(protocolView==='verify')return snapshots.verify||snapshots.proof||snapshots.derive||snapshots.issue||null;
  if(protocolView==='payment')return snapshots.payment||snapshots.verify||null;
  return snapshots[protocolView]||null;
}
function nextAction() {
  if(!run||invalidated||!run.order||stepStatus('credential')?.status!=='success')return 'prepare';
  if(run.receipt)return 'complete';
  const s=state(),m=s?.manual||{};
  if(s?.proposal)return !bridge.ownerApproved()?'owner':!m.walletSigned?'wallet':'settle';
  if(m.phase!=='proposal'||!m.active)return 'derive';
  if(m.expired||m.expiresAtUnix&&m.expiresAtUnix*1000<=Date.now())return 'derive';
  if(run.failure?.step==='proposal-verify'&&m.stage==='PROOF_READY')return 'derive';
  return ({CHALLENGE_READY:'derive',VC_DERIVED:run.negative?.passed?'device':'negative',DEVICE_SIGNED:'prove',PROOF_READY:'verify',VERIFIED:'submit'})[m.stage]||'derive';
}
function capturePositive() {
  if(!related())return;
  // A completed observation is immutable. Later transfers in the shared test
  // ledger must not be attributed to this order when the page is refreshed.
  if(run.receipt)return;
  const s=state(), m=s.manual;
  const trace=m.verificationResult?.verificationTrace;
  if(trace?.outcome==='pass')run.positive={ time:new Date().toISOString(), phase:m.phase, trace, attemptId:m.attemptId, challengeId:m.challenge?.challengeId, inputHash:m.challenge?.bodyHash, vcHash:m.cryptography?.w3cPresentationHash, bindingId:s.w3c?.originalCredential?.credentialSubject?.bindingId, after:metrics(s) };
  const receipt=receiptFor(s,run.order);
  if(receipt) {
    run.receipt=receipt;run.after=metrics(s);run.status='success';run.stage='complete';run.uncertain=false;
    run.message='本笔订单已结算。下方保留缺设备拒绝与合法请求完成的实际依据。';
  }
}
function updateFromBackend() {
  if(!bridge)return;
  if(run?.order && state()?.available && !related()) {invalidated=true;run.message='后端当前订单、凭证或模式已改变。保留的结果仅属于原输入，请重新运行当前输入。';}
  if(!operating&&related()) {
    if(bridge.ownerApproved()&&!run.approved){run.approved=true;recordStep('owner-approved','用户已明确批准','success');captureProtocol('owner-observed');if(!run.receipt)run.message='用户已明确批准本笔订单。可继续签署付款材料；此时尚未付款。';}
    capturePositive();save();
  }
  render();
}
function render() {
  if(!bridge)return;
  const s=state(), same=related(), pending=pendingPayment(s), old=invalidated||Boolean(run?.order&&s?.available&&!same);
  let validation;try {config();}catch(e){validation=e.message;}
  const available=s?.available===true&&s?.w3c?.enabled===true;
  const status=operating?'running':old?'stale':connectionError?'blocked':run?.status||'idle';
  $('core-status').dataset.state=status;
  text('core-status',`${labels[status]} · ${operating?run?.message||'等待真实后端返回':connectionError||validation||run?.message||'先准备凭证，再逐步查看设备绑定、证明生成与联合验证。'}`);
  text('core-source',available?`${operating?'正在实时执行':run?.restored?run.continuedAfterRestore?'本轮执行记录 · 含刷新恢复的历史步骤':'恢复的历史执行记录 · 未重新计算':run?'本轮实际执行记录':'已连接 · 尚未运行'} · 软件设备 · 本地 TEST_USDC（无真实价值）`:'后端未接入 · 暂无本次执行结果');
  $('core-stale').hidden=!old;
  text('core-stale','输入或后端订单已改变：下方是旧输入的历史结果，不能作为当前输入的验证结论。重新运行将创建新订单。');
  text('core-config',run?.order?`${old?'历史配置':'本次配置'}：${formatUnits(run.config.amountMinor)} TEST_USDC → ${names[run.config.payeeAccount]||run.config.payeeAccount} · ${modeName(run.config.mode)} · 订单 …${run.order.orderId.slice(-8)} · 开始 ${new Date(run.startedAt).toLocaleTimeString('zh-CN',{hour12:false})}`:'本次已提交配置：尚未运行');
  const snapshot=selectedSnapshot(),history=Boolean(snapshot&&(protocolView!==run?.protocolActive||run?.restored));
  const phaseLabel=snapshot?.phase==='authorize'?'付款授权阶段':snapshot?.phase==='settle'?'结算阶段':snapshot?.phase==='proposal'?'提案 / 资格验证阶段':'注册签发阶段';
  renderProtocol({view:protocolView,snapshot,negative:run?.protocol?.negative||null,stale:old,history,phaseLabel});
  text('protocol-context',snapshot?`${old?'旧输入记录':history?'已保存的执行记录':'本次执行记录'} · ${phaseLabel}${snapshot.attemptId?` · 尝试 …${snapshot.attemptId.slice(-8)}`:''} · ${snapshot.observedAt?new Date(snapshot.observedAt).toLocaleTimeString('zh-CN',{hour12:false}):'已记录'}`:'原理关系 · 尚无本次执行数据');
  for(const button of $('protocol-tabs').querySelectorAll('button[data-protocol-view]'))button.setAttribute('aria-pressed',String(button.dataset.protocolView===protocolView));
  $('core-progress').replaceChildren();
  const groups=[['准备输入与凭证',/^(input|credential|challenge|derive)$/,'derive'],['缺设备对照',/^negative$/,'negative'],['绑定设备验证',/^proposal-/,'proposal-verify'],['用户明确确认',/^owner-/,'owner-approved'],['签署付款材料',/^(authorize-|wallet)/,'wallet'],['实际结算',/^settle-/,'settle-verify']];
  const steps=groups.map(([label,pattern,terminal])=>{
    const observed=run?.steps?.filter(step=>pattern.test(step.id))||[],last=observed.at(-1);
    return {label,status:last?.status==='failure'||last?.status==='timeout'||last?.status==='running'?last.status:stepStatus(terminal)?.status==='success'?'success':'idle',detail:last?`${last.label} · ${labels[last.status]||'未运行'}`:'尚未执行'};
  });
  for(const step of steps){const li=document.createElement('li');li.dataset.state=old?'stale':step.status;const title=document.createElement('strong'), detail=document.createElement('span');title.textContent=step.label;detail.textContent=step.detail||labels[step.status]||'未运行';li.append(title,detail);$('core-progress').append(li);}
  const n=run?.negative, p=run?.positive;
  $('core-negative').dataset.state=old?'stale':n?.passed?'success':n?'failure':'idle';
  text('core-negative-status',old&&n?'历史结果 · 当前输入已失效':n?.passed?'请求被拒绝 · 防冒用对照成立':n?'对照未成立，请检查实际原因':'未运行');
  facts('core-negative-facts',n?[
    ['标准凭证',n.standard==='pass'?'有效 · BBS 校验通过':'未通过或未执行'],['设备使用证明',n.code],
    ['付款变化',n.delta.executions===0&&n.delta.payer===0&&n.delta.payee===0?'0 次 · 双方余额未变':'查看实际差值'],['设备签名增量',n.delta.signatures??'未取得数据'],
  ]:[['输入','有效 VC，省略设备证明'],['实际结果','尚未向验证方发送']]);
  text('core-negative-detail',n?JSON.stringify(n,null,2):'尚无本次返回数据。');
  const positiveError=run?.negative?.passed&&run?.failure&&['failure','timeout'].includes(run.status)?run.failure:null;
  $('core-positive').dataset.state=old?'stale':run?.receipt?'success':positiveError?run.status:p?'pending':'idle';
  text('core-positive-status',old&&(p||positiveError)?'历史结果 · 当前输入已失效':run?.receipt?'合法请求完成 · 本地测试币已结算':positiveError?`${labels[run.status]} · ${positiveError.code}`:p?'绑定设备验证通过 · 尚未结算':'未运行');
  const delta=difference(run?.baseline,run?.after||p?.after);
  facts('core-positive-facts',p?[
    ['设备绑定验证',p.trace?.outcome==='pass'?'实际检查通过':'未取得通过记录'],
    ['用户批准',same&&bridge.ownerApproved()||run?.approved?'已明确批准':'待用户确认'],
    ['观察期付款次数增量',run.receipt?delta.executions??'未取得数据':'尚未结算'],
    ['观察期设备签名增量',delta.signatures??'未取得数据'],
  ]:[['输入','同一凭证 + 绑定设备的新贡献'],['实际结果',positiveError?positiveError.message:'等待对照完成后运行']]);
  text('core-positive-detail',p||positiveError?JSON.stringify({config:run.config,order:run.order,steps:run.steps,...p,...(positiveError?{error:positiveError}:{})},null,2):'尚无本次返回数据。');
  const r=run?.receipt;
  const balancesMatch=r&&delta.payer===-r.amountMinor&&delta.payee===r.amountMinor&&delta.executions===1;
  const observedBalances=balancesMatch?`同期余额：付款方 ${formatUnits(delta.payer)} · 商户 +${formatUnits(delta.payee)}`:'同期账本变化未能单独对应本笔，请展开核对';
  text('core-receipt-summary',r?`${old?'历史回执 · ':''}已转账 ${formatUnits(r.amountMinor)} ${r.currency} · ${observedBalances} · 交易 ${r.transactionHash.slice(0,12)}…${r.transactionHash.slice(-8)}`:same&&s?.manual?.walletSigned?'付款材料已签署，尚未结算。下一步会实际转账本地测试币。':'尚未结算 · 不把资格验证或用户批准显示成付款成功');
  text('core-receipt-data',r?JSON.stringify({runId:run.id,config:run.config,baseline:run.baseline,after:run.after,receipt:r},null,2):'暂无本笔付款回执。');
  const next=nextAction();
  let button=({prepare:'准备本次凭证',derive:'派生本次 VC',negative:'仅发送 VC，验证缺设备对照',device:'请求绑定设备贡献',prove:'由 Agent 组合使用证明',verify:'发送并联合验证',submit:'提交用户确认，继续支付演示',owner:'核对并批准本笔订单',wallet:'签署付款材料（不转账）',settle:`验证并结算 ${formatUnits(run?.config?.amountMinor)} TEST_USDC`,complete:'本轮已完成'})[next];
  if(!old&&run?.order){
    if(run.uncertain)button=run.recoveryReady?run.recoveryPhase==='authorize'?'重试原订单付款签署':'重试原订单结算':'核对本次状态后继续';
    else if(next==='derive'&&s?.manual?.expired)button='挑战已过期，重新派生本次 VC';
  }
  text('core-run',operating?'执行中，请等待实际结果':button);
  $('core-run').disabled=operating||bridge.busy()||!available||Boolean(validation)||Boolean(run?.uncertain&&!run?.recoveryReady)||Boolean(!old&&run?.receipt)||Boolean(old&&pending);
  $('core-reset').disabled=operating||bridge.busy()||pending||Boolean(run?.uncertain)||!available;
  $('core-reset').title=pending?'付款签名或结算尚未确认，先核对原订单。':'恢复示例输入，保留原有余额与交易记录。';
  $('core-refresh').disabled=operating||bridge.busy()||checking;
  for(const id of ['core-amount','core-payee','core-mode'])$(id).disabled=operating||bridge.busy()||pending||Boolean(run?.uncertain);
  $('protocol-negative').disabled=operating||bridge.busy()||!same||old||!available||s?.manual?.phase!=='proposal'||!s?.manual?.availableActions?.includes('test-no-device');
  $('protocol-new-challenge').disabled=operating||bridge.busy()||!same||old||pending||!available||Boolean(s?.proposal)||!run?.bindingId;
  $('protocol-negative').hidden=!run?.protocol?.derive||Boolean(s?.proposal);
  $('protocol-new-challenge').hidden=!run?.protocol?.derive||Boolean(s?.proposal);
  $('protocol-details').inert=operating;
}
async function withOperation(work) {
  if(operating||bridge.busy())return;
  operating=true;connectionError=null;render();
  try {await work();}
  catch(error) {
    const failure=errorState(error);
    if(run){run.status=failure.status;run.failure={...failure,step:currentStep,time:new Date().toISOString()};run.message=`${failure.code}：${failure.message}`;run.uncertain=failure.status==='timeout';run.recoveryReady=false;if(currentStep)recordStep(currentStep,stepStatus(currentStep)?.label||'当前操作',failure.status,failure.code);
      const observedAction=({'proposal-device':'device-sign','proposal-proof':'prove','proposal-verify':'verify',derive:'derive-vc',negative:'test-no-device'})[currentStep];
      if(observedAction)captureProtocol(observedAction);
    }
    else connectionError=failure.message;
  } finally {currentStep=null;operating=false;save();render();}
}
async function beginRun() {
  const input=config();
  if(pendingPayment(state()))throw new Error('本笔付款结果尚未确认，不能创建新订单。');
  run={version:2,id:crypto.randomUUID(),config:input,order:null,startedAt:new Date().toISOString(),steps:[],protocol:{},status:'running',message:'正在准备本次订单并共同签发标准 VC 与设备绑定材料。',stage:'prepare'};
  protocolView='issue';
  invalidated=false;save();
  if(state()?.manual?.active)await bridge.action('discard');
  await bridge.selectMode(input.mode);
  if(state()?.manual?.active)await bridge.action('discard');
  await action('input','提交示例订单',()=>bridge.action('new',{amountMinor:input.amountMinor,payeeAccount:input.payeeAccount}));
  if(!inputMatches(input,state()))throw new Error('后端订单与本次输入不一致，已停止。');
  run.order=structuredClone(state().order);
  await action('credential','准备真实支付凭证',()=>bridge.action('issue'));
  run.bindingId=state().w3c?.originalCredential?.credentialSubject?.bindingId;
  run.baseline=metrics(state());
  captureProtocol('issue');
  run.status='success';run.stage='issued';run.message='共同签发完成。两份材料记录相同 bindingId，设备公钥被纳入论文凭证关系；尚未向 B 验证。';
}
async function deriveRun() {
  if(!related())throw new Error('当前订单或凭证已改变，请重新准备。');
  run.message='申请绑定精确订单的挑战，再派生标准 VC。此步不请求设备签名。';
  await manualAction('begin-proposal','challenge','获取订单挑战');
  // A new challenge invalidates downstream device/proof observations. Keep
  // the separate negative record with its own original attempt identifiers.
  delete run.protocol.device;delete run.protocol.proof;delete run.protocol.verify;
  run.steps=run.steps.filter(step=>!step.id.startsWith('proposal-')&&step.id!=='owner-proposal');
  run.positive=null;run.failure=null;
  await manualAction('derive-vc','derive','派生标准 VC');
  run.status='success';run.stage='derived';run.message='本次 VC 已派生：公开 5 项声明、隐藏 2 项。PH 绑定挑战，hVC 固定本次派生文档；尚未调用设备。';
}
async function negativeRun() {
  if(!related())throw new Error('当前订单或凭证已改变，请重新准备。');
  run.message='向 B 发送真实派生 VC，但省略设备使用证明。';
  const before=metrics(state());
  await manualAction('test-no-device','negative','发送缺设备请求');
  run.negative={...noDeviceEvidence(state(),before),time:new Date().toISOString(),orderId:run.order.orderId,bindingId:run.bindingId,attemptId:state().manual.attemptId,challengeId:state().manual.challenge?.challengeId,inputHash:state().manual.challenge?.bodyHash,vcHash:state().manual.cryptography?.w3cPresentationHash,before,after:metrics(state())};
  if(!run.negative.passed){recordStep('negative','发送缺设备请求','failure',run.negative.code);throw new Error(`缺设备对照未满足验收条件：${run.negative.code}。已停止后续付款。`);}
  run.status='success';run.stage='negative';run.message='有效凭证通过标准校验，因缺设备证明被拒绝；付款与设备签名均未增加。';
}
async function advance() {
  const next=nextAction();
  if(next==='prepare')return beginRun();
  if(!related())throw new Error('本次订单与后端状态不一致，请重新准备。');
  if(next==='derive')return deriveRun();
  if(next==='negative')return negativeRun();
  if(['device','prove','verify'].includes(next)){
    const settings={device:['device-sign','proposal-device','请求绑定设备贡献','设备返回贡献，尚未组合证明。请比较设备返回值与后续发给 B 的适配值。'],prove:['prove','proposal-proof','Agent 组合使用证明','Agent 已组合适配贡献、随机化凭证与知识证明。此时 B 尚未验证。'],verify:['verify','proposal-verify','发送并联合验证','联合验证通过。查看 B 实际重建的挑战和配对结果；此时尚未付款。']};
    const [op,id,label,message]=settings[next];
    run.message=`正在${label}，等待真实执行返回。`;
    await manualAction(op,id,label);
    if(next==='verify'){
      if(state().manual.verificationResult?.verificationTrace?.outcome!=='pass')throw new Error('未取得 B 的实际通过记录。');
      capturePositive();
    }
    run.failure=null;run.status='success';run.stage=next;run.message=message;return;
  }
  return continueRun();
}
async function verifiedPhase(phase, id) {
  const m=state().manual;
  const expired=m.expired||m.expiresAtUnix&&m.expiresAtUnix*1000<=Date.now();
  // A verifier may have consumed the challenge before a transport/settlement
  // failure. Explicit recovery keeps the order but generates a new proof.
  const freshProof=run.recoveryPhase===phase||run.failure?.step===`${id}-verify`;
  if(!m.active||m.phase!==phase||expired||freshProof){await manualAction(`begin-${phase}`,`${id}-challenge`,`${phase==='proposal'?'资格':phase==='authorize'?'付款授权':'结算'}：新挑战`);run.recoveryPhase=null;}
  if(state().manual.stage==='CHALLENGE_READY')await manualAction('derive-vc',`${id}-derive`,'派生本阶段 VC');
  if(state().manual.stage==='VC_DERIVED')await manualAction('device-sign',`${id}-device`,'请求绑定设备贡献');
  if(state().manual.stage==='DEVICE_SIGNED')await manualAction('prove',`${id}-proof`,'生成设备使用证明');
  if(state().manual.stage==='PROOF_READY')await manualAction('verify',`${id}-verify`,phase==='settle'?'验证并执行结算':'验证凭证与设备');
  const trace=state().manual.verificationResult?.verificationTrace;
  if(trace?.outcome!=='pass')throw new Error('未取得本阶段的真实验证通过记录，已停止。');
  capturePositive();
}
async function continueRun() {
  if(!related())throw new Error('本次订单与后端状态不一致，请重新运行。');
  if(run.uncertain&&!run.recoveryReady)throw new Error('请先核对原订单真实状态，再明确恢复。');
  run.uncertain=false;run.recoveryReady=false;
  run.status='running';
  if(!state().proposal){
    if(state().manual.phase!=='proposal'||state().manual.verificationResult?.verificationTrace?.outcome!=='pass')throw new Error('先完成本阶段的联合验证，再提交用户确认。');
    run.message='将 B 的真实验证证据提交给 Owner，仍需逐笔明确批准。';
    await manualAction('submit-owner','owner-proposal','提交用户确认');
    run.status='pending';run.stage='owner';run.message='设备参与已通过验证。请核对本笔订单并明确批准；此时尚未付款。';
  } else if(!bridge.ownerApproved()) {
    run.status='pending';run.message='等待用户在订单核对框中明确批准。';
    await bridge.openOwner();
  } else if(!state().manual.walletSigned) {
    run.message='用户已批准，正在生成付款授权阶段的新证明。';
    await manualAction('sync-owner','owner-approved','同步用户明确授权');run.approved=true;
    await verifiedPhase('authorize','authorize');
    await manualAction('wallet-sign','wallet','钱包签署付款材料');
    run.status='pending';run.stage='signed';run.message='付款材料已签署，余额尚未改变。点击最终结算才提交本地测试币转账。';
  } else {
    run.message='正在生成结算阶段的新证明并提交本笔转账；请等待真实回执。';
    await verifiedPhase('settle','settle');capturePositive();
    if(!run.receipt)throw new Error('验证返回但尚未读到匹配本笔输入的成功回执，请核对原订单。');
  }
}
async function reconcile() {
  if(operating||bridge.busy())return;checking=true;render();
  try {
    await bridge.read();connectionError=null;
    if(related()){
      capturePositive();
      if(!run.receipt){
        const m=state().manual;
        // Reading never repeats signing or settlement. A missing response is
        // recoverable only after the backend has returned its current state.
        const phase=(run.uncertain||m.walletSigningUnconfirmed)?recoveryPhase(state()):null;
        run.uncertain=Boolean(phase);run.recoveryReady=Boolean(phase);run.recoveryPhase=phase;
        if(run.uncertain){run.status='timeout';run.message=phase==='authorize'?'已核对原订单，钱包签名结果仍未确认。可明确重试原订单签署；禁止换单。':'已核对原订单，尚未取得成功回执。可明确用新证明重试原订单结算；禁止换单。';}
        else if(run.status!=='failure'){run.status='pending';run.message='已读取原订单真实状态；后续操作仍需明确点击。';}
      }
    } else if(run?.uncertain && !pendingPayment(state()) && !run.approved && !run.steps.some(step=>step.id==='wallet')) {
      // Preparation/new-order responses may be lost before an order ID is
      // known. A fresh read permits an explicit restart, never an inferred
      // success or an automatic financial retry.
      run.uncertain=false;invalidated=true;run.status='stale';
      run.message='已读取后端且当前没有待确认付款。旧准备结果不再使用，请明确重新运行。';
    }
  }catch(error){connectionError=error.message;}finally{checking=false;save();render();}
}
async function reset() {
  await withOperation(async()=>{
    if(pendingPayment(state())||run?.uncertain)throw new Error('原订单付款状态尚未确认，不能重置。');
    if(state()?.manual?.active)await bridge.action('discard');
    await bridge.selectMode(DEFAULT_INPUT.mode);
    if(state()?.manual?.active)await bridge.action('discard');
    await bridge.action('new',{amountMinor:2990000,payeeAccount:DEFAULT_INPUT.payeeAccount});
    applyDraft(DEFAULT_INPUT);run=null;invalidated=false;protocolView='issue';
  });
}
function init() {
  bridge=window.DemoManual;restore();
  $('core-form').addEventListener('submit',event=>event.preventDefault());
  for(const id of ['core-amount','core-payee','core-mode'])$(id).addEventListener('input',()=>{if(run)invalidated=true;save();render();});
  $('core-run').addEventListener('click',()=>void withOperation(()=>advance()));
  $('core-reset').addEventListener('click',()=>void reset());$('core-refresh').addEventListener('click',()=>void reconcile());
  $('protocol-negative').addEventListener('click',()=>void withOperation(()=>negativeRun()));
  $('protocol-new-challenge').addEventListener('click',()=>void withOperation(()=>deriveRun()));
  for(const button of $('protocol-tabs').querySelectorAll('button[data-protocol-view]'))button.addEventListener('click',()=>{protocolView=button.dataset.protocolView;save();render();});
  window.addEventListener('manual:state',updateFromBackend);
  window.addEventListener('demo:activate',()=>void reconcile());
  if(run)text('core-source','历史会话记录 · 正在向后端核对');
  void reconcile();render();
}
if(window.DemoManual)init();else window.addEventListener('manual:ready',init,{once:true});
