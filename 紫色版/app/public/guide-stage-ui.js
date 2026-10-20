import { verificationEvidenceModel } from './guide-evidence.js';
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const labels = {pass:'验证通过',fail:'请求被拒绝',skipped:'未执行',pending:'尚未提交',unknown:'结果待核对',running:'请求处理中'};
const names = {w3c_bbs:'标准 BBS 凭证',holder_signature:'持有者签名',vc_device_binding:'凭证设备绑定',device_pairing:'本次设备贡献',credential_status:'凭证状态',owner_authorization:'单笔付款授权',execution:'阶段业务结果'};
/** A concise view of the same trace, with every failure always exposed. */
export function renderCheckPreview(trace, {phase, running=false}={}) {
  const model=verificationEvidenceModel(trace,{phase,running});
  const failures=model.steps.filter(step=>step.status==='fail');
  const selected=model.steps.filter(step=>Object.hasOwn(names,step.id)||step.status==='fail');
  if(!trace&&!running)return '<p class="stage-check-intent">本步将检查：标准 BBS 凭证、持有者签名、设备绑定与贡献、凭证状态及本次请求。尚未提交验证。</p>';
  const badges=selected.map(step=>`<button type="button" class="stage-check-link" data-scene-evidence="check:${escape(step.id)}" data-state="${step.status}"><span>${escape(names[step.id]||step.title)}</span><strong>${labels[step.status]||'结果待核对'}</strong></button>`).join('');
  return model.anomalies.map(text=>`<p class="guide-block">${escape(text)}</p>`).join('')+`<div class="stage-check-preview">${badges}</div>`+failures.map(step=>`<p class="stage-visible-failure">${escape(step.title)}：${escape([step.code,step.detail].filter(Boolean).join(' · ')||'请核对本次失败记录')}</p>`).join('');
}
export function renderStepBrief(panel) {
  const selected=panel.facts.filter(([label])=>['证明模式','用户授权','材料来源','模拟 eSIM'].includes(label));
  return (panel.purpose?`<p class="stage-round-note">本轮：${escape(panel.purpose.title)} · 第 ${panel.purpose.round} / 3 轮证明 · 新挑战与新贡献</p>`:'')+(selected.length?`<dl class="stage-brief">${selected.map(([label,value])=>`<div><dt>${escape(label)}</dt><dd>${escape(value)}</dd></div>`).join('')}</dl>`:'');
}
/** Dialog focus follows the invoking read-only control, even after re-render. */
export function installDialogFocus(dialog, fallback) {
  let previous;
  const open=()=>{previous=document.activeElement; if(!dialog.open)dialog.showModal();};
  dialog.addEventListener('close',()=>{const target=previous?.isConnected?previous:fallback();target?.focus({preventScroll:true});});
  return open;
}
