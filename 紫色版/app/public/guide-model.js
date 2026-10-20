// Presentation only: the server owns protocol state and every security decision.
const phases = ['proposal', 'authorize', 'settle'];
const phaseNames = { proposal: '资格认证', authorize: '付款前再次认证', settle: '结算认证' };
const groups = [
  ['credential', '凭证真实性', ['w3c_bbs'], '核验可信签发方、标准 BBS 派生证明与 VC 有效期。'],
  ['participation', '持有者与设备共同参与', ['vc_device_binding', 'schema', 'proof_structure', 'proof_encoding', 'disclosure', 'knowledge', 'credential_pairing', 'device_pairing', 'holder_signature'], '持有者签名、设备贡献和两份材料的绑定分别核验。'],
  ['validity', '挑战时效与凭证状态', ['challenge', 'policy_context', 'credential_status'], '挑战有效期、资格日期与撤销状态是不同检查，均以本次记录为准。'],
  ['request', '本次请求绑定与防重放', ['extension', 'envelope', 'request_binding', 'scope', 'replay', 'consume'], '核对本次订单正文、调用范围和一次性挑战。'],
];
const stepsOf = trace => Array.isArray(trace?.steps) ? trace.steps.filter(step => step && typeof step.id === 'string') : [];
const failed = step => step.status === 'fail' || Array.isArray(step.evidence) && step.evidence.some(row => row?.match === false);
function statusFor(trace, ids) {
  const steps = stepsOf(trace).filter(step => ids.includes(step.id));
  if (trace?.source !== 'agent-b') return { status: 'pending', steps };
  if (steps.some(failed)) return { status: 'fail', steps };
  if (!ids.every(id => steps.filter(step => step.id === id).length === 1)) return { status: 'pending', steps };
  if (steps.every(step => step.status === 'pass')) return { status: 'pass', steps };
  if (steps.every(step => step.status === 'skipped')) return { status: 'skipped', steps };
  return { status: 'pending', steps };
}
export function verificationSummary(trace) {
  return groups.map(([id, title, ids, explanation]) => {
    const { status, steps } = statusFor(trace, ids);
    const detail = ({ pass: '本组必要检查均有唯一的通过记录。', fail: '本组存在失败或实际观测不匹配，请展开拒绝依据。', skipped: '本组检查均未执行，不能推断通过。', pending: '尚无完整、一致的验证者 B 记录。' })[status];
    return { id, title, status, detail: `${detail}${explanation}`, steps };
  });
}
function observedPhase(trace) {
  const values = stepsOf(trace).flatMap(step => (Array.isArray(step.evidence) ? step.evidence : []).flatMap(row => {
    if (!Array.isArray(row?.observed)) return [];
    if (step.id === 'scope' && row.label === 'method / scope / phase') return [row.observed[2]];
    if (step.id === 'execution' && row.label === 'phase / resulting task') return [row.observed[0]];
    return [];
  })).filter(value => phases.includes(value));
  return [...new Set(values)];
}
export function verificationVerdict(trace, { phase } = {}) {
  const result = (status, title, detail) => ({ status, title, detail });
  if (trace?.source !== 'agent-b') return result('pending', '尚未取得验证结论', '请求准备或通信状态不能代替验证者 B 的结论。');
  const steps = stepsOf(trace), failure = steps.find(failed);
  if (failure) return result('fail', '本次请求未通过验证', `${failure.title || failure.id}${failure.code ? `（${failure.code}）` : ''}；后续未执行项不代表通过。`);
  const observed = observedPhase(trace);
  if (!phases.includes(phase) || observed.some(value => value !== phase)) return result('pending', '验证阶段需要核对', '缺少当前阶段，或记录中的阶段与当前请求不一致。');
  if (trace.profile !== 'dbac-payment' || trace.outcome !== 'pass' || new Set(steps.map(step => step.id)).size !== steps.length
    || steps.some(step => !['pass', 'fail', 'skipped'].includes(step.status)))
    return result('pending', '验证记录需要核对', '记录类型、结论或检查项数量不一致，不能宣布通过。');
  const required = [...groups.flatMap(([, , ids]) => ids), 'execution', ...(phase !== 'proposal' ? ['owner_authorization'] : []), ...(phase === 'settle' ? ['task_binding', 'settlement_gate'] : [])];
  if (statusFor(trace, required).status !== 'pass') return result('pending', '验证记录尚不完整', '本阶段的必要检查存在缺失、未执行或待确认项。');
  return result('pass', phase === 'proposal' ? '本次凭证使用资格验证通过' : phase === 'authorize' ? '付款前核验通过' : '本次结算验证通过', phase === 'settle' ? '支付是否完成仍须核对当前订单的实际回执。' : '认证通过不等于用户批准，用户批准不等于付款完成。');
}

function receiptFor(state) {
  const order = state?.order;
  if (!order?.orderId) return null;
  for (const value of [state?.manual?.verificationResult?.paymentResult, state?.lastResult?.paymentResult]) {
    const receipt = value?.receipt;
    if (!['EXECUTED', 'ALREADY_PROCESSED'].includes(value?.outcome) || receipt?.orderId !== order.orderId) continue;
    if (!['amountMinor', 'currency', 'payerAccount', 'payeeAccount'].every(key => order[key] !== undefined && receipt[key] === order[key])) continue;
    const settlement = order.settlement;
    if (settlement && !['network', 'asset', 'payerAddress', 'payTo'].every(key => receipt.settlement?.[key] === settlement[key])) continue;
    return value;
  }
  return null;
}
function credentialProblem(state, now) {
  const status = state.credentialStatus || {};
  if (status.revoked === true || status.status === 'revoked') return '当前凭证已撤销，不能继续正常付款；请到凭证与设备查看或选择有效凭证。';
  if (status.available === false || status.status === 'unknown') return '凭证状态尚未确认，请重新读取后端状态；不能推断凭证有效。';
  const original = state.w3c?.originalCredential;
  if (['validFrom', 'validUntil'].some(key => original?.[key] && !Number.isFinite(Date.parse(original[key])))) return '当前 VC 时间信息无法解析，请刷新并核对原始文档。';
  if (status.status === 'expired' || original?.validUntil && Date.parse(original.validUntil) <= now) return '当前 VC 已过有效期，请准备有效凭证后再开始新演示。';
  if (original?.validFrom && Date.parse(original.validFrom) > now) return '当前 VC 尚未生效，请核对凭证时间。';
  return '';
}
const catalog = {
  issue: ['准备演示凭证', '签发测试 VC 并准备绑定设备材料。', 'prepare'],
  new: ['创建下一笔模拟订单', '保留已有回执，创建需要重新认证和明确授权的新订单。', 'prepare'],
  'begin-proposal': ['获取资格认证挑战', '为当前订单申请新挑战，再生成凭证披露材料与双方证明并提交验证。', 'request'],
  'derive-vc': ['生成本次派生凭证', '根据本次挑战生成选择性披露证明。', 'proof'],
  'device-sign': ['请求模拟 eSIM 贡献', '软件设备为本次请求生成签名贡献。', 'proof'],
  prove: ['生成持有者证明并组合', '持有者 A 核验设备贡献，再生成绑定本次请求的持有者签名与证明。', 'proof'],
  verify: ['提交本次证明验证', '由验证者 B 核验实际提交的凭证与使用证明。', 'result'],
  'submit-owner': ['提交付款授权申请', '发送已经核验的订单，等待用户逐笔批准。', 'result'],
  'owner-review': ['核对并决定付款授权', '打开当前订单条款，由用户明确批准或拒绝；批准本身不付款。', 'result'],
  'sync-owner': ['同步付款授权', '读取当前订单的用户决定和授权，不代替用户批准。', 'result'],
  'begin-authorize': ['获取付款前核验挑战', '沿用已批准订单，再次生成绑定用户授权的双方证明。', 'request'],
  'wallet-sign': ['签署本笔付款材料', '钱包独立核验本笔授权和验证证据；此步尚不转账。', 'proof'],
  'begin-settle': ['获取结算挑战', '保留原订单与已签付款材料，为结算生成新的双方证明。', 'request'],
  discard: ['结束本次认证', '结束当前挑战，保留订单、授权、已签付款材料及已有回执。', 'result'],
  complete: ['本次流程已结束', '查看本次结果与验证依据。', 'result'],
  refresh: ['刷新并核对状态', '重新读取后端状态，不签名、不新建订单或付款。', 'prepare'],
};
export function planPayment(state, { now = Date.now(), ownerAvailable = false } = {}) {
  const m = state?.manual || {}, available = new Set(m.availableActions || []);
  const plan = (id, { enabled, reason = '', label, description } = {}) => {
    const [defaultLabel, defaultDescription, step] = catalog[id];
    return { id, label: label || defaultLabel, description: description || defaultDescription, enabled: enabled ?? available.has(id), reason, step };
  };
  const read = reason => plan('refresh', { enabled: true, reason });
  if (state?.available !== true || !state.manual) return read('尚未取得可用的后端状态。');
  const receipt = receiptFor(state);
  if (receipt && (m.walletSigningUnconfirmed || state.paymentPending && !m.settled)) return read('已有匹配回执，但后端仍标记付款待确认；请核对原订单状态后再创建下一笔。');
  if (receipt) return m.active ? plan('discard', { label: '结束本次演示', description: '本订单已有匹配的实际回执；结束认证后仍可查看回执。' }) : plan('new', { enabled: true });
  if (m.settled) return read('后端标记已结算，但当前订单的匹配回执尚未确认；请保留原订单。');
  if (m.walletSigningUnconfirmed) return read('钱包签名结果尚未确认；请保留原订单，不能重新签名或新建订单。');
  if (state.paymentPending && !m.walletSigned) return read('原订单的付款结果尚待核对；当前没有可继续结算的已确认钱包材料。');
  if (!state.order?.orderId) return read('当前订单尚未载入。');
  if (!state.credential) {
    if (m.active || state.proposal || state.authorization || m.walletSigned) return read('当前订单仍有关联流程，但凭证材料未载入；请保留上下文并核对状态。');
    return plan('issue', { enabled: true });
  }
  const problem = credentialProblem(state, now);
  if (problem) return plan('refresh', { enabled: true, reason: `${problem}${m.walletSigned ? ' 已签付款材料仍保留，不能更换原订单。' : ''}` });
  const deadline = Number.isFinite(m.expiresAtUnix) ? m.expiresAtUnix * 1000 : null;
  const expired = m.active && (m.expired === true || m.stage === 'EXPIRED' || deadline !== null && deadline <= now);
  const nextProof = () => {
    const action = { CHALLENGE_READY: state.w3c?.enabled === false ? 'device-sign' : 'derive-vc', VC_DERIVED: 'device-sign', DEVICE_SIGNED: 'prove', PROOF_READY: 'verify' }[m.stage];
    if (!action) return null;
    return plan(action, { label: action === 'verify' && m.phase === 'settle' ? '提交结算验证并执行模拟支付' : undefined, description: `${phaseNames[m.phase]}：${catalog[action][1]}${m.phase === 'settle' && action === 'verify' ? '只有本次操作通过并返回匹配回执，才表示测试代币支付完成。' : ''}`, reason: available.has(action) ? '' : '后端当前未开放此操作，请刷新核对。' });
  };
  if (m.walletSigned) {
    if (m.active && m.phase === 'settle' && !expired) return nextProof() || read('当前结算阶段需要核对；保留原订单和付款材料。');
    return plan('begin-settle', { reason: expired ? '本阶段材料已过期，需要为原订单取得新的结算挑战。' : available.has('begin-settle') ? '' : '已有钱包签名，但后端未开放结算入口，请刷新核对。' });
  }
  if (['REJECTED', 'EXPIRED'].includes(state.proposal?.status)) {
    const reason = state.proposal.status === 'REJECTED' ? '用户已拒绝本笔付款授权，不能继续本次付款。' : '付款授权申请已过期，不能沿用原申请继续付款。';
    return m.active ? plan('discard', { label: '结束本次付款尝试', reason }) : plan('new', { enabled: true, label: '创建新订单重新申请', reason });
  }
  if (state.proposal?.status === 'PENDING' && !state.authorization) return plan('owner-review', { enabled: ownerAvailable && state.owner?.available !== false, reason: state.owner?.available === false ? '付款授权服务不可用，请先核对连接。' : ownerAvailable ? '' : '尚未载入用户付款授权权限；可在付款授权入口载入。' });
  if (state.proposal?.status === 'APPROVED' && !state.authorization) return plan('sync-owner', { reason: '用户已批准，需同步原订单授权后继续。' });
  if (state.authorization && state.proposal?.status !== 'APPROVED') return read('付款授权材料与当前用户决定不一致，请核对原订单状态。');
  if (m.active && expired) {
    const phase = phases.includes(m.phase) ? m.phase : null;
    return phase ? plan(`begin-${phase}`, { reason: '本阶段挑战或验证证据已过期，需要重新生成本阶段的证明。' }) : read('过期记录未提供有效阶段，不能猜测重启位置。');
  }
  if (m.active) {
    if (!phases.includes(m.phase)) return read('当前认证阶段无法识别。');
    const proof = nextProof();
    if (proof) return proof;
    if (m.stage === 'VERIFIED') {
      const verdict = verificationVerdict(m.verificationResult?.verificationTrace, { phase: m.phase });
      if (verdict.status !== 'pass') return read(verdict.detail);
      if (m.phase === 'proposal') return plan('submit-owner');
      if (m.phase === 'authorize') return plan('wallet-sign');
      return read('结算验证已返回，但匹配回执尚未确认。');
    }
    if (m.stage === 'OWNER_SUBMITTED' && state.authorization) return plan('begin-authorize');
    return read('当前步骤尚未取得可继续的状态，请核对后端记录。');
  }
  if (state.authorization) return plan('begin-authorize');
  if (state.proposal) return plan('sync-owner', { reason: '先核对现有授权申请，避免重复提交。' });
  return plan('begin-proposal');
}

function milestoneContextMatches(state, { trace, credential }) {
  const original = state.w3c?.originalCredential?.credentialSubject, subject = credential?.credentialSubject;
  const bindingId = original?.bindingId;
  if (!state.order?.orderId || !bindingId || !subject || subject.bindingId !== bindingId || subject.mode !== state.mode) return false;
  const evidence = stepsOf(trace).flatMap(step => (Array.isArray(step.evidence) ? step.evidence : []).map(row => ({ id: step.id, ...row })));
  const orders = evidence.filter(row => row.id === 'scope' && row.label === 'payment order ID');
  const bindings = evidence.filter(row => row.id === 'vc_device_binding' && row.label === 'bindingId / mode / device contribution');
  if (orders.length !== 1 || orders[0].expected !== state.order.orderId || orders[0].observed !== state.order.orderId
    || bindings.length !== 1 || bindings[0].expected?.[0] !== bindingId || bindings[0].observed?.[0] !== bindingId || bindings[0].observed?.[1] !== state.mode) return false;
  // Optional disclosure can change without changing bindingId. The sent VC,
  // rather than the proof's current phase, identifies the policy actually used.
  const paths = state.w3c?.disclosedPaths;
  if (!Array.isArray(paths) || !paths.length || paths.some(path => typeof path !== 'string' || !/^\/credentialSubject\/[^/]+$/.test(path))) return false;
  const disclosed = paths.map(path => path.slice('/credentialSubject/'.length));
  return Object.keys(subject).length === disclosed.length && disclosed.every(key => Object.hasOwn(original, key)
    && Object.hasOwn(subject, key) && subject[key] === original[key]);
}

// A visible completion requires the current verifier response and its sent VC,
// not a previous phase's milestone or an optimistic client action.
export function currentVerificationCompletion(state, {now=Date.now(),uncertain=false}={}) {
  const m=state?.manual||{},result=m.verificationResult;
  if(uncertain||state?.available!==true||!state.credential||credentialProblem(state,now)||m.active!==true||m.lastError||m.expired||m.stage==='EXPIRED'
    ||Number.isFinite(m.expiresAtUnix)&&m.expiresAtUnix*1000<=now
    ||!['proposal','authorize'].includes(m.phase)||!['VERIFIED','OWNER_SUBMITTED'].includes(m.stage)
    ||result?.mode!==state.mode||result?.phase!==m.phase||result?.accepted!==true) return null;
  if(result.wire?.context?.challengeId&&result.wire.context.challengeId!==m.challenge?.challengeId)return null;
  const trace=result.verificationTrace,credential=m.sentCredential||result.wire?.proof?.verifiableCredential;
  if(stepsOf(trace).some(step=>(Array.isArray(step.evidence)?step.evidence:[]).some(row=>row.label==='hVC: derived credential hash'&&m.cryptography?.w3cPresentationHash&&row.observed!==m.cryptography.w3cPresentationHash)))return null;
  if(!milestoneContextMatches(state,{trace,credential})||verificationVerdict(trace,{phase:m.phase}).status!=='pass')return null;
  return m.phase==='proposal'
    ? {title:'验证者 B 已确认本次凭证使用资格',detail:state.proposal?'本笔授权状态见上方当前结果；尚未付款。':'尚未申请用户付款授权、尚未付款。下一步提交本笔条款给用户。'}
    : {title:'验证者 B 已通过付款前复核',detail:'尚未进行钱包签名、尚未付款。下一步由钱包核验并签署本笔付款材料。'};
}

export function paymentMilestones(state) {
  const m = state?.manual || {}, rows = [
    ['prepare', '准备凭证与订单'], ['qualification', '资格认证'], ['owner', '用户付款授权'],
    ['authorize', '付款前再次核验'], ['wallet', '钱包签署材料'], ['settle', '结算与模拟支付'],
  ].map(([id, title]) => ({ id, title, status: 'pending', detail: '尚无本步骤完成记录。' }));
  const set = (id, status, detail) => Object.assign(rows.find(row => row.id === id), { status, detail });
  if (state?.available !== true) return rows;
  if (state.credential && state.order?.orderId) set('prepare', 'pass', '后端已返回当前凭证与订单；凭证有效性仍由本次验证确认。');
  const records = [];
  let sent;
  for (const record of m.log || []) {
    if (record.from === 'agent-a' && record.action === 'verify' && record.status === 'sent') sent = record.data;
    if (record.from !== 'agent-b' || record.action !== 'verify' || !record.data?.verificationTrace) continue;
    const trace = record.data.verificationTrace, values = observedPhase(trace);
    const data = sent?.body?.params?.message?.parts?.[0]?.data;
    if (values.length === 1 && data?.phase === values[0] && data.payment?.orderId === state.order?.orderId)
      records.push({ trace, phase: values[0], credential: sent.verifiableCredential });
    sent = undefined;
  }
  // Current snapshots follow historical records so an older pass cannot
  // overwrite a newer result. History remains available in the message log.
  for (const result of [state.lastResult, m.verificationResult]) if (result?.verificationTrace) records.push({
    trace: result.verificationTrace, phase: result.phase || (result === m.verificationResult ? m.phase : undefined),
    credential: result.wire?.proof?.verifiableCredential || (result === m.verificationResult ? m.sentCredential : undefined),
  });
  if (m.lastError?.verificationTrace && phases.includes(m.phase)) records.push({ trace: m.lastError.verificationTrace, phase: m.phase, currentError: true });
  for (const phase of ['proposal', 'authorize']) {
    const record = records.filter(record => record.phase === phase).at(-1);
    if (!record) continue;
    const verdict = record.currentError || milestoneContextMatches(state, record) ? verificationVerdict(record.trace, { phase })
      : { status: 'pending', detail: '保存的验证记录与当前订单、凭证或披露策略不一致，或缺少对应发送材料；旧记录仅供历史回看。' };
    set(phase === 'proposal' ? 'qualification' : 'authorize', verdict.status, verdict.detail);
  }
  if (state.authorization && state.proposal?.status === 'APPROVED') set('owner', 'pass', '本订单授权已批准并同步；这不表示付款完成。');
  else if (['REJECTED', 'EXPIRED'].includes(state.proposal?.status)) set('owner', 'fail', state.proposal.status === 'REJECTED' ? '用户已拒绝本笔付款授权。' : '当前授权申请已过期。');
  else if (state.proposal) set('owner', 'pending', state.proposal.status === 'APPROVED' ? '用户已批准，原订单授权尚待同步。' : '申请已提交，等待用户明确决定。');
  if (m.walletSigningUnconfirmed) set('wallet', 'pending', '已请求钱包签名，结果尚未确认；保留原订单。');
  else if (m.walletSigned) set('wallet', 'pass', '钱包已返回本订单付款材料；签名本身不转账。');
  if (receiptFor(state)) set('settle', 'pass', '后端已返回与当前订单条款匹配的模拟支付回执。');
  else if (state.paymentPending || m.walletSigned || m.walletSigningUnconfirmed || m.settled) set('settle', 'pending', '尚未确认当前订单的匹配回执，请保留原订单继续核对。');
  return rows;
}
