import { verificationVerdict } from './guide-model.js';
import { renderVerificationChecks } from './guide-evidence.js';
// Public presentation only. Value comparisons here never replace B's verification.
const escape = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
const own = (value, key) => Boolean(value && typeof value === 'object' && Object.hasOwn(value, key));
const present = value => value !== undefined && value !== null && value !== '';
const fields = [
  ['role', '角色'], ['scope', '调用权限'], ['epoch', '策略日期'], ['mode', '设备模式'],
  ['bindingId', '绑定标识'], ['holderDid', '持有者公钥标识'], ['organization', '组织'], ['holderLabel', '持有者标签'],
];
const phaseLabels = { proposal: '资格认证', authorize: '付款前再次核验', settle: '结算验证' };
const phasePurposes = {
  proposal: { round: 1, title: '资格认证', purpose: '确认持有者 A 与绑定设备能为当前订单提出付款申请。', input: '当前订单 + 本轮新挑战', next: '通过后可提交用户授权申请；本轮不调用钱包签名或付款。' },
  authorize: { round: 2, title: '授权后付款复核', purpose: '重新核验当前订单，并将本轮证明与用户已批准的单笔授权绑定，供钱包独立核对。', input: '原订单 + 用户授权 + 本轮新挑战', next: '通过后可请求钱包签署付款材料；本轮尚未转账。' },
  settle: { round: 3, title: '结算验证', purpose: '将本轮新证明与原订单、单笔授权及已签付款材料绑定，核对支付任务连续性。', input: '原订单 + 用户授权 + 已签付款材料 + 本轮新挑战', next: '最终提交通过并返回匹配本订单的回执，才表示模拟支付完成。' },
};
const scalarText = value => value === null ? 'null' : ['string', 'number', 'boolean'].includes(typeof value) ? String(value) : '[非预期字段类型]';
const equal = (left, right) => present(left) && present(right) && ['string', 'number', 'boolean'].includes(typeof left) && typeof left === typeof right && left === right;

function publicValue(value, empty = '尚未生成', limit = 62) {
  if (value === undefined) return `<span class="guide-muted">${escape(empty)}</span>`;
  const text = scalarText(value);
  if (text.length <= limit) return `<span>${escape(text)}</span>`;
  const head = Math.min(24, Math.floor(limit * 0.4)), tail = Math.min(12, Math.floor(limit * 0.3));
  return `<details class="guide-public-value"><summary title="展开完整公开值，可选择复制">${escape(text.slice(0, head))}…${escape(text.slice(-tail))}</summary><pre tabindex="0">${escape(text)}</pre></details>`;
}
function row(label, key, value, status = '', state = 'pending') {
  return `<div class="guide-material-row" data-field="${escape(key)}" data-state="${escape(state)}"><dt class="guide-material-label">${escape(label)}<code>${escape(key)}</code></dt><dd class="guide-material-value">${publicValue(value)}</dd>${status ? `<dd class="guide-material-status">${escape(status)}</dd>` : ''}</div>`;
}
function rows(items) { return `<dl class="guide-material-rows">${items.map(item => row(...item)).join('')}</dl>`; }
function section(title, summary, content, open = false) {
  return `<details class="guide-material-section"${open ? ' open' : ''}><summary>${escape(title)}<span>${escape(summary)}</span></summary>${content}</details>`;
}
function comparison(label, key, expected, observed, expectedLabel = '本地预期', observedLabel = '实际材料') {
  const state = !present(expected) || !present(observed) ? 'pending' : equal(expected, observed) ? 'pass' : 'fail';
  const status = state === 'pending' ? '材料待齐' : state === 'pass' ? '字段一致' : '字段不一致';
  return `<div class="guide-material-comparison" data-field="${escape(key)}" data-state="${state}"><strong>${escape(label)} <code>${escape(key)}</code></strong><span class="guide-material-status">${status}</span><div class="guide-material-grid"><div><small>${escape(expectedLabel)}</small>${publicValue(expected)}</div><div><small>${escape(observedLabel)}</small>${publicValue(observed)}</div></div></div>`;
}

/** Actual presence in the selected document determines disclosure, never policy alone. */
export function credentialFieldComparison(state) {
  const manual = state?.manual || {}, original = state?.w3c?.originalCredential;
  const sent = manual.sentCredential !== null && manual.sentCredential !== undefined;
  const derived = sent ? manual.sentCredential : manual.verifiableCredential;
  const disclosed = new Set(state?.w3c?.disclosedPaths || []), hidden = new Set(state?.w3c?.hiddenPaths || []);
  return fields.map(([key, label]) => {
    const path = `/credentialSubject/${key}`, sourcePresent = own(original?.credentialSubject, key), targetPresent = own(derived?.credentialSubject, key);
    const policy = disclosed.has(path) ? '披露' : hidden.has(path) ? '隐藏' : '未提供';
    const sourceValue = sourcePresent ? original.credentialSubject[key] : undefined;
    const targetValue = targetPresent ? derived.credentialSubject[key] : undefined;
    let status = 'pending', detail = '派生文档待生成';
    if (derived) {
      if (targetPresent) {
        if (policy === '隐藏') { status = 'fail'; detail = '实际含有该字段，与隐藏策略不符'; }
        else if (!sourcePresent) { status = 'pending'; detail = '文档中存在；原始字段缺失，无法比对'; }
        else if (!equal(sourceValue, targetValue)) { status = 'fail'; detail = '字段不一致'; }
        else { status = 'pass'; detail = sent ? '已发送 · 与原始值一致' : '已披露 · 与原始值一致'; }
      } else if (policy === '披露') { status = 'fail'; detail = '应披露字段缺失'; }
      else { detail = sent ? '文档中不存在 · 未发送此字段' : '文档中不存在 · 未包含此字段'; }
    }
    return { key, label, policy, sourcePresent, targetPresent, sourceValue, targetValue, status, detail };
  });
}

function credentialCards(state) {
  const m = state?.manual || {}, original = state?.w3c?.originalCredential;
  const sent = m.sentCredential !== null && m.sentCredential !== undefined;
  const derived = sent ? m.sentCredential : m.verifiableCredential;
  const comparisonRows = credentialFieldComparison(state);
  const originalRows = comparisonRows.map(item => row(item.label, item.key, item.sourcePresent ? item.sourceValue : undefined, `策略：${item.policy}`));
  const derivedRows = comparisonRows.map(item => row(item.label, item.key, item.targetPresent ? item.targetValue : derived ? '文档中不存在' : undefined, item.detail, item.status === 'pass' ? 'material' : item.status));
  const proof = value => rows([
    ['签名套件', 'cryptosuite', value?.proof?.cryptosuite],
    ['验证公钥引用', 'verificationMethod', value?.proof?.verificationMethod],
    ['证明公开值', 'proofValue', value?.proof?.proofValue],
  ]);
  return `<div class="guide-credential-compare"><article class="guide-credential-card"><div class="guide-material-header"><h4>持有者 A 本地持有 · 原始 VC</h4><span>${original ? '已载入文档' : '待签发'}</span></div><dl class="guide-material-rows">${originalRows.join('')}</dl><div class="guide-material-proof"><strong>签发方的 BBS 基础证明</strong><p>作为选择性披露的输入；原始属性只在本地展示。</p>${proof(original)}</div></article><article class="guide-credential-card"><div class="guide-material-header"><h4>${sent ? '持有者 A 已发送 · 派生 VC' : '持有者 A 将出示 · 派生 VC'}</h4><span>${derived ? sent ? '已发送记录' : '已派生 · 本次文档' : '待生成'}</span></div><dl class="guide-material-rows">${derivedRows.join('')}</dl><div class="guide-material-proof"><strong>标准 BBS 派生证明 π_std</strong><p>${derived ? '逐字段核对实际文档；证明是否通过，以验证者 B 的本轮检查记录为准。' : '取得挑战并执行派生后，才会出现本次证明与实际披露字段。'}</p>${proof(derived)}</div></article></div>`;
}

function challengeDetails(state, plan) {
  const m = state?.manual || {}, c = m.challenge || {};
  return section('本轮挑战与请求绑定', m.challenge ? `${phaseLabels[m.phase] || '阶段待确认'} · ${m.expired ? '本轮已过期' : '已取得挑战材料'}` : '待获取挑战',
    rows([
      ['本轮编号', 'attemptId', m.attemptId ?? undefined], ['挑战编号', 'challengeId', c.challengeId],
      ['一次性随机数', 'nonce', c.nonce], ['请求正文摘要', 'bodyHash', c.bodyHash],
      ['验证方', 'verifier', c.verifier], ['请求目标', 'target', c.target], ['请求方法', 'method', c.method],
      ['挑战失效时刻', 'exp (Unix 秒)', c.exp], ['当前材料有效期', 'expiresAt', m.expiresAt ?? undefined],
      ['派生证明挑战头', 'presentationHeader', m.cryptography?.presentationHeader],
      ['派生 VC 文档摘要', 'w3cPresentationHash', m.cryptography?.w3cPresentationHash],
    ]) + comparison('挑战绑定订单', 'paymentOrderId', state?.order?.orderId, c.paymentOrderId, '当前订单 orderId', '挑战 paymentOrderId')
      + comparison('挑战调用范围', 'scope', state?.w3c?.originalCredential?.credentialSubject?.scope, c.scope, '原始 VC scope', '挑战 scope')
      + `<p class="guide-muted">bodyHash 绑定精确请求正文；nonce 与 challengeId 标识本次挑战。材料存在或字段一致，不代表时效、防重放或签名检查已经通过。</p>`,
    Boolean(plan?.open || plan?.id?.startsWith('begin-') || plan?.id === 'derive-vc'));
}

function deviceDetails(state, plan, mode) {
  const m = state?.manual || {}, request = m.deviceRequest, response = m.deviceResponse, presentation = m.presentation;
  const blind = (request?.mode || mode) === 'bbs-blind-bls';
  const input = blind ? [
    ['盲化待签点', 'blindedPoint', request?.blindedPoint],
  ] : [
    ['本订单设备伪名', 'randomizedDevicePublicKey', request?.randomizedDevicePublicKey],
    ['输入绑定挑战', 'context.challengeId', request?.context?.challengeId],
    ['输入绑定正文', 'context.bodyHash', request?.context?.bodyHash],
    ['输入绑定派生 VC', 'context.w3cPresentationHash', request?.context?.w3cPresentationHash],
  ];
  return section('模拟 eSIM · 公开输入与输出', typeof response?.signature === 'string' && response.signature.length ? '已返回设备贡献；查看本次实际公开值' : response ? '返回字段不完整，尚未确认设备贡献' : request ? '输入已准备，等待调用设备' : '待派生凭证后准备输入',
    `<div class="guide-material-grid"><article data-source="device-input"><h4>持有者 A → 模拟 eSIM</h4>${rows([['模式', 'mode', request?.mode], ...[['协议版本', 'version', request?.version], ['密码套件', 'suite', request?.suite]].filter(([, , value]) => value !== undefined), ...input])}</article><article data-source="device-output"><h4>模拟 eSIM → 持有者 A</h4>${rows([
      ['返回模式', 'mode', response?.mode], ['设备签名贡献', 'signature', response?.signature],
      ['绑定设备公钥', 'publicKey', m.device?.publicKey], ['公钥指纹', 'publicKeyFingerprint', m.device?.publicKeyFingerprint],
    ])}</article></div>`
      + (blind ? `<section class="guide-device-local-context" data-source="agent-a-local"><h4>持有者 A 本地明文上下文</h4>${rows([['持有者 A 本地挑战', 'challengeId', m.challenge?.challengeId], ['持有者 A 本地请求正文摘要', 'bodyHash', m.challenge?.bodyHash], ['持有者 A 本地派生 VC 摘要', 'w3cPresentationHash', m.cryptography?.w3cPresentationHash]])}<p class="guide-muted">这些明文值保留在持有者 A 本地；设备输入只包含上方盲化待签点及公开协议标识。</p></section>` : '')
      + comparison('请求与返回模式', 'mode', request?.mode, response?.mode, '设备请求', '设备返回')
      + (!blind ? comparison('派生 VC 摘要绑定', 'w3cPresentationHash', m.cryptography?.w3cPresentationHash, request?.context?.w3cPresentationHash, '本次派生记录', '设备输入上下文') : '')
      + rows([['适配后的设备证明', 'π_se / deviceSignature', presentation?.deviceSignature], ['证明内设备伪名', 'randomizedDevicePublicKey', presentation?.randomizedDevicePublicKey]])
      + `<p class="guide-muted">${blind ? '盲化模式的设备请求只含 blindedPoint 等协议字段，不向设备发送明文挑战上下文。持有者 A 在本地去盲并核验贡献。' : '普通模式把本次挑战、正文摘要与派生 VC 摘要放入设备待签上下文。'} 持有者 A 的设备贡献核验关系为 e(H₀, σ_SE) = e(pk_SE, Q)；这是核验关系说明，实际执行结论查看后端记录。模拟 eSIM 为软件服务。</p>`,
    Boolean(plan?.open || ['device-sign', 'prove'].includes(plan?.id)));
}

function parseHolder(proof) {
  if (typeof proof !== 'string') return null;
  try {
    const parts = proof.split('.');
    if (parts.length !== 3 || !parts.every(part => /^[A-Za-z0-9_-]+$/.test(part))) return null;
    const decode = part => JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(part.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0))));
    return { header: decode(parts[0]), claims: decode(parts[1]), signature: parts[2] };
  } catch { return null; }
}
function holderDetails(state, plan) {
  const m = state?.manual || {}, decoded = parseHolder(m.holderProof), claims = decoded?.claims || {};
  const vc = m.sentCredential ?? m.verifiableCredential;
  const blind = (m.deviceRequest?.mode || state?.mode) === 'bbs-blind-bls';
  const deviceBasis = `<section class="guide-holder-device-basis"><h4>设备贡献 → 持有者 A 本地${blind ? '去盲与' : ''}核验</h4>${rows([
    ['设备返回模式', 'deviceResponse.mode', m.deviceResponse?.mode], ['设备原始签名贡献', 'deviceResponse.signature', m.deviceResponse?.signature],
    ['原绑定设备公钥', 'device.publicKey', m.device?.publicKey], ['设备公钥指纹', 'device.publicKeyFingerprint', m.device?.publicKeyFingerprint],
    ...(blind ? [['设备收到的盲化点', 'deviceRequest.blindedPoint', m.deviceRequest?.blindedPoint]] : []),
    ['适配后的设备贡献', 'deviceSignature', m.presentation?.deviceSignature],
  ])}${blind ? `<section class="guide-device-local-context" data-source="agent-a-local"><h4>持有者 A 本地明文上下文</h4>${rows([['持有者 A 本地挑战', 'challengeId', m.challenge?.challengeId], ['持有者 A 本地请求正文摘要', 'bodyHash', m.challenge?.bodyHash]])}<p class="guide-muted">这些明文值与下方派生文档摘要保留在持有者 A 本地；模拟 eSIM 的输入只有盲化点及公开协议标识。</p></section>` : ''}<p class="guide-muted">${blind ? '持有者 A 先在本地去盲，再按原绑定公钥核验贡献。' : '持有者 A 按原绑定公钥核验设备返回的贡献。'}核验关系为 e(H₀, σ_SE) = e(pk_SE, Q)。这是协议关系说明；生成组合材料才说明本次本地处理已完成，验证者 B 的核验另有记录。</p></section>`;
  return section('持有者 A · 签名与组合证明', m.holderProof ? decoded ? '已生成签名材料；以下为公开载荷解析' : '已有材料，但无法解析为 JWS' : m.deviceResponse ? '设备贡献已返回，等待持有者 A 核验与组合' : '等待设备贡献后生成',
    deviceBasis + comparison('签名者与凭证持有者', 'iss ↔ holderDid', vc?.credentialSubject?.holderDid, claims.iss, '派生 VC 的 holderDid', '签名载荷 iss')
      + comparison('签名接收方与挑战验证方', 'aud ↔ verifier', m.challenge?.verifier, claims.aud, '挑战 verifier', '签名载荷 aud')
      + comparison('签名绑定派生文档', 'credentialHash', m.cryptography?.w3cPresentationHash, claims.credentialHash, '派生文档摘要记录', '签名载荷 credentialHash')
      + rows([
        ['签名算法', 'alg', decoded?.header?.alg], ['签名用途', 'purpose', claims.purpose],
        ['挑战上下文摘要', 'contextHash', claims.contextHash], ['完整设备证明摘要', 'deviceProofHash', claims.deviceProofHash],
        ['签名到期时间', 'exp (Unix 秒)', claims.exp], ['持有者签名公开值', 'JWS signature', decoded?.signature],
        ['知识证明挑战', 'proof.challenge', m.presentation?.proof?.challenge],
        ['随机化凭证点', 'Abar', m.presentation?.Abar], ['随机化凭证点', 'Bbar', m.presentation?.Bbar], ['随机化凭证点', 'Cbar', m.presentation?.Cbar],
      ]) + `<p class="guide-muted">这里仅解析公开签名载荷和比较现有字段，没有在浏览器执行验签。验证者 B 需验签并重新计算挑战、派生 VC、完整设备证明的摘要；以本事项内的验证者 B 实际检查记录为准。</p>`,
    Boolean(plan?.open || ['prove', 'verify'].includes(plan?.id)));
}

function orderDetails(state, plan) {
  const m = state?.manual || {}, order = state?.order || {}, authorization = state?.authorization?.document;
  const expectedPayment = authorization?.payment || state?.proposal?.payment;
  const comparisonSource = authorization ? '已同步授权 payment' : '付款申请 payment';
  const terms = [['orderId', '订单编号'], ['amountMinor', '金额（最小单位）'], ['currency', '币种'], ['payerAccount', '付款账户'], ['payeeAccount', '收款账户']];
  return section('当前订单与用户逐笔授权', authorization ? '已同步授权文档；下方对照本单条款' : state?.proposal ? `授权申请状态：${state.proposal.status}` : '尚未提交用户授权申请',
    terms.map(([key, label]) => comparison(label, key, order[key], expectedPayment?.[key], '当前订单', comparisonSource)).join('')
      + ['network', 'asset', 'payerAddress', 'payTo'].map(key => comparison('结算条款', `settlement.${key}`, order.settlement?.[key], expectedPayment?.settlement?.[key], '当前订单', comparisonSource)).join('')
      + rows([
        ['授权申请编号', 'proposalId', state?.proposal?.id], ['用户决定', 'proposal.status', state?.proposal?.status],
        ['授权编号', 'authorizationId', authorization?.authorizationId], ['授权签发方', 'iss', authorization?.iss],
        ['授权接收方', 'aud', authorization?.aud], ['最多执行次数', 'maxExecutions', authorization?.maxExecutions],
        ['允许转授权', 'delegationAllowed', authorization?.delegationAllowed], ['授权有效期', 'exp (Unix 秒)', authorization?.exp],
        ['钱包材料状态', 'walletSigned', m.walletSigned === true ? '已返回签署材料' : m.walletSigningUnconfirmed ? '签署请求结果待确认' : '尚无已签材料'],
      ]) + `<p class="guide-muted">金额使用后端 amountMinor 原值；TEST_USDC 的 1,000,000 最小单位 = 1 TEST_USDC。批准授权、钱包签署、完成支付是三个不同结果，支付完成以匹配本订单的实际回执为准。</p>`,
    Boolean(plan?.open || ['submit-owner', 'owner-review', 'sync-owner', 'wallet-sign', 'begin-settle', 'new', 'discard'].includes(plan?.id)));
}

// Exact action mapping: preparation never inherits the checks of another phase.
const actionKinds = {
  issue: 'credential', new: 'credential', 'begin-proposal': 'challenge', 'begin-authorize': 'challenge', 'begin-settle': 'challenge',
  'derive-vc': 'disclosure', 'device-sign': 'device', prove: 'holder', verify: 'verification',
  'submit-owner': 'owner', 'owner-review': 'owner', 'sync-owner': 'owner',
  'wallet-sign': 'wallet', discard: 'review', complete: 'review', refresh: 'review',
};
const kindTitles = { credential: '准备凭证', challenge: '获取本次挑战', disclosure: '选择性披露', device: '模拟 eSIM 参与', holder: '组合共同证明', verification: '提交验证', owner: '用户付款授权', wallet: '钱包签署材料', review: '核对本轮状态', receipt: '结算验证' };
const phaseForAction = { 'begin-proposal': 'proposal', 'begin-authorize': 'authorize', 'begin-settle': 'settle' };
const textMoney = order => Number.isSafeInteger(order?.amountMinor) ? `${(order.amountMinor / 1000000).toLocaleString('zh-CN', { maximumFractionDigits: 6 })} ${order.currency || 'TEST_USDC'}` : undefined;

/** Only the current attempt snapshot is eligible; history/lastResult never supplies a new check. */
export function currentVerificationTrace(state) {
  const m = state?.manual || {}, result = m.verificationResult;
  if (!m.lastError?.verificationTrace && (result?.mode && result.mode !== state?.mode || result?.phase && result.phase !== m.phase)) return null;
  const trace = m.lastError?.verificationTrace || result?.verificationTrace;
  if (trace?.source !== 'agent-b' || trace?.profile !== 'dbac-payment') return null;
  if (!m.lastError?.verificationTrace && result?.wire?.context?.challengeId && result.wire.context.challengeId !== m.challenge?.challengeId) return null;
  const bindingId = state?.w3c?.originalCredential?.credentialSubject?.bindingId;
  for (const step of Array.isArray(trace.steps) ? trace.steps : []) for (const row of Array.isArray(step.evidence) ? step.evidence : []) {
    if (step.id === 'scope' && row.label === 'method / scope / phase' && Array.isArray(row.observed) && row.observed[2] !== m.phase) return null;
    if (step.id === 'execution' && row.label === 'phase / resulting task' && Array.isArray(row.observed) && row.observed[0] !== m.phase) return null;
    if (row.label === 'payment order ID' && typeof row.observed === 'string' && row.observed !== state?.order?.orderId) return null;
    // Compare the verifier's expected VC with the selected VC. A failed observed
    // binding stays visible: it is the actual reason a mixed proof was rejected.
    if (row.label === 'bindingId / mode / device contribution' && Array.isArray(row.expected) && bindingId && row.expected[0] !== bindingId) return null;
    if (row.label === 'hVC: derived credential hash' && m.cryptography?.w3cPresentationHash && typeof row.observed === 'string' && row.observed !== m.cryptography.w3cPresentationHash) return null;
  }
  return trace || null;
}

/** 持有者 A view projection, never an authorization or protocol state machine. */
export function currentStepPanel(state, { plan = {}, action = '', uncertain = false, complete = false } = {}) {
  const m = state?.manual || {}, id = action || plan.id || 'refresh';
  const phase = phaseForAction[id] || m.phase;
  const kind = complete ? 'receipt' : actionKinds[id] || 'review';
  const starting = Object.hasOwn(phaseForAction, id);
  const verification = ['verification', 'receipt'].includes(kind);
  const trace = verification && !uncertain && action !== 'verify' ? currentVerificationTrace(state) : null;
  const title = kind === 'verification' ? (phase === 'settle' ? '结算验证' : phase === 'authorize' ? '付款前复核' : '验证使用资格')
    : kind === 'challenge' ? `获取${phaseLabels[phase] || '本次'}挑战` : kindTitles[kind];
  const facts = [];
  const add = (label, value) => { if (present(value)) facts.push([label, value]); };
  if (kind === 'credential') {
    add('当前凭证', state?.currentCredentialId); add('模拟 eSIM', m.device?.available === false ? '服务不可用' : m.device?.available ? '软件设备已连接' : '等待状态');
    add('设备公钥指纹', m.device?.publicKeyFingerprint); add('证明模式', state?.mode === 'bbs-blind-bls' ? '盲化 BLS' : '普通 BLS');
  } else if (['device', 'holder'].includes(kind)) {
    add('本次请求', state?.order?.orderId); add('本次挑战', m.challenge?.challengeId);
    add('证明模式', state?.mode === 'bbs-blind-bls' ? '盲化 BLS' : state?.mode === 'bbs-bls' ? '普通 BLS' : undefined);
    add('材料来源', m.sentCredential ? '持有者 A 已发送 · 查看 验证者 B 本次记录' : m.verifiableCredential ? '持有者 A 本地已生成 · 尚未发送' : state?.credential ? '持有者 A 本地持有 · 待生成本次材料' : '等待本次材料');
  } else {
    add('本笔金额', textMoney(state?.order)); add('收款对象', state?.order?.payeeAccount); add('订单编号', state?.order?.orderId);
    if (!starting && ['disclosure', 'device', 'holder', 'verification'].includes(kind)) {
      add('本次挑战', m.challenge?.challengeId); add('材料来源', m.sentCredential ? '持有者 A 已发送 · 等待/查看 验证者 B 本次记录' : m.verifiableCredential ? '持有者 A 本地已生成 · 尚未发送' : '持有者 A 本地持有 · 待生成本次材料');
    }
    if (['owner', 'wallet', 'receipt'].includes(kind) || phase && phase !== 'proposal') add('用户授权', state?.proposal?.status === 'REJECTED' ? '已拒绝' : state?.authorization && state?.proposal?.status === 'APPROVED' ? '已授权' : state?.proposal?.status === 'APPROVED' ? '已批准 · 待同步' : state?.proposal?.status === 'PENDING' ? '待用户授权' : '尚未申请');
  }
  const prerequisite = !uncertain && ['owner', 'wallet'].includes(kind) ? currentVerificationTrace(state) : null;
  const recheck = phase === 'authorize' ? '本步复核' : phase === 'settle' ? '结算阶段复核' : '';
  return { kind, phase, title, facts, trace, verification, starting, recheck, prerequisite,
    purpose: ['challenge', 'disclosure', 'device', 'holder', 'verification', 'receipt'].includes(kind) ? phasePurposes[phase] || null : null,
    key: [state?.mode, state?.order?.orderId, state?.currentCredentialId, state?.w3c?.originalCredential?.credentialSubject?.bindingId, m.attemptId, phase, kind].join(':'),
    description: complete ? '核对本订单结算记录及匹配的测试资产回执。' : plan.description || '读取原订单状态，确认当前可执行的操作。' };
}

export function renderStepSummary(panel) {
  const purpose = panel.purpose;
  const explanation = purpose ? `<section class="guide-phase-purpose" data-phase="${escape(panel.phase)}"><h3>本轮目的 · 第 ${purpose.round} / 3 轮：${escape(purpose.title)}</h3><p>${escape(purpose.purpose)}</p><p><strong>本轮绑定：</strong>${escape(purpose.input)}。${escape(purpose.next)}</p><p class="guide-muted">三个业务轮次分别使用新挑战与新证明；下方四个环节属于当前这一轮。</p></section>` : '';
  return explanation + `<dl class="guide-step-summary">${panel.facts.map(([label, value]) => `<div><dt>${escape(label)}</dt><dd>${publicValue(value, '尚未生成', ['本次请求', '本次挑战', '订单编号'].includes(label) ? 28 : 40)}</dd></div>`).join('')}</dl>`;
}

const hasPublicText = value => typeof value === 'string' && value.length > 0;
const deviceCheckNames = { vc_device_binding: '凭证与设备绑定', device_pairing: '设备贡献配对' };
const deviceCheckLabels = { pending: '待验证', running: '验证中', pass: '通过', fail: '不通过', skipped: '未执行', unknown: '未提供独立结论' };
const deviceSymbols = { pending: '○', running: '◌', material: '▣', pass: '✓', fail: '×', skipped: '—', unknown: '?' };
function participationCheck(trace, id, running) {
  const matches = Array.isArray(trace?.steps) ? trace.steps.filter(step => step?.id === id) : [];
  const failure = matches.find(step => step.status === 'fail' || step.status !== 'skipped' && Array.isArray(step.evidence) && step.evidence.some(row => row?.match === false));
  const status = running ? 'running' : failure ? 'fail' : matches.length === 1 && ['pass', 'skipped'].includes(matches[0].status) ? matches[0].status : trace ? 'unknown' : 'pending';
  const step = failure || matches[0];
  return { id, title: deviceCheckNames[id], status, detail: status === 'fail' ? [step?.code, step?.detail].filter(hasPublicText).join(' · ') : matches.length > 1 ? '记录编号重复，需核对。' : '' };
}
function participationValues(entries) {
  const selected = entries.filter(([, value]) => hasPublicText(value) || typeof value === 'number' && Number.isFinite(value));
  return `<dl class="guide-device-values">${selected.map(([label, value]) => `<div><dt>${escape(label)}</dt><dd>${publicValue(value)}</dd></div>`).join('')}</dl>`;
}
/** Material presence and local generation are distinct from 验证者 B's two recorded checks. */
export function renderDeviceParticipation(state, { panel = currentStepPanel(state), action = '', uncertain = false, mode = state?.mode || 'bbs-bls' } = {}) {
  const m = state?.manual || {}, phase = panel.phase || m.phase;
  const expired = m.expired === true || m.stage === 'EXPIRED' || Number.isFinite(m.expiresAtUnix) && m.expiresAtUnix * 1000 <= Date.now();
  const contextMatches = state?.mode === mode && Boolean(m.attemptId) && phase === m.phase && m.stage !== 'DISCARDED';
  const usable = state?.available === true && contextMatches && !panel.starting && !uncertain && !expired;
  const request = usable ? m.deviceRequest : null, response = usable ? m.deviceResponse : null;
  const blind = mode === 'bbs-blind-bls';
  const requestReady = request?.mode === mode && (blind ? hasPublicText(request.blindedPoint)
    : hasPublicText(request.randomizedDevicePublicKey) && hasPublicText(request.context?.challengeId) && request.context.challengeId === m.challenge?.challengeId);
  const contributionReady = Boolean(response?.mode === mode && hasPublicText(response.signature));
  const combined = usable && requestReady && contributionReady && ['PROOF_READY', 'VERIFIED', 'OWNER_SUBMITTED', 'WALLET_SIGNED', 'SETTLED'].includes(m.stage)
    && hasPublicText(m.presentation?.deviceSignature) && hasPublicText(m.holderProof);
  const validationStep = ['verification', 'receipt', 'owner', 'wallet'].includes(panel.kind);
  const trace = usable && validationStep && action !== 'verify' ? currentVerificationTrace(state) : null;
  const checking = action === 'verify' && !uncertain;
  const checks = Object.keys(deviceCheckNames).map(id => participationCheck(trace, id, checking));
  const checked = checks.every(check => check.status === 'pass');
  const failed = checks.some(check => check.status === 'fail');
  const checkStatus = checking ? 'running' : failed ? 'fail' : checked ? 'pass' : checks.every(check => check.status === 'skipped') ? 'skipped' : checks.some(check => check.status === 'unknown') ? 'unknown' : 'pending';
  const checkText = checks.map(check => `${check.title}：${deviceCheckLabels[check.status]}`).join('；');
  let alert = uncertain ? '本次响应尚未确认，不能沿用此前的设备核验结论。'
    : panel.starting ? '新阶段将重新取得挑战和设备贡献，前一步的结果不用于本轮。'
      : expired ? '本轮挑战或证据已过期，需重新取得设备贡献；旧记录不表示当前通过。'
        : !contextMatches && m.attemptId ? '设备材料与当前模式或阶段不一致，需核对本轮记录。' : '';
  if (trace?.outcome === 'pass' && failed) alert = '验证者 B 的整体结论与设备检查记录存在冲突；保留以下实际失败记录。';
  const otherFailure = (Array.isArray(trace?.steps) ? trace.steps : []).find(step => step && !Object.hasOwn(deviceCheckNames, step.id) && (step.status === 'fail' || step.status !== 'skipped' && Array.isArray(step.evidence) && step.evidence.some(row => row?.match === false)));
  if (checked && otherFailure) alert = `设备两项检查通过；本次请求仍停在${otherFailure.title || otherFailure.id}${otherFailure.code ? `（${otherFailure.code}）` : ''}。`;
  if (['owner', 'wallet'].includes(panel.kind)) {
    const previous = trace ? `前一步验证者 B 记录：${checkText}。` : '前一步验证者 B 的设备核验记录待核对。';
    const failureDetails = checks.filter(check => check.status === 'fail' && check.detail).map(check => check.detail).join('；');
    return `<p class="guide-device-prerequisite" data-state="${checkStatus}">${deviceSymbols[contributionReady ? 'material' : 'pending']} 模拟 eSIM：${contributionReady ? '贡献已返回持有者 A' : '本轮贡献返回记录待确认'}。${escape(previous)}${failureDetails ? ` ${escape(failureDetails)}` : ''}${alert ? ` ${escape(alert)}` : ''} 软件仿真；这不表示模拟支付完成。</p>`;
  }
  const preparationRunning = ['begin-proposal', 'begin-authorize', 'begin-settle', 'derive-vc'].includes(action) && !uncertain;
  const deviceRunning = action === 'device-sign' && !uncertain, holderRunning = action === 'prove' && !uncertain;
  const deviceFailed = usable && !action && panel.kind === 'device' && m.lastError && !currentVerificationTrace(state);
  const holderFailed = usable && !action && panel.kind === 'holder' && m.stage === 'DEVICE_SIGNED' && m.lastError && !currentVerificationTrace(state);
  const nodes = [
    { role: 'request', title: '持有者 A 准备请求', status: preparationRunning ? 'running' : requestReady ? 'material' : 'pending', label: preparationRunning ? '正在准备' : requestReady ? '输入已准备' : '等待本轮输入', note: blind ? '持有者 A 将本次上下文转为盲化待签点。' : '输入绑定本次挑战与派生 VC 摘要。' },
    { role: 'device', title: '模拟 eSIM 贡献', status: deviceRunning ? 'running' : deviceFailed ? 'fail' : contributionReady ? 'material' : 'pending', label: deviceRunning ? '等待设备返回' : deviceFailed ? '调用未完成' : contributionReady ? '贡献已返回持有者 A' : '等待设备调用', note: deviceFailed ? `${m.lastError.code || ''} ${m.lastError.message || '请核对设备调用记录。'}` : m.device?.available === false ? '软件设备服务当前不可用。' : '软件设备只返回本次签名贡献。' },
    { role: 'holder', title: '持有者 A 核验并组合', status: holderRunning ? 'running' : holderFailed ? 'fail' : combined ? 'material' : 'pending', label: holderRunning ? '正在核验与组合' : holderFailed ? '组合未完成' : combined ? '组合材料已生成' : '等待持有者 A 处理', note: holderFailed ? `${m.lastError.code || ''} ${m.lastError.message || '请核对 持有者 A 本地处理记录。'}` : combined ? `${blind ? '已去盲并核验贡献' : '已核验设备贡献'}；另有独立的持有者 A 请求签名。` : `${blind ? '先去盲并核验贡献' : '先核验设备贡献'}，再适配证明并独立签署请求。` },
    { role: 'verifier', title: '验证者 B 核验设备绑定', status: checkStatus, label: checking ? '验证中' : failed ? '设备检查不通过' : checked ? '设备两项通过' : checkStatus === 'skipped' ? '设备检查未执行' : checkStatus === 'unknown' ? '独立记录待核对' : '等待本次核验', note: trace ? '凭证绑定与设备配对以本次 验证者 B 记录为准。' : '生成或发送材料不表示验证者 B 已接受。' },
  ];
  const currentRole = { credential: 'request', challenge: 'request', disclosure: 'request', device: 'device', holder: 'holder', verification: 'verifier', receipt: 'verifier' }[panel.kind];
  const chain = `<ol class="guide-device-chain" aria-label="本轮证明内部的四个环节">${nodes.map((node, index) => {
    const completed = node.role !== currentRole && ['material', 'pass'].includes(node.status);
    const note = `<p class="guide-device-node-note">${escape(node.note)}</p>`;
    return `<li data-device-role="${node.role}" data-state="${node.status}"${node.role === currentRole ? ' aria-current="step"' : ''}><strong class="guide-device-role">${index + 1}. ${escape(node.title)}</strong><span class="guide-device-node-status">${deviceSymbols[node.status]} ${escape(node.label)}</span>${completed ? `<details class="guide-device-node-detail" data-detail-key="device-node-${node.role}"><summary>查看本环节说明</summary>${note}</details>` : note}</li>`;
  }).join('')}</ol>`;
  const bindingId = state?.mode === mode ? state?.w3c?.originalCredential?.credentialSubject?.bindingId : undefined;
  const binding = ['credential', 'challenge'].includes(panel.kind) ? `<div class="guide-device-binding" data-state="${hasPublicText(bindingId) ? 'material' : 'pending'}"><p>${hasPublicText(bindingId) ? '已返回绑定材料：签发材料通过绑定标识关联 VC 与配套设备凭证；每次使用仍需原绑定模拟 eSIM 参与。' : '等待签发凭证与绑定材料；设备公钥指纹本身不表示 VC 绑定已验证。'}</p>${participationValues(state?.mode === mode ? [['持有者 A 本地 VC 绑定标识', bindingId], ['当前模拟 eSIM 公钥指纹', m.device?.publicKeyFingerprint]] : [])}<p class="guide-muted">来源：当前本地凭证与设备摘要；未提供本次签发绑定的独立核验记录。</p></div>` : '';
  const checkRows = validationStep ? `<div class="guide-device-checks">${checks.map(check => `<p data-device-check-id="${check.id}" data-state="${check.status}">${deviceSymbols[check.status]} ${escape(check.title)}：${deviceCheckLabels[check.status]}${check.detail ? ` · ${escape(check.detail)}` : ''}</p>`).join('')}</div>` : '';
  return `<section class="guide-device-participation" data-kind="${escape(panel.kind)}" data-mode="${escape(mode)}"><div class="guide-device-participation-heading"><h3>模拟 eSIM 如何参与本次证明</h3><span>软件仿真 · 本轮内部 4 个环节${panel.recheck ? ` · ${escape(panel.recheck)}` : ''}</span></div>${alert ? `<p class="guide-device-alert">! ${escape(alert)}</p>` : ''}${binding}${chain}${checkRows}</section>`;
}

export function renderStepMaterial(state, kind, mode = state?.mode, { open = false } = {}) {
  if (kind === 'credential' || kind === 'disclosure') return section('原始 VC 与本次派生 VC', '持有者 A 本地材料 / 持有者 A 已发送记录，不推断验证者 B 已收到', credentialCards(state), open);
  if (kind === 'challenge') return challengeDetails(state, { open });
  if (kind === 'device') return deviceDetails(state, { open }, mode);
  if (kind === 'holder') return holderDetails(state, { open });
  if (kind === 'owner' || kind === 'wallet') return orderDetails(state, { open });
  return '';
}

function operationRecord(id, title, description, status, detail) {
  return `<article class="guide-operation-record" data-operation-id="${escape(id)}"><div class="guide-record-heading"><h3>${escape(title)}</h3><span class="guide-record-status">${escape(status)}</span></div><p>${escape(description)}</p>${detail}</article>`;
}

function operationFlow(state, kind, action) {
  const m = state?.manual || {}, blind = (m.deviceRequest?.mode || state?.mode) === 'bbs-blind-bls';
  const flows = {
    credential: ['当前选中的设备与签发方测试配置。', '签发 VC，并准备关联同一绑定标识的设备凭证。', state?.credential ? '当前凭证材料已载入；公开字段见下方。' : '尚未取得当前凭证材料。', state?.credential ? '签发材料已载入，仍需在每次使用时重新核验真实性、设备参与与撤销状态。' : '当前没有凭证材料，先准备测试凭证再开始资格认证。'],
    challenge: ['当前订单及当前业务轮次需要的授权或付款材料。', '持有者 A 向验证者 B 申请一次性挑战；bodyHash 绑定本轮精确请求正文。', m.challenge ? '验证者 B 已返回本轮挑战；challengeId、nonce 与到期时间见下方。' : '尚未取得这一轮的新挑战。', '取得挑战后可准备本轮证明；尚未验证使用资格，也未付款。'],
    disclosure: ['持有者 A 本地原始 VC、本轮挑战与披露策略。', '生成标准 BBS 选择性披露证明 π_std，隐藏策略字段不写入本次派生文档。', m.sentCredential || m.verifiableCredential ? '本次派生文档已生成；以实际包含的字段为准。' : '本次派生文档尚未生成。', '字段对照只说明文档内容；标准 BBS 证明是否有效仍由验证者 B 独立核验。'],
    device: [blind ? '持有者 A 准备的盲化待签点；明文挑战上下文留在持有者 A。' : '本次挑战、正文摘要与派生 VC 摘要绑定的设备待签上下文。', '模拟 eSIM 对本次输入返回设备贡献；持有者 A 随后按下方配对关系核验。', m.deviceResponse?.signature ? '设备贡献已返回持有者 A；公开签名值见下方。' : '尚未取得本次设备贡献。', '返回贡献后仍需持有者 A 核验并组合、验证者 B 独立检查；这一步不付款。'],
    holder: ['本轮派生 VC、挑战与设备返回的贡献。', `${blind ? '持有者 A 先去盲，' : '持有者 A '}核验设备贡献，适配设备证明，再独立签署绑定当前请求的持有者证明。`, m.holderProof && m.presentation ? '持有者 A 的组合材料与独立签名已生成；公开载荷见下方。' : '尚未取得完整的持有者 A 组合材料与独立签名。', '本地组合完成后可提交验证者 B；只有验证者 B 的本轮记录能确认使用证明通过。'],
    owner: ['当前订单的金额、收款对象、网络与凭证绑定。', state?.proposal ? '用户逐笔核对条款，明确批准或拒绝。' : '持有者 A 提交已核验订单，申请用户逐笔授权。', state?.proposal?.status === 'REJECTED' ? '用户已拒绝本笔授权。' : state?.authorization ? '本笔用户授权已同步。' : state?.proposal ? '已有授权申请，等待用户决定或同步。' : '尚未提交本笔授权申请。', '批准只生成本笔授权；后续复核、钱包签署和模拟支付分别执行。'],
    wallet: ['原订单、已同步的用户授权与付款前复核证据。', '钱包独立核对订单及授权，再签署本笔付款材料。', m.walletSigningUnconfirmed ? '钱包签署结果尚未确认，请核对原订单。' : m.walletSigned ? '原订单的已签付款材料已返回。' : '尚未取得本笔已签付款材料。', '钱包签名本身不转账；还需新结算挑战、新证明和匹配本订单的回执。'],
  };
  const flow = flows[kind];
  if (!flow) return '';
  const output = action ? '本步请求正在执行，等待本次返回；已有材料不代替这次结果。' : flow[2];
  const conclusion = !action && m.lastError ? `本步尚未完成：${m.lastError.code ? m.lastError.code + ' · ' : ''}${m.lastError.message || '请核对本轮错误记录。'}` : flow[3];
  return `<dl class="guide-operation-flow">${[['输入', flow[0]], ['操作 / 核验关系', flow[1]], ['输出', output], ['结论 / 下一步', conclusion]].map(([label, value]) => `<div><dt>${escape(label)}</dt><dd>${escape(value)}</dd></div>`).join('')}</dl>`;
}

/** Only materials relevant to the current action; no history or future checks. */
export function renderStepDetail(state, { plan = {}, mode = state?.mode || 'bbs-bls', panel = currentStepPanel(state, { plan }), action = '' } = {}) {
  if (panel.starting) state = { ...state, manual: { ...state?.manual, challenge: null, attemptId: null, cryptography: null, verifiableCredential: null, sentCredential: null } };
  const m = state?.manual || {}, kind = panel.kind;
  if (panel.verification) return '';
  const operationTitles = { credential: '本地凭证与绑定设备', challenge: '申请新挑战', disclosure: '生成派生 VC', device: '请求设备签名贡献', holder: '持有者签名与证明', owner: state?.proposal ? '用户逐笔确认' : '提交授权申请', wallet: '请求钱包签署' };
  const descriptions = { credential: '载入当前测试凭证和模拟设备的公开信息。', challenge: '用本阶段的订单正文向验证者 B 申请独立挑战。', device: '设备对本次输入提供贡献，返回后仍需持有者 A 组合证明。', holder: '持有者 A 核验设备贡献，将持有者签名绑定到本次挑战与派生文档。', owner: state?.proposal ? '核对金额和收款对象，再选择批准或拒绝。' : '向用户提交已验证的订单，申请逐笔授权。', wallet: '钱包独立核对本笔授权与认证依据，再返回签署材料。' };
  let content = '', description = descriptions[kind] || plan.description || '核对本轮状态。', status = action ? '◌ 执行中' : '○ 待执行';
  if (kind === 'credential') status = action ? '◌ 正在准备' : state?.credential ? '▣ 已加载' : '○ 待准备';
  if (kind === 'disclosure') {
    const fields = credentialFieldComparison(state);
    const vc = m.sentCredential ?? m.verifiableCredential;
    const actual = fields.filter(row => row.targetPresent).map(row => row.label);
    const absent = fields.filter(row => !row.targetPresent && row.sourcePresent).map(row => row.label);
    description = vc ? `本次包含：${actual.join('、') || '未记录'}；未包含：${absent.join('、') || '无'}。` : '根据本次挑战派生凭证；披露范围以生成后的实际文档为准。';
    status = action ? '◌ 正在生成' : vc ? '▣ 已生成' : '○ 待生成';
  }
  if (kind === 'device') status = action ? '◌ 等待设备返回' : m.deviceResponse ? '▣ 贡献已返回' : '○ 待请求设备';
  if (kind === 'holder') status = action ? '◌ 正在组合' : m.holderProof && m.presentation ? '▣ 已生成' : '○ 待生成';
  if (kind === 'owner') status = action ? '◌ 正在提交' : state?.proposal?.status === 'REJECTED' ? '× 用户已拒绝' : state?.authorization ? '▣ 已授权' : state?.proposal ? '○ 待用户授权' : '○ 待提交申请';
  if (kind === 'wallet') status = action ? '◌ 等待钱包返回' : m.walletSigningUnconfirmed ? '○ 签名结果待确认' : m.walletSigned ? '▣ 材料已签署' : '○ 待签署';
  if (kind === 'review') return '';
  if (kind === 'device' && m.verifiableCredential) {
    const fields = credentialFieldComparison(state);
    const actual = fields.filter(row => row.targetPresent).map(row => row.label);
    const absent = fields.filter(row => !row.targetPresent && row.sourcePresent).map(row => row.label);
    const source = m.sentCredential ? '持有者 A 已发送记录' : '持有者 A 本地已生成';
    content += `<p class="guide-disclosure-prerequisite">▣ 选择性披露：本次包含${escape(actual.join('、') || '未记录')}；未包含${escape(absent.join('、') || '无')}。来源：${source}。</p><details class="guide-prerequisite" data-detail-key="previous-vc-${escape(m.attemptId)}"><summary>查看上一操作的 VC 对照</summary><p>只读回看：原始 VC 为持有者 A 本地持有，派生 VC 区分持有者 A 本地生成与持有者 A 已发送；这些材料记录不表示验证者 B 已收到或验证通过。展开不会重新派生、签名或提交请求。</p>${renderStepMaterial(state, 'disclosure', mode)}</details>`;
  }
  if (panel.prerequisite) {
    const verdict = verificationVerdict(panel.prerequisite, { phase: m.phase });
    content += `<details class="guide-prerequisite" data-detail-key="prerequisite-${escape(m.attemptId)}"><summary>${verdict.status === 'pass' ? '✓' : '○'} ${escape(phaseLabels[m.phase])}：${verdict.status === 'pass' ? '前一步已通过' : '记录待核对'} · 回看验证者 B 记录</summary><p>来源：本轮已返回记录，仅供回看，展开不会提交请求。</p>${renderVerificationChecks(panel.prerequisite,{phase:m.phase})}</details>`;
  }
  return content + operationRecord(plan.id || kind, operationTitles[kind] || panel.title, description, status,
    operationFlow(state, kind, action) + renderStepMaterial(state, kind, mode, { open: true }));
}
