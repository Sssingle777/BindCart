// Presentation only. The verifier's returned trace owns every check status.
// Accept selected public evidence only; never expand a credential/proof object.
const escape = value => String(value ?? '—').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
const labels = { pass: '通过', fail: '不通过', skipped: '未执行', pending: '待验证', running: '验证中', unknown: '未提供独立结论' };
const symbols = { pass: '✓', fail: '×', skipped: '—', pending: '○', running: '◌', unknown: '?' };
const definitions = [
  ['credential', '凭证来源与真实性', ['w3c_bbs'], ['w3c_bbs'], '核对签发方、密码套件及标准 BBS 派生证明。'],
  ['device', '模拟 eSIM 绑定与本次贡献', ['vc_device_binding', 'device_pairing'], ['vc_device_binding', 'device_pairing'], '分别检查凭证是否绑定本设备，以及设备贡献是否绑定本次请求；软件仿真。'],
  ['holder', '持有者 A 的本次签名', ['holder_signature'], ['holder_signature'], '独立核验持有者 A 的请求签名，不由设备参与代替。'],
  ['participation', '配套凭证与知识证明', ['schema', 'proof_structure', 'proof_encoding', 'disclosure', 'knowledge', 'credential_pairing'], ['knowledge', 'credential_pairing'], '核对披露结构、配套凭证和知识证明。'],
  ['validity', '挑战时效与凭证状态', ['credential_status', 'challenge', 'policy_context'], ['credential_status', 'challenge'], '核对签发方状态查询、新挑战的有效期与本次资格日期。'],
  ['request', '本次请求绑定与防重放', ['request_binding', 'extension', 'envelope', 'scope', 'replay', 'consume'], ['request_binding', 'scope'], '核对收到的订单正文、调用范围、挑战使用与消费记录。'],
  ['business', '单笔授权与阶段结果', ['owner_authorization', 'task_binding', 'settlement_gate', 'execution'], ['execution', 'owner_authorization'], '核对当前阶段的授权、任务连续性与实际业务输出。'],
];
const evidenceLabels = {
  'extension / identified headers': '扩展标识 / 是否携带具名请求头',
  'body / proof encoded length': '正文 / 证明编码长度',
  'challenge found / now / expiry (s)': '挑战存在 / 当前时间 / 截止时间（秒）',
  'challenge already used': '挑战是否已使用',
  'raw body SHA-256': '订单原始正文 SHA-256',
  'role / scope / epoch / mode': '角色 / 权限 / 日期 / 模式',
  'method / scope / phase': '调用方法 / 权限 / 支付阶段',
  'payment order ID': '本次订单编号',
  'signed attribute count': '签名保护的属性数量',
  'proof type / suite / issuer': '证明类型 / 密码套件 / 签发方',
  'expected presentationHeader SHA-256': '验证方输入 PH 的 SHA-256',
  'expected presentationHeader (hex)': '验证方输入 PH（十六进制）',
  'bindingId / mode / device contribution': 'VC 绑定标识 / 模式 / 是否携带设备贡献',
  'hVC: derived credential hash': 'hVC：收到的派生 VC 摘要',
  'version / suite / mode': '证明版本 / 密码套件 / 模式',
  'required disclosures (index=value)': '必需披露项（属性索引 = 值）',
  'Abar / Bbar / Cbar (G1)': '随机化凭证 Ā / B̄ / C̄',
  'randomized key (G1) / pi_se (G2)': '设备伪名 D / 适配签名 π_se',
  'Fiat-Shamir challenge': '重建知识证明挑战 c′ / 证明携带的 c',
  'reconstructed T1 / T2 (G1)': '重建承诺 T₁′ / T₂′',
  'issuer public key W (G2)': '配套凭证签发方公钥 W',
  'hash-to-curve point Q (G2)': '绑定本次上下文的曲线点 Q',
  'e(H0,pi_se) = e(randomizedKey,Q)': '设备贡献配对等式 E(H₀, π_se) = E(D, Q)',
  'e(Abar,W) = e(Bbar,G2)': '凭证配对等式 E(Ā, W) = E(B̄, g₂)',
  'issuer-protected holder key / signed input digest': '签发方保护的持有者公钥指纹 / 签名输入摘要',
  'issuer status / source / checked at': '签发方状态 / 查询来源 / 查询时间',
  'Owner / VC binding / issued / expires': '用户 / VC 绑定 / 授权签发时间 / 截止时间',
  'context / order / authorization / VC binding': '任务上下文 / 订单摘要 / 授权摘要 / VC 绑定',
  'task continuity tuple hash': '任务绑定各字段的联合摘要',
  'before consume: used / now / expires': '消费前：是否已使用 / 当前时间 / 截止时间',
  'after synchronous consume: used': '同步消费后：是否已使用',
  'phase / resulting task': '当前支付阶段 / 实际任务状态',
  'order / authorization / payload digest': '订单 / 授权 / 付款材料摘要',
  'settlement outcome / transaction': '实际结算结果 / 交易编号',
};
const evidenceNotes = {
  'Verifier input; checked by bbs-2023.': '这是验证方本次预期的 PH 输入，由标准库校验；并非从收到的证明中提取的 PH。',
  'Verifier input; the standard library compares the proof-embedded header with this expected header.': '这是验证方输入的摘要，标准库核对证明携带的 PH；并非从证明中提取的 PH。',
  'Claims untrusted until signature and binding checks pass.': '收到的声明在签名与绑定检查通过前不可信。',
  'Public compressed curve points; subgroup and canonical encoding are checked.': '这是公开的压缩曲线点，后端检查子群与规范编码。',
  'Recomputed from the received VC; the following knowledge/device checks bind it into the request context.': '根据收到的派生 VC 重算；后续知识证明与设备检查将此摘要绑定到本次上下文。',
  'pi_se is the adapted contribution; Q binds this context and randomized device key.': 'π_se 是适配后的设备贡献；Q 绑定本次上下文与设备伪名。',
  'Received claims are untrusted until the signed authorization check succeeds; no token is disclosed.': '收到的声明在授权验签通过前不可信；此处不展示完整授权令牌。',
  'Qualification only; no wallet signing or settlement is invoked.': '本阶段仅核验资格，未调用钱包签名或结算。',
  'Returns payment requirements; no transfer is performed.': '本阶段返回付款要求，尚未转账。',
};
const publicScalar = value => value == null || ['string', 'boolean'].includes(typeof value) || typeof value === 'number' && Number.isFinite(value);
const publicValue = value => publicScalar(value) || Array.isArray(value) && value.length <= 12 && value.every(publicScalar);
const textValue = value => value == null ? '未记录' : Array.isArray(value) ? value.map(textValue).join('\n') : String(value);
const asText = value => typeof value === 'string' ? value : '';
const phases = ['proposal', 'authorize', 'settle'];

function evidenceOf(step) {
  if (step.status === 'skipped' || !Array.isArray(step.evidence)) return [];
  return step.evidence.filter(row => row && Object.hasOwn(evidenceLabels, row.label) && publicValue(row.expected) && publicValue(row.observed)).map(row => ({
    label: evidenceLabels[row.label], sourceLabel: row.label,
    expected: row.expected == null ? (row.match === undefined ? '未记录约束（输入或计算输出）' : '服务端未记录预期值') : textValue(row.expected),
    observed: textValue(row.observed),
    match: row.match === true ? true : row.match === false ? false : null,
    expectedRecorded: Object.hasOwn(row, 'expected') && row.expected != null,
    observedRecorded: Object.hasOwn(row, 'observed') && row.observed != null,
    note: evidenceNotes[row.note] || asText(row.note),
  }));
}

// Explicit IDs mirror the existing verifier stages; presentation never invents checks.
const checkDefinitions = [
  ['w3c_bbs', '验证 W3C BBS 派生凭证', '核验可信签发方、标准选择性披露证明与本次挑战。'],
  ['credential_status', '查询凭证撤销状态', '读取签发方状态；撤销、未知或查询失败均须保留实际结论。'],
  ['holder_signature', '验证持有者 A 签名', '核验签发方保护的持有者公钥及本次请求签名。'],
  ['vc_device_binding', '核对凭证与模拟 eSIM 绑定', '核对两份签名保护的绑定标识。'],
  ['extension', '核对设备绑定扩展', '核对请求声明的扩展及具名请求头限制。'],
  ['envelope', '读取请求与设备证明', '检查收到的正文长度和证明编码。'],
  ['challenge', '核对一次性挑战', '检查本次挑战存在且未过期。'],
  ['replay', '检查挑战未使用', '检查本次挑战是否已经消费。'],
  ['request_binding', '核对本次请求哈希', '比较实际收到的正文摘要与挑战绑定值。'],
  ['policy_context', '核对日期与证明模式', '核对当前披露策略日期和证明模式。'],
  ['scope', '核对支付阶段与订单', '核对 payments:pay、当前阶段、订单与收付款条款。'],
  ['schema', '检查固定属性数量', '核对证明使用的属性数量与固定格式。'],
  ['proof_structure', '检查证明结构', '核对版本、套件、模式和披露属性索引。'],
  ['disclosure', '检查披露权限', '核对本次披露的角色、权限、日期和模式要求。'],
  ['proof_encoding', '解析曲线点与标量', '检查公开群元素、证明标量和隐藏属性响应编码。'],
  ['knowledge', '验证知识证明', '重建承诺并核对绑定当前请求的证明挑战。'],
  ['credential_pairing', '验证配套凭证', '执行随机化 BBS 凭证签名配对检查。'],
  ['device_pairing', '验证模拟 eSIM 贡献', '执行设备贡献配对检查并绑定当前请求。'],
  ['owner_authorization', '验证用户单笔授权', '核验 Owner 签名、有效期、订单与绑定公钥。'],
  ['task_binding', '核对支付任务连续性', '核对本次付款沿用同一授权、订单和公钥。'],
  ['consume', '消费一次性支付挑战', '全部必要检查通过后同步标记本次挑战已使用。'],
  ['settlement_gate', '签发结算前验证证据', '将本次验证结果、用户授权和付款材料摘要签名绑定。'],
  ['execution', '处理本次支付阶段', '读取服务端本阶段返回的任务状态或模拟支付回执。'],
];
const checkCatalog = new Map(checkDefinitions.map(([id, title, description]) => [id, { id, title, description }]));
const checkRelations = {
  w3c_bbs: '标准 BBS 库核验派生证明，并使用验证者本次预期的 presentationHeader。',
  request_binding: 'SHA-256(实际收到的正文) = 本轮挑战绑定的 bodyHash。',
  knowledge: '重建 Fiat–Shamir 挑战 c′，与证明携带的 c 比较。',
  credential_pairing: 'E(Ā, W) = E(B̄, g₂)。',
  device_pairing: 'E(H₀, π_se) = E(D, Q)；Q 绑定本次上下文与设备伪名。',
  holder_signature: '以签发方保护的持有者公钥验签，再核对挑战、派生 VC 与完整设备证明的摘要绑定。',
  vc_device_binding: '标准 VC 与配套设备凭证的 bindingId、mode 匹配，并携带本次设备贡献。',
  credential_status: '以当前 bindingId 查询签发方凭证状态；以本轮实际返回的状态为准。',
  owner_authorization: '核验用户签名、单笔订单条款、绑定公钥与授权有效期。',
  task_binding: '当前结算请求沿用原订单、单笔授权、任务上下文与 VC 绑定。',
  settlement_gate: '把当前验证、订单、用户授权与已签付款材料摘要签名绑定。',
};

export function paymentVerificationIds(phase) {
  const unused = phase === 'proposal' ? ['owner_authorization', 'task_binding', 'settlement_gate']
    : phase === 'authorize' ? ['task_binding', 'settlement_gate'] : [];
  return checkDefinitions.map(([id]) => id).filter(id => !unused.includes(id));
}

function observedPhases(steps) {
  return [...new Set(steps.flatMap(step => (Array.isArray(step.evidence) ? step.evidence : []).flatMap(row => {
    if (!Array.isArray(row?.observed)) return [];
    const value = step.id === 'scope' && row.label === 'method / scope / phase' ? row.observed[2]
      : step.id === 'execution' && row.label === 'phase / resulting task' ? row.observed[0] : null;
    return phases.includes(value) ? [value] : [];
  })))];
}

function stepOf(raw, id, { duplicates, trusted, received, running, phaseMismatch, recheck }) {
  const definition = checkCatalog.get(id) || { title: asText(raw?.title) || id, description: asText(raw?.detail) || '服务端实际返回的检查记录。' };
  const missing = !raw;
  let status = running ? 'running' : received ? 'unknown' : 'pending';
  if (raw && trusted && ['pass', 'fail', 'skipped'].includes(raw.status)) status = raw.status;
  const rows = raw && trusted ? evidenceOf(raw) : [];
  const mismatch = trusted && raw?.status !== 'skipped' && Array.isArray(raw?.evidence) && raw.evidence.some(row => row?.match === false);
  if (mismatch) status = 'fail';
  else if (duplicates.has(id) && status !== 'fail') status = 'unknown';
  const detail = phaseMismatch ? '返回记录属于其他支付阶段，本步尚无可用的验证结论。'
    : duplicates.has(id) ? `返回了重复的检查编号，需要核对；不能据此宣布通过。${raw?.status === 'fail' ? ` 失败记录：${asText(raw.detail)}` : ''}`
      : !trusted ? running ? '本次验证请求正在等待服务端返回；尚无本项独立结果。' : '本步尚未取得验证者 B 的检查记录。'
        : missing ? '服务端未返回本项独立检查记录，不能由整体结果推断本项通过。'
          : raw.status === 'skipped' ? '本次未执行此项检查，不能据此推断通过。'
            : mismatch && raw.status === 'pass' ? '服务器标记通过，但公开比较记录存在不匹配；需要核对记录。'
              : asText(raw.detail);
  return { id, title: definition.title, description: definition.description, status, reportedStatus: trusted ? raw?.status : null,
    detail, recheck: recheck === true, code: trusted ? asText(raw?.code) : '', rows,
    truncated: trusted && raw?.evidenceTruncated === true, missing,
    omitted: trusted && raw?.status !== 'skipped' && Array.isArray(raw?.evidence) ? raw.evidence.length - rows.length : 0 };
}

/** Build a current-step model only. No request, mutation or business success is derived here. */
export function verificationEvidenceModel(trace, { phase, ids, running = false, pending = false, recheck = false } = {}) {
  const rawSteps = Array.isArray(trace?.steps) ? trace.steps.filter(step => step && typeof step.id === 'string') : [];
  const phaseMismatch = phases.includes(phase) && observedPhases(rawSteps).some(value => value !== phase);
  const received = !running && !pending && trace?.source === 'agent-b' && trace?.profile === 'dbac-payment';
  const trusted = received && !phaseMismatch;
  const duplicates = trusted ? new Set(rawSteps.filter((step, index) => rawSteps.findIndex(other => other.id === step.id) !== index).map(step => step.id)) : new Set();
  const selected = [...new Set(Array.isArray(ids) ? ids : paymentVerificationIds(phase))].filter(id => checkCatalog.has(id));
  // Unexpected failed stages stay visible even when they are outside the normal phase map.
  const unexpectedFailures = trusted ? rawSteps.filter(step => !selected.includes(step.id)
    && (step.status === 'fail' || step.status !== 'skipped' && Array.isArray(step.evidence) && step.evidence.some(row => row?.match === false))).map(step => step.id) : [];
  selected.push(...new Set(unexpectedFailures));
  const steps = selected.map(id => stepOf(trusted ? rawSteps.find(step => step.id === id && (step.status === 'fail' || step.status !== 'skipped' && Array.isArray(step.evidence) && step.evidence.some(row => row?.match === false))) || rawSteps.find(step => step.id === id) : null, id,
    { trusted, received, running, duplicates, phaseMismatch, recheck }));
  const anomalies = [];
  if (!running && !pending && phaseMismatch) anomalies.push('结果异常：返回记录的支付阶段与本步不一致，旧阶段结果未用于本步。');
  if (unexpectedFailures.length) anomalies.push('结果异常：服务端还返回了本步预期范围外的失败事项，以下保留其真实记录。');
  if (trusted && duplicates.size) anomalies.push('结果异常：服务端返回重复检查编号，请核对原始记录。');
  if (trusted && trace.outcome === 'pass' && steps.some(step => step.status === 'fail'))
    anomalies.push('结果异常：服务端整体结论为通过，但存在失败或不匹配的检查记录。');
  else if (trusted && trace.outcome === 'pass' && (!steps.length || steps.some(step => step.status !== 'pass')))
    anomalies.push('记录不完整：服务端整体结论为通过，本步仍有未执行、缺失或待核对的检查；不能推断逐项通过。');
  if (trusted && trace.outcome === 'fail' && !rawSteps.some(step => step.status === 'fail' || step.status !== 'skipped' && Array.isArray(step.evidence) && step.evidence.some(row => row?.match === false)))
    anomalies.push('结果异常：服务端整体结论为不通过，但未提供对应失败事项；请核对原始记录。');
  const groups = definitions.map(([id, title, groupIds, priority, description]) => {
    const groupSteps = steps.filter(step => groupIds.includes(step.id));
    let status = running ? 'running' : 'pending';
    if (groupSteps.some(step => step.status === 'fail')) status = 'fail';
    else if (groupSteps.length && groupSteps.every(step => step.status === 'pass') && trace?.outcome === 'pass') status = 'pass';
    else if (groupSteps.length && groupSteps.every(step => step.status === 'skipped')) status = 'skipped';
    return { id, title, priority, status, description, steps: groupSteps,
      missing: groupSteps.filter(step => step.missing).map(step => step.id) };
  }).filter(group => group.steps.length);
  const ungrouped = steps.filter(step => !definitions.some(([, , groupIds]) => groupIds.includes(step.id)));
  if (ungrouped.length) groups.push({ id: 'unexpected', title: '其他实际返回的失败事项', status: 'fail', steps: ungrouped, missing: [] });
  return { trusted, phaseMismatch, groups, steps, anomalies, outcome: trusted ? trace.outcome : null };
}

function renderValue(value) {
  if (value.length <= 96) return `<span>${escape(value)}</span>`;
  return `<details class="guide-evidence-value"><summary><code>${escape(value.slice(0, 36))}…${escape(value.slice(-18))}</code> 查看完整值</summary><code>${escape(value)}</code></details>`;
}
function renderRow(row) {
  const status = row.match === true ? 'match' : row.match === false ? 'mismatch' : 'material';
  const match = row.match === true ? '服务端记录：相符（字段比较）' : row.match === false ? '服务端记录：不相符'
    : '该字段用于材料展示，服务端未返回独立核验结论。';
  return `<div class="guide-evidence-row" data-state="${status}"><div class="guide-evidence-row-heading"><strong>${escape(row.label)}</strong><span>${match}</span></div><dl class="guide-evidence-pair"><div><dt>预期 · 验证约束</dt><dd>${renderValue(row.expected)}</dd></div><div><dt>实际 · 验证者 B 本次记录</dt><dd>${renderValue(row.observed)}</dd></div></dl>${row.note ? `<p class="guide-evidence-note">${escape(row.note)}</p>` : ''}</div>`;
}
function renderStep(step, materialsById) {
  const problem = step.status === 'fail' || step.status === 'unknown';
  const mismatch = step.rows.filter(row => row.match === false);
  const materials = typeof materialsById?.[step.id] === 'string' ? materialsById[step.id] : '';
  // Actual failed comparisons always stay in the visible core. Other records
  // show up to two returned rows; remaining rows have one non-repeating entry.
  const comparisons = step.rows.filter(row => row.expectedRecorded && row.observedRecorded);
  const core = mismatch.length ? mismatch : (problem && comparisons.length ? comparisons : step.rows).slice(0, 2);
  const more = step.rows.filter(row => !core.includes(row));
  const source = step.reportedStatus ? `来源：验证者 B 的本次检查记录；服务端状态：${labels[step.reportedStatus] || step.reportedStatus}。` : '来源：本步应执行检查的定义；尚无对应服务端结果。';
  const conclusion = step.status === 'pass' ? '验证者 B 返回本项通过；单项通过不代替其他必要检查或付款回执。'
    : step.status === 'fail' ? '本项实际记录为不通过；后续未执行项不能推断通过。'
      : step.status === 'skipped' ? '本次未执行本项，不能推断通过。'
        : step.status === 'running' ? '等待本次返回，尚无独立结论。' : '本项尚无完整、唯一且一致的实际结论。';
  const empty = !step.rows.length ? `<p class="guide-evidence-empty">${step.status === 'skipped' ? '没有本项实际比较值。' : '服务端未返回可展示的公开比较值；执行状态以上方记录为准。'}</p>` : '';
  const incompleteComparison = step.status === 'fail' && !comparisons.length ? '<p class="guide-evidence-note">服务端未返回完整的预期 / 实际比对；以下只展示已有公开记录与错误原因，不补写比较结果。</p>' : '';
  return `<section class="guide-evidence-step guide-operation-record" data-state="${step.status}" data-check-id="${escape(step.id)}"><div class="guide-evidence-step-heading"><strong>${escape(step.title)}${step.recheck ? '<small class="guide-recheck-label">本步复核</small>' : ''}</strong><span class="guide-record-status"><span aria-hidden="true">${symbols[step.status]}</span> ${labels[step.status]}</span></div><p class="guide-evidence-description">${escape(step.description)}</p>${problem ? `<p class="guide-evidence-problem">${escape(step.detail || '本项未通过；服务端未提供具体原因。')}${step.code ? ` <code>${escape(step.code)}</code>` : ''}</p>` : ''}${mismatch.length ? `<p class="guide-evidence-problem">不相符项：${mismatch.map(row => escape(row.label)).join('；')}。</p>` : ''}<div class="guide-evidence-core"><p class="guide-evidence-source"><strong>输入来源：</strong>${escape(source)}</p>${materials}<p class="guide-evidence-operation"><strong>操作 / 核验关系：</strong>${escape(checkRelations[step.id] || step.description)} <span class="guide-muted">关系说明本身不代表本次已执行。</span></p><div class="guide-evidence-output"><strong>输出 · 本次公开记录</strong>${incompleteComparison}${core.map(renderRow).join('')}${empty}</div><p class="guide-evidence-conclusion"><strong>结论：</strong>${escape(conclusion)}</p>${!problem && step.detail ? `<p class="guide-evidence-detail">${escape(step.detail)}</p>` : ''}${more.length ? `<details class="guide-evidence-more" data-detail-key="check-more-${escape(step.id)}"><summary>其余本项公开记录 · ${more.length} 项</summary>${more.map(renderRow).join('')}</details>` : ''}${step.omitted ? '<p class="guide-evidence-note">有记录不属于允许展示的公开标量字段，未展开。</p>' : ''}${step.truncated ? '<p class="guide-evidence-note">服务端公开记录已达到上限，后续比较值未返回。</p>' : ''}</div></section>`;
}

/** Caller-supplied materials must come from its existing public, escaped material renderer. */
export function renderVerificationChecks(trace, options = {}) {
  const { groups, anomalies } = verificationEvidenceModel(trace, options);
  return anomalies.map(message => `<p class="guide-evidence-anomaly" role="status">${escape(message)}</p>`).join('')
    + (groups.length ? groups.map(group => `<section class="guide-evidence-group${group.id === 'device' ? ' guide-evidence-group--device' : ''}" data-group-id="${escape(group.id)}"><h3 class="guide-evidence-group-title">${escape(group.title)}</h3>${group.id === 'device' ? `<p class="guide-device-group-note">${escape(group.description)}</p>` : ''}<div class="guide-evidence-records">${group.steps.map(step => renderStep(step, options.materialsById)).join('')}</div></section>`).join('')
      : '<p class="guide-evidence-empty">本步没有可展示的检查记录，不能据此推断验证通过。</p>');
}
