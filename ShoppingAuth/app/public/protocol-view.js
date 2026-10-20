import { protocolChecks } from './protocol-model.js';

const fieldNames = {
  role: '角色', scope: '支付权限', epoch: '公共日期', mode: '设备模式',
  bindingId: '签发绑定标识', organization: '组织', holderLabel: '持有者标签',
};
const attributeNames = ['role', 'scope', 'epoch', 'mode', 'organization', 'holderLabel', 'bindingId'];
const publicNames = ['role', 'scope', 'epoch', 'mode', 'bindingId'];
const statusNames = { pass: '通过', fail: '拒绝', skipped: '未执行', pending: '待运行' };
const phaseNames = { proposal: '提案验证', authorize: '付款授权', settle: '结算验证' };
const stageNames = { IDLE: '尚未取挑战', CHALLENGE_READY: '挑战已返回', VC_DERIVED: 'VC 已派生', DEVICE_SIGNED: '设备贡献已返回', PROOF_READY: '证明已生成', VERIFIED: '验证已返回', OWNER_SUBMITTED: '提案已提交', WALLET_SIGNED: '钱包已签署', SETTLED: '结算已确认', EXPIRED: '挑战已过期', DISCARDED: '挑战已丢弃' };
const hasValue = value => value !== undefined && value !== null && value !== '';
const printable = value => typeof value === 'string' ? value : JSON.stringify(value, null, 2);
const short = value => value.length > 58 ? `${value.slice(0, 30)}…${value.slice(-14)}` : value;

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function note(parent, text) { parent.append(node('p', 'protocol-note', text)); }

function field(parent, label, value, { empty = '待运行 · 尚无返回值', source, expand = true } = {}) {
  const row = node('div', 'protocol-field-row');
  row.append(node('span', '', label));
  if (!hasValue(value)) row.append(node('span', 'protocol-state', empty));
  else {
    const full = printable(value);
    row.append(node('code', 'protocol-value', short(full.replace(/\n\s*/g, ' '))));
    if (expand && (full.length > 58 || typeof value === 'object')) {
      const details = node('details');
      details.append(node('summary', '', '完整值'), node('pre', 'protocol-value', full));
      row.append(details);
    }
  }
  if (source) row.title = `数据来源：${source}`;
  parent.append(row);
  return row;
}

function details(parent, title, render) {
  const element = node('details');
  element.append(node('summary', '', title));
  const body = node('div');
  render(body);
  element.append(body);
  parent.append(element);
}

function card(parent, title, description) {
  const element = node('section', 'protocol-card');
  element.append(node('h3', '', title));
  if (description) note(element, description);
  parent.append(element);
  return element;
}

function grid(parent, columns) {
  const element = node('div', 'protocol-grid');
  element.dataset.columns = String(columns);
  parent.append(element);
  return element;
}

function equation(parent, label, expression) {
  const row = node('div', 'protocol-equation');
  row.append(node('span', '', label), node('code', '', expression));
  parent.append(row);
}

function check(parent, label, status) {
  const state = Object.hasOwn(statusNames, status) ? status : 'pending';
  const element = node('div', 'protocol-check');
  element.dataset.state = state;
  element.append(node('span', '', label), node('strong', '', statusNames[state]));
  parent.append(element);
}

function compactCheck(parent, label, status) {
  const state = Object.hasOwn(statusNames, status) ? status : 'pending';
  const element = node('div', 'protocol-compact-check');
  element.dataset.state = state;
  element.append(node('span', '', label), node('strong', '', statusNames[state]));
  parent.append(element);
}

function evidence(snapshot, stepId, label) {
  return snapshot?.verificationTrace?.steps?.find(step => step.id === stepId)?.evidence?.find(row => row.label === label) ?? null;
}

function evidenceRows(parent, rows) {
  if (!Array.isArray(rows) || !rows.length) {
    note(parent, '未取得这项检查的实际比较值；不从公式推断通过。');
    return;
  }
  for (const row of rows) {
    const section = node('section');
    section.append(node('h4', '', row.label));
    if (Object.hasOwn(row, 'expected')) field(section, '预期 / 重建值', row.expected, { empty: '后端未记录' });
    field(section, '实际观察值', row.observed, { empty: '后端记录为空' });
    if (typeof row.match === 'boolean') check(section, '后端记录的 match', row.match ? 'pass' : 'fail');
    if (row.note) note(section, row.note);
    parent.append(section);
  }
}

function issueView(body, formulas, snapshot) {
  equation(formulas, '论文设备公钥', 'dpk = uH₀    W = xg₂');
  equation(formulas, '论文配套凭证', 'C = g₁ + dpk + Σ aᵢHᵢ₊₁    A = (x + ε)⁻¹C');
  const cards = grid(body, 2);
  const standard = card(cards, '① 标准 W3C VC', '签发方签署支付资格和 bindingId。');
  field(standard, '签发方', snapshot?.originalCredential?.issuer, { source: 'w3c.originalCredential.issuer' });
  field(standard, '标准签名套件', snapshot?.originalCredential?.proof?.cryptosuite, { source: 'w3c.originalCredential.proof.cryptosuite' });
  const standardBinding = snapshot?.originalCredential?.credentialSubject?.bindingId;
  field(standard, 'bindingId', standardBinding, { source: 'w3c.originalCredential.credentialSubject.bindingId' });
  details(standard, '标准签名、公钥和全部声明', content => {
    field(content, '标准 proofValue', snapshot?.originalCredential?.proof?.proofValue);
    field(content, '标准签发公钥', snapshot?.issuerProfile?.verificationMethod?.publicKeyMultibase);
    for (const name of attributeNames) field(content, `${fieldNames[name]} · ${name}`, snapshot?.originalCredential?.credentialSubject?.[name]);
  });
  const bound = card(cards, '② 论文设备绑定材料', '配套材料将相同 bindingId 与注册设备关联。');
  field(bound, '论文套件', snapshot?.credential?.suite, { source: 'credential.suite' });
  const paperBinding = snapshot?.credential?.attributes?.find(item => item.name === 'bindingId' || item.index === 6)?.value;
  field(bound, '同一次签发的 bindingId', paperBinding, { source: 'credential.attributes[index=6].value' });
  field(bound, '注册设备公钥指纹', snapshot?.credential ? snapshot?.device?.publicKeyFingerprint : null, { source: 'manual.device.publicKeyFingerprint' });
  details(bound, '本机设备公钥与材料边界', content => {
    field(content, 'dpk · 本机诊断公钥', snapshot?.credential ? snapshot?.device?.publicKey : null);
    note(content, 'u、x 为私钥，ε 为签名内部标量：私有，不展示。原始论文点 A、C 未由状态接口返回，不填写数值。');
    note(content, '设备指纹来自本机设备状态；长期公钥不会作为此字段直接发送给 Agent B。');
  });
  if (hasValue(standardBinding) && hasValue(paperBinding)) {
    check(body, '两份已返回材料的 bindingId 逐字相同', standardBinding === paperBinding ? 'pass' : 'fail');
    note(body, '此处比较公开标识；标准签名和设备证明是否有效，仍由后续验证器实际检查。');
  } else note(body, '待实际签发后展示两份材料的对应标识。上式属于论文配套凭证；标准 bbs-2023 的 proofValue 使用独立密钥和编码。');
}

function deriveView(body, formulas, snapshot) {
  equation(formulas, '按真实依赖顺序', 'ctx → PH → VC_d → h_VC → ctx*');
  equation(formulas, '挑战与派生文档绑定', 'PH = SHA-256(D_ph ∥ Canon(ctx))    h_VC = SHA-256(D_vc ∥ Canon(VC_d))');
  equation(formulas, '交给设备层的上下文', 'ctx* = ctx ∪ { w3cPresentationHash: h_VC }');
  const cards = grid(body, 2);
  const disclosure = card(cards, '① 7 项声明 → 公开 5 项、隐藏 2 项', '左侧原始声明供持有者查看；箭头后是派生文档实际携带的字段。');
  const original = snapshot?.originalCredential?.credentialSubject, derived = snapshot?.derivedCredential?.credentialSubject;
  for (const name of attributeNames) {
    const row = node('div', 'protocol-field-row');
    row.append(node('span', '', `${fieldNames[name]} · ${name}`));
    const originalValue = hasValue(original?.[name]) ? printable(original[name]) : '待签发';
    const derivedValue = !derived ? '待派生' : hasValue(derived[name]) ? printable(derived[name]) : publicNames.includes(name) ? '字段缺失' : '未披露';
    row.append(node('span', 'protocol-value', `${short(originalValue)} → ${short(derivedValue)}`));
    if (originalValue.length > 58 || derivedValue.length > 58) details(row, '完整声明值', content => {
      field(content, '持有者原始值', original?.[name]);
      field(content, '派生文档中的值', derived?.[name], { empty: derived ? '派生文档没有此字段' : '待派生' });
    });
    disclosure.append(row);
  }
  if (derived) {
    const disclosed = attributeNames.filter(name => Object.hasOwn(derived, name));
    note(disclosure, `本快照实际携带 ${disclosed.length} 项声明；字段缺失仅表示未披露，签名有效性由 B 检查。`);
  }
  const binding = card(cards, '② 这份证明只属于本次挑战', 'A 本地调用标准派生库，随后把精确派生文档的哈希交给设备层。');
  field(binding, 'ctx · 挑战编号', snapshot?.challenge?.challengeId, { source: 'manual.challenge.challengeId' });
  field(binding, 'PH · 实际派生输入', snapshot?.cryptography?.presentationHeader, { source: 'manual.cryptography.presentationHeader' });
  field(binding, 'h_VC · 精确派生文档哈希', snapshot?.cryptography?.w3cPresentationHash, { source: 'manual.cryptography.w3cPresentationHash' });
  field(binding, 'ctx* 中的 h_VC', snapshot?.deviceRequest?.context?.w3cPresentationHash, { empty: snapshot?.mode === 'bbs-blind-bls' ? '盲模式设备请求仅含 Q′，不发送明文 ctx*' : '待派生后返回设备输入' });
  details(binding, '挑战、派生证明与消息边界', content => {
    field(content, 'B 签发的 ctx', snapshot?.challenge);
    field(content, '标准派生 proofValue', snapshot?.derivedCredential?.proof?.proofValue);
    field(content, '设备实际请求', snapshot?.deviceRequest);
    note(content, 'D_ph 与 D_vc 是应用的用途隔离前缀；PH 不是标准套件内部 bbsHeader。Canon 是应用 JSON 编码，标准 VC 的 RDF 规范化由库完成。');
  });
}

function deviceView(body, formulas, snapshot) {
  const blind = snapshot?.mode === 'bbs-blind-bls';
  equation(formulas, '每订单设备伪名', 'dpk̃ = dpk + kH₀    Q = HashToG₂(Canon(version, suite, dpk̃, ctx*))');
  equation(formulas, blind ? '盲化模式' : '普通模式', blind ? 'Q′ = βQ → σ′ = uQ′ → σ = β⁻¹σ′' : '模拟 eSIM：σ = uQ');
  equation(formulas, 'A 适配与随机化', 'πₛₑ = σ + kQ    C̄ = r₁C    Ā = r₁r₂A    B̄ = r₂C̄ − εĀ');
  if (snapshot && !snapshot.deviceResponse) note(body, `所选快照停在“${stageNames[snapshot.stage] || '尚无设备响应'}”；下面的设备返回与生成证明仍待实际执行。`);
  else if (snapshot?.deviceResponse && !snapshot.presentation) note(body, '所选快照已收到设备贡献，尚未生成论文展示；两步数据不合并为一次完成。');
  const cards = grid(body, 3);
  const request = card(cards, '① A → 模拟 eSIM', blind ? '实际发送盲化点 Q′，设备不接收原始挑战明文。' : '实际发送公开上下文，设备据此计算消息点 Q。');
  if (blind) field(request, 'Q′ · 实际盲化点', snapshot?.deviceRequest?.blindedPoint, { source: 'manual.deviceRequest.blindedPoint' });
  else {
    field(request, 'ctx* · 正文哈希', snapshot?.deviceRequest?.context?.bodyHash);
    field(request, 'ctx* · 派生 VC 哈希', snapshot?.deviceRequest?.context?.w3cPresentationHash);
    field(request, 'dpk̃ · 订单设备伪名', snapshot?.deviceRequest?.randomizedDevicePublicKey);
  }
  details(request, '设备收到的完整公开请求', content => field(content, 'request', snapshot?.deviceRequest));
  const response = card(cards, '② 模拟 eSIM → A', '只有设备使用私钥 u 计算贡献；页面不取得 u。');
  field(response, blind ? 'σ′ · 设备实际返回' : 'σ · 设备实际返回', snapshot?.deviceResponse?.signature, { source: 'manual.deviceResponse.signature' });
  field(response, '设备公钥指纹', snapshot?.deviceResponse ? snapshot?.device?.publicKeyFingerprint : null);
  if (blind) note(response, '解盲后的 σ 由 A 内部计算，当前接口未返回这一中间点：未接入，不填数值。');
  else note(response, 'σ 是设备原始贡献；发送给 B 的 πₛₑ 还要加入订单随机化项。');
  const proof = card(cards, '③ A → 待发送展示', 'A 先检查设备贡献，再生成随机化凭证和知识证明。');
  field(proof, 'πₛₑ · 适配设备贡献', snapshot?.presentation?.deviceSignature, { source: 'manual.presentation.deviceSignature' });
  field(proof, 'Ā', snapshot?.presentation?.Abar);
  field(proof, 'B̄', snapshot?.presentation?.Bbar);
  field(proof, 'C̄', snapshot?.presentation?.Cbar);
  field(proof, 'c · 公开证明挑战', snapshot?.presentation?.proof?.challenge);
  details(proof, '知识证明的公开响应', content => {
    const responses = snapshot?.presentation?.proof?.responses;
    field(content, 'z_w · inverseR1', responses?.inverseR1);
    field(content, 'z_k · keyRandomizer', responses?.keyRandomizer);
    field(content, 'z_r · r2', responses?.r2);
    field(content, 'z_ε · e', responses?.e);
    field(content, '隐藏声明的公开响应 z_j', responses?.hidden);
    note(content, '这些值是公开证明响应，不是私有的 k、r₁、r₂、ε、β 或隐藏声明本身。随机化因子不从后端导出。');
  });
  note(body, '设备贡献、展示生成和 B 的最终验证是三个动作。点已返回不等于验证已通过；查看下一步的真实检查轨迹。');
}

const groups = [
  ['standard', '① 标准凭证', '核验派生证明及本次 PH。'],
  ['binding', '② 跨层与请求绑定', '核对正文、bindingId 和设备贡献。'],
  ['knowledge', '③ 知识证明与凭证配对', '重建 c，检查论文凭证配对。'],
  ['device', '④ 本次设备贡献', '重算 Q，检查适配设备贡献。'],
];

function verificationProvenance(parent, snapshot, negative) {
  const section = node('div', 'protocol-verification-provenance');
  const identifier = value => hasValue(value) ? `…${String(value).slice(-8)}` : '未记录';
  const summary = (label, value) => `${label} · ${phaseNames[value?.phase] || '阶段未记录'} · attempt ${identifier(value?.attemptId)} · challenge ${identifier(value?.challenge?.challengeId)}`;
  section.append(node('p', '', summary('当前选定请求', snapshot)));
  if (negative) {
    section.append(node('p', '', summary('缺设备请求', negative)));
    const currentId = snapshot?.challenge?.challengeId, negativeId = negative?.challenge?.challengeId;
    section.append(node('p', '', hasValue(currentId) && hasValue(negativeId)
      ? currentId === negativeId ? '同一 challengeId；两个提交的检查轨迹分别保存。' : '不同 challengeId；对照各自的真实请求，不混用检查值。'
      : '挑战关联未确认：某份快照缺少 challengeId。'));
  }
  details(section, '完整 attempt / challenge 标识', content => {
    field(content, '当前 attemptId', snapshot?.attemptId);
    field(content, '当前 challengeId', snapshot?.challenge?.challengeId);
    if (negative) {
      field(content, '缺设备 attemptId', negative.attemptId);
      field(content, '缺设备 challengeId', negative.challenge?.challengeId);
    }
  });
  parent.append(section);
}

function verifyView(body, formulas, snapshot, negative) {
  equation(formulas, '标准层 / 跨层绑定', 'ProofVerify_bbs-2023(…, PH) = true ∧ VC_d.credentialSubject.bindingId = disclosed[index=6]');
  equation(formulas, '论文层检查', 'c_received ≟ H(statement, ctx*, T₁, T₂)    E(Ā, W) ≟ E(B̄, g₂)');
  equation(formulas, '设备层检查', 'E(H₀, πₛₑ) ≟ E(dpk̃, Q)');
  const current = protocolChecks(snapshot), rejected = protocolChecks(negative);
  if (snapshot && !snapshot.verificationTrace) note(body, `所选快照停在“${stageNames[snapshot.stage] || '尚无验证返回'}”；尚无 B 的联合验证记录，下面各项保持未执行。`);
  const cards = grid(body, 4);
  for (const [id, title, description] of groups) {
    const group = current[id], other = rejected[id];
    const element = card(cards, title, description);
    compactCheck(element, '本请求', group?.status);
    compactCheck(element, '缺设备对照', negative ? other?.status : 'pending');
    if (id === 'standard') {
      const record = evidence(snapshot, 'w3c_bbs', 'proof type / suite / issuer');
      field(element, '实际套件', Array.isArray(record?.observed) ? record.observed[1] : null, { empty: '尚无标准检查记录', expand: false });
    } else if (id === 'binding') {
      const record = evidence(snapshot, 'vc_device_binding', 'bindingId / mode / device contribution');
      field(element, '收到的 bindingId', Array.isArray(record?.observed) ? record.observed[0] : null, { empty: '尚无绑定标识记录', expand: false });
      const bodyHash = evidence(snapshot, 'request_binding', 'raw body SHA-256');
      if (typeof bodyHash?.match === 'boolean') compactCheck(element, '正文哈希相符', bodyHash.match ? 'pass' : 'fail');
    } else if (id === 'knowledge') {
      const challenge = evidence(snapshot, 'knowledge', 'Fiat-Shamir challenge');
      field(element, '收到的 c', challenge?.observed, { empty: '尚无比较值', expand: false });
      field(element, '重建的 c', challenge?.expected, { empty: '尚无重建值', expand: false });
      if (typeof challenge?.match === 'boolean') compactCheck(element, 'c 比较', challenge.match ? 'pass' : 'fail');
      const pairing = evidence(snapshot, 'credential_pairing', 'e(Abar,W) = e(Bbar,G2)');
      if (typeof pairing?.observed === 'boolean') compactCheck(element, '论文凭证配对', pairing.observed ? 'pass' : 'fail');
    } else {
      const pairing = evidence(snapshot, 'device_pairing', 'e(H0,pi_se) = e(randomizedKey,Q)');
      if (typeof pairing?.observed === 'boolean') compactCheck(element, '设备贡献配对', pairing.observed ? 'pass' : 'fail');
      note(element, 'Q 的实际点值在检查依据中展开。');
    }
    details(element, '实际 expected / observed / match', content => {
      for (const step of group?.steps ?? []) {
        check(content, step.title || step.id, step.status);
        if (step.code) field(content, '拒绝码', step.code);
      }
      evidenceRows(content, group?.evidence);
      if (id === 'knowledge') note(content, 'T₁ / T₂ 是验证器从公开响应重建的公开承诺；没有记录时不补算。');
    });
    if (negative) details(element, '缺设备请求的真实检查依据', content => evidenceRows(content, other?.evidence));
  }
  if (negative) {
    const failure = negative.verificationTrace?.steps?.find(step => step.status === 'fail');
    field(body, '缺设备请求的实际拒绝原因', failure?.code ?? negative.error?.code, { empty: '未取得明确拒绝码' });
    note(body, '缺设备请求若在跨层检查处终止，后面的知识证明和配对是“未执行”，不是各自验算失败。');
  } else note(body, '尚未取得缺设备请求的对应快照；对照栏保持待运行。');
  verificationProvenance(body, snapshot, negative);
}

function paymentView(body, formulas, snapshot) {
  equation(formulas, '支付门槛', '资格与设备证明通过 → Owner 明确批准 → 钱包签署 → 新结算证明 → 匹配订单的回执');
  const cards = grid(body, 3);
  const input = card(cards, '① 同一订单', '每个阶段继续绑定这笔订单的金额、收款方及设备伪名。');
  const payment = snapshot?.payment ?? snapshot?.order;
  field(input, '订单编号', payment?.orderId ?? snapshot?.orderId);
  field(input, '金额（最小单位）', payment?.amountMinor, { empty: '未接入此快照' });
  field(input, '币种 / 收款方', payment ? [payment.currency, payment.payeeAccount] : null, { empty: '未接入此快照' });
  const approval = card(cards, '② 批准与签署', '资格通过只允许提交提案；Owner 批准和钱包签署仍是独立步骤。');
  field(approval, 'Owner 明确批准', typeof snapshot?.ownerApprovalObserved === 'boolean' ? snapshot.ownerApprovalObserved ? '已确认' : '尚未确认' : null, { empty: '未读取独立 Owner 状态' });
  field(approval, 'Agent 保存的提案状态', snapshot?.proposal?.status, { empty: '尚无提案状态记录' });
  field(approval, 'Agent 已同步授权', typeof snapshot?.ownerApproved === 'boolean' ? snapshot.ownerApproved ? '已取得' : '尚未取得' : null, { empty: '未接入此快照' });
  field(approval, '钱包实际状态', snapshot?.walletSigningUnconfirmed ? '签名请求已发出，返回未确认' : snapshot?.walletSigned === true ? '已返回签名，仍需结算回执' : snapshot?.walletSigned === false ? '尚未取得签名' : null, { empty: '未接入此快照' });
  const result = card(cards, '③ 业务结果', '结算配对检查通过之后，仍需读取匹配原订单的实际付款回执。');
  field(result, '实际 outcome', snapshot?.paymentResult?.outcome, { empty: '尚无最终付款结果' });
  field(result, '交易哈希', snapshot?.paymentResult?.receipt?.transactionHash, { empty: '尚无交易回执' });
  field(result, '本阶段', phaseNames[snapshot?.phase] ?? null);
  note(body, '这里展示本地 TEST_USDC 执行状态。完整付款签名、地址和回执留在详情；一次成功不代表完整系统安全证明。');
}

const views = {
  issue: ['签发：把资格与设备连到同一记录', '签发方分别提供标准 VC 和论文配套材料，共享签发绑定标识。'],
  derive: ['派生：少披露声明，绑定本次请求', 'Agent A 从已签发 VC 生成选择性披露证明，随后固定这份派生文档。'],
  device: ['设备参与：一次真实贡献进入证明', '模拟 eSIM 用私钥计算贡献；A 核验、适配并生成公开证明。'],
  verify: ['验证：让每项技术主张对应实际检查', 'Agent B 分层核验；同时保留“有效 VC，但缺设备”的实际对照。'],
  payment: ['支付：验证之后还要逐笔批准与结算', '密码学证明约束使用权；Owner 的精确授权和最终回执约束业务执行。'],
};

// Rendering is read-only: snapshots are supplied by the controller. No fetch,
// local cryptographic computation, timers, signing, or guessed evidence here.
export function renderProtocol({ view = 'issue', snapshot = null, negative = null, stale = false, history = false, phaseLabel } = {}) {
  const title = document.getElementById('protocol-title');
  const purpose = document.getElementById('protocol-purpose');
  const formulas = document.getElementById('protocol-formulas');
  const body = document.getElementById('protocol-body');
  const observation = document.getElementById('protocol-observation');
  if (!title || !purpose || !formulas || !body || !observation) return;
  const selected = Object.hasOwn(views, view) ? view : 'issue';
  title.textContent = views[selected][0];
  purpose.textContent = views[selected][1];
  formulas.replaceChildren(); body.replaceChildren();
  if (selected === 'issue') issueView(body, formulas, snapshot);
  else if (selected === 'derive') deriveView(body, formulas, snapshot);
  else if (selected === 'device') deviceView(body, formulas, snapshot);
  else if (selected === 'verify') verifyView(body, formulas, snapshot, negative);
  else paymentView(body, formulas, snapshot);
  const origin = stale ? '输入已更改：以下旧结果已失效' : history ? '已保存的真实执行快照' : snapshot?.attemptId || snapshot?.originalCredential ? '本次后端执行快照' : '原理预览 · 尚无本次执行结果';
  const phase = phaseLabel || phaseNames[snapshot?.phase];
  const stage = stageNames[snapshot?.stage];
  observation.textContent = `${origin}${phase ? ` · ${phase}` : ''}${stage ? ` · 快照停在：${stage}` : ''}。关系式用于说明协议；点、哈希、响应和检查结果只显示已返回数据。`;
  observation.dataset.state = stale ? 'stale' : history ? 'history' : 'current';
}
