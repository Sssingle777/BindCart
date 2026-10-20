// Presentation-only records of checks that actually ran. Only explicitly
// selected public comparison values may enter evidence; no whole credential,
// proof object, access capability or private state is copied into these records.
function evidenceValue(value) {
  if (value === undefined || value === null) return null;
  if (typeof value === 'boolean' || typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') return value.length > 384 ? `${value.slice(0, 384)}…` : value;
  if (Array.isArray(value) && value.length <= 12 && value.every(item => !Array.isArray(item) && (item === null || typeof item !== 'object'))) return value.map(evidenceValue);
  throw new TypeError('Verification evidence accepts only public scalar values or small scalar arrays.');
}
const IDENTITY_STEPS = [
  ['request', '接收本地请求', '检查本地来源并读取请求正文。'],
  ['extension', '协商身份扩展', '请求必须声明 DID/VC 扩展。'],
  ['holder_envelope', '读取持有者证明', '检查 Bearer 证明是否存在及长度。'],
  ['holder_signature', '验证 Agent A 签名', '解析 DID 公钥并验证持有者 JWS 签名。'],
  ['holder_binding', '核对签名双方', '签名者、签发者和接收方必须一致。'],
  ['proof_time', '检查证明有效期', '检查短期时间窗口和证明编号。'],
  ['challenge', '核对一次性挑战', '检查挑战存在、有效期、主体和 nonce 绑定。'],
  ['replay', '检查挑战未使用', '已消费的挑战不能重复使用。'],
  ['request_binding', '核对请求哈希', '检查 POST、目标端点及原始正文哈希。'],
  ['credential', '验证 VC 及授权范围', '实际核验签发者签名、信任、主体、接收方、时效、撤销、scope 和设备绑定。'],
  ['device', '验证绑定设备证明', '使用 VC 内的设备 DID 验签，并核对持有者证明、凭证及请求绑定。'],
  ['consume', '消费一次性挑战', '全部身份检查通过后同步标记挑战已使用。'],
  ['execution', '处理 A2A 任务', '检查任务参数和业务权限，返回实际任务状态。'],
];
const DBAC_STEPS = [
  ['extension', '协商匿名扩展', '必须使用 DBAC 扩展且不携带具名身份请求头。'],
  ['envelope', '读取匿名证明', '检查正文长度及规范的匿名证明编码。'],
  ['challenge', '核对一次性挑战', '挑战必须存在且处于有效期内。'],
  ['replay', '检查挑战未使用', '拒绝已消费的匿名挑战。'],
  ['request_binding', '核对请求哈希', '实际正文哈希必须等于挑战绑定值。'],
  ['policy_context', '核对日期与方案', '检查当前披露策略日期以及展示的方案模式。'],
  ['scope', '检查匿名调用范围', '验证普通 A2A message/send 结构，仅允许 demo:echo。'],
  ['schema', '检查固定属性数量', '展示属性数量必须符合固定 schema。'],
  ['proof_structure', '检查展示结构', '核对版本、套件、模式以及披露属性的结构和索引。'],
  ['disclosure', '验证披露权限', '逐项检查角色、scope、日期和模式的要求值。'],
  ['proof_encoding', '解析曲线点和标量', '检查上下文、群元素、证明标量及隐藏属性响应。'],
  ['knowledge', '验证知识证明', '重建线性关系承诺并核对绑定上下文的 Fiat–Shamir 挑战。'],
  ['credential_pairing', '验证 BBS 凭证', '执行随机化 BBS 凭证签名的配对等式检查。'],
  ['device_pairing', '验证设备贡献', '执行适配设备签名的配对等式检查并绑定本次上下文。'],
  ['consume', '消费一次性挑战', '所有检查通过后同步消费挑战。'],
  ['execution', '执行匿名任务', '完成本次匿名 echo 并创建任务回执。'],
];
const DBAC_PAYMENT_STEPS = [
  ['merchant_order', '核对商家商品订单', '验证可信商家签名、完整商品快照、订单版本与支付收款目标。'],
  ['w3c_bbs', '验证 W3C BBS 派生凭证', '标准库验证可信签发方、披露证明和挑战。'],
  ['credential_status', '查询签发方凭证状态', '每阶段查询；撤销、未知或查询失败均拒绝。'],
  ['holder_signature', '验证 A 私钥签名', '核验签发方保护的公钥、VC、设备证明和上下文。'],
  ['vc_device_binding', '核对 VC 与 eSIM 绑定', '核对两份签名保护的同一绑定标识。'],
  ...DBAC_STEPS.filter(([id]) => !['consume', 'execution'].includes(id)).map(step => ({
    extension: ['extension', '协商设备绑定扩展', '必须使用设备绑定扩展且不携带具名身份请求头。'],
    envelope: ['envelope', '读取支付请求与设备绑定证明', '检查正文长度及规范的设备绑定证明编码。'],
    scope: ['scope', '核对支付阶段与订单', '仅允许 payments:pay，并绑定明确阶段、完整订单与收付款条款。'],
    credential_pairing: ['credential_pairing', '验证配套凭证配对', '验证 DBAC 随机化凭证签名配对。'],
  }[step[0]] ?? step)),
  ['owner_authorization', '验证 Owner 单笔授权', '验签并核对有效期、订单和绑定公钥。'],
  ['task_binding', '核对支付任务连续性', '继续同一授权、订单和公钥的付款任务。'],
  ['consume', '消费一次性支付挑战', '全部检查通过后原子消费。'],
  ['settlement_gate', '签发结算前验证证据', '签名绑定验证结果、授权及付款载荷。'],
  ['execution', '执行支付阶段', '返回本阶段实际任务或支付回执。'],
];

export function createVerificationTrace(profile) {
  const definitions = profile === 'dbac-payment' ? DBAC_PAYMENT_STEPS : profile === 'dbac' ? DBAC_STEPS : IDENTITY_STEPS;
  const steps = definitions.map(([id, title, detail]) => ({ id, title, actor: 'agent-b', status: 'skipped', detail }));
  const started = [];
  let active;
  return {
    start(id) { active = steps.find(step => step.id === id); if (!active) throw new Error(`Unknown verification stage: ${id}`); if (!started.includes(id)) started.push(id); },
    record(id, { label, expected, observed, match, note } = {}) {
      if (!active || active.id !== id) throw new Error(`Evidence requires an active verification stage: ${id}`);
      if (typeof label !== 'string' || !label || label.length > 96 || (match !== undefined && typeof match !== 'boolean') || (note !== undefined && (typeof note !== 'string' || note.length > 256))) throw new TypeError('Invalid verification evidence row.');
      const row = { label, ...(expected === undefined ? {} : { expected: evidenceValue(expected) }), observed: evidenceValue(observed), ...(match === undefined ? {} : { match }), ...(note === undefined ? {} : { note }) };
      active.evidence ??= [];
      const existing = active.evidence.findIndex(item => item.label === label);
      if (existing >= 0) active.evidence[existing] = row;
      else if (active.evidence.length < 8) active.evidence.push(row);
      else active.evidenceTruncated = true;
    },
    pass(id) { const step = steps.find(step => step.id === id); if (!step) throw new Error(`Unknown verification stage: ${id}`); step.status = 'pass'; if (active === step) active = null; },
    fail(error) { if (active) { active.status = 'fail'; active.code = String(error.code ?? 'INVALID_REQUEST'); active.detail += ` 检查终止（${active.code}）。`; active = null; } },
    snapshot() { return { profile, source: 'agent-b', outcome: steps.some(step => step.status === 'fail') ? 'fail' : 'pass', steps: structuredClone([...started.map(id => steps.find(step => step.id === id)), ...steps.filter(step => !started.includes(step.id))]) }; },
  };
}

export function preVerificationFailure(profile, error) {
  // Without a B trace, its internal checks cannot be claimed as passed.
  const trace = createVerificationTrace(profile).snapshot();
  return { ...trace, source: 'agent-a', outcome: 'fail', steps: [
    { id: 'preparation', title: '准备请求或设备证明', actor: 'agent-a', status: 'fail', code: String(error.code ?? 'ERROR'), detail: '请求准备、设备调用或通信阶段失败；未取得 B 的逐项验证记录。' },
    ...trace.steps,
  ] };
}
