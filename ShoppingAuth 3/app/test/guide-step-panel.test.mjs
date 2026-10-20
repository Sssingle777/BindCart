import test from 'node:test';
import assert from 'node:assert/strict';
import { currentStepPanel, currentVerificationTrace, renderStepSummary, renderStepDetail, renderStepMaterial, renderDeviceParticipation } from '../public/guide-step-detail.js';
import { verificationVerdict } from '../public/guide-model.js';

const localOrganization = 'LOCAL_UNDISCLOSED_ORGANIZATION';
const localHolderLabel = 'LOCAL_UNDISCLOSED_HOLDER_LABEL';
const privateSentinel = 'PRIVATE_MATERIAL_MUST_NOT_APPEAR';
const baseCheckIds = ['extension', 'envelope', 'challenge', 'replay', 'request_binding', 'policy_context', 'scope', 'w3c_bbs', 'schema', 'vc_device_binding', 'proof_structure', 'disclosure', 'proof_encoding', 'knowledge', 'credential_pairing', 'device_pairing', 'holder_signature', 'credential_status', 'consume', 'execution'];
function traceFor(phase = 'proposal') {
  const ids = [...baseCheckIds, ...(phase === 'proposal' ? [] : ['owner_authorization']), ...(phase === 'settle' ? ['task_binding', 'settlement_gate'] : [])];
  return { source: 'agent-b', profile: 'dbac-payment', outcome: 'pass', steps: ids.map(id => ({
    id, title: id, status: 'pass', evidence: id === 'scope'
      ? [{ label: 'method / scope / phase', observed: ['message/send', 'payments:pay', phase] }, { label: 'payment order ID', observed: 'order-current' }]
      : id === 'execution' ? [{ label: 'phase / resulting task', observed: [phase, phase === 'settle' ? 'completed' : 'input-required'] }] : [],
  })) };
}
function fixture(phase = 'proposal') {
  const subject = { role: 'authorized-agent', scope: 'payments:pay', epoch: '2026-10-11', mode: 'bbs-bls', bindingId: 'binding-current', holderDid: 'did:key:holder-current' };
  return {
    available: true, mode: 'bbs-bls', currentCredentialId: 'credential-current', credential: { suite: 'test-suite' },
    order: { orderId: 'order-current', amountMinor: 2990000, currency: 'TEST_USDC', payeeAccount: 'merchant-current', payerAccount: 'payer-current' },
    w3c: { originalCredential: { credentialSubject: { ...subject, organization: localOrganization, holderLabel: localHolderLabel, secretKey: privateSentinel } },
      disclosedPaths: Object.keys(subject).map(key => `/credentialSubject/${key}`), hiddenPaths: ['/credentialSubject/organization', '/credentialSubject/holderLabel'] },
    manual: { attemptId: 'attempt-current', active: true, phase, stage: 'PROOF_READY',
      challenge: { challengeId: 'challenge-current', bodyHash: 'body-current', paymentOrderId: 'order-current', scope: 'payments:pay' },
      verifiableCredential: { credentialSubject: subject },
      device: { available: true, publicKeyFingerprint: 'fingerprint-current', publicKey: 'device-public-current', secretKey: privateSentinel },
      deviceRequest: { mode: 'bbs-bls', context: { challengeId: 'challenge-current' }, secret: privateSentinel },
      deviceResponse: { mode: 'bbs-bls', signature: 'device-signature-current' },
      holderProof: 'header.payload.signature', presentation: { Abar: 'public-point-current', secret: privateSentinel },
      verificationResult: { mode: 'bbs-bls', phase, verificationTrace: traceFor(phase) },
    },
  };
}
const panelFor = (state, id, options = {}) => currentStepPanel(state, { plan: { id, description: '本步任务说明' }, ...options });

test('exact action IDs select current materials even when labels and the snapshot contain later results', () => {
  const state = fixture();
  const expected = {
    issue: 'credential', new: 'credential', 'begin-proposal': 'challenge', 'begin-authorize': 'challenge', 'begin-settle': 'challenge',
    'derive-vc': 'disclosure', 'device-sign': 'device', prove: 'holder', verify: 'verification',
    'submit-owner': 'owner', 'owner-review': 'owner', 'sync-owner': 'owner', 'wallet-sign': 'wallet',
  };
  for (const [id, kind] of Object.entries(expected)) {
    const panel = currentStepPanel(state, { plan: { id, label: '结算验证与凭证准备', description: '共同证明，用户授权，全部通过' } });
    assert.equal(panel.kind, kind, id);
    assert.equal(panel.verification, id === 'verify', id);
    if (!panel.verification) assert.equal(panel.trace, null, `${id} cannot inherit a B trace as its own result`);
  }
  assert.equal(panelFor(state, '未注册中文验证步骤').kind, 'review');
  assert.equal(panelFor(state, 'verify', { action: 'device-sign' }).kind, 'device', 'actual running action owns the current panel');
});

test('credential preparation summary omits transaction, proof and verifier details', () => {
  const html = renderStepSummary(panelFor(fixture(), 'issue'));
  assert.match(html, /credential-current|fingerprint-current|模拟 eSIM/);
  assert.doesNotMatch(html, /order-current|merchant-current|challenge-current|public-point-current|已授权|验证通过/);
});

test('current operation evidence is open while prior records and long individual values stay collapsed', () => {
  const state = fixture();
  const cases = [
    ['issue', /A 本地持有 · 原始 VC/, /设备签名贡献|签名算法|用户决定/],
    ['derive-vc', /本次包含：角色、调用权限/, /设备签名贡献|签名算法|用户决定/],
    ['device-sign', /设备签名贡献/, /A 本地持有 · 原始 VC|签名算法|用户决定/],
    ['prove', /签名算法/, /A 本地持有 · 原始 VC|设备签名贡献|用户决定/],
    ['owner-review', /用户决定/, /A 本地持有 · 原始 VC|设备签名贡献|签名算法/],
    ['wallet-sign', /钱包材料状态/, /A 本地持有 · 原始 VC|设备签名贡献|签名算法/],
  ];
  for (const [id, present, absent] of cases) {
    const html = renderStepDetail(state, { plan: { id } });
    assert.match(html, present, id);
    const currentRecord = html.slice(html.indexOf(`data-operation-id="${id}"`));
    assert.doesNotMatch(currentRecord, absent, id);
    assert.match(currentRecord, /<details class="guide-material-section" open>/, id);
    assert.doesNotMatch(html, /<details class="(?:guide-prerequisite|guide-public-value)"[^>]*\sopen(?:\s|>)/, id);
    assert.match(currentRecord, /guide-operation-flow/);
    assert.doesNotMatch(currentRecord, /data-check-id=|本次材料逐项对照/, id);
    if (['owner-review', 'wallet-sign'].includes(id)) assert.match(html, /<details class="guide-prerequisite"[^>]*><summary>[^<]*前一步已通过/);
    else assert.doesNotMatch(html, /data-check-id=/, id);
  }
  for (const id of ['verify', 'refresh']) assert.equal(renderStepDetail(state, { plan: { id } }), '');
});

test('device participation keeps the derived VC reachable only through a collapsed read-only prerequisite', () => {
  const state = fixture(), original = structuredClone(state);
  const html = renderStepDetail(state, { plan: { id: 'device-sign' } });
  const firstDetails = html.indexOf('<details'), currentOperation = html.indexOf('<article class="guide-operation-record" data-operation-id="device-sign"');
  const visibleSummary = html.slice(0, firstDetails), priorOperation = html.slice(firstDetails, currentOperation), currentRecord = html.slice(currentOperation);
  assert.match(visibleSummary, /选择性披露：本次包含角色、调用权限、策略日期、设备模式、绑定标识、持有者公钥标识；未包含组织、持有者标签/);
  assert.match(visibleSummary, /来源：持有者 A 本地已生成/);
  for (const value of [localOrganization, localHolderLabel, privateSentinel]) assert.ok(!visibleSummary.includes(value));
  assert.match(priorOperation, /^<details class="guide-prerequisite" data-detail-key="previous-vc-attempt-current"><summary>查看上一操作的 VC 对照<\/summary>/);
  assert.match(priorOperation, /只读回看|不表示验证者 B 已收到或验证通过|展开不会重新派生、签名或提交请求/);
  assert.match(priorOperation, /A 本地持有 · 原始 VC/);
  assert.match(priorOperation, /A 将出示 · 派生 VC/);
  assert.doesNotMatch(priorOperation, /<details\b[^>]*\sopen(?:\s|>)|\bon(?:click|toggle)=|data-experiment-action=|<button/);
  assert.doesNotMatch(currentRecord, /guide-credential-compare|A 本地持有 · 原始 VC|A 将出示 · 派生 VC|LOCAL_UNDISCLOSED|data-check-id=/);
  assert.deepEqual(state, original, 'history rendering does not alter the active request');
  assert.equal(renderStepDetail(state, { plan: { id: 'device-sign' } }), html, 'refreshing the view does not regenerate any material');
});

test('the disclosure prerequisite follows actual document presence and preserves source boundaries', () => {
  const state = fixture();
  state.manual.sentCredential = structuredClone(state.manual.verifiableCredential);
  state.manual.sentCredential.credentialSubject.organization = localOrganization;
  const html = renderStepDetail(state, { plan: { id: 'device-sign' } });
  const summary = html.slice(0, html.indexOf('<details'));
  assert.match(summary, /本次包含[^；]*组织；未包含持有者标签/);
  assert.match(summary, /来源：持有者 A 已发送记录/);
  assert.doesNotMatch(summary, /LOCAL_UNDISCLOSED|验证通过|B 已收到/);
  assert.match(html, /A 已发送 · 派生 VC/);
  state.manual.verifiableCredential = null;
  assert.doesNotMatch(renderStepDetail(state, { plan: { id: 'device-sign' } }), /查看上一操作的 VC 对照|guide-disclosure-prerequisite/);
  for (const id of ['prove', 'verify', 'owner-review', 'wallet-sign']) assert.doesNotMatch(renderStepDetail(fixture(), { plan: { id } }), /查看上一操作的 VC 对照|guide-disclosure-prerequisite/);
});

test('beginning a new phase never exposes a previous phase challenge or proof as its new material', () => {
  const state = fixture('proposal');
  state.manual.challenge.challengeId = 'OLD_PHASE_CHALLENGE';
  state.manual.cryptography = { presentationHeader: 'OLD_PHASE_HEADER', w3cPresentationHash: 'OLD_PHASE_VC_HASH' };
  for (const id of ['begin-authorize', 'begin-settle']) {
    const panel = panelFor(state, id);
    assert.equal(panel.phase, id === 'begin-authorize' ? 'authorize' : 'settle');
    assert.equal(panel.trace, null);
    const html = renderStepSummary(panel) + renderStepDetail(state, { plan: { id }, panel });
    assert.doesNotMatch(html, /OLD_PHASE_CHALLENGE|OLD_PHASE_HEADER|OLD_PHASE_VC_HASH/);
  }
});

test('each verification phase uses its own new trace and identifies the actual recheck', () => {
  for (const [phase, recheck] of [['proposal', ''], ['authorize', '本步复核'], ['settle', '结算阶段复核']]) {
    const state = fixture(phase), panel = panelFor(state, 'verify');
    assert.equal(panel.trace, state.manual.verificationResult.verificationTrace);
    assert.equal(panel.recheck, recheck);
    assert.equal(verificationVerdict(panel.trace, { phase }).status, 'pass');
    state.lastResult = state.manual.verificationResult;
    state.manual.verificationResult = null;
    assert.equal(panelFor(state, 'verify').trace, null, 'lastResult cannot stand in for a new attempt');
  }
});

test('current trace rejects mismatching result mode, phase, order, source and evidence phase', () => {
  const mutations = [
    state => { state.manual.verificationResult.mode = 'bbs-blind-bls'; },
    state => { state.manual.verificationResult.phase = 'authorize'; },
    state => { state.manual.verificationResult.verificationTrace.source = 'agent-a'; },
    state => { state.manual.verificationResult.verificationTrace.profile = 'dbac'; },
    state => { state.manual.verificationResult.verificationTrace.steps.find(step => step.id === 'scope').evidence[0].observed[2] = 'settle'; },
    state => { state.manual.verificationResult.verificationTrace.steps.find(step => step.id === 'execution').evidence[0].observed[0] = 'authorize'; },
    state => { state.manual.verificationResult.verificationTrace.steps.find(step => step.id === 'scope').evidence[1].observed = 'other-order'; },
  ];
  for (const mutate of mutations) { const state = fixture(); mutate(state); assert.equal(currentVerificationTrace(state), null); }
  assert.equal(currentVerificationTrace(null), null);
});

test('current B failure is retained even if an older success result still exists', () => {
  const state = fixture('authorize');
  state.manual.verificationResult.phase = 'proposal';
  const errorTrace = traceFor('authorize');
  const failed = errorTrace.steps.find(step => step.id === 'credential_status');
  failed.status = 'fail'; failed.code = 'W3C_CREDENTIAL_REVOKED';
  errorTrace.outcome = 'fail';
  state.manual.lastError = { code: failed.code, message: '当前凭证已撤销', verificationTrace: errorTrace };
  assert.equal(currentVerificationTrace(state), errorTrace);
  assert.equal(panelFor(state, 'verify').trace, errorTrace);
});

test('network uncertainty and an in-flight verify never repeat an earlier success as current validation', () => {
  const state = fixture('authorize');
  state.manual.lastError = { code: 'TRANSPORT_TIMEOUT', message: '未收到确定响应' };
  assert.equal(panelFor(state, 'verify', { uncertain: true }).trace, null);
  assert.equal(panelFor(state, 'verify', { action: 'verify' }).trace, null);
  assert.equal(panelFor(state, 'wallet-sign', { uncertain: true }).prerequisite, null);
  assert.equal(panelFor(state, 'owner-review', { uncertain: true }).prerequisite, null);
});

test('empty, partial and contradictory traces remain incomplete or failed without inventing check results', () => {
  for (const steps of [[], [{ id: 'w3c_bbs', status: 'pass' }], [{ id: 'w3c_bbs', status: 'skipped' }]]) {
    const state = fixture();
    state.manual.verificationResult.verificationTrace.steps = steps;
    const panel = panelFor(state, 'verify');
    assert.equal(verificationVerdict(panel.trace, { phase: 'proposal' }).status, 'pending');
    assert.deepEqual(panel.trace.steps, steps);
  }
  const state = fixture(), trace = state.manual.verificationResult.verificationTrace;
  trace.steps.find(step => step.id === 'holder_signature').status = 'fail';
  const panel = panelFor(state, 'verify');
  assert.equal(panel.trace.outcome, 'pass', 'keep the server overall conclusion intact for conflict reporting');
  assert.equal(verificationVerdict(panel.trace, { phase: 'proposal' }).status, 'fail');
});

test('summary distinguishes local generation, A sending, user approval and payment completion', () => {
  const state = fixture('authorize');
  let html = renderStepSummary(panelFor(state, 'verify'));
  assert.match(html, /A 本地已生成 · 尚未发送/);
  assert.doesNotMatch(html, /B 已收到|支付完成/);
  state.manual.sentCredential = structuredClone(state.manual.verifiableCredential);
  html = renderStepSummary(panelFor(state, 'verify'));
  assert.match(html, /A 已发送/);
  assert.doesNotMatch(html, /B 已收到|支付完成/);
  state.proposal = { status: 'APPROVED' };
  assert.match(renderStepSummary(panelFor(state, 'wallet-sign')), /已批准 · 待同步/);
  state.authorization = { document: {} };
  assert.match(renderStepSummary(panelFor(state, 'wallet-sign')), /已授权/);
  assert.doesNotMatch(renderStepSummary(panelFor(state, 'wallet-sign')), /支付完成/);
  state.proposal.status = 'REJECTED';
  assert.match(renderStepSummary(panelFor(state, 'owner-review')), /已拒绝/);
});

test('hidden local attribute values and secret fields never enter current summaries or verifier material', () => {
  const state = fixture();
  for (const id of ['issue', 'derive-vc', 'device-sign', 'prove', 'verify', 'owner-review', 'wallet-sign']) {
    const html = renderStepSummary(panelFor(state, id));
    for (const forbidden of [localOrganization, localHolderLabel, privateSentinel]) assert.ok(!html.includes(forbidden), id);
  }
  for (const kind of ['device', 'holder', 'owner', 'wallet']) {
    const html = renderStepMaterial(state, kind);
    for (const forbidden of [localOrganization, localHolderLabel, privateSentinel]) assert.ok(!html.includes(forbidden), kind);
  }
  const local = renderStepMaterial(state, 'disclosure');
  const derived = local.slice(local.indexOf('<h4>A 将出示 · 派生 VC</h4>'));
  assert.ok(local.includes(localOrganization), 'local source comparison remains available on demand');
  assert.doesNotMatch(local, new RegExp(privateSentinel));
  assert.doesNotMatch(derived, new RegExp(`${localOrganization}|${localHolderLabel}`));
});

test('summary escapes markup and makes a long public identifier keyboard-readable', () => {
  const state = fixture(), malicious = '<img src=x onerror="alert(1)">';
  state.order.payeeAccount = malicious;
  state.order.orderId = `order-${'a'.repeat(160)}`;
  const html = renderStepSummary(panelFor(state, 'verify'));
  assert.doesNotMatch(html, /<img/);
  assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
  assert.match(html, /<details class="guide-public-value"><summary/);
  assert.match(html, /<pre tabindex="0">order-a{160}<\/pre>/);
  assert.doesNotMatch(html, /<details\b[^>]*\sopen(?:\s|>)/);
});

test('display context keys change for new orders, attempts, modes, phases and current operations', () => {
  const base = fixture(), key = panelFor(base, 'verify').key;
  for (const mutate of [
    state => { state.order.orderId = 'new-order'; }, state => { state.manual.attemptId = 'new-attempt'; },
    state => { state.mode = 'bbs-blind-bls'; }, state => { state.manual.phase = 'authorize'; },
    state => { state.currentCredentialId = 'new-credential'; }, state => { state.w3c.originalCredential.credentialSubject.bindingId = 'new-binding'; },
  ]) { const state = fixture(); mutate(state); assert.notEqual(panelFor(state, 'verify').key, key); }
  assert.notEqual(panelFor(base, 'device-sign').key, key);
});

test('rendering and opening material markup are read-only and never invoke a business request', () => {
  const state = fixture(), original = structuredClone(state), previousFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('Presentation must never initiate a request'); };
  try {
    for (const id of ['issue', 'begin-proposal', 'derive-vc', 'device-sign', 'prove', 'verify', 'owner-review', 'wallet-sign']) {
      const panel = panelFor(state, id), summary = renderStepSummary(panel), detail = renderStepDetail(state, { plan: { id }, panel });
      assert.doesNotMatch(summary + detail, /\bon(?:click|toggle)=|<script\b/i);
      renderStepSummary(panel); renderStepDetail(state, { plan: { id }, panel });
    }
    assert.deepEqual(state, original);
  } finally { globalThis.fetch = previousFetch; }
});

function deviceFixture(phase = 'proposal') {
  const state = fixture(phase);
  state.manual.stage = 'VC_DERIVED';
  state.manual.verificationResult = null;
  state.manual.deviceRequest = { version: 1, suite: 'public-suite', mode: state.mode, randomizedDevicePublicKey: 'public-device-pseudonym',
    context: { challengeId: 'challenge-current', bodyHash: 'body-current', w3cPresentationHash: 'derived-hash-current' }, secret: privateSentinel };
  state.manual.deviceResponse = null;
  state.manual.presentation = null;
  state.manual.holderProof = null;
  state.manual.cryptography = { w3cPresentationHash: 'derived-hash-current' };
  return state;
}
const deviceView = (state, id, options = {}) => renderDeviceParticipation(state, { panel: panelFor(state, id, options), ...options });
function roleMarkup(html, role) {
  const start = html.indexOf(`<li data-device-role="${role}"`);
  assert.ok(start >= 0, `role exists: ${role}`);
  return html.slice(start, html.indexOf('</li>', start) + 5);
}
test('the device chain separates prepared input, returned contribution, local combination and B checks', () => {
  const state = deviceFixture();
  let html = deviceView(state, 'device-sign');
  assert.match(roleMarkup(html, 'request'), /data-state="material".*输入已准备/);
  assert.match(roleMarkup(html, 'device'), /data-state="pending".*等待设备调用/);
  assert.match(roleMarkup(html, 'holder'), /data-state="pending".*等待持有者 A 处理/);
  assert.match(roleMarkup(html, 'verifier'), /data-state="pending".*等待本次核验/);
  assert.doesNotMatch(html, /data-state="pass"|data-device-check-id=/);
  state.manual.stage = 'DEVICE_SIGNED';
  state.manual.deviceResponse = { mode: state.mode, signature: 'returned-device-contribution' };
  html = deviceView(state, 'prove');
  assert.match(roleMarkup(html, 'device'), /data-state="material".*贡献已返回持有者 A/);
  assert.match(roleMarkup(html, 'holder'), /data-state="pending"/);
  assert.doesNotMatch(html, /guide-device-public-details|查看本步设备输入与返回摘要/);
  const holderMaterial = renderStepMaterial(state, 'holder');
  assert.match(holderMaterial, /设备贡献已返回，等待持有者 A 核验与组合/);
  assert.doesNotMatch(holderMaterial, /等待设备贡献后生成/);
  state.manual.stage = 'PROOF_READY';
  state.manual.presentation = { deviceSignature: 'adapted-contribution' };
  state.manual.holderProof = 'header.payload.signature';
  html = deviceView(state, 'verify');
  assert.match(roleMarkup(html, 'holder'), /data-state="material".*组合材料已生成/);
  assert.match(roleMarkup(html, 'holder'), /已核验设备贡献；另有独立的持有者 A 请求签名/);
  assert.match(roleMarkup(html, 'verifier'), /data-state="pending"/);
  assert.doesNotMatch(html, /data-state="pass"/);
});

test('running device, holder and verify actions cannot inherit an older completed state', () => {
  const state = deviceFixture();
  state.manual.stage = 'PROOF_READY';
  state.manual.deviceResponse = { mode: state.mode, signature: 'returned-device-contribution' };
  state.manual.presentation = { deviceSignature: 'adapted-contribution' };
  state.manual.holderProof = 'header.payload.signature';
  state.manual.verificationResult = { mode: state.mode, phase: 'proposal', verificationTrace: traceFor() };
  for (const [action, role] of [['device-sign', 'device'], ['prove', 'holder'], ['verify', 'verifier']]) {
    const html = deviceView(state, action, { action });
    assert.match(roleMarkup(html, role), /data-state="running"/);
    assert.doesNotMatch(roleMarkup(html, role), /data-state="pass"|设备两项通过|组合材料已生成|贡献已返回 A/);
  }
  const verifying = deviceView(state, 'verify', { action: 'verify' });
  assert.match(verifying, /data-device-check-id="device_pairing" data-state="running"/);
  assert.doesNotMatch(verifying, /data-state="pass"/);
});

test('B device pass and fail require unique current check IDs, never just an overall success', () => {
  const state = deviceFixture();
  state.manual.verificationResult = { mode: state.mode, phase: 'proposal', verificationTrace: { source: 'agent-b', profile: 'dbac-payment', outcome: 'pass', steps: [] } };
  for (const steps of [[], [{ id: 'vc_device_binding', status: 'pass' }], [{ id: 'device_pairing', status: 'pass' }],
    [{ id: 'vc_device_binding', status: 'pass' }, { id: 'device_pairing', status: 'pass' }, { id: 'device_pairing', status: 'pass' }]]) {
    state.manual.verificationResult.verificationTrace.steps = steps;
    const html = deviceView(state, 'verify');
    assert.match(roleMarkup(html, 'verifier'), /data-state="unknown"/);
    assert.match(html, /未提供独立结论/);
    assert.doesNotMatch(roleMarkup(html, 'verifier'), /设备两项通过/);
  }
  state.manual.verificationResult.verificationTrace = traceFor();
  let html = deviceView(state, 'verify');
  assert.match(roleMarkup(html, 'verifier'), /data-state="pass".*设备两项通过/);
  state.manual.verificationResult.verificationTrace.steps.find(step => step.id === 'device_pairing').evidence = [{ match: false }];
  html = deviceView(state, 'verify');
  assert.match(roleMarkup(html, 'verifier'), /data-state="fail"/);
  assert.match(html, /整体结论与设备检查记录存在冲突/);
});

test('an actual device rejection remains distinct from later skipped checks and a later credential rejection', () => {
  const state = deviceFixture(), trace = traceFor();
  state.manual.lastError = { code: 'W3C_DEVICE_PROOF_REQUIRED', message: '缺少本次设备贡献', verificationTrace: trace };
  trace.outcome = 'fail';
  Object.assign(trace.steps.find(step => step.id === 'vc_device_binding'), { status: 'fail', code: 'W3C_DEVICE_PROOF_REQUIRED', detail: '缺少本次设备贡献' });
  trace.steps.find(step => step.id === 'device_pairing').status = 'skipped';
  let html = deviceView(state, 'verify');
  assert.match(html, /data-device-check-id="vc_device_binding" data-state="fail"/);
  assert.match(html, /W3C_DEVICE_PROOF_REQUIRED · 缺少本次设备贡献/);
  assert.match(html, /data-device-check-id="device_pairing" data-state="skipped"/);
  state.manual.lastError = { verificationTrace: traceFor() };
  const current = state.manual.lastError.verificationTrace;
  current.outcome = 'fail';
  Object.assign(current.steps.find(step => step.id === 'credential_status'), { status: 'fail', title: '凭证撤销状态', code: 'W3C_CREDENTIAL_REVOKED' });
  html = deviceView(state, 'verify');
  assert.match(roleMarkup(html, 'verifier'), /data-state="pass"/);
  assert.match(html, /设备两项检查通过；本次请求仍停在凭证撤销状态（W3C_CREDENTIAL_REVOKED）/);
});

test('new stages, uncertainty, expiry and mode mismatch remove old device success and public values', () => {
  const cases = [
    { id: 'begin-authorize', mutate() {}, options: {} },
    { id: 'verify', mutate() {}, options: { uncertain: true } },
    { id: 'verify', mutate(state) { state.manual.expired = true; }, options: {} },
    { id: 'verify', mutate(state) { state.manual.stage = 'EXPIRED'; }, options: {} },
    { id: 'verify', mutate(state) { state.manual.expiresAtUnix = 1; }, options: {} },
    { id: 'device-sign', mutate() {}, options: { mode: 'bbs-blind-bls' } },
  ];
  for (const { id, mutate, options } of cases) {
    const state = deviceFixture();
    state.manual.deviceResponse = { mode: state.mode, signature: 'OLD_DEVICE_CONTRIBUTION' };
    state.manual.verificationResult = { mode: state.mode, phase: 'proposal', verificationTrace: traceFor() };
    mutate(state);
    const html = deviceView(state, id, options);
    assert.doesNotMatch(html, /data-state="pass"|OLD_DEVICE_CONTRIBUTION|设备两项通过/);
    assert.match(html, /guide-device-alert/);
  }
});

test('authorize and settle device rechecks only use matching-phase traces', () => {
  for (const phase of ['authorize', 'settle']) {
    const state = deviceFixture(phase);
    state.manual.verificationResult = { mode: state.mode, phase: 'proposal', verificationTrace: traceFor() };
    let html = deviceView(state, 'verify');
    assert.doesNotMatch(html, /data-state="pass"/);
    assert.match(html, phase === 'settle' ? /结算阶段复核/ : /本步复核/);
    state.manual.verificationResult = { mode: state.mode, phase, verificationTrace: traceFor(phase) };
    html = deviceView(state, 'verify');
    assert.match(roleMarkup(html, 'verifier'), /data-state="pass"/);
  }
});

test('blind device input exposes only the blinded point and protocol metadata, while clear context stays at A', () => {
  const state = deviceFixture();
  state.mode = 'bbs-blind-bls';
  state.manual.deviceRequest = { mode: state.mode, version: 1, suite: 'public-suite', blindedPoint: 'b'.repeat(192),
    context: { challengeId: 'MUST_NOT_BE_DEVICE_INPUT' }, secretKey: privateSentinel, blind: privateSentinel };
  state.manual.deviceResponse = { mode: state.mode, signature: 'c'.repeat(192), seed: privateSentinel };
  state.manual.stage = 'DEVICE_SIGNED';
  const chain = deviceView(state, 'prove'), html = renderStepMaterial(state, 'device');
  const input = html.match(/<article data-source="device-input">([\s\S]*?)<\/article>/)?.[1];
  const local = html.match(/<section class="guide-device-local-context" data-source="agent-a-local">([\s\S]*?)<\/section>/)?.[1];
  assert.match(input, /盲化待签点/);
  assert.match(input, /协议版本/);
  assert.match(input, /密码套件/);
  assert.match(input, /b{192}/);
  assert.doesNotMatch(input, /challenge-current|body-current|derived-hash-current|MUST_NOT_BE_DEVICE_INPUT|设备伪名/);
  for (const value of ['challenge-current', 'body-current', 'derived-hash-current']) assert.ok(local.includes(value));
  assert.match(local, /明文值保留在持有者 A 本地；设备输入只包含上方盲化待签点及公开协议标识/);
  assert.doesNotMatch(chain, /guide-device-public-details/);
  assert.doesNotMatch(chain, /<details\b[^>]*\sopen(?:\s|>)|b{192}|c{192}|challenge-current|body-current|derived-hash-current/);
  assert.doesNotMatch(html, /PRIVATE_MATERIAL_MUST_NOT_APPEAR|LOCAL_UNDISCLOSED/);
  assert.match(html, /<details class="guide-public-value"><summary/);
  assert.doesNotMatch(html, /<details\b[^>]*\sopen(?:\s|>)/);
});

test('device public details remain collapsed, escaped and read-only with no private fields or token export', () => {
  const state = deviceFixture(), originalFetch = globalThis.fetch, original = structuredClone(state);
  state.manual.deviceRequest.context.bodyHash = '<img src=x onerror="alert(1)">';
  const before = structuredClone(state);
  globalThis.fetch = () => { throw new Error('Read-only device view must not request signatures'); };
  try {
    const view = () => deviceView(state, 'device-sign') + renderStepMaterial(state, 'device');
    const html = view();
    assert.doesNotMatch(html, /<img|\bon(?:click|toggle)=|<button|PRIVATE_MATERIAL_MUST_NOT_APPEAR|LOCAL_UNDISCLOSED/);
    assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
    assert.doesNotMatch(html, /<details\b[^>]*\sopen(?:\s|>)/);
    assert.equal(view(), html);
    assert.deepEqual(state, before);
  } finally { globalThis.fetch = originalFetch; }
  assert.notDeepEqual(original, state, 'only the test fixture mutation changed the snapshot');
});

test('owner and wallet retain a compact explicit device prerequisite rather than repeating the chain', () => {
  const state = deviceFixture();
  state.manual.deviceResponse = { mode: state.mode, signature: 'returned-device-contribution' };
  state.manual.verificationResult = { mode: state.mode, phase: 'proposal', verificationTrace: traceFor() };
  for (const id of ['submit-owner', 'owner-review', 'wallet-sign']) {
    const html = deviceView(state, id);
    assert.match(html, /^<p class="guide-device-prerequisite"/);
    assert.match(html, /模拟 eSIM：贡献已返回持有者 A/);
    assert.match(html, /前一步验证者 B 记录：凭证与设备绑定：通过；设备贡献配对：通过/);
    assert.doesNotMatch(html, /guide-device-chain|guide-device-public|<details|returned-device-contribution/);
    const unknown = deviceView(state, id, { uncertain: true });
    assert.doesNotMatch(unknown, /data-state="pass"|设备贡献配对：通过/);
  }
});

test('partial device outputs and local processing failures do not masquerade as a B rejection', () => {
  const state = deviceFixture();
  state.manual.deviceResponse = {};
  let html = deviceView(state, 'prove');
  assert.match(roleMarkup(html, 'device'), /data-state="pending"/);
  assert.match(renderStepMaterial(state, 'device'), /返回字段不完整，尚未确认设备贡献/);
  state.manual.stage = 'DEVICE_SIGNED';
  state.manual.lastError = { code: 'DBAC_DEVICE_SIGNATURE_INVALID', message: '另一设备贡献不匹配' };
  html = deviceView(state, 'prove');
  assert.match(roleMarkup(html, 'holder'), /data-state="fail".*组合未完成/);
  assert.match(roleMarkup(html, 'holder'), /DBAC_DEVICE_SIGNATURE_INVALID/);
  assert.match(roleMarkup(html, 'verifier'), /data-state="pending"/);
  assert.doesNotMatch(html, /B 已拒绝|设备检查不通过/);
});

test('credential and challenge steps identify issuance binding as local material without fabricating its verification', () => {
  const state = deviceFixture();
  state.manual.device.publicKeyFingerprint = 'f'.repeat(96);
  for (const id of ['issue', 'begin-proposal', 'begin-authorize']) {
    const html = deviceView(state, id);
    assert.match(html, /guide-device-binding/);
    assert.match(html, /签发材料通过绑定标识关联 VC 与配套设备凭证/);
    assert.match(html, /A 本地 VC 绑定标识|binding-current|当前模拟 eSIM 公钥指纹/);
    assert.match(html, /未提供本次签发绑定的独立核验记录/);
    assert.match(html, /<details class="guide-public-value"><summary/);
    assert.doesNotMatch(html, /data-state="pass"|<details\b[^>]*\sopen(?:\s|>)|PRIVATE_MATERIAL_MUST_NOT_APPEAR|LOCAL_UNDISCLOSED/);
  }
  const html = deviceView(state, 'issue', { mode: 'bbs-blind-bls' });
  assert.doesNotMatch(html, /binding-current|f{96}/);
  delete state.w3c.originalCredential.credentialSubject.bindingId;
  const pending = deviceView(state, 'issue');
  assert.match(pending, /class="guide-device-binding" data-state="pending"/);
  assert.match(pending, /等待签发凭证与绑定材料/);
  assert.doesNotMatch(pending, /已返回绑定材料|data-state="pass"/);
});

test('device chain is a compact status summary and the current operation owns each public contribution once', () => {
  for (const mode of ['bbs-bls', 'bbs-blind-bls']) {
    const state = deviceFixture();
    state.mode = mode;
    state.manual.deviceRequest.mode = mode;
    if (mode === 'bbs-blind-bls') state.manual.deviceRequest.blindedPoint = 'blind-point-current';
    state.manual.deviceResponse = { mode, signature: 'ORIGINAL_DEVICE_RESPONSE' };
    state.manual.device.publicKey = 'BOUND_DEVICE_PUBLIC_KEY';
    state.manual.device.publicKeyFingerprint = 'BOUND_DEVICE_FINGERPRINT';
    state.manual.presentation = { deviceSignature: 'ADAPTED_DEVICE_CONTRIBUTION' };
    const encoded = value => Buffer.from(JSON.stringify(value)).toString('base64url');
    state.manual.holderProof = `${encoded({ alg: 'EdDSA' })}.${encoded({ purpose: 'dbac-payment' })}.INDEPENDENT_HOLDER_SIGNATURE`;
    state.manual.stage = 'PROOF_READY';
    const chain = deviceView(state, 'prove');
    const html = chain + renderStepDetail(state, { plan: { id: 'prove' } });
    assert.doesNotMatch(chain, /<details\b[^>]*\sopen(?:\s|>)|查看公开依据|ORIGINAL_DEVICE_RESPONSE|BOUND_DEVICE_PUBLIC_KEY|BOUND_DEVICE_FINGERPRINT|ADAPTED_DEVICE_CONTRIBUTION|INDEPENDENT_HOLDER_SIGNATURE/);
    for (const value of ['ORIGINAL_DEVICE_RESPONSE', 'BOUND_DEVICE_PUBLIC_KEY', 'BOUND_DEVICE_FINGERPRINT', 'ADAPTED_DEVICE_CONTRIBUTION', 'INDEPENDENT_HOLDER_SIGNATURE']) {
      assert.equal(html.split(value).length - 1, 1, `${mode}: ${value} should have one evidence source`);
    }
    assert.match(html, /e\(H₀, σ_SE\) = e\(pk_SE, Q\)/);
    assert.match(html, /<details class="guide-material-section" open>/);
    assert.doesNotMatch(html, /<details class="guide-public-value"[^>]*\sopen(?:\s|>)|PRIVATE_MATERIAL_MUST_NOT_APPEAR|LOCAL_UNDISCLOSED/);
    if (mode === 'bbs-blind-bls') {
      assert.match(html, /A 先在本地去盲/);
      assert.match(html, /A 本地明文上下文/);
      assert.match(html, /challenge-current/);
      assert.match(html, /body-current/);
      assert.match(html, /blind-point-current/);
    }
  }
});

test('device and holder summaries keep only four current-material facts, without repeating role states', () => {
  const state = deviceFixture('authorize');
  state.proposal = { status: 'APPROVED' };
  state.authorization = { document: {} };
  state.order.orderId = 'urn:uuid:71fe9adc-ed55-4b7b-aac2-14626f617272';
  state.manual.challenge.challengeId = '71fe9adc-ed55-4b7b-aac2-14626f617273';
  for (const id of ['device-sign', 'prove']) {
    const panel = panelFor(state, id), html = renderStepSummary(panel);
    assert.deepEqual(panel.facts.map(([label]) => label), ['本次请求', '本次挑战', '证明模式', '材料来源']);
    assert.equal(panel.facts[0][1], state.order.orderId);
    assert.equal(panel.facts[1][1], state.manual.challenge.challengeId);
    assert.doesNotMatch(html.slice(html.indexOf('<dl class="guide-step-summary">')), /本笔金额|收款对象|用户授权|签名已生成|贡献已返回/);
    assert.equal((html.match(/<details class="guide-public-value">/g) || []).length, 2);
    assert.match(html, new RegExp(`<pre tabindex="0">${state.order.orderId}</pre>`));
    assert.match(html, new RegExp(`<pre tabindex="0">${state.manual.challenge.challengeId}</pre>`));
    assert.doesNotMatch(html, /<details\b[^>]*\sopen(?:\s|>)/);
  }
  state.manual.challenge = null;
  assert.equal(panelFor(state, 'device-sign').facts.length, 3, 'no fabricated challenge fact when the field is absent');
  for (const id of ['begin-authorize', 'verify', 'owner-review', 'wallet-sign']) {
    assert.ok(panelFor(state, id).facts.some(([label]) => label === '本笔金额'));
    assert.ok(panelFor(state, id).facts.some(([label]) => label === '收款对象'));
  }
});

test('the device chain marks exactly the actual current role for keyboard and screen-reader context', () => {
  const state = deviceFixture();
  for (const [id, role] of [['issue', 'request'], ['begin-proposal', 'request'], ['derive-vc', 'request'], ['device-sign', 'device'], ['prove', 'holder'], ['verify', 'verifier']]) {
    const html = deviceView(state, id);
    assert.equal((html.match(/aria-current="step"/g) || []).length, 1, id);
    assert.match(roleMarkup(html, role), /aria-current="step"/);
  }
});

test('three fresh proof rounds explain their distinct purpose and mark the device chain as four internal roles', () => {
  const expectations = { proposal: [1, /提交用户授权申请/, /不调用钱包签名或付款/], authorize: [2, /用户已批准的单笔授权/, /请求钱包签署付款材料/], settle: [3, /已签付款材料/, /匹配本订单的回执/] };
  for (const [phase, [round, purpose, next]] of Object.entries(expectations)) {
    const state = deviceFixture(phase), panel = panelFor(state, 'device-sign');
    const html = renderStepSummary(panel), chain = deviceView(state, 'device-sign');
    assert.match(html, new RegExp(`第 ${round} / 3 轮`));
    assert.match(html, purpose); assert.match(html, next);
    assert.match(html, /下方四个环节属于当前这一轮/);
    assert.doesNotMatch(html, /data-state="pass"/);
    assert.match(chain, /本轮内部 4 个环节|aria-label="本轮证明内部的四个环节"/);
    for (const [index, role, name] of [[1, 'request', '持有者 A 准备请求'], [2, 'device', '模拟 eSIM 贡献'], [3, 'holder', '持有者 A 核验并组合'], [4, 'verifier', '验证者 B 核验设备绑定']]) {
      assert.ok(roleMarkup(chain, role).includes(`${index}. ${name}`));
    }
  }
});

test('current verifier evidence rejects an old challenge or selected VC but preserves a genuine observed binding failure', () => {
  const state = fixture();
  state.manual.verificationResult.wire = { context: { challengeId: 'old-challenge' } };
  assert.equal(currentVerificationTrace(state), null);
  delete state.manual.verificationResult.wire;
  const trace = state.manual.verificationResult.verificationTrace, binding = trace.steps.find(step => step.id === 'vc_device_binding');
  binding.evidence = [{ label: 'bindingId / mode / device contribution', expected: ['old-vc-binding', state.mode, true], observed: ['old-vc-binding', state.mode, true] }];
  assert.equal(currentVerificationTrace(state), null);
  binding.status = 'fail'; trace.outcome = 'fail';
  binding.evidence[0] = { label: 'bindingId / mode / device contribution', expected: ['binding-current', state.mode, true], observed: ['mixed-device-binding', state.mode, true], match: false };
  assert.equal(currentVerificationTrace(state), trace, 'received mismatches are real failure evidence, not stale expected context');
  state.manual.cryptography = { w3cPresentationHash: 'current-derived-vc' };
  binding.evidence.push({ label: 'hVC: derived credential hash', observed: 'old-derived-vc' });
  assert.equal(currentVerificationTrace(state), null);
  binding.evidence.at(-1).observed = 'current-derived-vc';
  assert.equal(currentVerificationTrace(state), trace);
});
