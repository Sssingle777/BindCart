import test from 'node:test';
import assert from 'node:assert/strict';
import { credentialFieldComparison, renderStepDetail, renderStepMaterial } from '../public/guide-step-detail.js';

const subject = { role: 'authorized-agent', scope: 'payments:pay', epoch: '2026-10-10', mode: 'bbs-bls', bindingId: 'urn:uuid:binding-one', holderDid: 'did:key:holder-one', organization: 'Competition team', holderLabel: 'Alice / Agent A' };
function fixture() {
  const { organization, holderLabel, ...disclosed } = subject;
  return {
    mode: 'bbs-bls', order: { orderId: 'order-one', amountMinor: 1000000, currency: 'TEST_USDC', payerAccount: 'A', payeeAccount: 'B' },
    w3c: { originalCredential: { credentialSubject: { ...subject } }, disclosedPaths: Object.keys(disclosed).map(key => `/credentialSubject/${key}`), hiddenPaths: ['/credentialSubject/organization', '/credentialSubject/holderLabel'] },
    manual: { phase: 'proposal', stage: 'VC_DERIVED', verifiableCredential: { credentialSubject: disclosed } },
  };
}
const field = (state, key) => credentialFieldComparison(state).find(row => row.key === key);

test('compares actual original and derived fields while distinguishing hidden absence from missing required claims', () => {
  const state = fixture();
  assert.equal(field(state, 'role').status, 'pass');
  assert.equal(field(state, 'organization').targetPresent, false);
  assert.match(field(state, 'organization').detail, /文档中不存在/);
  delete state.manual.verifiableCredential.credentialSubject.scope;
  assert.equal(field(state, 'scope').status, 'fail');
  assert.equal(field(state, 'scope').detail, '应披露字段缺失');
  state.manual.verifiableCredential.credentialSubject.role = 'attacker';
  assert.equal(field(state, 'role').status, 'fail');
  assert.equal(field(state, 'role').detail, '字段不一致');
});

test('policy cannot fabricate hidden status when a field is actually disclosed or a credential is not generated', () => {
  const state = fixture();
  state.manual.verifiableCredential.credentialSubject.organization = subject.organization;
  assert.equal(field(state, 'organization').targetPresent, true);
  assert.equal(field(state, 'organization').status, 'fail');
  assert.match(field(state, 'organization').detail, /与隐藏策略不符/);
  state.manual.verifiableCredential = null;
  assert.ok(credentialFieldComparison(state).every(row => row.status === 'pending' && row.detail === '派生文档待生成'));
  assert.doesNotMatch(renderStepDetail(state, { plan: { id: 'derive-vc' } }), /已披露 · 与原始值一致/);
});

test('sent document takes precedence over prepared document, and a missing local value never compares successfully', () => {
  const state = fixture();
  state.manual.sentCredential = { credentialSubject: { ...state.manual.verifiableCredential.credentialSubject, bindingId: 'different-sent-binding' } };
  assert.equal(field(state, 'bindingId').targetValue, 'different-sent-binding');
  assert.equal(field(state, 'bindingId').status, 'fail');
  delete state.w3c.originalCredential.credentialSubject.holderDid;
  assert.equal(field(state, 'holderDid').status, 'pending');
  assert.match(field(state, 'holderDid').detail, /原始字段缺失/);
  const html = renderStepMaterial(state, 'disclosure');
  assert.match(html, /A 已发送 · 派生 VC/);
  assert.match(html, /different-sent-binding/);
});

test('unknown policy and invalid claim values never invent successful disclosure or equality', () => {
  const state = fixture();
  state.w3c.disclosedPaths = [];
  state.manual.verifiableCredential.credentialSubject.role = null;
  assert.equal(field(state, 'role').policy, '未提供');
  assert.equal(field(state, 'role').status, 'fail');
  state.manual.verifiableCredential.credentialSubject.role = {};
  state.w3c.originalCredential.credentialSubject.role = {};
  assert.equal(field(state, 'role').status, 'fail');
});

test('each material entry preserves its exact comparisons without showing other steps by default', () => {
  const state = fixture();
  state.manual.challenge = { challengeId: 'challenge-one', paymentOrderId: 'wrong-order', scope: 'payments:pay', nonce: 'nonce-one' };
  state.manual.deviceRequest = { mode: 'bbs-blind-bls', blindedPoint: 'point-one' };
  state.manual.deviceResponse = { mode: 'bbs-bls', signature: 'signature-one' };
  state.manual.walletSigningUnconfirmed = true;
  const html = renderStepDetail(state, { mode: 'bbs-blind-bls', plan: { id: 'device-sign' } });
  const currentRecord = html.slice(html.indexOf('data-operation-id="device-sign"'));
  assert.doesNotMatch(currentRecord, /data-field="paymentOrderId"|签署请求结果待确认|A 本地持有 · 原始 VC/);
  assert.match(html, /data-field="mode" data-state="fail"><strong>请求与返回模式/);
  assert.match(html, /point-one/);
  assert.doesNotMatch(html, /data-field="context.challengeId"/);
  assert.match(renderStepMaterial(state, 'challenge'), /data-field="paymentOrderId" data-state="fail"/);
  assert.match(renderStepMaterial(state, 'wallet'), /签署请求结果待确认/);
  assert.match(renderStepMaterial(null, 'challenge'), /待获取挑战/);
  assert.equal(renderStepDetail(null), '');
});

test('holder JWS claims are displayed as decoded public material, and mismatched credential hash is visible', () => {
  const state = fixture(), encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  state.manual.cryptography = { w3cPresentationHash: 'expected-hash' };
  state.manual.challenge = { verifier: 'did:key:B' };
  state.manual.holderProof = `${encode({ alg: 'EdDSA' })}.${encode({ iss: subject.holderDid, aud: 'did:key:B', credentialHash: 'different-hash', contextHash: 'context-hash', deviceProofHash: 'device-hash' })}.c2lnbmF0dXJl`;
  const html = renderStepMaterial(state, 'holder');
  assert.match(html, /data-field="credentialHash" data-state="fail"/);
  assert.match(html, /data-field="iss ↔ holderDid" data-state="pass"/);
  assert.match(html, /没有在浏览器执行验签/);
  state.manual.holderProof = 'not-a-jws';
  assert.match(renderStepMaterial(state, 'holder'), /无法解析为 JWS/);
});

test('uses allowlisted public fields, escapes content, and makes long exact values expandable', () => {
  const state = fixture();
  const malicious = '<img src=x onerror="alert(1)">';
  state.w3c.originalCredential.credentialSubject.holderLabel = malicious;
  state.manual.stage = malicious;
  state.manual.device = { secretKey: 'DO_NOT_RENDER_PRIVATE_KEY', publicKey: 'a'.repeat(96) };
  state.manual.holderProof = { privateKey: 'DO_NOT_RENDER_PRIVATE_KEY' };
  state.w3c.originalCredential.credentialSubject.privateKey = 'DO_NOT_RENDER_PRIVATE_KEY';
  const html = ['credential', 'disclosure', 'device', 'holder'].map(kind => renderStepMaterial(state, kind)).join('');
  assert.doesNotMatch(html, /<img|DO_NOT_RENDER_PRIVATE_KEY/);
  assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
  assert.match(html, /<details class="guide-public-value">/);
  assert.match(html, new RegExp(`<pre tabindex="0">${'a'.repeat(96)}</pre>`));
  assert.doesNotMatch(html, /<details\b[^>]*\sopen(?:\s|>)/);
});

test('order authorization comparison detects changed terms and preserves zero or false public values', () => {
  const state = fixture();
  state.authorization = { document: { payment: { ...state.order, amountMinor: 2000000 }, maxExecutions: 1, delegationAllowed: false, exp: 0 } };
  const html = renderStepDetail(state, { plan: { id: 'wallet-sign' } });
  assert.match(html, /data-field="amountMinor" data-state="fail"/);
  assert.match(html, /data-field="orderId" data-state="pass"/);
  assert.match(html, /<span>false<\/span>/);
  assert.match(html, /<span>0<\/span>/);
});

test('visible operation flow follows actual returned material and never declares an unprepared credential present', () => {
  const empty = { mode: 'bbs-bls', manual: {} };
  let html = renderStepDetail(empty, { plan: { id: 'issue' } });
  assert.match(html, /<dt>输入<\/dt>|<dt>操作 \/ 核验关系<\/dt>|<dt>输出<\/dt>|<dt>结论 \/ 下一步<\/dt>/);
  assert.match(html, /尚未取得当前凭证材料|当前没有凭证材料，先准备测试凭证/);
  assert.doesNotMatch(html, /签发材料已载入|当前凭证材料已载入/);
  const prepared = fixture(); prepared.credential = { suite: 'test' };
  html = renderStepDetail(prepared, { plan: { id: 'issue' } });
  assert.match(html, /当前凭证材料已载入|签发材料已载入/);
  prepared.manual.deviceResponse = { mode: 'bbs-bls', signature: 'OLD_RETURN_MATERIAL' };
  html = renderStepDetail(prepared, { plan: { id: 'device-sign' }, action: 'device-sign' });
  const flow = html.match(/<dl class="guide-operation-flow">([\s\S]*?)<\/dl>/)?.[1];
  assert.match(flow, /本步请求正在执行，等待本次返回/);
  assert.doesNotMatch(flow, /设备贡献已返回/);
});

test('current material is open by default while a long signature stays in its own closed exact-value disclosure', () => {
  const state = fixture();
  state.manual.deviceRequest = { mode: 'bbs-bls', context: { challengeId: 'current-challenge' } };
  state.manual.deviceResponse = { mode: 'bbs-bls', signature: 's'.repeat(192) };
  const html = renderStepDetail(state, { plan: { id: 'device-sign' } });
  assert.match(html, /<details class="guide-material-section" open>/);
  assert.match(html, /<details class="guide-public-value"><summary[^>]*>[\s\S]*?<pre tabindex="0">s{192}<\/pre>/);
  assert.doesNotMatch(html, /<details class="guide-public-value"[^>]*\bopen\b/);
  assert.match(html, /e\(H₀, σ_SE\) = e\(pk_SE, Q\)/);
  assert.doesNotMatch(html, /查看本步设备输入与返回摘要|guide-device-public-details/);
});
