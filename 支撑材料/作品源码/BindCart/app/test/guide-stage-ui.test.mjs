import test from 'node:test';
import assert from 'node:assert/strict';
import { renderCheckPreview, renderStepBrief, installDialogFocus } from '../public/guide-stage-ui.js';

const trace = steps => ({ source: 'agent-b', profile: 'dbac-payment', outcome: 'fail', steps });

test('unsubmitted previews describe future checks without a generated success state', () => {
  const html = renderCheckPreview(null, { phase: 'proposal' });
  assert.match(html, /本步将检查/); assert.match(html, /尚未提交验证/);
  assert.doesNotMatch(html, /验证通过|请求被拒绝|data-state="pass"/);
});

test('preview exposes every actual failure, including checks outside the normal compact selection', () => {
  const html = renderCheckPreview(trace([
    { id: 'holder_signature', status: 'fail', code: 'HOLDER_SIGNATURE_INVALID', detail: '持有者请求签名不匹配' },
    { id: 'scope', status: 'fail', code: 'ORDER_BINDING_MISMATCH', detail: '本次订单与挑战不匹配' },
    { id: 'unusual_check', title: '补充核对', status: 'fail', code: 'CHECK_FAILED', detail: '额外检查实际失败' },
    { id: 'device_pairing', status: 'skipped' },
  ]), { phase: 'proposal' });
  for (const code of ['HOLDER_SIGNATURE_INVALID', 'ORDER_BINDING_MISMATCH', 'CHECK_FAILED']) assert.match(html, new RegExp(code));
  assert.equal((html.match(/class="stage-visible-failure"/g) || []).length, 3);
  assert.match(html, /data-scene-evidence="check:device_pairing" data-state="skipped"/);
  assert.match(html, /未执行/); assert.doesNotMatch(html, /<details/);
});

test('contradictory or wrong-phase trace cannot turn a compact preview into a false pass', () => {
  const contradictory = { ...trace([{ id: 'w3c_bbs', status: 'pass', evidence: [{ label: 'proof type / suite / issuer', expected: 'expected', observed: 'other', match: false }] }]), outcome: 'pass' };
  const html = renderCheckPreview(contradictory, { phase: 'proposal' });
  assert.match(html, /整体结论为通过，但存在失败或不匹配/);
  assert.match(html, /data-scene-evidence="check:w3c_bbs" data-state="fail"/);
  const old = renderCheckPreview({ ...trace([{ id: 'w3c_bbs', status: 'pass' }, { id: 'scope', status: 'pass', evidence: [{ label: 'method / scope / phase', observed: ['message/send', 'payments:pay', 'proposal'] }] }]), outcome: 'pass' }, { phase: 'settle' });
  assert.match(old, /支付阶段与本步不一致/);
  assert.doesNotMatch(old, /data-state="pass"|验证通过/);
});

test('running and untrusted-source checks retain uncertainty instead of an old result', () => {
  const old = trace([{ id: 'w3c_bbs', status: 'pass' }, { id: 'holder_signature', status: 'fail', code: 'OLD_FAILURE' }]);
  const running = renderCheckPreview(old, { phase: 'proposal', running: true });
  assert.match(running, /请求处理中/);
  assert.doesNotMatch(running, /data-state="pass"|data-state="fail"|OLD_FAILURE/);
  const local = renderCheckPreview({ ...old, source: 'agent-a' }, { phase: 'proposal' });
  assert.doesNotMatch(local, /验证通过|请求被拒绝|OLD_FAILURE/);
});

test('public preview text and evidence identifiers are escaped and unselected nested secrets are omitted', () => {
  const html = renderCheckPreview(trace([{ id: 'holder_signature', status: 'fail', code: '<error>', detail: '<img src=x onerror=alert(1)>', privateKey: 'NEVER_EXPOSE_PRIVATE_VALUE' }]), { phase: 'proposal' });
  assert.match(html, /&lt;error&gt;/); assert.match(html, /&lt;img/);
  assert.doesNotMatch(html, /<img|NEVER_EXPOSE_PRIVATE_VALUE/);
  assert.match(html, /data-scene-evidence="check:holder_signature"/);
});

test('step brief preserves the current proof-round purpose and selects only concise public summaries', () => {
  const html = renderStepBrief({ purpose: { title: '本次结算验证', round: 3 }, facts: [
    ['证明模式', '盲化 BLS'], ['用户授权', '批准尚未付款'], ['材料来源', 'A 本地材料'], ['模拟 eSIM', '软件模拟 eSIM'],
    ['ownerKey', 'NEVER_RENDER_OWNER_KEY'], ['长订单JSON', 'NEVER_RENDER_UNSELECTED'],
  ] });
  assert.match(html, /本次结算验证 · 第 3 \/ 3 轮证明 · 新挑战与新贡献/);
  for (const text of ['盲化 BLS', '批准尚未付款', 'A 本地材料', '软件模拟 eSIM']) assert.ok(html.includes(text));
  assert.doesNotMatch(html, /NEVER_RENDER/);
  assert.equal((html.match(/<dt>/g) || []).length, 4);
  assert.match(renderStepBrief({ facts: [['材料来源', '<A>']] }), /&lt;A&gt;/);
});

test('rendering checks and summaries is pure and cannot request a business operation', t => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('rendering must not request'); };
  t.after(() => { globalThis.fetch = originalFetch; });
  const value = trace([{ id: 'credential_status', status: 'fail', code: 'W3C_CREDENTIAL_REVOKED' }]), before = structuredClone(value);
  assert.equal(renderCheckPreview(value), renderCheckPreview(value));
  assert.deepEqual(value, before);
  assert.equal(renderStepBrief({ facts: [] }), '');
});

test('dialog close restores the original read-only trigger or its current fallback without any API call', t => {
  const originalDocument = globalThis.document, focused = [], listeners = new Map();
  const trigger = { isConnected: true, focus: options => focused.push(['trigger', options]) };
  const fallback = { focus: options => focused.push(['fallback', options]) };
  globalThis.document = { activeElement: trigger };
  t.after(() => { if (originalDocument === undefined) delete globalThis.document; else globalThis.document = originalDocument; });
  let opened = 0;
  const dialog = { open: false, showModal() { opened++; this.open = true; }, addEventListener(name, listener) { listeners.set(name, listener); } };
  const open = installDialogFocus(dialog, () => fallback);
  open(); assert.equal(opened, 1);
  dialog.open = false; listeners.get('close')();
  assert.deepEqual(focused[0], ['trigger', { preventScroll: true }]);
  open(); trigger.isConnected = false;
  dialog.open = false; listeners.get('close')();
  assert.deepEqual(focused[1], ['fallback', { preventScroll: true }]);
});
