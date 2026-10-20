import test from 'node:test';
import assert from 'node:assert/strict';
import { paymentVerificationIds, verificationEvidenceModel, renderVerificationChecks } from '../public/guide-evidence.js';

const ids = ['w3c_bbs', 'credential_status', 'holder_signature', 'vc_device_binding', 'extension', 'envelope',
  'challenge', 'replay', 'request_binding', 'policy_context', 'scope', 'schema', 'proof_structure', 'disclosure',
  'proof_encoding', 'knowledge', 'credential_pairing', 'device_pairing', 'owner_authorization', 'task_binding',
  'consume', 'settlement_gate', 'execution'];
function trace(phase = 'proposal') {
  const required = new Set(paymentVerificationIds(phase));
  return { source: 'agent-b', profile: 'dbac-payment', outcome: 'pass', steps: ids.map(id => ({ id, title: id,
    status: required.has(id) ? 'pass' : 'skipped', ...(id === 'scope' ? { evidence: [{ label: 'method / scope / phase', observed: ['message/send', 'payments:pay', phase] }] } : {}) })) };
}
const item = (value, id) => value.steps.find(step => step.id === id);
const group = (value, id, phase = 'proposal') => verificationEvidenceModel(value, { phase }).groups.find(row => row.id === id);
const recordHtml = (html, id) => html.slice(html.indexOf(`data-check-id="${id}"`)).split('</section>')[0];

test('empty, non-B and non-payment traces show required pending checks without manufacturing success', () => {
  for (const value of [null, {}, { ...trace(), source: 'agent-a' }, { ...trace(), profile: 'identity' }]) {
    const model = verificationEvidenceModel(value, { phase: 'proposal' });
    assert.ok(model.steps.length > 0);
    assert.ok(model.steps.every(row => row.status === 'pending' && row.rows.length === 0));
    assert.doesNotMatch(renderVerificationChecks(value, { phase: 'proposal' }), /data-state="pass"/);
    assert.match(renderVerificationChecks(value, { phase: 'proposal' }), /待验证/);
  }
  assert.doesNotMatch(renderVerificationChecks(trace(), { phase: 'proposal', ids: [] }), /data-state="pass"/);
  assert.match(renderVerificationChecks(trace(), { phase: 'proposal', ids: [] }), /不能据此推断验证通过/);
});

test('phase and explicit ID selection preserve every necessary pending, failed and skipped check', () => {
  for (const phase of ['proposal', 'authorize', 'settle']) {
    const value = trace(phase), model = verificationEvidenceModel(value, { phase });
    assert.deepEqual(model.steps.map(step => step.id), paymentVerificationIds(phase));
    assert.ok(model.groups.every(row => row.status === 'pass'));
    assert.equal(model.steps.some(step => step.id === 'task_binding'), phase === 'settle');
    assert.equal(model.steps.some(step => step.id === 'owner_authorization'), phase !== 'proposal');
  }
  const value = trace();
  item(value, 'device_pairing').status = 'skipped';
  assert.equal(group(value, 'device').status, 'pending');
  assert.equal(item(verificationEvidenceModel(value, { phase: 'proposal' }), 'device_pairing').status, 'skipped');
  value.steps = value.steps.filter(step => step.id !== 'device_pairing');
  assert.equal(item(verificationEvidenceModel(value, { phase: 'proposal' }), 'device_pairing').status, 'unknown');
  assert.ok(group(value, 'device').missing.includes('device_pairing'));
  const selected = verificationEvidenceModel(null, { phase: 'proposal', ids: ['credential_status', 'holder_signature'] });
  assert.deepEqual(selected.steps.map(step => step.id), ['credential_status', 'holder_signature']);
  const skipped = trace(); skipped.steps.forEach(step => step.status = 'skipped');
  assert.ok(verificationEvidenceModel(skipped, { phase: 'proposal' }).groups.every(row => row.status === 'skipped'));
});

test('running and phase changes never reuse an earlier pass as the current check result', () => {
  const old = trace('proposal');
  for (const option of [{ running: true }, { pending: true }]) {
    const model = verificationEvidenceModel(old, { phase: 'proposal', ...option });
    assert.ok(model.steps.every(step => step.status === (option.running ? 'running' : 'pending')));
    assert.doesNotMatch(renderVerificationChecks(old, { phase: 'proposal', ...option }), /data-state="pass"/);
  }
  const recheck = verificationEvidenceModel(old, { phase: 'settle', recheck: true });
  assert.equal(recheck.phaseMismatch, true);
  assert.ok(recheck.steps.every(step => step.status === 'unknown'));
  const html = renderVerificationChecks(old, { phase: 'settle', recheck: true });
  assert.match(html, /本步复核/);
  assert.match(html, /旧阶段结果未用于本步/);
  assert.doesNotMatch(html, /data-state="pass"/);
});

test('duplicate IDs, overall contradictions and failed comparison values are visible before evidence expansion', () => {
  const duplicate = trace(); duplicate.steps.push(structuredClone(item(duplicate, 'device_pairing')));
  assert.equal(group(duplicate, 'device').status, 'pending');
  duplicate.steps.at(-1).status = 'fail'; duplicate.steps.at(-1).code = 'LATE_FAILURE';
  assert.equal(item(verificationEvidenceModel(duplicate, { phase: 'proposal' }), 'device_pairing').status, 'fail');
  assert.match(recordHtml(renderVerificationChecks(duplicate, { phase: 'proposal' }), 'device_pairing').split('<details')[0], /LATE_FAILURE/);
  const contradiction = trace();
  item(contradiction, 'device_pairing').evidence = [{ label: 'e(H0,pi_se) = e(randomizedKey,Q)', expected: true, observed: false, match: false }];
  assert.equal(group(contradiction, 'device').status, 'fail');
  const html = renderVerificationChecks(contradiction, { phase: 'proposal' });
  assert.match(html, /整体结论为通过，但存在失败或不匹配/);
  const defaultRecord = recordHtml(html, 'device_pairing').split('<details')[0];
  assert.match(defaultRecord, /服务器标记通过，但公开比较记录存在不匹配/);
  assert.match(defaultRecord, /不相符项/);
  assert.match(html, /服务端记录：不相符/);
  const overallOnly = { source: 'agent-b', profile: 'dbac-payment', outcome: 'pass', steps: [] };
  assert.ok(verificationEvidenceModel(overallOnly, { phase: 'proposal' }).steps.every(step => step.status === 'unknown'));
  assert.match(renderVerificationChecks(overallOnly, { phase: 'proposal' }), /记录不完整/);
});

test('unexpected failed IDs remain visible instead of being filtered into a false success', () => {
  const value = trace();
  item(value, 'owner_authorization').status = 'fail';
  item(value, 'owner_authorization').code = 'UNEXPECTED_AUTH_FAILURE';
  value.steps.push({ id: 'future_check', title: '新增服务端检查', status: 'fail', code: 'FUTURE_FAILURE' });
  const html = renderVerificationChecks(value, { phase: 'proposal', ids: ['w3c_bbs'] });
  assert.match(html, /data-check-id="w3c_bbs"/);
  assert.match(html, /data-check-id="owner_authorization"/);
  assert.match(html, /data-check-id="future_check"/);
  assert.match(html, /UNEXPECTED_AUTH_FAILURE/);
  assert.match(html, /FUTURE_FAILURE/);
  assert.doesNotMatch(html, /data-check-id="scope"/);
  assert.match(html, /预期范围外的失败事项/);
});

test('a check pass does not fabricate field comparisons and skipped steps suppress attached evidence', () => {
  const value = trace();
  item(value, 'w3c_bbs').evidence = [{ label: 'proof type / suite / issuer', expected: ['DataIntegrityProof', 'bbs-2023', 'issuer'], observed: ['DataIntegrityProof', 'bbs-2023', 'issuer'] }];
  const html = renderVerificationChecks(value, { phase: 'proposal' });
  assert.match(html, /该字段用于材料展示，服务端未返回独立核验结论。/);
  assert.doesNotMatch(html, /服务端记录：相符/);
  assert.match(html, /guide-evidence-row" data-state="material"/);
  item(value, 'w3c_bbs').status = 'skipped';
  item(value, 'w3c_bbs').evidence[0].observed = 'UNEXECUTED_SENTINEL';
  item(value, 'w3c_bbs').evidence[0].match = true;
  const skipped = renderVerificationChecks(value, { phase: 'proposal' });
  assert.doesNotMatch(skipped, /UNEXECUTED_SENTINEL/);
  assert.match(skipped, /本次未执行此项检查，不能据此推断通过/);
});

test('public comparisons remain escaped and unsupported material objects are never expanded', () => {
  const value = trace();
  item(value, 'request_binding').evidence = [{ label: 'raw body SHA-256', expected: '<b>expected</b>', observed: '<img src=x onerror="alert(1)">', match: false, note: 'note <script>bad()</script>' }];
  item(value, 'w3c_bbs').evidence = [
    { label: 'proof type / suite / issuer', observed: { privateKey: 'PRIVATE_SENTINEL', organization: 'HIDDEN_SENTINEL' } },
    { label: 'privateKey', observed: 'PRIVATE_SCALAR_SENTINEL' },
    { label: 'holderLabel', observed: 'HIDDEN_LABEL_SENTINEL' },
    { label: 'proof type / suite / issuer', expected: 'bbs-2023', observed: 'bbs-2023', secretKey: 'UNSELECTED_SENTINEL' },
  ];
  const html = renderVerificationChecks(value, { phase: 'proposal' });
  assert.match(html, /&lt;b&gt;expected&lt;\/b&gt;/);
  assert.match(html, /&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
  assert.match(html, /note &lt;script&gt;bad\(\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<img|<script|<b>/);
  assert.doesNotMatch(html, /PRIVATE_SENTINEL|HIDDEN_SENTINEL|PRIVATE_SCALAR_SENTINEL|HIDDEN_LABEL_SENTINEL|UNSELECTED_SENTINEL/);
  assert.match(html, /不属于允许展示的公开标量字段/);
});

test('PH is labeled as verifier input and long public values are readable only on demand', () => {
  const value = trace();
  item(value, 'w3c_bbs').evidence = [{ label: 'expected presentationHeader (hex)', observed: 'abcdef'.repeat(50), note: 'Verifier input; checked by bbs-2023.' }];
  item(value, 'w3c_bbs').evidenceTruncated = true;
  const html = renderVerificationChecks(value, { phase: 'proposal' });
  assert.match(html, /并非从收到的证明中提取的 PH/);
  assert.match(html, /未记录约束（输入或计算输出）/);
  assert.match(html, /后续比较值未返回/);
  assert.match(html, /服务端未返回可展示的公开比较值/);
  assert.match(html, /<details class="guide-evidence-value">/);
  assert.match(html, /查看完整值/);
  assert.ok(html.includes('abcdef'.repeat(50)));
});

test('core inputs, relation, returned comparisons and conclusion are visible without a duplicate evidence entry', () => {
  const value = trace();
  item(value, 'request_binding').evidence = [
    { label: 'raw body SHA-256', expected: 'expected-a', observed: 'observed-a', match: true },
    { label: 'payment order ID', expected: 'expected-b', observed: 'observed-b', match: true },
    { label: 'challenge already used', expected: false, observed: false, match: true },
  ];
  const before = JSON.stringify(value);
  const html = renderVerificationChecks(value, { phase: 'proposal', materialsById: { request_binding: '<p>SAFE_PUBLIC_MATERIAL</p>', task_binding: '<p>FUTURE_MATERIAL</p>' } });
  assert.equal((html.match(/data-check-id=/g) || []).length, paymentVerificationIds('proposal').length);
  const record = recordHtml(html, 'request_binding'), [defaultRecord, details] = record.split('<details class="guide-evidence-more"');
  for (const value of ['expected-a', 'observed-a', 'expected-b', 'observed-b', 'SAFE_PUBLIC_MATERIAL']) assert.ok(defaultRecord.includes(value));
  assert.match(defaultRecord, /输入来源|操作 \/ 核验关系|输出 · 本次公开记录|结论：|SHA-256/);
  assert.match(details, /其余本项公开记录 · 1 项/);
  assert.match(details, /挑战是否已使用/);
  assert.doesNotMatch(details, /expected-a|observed-a|SAFE_PUBLIC_MATERIAL/);
  assert.doesNotMatch(html, /查看验证依据|guide-check-evidence/);
  assert.doesNotMatch(html, /FUTURE_MATERIAL|<details[^>]+\bopen\b|onclick=|onchange=|fetch\(/);
  assert.equal(JSON.stringify(value), before);
});

test('failed actual comparisons remain directly visible while missing comparisons are never filled in', () => {
  const value = trace(); value.outcome = 'fail';
  const failed = item(value, 'vc_device_binding');
  failed.status = 'fail'; failed.code = 'W3C_DEVICE_PROOF_REQUIRED';
  failed.evidence = [{ label: 'bindingId / mode / device contribution', expected: ['binding-current', 'bbs-bls', true], observed: ['binding-current', 'bbs-bls', false] }];
  let record = recordHtml(renderVerificationChecks(value, { phase: 'proposal' }), 'vc_device_binding');
  assert.match(record, /预期 · 验证约束|实际 · 验证者 B 本次记录/);
  assert.match(record, /<span>binding-current\nbbs-bls\ntrue<\/span>/);
  assert.match(record, /<span>binding-current\nbbs-bls\nfalse<\/span>/);
  assert.doesNotMatch(record, /<details|服务端记录：不相符|服务端记录：相符/);
  failed.evidence = [{ label: 'bindingId / mode / device contribution', observed: ['binding-current', 'bbs-bls', false] }];
  record = recordHtml(renderVerificationChecks(value, { phase: 'proposal' }), 'vc_device_binding');
  assert.match(record, /服务端未返回完整的预期 \/ 实际比对/);
  assert.match(record, /未记录约束/);
  assert.doesNotMatch(record, /\ntrue|服务端记录：不相符|服务端记录：相符/);
  failed.status = 'skipped';
  assert.doesNotMatch(recordHtml(renderVerificationChecks(value, { phase: 'proposal' }), 'vc_device_binding'), /binding-current/);
});


test('device binding and contribution have their own compact group and never replace holder or other checks', () => {
  for (const phase of ['proposal', 'authorize', 'settle']) {
    const model = verificationEvidenceModel(trace(phase), { phase });
    assert.deepEqual(model.groups.find(row => row.id === 'device').steps.map(row => row.id), ['vc_device_binding', 'device_pairing']);
    assert.deepEqual(model.groups.find(row => row.id === 'holder').steps.map(row => row.id), ['holder_signature']);
    assert.deepEqual(new Set(model.groups.flatMap(row => row.steps.map(step => step.id))), new Set(paymentVerificationIds(phase)));
    assert.equal(model.groups.flatMap(row => row.steps).length, paymentVerificationIds(phase).length);
  }
  const html = renderVerificationChecks(null, { phase: 'proposal' });
  assert.match(html, /guide-evidence-group--device/);
  assert.match(html, /模拟 eSIM 绑定与本次贡献/);
  assert.match(html, /软件仿真/);
  assert.doesNotMatch(html, /data-state="pass"/);
  const partial = trace(); partial.steps = partial.steps.filter(step => step.id !== 'device_pairing');
  const device = verificationEvidenceModel(partial, { phase: 'proposal' }).groups.find(row => row.id === 'device');
  assert.equal(device.status, 'pending');
  assert.equal(device.steps.find(step => step.id === 'device_pairing').status, 'unknown');
});
