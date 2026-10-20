'use strict';

// Render only the checks reported by the server; the browser never infers a pass.
window.DemoVerification = (() => {
  const statuses = { pass: ['通过', '✓'], fail: ['未通过', '×'], skipped: ['未执行', '—'] };
  const actors = { 'agent-a': '持有者智能体 A', 'agent-b': '验证者智能体 B', issuer: '凭证签发方', device: '模拟 eSIM', owner: '用户（Owner）' };
  const principles = {
    w3c_bbs: ['标准 bbs-2023', 'ProofVerify(pk_std, π_std, header_std, M_disclosed, PH, I_std) = true', '标准库核验 JSON-LD/RDF 派生证明。I_std 是标准库消息索引；PH 绑定本次挑战，与内部 header_std 不同。'],
    vc_device_binding: ['项目绑定扩展', 'VC.credentialSubject.bindingId = disclosed.find(index = 6).value', '两份材料由同一签发方签入同一绑定标识，防止把别人的 VC 与自己的设备证明拼接。'],
    challenge: ['新鲜性', 'issued(ctx) ∧ now < ctx.exp', '挑战由 B 签发，保留 60 秒；页面回看或刷新不会重新申请。'],
    replay: ['防重放', 'challenge.used = false', '校验成功后还会原子消费挑战；这是请求防重放，订单防重复扣款另行处理。'],
    request_binding: ['精确请求绑定', 'SHA256(rawRequest) = ctx.bodyHash', '检查收到的原始正文、方法与端点。改动金额或任一正文内容会改变摘要。'],
    disclosure: ['披露策略', 'I = {0, 1, 2, 3, 6}；J = {4, 5}', '此处 I、J 是配套材料的属性索引；标准 VC 另按本次策略披露字段，组织与持有者标签是否披露以派生文档为准。'],
    knowledge: ['论文知识证明', "Y = g₁ + D + Σᵢ∈ᴵ aᵢHᵢ₊₁\nT₁′ = z_w C̄ + z_k H₀ − Σⱼ∈ᴶ zⱼHⱼ₊₁ − cY\nT₂′ = z_r C̄ − z_ε Ā − cB̄\nc′ = H_scalar(公开语句, ctx*, T₁′, T₂′)；检查 c′ = c", 'z 是公开的掩码响应。该检查证明掌握配套凭证与随机化材料，不要求持有者 A 知道设备私钥 u。'],
    credential_pairing: ['论文配套凭证', 'E(Ā, W) = E(B̄, g₂)', 'E 是双线性配对，W 是配套凭证签发方公钥。此项与上面的标准 W3C BBS 校验分别执行。'],
    device_pairing: ['模拟 eSIM 贡献', 'D = dpk + kH₀；π_se = σ + kQ\nE(H₀, π_se) = E(D, Q)', 'Q 绑定订单挑战及派生 VC 哈希。只复制 VC，无法补出匹配原设备的签名贡献。'],
    owner_authorization: ['单笔付款授权', 'VerifyOwnerSig(auth) ∧ exactTerms(auth, order, D, bindingId)', '核对用户签署的精确金额、收款方、网络、有效期和凭证绑定；密码学资格核验不代替用户批准。'],
    task_binding: ['任务连续性', 'taskId / contextId / orderHash / authHash / D / bindingId 一致', '结算只能继续原付款任务，不能更换已批准订单、设备伪名或 VC。'],
    consume: ['原子消费挑战', '再次检查未使用与有效期 → used = true', '异步密码验证结束后再次检查并同步消费，防止并发请求重复使用挑战。'],
    execution: ['业务结果', '提案 → 资格证据；授权 → 付款要求；结算 → 支付回执', '只有结算阶段返回实际成功回执才表示付款完成。钱包签署材料本身不转账。'],
  };
  const evidenceLabels = {
    'extension / identified headers':'扩展标识 / 是否携带具名请求头',
    'body / proof encoded length':'正文 / 证明编码长度',
    'challenge found / now / expiry (s)':'挑战存在 / 当前时间 / 截止时间（秒）',
    'challenge already used':'挑战是否已使用',
    'raw body SHA-256':'实际正文 SHA-256',
    'role / scope / epoch / mode':'角色 / 权限 / 日期 / 模式',
    'method / scope / phase':'方法 / 权限 / 支付阶段',
    'payment order ID':'订单编号',
    'signed attribute count':'签名属性数量',
    'proof type / suite / issuer':'证明类型 / 密码套件 / 签发方',
    'expected presentationHeader SHA-256':'验证方输入 PH 的 SHA-256 摘要',
    'expected presentationHeader (hex)':'本次预期 PH（十六进制）',
    'bindingId / mode / device contribution':'绑定标识 / 模式 / 是否携带设备贡献',
    'hVC: derived credential hash':'hVC：收到的派生 VC 摘要',
    'version / suite / mode':'版本 / 密码套件 / 模式',
    'required disclosures (index=value)':'必需披露项（索引 = 值）',
    'Abar / Bbar / Cbar (G1)':'随机化凭证 Ā / B̄ / C̄',
    'randomized key (G1) / pi_se (G2)':'设备伪名 D / 适配签名 π_se',
    'Fiat-Shamir challenge':'知识证明挑战 c′ / c',
    'reconstructed T1 / T2 (G1)':'重建承诺 T₁′ / T₂′',
    'issuer public key W (G2)':'论文配套凭证签发公钥 W',
    'hash-to-curve point Q (G2)':'哈希到曲线的实际结果 Q',
    'Owner / VC binding / issued / expires':'用户 / VC 绑定 / 签发时间 / 截止时间',
    'context / order / authorization / VC binding':'任务上下文 / 订单摘要 / 授权摘要 / VC 绑定',
    'task continuity tuple hash':'任务绑定各字段的联合摘要',
    'before consume: used / now / expires':'消费前：是否已用 / 当前时间 / 截止时间',
    'after synchronous consume: used':'同步消费后：是否已用',
    'phase / resulting task':'支付阶段 / 实际任务状态',
    'order / authorization / payload digest':'订单 / 授权 / 付款材料摘要',
    'settlement outcome / transaction':'结算结果 / 交易编号',
  };
  const evidenceNotes = {
    'Verifier input; checked by bbs-2023.':'这是本次预期 PH；由标准 bbs-2023 库核对。',
    'Claims untrusted until signature and binding checks pass.':'收到的声明在签名与绑定检查通过前不可信。',
    'Public compressed curve points; subgroup and canonical encoding are checked.':'公开的压缩曲线点；后端实际检查子群及规范编码。',
    'Verifier input; the standard library compares the proof-embedded header with this expected header.':'这是验证方的输入摘要；标准库核对证明携带的 PH 与本次预期 PH。此值不是从证明中提取的 PH。',
    'Recomputed from the received VC; the following knowledge/device checks bind it into the request context.':'根据实际收到的 VC 重算；后续知识证明与设备检查将这个摘要绑定到请求上下文。',
    'pi_se is the adapted contribution; Q binds this context and randomized device key.':'π_se 是适配后的设备贡献；Q 绑定本次上下文与设备伪名。',
    'Received claims are untrusted until the signed authorization check succeeds; no token is disclosed.':'这些收到的声明在签名验证成功前不可信；此处不展示完整授权令牌。',
    'Qualification only; no wallet signing or settlement is invoked.':'本阶段仅核验资格，未调用钱包签名或结算。',
    'Returns payment requirements; no transfer is performed.':'本阶段返回付款要求，尚未转账。',
  };
  const node = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = String(text);
    return element;
  };

  function create(root) {
    let state = 'empty';
    function reset(kind, title, message) {
      state = kind;
      root.replaceChildren();
      root.className = `verification-view verification-${kind}`;
      root.setAttribute('aria-busy', String(kind === 'loading'));
      const notice = node('div', 'verification-notice');
      notice.append(node('span', 'verification-notice-icon', kind === 'loading' ? '⋯' : kind === 'error' ? '!' : '↔'));
      const content = node('div');
      content.append(node('strong', '', title), node('p', '', message));
      notice.append(content);
      root.append(notice);
    }
    function render(trace, options = {}) {
      if (!trace || !Array.isArray(trace.steps) || !trace.steps.length) {
        reset(options.error ? 'error' : 'empty', options.label || '本次没有验证轨迹', options.error || options.message || '服务端未返回本次检查步骤；不能据此判断验证是否通过。发起调用后，可在这里查看服务端记录。');
        return;
      }
      state = 'result';
      root.replaceChildren();
      root.className = 'verification-view';
      root.setAttribute('aria-busy', 'false');
      const heading = node('div', 'verification-heading');
      const headingText = node('div');
      headingText.append(node('p', 'verification-kicker', '本次验证记录 · 按执行顺序'), node('h3', '', options.label || '请求验证过程'));
      heading.append(headingText);
      const outcome = trace.outcome === 'pass' ? 'pass' : trace.outcome === 'fail' ? 'fail' : 'unknown';
      heading.append(node('span', `verification-outcome ${outcome}`, outcome === 'pass' ? '本次验证通过' : outcome === 'fail' ? '本次验证未通过' : '结果未标注'));
      root.append(heading);
      const traces = Array.isArray(options.traces) ? options.traces.filter(item => Array.isArray(item?.steps) && item.steps.length) : [];
      if (traces.length > 1) {
        const selected = options.selectedTraceIndex ?? traces.findIndex(item => JSON.stringify(item) === JSON.stringify(trace));
        const attempts = node('div', 'verification-attempts');
        attempts.setAttribute('aria-label', '本用例内的各次请求');
        traces.forEach((attempt, index) => {
          const button = node('button', 'verification-attempt', `请求 ${index + 1} · ${attempt.outcome === 'pass' ? '通过' : attempt.outcome === 'fail' ? '未通过' : '未标注'}`);
          button.type = 'button';
          button.setAttribute('aria-pressed', String(index === selected));
          button.addEventListener('click', () => render(attempt, { ...options, selectedTraceIndex: index }));
          attempts.append(button);
        });
        root.append(attempts);
      }
      const source = actors[trace.source] || trace.source;
      const counts = trace.steps.reduce((acc, step) => { if (statuses[step?.status]) acc[step.status] += 1; return acc; }, { pass: 0, fail: 0, skipped: 0 });
      root.append(node('p', 'verification-caption', `${source ? `轨迹来源：${source} · ` : ''}${counts.pass} 项通过 / ${counts.fail} 项未通过 / ${counts.skipped} 项未执行。`));
      const evidencePanels = [];
      const list = node('ol', 'verification-steps');
      trace.steps.forEach((step, index) => {
        const status = statuses[step?.status] ? step.status : 'unknown';
        const [label, symbol] = statuses[status] || ['未标注', '?'];
        const item = node('li', `verification-step ${status}`);
        item.append(node('span', 'verification-step-number', String(index + 1).padStart(2, '0')));
        const body = node('div', 'verification-step-body');
        const title = node('div', 'verification-step-title');
        title.append(node('strong', '', step?.title || step?.id || '检查步骤'), node('span', 'verification-step-status', `${symbol} ${label}`));
        body.append(title);
        body.append(node('span', 'verification-actor', actors[step?.actor] || step?.actor || '执行角色未标注'));
        if (step?.detail) body.append(node('p', 'verification-detail', step.detail));
        if (step?.code) body.append(node('code', 'verification-code', step.code));
        const evidence = status === 'skipped' ? [] : Array.isArray(step?.evidence) ? step.evidence : [];
        const principle = trace.profile === 'dbac-payment' ? principles[step?.id] : null;
        if (evidence.length || principle) {
          const details = node('details', 'verification-evidence');
          details.open = status === 'fail' || Boolean(options.detailed && status === 'pass' && ['w3c_bbs','vc_device_binding','proof_encoding','knowledge','credential_pairing','device_pairing'].includes(step.id));
          details.append(node('summary', '', evidence.length ? `实际比较 · ${evidence.length} 项${principle ? ' / 校验原理' : ''}` : '校验原理 · 本项没有实际比较记录'));
          if (principle) {
            const explanation=node('div','verification-principle');
            explanation.append(node('strong','',`${principle[0]} · 算法说明`),node('pre','verification-formula',principle[1]),node('p','',principle[2]));
            details.append(explanation);
          }
          if (evidence.length) {
            const table=node('table','verification-evidence-table'), head=node('thead'), row=node('tr');
            ['比较项','预期 / 约束','验证记录中的值'].forEach(label=>row.append(node('th','',label)));head.append(row);table.append(head);
            const rows=node('tbody');
            for (const entry of evidence) {
              const row=node('tr',entry.match===false ? 'evidence-mismatch' : '');
              const label=node('th','',evidenceLabels[entry.label] || entry.label || '比较值');label.scope='row';
              if(typeof entry.match==='boolean')label.append(node('span','evidence-match',entry.match ? '相符' : '不相符'));
              const display=value=>value===null||value===undefined ? '未提供' : typeof value==='string' ? value : Array.isArray(value) ? value.map(item=>typeof item==='string' ? item : JSON.stringify(item)).join('\n') : JSON.stringify(value);
              row.append(label,node('td','',entry.expected==null && entry.match===undefined ? '—（计算输出）' : display(entry.expected)),node('td','',display(entry.observed)));rows.append(row);
              if(entry.note){const noteRow=node('tr'),note=node('td','evidence-note',evidenceNotes[entry.note] || entry.note);note.colSpan=3;noteRow.append(note);rows.append(noteRow);}
            }
            table.append(rows);const scroll=node('div','verification-table-scroll');scroll.append(table);details.append(scroll);
            if(step.evidenceTruncated)details.append(node('p','verification-detail','本项公开记录达到显示上限，已省略后续比较值。'));
          } else details.append(node('p','verification-detail',status==='skipped' ? '本项没有执行。以上仅为原理说明，没有通过结论。' : '服务端未记录本项比较值；执行状态以上方返回结果为准。'));
          body.append(details);evidencePanels.push(details);
        }
        item.append(body);
        list.append(item);
      });
      if(evidencePanels.length){const controls=node('div','verification-data-controls');for(const [label,open]of [['展开全部数据',true],['收起数据',false]]){const button=node('button','verification-attempt',label);button.type='button';button.addEventListener('click',()=>evidencePanels.forEach(panel=>{panel.open=open;}));controls.append(button);}root.append(controls);}
      root.append(list);
      if (options.error) root.append(node('p', 'verification-error-message', options.error));
    }
    reset('empty', '等待本次验证结果', '提交请求后，查看检查结果、执行角色和验证依据。灰色“未执行”表示该检查没有运行。');
    return {
      render,
      clear: message => reset('empty', '等待本次验证结果', message || '本次操作未调用验证方。发起新的请求后查看验证过程。'),
      loading: message => reset('loading', '正在等待验证记录', message || '结果返回后显示已执行的检查步骤。'),
      error: message => reset('error', '暂未取得验证结果', message),
      get pending() { return state === 'loading'; },
    };
  }

  function bindNavigation() {
    document.querySelectorAll('[data-demo-view]').forEach(link => {
      link.addEventListener('click', event => {
        if (window.parent === window) return;
        event.preventDefault();
        window.parent.postMessage({ type: 'demo:navigate', view: link.dataset.demoView }, location.origin);
      });
    });
  }
  function focus(root) {
    if (window.parent !== window) window.parent.postMessage({ type: 'demo:scroll', top: root.getBoundingClientRect().top + window.scrollY }, location.origin);
    else root.scrollIntoView({ block: 'start', behavior: 'smooth' });
  }
  bindNavigation();
  return { create, focus };
})();
