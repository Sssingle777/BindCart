import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { resolve } from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { AppError } from '../protocol.mjs';
import { createLocalMerchant } from './merchant.mjs';
import { canonicalOrder } from './merchant-protocol.mjs';
import { CATALOG, catalogProduct } from './catalog.mjs';

// The storefront adapts business actions to the supplied payment-session.mjs.
// Credential, device, Owner, wallet and settlement decisions stay in that core.
export { CATALOG } from './catalog.mjs';
const fail = (code, message, status = 409) => { throw new AppError(code, message, status); };
function exact(body, keys) {
  if (!body || Array.isArray(body) || Object.keys(body).sort().join() !== [...keys].sort().join()) fail('STORE_INPUT_INVALID', '请求字段不正确；商品价格与收款方由后端确定。', 400);
}
export async function createStorefrontController({ paymentSession: payments, directory, merchant: merchantConfig, paymentInfo, emit = () => {} }) {
  await mkdir(directory, { recursive: true });
  const merchant = merchantConfig ? await createLocalMerchant({ ...merchantConfig, paymentInfo, queryPayment: options => payments.queryPayment(options), emit }) : null;
  let record = { version: 1, phase: 'cart', revision: 0, cart: {}, boundOrder: null, receipt: null, verification: null, events: [], message: '挑选商品，加入购物车。' };
  let controlToken = randomBytes(32).toString('base64url'), stepRevision = 0, manualRunning = false;
  try {
    const previous = JSON.parse(await readFile(resolve(directory, 'current.json'), 'utf8'));
    if (previous.version !== 1 || !previous.cart || Array.isArray(previous.cart) || typeof previous.cart !== 'object' || !Number.isSafeInteger(previous.revision) || previous.revision < 0 ||
      !['cart', 'verifying', 'checkout', 'paying', 'confirming', 'paid', 'unknown'].includes(previous.phase) ||
      Object.entries(previous.cart).some(([id, qty]) => !catalogProduct(id) || !Number.isInteger(qty) || qty < 1 || qty > catalogProduct(id).maxQuantity) ||
      (previous.boundOrder && !/^urn:uuid:[0-9a-f-]{36}$/.test(previous.boundOrder.orderId))) throw new Error('Unexpected order record');
    record = { ...record, ...previous };
    if (['paying', 'unknown'].includes(previous.phase)) record.phase = 'unknown';
    else if (!['paid', 'confirming'].includes(previous.phase)) { record.phase = 'cart'; record.boundOrder = null; record.verification = null; delete record.error; record.message = '本地服务已重新启动，请重新结算当前购物车。'; }
  } catch (error) { if (error.code !== 'ENOENT') record = { ...record, phase: 'unknown', message: '原订单记录读取失败，请先核对记录。' }; }
  const lines = () => Object.entries(record.cart).map(([id, quantity]) => ({ ...catalogProduct(id), quantity, amountMinor: catalogProduct(id).unitAmountMinor * quantity }));
  const total = () => lines().reduce((sum, line) => sum + line.amountMinor, 0);
  const event = (action, result, detail) => {
    record.events.push({ at: new Date().toISOString(), orderId: record.boundOrder?.orderId ?? null, action, result, ...(detail ? { detail } : {}) });
    record.events = record.events.slice(-60);
  };
  async function save() {
    record.merchant = record.boundOrder && merchant ? await merchant.state(record.boundOrder.orderId) : { status: 'none', merchantId: 'mystore' };
    const data = JSON.stringify(record, null, 2);
    await writeFile(resolve(directory, 'current.json.tmp'), data);
    await rename(resolve(directory, 'current.json.tmp'), resolve(directory, 'current.json'));
    if (record.boundOrder) {
      const path = resolve(directory, `${record.boundOrder.orderId.slice(9)}.json`);
      await writeFile(`${path}.tmp`, data); await rename(`${path}.tmp`, path);
    }
  }
  function revision(value) { if (!Number.isInteger(value) || value !== record.revision) fail('STORE_STALE_CART', '购物车已更新，请刷新后操作。'); }
  function noPendingPayment() { if (['paying', 'confirming', 'unknown'].includes(record.phase)) fail('STORE_PAYMENT_UNRESOLVED', '原订单的付款结果待核对，不能创建或重复提交付款。'); }
  function rotateControl() { controlToken = randomBytes(32).toString('base64url'); stepRevision++; }
  function sameOrder(left, right) { return Boolean(left && right && canonicalOrder(left) === canonicalOrder(right)); }
  const actionLabels = {
    issue: '签发本次支付资格凭证', 'begin-proposal': '获取资格认证挑战', 'derive-vc': '生成本次派生凭证',
    'device-sign': '请求模拟 eSIM 贡献', prove: '生成持有者证明并组合', verify: '提交验证者 B 验证',
    'submit-owner': '提交付款授权申请', 'sync-owner': '同步用户付款授权', 'begin-authorize': '获取付款前核验挑战',
    'wallet-sign': '签署本笔付款材料', 'begin-settle': '获取结算挑战', 'confirm-merchant': '核对商家并确认订单', discard: '结束当前认证尝试',
  };
  function manualControl(core) {
    const m = core.manual ?? {}, protocolActions = m.availableActions ?? [];
    const authorizationExpired = Boolean(core.authorization && Number.isSafeInteger(core.authorization.document?.exp) && core.authorization.document.exp * 1000 <= Date.now());
    let availableActions = [], nextAction = null, reason = '';
    if (record.phase === 'verifying') {
      availableActions = core.credential ? protocolActions.filter(action => ['begin-proposal', 'derive-vc', 'device-sign', 'prove', 'verify', 'submit-owner', 'discard', 'test-wrong-device', 'test-no-device', 'test-tamper', 'replay'].includes(action)) : ['issue'];
    } else if (record.phase === 'paying') {
      availableActions = protocolActions.filter(action => ['sync-owner', 'begin-authorize', 'derive-vc', 'device-sign', 'prove', 'verify', 'wallet-sign', 'begin-settle', 'discard', 'test-wrong-device', 'test-no-device', 'test-tamper', 'replay'].includes(action));
      if (!core.authorization || authorizationExpired) availableActions = availableActions.filter(action => action === 'sync-owner');
      if (m.walletSigned) availableActions = availableActions.filter(action => !['wallet-sign', 'begin-authorize'].includes(action));
      if (m.walletSigningUnconfirmed) availableActions = [];
    } else if (record.phase === 'confirming' && record.receipt) availableActions = ['confirm-merchant'];
    else if (record.phase === 'checkout' && (['EXPIRED', 'REJECTED'].includes(core.proposal?.status) || record.ownerDecision?.status === 'REJECTED' || Number.isFinite(Date.parse(core.proposal?.expiresAt)) && Date.parse(core.proposal.expiresAt) <= Date.now())) availableActions = protocolActions.filter(action => action === 'sync-owner');
    const expired = Boolean(m.expired || m.stage === 'EXPIRED' || m.active && Number.isFinite(m.expiresAtUnix) && m.expiresAtUnix * 1000 <= Date.now());
    if (record.phase === 'confirming') nextAction = 'confirm-merchant';
    else if (record.phase === 'checkout' && availableActions.includes('sync-owner')) { nextAction = 'sync-owner'; reason = '原用户授权已失效或被拒绝，请手动同步原决定后重新验证本单。'; }
    else if (record.phase === 'verifying' && !core.credential) nextAction = 'issue';
    else if (record.phase === 'verifying' && ['REJECTED', 'EXPIRED'].includes(core.proposal?.status)) nextAction = 'begin-proposal';
    else if (record.phase === 'paying' && (!core.authorization || authorizationExpired)) { nextAction = 'sync-owner'; if (authorizationExpired) reason = m.walletSigned ? '原授权已过期，已签付款材料必须保留；请显式同步并核对原订单。' : '原授权已过期，请显式同步原决定后重新验证本单。'; }
    else if (['verifying', 'paying'].includes(record.phase)) {
      if (m.walletSigningUnconfirmed) reason = '钱包签名结果尚待核对，保留原订单，不能重新签名。';
      else if (m.walletSigned && (m.phase !== 'settle' || !m.active || expired)) nextAction = 'begin-settle';
      else if (expired && m.active) { nextAction = `begin-${m.phase}`; reason = '本阶段材料已过期，请手动取得新挑战；不会自动重签。'; }
      else nextAction = ({ CHALLENGE_READY: core.w3c?.enabled === false ? 'device-sign' : 'derive-vc', VC_DERIVED: 'device-sign', DEVICE_SIGNED: 'prove', PROOF_READY: 'verify', VERIFIED: m.phase === 'proposal' ? 'submit-owner' : m.phase === 'authorize' ? 'wallet-sign' : null, OWNER_SUBMITTED: 'begin-authorize', WALLET_SIGNED: 'begin-settle' })[m.stage] ?? (record.phase === 'verifying' ? 'begin-proposal' : 'begin-authorize');
    } else reason = record.phase === 'checkout' ? '等待在商城核对商品并明确批准付款，控制台不会自动继续。' : record.phase === 'unknown' ? '原付款结果待核对，请查询原订单，不能重新付款。' : record.phase === 'paid' ? '本订单已完成。' : '请先在商城选择商品并结算。';
    if (!availableActions.includes(nextAction)) nextAction = null;
    return { token: controlToken, stepRevision, availableActions, nextAction, label: nextAction ? (nextAction === 'verify' && m.phase === 'settle' ? '提交结算验证并执行模拟支付' : actionLabels[nextAction] ?? nextAction) : null, reason,
      mode: core.mode ?? 'bbs-bls', phase: m.phase ?? null, stage: m.stage ?? 'IDLE', attemptId: m.attemptId ?? null, expiresAtUnix: m.expiresAtUnix ?? null, expired,
      waitingForFrontend: ['cart', 'checkout'].includes(record.phase) && !nextAction };
  }
  async function state(coreSnapshot) {
    const core = coreSnapshot ?? await payments.state();
    return {
      phase: record.phase, revision: record.revision, cart: lines(), totalMinor: total(), currency: 'TEST_USDC',
      message: record.message, error: record.error ?? null, order: record.boundOrder, receipt: record.receipt,
      verification: record.verification, events: record.events, merchant: record.boundOrder && merchant ? await merchant.state(record.boundOrder.orderId) : { status: 'none', merchantId: 'mystore' }, experiment: record.experiment ?? null,
      manualControl: manualControl(core),
      backend: {
        module: 'lib/dbac/payment-session.mjs', credentialStatus: core.credentialStatus, holder: core.holder,
        currentCredentialId: core.currentCredentialId, currentDeviceId: core.currentDeviceId,
        proposal: core.proposal, authorization: core.authorization ? { id: core.authorization.id } : null,
        paymentPending: core.paymentPending, ledger: core.ledger,
        manual: core.manual, w3c: { enabled: core.w3c?.enabled !== false },
        protocol: 'x402-v2 / local test EVM',
      },
      localTestOnly: true, paymentProvider: 'original-local-x402',
    };
  }
  async function changeCart(body) {
    exact(body, ['productId', 'quantity', 'revision']); revision(body.revision); noPendingPayment();
    if (record.phase !== 'cart') fail('STORE_CART_LOCKED', '此订单已进入结算。开始新一笔购物后再修改商品。');
    if (!CATALOG.some(p => p.id === body.productId) || !Number.isInteger(body.quantity) || body.quantity < 0 || body.quantity > 1) fail('STORE_PRODUCT_INVALID', '请选择目录中的商品，每种商品最多一件。', 400);
    if (body.quantity === 0) delete record.cart[body.productId]; else record.cart[body.productId] = body.quantity;
    record.revision++; record.boundOrder = null; record.verification = null; delete record.error; delete record.ownerDecision; rotateControl();
    record.message = '购物车已更新。'; event('cart.update', 'ok'); await save(); return state();
  }
  async function checkout(body) {
    exact(body, ['revision']); revision(body.revision); noPendingPayment();
    if (['verifying', 'checkout'].includes(record.phase)) return state();
    if (record.phase !== 'cart' || !total()) fail('STORE_CART_EMPTY', '请先将商品加入购物车。');
    if (lines().some(line => line.legacy || line.quantity !== 1)) fail('STORE_PRODUCT_INVALID', '旧版购物车仅保留供核对，请开始新一笔购物。', 400);
    record.phase = 'verifying'; delete record.error;
    try {
      let core = await payments.state();
      if (!record.boundOrder) {
        const merchantOrder = merchant ? await merchant.create(lines(), record.revision + 1) : null;
        core = await payments.newOrder(merchantOrder?.payment ?? { amountMinor: total(), payeeAccount: 'merchant:keyboard' });
        record.boundOrder = core.order;
      }
      if (core.order.orderId !== record.boundOrder.orderId || core.order.amountMinor !== total() || canonicalOrder(core.order.merchantOrder ?? null) !== canonicalOrder(record.boundOrder.merchantOrder ?? null)) fail('STORE_ORDER_CHANGED', '控制器订单与购物车不一致。');
      record.verification = null; record.receipt = null; delete record.ownerDecision; rotateControl();
      record.message = '商品订单已固定。请在右侧控制台逐步执行资格验证；未点击不会继续。';
      event('checkout.prepare', 'ready', '仅建立完整商品订单，尚未签发凭证、请求挑战、调用设备或提交验证。');
    } catch (error) {
      record.phase = 'cart'; record.error = { code: error.code, message: error.message }; record.message = error.message;
      record.verification = error.verificationTrace ?? null; event('checkout.verify', 'fail', error.code ?? error.message);
      await save(); throw error;
    }
    await save(); return state();
  }
  async function pay(body) {
    exact(body, ['orderId', 'revision']); revision(body.revision); noPendingPayment();
    if (!record.boundOrder || body.orderId !== record.boundOrder.orderId) fail('STORE_ORDER_CHANGED', '付款请求不属于当前订单。');
    if (record.phase === 'paid') return state(); // Identical retries return the original receipt.
    if (record.phase !== 'checkout') fail('STORE_NOT_QUALIFIED', '请先通过结算资格验证。');
    const core = await payments.state();
    if (core.order.orderId !== body.orderId || core.order.amountMinor !== total() || canonicalOrder(core.order.merchantOrder ?? null) !== canonicalOrder(record.boundOrder.merchantOrder ?? null)) fail('STORE_ORDER_CHANGED', '后端订单已变化。');
    const decision = record.ownerDecision;
    const approved = core.proposal?.status === 'APPROVED' ? core.proposal : decision;
    if (approved?.status !== 'APPROVED' || approved.id !== core.proposal?.id || !sameOrder(approved.payment, record.boundOrder) || Date.parse(approved.expiresAt) <= Date.now()) fail('OWNER_CONFIRMATION_REQUIRED', '需要用户明确确认当前订单。', 403);
    record.phase = 'paying'; record.message = '用户已确认本单。请在右侧控制台逐次同步授权、付款前核验、钱包签名和结算。'; delete record.error; rotateControl();
    event('payment.request', 'ready', '仅记录用户付款意愿；未同步授权、未签名、未提交结算。'); await save();
    return state();
  }
  async function observeOwnerDecision(proposal) {
    const core = await payments.state();
    if (record.phase !== 'checkout' || !record.boundOrder || proposal?.id !== core.proposal?.id || !sameOrder(proposal.payment, record.boundOrder) || !['APPROVED', 'REJECTED'].includes(proposal.status)) fail('STORE_OWNER_MISMATCH', '用户决定与当前商城订单不一致。');
    // This is called only with the independent Owner service's successful
    // response, never with browser-supplied approval claims.
    record.ownerDecision = { id: proposal.id, status: proposal.status, payment: proposal.payment, expiresAt: proposal.expiresAt };
    event('owner.decision', proposal.status.toLowerCase()); rotateControl(); await save();
  }
  async function manual(body) {
    exact(body, ['action', 'orderId', 'revision', 'attemptId', 'controlToken']); revision(body.revision);
    if (manualRunning) fail('STORE_BUSY', '已有控制台操作正在处理。');
    if (!record.boundOrder || body.orderId !== record.boundOrder.orderId) fail('STORE_ORDER_CHANGED', '控制台操作不属于当前订单。');
    const supplied = Buffer.from(typeof body.controlToken === 'string' ? body.controlToken : ''), expected = Buffer.from(controlToken);
    if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) fail('STORE_STALE_CONTROL', '该步骤已执行或状态已变化，请重新读取控制台后操作。');
    const core = await payments.state(), control = manualControl(core);
    if (body.attemptId !== (core.manual?.attemptId ?? null)) fail('DBAC_MANUAL_ATTEMPT_MISMATCH', '当前挑战已变化，请重新读取控制台。');
    if (body.action !== 'confirm-merchant' && !sameOrder(core.order, record.boundOrder)) fail('STORE_ORDER_CHANGED', '原控制器订单与商城订单不一致。');
    if (!control.availableActions.includes(body.action)) fail('STORE_MANUAL_STAGE', '当前步骤不允许此操作，请按控制台提供的操作逐步执行。');
    if (manualRunning) fail('STORE_BUSY', '已有控制台操作正在处理。');
    if (body.controlToken !== controlToken) fail('STORE_STALE_CONTROL', '该步骤已执行或状态已变化，请重新读取控制台后操作。');
    manualRunning = true; rotateControl();
    try {
      if (body.action === 'confirm-merchant') {
        if (merchant) await confirmMerchant();
        else { record.phase = 'paid'; record.message = '模拟支付成功，订单已完成。'; await save(); }
        return state();
      }
      const result = body.action === 'issue' ? await payments.issue() : await payments.manual({ mode: core.mode ?? 'bbs-bls', action: body.action, attemptId: body.attemptId });
      if (!sameOrder(result.order, record.boundOrder)) fail('STORE_ORDER_CHANGED', '单步结果与当前商城订单不一致。');
      const m = result.manual ?? {};
      if (body.action === 'verify' && m.verificationResult?.verificationTrace) record.verification = m.verificationResult.verificationTrace;
      if (body.action === 'sync-owner' && ['REJECTED', 'EXPIRED'].includes(result.proposal?.status)) {
        record.phase = 'verifying'; delete record.ownerDecision; record.message = '原授权已失效或被拒绝。请手动重新验证本单，仍不会付款。';
      } else if (body.action === 'submit-owner') {
        if (result.proposal?.status !== 'PENDING' || !sameOrder(result.proposal.payment, record.boundOrder)) fail('STORE_PROPOSAL_INVALID', '后端未返回当前订单的待确认授权申请。');
        record.phase = 'checkout'; record.message = '资格验证已完成。请在商城核对商品并明确批准本笔付款。';
      } else if (body.action === 'verify' && m.phase === 'settle') {
        const paymentResult = m.verificationResult?.paymentResult, receipt = paymentResult?.receipt;
        if (!m.settled || !['EXECUTED', 'ALREADY_PROCESSED'].includes(paymentResult?.outcome) || !sameOrder(Object.fromEntries(Object.keys(record.boundOrder).map(key => [key, receipt?.[key]])), record.boundOrder) || receipt?.transactionStatus !== 'success') fail('STORE_RECEIPT_INVALID', '未取得匹配当前商品订单的真实成功回执。');
        record.receipt = receipt; record.phase = 'confirming'; record.message = '付款回执已返回。请手动核对商家并确认本单；尚未自动确认。';
        event('payment.receipt', 'pass', receipt.transactionHash);
      } else record.message = `已完成：${actionLabels[body.action] ?? body.action}。下一步需再次点击。`;
      delete record.error; event(`manual.${body.action}`, 'complete'); await save(); return state(result);
    } catch (error) {
      const latest = await payments.state().catch(() => null);
      if (latest?.manual?.walletSigningUnconfirmed || body.action === 'verify' && core.manual?.phase === 'settle' && latest?.paymentPending || body.action === 'sync-owner' && latest?.manual?.walletSigned && ['REJECTED', 'EXPIRED'].includes(latest?.proposal?.status)) record.phase = 'unknown';
      else if (body.action === 'sync-owner' && ['REJECTED', 'EXPIRED'].includes(latest?.proposal?.status)) { record.phase = 'verifying'; delete record.ownerDecision; }
      record.error = { code: error.code ?? 'STORE_MANUAL_FAILED', message: error.message }; record.message = error.message;
      record.verification = error.verificationTrace ?? record.verification;
      event(`manual.${body.action}`, 'fail', error.code ?? error.message); await save(); throw error;
    } finally { manualRunning = false; }
  }
  async function reset(body) {
    exact(body, ['revision']); revision(body.revision); noPendingPayment();
    const core = await payments.state(); if (core.paymentPending) fail('STORE_PAYMENT_UNRESOLVED', '控制器仍有未确认的付款。');
    await payments.newOrder();
    record = { ...record, phase: 'cart', revision: record.revision + 1, cart: {}, boundOrder: null, receipt: null, verification: null, events: [], message: '可以开始新的购物。' };
    delete record.error; delete record.ownerDecision; rotateControl(); event('cart.new', 'ok'); await save(); return state();
  }
  async function security(body) {
    exact(body, ['action']); noPendingPayment();
    if (!['issue', 'revoke', 'lock', 'unlock'].includes(body.action)) fail('STORE_INPUT_INVALID', '不支持的演示操作。', 400);
    if (record.phase !== 'cart') fail('STORE_SECURITY_STATE', '请在购物车阶段演示凭证与设备状态。');
    if (body.action === 'issue') {
      await payments.newOrder({ amountMinor: total() || CATALOG[0].unitAmountMinor }); record.boundOrder = null; record.verification = null;
    }
    await payments.manage({ action: body.action });
    event(`security.${body.action}`, 'ok'); record.message = ({ issue: '凭证已重新签发。', revoke: '凭证已撤销，再次结算会被拒绝。', lock: '软件 eSIM 已锁定，再次结算会被拒绝。', unlock: '软件 eSIM 已解锁。' })[body.action];
    delete record.error; rotateControl(); await save(); return state();
  }
  async function confirmMerchant() {
    try {
      const confirmed = await merchant.confirm(record.boundOrder.orderId, record.receipt);
      record.receipt = confirmed.receipt; record.phase = 'paid'; delete record.error;
      record.message = 'Payment received. Your order is confirmed.';
      event('merchant.confirm', 'pass', confirmed.receipt.transactionHash);
    } catch (error) {
      record.phase = 'confirming'; record.error = { code: error.code ?? 'MERCHANT_ERROR', message: error.message };
      record.message = '付款已确认，商家订单待核对。查询原订单即可继续，不需要再次付款。';
      event('merchant.confirm', 'pending', error.code ?? error.message);
    }
    await save();
  }
  async function queryPayment(body) {
    exact(body, ['orderId', 'revision']); revision(body.revision);
    if (!record.boundOrder || body.orderId !== record.boundOrder.orderId || !['confirming', 'unknown', 'paid'].includes(record.phase)) fail('STORE_QUERY_STATE', '只能查询当前已付款或结果待核对的原订单。');
    const wasPaid = record.phase === 'paid';
    const result = await payments.queryPayment({ payment: record.boundOrder });
    if (result.status !== 'confirmed' || !result.receipt || result.receipt.transactionStatus !== 'success') {
      // A persisted unknown record can outlive the in-memory payment session
      // that created it. If the replacement session has a different order,
      // has no pending signature/settlement, and the authoritative query found
      // no receipt, the old checkpoint is orphaned. Release only that case;
      // an active session with the same order remains blocked for recovery.
      const current = await payments.state();
      const currentManual = current?.manual ?? {};
      const sameSessionOrder = current?.order?.orderId === record.boundOrder.orderId;
      const pending = Boolean(current?.paymentPending || currentManual.walletSigningUnconfirmed || currentManual.walletSigned && !currentManual.settled);
      if (!sameSessionOrder && !pending) {
        const oldOrderId = record.boundOrder.orderId;
        record.phase = 'cart'; record.boundOrder = null; record.receipt = null; record.verification = null;
        delete record.error; delete record.ownerDecision;
        record.message = '原订单未找到可核对的付款回执，已解除旧订单锁定；购物车商品已保留。';
        rotateControl(); event('payment.query', 'released', `未发现可核对的原订单回执，已释放旧订单 ${oldOrderId}。`); await save(); return state(current);
      }
      record.phase = 'unknown'; record.message = '原付款结果尚未确认，继续保留本单，不能再次付款或开始新单。';
      event('payment.query', 'unknown'); await save(); return state();
    }
    record.receipt = result.receipt; record.phase = merchant ? 'confirming' : 'paid';
    event('payment.query', 'pass', result.receipt.transactionHash); await save();
    record.message = wasPaid ? '原订单和商家确认已完成，已核对同一付款回执。' : merchant ? '已查询到原付款回执。请再手动核对商家并确认订单。' : '原付款回执已确认。请手动完成订单确认。';
    record.phase = wasPaid ? 'paid' : 'confirming'; rotateControl(); await save();
    return state();
  }
  async function experiment(body) {
    exact(body, ['scenario']); noPendingPayment();
    if (record.phase !== 'cart' || !['copied-vc', 'revoked'].includes(body.scenario)) fail('STORE_EXPERIMENT_STATE', '请在购物车阶段选择凭证复制或撤销实验。');
    const core = await payments.state();
    if (core.paymentPending) fail('STORE_PAYMENT_UNRESOLVED', '原付款结果尚未确认，不能执行实验。');
    const experimentalOrder = merchant ? await merchant.create([{ ...CATALOG[0], quantity: 1, amountMinor: CATALOG[0].unitAmountMinor }], 1) : null;
    const result = await payments.experiments({ scenarioId: body.scenario, ...(experimentalOrder ? { paymentOrder: experimentalOrder.payment } : {}) });
    const keys = ['id', 'scenarioId', 'scenario', 'kind', 'mode', 'startedAt', 'completedAt', 'durationMs', 'completion', 'expected', 'actual', 'expectationMet', 'requestRejected', 'authenticationIssued', 'rejectionStage', 'error', 'control', 'verificationTrace', 'sideEffects', 'attackerContext', 'revocation', 'accessChecks'];
    record.experiment = { ...Object.fromEntries(keys.filter(k => result[k] !== undefined).map(k => [k, result[k]])), scenario: body.scenario };
    event('security.experiment', result.expectationMet ? 'pass' : 'incomplete', result.actual);
    try { emit({ type: 'business', source: 'security-experiment', action: 'experiment', status: result.expectationMet ? 'complete' : 'fail', title: '凭证验证对照实验', orderId: experimentalOrder?.payment.orderId ?? null, phase: 'experiment', detail: `合法控制组 ${result.control?.accepted === true ? '通过' : '未通过'}；攻击分支实际返回 ${result.actual}。`, data: record.experiment }); } catch { /* Observers cannot modify outcomes. */ }
    await save(); return state();
  }
  async function fault(body) {
    exact(body, ['action']); noPendingPayment();
    if (!merchant || record.phase !== 'cart' || !['delay-merchant-once', 'clear'].includes(body.action)) fail('STORE_FAULT_STATE', '只能在购物车阶段设置商家确认故障。');
    const value = merchant.fault(body.action === 'delay-merchant-once');
    record.message = value.confirmationDelayOnce ? '下一笔付款后，商家确认将暂停一次；可查询原流水恢复。' : '商家确认故障已清除。';
    event('merchant.fault', 'ok', body.action); await save(); return state();
  }
  return { catalog: () => structuredClone(CATALOG), state, changeCart, checkout, pay, manual, observeOwnerDecision, reset, security, queryPayment, experiment, fault };
}
