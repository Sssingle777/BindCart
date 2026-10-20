import http from 'node:http';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createPublicClient, createWalletClient, defineChain, getAddress, http as rpcHttp, parseEther, publicActions, decodeEventLog, parseAbiItem } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { x402Client } from '@x402/core/client';
import { x402Facilitator } from '@x402/core/facilitator';
import { ExactEvmScheme as ExactEvmClient } from '@x402/evm/exact/client';
import { ExactEvmScheme as ExactEvmFacilitator } from '@x402/evm/exact/facilitator';
import { toFacilitatorEvmSigner } from '@x402/evm';
import { verifyCredential, verifyJws } from './identity.mjs';
import { PAYMENT_SCOPE, validatePayment, verifyPaymentAuthorization } from './payment.mjs';
import { DBAC_PAYMENT_PROFILE, verifyDbacPaymentAuthorization, verifyDbacPaymentEvidence, credentialBindingOf } from './dbac/payment-policy.mjs';

export const X402_VERSION = 2;
export const TEST_CURRENCY = 'TEST_USDC';
export const TEST_DECIMALS = 6;
const TOKEN_NAME = 'A2A Local Test USD';
const TOKEN_VERSION = '2';
const INITIAL_BALANCE = 1_000_000_000;
const MAX_TIMEOUT_SECONDS = 60;
const MERCHANTS = ['merchant:keyboard', 'merchant:other'];
const BODY_LIMIT = 96 * 1024;
const usedEvent = parseAbiItem('event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)');
const transferEvent = parseAbiItem('event Transfer(address indexed from, address indexed to, uint256 value)');
const hash = value => createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex');
const evidenceHash = value => createHash('sha256').update(value).digest('base64url');
const now = () => Math.floor(Date.now() / 1000);

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(item => canonical(item) ?? 'null').join(',')}]`;
  // Match JSON wire semantics: the official SDK can include optional undefined
  // fields that disappear during HTTP JSON serialization.
  if (value && typeof value === 'object') return `{${Object.keys(value).filter(k => value[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}

export class X402PaymentError extends Error {
  constructor(code, message, status = 400) { super(message); this.name = 'X402PaymentError'; this.code = code; this.status = status; }
}
const fail = (code, message, status = 400) => { throw new X402PaymentError(code, message, status); };
const clone = value => structuredClone(value);
const isTransactionHash = value => typeof value === 'string' && /^0x[0-9a-fA-F]{64}$/.test(value);
const firstTransactionHash = (...candidates) => candidates.find(isTransactionHash);
function settlementError(code, message, settlementResponse, transaction, status = 503) {
  const error = new X402PaymentError(code, message, status);
  if (settlementResponse && typeof settlementResponse === 'object' && !Array.isArray(settlementResponse)) error.settlementResponse = clone(settlementResponse);
  const knownTransaction = firstTransactionHash(settlementResponse?.transaction, transaction);
  if (isTransactionHash(knownTransaction)) error.transaction = error.transactionHash = knownTransaction;
  return error;
}

function safeFile(path) {
  if (existsSync(path)) {
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) fail('UNSAFE_X402_STORAGE', 'x402 状态必须存放在独立普通文件中。');
    chmodSync(path, 0o600);
  }
}

function privateJSON(path, create) {
  safeFile(path);
  if (!existsSync(path)) writeFileSync(path, JSON.stringify(create()), { mode: 0o600, flag: 'wx' });
  return JSON.parse(readFileSync(path, 'utf8'));
}

let compiled;
async function compileToken() {
  if (!compiled) compiled = (async () => {
    const { default: solc } = await import('solc');
    const source = readFileSync(fileURLToPath(new URL('../contracts/LocalTestUSDC.sol', import.meta.url)), 'utf8');
    const output = JSON.parse(solc.compile(JSON.stringify({
      language: 'Solidity', sources: { 'LocalTestUSDC.sol': { content: source } },
      settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: 'shanghai', outputSelection: { '*': { '*': ['abi', 'evm.bytecode.object'] } } },
    })));
    const errors = output.errors?.filter(e => e.severity === 'error') ?? [];
    if (errors.length) fail('TEST_TOKEN_COMPILATION_FAILED', errors.map(e => e.formattedMessage).join('\n'), 500);
    const artifact = output.contracts['LocalTestUSDC.sol'].LocalTestUSDC;
    return { abi: artifact.abi, bytecode: `0x${artifact.evm.bytecode.object}`, sourceHash: hash(source), compilerVersion: solc.version() };
  })();
  return compiled;
}

export function paymentSettlement(publicInfo, payeeAccount = 'merchant:keyboard') {
  const payTo = publicInfo?.payees?.[payeeAccount];
  if (!payTo) fail('X402_UNKNOWN_MERCHANT', '未知的本地测试代币收款方。');
  return { network: publicInfo.network, asset: publicInfo.asset, payTo, payerAddress: publicInfo.payerAddress };
}

function localPayment(publicInfo, payment) {
  const normalized = validatePayment(payment);
  if (normalized.currency !== TEST_CURRENCY) fail('X402_CURRENCY_REQUIRED', '在线 x402 只接受本地 TEST_USDC 测试代币。');
  const expected = paymentSettlement(publicInfo, normalized.payeeAccount);
  if (!normalized.settlement || Object.keys(expected).some(k => normalized.settlement[k] !== expected[k]) || Object.keys(normalized.settlement).length !== 4) {
    fail('X402_SETTLEMENT_MISMATCH', 'Owner 授权必须绑定本地测试链、代币、付款钱包和当前商户地址。', 403);
  }
  return normalized;
}

export function x402Requirements(publicInfo, payment, { resourceUrl = 'http://127.0.0.1/a2a' } = {}) {
  const p = localPayment(publicInfo, payment);
  return {
    x402Version: X402_VERSION,
    resource: { url: resourceUrl, description: `Local TEST_USDC payment for order ${p.orderId}`, mimeType: 'application/json' },
    accepts: [{
      scheme: 'exact', network: publicInfo.network, asset: publicInfo.asset,
      amount: String(p.amountMinor), payTo: publicInfo.payees[p.payeeAccount], maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
      extra: { name: TOKEN_NAME, version: TOKEN_VERSION, assetTransferMethod: 'eip3009' },
    }],
  };
}

function assertPayload(publicInfo, payment, payload) {
  const expected = x402Requirements(publicInfo, payment).accepts[0];
  if (!payload || payload.x402Version !== X402_VERSION || canonical(payload.accepted) !== canonical(expected) ||
      payload.payload?.authorization?.from?.toLowerCase() !== publicInfo.payerAddress.toLowerCase()) {
    fail('X402_PAYLOAD_MISMATCH', 'x402 payload 未对应本次授权的链、代币、金额、付款方或收款方。', 403);
  }
  return expected;
}

/**
 * Starts a loopback-only Ganache chain and an independently permissioned local
 * wallet/facilitator service. Wallet secrets stay in this closure/private file;
 * A receives only payerConfig and B receives only backendConfig.
 * The token and chain have NO real monetary value or production security claim.
 */
export async function createLocalX402Environment({
  stateDir = fileURLToPath(new URL('../var/x402', import.meta.url)), chainId = 31337, rpcPort = 0, port = 0,
  trustedIssuers, trustedAuthorizers, holderDid, deviceDid, verifierDid, isCredentialRevoked,
  dbacIssuerPublicKey, w3cIssuer, isDbacCredentialRevoked,
} = {}) {
  if (w3cIssuer !== undefined && (typeof w3cIssuer !== 'string' || w3cIssuer.length > 256 || !/^[a-z][a-z0-9+.-]*:\S+$/i.test(w3cIssuer))) fail('INVALID_X402_CONFIGURATION', 'W3C 签发方配置必须是非空绝对标识，不能回退旧凭证模式。');
  if (!Number.isSafeInteger(chainId) || chainId <= 0 || ![trustedIssuers, trustedAuthorizers].every(v => Array.isArray(v) || v instanceof Set) ||
      !holderDid || !deviceDid || !verifierDid || typeof isCredentialRevoked !== 'function' ||
      (dbacIssuerPublicKey !== undefined && (typeof dbacIssuerPublicKey !== 'string' || !/^[0-9a-f]{192}$/.test(dbacIssuerPublicKey)))) fail('INVALID_X402_CONFIGURATION', '本地 x402 环境需要明确的链 ID、可信身份、Owner 与可信凭证撤销查询。');
  const directory = resolve(stateDir);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail('UNSAFE_X402_STORAGE', 'x402 状态目录不可为符号链接。');
  chmodSync(directory, 0o700);
  const wallet = privateJSON(resolve(directory, 'wallets.json'), () => ({
    version: 1, chainId, payerKey: generatePrivateKey(), gasKey: generatePrivateKey(),
    payees: Object.fromEntries(MERCHANTS.map(id => [id, privateKeyToAccount(generatePrivateKey()).address])),
  }));
  if (wallet.version !== 1 || wallet.chainId !== chainId) fail('X402_CHAIN_CONFIGURATION_CHANGED', '已有钱包状态的 chainId 不匹配。');
  const payerAccount = privateKeyToAccount(wallet.payerKey);
  const gasAccount = privateKeyToAccount(wallet.gasKey);
  const { default: ganache } = await import('ganache');
  const chainServer = ganache.server({
    logging: { quiet: true },
    chain: { chainId, networkId: chainId, hardfork: 'shanghai' },
    database: { dbPath: resolve(directory, 'chain') },
    // Payer key is not installed in the RPC wallet. Even the fee account is
    // locked; transactions are signed locally by the facilitator signer.
    wallet: { accounts: [{ secretKey: wallet.gasKey, balance: `0x${parseEther('100').toString(16)}` }], locked: true },
  });
  let db, server, publicInfo;
  let tail = Promise.resolve();
  const serial = action => { const current = tail.then(action, action); tail = current.catch(() => {}); return current; };
  try {
    await chainServer.listen(rpcPort, '127.0.0.1');
    const rpcUrl = `http://127.0.0.1:${chainServer.address().port}`;
    const chain = defineChain({ id: chainId, name: 'A2A local test EVM', nativeCurrency: { name: 'Test Ether', symbol: 'TEST_ETH', decimals: 18 }, rpcUrls: { default: { http: [rpcUrl] } } });
    const reader = createPublicClient({ chain, transport: rpcHttp(rpcUrl), pollingInterval: 20 });
    const feeWallet = createWalletClient({ account: gasAccount, chain, transport: rpcHttp(rpcUrl), pollingInterval: 20 }).extend(publicActions);
    const artifact = await compileToken();
    const manifestPath = resolve(directory, 'token.json');
    safeFile(manifestPath);
    let manifest = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : null;
    if (manifest) {
      if (manifest.sourceHash !== artifact.sourceHash || manifest.chainId !== chainId || !await reader.getCode({ address: manifest.asset })) {
        fail('X402_CHAIN_STATE_MISMATCH', '测试代币源文件或链状态与持久化记录不一致，请选择独立状态目录。', 500);
      }
    } else {
      const tx = await feeWallet.deployContract({ abi: artifact.abi, bytecode: artifact.bytecode, args: [payerAccount.address, BigInt(INITIAL_BALANCE)] });
      const deployed = await reader.waitForTransactionReceipt({ hash: tx });
      if (deployed.status !== 'success' || !deployed.contractAddress) fail('TEST_TOKEN_DEPLOYMENT_FAILED', '测试代币合约部署未成功。', 500);
      manifest = { chainId, asset: getAddress(deployed.contractAddress), deploymentTransaction: tx, deploymentBlock: Number(deployed.blockNumber), sourceHash: artifact.sourceHash, compilerVersion: artifact.compilerVersion };
      writeFileSync(manifestPath, JSON.stringify(manifest), { mode: 0o600, flag: 'wx' });
    }
    publicInfo = Object.freeze({
      localTestOnly: true, mode: 'local-evm', chainId, network: `eip155:${chainId}`, rpcUrl,
      asset: manifest.asset.toLowerCase(), name: TOKEN_NAME, symbol: TEST_CURRENCY, currency: TEST_CURRENCY, decimals: TEST_DECIMALS,
      payerAddress: payerAccount.address.toLowerCase(), facilitatorAddress: gasAccount.address.toLowerCase(), payees: Object.fromEntries(Object.entries(wallet.payees).map(([id, address]) => [id, address.toLowerCase()])),
      initialBalanceMinor: INITIAL_BALANCE, faucet: 'constructor-only test mint', deploymentTransaction: manifest.deploymentTransaction,
      contractSourceHash: artifact.sourceHash, compilerVersion: artifact.compilerVersion,
    });
    const dbPath = resolve(directory, 'payments.sqlite');
    safeFile(dbPath);
    db = new DatabaseSync(dbPath);
    chmodSync(dbPath, 0o600);
    db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS x402_orders (
        order_id TEXT PRIMARY KEY, payment_json TEXT NOT NULL, payload_json TEXT NOT NULL,
        original_authorization_id TEXT NOT NULL, status TEXT NOT NULL, transaction_hash TEXT,
        receipt_json TEXT, created_at TEXT NOT NULL,
        security_profile TEXT NOT NULL DEFAULT 'identified', security_binding TEXT
      );
      CREATE TABLE IF NOT EXISTS x402_authorizations (
        authorization_id TEXT PRIMARY KEY, authorization_hash TEXT NOT NULL,
        order_id TEXT NOT NULL, payment_hash TEXT NOT NULL
      );`);
    // Existing orders retain their original identified security policy. Keep
    // all nonce, receipt, transaction and authorization rows unchanged.
    const orderColumns = new Set(db.prepare('PRAGMA table_info(x402_orders)').all().map(column => column.name));
    if (!orderColumns.has('security_profile')) db.exec("ALTER TABLE x402_orders ADD COLUMN security_profile TEXT NOT NULL DEFAULT 'identified'");
    if (!orderColumns.has('security_binding')) db.exec('ALTER TABLE x402_orders ADD COLUMN security_binding TEXT');
    const signer = toFacilitatorEvmSigner({
      address: gasAccount.address,
      getCode: args => reader.getCode(args),
      readContract: args => reader.readContract(args),
      verifyTypedData: args => reader.verifyTypedData(args),
      writeContract: args => feeWallet.writeContract(args),
      sendTransaction: args => feeWallet.sendTransaction(args),
      waitForTransactionReceipt: args => reader.waitForTransactionReceipt({ ...args, timeout: 15_000 }),
    });
    const facilitator = new x402Facilitator().register(publicInfo.network, new ExactEvmFacilitator(signer, { eip6492AllowedFactories: [] }));
    const payer = x402Client.fromConfig({
      schemes: [{ network: publicInfo.network, client: new ExactEvmClient(payerAccount) }],
      spendControls: { allowedAssets: [{ network: publicInfo.network, asset: publicInfo.asset, maxAmountPerPayment: String(INITIAL_BALANCE) }] },
    });
    function verifiedApproval(input) {
      const payment = localPayment(publicInfo, input.payment);
      if (input.profile === DBAC_PAYMENT_PROFILE) {
        if (!dbacIssuerPublicKey) fail('DBAC_PAYMENT_NOT_CONFIGURED', '钱包尚未配置可信 DBAC 支付签发方。', 403);
        const approval = verifyDbacPaymentAuthorization(input.authorization, { trustedAuthorizers, verifierDid, issuerPublicKey: dbacIssuerPublicKey, payment, ...(w3cIssuer ? { w3cIssuer } : {}) });
        return { approval, payment, profile: DBAC_PAYMENT_PROFILE };
      }
      if (input.profile !== undefined && input.profile !== 'identified') fail('X402_SECURITY_PROFILE_INVALID', '钱包不支持此支付验证类型。', 403);
      const credential = verifyCredential(input.credential, { trustedIssuers, subjectDid: holderDid, audience: verifierDid, scope: PAYMENT_SCOPE, requireDevice: true });
      if (credential.credentialSubject.deviceDid !== deviceDid) fail('X402_DEVICE_BINDING_MISMATCH', 'VC 指定设备不是当前付款设备。', 403);
      const approval = verifyPaymentAuthorization(input.authorization, { trustedAuthorizers, holderDid, deviceDid, verifierDid, credential: input.credential, payment });
      return { approval, payment, credential, profile: 'identified' };
    }
    // The caller pins this callback to B's authenticated status service. A
    // recent B attestation is evidence of a prior check, not current status.
    // Missing, unavailable, or ambiguous status must never enable signing.
    async function checkCredentialStatus(credentialId) {
      let revoked;
      try { revoked = await isCredentialRevoked(credentialId); }
      catch { fail('STATUS_UNAVAILABLE', '无法取得可信的最新凭证撤销状态；已停止钱包签名或结算。', 503); }
      if (typeof revoked !== 'boolean') fail('STATUS_UNAVAILABLE', '凭证撤销状态不是明确的布尔结果；已停止钱包签名或结算。', 503);
      if (revoked) fail('CREDENTIAL_REVOKED', '凭证已撤销，钱包拒绝生成或返回付款签名，并停止新的结算。', 403);
    }
    async function checkCurrentCredential(verified) {
      // DBAC discloses a public epoch, not a named credential ID. Its signed
      // current challenge and Owner expiry are checked after every await.
      if (verified.profile !== DBAC_PAYMENT_PROFILE) await checkCredentialStatus(verified.credential.id);
      else if (verified.approval.vcBindingId || isDbacCredentialRevoked) {
        if (typeof isDbacCredentialRevoked !== 'function') fail('W3C_STATUS_UNAVAILABLE', 'W3C 凭证付款必须配置最新可信状态查询。', 503);
        let revoked;
        try { revoked = await isDbacCredentialRevoked(verified.approval.vcBindingId); } catch { fail('W3C_STATUS_UNAVAILABLE', '无法确认本地签发方最新状态；停止钱包签名和新结算。', 503); }
        if (typeof revoked !== 'boolean') fail('W3C_STATUS_UNAVAILABLE', '凭证状态未知，停止执行。', 503);
        if (revoked) fail('W3C_CREDENTIAL_REVOKED', '凭证已撤销，停止签发付款载荷或新的结算。', 403);
      }
    }
    function verifiedGate(input, verified, phase) {
      if (verified.profile !== DBAC_PAYMENT_PROFILE) {
        if (phase === 'authorize') verifiedDeviceGate(input, verified.payment);
        return;
      }
      const evidence = input.responseEvidence ?? { proof: input.proof, rawRequest: input.rawRequest, rawResponse: input.rawResponse, context: input.context };
      const { gate } = verifyDbacPaymentEvidence(evidence, {
        verifierDid, issuerPublicKey: dbacIssuerPublicKey, phase, payment: verified.payment, authorization: input.authorization, credentialBinding: credentialBindingOf(verified.approval), ...(w3cIssuer ? { w3cIssuer } : {}),
        ...(phase === 'authorize' ? { paymentRequired: input.paymentRequired } : { payload: input.payload }),
      });
      if (gate.orderKey !== verified.approval.orderKey || gate.mode !== verified.approval.mode || gate.issuerPublicKey !== verified.approval.issuerPublicKey) {
        fail('PAYMENT_AUTHORIZATION_BINDING_MISMATCH', 'B 的 DBAC 验证门槛与 Owner 授权的订单公钥、方案或签发方不一致。', 403);
      }
    }
    function revalidate(input, phase) {
      const verified = verifiedApproval(input);
      verifiedGate(input, verified, phase);
      return verified;
    }
    function verifiedDeviceGate(input, payment) {
      const evidence = input.responseEvidence ?? input;
      if (![evidence.proof, evidence.rawRequest, evidence.rawResponse].every(value => typeof value === 'string' && value)) {
        fail('X402_DEVICE_ATTESTATION_REQUIRED', '付款钱包需要 B 首轮验证设备双签名后签发的原始响应证明。', 403);
      }
      let proof, request, response;
      try {
        proof = verifyJws(evidence.proof, { typ: 'a2a-did-response+jwt', purpose: 'authentication', expectedDid: verifierDid }).payload;
        request = JSON.parse(evidence.rawRequest); response = JSON.parse(evidence.rawResponse);
      } catch {
        fail('X402_DEVICE_ATTESTATION_INVALID', 'B 的设备验签响应证据无效。', 403);
      }
      const data = request?.params?.message?.parts?.[0]?.data;
      const task = response?.result;
      const metadata = task?.status?.message?.metadata;
      if (proof.iss !== verifierDid || proof.aud !== holderDid || proof.deviceDid !== deviceDid ||
          !Number.isSafeInteger(proof.iat) || !Number.isSafeInteger(proof.exp) || proof.iat > now() + 5 || proof.exp <= now() || proof.exp <= proof.iat || proof.exp - proof.iat > 60 ||
          !/^[A-Za-z0-9_-]{43}$/.test(proof.deviceProofHash ?? '') ||
          proof.requestHash !== evidenceHash(evidence.rawRequest) || proof.responseHash !== evidenceHash(evidence.rawResponse) ||
          request.jsonrpc !== '2.0' || request.method !== 'message/send' || request.params?.message?.parts?.length !== 1 || data?.scope !== PAYMENT_SCOPE ||
          data?.authorization !== input.authorization || canonical(validatePayment(data?.payment)) !== canonical(payment) ||
          response.jsonrpc !== '2.0' || response.id !== request.id || task?.kind !== 'task' || task.status?.state !== 'input-required' ||
          metadata?.['x402.payment.status'] !== 'payment-required' || canonical(metadata?.['x402.payment.required']) !== canonical(input.paymentRequired)) {
        fail('X402_DEVICE_ATTESTATION_MISMATCH', 'B 的设备验签回执未绑定本次 Owner 授权、订单与付款要求，或已过期。', 403);
      }
    }
    const findOrder = id => db.prepare('SELECT * FROM x402_orders WHERE order_id=?').get(id);
    function bindAuthorization(approval, token, payment, profile) {
      const existing = db.prepare('SELECT * FROM x402_authorizations WHERE authorization_id=?').get(approval.authorizationId);
      const signatureHash = hash(token), paymentHash = hash(payment);
      if (existing && (existing.authorization_hash !== signatureHash || existing.order_id !== payment.orderId || existing.payment_hash !== paymentHash)) {
        fail('AUTHORIZATION_REUSED', '此授权 ID 已绑定其他授权原文或支付条款。', 409);
      }
      const order = findOrder(payment.orderId);
      if (order && order.security_profile !== profile) fail('X402_SECURITY_PROFILE_MISMATCH', '此订单已绑定其他支付验证类型，不能在具名与 DBAC 流程间切换。', 409);
      if (order && order.payment_json !== canonical(payment)) fail('ORDER_TERMS_MISMATCH', '此订单已绑定不同的支付条款。', 409);
      if (order && profile === DBAC_PAYMENT_PROFILE && order.security_binding !== securityBinding(approval, profile)) fail('X402_ORDER_BINDING_MISMATCH', '本订单已绑定不同的 VC、设备绑定标识、方案、签发方或订单公钥。', 409);
      if (!existing) db.prepare('INSERT INTO x402_authorizations VALUES(?,?,?,?)').run(approval.authorizationId, signatureHash, payment.orderId, paymentHash);
      return order;
    }
    function securityBinding(approval, profile) {
      return profile === DBAC_PAYMENT_PROFILE ? canonical({ mode: approval.mode, issuerPublicKey: approval.issuerPublicKey, orderKey: approval.orderKey, ...credentialBindingOf(approval) }) : null;
    }
    async function createPayload(input) {
      const verified = revalidate(input, 'authorize');
      const { approval, payment, profile } = verified;
      const expected = x402Requirements(publicInfo, payment).accepts[0];
      if (input.paymentRequired?.x402Version !== X402_VERSION || input.paymentRequired.accepts?.length !== 1 || canonical(input.paymentRequired.accepts[0]) !== canonical(expected)) {
        fail('X402_REQUIREMENTS_MISMATCH', '付款要求与 Owner 批准的链、代币、金额或收款人不一致。', 403);
      }
      await checkCurrentCredential(verified);
      revalidate(input, 'authorize');
      const order = bindAuthorization(approval, input.authorization, payment, profile);
      if (order) {
        const cached = JSON.parse(order.payload_json);
        if (order.status !== 'SETTLED' && Number(cached.payload.authorization.validBefore) <= now() + 6 && !await recoverTransaction(cached)) {
          fail('X402_PAYLOAD_EXPIRED', '本订单的链上签名已过期，请创建新订单重新确认。', 409);
        }
        await checkCurrentCredential(verified);
        revalidate(input, 'authorize');
        return cached;
      }
      if (approval.exp < now() + MAX_TIMEOUT_SECONDS + 1) fail('PAYMENT_AUTHORIZATION_EXPIRED', 'Owner 授权剩余时间不足以生成本次链上签名，请重新确认。', 403);
      const payload = await payer.createPaymentPayload(input.paymentRequired);
      assertPayload(publicInfo, payment, payload);
      // Do not release a signature if revocation happened while the signer was
      // running. Previously released EIP-3009 payloads remain bearer payments
      // until their own expiry; this off-chain check cannot revoke those bytes.
      await checkCurrentCredential(verified);
      revalidate(input, 'authorize');
      db.prepare('INSERT INTO x402_orders (order_id,payment_json,payload_json,original_authorization_id,status,transaction_hash,receipt_json,created_at,security_profile,security_binding) VALUES(?,?,?,?,?,?,?,?,?,?)').run(payment.orderId, canonical(payment), canonical(payload), approval.authorizationId, 'SIGNED', null, null, new Date().toISOString(), profile, securityBinding(approval, profile));
      return payload;
    }
    async function verify(input) {
      const payment = localPayment(publicInfo, input.payment);
      const requirements = assertPayload(publicInfo, payment, input.payload);
      return facilitator.verify(input.payload, requirements);
    }
    const tokenBalance = address => reader.readContract({ address: publicInfo.asset, abi: artifact.abi, functionName: 'balanceOf', args: [address] });
    async function checkedReceipt(transactionHash, payment, authorizationId, payload) {
      const receipt = await reader.getTransactionReceipt({ hash: transactionHash });
      if (receipt.status !== 'success') fail('X402_SETTLEMENT_FAILED', '链上交易未执行成功。', 502);
      const matches = receipt.logs.filter(log => {
        if (log.address.toLowerCase() !== publicInfo.asset.toLowerCase()) return false;
        try {
          const event = decodeEventLog({ abi: [transferEvent], topics: log.topics, data: log.data });
          return event.args.from.toLowerCase() === publicInfo.payerAddress.toLowerCase() && event.args.to.toLowerCase() === publicInfo.payees[payment.payeeAccount].toLowerCase() && event.args.value === BigInt(payment.amountMinor);
        } catch { return false; }
      });
      if (matches.length !== 1) fail('X402_TRANSFER_EVENT_MISMATCH', '链上交易缺少唯一且金额、收款人匹配的 Transfer 事件。', 502);
      const consumed = await reader.readContract({ address: publicInfo.asset, abi: artifact.abi, functionName: 'authorizationState', args: [publicInfo.payerAddress, payload.payload.authorization.nonce] });
      if (!consumed) fail('X402_NONCE_NOT_CONSUMED', '链上授权 nonce 未消费。', 502);
      const [payerBalance, payeeBalance] = await Promise.all([tokenBalance(publicInfo.payerAddress), tokenBalance(publicInfo.payees[payment.payeeAccount])]);
      return {
        ...payment, receiptId: `x402:${transactionHash}`, authorizationId, transactionHash,
        network: publicInfo.network, asset: publicInfo.asset, payerAddress: publicInfo.payerAddress, payTo: publicInfo.payees[payment.payeeAccount],
        blockNumber: Number(receipt.blockNumber), blockHash: receipt.blockHash, transactionStatus: receipt.status,
        gasUsed: receipt.gasUsed.toString(), payerBalanceAfter: Number(payerBalance), payeeBalanceAfter: Number(payeeBalance),
        localTestOnly: true, executedAt: new Date().toISOString(),
      };
    }
    async function recoverTransaction(payload) {
      const nonce = payload.payload.authorization.nonce;
      const consumed = await reader.readContract({ address: publicInfo.asset, abi: artifact.abi, functionName: 'authorizationState', args: [publicInfo.payerAddress, nonce] });
      if (!consumed) return null;
      const logs = await reader.getLogs({ address: publicInfo.asset, event: usedEvent, args: { authorizer: publicInfo.payerAddress, nonce }, fromBlock: BigInt(manifest.deploymentBlock), toBlock: 'latest' });
      if (logs.length !== 1) fail('X402_RECOVERY_REQUIRED', '授权已在链上消费，但无法定位唯一交易；停止再次付款。', 503);
      return logs[0].transactionHash;
    }
    async function execute(input) {
      const verified = revalidate(input, 'settle');
      const { approval, payment, profile } = verified;
      const requirements = assertPayload(publicInfo, payment, input.payload);
      await checkCurrentCredential(verified);
      revalidate(input, 'settle');
      const order = bindAuthorization(approval, input.authorization, payment, profile);
      if (!order || order.payload_json !== canonical(input.payload)) fail('X402_UNAPPROVED_PAYLOAD', '付款签名没有与本地已批准订单绑定。', 403);
      if (order.receipt_json) {
        const settlementResponse = { success: true, transaction: order.transaction_hash, network: publicInfo.network, payer: publicInfo.payerAddress };
        return { outcome: 'ALREADY_PROCESSED', receipt: JSON.parse(order.receipt_json), x402: settlementResponse, settlementResponse };
      }
      // If the process died after broadcast and before SQLite commit, query the
      // token's consumed nonce and event to recover the ORIGINAL transaction.
      // Never create another signed nonce for the same order.
      let transactionHash = await recoverTransaction(input.payload);
      if (transactionHash) db.prepare('UPDATE x402_orders SET transaction_hash=? WHERE order_id=?').run(transactionHash, payment.orderId);
      // Validation can expire while querying the chain. A discovered transfer
      // is retained before returning an error, so a new gate can recover it.
      try { revalidate(input, 'settle'); }
      catch (error) {
        if (transactionHash) throw settlementError(error.code, `${error.message} 已发现原交易，请使用新的有效验证证据查询同一订单。`, undefined, transactionHash, error.status);
        throw error;
      }
      let settlement;
      const recovered = Boolean(transactionHash);
      if (!transactionHash) {
        const verification = await facilitator.verify(input.payload, requirements);
        revalidate(input, 'settle');
        if (!verification.isValid) fail('X402_VERIFICATION_FAILED', `官方 facilitator 验证拒绝：${verification.invalidReason ?? 'invalid payment'}`, 403);
        await checkCurrentCredential(verified);
        revalidate(input, 'settle');
        db.prepare("UPDATE x402_orders SET status='SETTLING' WHERE order_id=?").run(payment.orderId);
        try { settlement = await facilitator.settle(input.payload, requirements); }
        catch (error) {
          // A thrown transport/provider error does not prove that broadcast
          // failed. Preserve public evidence and leave the order recoverable.
          const pending = settlementError('X402_SETTLEMENT_PENDING', '结算结果尚未确认；交易可能已广播，请用同一订单查询，不表示资金已回滚。', error.settlementResponse, firstTransactionHash(error.transaction, error.transactionHash));
          if (pending.transaction) db.prepare('UPDATE x402_orders SET transaction_hash=? WHERE order_id=?').run(pending.transaction, payment.orderId);
          throw pending;
        }
        if (!settlement.success) {
          if (isTransactionHash(settlement.transaction)) db.prepare('UPDATE x402_orders SET transaction_hash=? WHERE order_id=?').run(settlement.transaction, payment.orderId);
          throw settlementError(settlement.errorReason === 'settlement_pending' ? 'X402_SETTLEMENT_PENDING' : 'X402_SETTLEMENT_FAILED', `官方 facilitator 结算未确认：${settlement.errorReason ?? 'unknown'}；未取得成功回执不表示资金已回滚。`, settlement);
        }
        transactionHash = settlement.transaction;
      }
      if (isTransactionHash(transactionHash)) db.prepare('UPDATE x402_orders SET transaction_hash=? WHERE order_id=?').run(transactionHash, payment.orderId);
      if (profile === DBAC_PAYMENT_PROFILE) {
        try { revalidate(input, 'settle'); }
        catch (error) { throw settlementError(error.code, `${error.message} 交易可能已经执行，请用新的有效证明查询同一订单；不表示资金已回滚。`, settlement, transactionHash, error.status); }
      }
      let receipt;
      try { receipt = await checkedReceipt(transactionHash, payment, order.original_authorization_id, input.payload); }
      catch (error) {
        throw settlementError(error.code ?? 'X402_SETTLEMENT_PENDING', '已取得交易引用，但结算回执尚未核验成功；请查询同一订单，不表示资金已回滚。', settlement, transactionHash);
      }
      const settlementResponse = settlement ?? { success: true, transaction: transactionHash, network: publicInfo.network, payer: publicInfo.payerAddress };
      receipt.settlementResponse = settlementResponse;
      db.prepare("UPDATE x402_orders SET status='SETTLED',transaction_hash=?,receipt_json=? WHERE order_id=?").run(transactionHash, JSON.stringify(receipt), payment.orderId);
      if (profile === DBAC_PAYMENT_PROFILE) {
        try { revalidate(input, 'settle'); }
        catch (error) { throw settlementError(error.code, `${error.message} 已核验并保存原交易回执，请用新的有效证明查询同一订单。`, settlementResponse, transactionHash, error.status); }
      }
      return { outcome: recovered ? 'ALREADY_PROCESSED' : 'EXECUTED', receipt, x402: settlementResponse, settlementResponse };
    }
    async function queryPayment(input) {
      const payment = localPayment(publicInfo, input.payment), order = findOrder(payment.orderId);
      if (!order) return { status: 'unknown', orderId: payment.orderId, receipt: null };
      if (order.payment_json !== canonical(payment)) fail('ORDER_TERMS_MISMATCH', '只能查询原订单的完整付款条款。', 409);
      if (order.receipt_json) {
        const stored = JSON.parse(order.receipt_json);
        // Independently re-read the original transaction and token events.
        const checked = await checkedReceipt(stored.transactionHash, payment, order.original_authorization_id, JSON.parse(order.payload_json));
        return { status: 'confirmed', orderId: payment.orderId, receipt: { ...checked, settlementResponse: stored.settlementResponse }, source: 'original-x402-chain-query' };
      }
      if (!order.payload_json) return { status: 'unknown', orderId: payment.orderId, receipt: null };
      const payload = JSON.parse(order.payload_json);
      const transactionHash = order.transaction_hash || await recoverTransaction(payload);
      if (!transactionHash) return { status: 'unknown', orderId: payment.orderId, receipt: null };
      const receipt = await checkedReceipt(transactionHash, payment, order.original_authorization_id, payload);
      receipt.settlementResponse = { success: true, transaction: transactionHash, network: publicInfo.network, payer: publicInfo.payerAddress };
      db.prepare("UPDATE x402_orders SET status='SETTLED',transaction_hash=?,receipt_json=? WHERE order_id=?").run(transactionHash, JSON.stringify(receipt), payment.orderId);
      return { status: 'confirmed', orderId: payment.orderId, receipt, source: 'original-x402-chain-query' };
    }
    async function snapshot() {
      const entries = [['demo:alice', publicInfo.payerAddress], ...Object.entries(publicInfo.payees)];
      const accounts = await Promise.all(entries.map(async ([id, address]) => ({ id, address, balanceMinor: Number(await tokenBalance(address)) })));
      const receipts = db.prepare('SELECT receipt_json FROM x402_orders WHERE receipt_json IS NOT NULL ORDER BY rowid').all().map(row => JSON.parse(row.receipt_json));
      return { currency: TEST_CURRENCY, decimals: TEST_DECIMALS, accounts, executionCount: receipts.length, receipts, chainInfo: clone(publicInfo) };
    }
    const payerToken = randomBytes(32).toString('base64url'), backendToken = randomBytes(32).toString('base64url');
    let baseUrl;
    function authorize(req, expected) {
      const given = Buffer.from(req.headers.authorization ?? ''), desired = Buffer.from(`Bearer ${expected}`);
      if (given.length !== desired.length || !timingSafeEqual(given, desired)) fail('X402_ACCESS_DENIED', '缺少此 x402 角色的专用调用权限。', 403);
    }
    const send = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(body)); };
    server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 20_000 }, async (req, res) => {
      try {
        if (req.headers.host !== new URL(baseUrl).host || req.headers.origin || (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'none')) fail('X402_LOCAL_REQUEST_REQUIRED', '此接口仅供本机服务进程调用。', 403);
        if (req.method === 'GET' && req.url === '/health') return send(res, 200, { ok: true, service: 'local-x402', ...publicInfo });
        if (req.method === 'GET' && req.url === '/snapshot') { authorize(req, backendToken); return send(res, 200, await snapshot()); }
        if (req.method === 'GET' && req.url === '/supported') { authorize(req, backendToken); return send(res, 200, await facilitator.getSupported()); }
        if (req.method !== 'POST' || !['/payer/sign', '/payer/query', '/verify', '/settle'].includes(req.url)) fail('NOT_FOUND', '接口不存在。', 404);
        authorize(req, req.url.startsWith('/payer/') ? payerToken : backendToken);
        if (!(req.headers['content-type'] ?? '').startsWith('application/json')) fail('INVALID_CONTENT_TYPE', '请求必须使用 application/json。', 415);
        let size = 0, raw = '';
        for await (const chunk of req) { size += chunk.length; if (size > BODY_LIMIT) fail('BODY_TOO_LARGE', '请求正文过大。', 413); raw += chunk; }
        let input; try { input = JSON.parse(raw); } catch { fail('INVALID_JSON', '请求不是有效 JSON。'); }
        if (!input || typeof input !== 'object' || Array.isArray(input)) fail('INVALID_JSON', '请求必须是 JSON 对象。');
        const result = await serial(() => req.url === '/payer/sign' ? createPayload(input) : req.url === '/payer/query' ? queryPayment(input) : req.url === '/verify' ? verify(input) : execute(input));
        send(res, 200, result);
      } catch (error) {
        send(res, error.status ?? 500, { error: {
          code: error.code ?? 'X402_INTERNAL_ERROR', message: error.code ? error.message : '本地 x402 服务处理失败。',
          ...(error.settlementResponse ? { settlementResponse: error.settlementResponse } : {}),
          ...(isTransactionHash(error.transaction) ? { transaction: error.transaction } : {}),
        } });
      }
    });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
    let closed = false;
    return {
      publicInfo: clone(publicInfo),
      payerConfig: { url: baseUrl, accessToken: payerToken, publicInfo: clone(publicInfo) },
      backendConfig: { url: baseUrl, accessToken: backendToken, publicInfo: clone(publicInfo) },
      paymentSettlement: payee => paymentSettlement(publicInfo, payee),
      requirements: (payment, options) => x402Requirements(publicInfo, payment, options),
      snapshot,
      async close() {
        if (closed) return; closed = true;
        server.closeAllConnections();
        await new Promise(resolve => server.close(resolve));
        await tail;
        db.close();
        await chainServer.close();
      },
    };
  } catch (error) {
    try { server?.closeAllConnections(); if (server?.listening) await new Promise(resolve => server.close(resolve)); } catch { /* preserve error */ }
    try { db?.close(); } catch { /* preserve error */ }
    try { await chainServer.close(); } catch { /* preserve error */ }
    throw error;
  }
}

function remote(config) {
  let url;
  try { url = new URL(config.url); } catch { fail('INVALID_X402_CONFIGURATION', 'x402 服务 URL 无效。'); }
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || url.username || url.password || typeof config.accessToken !== 'string' || !config.accessToken) fail('INVALID_X402_CONFIGURATION', '测试 x402 服务必须位于 127.0.0.1 且有专用访问令牌。');
  return async (path, body) => {
    let response, data;
    try {
      response = await fetch(new URL(path, url), { method: body === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${config.accessToken}`, 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(20_000), redirect: 'error' });
      data = await response.json();
    } catch (error) {
      if (path === '/settle') throw settlementError('X402_SETTLEMENT_PENDING', '结算响应未能确认；交易可能已广播，请查询同一订单，不表示资金已回滚。');
      throw error;
    }
    if (!response.ok) throw settlementError(data.error?.code ?? 'X402_REMOTE_ERROR', data.error?.message ?? 'x402 服务调用失败。', data.error?.settlementResponse, firstTransactionHash(data.error?.transaction, data.error?.transactionHash), response.status);
    return data;
  };
}

export function createX402Payer(config) {
  const call = remote(config);
  return { publicInfo: clone(config.publicInfo), createPayload: input => call('/payer/sign', input), queryPayment: input => call('/payer/query', input) };
}

export function createX402Backend(config) {
  const call = remote(config);
  return {
    publicInfo: clone(config.publicInfo),
    paymentSettlement: payee => paymentSettlement(config.publicInfo, payee),
    requirements: (payment, options) => x402Requirements(config.publicInfo, payment, options),
    verify: input => call('/verify', input),
    execute: input => call('/settle', input),
    settle: input => call('/settle', input),
    snapshot: () => call('/snapshot'),
    supported: () => call('/supported'),
  };
}
