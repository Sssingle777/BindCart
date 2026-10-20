import { chromium } from 'playwright-core';
import { randomUUID } from 'node:crypto';
import { AppError } from '../protocol.mjs';
import { SHOP_ORIGIN, validateShopOrder } from './credentials.mjs';

const fail = (code, message) => { throw new AppError(code, message, 502); };
const minor = text => {
  const match = String(text).trim().match(/^€\s*(\d+)\.(\d{2})$/);
  if (!match) fail('SHOP_PRICE_FORMAT', '商城价格格式发生变化，停止付款。');
  return Number(match[1]) * 100 + Number(match[2]);
};

// Only drives the public demo as a shopper. No demo server secret, client key,
// private API, or intercepted session credential is reused by our backend.
export class MyStoreBrowser {
  constructor({ headless = true } = {}) {
    this.headless = headless;
    this.publicErrors = [];
    this.session = null;
    this.paymentAttempted = false;
    this.pendingObservations = new Set();
  }
  async launch() {
    try { this.browser = await chromium.launch({ channel: 'chrome', headless: this.headless }); }
    catch { this.browser = await chromium.launch({ channel: 'msedge', headless: this.headless }); }
    this.page = await this.browser.newPage({ viewport: { width: 1280, height: 950 }, locale: 'en-US' });
    this.page.setDefaultTimeout(15000);
    this.page.on('pageerror', error => { this.publicErrors.push(error.message.slice(0, 160)); this.publicErrors = this.publicErrors.slice(-8); });
    this.page.on('response', response => {
      const task = this.observe(response).catch(() => {}).finally(() => this.pendingObservations.delete(task));
      this.pendingObservations.add(task);
    });
  }
  async observe(response) {
    const url = new URL(response.url());
    if (url.origin === SHOP_ORIGIN && url.pathname === '/.netlify/functions/sessions' && response.ok()) {
      const data = await response.json();
      // Intentionally discard sessionData, shopper identity and all other fields.
      this.session = { id: data.id, reference: data.reference, amount: data.amount, observedAt: Date.now(), source: 'official-demo-network-response' };
    }
  }
  async quote() {
    if (!this.browser) await this.launch();
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await this.page.goto(SHOP_ORIGIN, { waitUntil: 'domcontentloaded', timeout: 30000 });
        await this.page.locator('a[href="#/product/02"]').waitFor();
        break;
      } catch (error) { if (attempt === 1) throw error; }
    }
    await this.page.locator('a[href="#/product/02"]').click();
    await this.page.locator('.product-detail__title').waitFor();
    const product = await this.page.locator('main').evaluate(main => ({
      name: main.querySelector('.product-detail__title')?.textContent?.trim(),
      price: main.querySelector('.product-detail__price')?.textContent?.trim(),
      image: main.querySelector('img[alt="Headphones"]')?.src,
    }));
    if (!product.price) {
      const bodyText = await this.page.locator('body').innerText();
      product.price = bodyText.match(/€\d+\.\d{2}/)?.[0];
    }
    if (product.name !== 'Headphones' || !product.image?.startsWith(`${SHOP_ORIGIN}/`)) fail('SHOP_PRODUCT_MISMATCH', '官方商城商品结构已变化。');
    const amountMinor = minor(product.price);
    await this.page.getByRole('button', { name: 'Add to cart', exact: true }).click();
    await this.page.locator('a[href="#/cart"]').click();
    await this.page.locator('.cart__price-amount').waitFor();
    const order = validateShopOrder({ id: `urn:uuid:${randomUUID()}`, provider: 'adyen-mystore', origin: SHOP_ORIGIN, productId: '02', productName: product.name, quantity: 1, amountMinor, currency: 'EUR', providerReference: null });
    await this.assertCart(order);
    return { order, product: { ...product, sourceUrl: `${SHOP_ORIGIN}/#/product/02` } };
  }
  async assertCart(order) {
    const rows = this.page.locator('.order-summary__list__list-item');
    if (await rows.count() !== 1 || (await rows.first().locator('.order-summary__list__list-item__title').innerText()).trim() !== order.productName || minor(await rows.first().locator('.order-summary__list__list-item__price').innerText()) !== order.amountMinor) fail('SHOP_CART_CHANGED', '官方购物车与已验证订单不一致。');
    const total = this.page.locator('.cart__price-amount, .order-summary__total-price, .order-summary__total__amount');
    if (await total.count()) {
      if (minor(await total.first().innerText()) !== order.amountMinor) fail('SHOP_TOTAL_CHANGED', '官方结算总额发生变化。');
    }
  }
  async openCheckout(order) {
    if (new URL(this.page.url()).hash !== '#/cart') {
      await this.page.locator('a[href="#/cart"]').first().click();
      await this.page.locator('.cart__price-amount').waitFor();
    }
    await this.assertCart(order);
    const started = Date.now();
    await this.page.getByRole('link', { name: 'Continue to Checkout', exact: true }).evaluate(el => el.click());
    await this.page.getByText('Cards', { exact: true }).waitFor({ timeout: 30000 });
    await Promise.allSettled([...this.pendingObservations]);
    if (!this.session || this.session.observedAt < started || this.session.amount?.currency !== order.currency || this.session.amount?.value !== order.amountMinor) fail('SHOP_SESSION_MISMATCH', '官方测试会话的金额、币种或创建时点不匹配。');
    await this.page.getByText('Cards', { exact: true }).click();
    await this.findCardField('encryptedCardNumber');
    await this.findCardField('encryptedExpiryDate');
    await this.findCardField('encryptedSecurityCode');
    await this.page.getByRole('button', { name: /^Pay €/ }).waitFor({ state: 'visible' });
    return structuredClone(this.session);
  }
  async findCardField(field) {
    const deadline = Date.now() + 15000;
    while (Date.now() < deadline) {
      for (const frame of this.page.frames()) {
        if (!frame.url().startsWith('https://checkoutshopper-test.adyen.com/')) continue;
        const input = frame.locator(`input[data-fieldtype="${field}"]`);
        if (await input.isVisible()) return input;
      }
      await new Promise(resolve => setTimeout(resolve, 150));
    }
    fail('SHOP_TEST_CARD_FORM_UNAVAILABLE', '没有加载出 Adyen 测试环境的银行卡输入框。');
  }
  async pay(order, beforeSubmit) {
    if (this.paymentAttempted) fail('SHOP_PAYMENT_ALREADY_ATTEMPTED', '本订单已经提交过测试付款，不能重复提交。');
    if (!this.session || order.providerReference !== this.session.reference || this.session.amount?.value !== order.amountMinor || this.session.amount?.currency !== order.currency) fail('SHOP_SESSION_MISMATCH', '测试会话与付款许可不符。');
    await this.assertCart(order);
    // Official Adyen sandbox Mastercard. There is no real-card entry path.
    await (await this.findCardField('encryptedCardNumber')).fill('5555341244441115');
    await (await this.findCardField('encryptedExpiryDate')).fill('0330');
    await (await this.findCardField('encryptedSecurityCode')).fill('737');
    const holder = this.page.locator('input[name="holderName"]');
    if (await holder.count()) await holder.fill('Demo Shopper');
    const submit = this.page.getByRole('button', { name: /^Pay €/ });
    await submit.waitFor();
    if (!(await submit.innerText()).includes((order.amountMinor / 100).toFixed(2))) fail('SHOP_BUTTON_AMOUNT_CHANGED', '付款按钮显示的金额与许可不符。');
    await beforeSubmit();
    this.paymentAttempted = true;
    const responsePromise = this.page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.origin === 'https://checkoutshopper-test.adyen.com' && url.pathname.includes(`/sessions/${this.session.id}/`) && url.pathname.endsWith('/payments') && response.request().method() === 'POST';
    }, { timeout: 30000 });
    // Register rejection immediately so a failed click cannot leave an unhandled wait.
    responsePromise.catch(() => {});
    await submit.click({ timeout: 10000 });
    const response = await responsePromise;
    const data = await response.json();
    const resultCode = data.resultCode;
    if (!response.ok() || typeof resultCode !== 'string') fail('SHOP_PAYMENT_OUTCOME_UNKNOWN', '已提交，但未取得明确的官方测试支付结果，请勿重复付款。');
    const result = { status: resultCode === 'Authorised' ? 'authorised' : 'not-authorised', resultCode, providerReference: this.session.reference, sessionId: this.session.id, ...(typeof data.pspReference === 'string' ? { pspReference: data.pspReference } : {}), amountMinor: order.amountMinor, currency: order.currency, testOnly: true, source: 'checkoutshopper-test.adyen.com network response', receivedAt: new Date().toISOString() };
    await this.page.locator('.adyen-checkout__dropin').waitFor({ state: 'hidden', timeout: 5000 }).catch(() => {});
    return result;
  }
  async screenshot() { return this.page.screenshot({ fullPage: true }); }
  async close() { await this.browser?.close(); this.browser = null; }
}
