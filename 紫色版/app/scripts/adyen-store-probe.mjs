import { mkdir, writeFile } from 'node:fs/promises';
import { MyStoreBrowser } from '../lib/adyen-shop/browser.mjs';

const browser = new MyStoreBrowser();
const dir = new URL('../var/adyen-probe/', import.meta.url);
await mkdir(dir, { recursive: true });
try {
  const { order, product } = await browser.quote();
  console.log(JSON.stringify({ stage: 'cart', product, order }));
  const session = await browser.openCheckout(order);
  order.providerReference = session.reference;
  console.log(JSON.stringify({ stage: 'checkout', session }));
  await writeFile(new URL('checkout.png', dir), await browser.screenshot());
  if (process.env.MYSTORE_TESTPAY === '1') {
    const result = await browser.pay(order, async () => console.log('Submitting one sandbox payment using the published Adyen test card.'));
    await writeFile(new URL('result.json', dir), JSON.stringify({ standaloneProviderProbe: true, order, result }, null, 2));
    await writeFile(new URL('result.png', dir), await browser.screenshot());
    console.log(JSON.stringify(result));
  }
} catch (error) {
  console.error(JSON.stringify({ code: error.code, message: error.message, errors: browser.publicErrors }));
  if (browser.page) {
    console.error((await browser.page.locator('body').innerText()).slice(0, 2200));
    for (const frame of browser.page.frames()) if (frame.url().startsWith('https://checkoutshopper-test.adyen.com/')) console.error(JSON.stringify(await frame.locator('input').evaluateAll(xs => xs.map(x => ({ name: x.name, field: x.getAttribute('data-fieldtype'), placeholder: x.placeholder })))));
    await writeFile(new URL('failure.png', dir), await browser.screenshot());
  }
  process.exitCode = 1;
} finally { await browser.close(); }
