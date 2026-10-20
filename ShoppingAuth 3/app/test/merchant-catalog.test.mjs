import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateIdentity, signJws } from '../lib/identity.mjs';
import { CATALOG, LEGACY_CATALOG } from '../lib/storefront/catalog.mjs';
import { validateMerchantOrder, merchantOrderHash, MERCHANT_ORDER_TYP } from '../lib/storefront/merchant-protocol.mjs';

function signedOrder(products) {
  const identity = generateIdentity('catalog test merchant'), createdAt = new Date().toISOString();
  const items = products.map(product => ({ productId: product.id, name: product.name, quantity: 1, unitAmountMinor: product.unitAmountMinor, amountMinor: product.unitAmountMinor }));
  const snapshot = { type: 'MyStoreOrderSnapshot', version: 1, merchantDid: identity.did, merchantId: 'mystore', orderId: `urn:uuid:${randomUUID()}`, orderVersion: 1, createdAt, validUntil: new Date(Date.now() + 60_000).toISOString(), payerAccount: 'demo:alice', payeeAccount: 'merchant:keyboard', currency: 'TEST_USDC', amountMinor: items.reduce((sum, item) => sum + item.amountMinor, 0), settlement: { network: 'eip155:31337', asset: `0x${'1'.repeat(40)}`, payTo: `0x${'2'.repeat(40)}`, payerAddress: `0x${'3'.repeat(40)}` }, items };
  const sign = changed => {
    changed.amountMinor = changed.items.reduce((sum, item) => sum + item.amountMinor, 0);
    const snapshotHash = merchantOrderHash(changed);
    return { snapshot: changed, snapshotHash, signature: signJws({ type: 'SignedMyStoreOrder', version: 1, iss: identity.did, snapshotHash, snapshot: changed }, identity, MERCHANT_ORDER_TYP) };
  };
  return { order: sign(snapshot), sign };
}

test('all official products are checked against exact merchant-signed name, amount and one-item limit', () => {
  const { order, sign } = signedOrder(CATALOG);
  assert.equal(validateMerchantOrder(order, undefined, { allowLegacy: false }).snapshot.amountMinor, 676_920_000);
  for (const change of [
    item => { item.name = 'Unlisted goods'; },
    item => { item.unitAmountMinor = 1; item.amountMinor = 1; },
    item => { item.quantity = 2; item.amountMinor *= 2; },
    item => { item.productId = '10'; },
  ]) {
    const snapshot = structuredClone(order.snapshot); change(snapshot.items[0]);
    assert.throws(() => validateMerchantOrder(sign(snapshot), undefined, { allowLegacy: false }), { code: 'MERCHANT_ORDER_INVALID' });
  }
});

test('legacy signed orders stay readable only at their old prices and cannot enter new merchant creation', () => {
  const { order, sign } = signedOrder(LEGACY_CATALOG);
  assert.equal(validateMerchantOrder(order).snapshot.amountMinor, 100_000_000);
  assert.throws(() => validateMerchantOrder(order, undefined, { allowLegacy: false }), { code: 'MERCHANT_ORDER_INVALID' });
  const changed = structuredClone(order.snapshot); changed.items[0].unitAmountMinor = CATALOG[1].unitAmountMinor; changed.items[0].amountMinor = changed.items[0].unitAmountMinor;
  assert.throws(() => validateMerchantOrder(sign(changed)), { code: 'MERCHANT_ORDER_INVALID' });
  const quantity = structuredClone(order.snapshot); quantity.items[0].quantity = 3; quantity.items[0].amountMinor *= 3;
  assert.equal(validateMerchantOrder(sign(quantity)).snapshot.items[0].quantity, 3);
  quantity.items[0].quantity = 4; quantity.items[0].amountMinor = quantity.items[0].unitAmountMinor * 4;
  assert.throws(() => validateMerchantOrder(sign(quantity)), { code: 'MERCHANT_ORDER_INVALID' });
});
