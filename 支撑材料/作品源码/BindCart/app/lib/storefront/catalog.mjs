// MyStore's public catalog uses integer euro cents. The local demonstration
// settles the same displayed numeric amount with six-decimal TEST_USDC.
// Product names and image identifiers are taken from the preserved public build.
const product = (id, name, title, cents, image) => Object.freeze({
  id, name, title, image: `/store/mystore/${image}`,
  unitAmountMinor: cents * 10_000, currency: 'TEST_USDC', maxQuantity: 1,
});

export const CATALOG = Object.freeze([
  product('01', 'Polo shirt', 'Polo 衫', 2499, '1689f3f40b292d1de2c6.png'),
  product('02', 'Headphones', '耳机', 1999, 'a7504eee284c774d0a73.png'),
  product('03', 'Sunglasses', '太阳镜', 1499, 'ff0e4b0191980be4a839.png'),
  product('04', 'Boots', '短靴', 3599, '6966d3ad4f0f644d236b.png'),
  product('05', 'Event ticket', '活动门票', 200, '2d5aa9e22be92846d23e.png'),
  product('06', 'Backpack', '双肩背包', 3599, '8db885d088ed05f4a2c1.png'),
  product('07', 'Joypad', '游戏手柄', 2399, '6df62995d39927d21ba1.png'),
  product('08', 'Food delivery', '外卖餐盒', 1899, '74a7fcc9408bb3887c31.png'),
  product('09', 'Handbag', '手提包', 49999, '6ad4988f7468c17c268e.png'),
]);

// Old signed orders and receipts remain readable at their original prices.
// These products are never exposed in the active catalog or accepted as new cart input.
export const LEGACY_CATALOG = Object.freeze([
  Object.freeze({ id: 'headphones', name: 'Headphones', title: '头戴式耳机', image: '/store/images/headphones.png', unitAmountMinor: 50_000_000, currency: 'TEST_USDC', maxQuantity: 3, legacy: true }),
  Object.freeze({ id: 'sunglasses', name: 'Sunglasses', title: '经典太阳镜', image: '/store/images/sunglasses.png', unitAmountMinor: 50_000_000, currency: 'TEST_USDC', maxQuantity: 3, legacy: true }),
]);
export const ALL_CATALOG = Object.freeze([...CATALOG, ...LEGACY_CATALOG]);
export const catalogProduct = id => ALL_CATALOG.find(entry => entry.id === id);
