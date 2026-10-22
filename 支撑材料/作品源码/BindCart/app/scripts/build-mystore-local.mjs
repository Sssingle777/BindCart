import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import vm from 'node:vm';

const sourceUrl = new URL('../third-party/mystore-web/main.bundle.js', import.meta.url);
const source = await readFile(sourceUrl, 'utf8');
const catalogMatch = source.match(/const b=(\[\{id:"01"[\s\S]*?\]);var g=/);
if (!catalogMatch) throw new Error('Official product catalog anchor changed');
const catalog = vm.runInNewContext(catalogMatch[1], Object.create(null), { timeout: 1000 });
const names = ['Polo 衫', '耳机', '太阳镜', '短靴', '活动门票', '双肩背包', '游戏手柄', '外卖餐盒', '手提包'];
const descriptions = [
  '适合各种场合的经典 Polo 衫。打高尔夫时搭配卡其裤，聚会时竖起衣领，让 Polo 衫展现你的个性。',
  '出色音质、获奖降噪技术与流线型设计。别被价格迷惑，这是一款出色的耳机。',
  '冲浪、沙滩与太阳镜，夏日的理想搭配。这款飞行员太阳镜可以保护双眼免受紫外线伤害，也让你看起来更酷。',
  '高于脚踝的短靴，让你不必再穿总会从脚跟滑落的隐形袜。我们认为它防水，欢迎告诉我们你的使用体验。',
  '一张活动门票，日期是 5 月 10 日或 10 月 5 日，取决于你习惯的日期写法。一个座位，仅此一晚，不予退款。',
  '无论叫背包还是行囊，它都是徒步者和学生喜爱的携物方式。我们认为它防水，欢迎告诉我们你的使用体验。',
  '你可能需要它来搭配现有游戏机，也可能只是想假装自己有一台游戏机。买下它，收获快乐。',
  '就像暑假前学校食堂的菜单，这份特价餐盒的内容充满惊喜。好消息是，我们会把它送到你的门口。',
  '如虎鲸的背鳍、如油面、如黑洞，也像带口袋的夜色。这是一款神秘的深黑色手提包。',
];
const translations = {
  'My Store': 'MyStore 商城', 'Shopping cart': '购物车', 'Recommendations': '猜你喜欢',
  'Product added to your cart': '商品已加入购物车', 'Add to cart': '加入购物车', 'Or': '或', 'Buy instantly': '立即购买',
  'Remove product': '删除商品', 'Trash bin': '删除', 'Cart': '购物车', 'Total:': '合计：',
  'Continue to Checkout': '前往结算', 'Your cart is empty.': '购物车是空的。', 'Return Home': '返回首页',
  'Checkout': '结算', 'Select your payment method': '选择付款方式', 'Shopper Email': '买家邮箱', 'Order summary': '订单详情',
  'Your order has been successfully placed.': '订单已成功提交。', 'Oops! Something went wrong. Please try again.': '操作未成功，请重试。',
  'Success icon': '成功', 'Thank you': '谢谢惠顾', 'Error icon': '错误', 'Product Detail': '商品详情',
  'I want to have ': '我希望使用 ', ' as a payment method option': ' 付款', 'Your Click to Pay email address': 'Click to Pay 邮箱地址',
  'Invalid email address.': '邮箱地址无效。', 'Flag icon': '国旗', 'Dropdown caret': '展开', 'rating star': '评分',
  'Australia': '澳大利亚', 'Austria': '奥地利', 'Belgium': '比利时', 'Brazil': '巴西', 'Canada': '加拿大', 'China': '中国',
  'Czech Republic': '捷克', 'Denmark': '丹麦', 'Finland': '芬兰', 'France': '法国', 'Greece': '希腊', 'Germany': '德国',
  'Hong Kong': '中国香港', 'India': '印度', 'Indonesia': '印度尼西亚', 'Italy': '意大利', 'Japan': '日本', 'Kenya': '肯尼亚',
  'Malaysia': '马来西亚', 'Mexico': '墨西哥', 'Netherlands': '荷兰', 'Norway': '挪威', 'New Zealand': '新西兰', 'Philippines': '菲律宾',
  'Poland': '波兰', 'Portugal': '葡萄牙', 'Russia': '俄罗斯', 'Singapore': '新加坡', 'South Korea': '韩国', 'Spain': '西班牙',
  'Sweden': '瑞典', 'Switzerland': '瑞士', 'Thailand': '泰国', 'United Arab Emirates': '阿联酋', 'United Kingdom': '英国',
  'United States': '美国', 'Vietnam': '越南',
};
catalog.forEach((product, index) => { translations[product.name] = names[index]; translations[product.description] = descriptions[index]; });
let local = source;
const translationChanges = [];
for (const [from, to] of Object.entries(translations)) {
  const search = JSON.stringify(from), replacement = JSON.stringify(to), occurrences = local.split(search).length - 1;
  if (!occurrences) throw new Error(`Official translation anchor changed: ${from}`);
  local = local.replaceAll(search, replacement); translationChanges.push({ from, to, occurrences });
}
const patches = [];
function replaceOnce(name, from, to) {
  if (local.split(from).length !== 2) throw new Error(`Official integration anchor changed: ${name}`);
  local = local.replace(from, to); patches.push({ name, from, to });
}
replaceOnce('controller-hook', 'const qr=zr;window.version=',
  'const qr=zr;window.MyStoreLocal.mount({store:qr,catalog:b,payment:or,localisation:Ar});window.version=');
replaceOnce('local-country-flags', '"https://ca-test.adyen.com/ca/adl/img/flags/"', '"/store/mystore/flags/"');
// Account-backed redirect recovery cannot authorize a local controller order.
// Reload/resume always reads /api/store/state instead of invoking Adyen SDK.
replaceOnce('disable-psp-query-redirect-recovery', 'function(t){j.apply(this,arguments)}(this.props)', 'void 0');
// Click to Pay and its shopper email belong to the remote PSP, whose session is
// not used here. Remove only those existing render slots, leaving CSS intact.
replaceOnce('remove-psp-click-to-pay-cart-widget', '(0,n.h)(Ue,null),', '');
replaceOnce('remove-unconsumed-psp-shopper-email',
  'o.email&&(0,n.h)("div",null,(0,n.h)("h3",{className:"checkout__order-summary__title"},"买家邮箱"),(0,n.h)("div",{className:"checkout__order-summary__shopper-email"},o.email)),', '');
// Preserve the official express slot and its original button style; the local
// payment controller replaces the account-backed PayPal SDK implementation.
const expressStart = local.indexOf('const Ee=(0,o.N)('), expressEnd = local.indexOf(';const Ne=', expressStart);
if (expressStart < 0 || expressEnd < 0) throw new Error('Official express component anchor changed');
const expressBefore = local.slice(expressStart, expressEnd);
const expressAfter = 'const Ee=(0,o.N)(["settings"],v)((function(t){return(0,n.h)("div",{id:"paypal-express"},(0,n.h)("button",{type:"button",className:"button local-express-button",onClick:function(){window.MyStoreLocal.express(t.product)}},"立即购买"))}))';
local = local.slice(0, expressStart) + expressAfter + local.slice(expressEnd);
patches.push({ name: 'express-controller-slot', from: expressBefore, to: expressAfter });
await writeFile(new URL('../public/store/mystore/main.local.bundle.js', import.meta.url), local);
await writeFile(new URL('../public/store/mystore-localization.json', import.meta.url), JSON.stringify(translations, null, 2) + '\n');
await writeFile(new URL('../public/store/mystore-integration-manifest.json', import.meta.url), JSON.stringify({
  source: 'https://www.mystoredemo.io/', sourceSha256: createHash('sha256').update(source).digest('hex'),
  outputSha256: createHash('sha256').update(local).digest('hex'), upstreamStylesModified: false,
  translations: translationChanges, patches,
}, null, 2) + '\n');
process.stdout.write(`Built complete MyStore: ${catalog.length} official products, ${translationChanges.length} text translations, ${patches.length} integration patches; original styles unchanged.\n`);
