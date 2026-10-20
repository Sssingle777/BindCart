// Navigation only chooses a view; it never runs a protocol action.
export const views = {
  guide: { title: '演示平台', description: '正常支付、复制冒用与凭证撤销', page: '/guide/normal.html' },
  manage: { title: '凭证与设备', description: '管理凭证状态与设备签名能力', page: '/workspace.html?module=manage' },
  attacks: { title: '安全实验', description: '构造请求、查看实际结果与验证依据', page: '/workspace.html?module=attacks' },
  owner: { title: '付款授权', description: '逐笔核对订单，明确批准或拒绝', page: '/owner/' },
  identity: { title: '基础 JWS 对照', description: '具名凭证与设备签名的独立对照流程', page: '/console.html' },
  diagnostic: { title: '机制诊断', description: '批量支付与论文机制辅助检查', page: '/dbac.html' },
};
export const scenarios = new Set(['normal', 'copied-vc', 'revoked']);
export function normalizeRoute(view, scenario) {
  const aliases = { dbac: 'guide', advanced: 'guide', payment: 'guide', 'payment-detail': 'guide', 'payment-advanced': 'guide' };
  const canonical = Object.hasOwn(aliases, view) ? aliases[view] : view;
  return { view: Object.hasOwn(views, canonical) ? canonical : 'guide', scenario: scenarios.has(scenario) ? scenario : 'normal' };
}
export function routeHash(route) {
  const value = normalizeRoute(route.view, route.scenario);
  return `#view=${value.view}${value.view === 'guide' ? `&scenario=${value.scenario}` : ''}`;
}
export function availableViews(health) {
  const full = health.dbacAvailable && health.namedAvailable;
  return new Set(Object.entries({ guide: full, manage: full, attacks: full, owner: health.ownerAvailable, identity: health.namedAvailable, diagnostic: health.dbacAvailable }).filter(([, enabled]) => enabled).map(([view]) => view));
}
