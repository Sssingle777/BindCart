import { views, scenarios, normalizeRoute, routeHash, availableViews } from './navigation-model.js';
const $ = id => document.getElementById(id);
const keyPattern = /^[A-Za-z0-9_-]{43}$/;
const storage = { get(key) { try { return sessionStorage.getItem(key) || ''; } catch { return ''; } }, set(key, value) { try { if (value) sessionStorage.setItem(key, value); else sessionStorage.removeItem(key); } catch {} } };
const entry = new URLSearchParams(location.hash.slice(1)), savedKey = storage.get('a2a-did-vc-ui-key');
let uiKey = keyPattern.test(entry.get('key') || '') ? entry.get('key') : savedKey;
let ownerKey = keyPattern.test(entry.get('ownerKey') || '') ? entry.get('ownerKey') : uiKey === savedKey ? storage.get('a2a-owner-ui-key') : '';
if (!keyPattern.test(uiKey)) uiKey = ''; if (!keyPattern.test(ownerKey)) ownerKey = '';
storage.set('a2a-did-vc-ui-key', uiKey); storage.set('a2a-owner-ui-key', ownerKey);
let route = normalizeRoute(entry.get('view'), entry.get('scenario')), available = new Set(), serviceLabel = '';
let pendingHistoryRoute = null, observedLocationHash = '';
const loaded = new Set(), busyFrames = new Set(), buttons = [...document.querySelectorAll('[data-view]')];
const scenarioButtons = [...scenarios].map(scenario => ({ scenario, button: $(`scenario-${scenario}`) }));
// This is a display preference only. It never participates in protocol planning,
// routing, capability storage or frame activation.
const presentationPreferenceKey = 'a2a-demo-display';
let presentationPreference = 'compact', navigationOpen = false;
try { if (localStorage.getItem(presentationPreferenceKey) === 'platform') presentationPreference = 'platform'; } catch {}
function applyPresentation() {
  const compact = presentationPreference === 'compact';
  document.body.dataset.presentation = compact ? 'compact' : 'platform';
  $('platform-navigation').hidden = compact && !navigationOpen;
  $('platform-tools-toggle').hidden = !compact;
  $('platform-tools-toggle').setAttribute('aria-expanded', String(compact && navigationOpen));
  $('presentation-toggle').hidden = false;
  $('presentation-toggle').textContent = compact ? '展开平台导航' : '收起平台导航';
  $('presentation-toggle').setAttribute('aria-pressed', String(compact));
  $('shell-scenarios').hidden = route.view !== 'guide';
  $('shell-module-context').hidden = route.view === 'guide';
  $('shell-module-title').textContent = views[route.view].title;
  updateOrientation();
}
function closeNavigation({ restoreFocus = false } = {}) {
  if (!navigationOpen) return;
  navigationOpen = false; applyPresentation();
  if (restoreFocus) $('platform-tools-toggle').focus();
}
$('presentation-toggle').addEventListener('click', () => {
  presentationPreference = presentationPreference === 'compact' ? 'platform' : 'compact';
  try { localStorage.setItem(presentationPreferenceKey, presentationPreference); } catch {}
  navigationOpen = false; applyPresentation();
});
$('platform-tools-toggle').addEventListener('click', () => {
  navigationOpen = !navigationOpen; applyPresentation();
  if (navigationOpen) $('platform-navigation').focus();
});
window.addEventListener('keydown', event => { if (event.key === 'Escape' && navigationOpen) { event.preventDefault(); closeNavigation({ restoreFocus: true }); } });
window.addEventListener('click', event => {
  if (navigationOpen && !$('platform-navigation').contains(event.target) && !$('platform-tools-toggle').contains(event.target)) closeNavigation();
});
applyPresentation();
history.replaceState(null, '', '/' + routeHash(route));
observedLocationHash = location.hash;
function updateControls() {
  for (const button of buttons) {
    const selected = button.dataset.view === route.view;
    button.disabled = busyFrames.size > 0 || !available.has(button.dataset.view);
    button.classList.toggle('selected', selected);
    if (button.getAttribute('role') === 'tab') { button.setAttribute('aria-selected', String(selected)); button.tabIndex = selected ? 0 : -1; }
    if (selected) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
  }
  if (!document.querySelector('.demo-tabs [aria-selected=true]')) $('tab-guide').tabIndex = 0;
  $('service-state').textContent = busyFrames.size ? '操作进行中' : serviceLabel;
  for (const { scenario, button } of scenarioButtons) {
    const selected = scenario === route.scenario;
    button.disabled = busyFrames.size > 0 || !available.has('guide');
    button.setAttribute('aria-pressed', String(selected));
    button.classList.toggle('selected', selected);
  }
}
function notifyFrame(view, activate = false) {
  const target = $(`frame-${view}`).contentWindow;
  if (view === 'guide') target.postMessage({ type: 'demo:guide-route', scenario: route.scenario, activate }, location.origin);
  else if (activate) target.postMessage({ type: 'demo:activate' }, location.origin);
}
function loadFrame(view) {
  const frame = $(`frame-${view}`);
  if (view === 'owner') { $('owner-access').hidden = Boolean(ownerKey); $('owner-access-workspace').hidden = Boolean(ownerKey); frame.hidden = !ownerKey; if (!ownerKey) return; }
  if (loaded.has(view)) { notifyFrame(view, true); return; }
  frame.addEventListener('load', () => { if (route.view === view) notifyFrame(view); });
  const page = view === 'guide' ? `/guide/${route.scenario}.html` : views[view].page;
  const key = view === 'owner' ? ownerKey : uiKey;
  frame.src = page + (key ? `#key=${key}` : ''); loaded.add(view);
}
function select(requested, scenario = route.scenario, { replace = false, fromHistory = false } = {}) {
  const next = normalizeRoute(requested, scenario);
  if (busyFrames.size || !available.size) {
    if (fromHistory) pendingHistoryRoute = routeHash(next) === routeHash(route) ? null : next;
    return;
  }
  if (!available.has(next.view)) next.view = available.has('guide') ? 'guide' : available.values().next().value;
  if (!next.view) return;
  pendingHistoryRoute = null;
  const previous = routeHash(route); route = next;
  for (const name of Object.keys(views)) $(`panel-${name}`).hidden = name !== route.view;
  $('workspace-location').textContent = views[route.view].title;
  $('workspace-description').textContent = views[route.view].description;
  document.title = `${views[route.view].title} · 智能体可信身份`;
  document.body.dataset.module = route.view;
  navigationOpen = false; applyPresentation();
  if ($('platform-navigation').hidden && document.activeElement && $('platform-navigation').contains(document.activeElement)) $('platform-tools-toggle').focus();
  updateControls();
  const hash = routeHash(route);
  if (!fromHistory) {
    if (replace || previous === hash) history.replaceState(null, '', '/' + hash); else history.pushState(null, '', '/' + hash);
    observedLocationHash = location.hash;
  }
  loadFrame(route.view);
  if (matchMedia('(max-width: 820px)').matches) document.querySelector('.platform-tools').open = false;
}
document.querySelector('.skip-link').addEventListener('click', event => { event.preventDefault(); $('demo-content').focus(); });
buttons.forEach(button => button.addEventListener('click', () => select(button.dataset.view)));
scenarioButtons.forEach(({ scenario, button }) => button.addEventListener('click', () => {
  if (route.view !== 'guide' || route.scenario !== scenario) select('guide', scenario);
}));
document.querySelector('.demo-tabs').addEventListener('keydown', event => {
  const tabs = [...document.querySelectorAll('.demo-tabs [data-view]')].filter(button => !button.disabled);
  let index = tabs.indexOf(document.activeElement); if (index < 0 || !tabs.length) return;
  if (['ArrowRight', 'ArrowDown'].includes(event.key)) index = (index + 1) % tabs.length;
  else if (['ArrowLeft', 'ArrowUp'].includes(event.key)) index = (index + tabs.length - 1) % tabs.length;
  else if (event.key === 'Home') index = 0; else if (event.key === 'End') index = tabs.length - 1; else return;
  event.preventDefault(); tabs[index].click(); tabs[index].focus();
});
function restoreLocation() {
  // One history traversal can emit both events. Keep the browser's destination
  // intact while an embedded request finishes, then apply only the latest route.
  const hash = location.hash;
  if (hash === observedLocationHash) return;
  observedLocationHash = hash;
  const entry = new URLSearchParams(hash.slice(1));
  select(entry.get('view'), entry.get('scenario'), { fromHistory: true });
}
function drainHistoryRoute() {
  if (busyFrames.size || !available.size || !pendingHistoryRoute) return;
  const next = pendingHistoryRoute; pendingHistoryRoute = null;
  select(next.view, next.scenario, { fromHistory: true });
}
window.addEventListener('popstate', restoreLocation);
window.addEventListener('hashchange', restoreLocation);
function updateOrientation() { document.querySelector('.demo-tabs').setAttribute('aria-orientation', presentationPreference === 'platform' && matchMedia('(max-width: 820px)').matches ? 'horizontal' : 'vertical'); }
window.addEventListener('resize', updateOrientation); updateOrientation();
window.addEventListener('message', event => {
  if (event.origin !== location.origin) return;
  const source = [...loaded].find(view => $(`frame-${view}`).contentWindow === event.source); if (!source) return;
  const data = event.data;
  if (data?.type === 'demo:busy') { if (data.busy) busyFrames.add(source); else busyFrames.delete(source); updateControls(); if (!data.busy) drainHistoryRoute(); }
  if (data?.type === 'demo:scenario-selected' && !pendingHistoryRoute && source === 'guide' && route.view === 'guide' && scenarios.has(data.scenario) && route.scenario !== data.scenario) {
    route = { view: 'guide', scenario: data.scenario }; history.pushState(null, '', '/' + routeHash(route));
    observedLocationHash = location.hash;
    updateControls();
  }
  if (data?.type === 'demo:navigate') select(data.view);
  if (data?.type === 'demo:changed') for (const view of loaded) if (view !== source) $(`frame-${view}`).contentWindow.postMessage({ type: 'demo:invalidate' }, location.origin);
  if (data?.type === 'demo:scroll' && source === route.view && Number.isFinite(data.top) && data.top >= 0) event.source.scrollTo({ top: data.top, behavior: 'smooth' });
});
$('owner-access').addEventListener('submit', async event => {
  event.preventDefault(); let candidate = $('owner-entry').value.trim();
  try { if (!keyPattern.test(candidate)) { const query = new URLSearchParams(new URL(candidate).hash.slice(1)); candidate = query.get('ownerKey') || query.get('key'); } } catch { candidate = ''; }
  if (!keyPattern.test(candidate || '')) { $('owner-access-feedback').textContent = '请粘贴本次启动终端中的 Owner 专用链接。'; return; }
  event.submitter.disabled = true;
  try {
    const response = await fetch('/owner/api/state', { headers: { 'X-Owner-UI-Key': candidate }, cache: 'no-store', signal: AbortSignal.timeout(12000) });
    if (!response.ok) throw new Error('用户授权访问权限未通过验证。');
    ownerKey = candidate; storage.set('a2a-owner-ui-key', ownerKey); $('owner-entry').value = ''; loadFrame('owner');
  } catch (error) { $('owner-access-feedback').textContent = error.message; } finally { event.submitter.disabled = false; }
});
(async () => { try {
  const response = await fetch('/api/health', { cache: 'no-store', signal: AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error('服务健康检查失败。'); const health = await response.json();
  if (typeof health.namedAvailable !== 'boolean') throw new Error('请重启服务到当前版本。');
  available = availableViews(health); serviceLabel = health.namedAvailable && health.dbacAvailable ? '本地服务已连接' : '辅助模式';
  $('service-state').className = 'service-state connected';
  for (const button of buttons) if (!available.has(button.dataset.view)) button.title = '完整演示请使用 npm start 启动';
  if (!uiKey) { $('entry-notice').hidden = false; $('entry-notice').textContent = '请使用启动终端中的统一演示链接载入本次会话权限。'; }
  if (pendingHistoryRoute) drainHistoryRoute(); else select(route.view, route.scenario, { replace: true });
} catch (error) { $('service-state').textContent = '连接未完成'; $('service-state').className = 'service-state failed'; $('entry-notice').hidden = false; $('entry-notice').textContent = error.message + ' 请确认服务已启动，然后刷新。'; } })();
