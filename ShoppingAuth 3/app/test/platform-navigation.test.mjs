import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { views, availableViews, normalizeRoute, routeHash } from '../public/navigation-model.js';

test('retired workbench and duplicate payment bookmarks resolve to canonical destinations', () => {
  for (const view of ['dbac','advanced','payment','payment-detail','payment-advanced']) assert.deepEqual(normalizeRoute(view,'revoked'),{view:'guide',scenario:'revoked'});
  for (const view of ['payment-detail','payment-advanced']) assert.equal(routeHash({view,scenario:'copied-vc'}),'#view=guide&scenario=copied-vc');
  for (const view of ['__proto__','constructor','unknown',undefined]) assert.equal(normalizeRoute(view).view,'guide');
});
test('scenario history can restore each scenario without retaining access fragments', () => {
  for (const scenario of ['normal','copied-vc','revoked']) {
    const hash=routeHash({view:'guide',scenario,key:'access-fragment'});
    const params=new URLSearchParams(hash.slice(1));
    assert.deepEqual(normalizeRoute(params.get('view'),params.get('scenario')),{view:'guide',scenario});
    assert.equal(params.has('key'),false);
  }
  assert.equal(routeHash({view:'owner',scenario:'revoked'}),'#view=owner');
  assert.equal(normalizeRoute('guide','unknown').scenario,'normal');
});
test('auxiliary-only startup exposes mechanism diagnostics and no unavailable payment surfaces', () => {
  assert.deepEqual([...availableViews({dbacAvailable:true,namedAvailable:false,ownerAvailable:false})],['diagnostic']);
  const full=availableViews({dbacAvailable:true,namedAvailable:true,ownerAvailable:true});
  assert.equal(full.size,6);
  for(const retired of ['dbac','advanced','payment','payment-detail','payment-advanced'])assert.equal(full.has(retired),false);
});
test('the remaining navigation registry, shell panels and internal links have no orphaned payment-detail entry', async () => {
  const shell = await readFile(new URL('../public/demo.html', import.meta.url), 'utf8');
  const controls = [...shell.matchAll(/data-view="([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(new Set(controls), new Set(Object.keys(views)));
  for (const view of Object.keys(views)) {
    assert.ok(shell.includes(`id="panel-${view}"`), `${view} has its panel`);
    assert.ok(shell.includes(`id="frame-${view}"`), `${view} has its frame`);
  }
  for (const name of ['demo.html', 'guide.html', 'dbac.html']) {
    const html = name === 'demo.html' ? shell : await readFile(new URL(`../public/${name}`, import.meta.url), 'utf8');
    assert.doesNotMatch(html, /(?:data-(?:demo-)?view|id)="(?:payment-detail|(?:panel|frame)-payment-detail)"/);
    for (const [, view] of html.matchAll(/data-demo-view="([^"]+)"/g)) assert.ok(Object.hasOwn(views, view), `${name} links to active ${view}`);
  }
});
