// Cards, paths and arrowheads share measured CSS-pixel coordinates.
// Message buttons stay in a dedicated row below the diagram.
const mounted = new WeakMap();

function roundedPath(points) {
  const route = points.filter((point, index) => !index || point.some((value, axis) => value !== points[index - 1][axis]));
  let path = `M${route[0]}`;
  for (let index = 1; index < route.length - 1; index++) {
    const previous = route[index - 1], corner = route[index], next = route[index + 1];
    const before = Math.hypot(corner[0] - previous[0], corner[1] - previous[1]);
    const after = Math.hypot(next[0] - corner[0], next[1] - corner[1]);
    const radius = Math.min(9, before / 2, after / 2);
    const entry = corner.map((value, axis) => value + (previous[axis] - value) * radius / before);
    const exit = corner.map((value, axis) => value + (next[axis] - value) * radius / after);
    path += ` L${entry} Q${corner} ${exit}`;
  }
  return `${path} L${route.at(-1)}`;
}

function avoidCards(points, from, to, cards, width, height, paired) {
  const clear = route => route.slice(1).every((end, index) => {
    const start = route[index];
    return cards.every(rect => Math.max(start[0], end[0]) <= rect.left - 1 || Math.min(start[0], end[0]) >= rect.right + 1
      || Math.max(start[1], end[1]) <= rect.top - 1 || Math.min(start[1], end[1]) >= rect.bottom + 1);
  });
  if (clear(points)) return points;
  // A longer route can pass another role (for example an extra attacker below
  // the ledger). Try the outside gutters instead of drawing through a card.
  const left = Math.min(...cards.map(rect => rect.left)), right = Math.max(...cards.map(rect => rect.right));
  const top = Math.min(...cards.map(rect => rect.top)), bottom = Math.max(...cards.map(rect => rect.bottom));
  const x1 = (from.left + from.right) / 2, y1 = (from.top + from.bottom) / 2;
  const x2 = (to.left + to.right) / 2, y2 = (to.top + to.bottom) / 2;
  const side = Math.sign(x2 - x1 || y2 - y1) || 1, offset = paired ? side * 12 : 0;
  const candidates = [];
  for (const [edge, bound, limit] of [['left', left, 0], ['right', right, width], ['top', top, 0], ['bottom', bottom, height]]) {
    const outward = edge === 'left' || edge === 'top' ? -1 : 1;
    const margin = Math.abs(limit - bound), gap = Math.min(6, margin / 3);
    const lane = bound + outward * margin * 2 / 3 + (paired ? side * Math.min(3, margin / 8) : 0);
    if (edge === 'left' || edge === 'right') candidates.push([[from[edge] + outward * gap, y1 + offset], [lane, y1 + offset], [lane, y2 + offset], [to[edge] + outward * gap, y2 + offset]]);
    else candidates.push([[x1 + offset, from[edge] + outward * gap], [x1 + offset, lane], [x2 + offset, lane], [x2 + offset, to[edge] + outward * gap]]);
  }
  const length = route => route.slice(1).reduce((sum, point, index) => sum + Math.hypot(point[0] - route[index][0], point[1] - route[index][1]), 0);
  return candidates.filter(clear).sort((a, b) => length(a) - length(b))[0] || points;
}

function sceneWireRoute(from, to, paired, cards, width, height) {
  const x1 = (from.left + from.right) / 2, y1 = (from.top + from.bottom) / 2;
  const x2 = (to.left + to.right) / 2, y2 = (to.top + to.bottom) / 2;
  const dx = x2 - x1, dy = y2 - y1;
  const horizontalGap = Math.abs(dx) - (from.right - from.left + to.right - to.left) / 2;
  const verticalGap = Math.abs(dy) - (from.bottom - from.top + to.bottom - to.top) / 2;
  const horizontal = horizontalGap >= verticalGap;
  const gap = Math.min(6, Math.max(2, Math.max(horizontalGap, verticalGap) / 4));
  const direction = Math.sign(horizontal ? dx : dy) || 1;
  const offset = paired ? -direction * 12 : 0;
  const finish = points => roundedPath(avoidCards(points, from, to, cards, width, height, paired));
  if (horizontal) {
    const start = [direction > 0 ? from.right + gap : from.left - gap, y1 + offset];
    const end = [direction > 0 ? to.left - gap : to.right + gap, y2 + offset];
    if (Math.abs(dy) < 1) return finish([start, end]);
    const separation = paired ? direction * Math.min(9, Math.max(0, horizontalGap - gap * 2) / 5) : 0;
    const lane = (start[0] + end[0]) / 2 + separation;
    return finish([start, [lane, start[1]], [lane, end[1]], end]);
  }
  const start = [x1 - offset, direction > 0 ? from.bottom + gap : from.top - gap];
  const end = [x2 - offset, direction > 0 ? to.top - gap : to.bottom + gap];
  if (Math.abs(dx) < 1) return finish([start, end]);
  const separation = paired ? direction * Math.min(9, Math.max(0, verticalGap - gap * 2) / 5) : 0;
  const lane = (start[1] + end[1]) / 2 + separation;
  return finish([start, [start[0], lane], [end[0], lane], end]);
}

export function layoutSceneLabels(root) {
  const stage = root?.querySelector('.scene-stage');
  const previous = mounted.get(root);
  if (previous?.stage === stage) return;
  previous?.observer.disconnect();
  previous?.layer.remove();
  if (!stage) return;
  const svg = stage.querySelector('.scene-wires');
  if (!svg) return;
  const wires = [...svg.querySelectorAll('.scene-wire')];
  const layer = document.createElement('div');
  layer.className = 'scene-labels';
  layer.setAttribute('role', 'group');
  layer.setAttribute('aria-label', '本轮消息方向，点击查看公开证据');
  for (const wire of wires) {
    const box = wire.querySelector('foreignObject'), button = box?.querySelector('.scene-message');
    if (!button) continue;
    button.dataset.state = wire.dataset.state;
    button.dataset.from = wire.dataset.from;
    button.dataset.to = wire.dataset.to;
    layer.append(button);
    box.remove();
  }
  layer.hidden = !layer.childElementCount;
  stage.after(layer);
  function position() {
    const width = stage.clientWidth, height = stage.clientHeight;
    if (width <= 0 || height <= 0) return;
    const origin = stage.getBoundingClientRect();
    const cards = new Map([...stage.querySelectorAll('.scene-node')].map(node => {
      const rect = node.getBoundingClientRect();
      return [node.dataset.node, { left: rect.left - origin.left, right: rect.right - origin.left, top: rect.top - origin.top, bottom: rect.bottom - origin.top }];
    }));
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    const marker = svg.querySelector('marker');
    if (marker) {
      marker.setAttribute('markerUnits', 'userSpaceOnUse');
      marker.setAttribute('markerWidth', '8');
      marker.setAttribute('markerHeight', '8');
      marker.setAttribute('refX', '10');
    }
    for (const wire of wires) {
      const from = cards.get(wire.dataset.from), to = cards.get(wire.dataset.to);
      if (!from || !to) continue;
      const paired = wires.some(other => other !== wire && other.dataset.from === wire.dataset.to && other.dataset.to === wire.dataset.from);
      wire.querySelector('path').setAttribute('d', sceneWireRoute(from, to, paired, [...cards.values()], width, height));
    }
  }
  position();
  const observer = new ResizeObserver(position);
  observer.observe(stage);
  for (const card of stage.querySelectorAll('.scene-node')) observer.observe(card);
  mounted.set(root, { stage, observer, layer });
}
