export function observeSystem({ key, onSnapshot, onEvent = () => {}, onConnection = () => {} }) {
  let stopped = false, cursor = 0, controller, retry;
  async function connect() {
    if (stopped || !key) return;
    controller = new AbortController();
    try {
      const response = await fetch(`/api/live/events?after=${cursor}`, { headers: { 'X-Demo-UI-Key': key, Accept: 'text/event-stream' }, signal: controller.signal });
      if (!response.ok || !response.body) throw new Error('观察连接未建立');
      const reader = response.body.getReader(), decoder = new TextDecoder(); let buffer = '';
      onConnection(true);
      while (!stopped) {
        const { value, done } = await reader.read(); if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let end;
        while ((end = buffer.indexOf('\n\n')) !== -1) {
          const packet = buffer.slice(0, end); buffer = buffer.slice(end + 2);
          const type = packet.split('\n').find(row => row.startsWith('event:'))?.slice(6).trim();
          const body = packet.split('\n').filter(row => row.startsWith('data:')).map(row => row.slice(5).trimStart()).join('\n');
          if (!body) continue;
          const data = JSON.parse(body);
          if (type === 'system' && data.seq > cursor) { cursor = data.seq; onEvent(data); }
          if (type === 'snapshot') { cursor = Math.max(cursor, data.sequence ?? 0); onSnapshot(data); }
        }
      }
    } catch (error) { if (stopped) return; }
    if (!stopped) { onConnection(false); retry = setTimeout(connect, 1500); }
  }
  void connect();
  const stop = () => { stopped = true; clearTimeout(retry); controller?.abort(); };
  window.addEventListener('pagehide', stop, { once: true });
  return stop;
}
