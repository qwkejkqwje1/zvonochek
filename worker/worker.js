// ZVONochek Worker — способ связи №2 + выдача временных TURN-ключей.
// Worker пересылает только зашифрованные сообщения и не знает ключей комнат.
const json = (obj, status, cors) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...cors } });

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = req.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
    const originOk = allowed.length === 0 || allowed.includes(origin);
    const cors = originOk && origin ? { 'access-control-allow-origin': origin, vary: 'Origin' } : {};

    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...cors, 'access-control-allow-methods': 'GET', 'access-control-max-age': '86400' } });
    if (url.pathname === '/' || url.pathname === '/health')
      return json({ ok: true, app: 'ZVONochek', turn: !!(env.TURN_KEY_ID && env.TURN_KEY_API_TOKEN) }, 200, cors);
    if (!originOk) return json({ error: 'origin not allowed' }, 403, cors);

    if (url.pathname === '/turn') {
      if (!env.TURN_KEY_ID || !env.TURN_KEY_API_TOKEN) return json({ iceServers: [] }, 200, cors);
      const ttl = 6 * 3600; // ключи живут 6 часов
      const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`, {
        method: 'POST',
        headers: { authorization: `Bearer ${env.TURN_KEY_API_TOKEN}`, 'content-type': 'application/json' },
        body: JSON.stringify({ ttl }),
      });
      if (!r.ok) return json({ iceServers: [], error: 'turn ' + r.status }, 502, cors);
      const data = await r.json();
      let list = [].concat(data.iceServers || []);
      // Браузеры плохо работают с портом 53 — убираем такие адреса
      list = list.map((s) => ({ ...s, urls: [].concat(s.urls).filter((u) => !/:53(\?|$)/.test(u)) })).filter((s) => s.urls.length);
      return json({ iceServers: list }, 200, cors);
    }

    const m = url.pathname.match(/^\/room\/([a-f0-9]{32,64})$/);
    if (m) {
      if (req.headers.get('Upgrade') !== 'websocket') return json({ error: 'expected websocket' }, 426, cors);
      const stub = env.ROOMS.get(env.ROOMS.idFromName(m[1]));
      return stub.fetch(req);
    }
    return json({ error: 'not found' }, 404, cors);
  },
};

// Одна "комната" = один Durable Object. Сообщения пересылаются всем, кроме отправителя.
export class Room {
  constructor(state) {
    this.state = state;
    this.state.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }
  async fetch() {
    if (this.state.getWebSockets().length >= 8) return new Response('room is full', { status: 429 });
    const [client, server] = Object.values(new WebSocketPair());
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }
  webSocketMessage(ws, msg) {
    if (typeof msg !== 'string' || msg.length > 100000) return;
    for (const s of this.state.getWebSockets()) if (s !== ws) { try { s.send(msg); } catch {} }
  }
  webSocketClose(ws) { try { ws.close(1000, 'bye'); } catch {} }
  webSocketError(ws) { try { ws.close(1011, 'error'); } catch {} }
}
