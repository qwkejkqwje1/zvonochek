// ZVONochek Worker v12 — сигналинг (WebSocket + HTTP-поллинг + буфер рукопожатий) + выдача TURN/STUN.
// Worker пересылает только зашифрованные сообщения (AES-256-GCM) и не знает ключей комнат.

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store, no-cache, must-revalidate',
};

const json = (obj, status = 200, cors = {}) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { ...JSON_HEADERS, ...cors },
  });

// Защита квоты TURN от ботов (до 20 запросов в минуту с одного IP)
const turnRateLimit = new Map();
function checkTurnRateLimit(ip, limit = 20, windowMs = 60_000) {
  const now = Date.now();
  if (turnRateLimit.size > 5000) turnRateLimit.clear();
  const entry = turnRateLimit.get(ip);
  if (!entry || now > entry.resetAt) {
    turnRateLimit.set(ip, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= limit) return false;
  entry.count++;
  return true;
}

// Ограничение HTTP-поллинга/POST на комнату с одного IP (WS ограничен внутри Durable Object).
const roomRateLimit = new Map();
function checkRoomRateLimit(key, limit, windowMs = 10_000) {
  const now = Date.now();
  if (roomRateLimit.size > 8000) roomRateLimit.clear();
  const entry = roomRateLimit.get(key);
  if (!entry || now > entry.resetAt) {
    roomRateLimit.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= limit) return false;
  entry.count++;
  return true;
}

// Базовые STUN на случай, если внешние TURN API не настроены или недоступны
const FALLBACK_STUN = [
  {
    urls: [
      'stun:stun.cloudflare.com:3478',
      'stun:stun.l.google.com:19302',
      'stun:stun.relay.metered.ca:80',
    ],
  },
];

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = req.headers.get('Origin') || '';
    const allowed = (env.ALLOWED_ORIGINS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    // Разрешаем запросы без Origin (мобильные WebView / PWA) или из белого списка.
    // Никогда не отвечаем `*`: чужой Origin либо получает эхо своего адреса, либо ничего.
    const originOk = allowed.length === 0 || !origin || allowed.includes(origin);
    const cors =
      originOk && origin
        ? {
            'access-control-allow-origin': origin,
            'access-control-allow-methods': 'GET, POST, OPTIONS',
            'access-control-allow-headers': 'Content-Type, Authorization',
            'access-control-max-age': '86400',
            vary: 'Origin',
          }
        : {};

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: originOk ? 204 : 403, headers: cors });
    }

    if (url.pathname === '/' || url.pathname === '/health') {
      const hasTurn = !!(
        (env.TURN_KEY_ID && env.TURN_KEY_API_TOKEN) ||
        (env.METERED_DOMAIN && env.METERED_API_KEY) ||
        (env.TURN_URLS && env.TURN_USERNAME)
      );
      return json({ ok: true, app: 'ZVONochek', v: 12, turn: hasTurn, ts: Date.now() }, 200, cors);
    }

    if (!originOk) {
      return json({ error: 'origin not allowed' }, 403, cors);
    }

    // Поллинг и POST — самые дешёвые цели для флуда, ограничиваем их по IP.
    if (url.pathname.startsWith('/room/') && req.method !== 'GET' && req.method !== 'POST') {
      return json({ error: 'method not allowed' }, 405, cors);
    }
    if (
      url.pathname.startsWith('/room/') &&
      (req.method === 'POST' || req.method === 'GET') &&
      req.headers.get('Upgrade') !== 'websocket'
    ) {
      const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
      const room = url.pathname.split('/')[2] || '';
      const limit = req.method === 'POST' ? 90 : 40;
      if (!checkRoomRateLimit(`${ip}|${room}|${req.method}`, limit)) {
        return json({ error: 'rate limited' }, 429, cors);
      }
    }

    // 1) Выдача временных TURN-ключей (параллельный опрос с таймаутом 3.5 сек)
    if (url.pathname === '/turn') {
      const clientIp = req.headers.get('CF-Connecting-IP') || 'unknown';
      if (!checkTurnRateLimit(clientIp)) {
        return json({ iceServers: FALLBACK_STUN, rateLimited: true }, 200, cors);
      }

      const tasks = [];

      // Провайдер 1: Cloudflare Calls TURN
      if (env.TURN_KEY_ID && env.TURN_KEY_API_TOKEN) {
        tasks.push(
          fetch(
            `https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate-ice-servers`,
            {
              method: 'POST',
              headers: {
                authorization: `Bearer ${env.TURN_KEY_API_TOKEN}`,
                'content-type': 'application/json',
              },
              body: JSON.stringify({ ttl: 6 * 3600 }),
              signal: AbortSignal.timeout(3500),
            }
          ).then(async (r) => (r.ok ? (await r.json()).iceServers || [] : []))
        );
      }

      // Провайдер 2: Metered.ca TURN
      if (env.METERED_DOMAIN && env.METERED_API_TOKEN || (env.METERED_DOMAIN && env.METERED_API_KEY)) {
        const key = env.METERED_API_KEY || env.METERED_API_TOKEN;
        tasks.push(
          fetch(
            `https://${env.METERED_DOMAIN}/api/v1/turn/credentials?apiKey=${encodeURIComponent(key)}`,
            { signal: AbortSignal.timeout(3500) }
          ).then(async (r) => (r.ok ? await r.json() : []))
        );
      }

      const results = await Promise.allSettled(tasks);
      const list = [];

      for (const res of results) {
        if (res.status === 'fulfilled' && res.value) {
          list.push(...[].concat(res.value));
        }
      }

      // Провайдер 3: Свой TURN (coturn и др.) из переменных окружения
      if (env.TURN_URLS && env.TURN_USERNAME && env.TURN_CREDENTIAL) {
        list.push({
          urls: env.TURN_URLS.split(',').map((u) => u.trim()),
          username: env.TURN_USERNAME,
          credential: env.TURN_CREDENTIAL,
        });
      }

      // Убираем порт :53 и ставим turns: / :443 первыми для пробития жестких файрволов и ТСПУ
      const clean = list
        .filter((s) => s && s.urls)
        .map((s) => {
          const urls = []
            .concat(s.urls)
            .filter((u) => typeof u === 'string' && !/:53(\?|$)/.test(u))
            .sort((a, b) => {
              const score = (x) => (x.startsWith('turns:') ? 4 : 0) + (x.includes(':443') ? 2 : 0) + (x.includes('transport=tcp') ? 1 : 0);
              return score(b) - score(a);
            });
          return { ...s, urls };
        })
        .filter((s) => s.urls.length > 0);

      return json({ iceServers: clean }, 200, cors);
    }

    // 2) Комната сигналинга: поддержка WebSocket + HTTP GET поллинга + HTTP POST отправки/сброса
    const m = url.pathname.match(/^\/room\/([a-f0-9]{16,64})$/);
    if (m) {
      const stub = env.ROOMS.get(env.ROOMS.idFromName(m[1]));
      const res = await stub.fetch(req);
      if (res.status !== 101) {
        const headers = new Headers(res.headers);
        for (const [k, v] of Object.entries(cors)) headers.set(k, v);
        return new Response(res.body, { status: res.status, headers });
      }
      return res;
    }

    return json({ error: 'not found' }, 404, cors);
  },
};

// Durable Object комнаты: WebSocket Hibernation + Кольцевой буфер + HTTP-поллинг
export class Room {
  constructor(state) {
    this.state = state;
    this.state.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
    this.recentMessages = []; // { key, senderId, data, ts, fast }
    this.seenKeys = new Set();
  }

  prune() {
    const now = Date.now();
    // Обычные сигнальные пакеты храним 40 секунд (для реконнектов и опоздавших пиров),
    // а голосовые чанки (fast) — 10 секунд (для HTTP-поллинга)
    this.recentMessages = this.recentMessages
      .filter((item) => now - item.ts < (item.fast ? 10_000 : 40_000))
      .slice(-45);
    if (this.seenKeys.size > 600) {
      this.seenKeys = new Set(this.recentMessages.map((m) => m.key));
    }
  }

  recordMessage(senderId, raw) {
    if (typeof raw !== 'string' || raw.length === 0 || raw.length > 180_000) return false;
    this.prune();
    // Ключ дедупликации: первые 44 символа шифротекста (содержат случайный 96-битный IV и начало шифротекста)
    const key = raw.length > 48 ? raw.slice(0, 44) + ':' + raw.length : raw;
    if (this.seenKeys.has(key)) return false;
    this.seenKeys.add(key);

    // Если пакет крупный (> 12 КБ) — помечаем как быстрый (например, голосовой чанк или большой SDP)
    const fast = raw.length > 12_000;
    this.recentMessages.push({
      key,
      senderId: senderId || 'anon',
      data: raw,
      ts: Date.now(),
      fast,
    });
    return true;
  }

  broadcast(senderWs, msg, excludePeerId = null) {
    for (const s of this.state.getWebSockets()) {
      if (s === senderWs) continue;
      if (excludePeerId) {
        const meta = s.deserializeAttachment() || {};
        if (meta.peerId && meta.peerId === excludePeerId) continue;
      }
      try {
        s.send(msg);
      } catch {}
    }
  }

  async fetch(req) {
    const url = new URL(req.url);
    const peerId = url.searchParams.get('peer') || '';

    // А) HTTP POST — отправка пакета (резервный канал при блокировке WS + sendBeacon при закрытии вкладки)
    if (req.method === 'POST') {
      try {
        const body = await req.text();
        if (body && body.length <= 180_000) {
          const isNew = this.recordMessage(peerId, body);
          if (isNew) this.broadcast(null, body, peerId || null);
          return new Response(JSON.stringify({ ok: true, ts: Date.now() }), {
            status: 200,
            headers: JSON_HEADERS,
          });
        }
      } catch {}
      return new Response(JSON.stringify({ error: 'bad payload' }), {
        status: 400,
        headers: JSON_HEADERS,
      });
    }

    // Б) HTTP GET без заголовка Upgrade: websocket — режим HTTP-поллинга (обход блокировок WebSocket)
    if (req.headers.get('Upgrade') !== 'websocket') {
      if (req.method === 'GET') {
        this.prune();
        let since = Number(url.searchParams.get('since') || 0);
        // Часы клиента могут убежать вперёд — тогда since окажется в будущем и
        // поллинг навсегда вернёт пустоту. Подрезаем курсор по серверному времени.
        if (!Number.isFinite(since) || since < 0) since = 0;
        if (since > Date.now()) since = Date.now() - 40_000;
        const messages = this.recentMessages
          .filter((item) => item.ts > since && (!peerId || item.senderId !== peerId))
          .map((item) => ({ ts: item.ts, data: item.data }));

        return new Response(
          JSON.stringify({
            ok: true,
            now: Date.now(),
            peers: this.state.getWebSockets().length,
            messages,
          }),
          { status: 200, headers: JSON_HEADERS }
        );
      }
      return new Response(JSON.stringify({ error: 'expected websocket or GET/POST' }), {
        status: 426,
        headers: JSON_HEADERS,
      });
    }

    // В) Основной WebSocket-канал
    const sockets = this.state.getWebSockets();
    // При ротации сокетов (обход 16 КБ ТСПУ-лимита) в комнате могут временно висеть старые сокеты.
    // Вместо ошибки 429 мягко закрываем самый старый сокет, если их накопилось >= 12.
    if (sockets.length >= 12) {
      let oldestWs = sockets[0];
      let oldestTime = Infinity;
      for (const s of sockets) {
        const meta = s.deserializeAttachment() || { connectedAt: 0 };
        if (meta.connectedAt < oldestTime) {
          oldestTime = meta.connectedAt;
          oldestWs = s;
        }
      }
      try {
        oldestWs.close(4000, 'replaced');
      } catch {}
    }

    const [client, server] = Object.values(new WebSocketPair());
    const assignedPeer = peerId || crypto.randomUUID().slice(0, 12);

    this.state.acceptWebSocket(server);
    server.serializeAttachment({
      peerId: assignedPeer,
      connectedAt: Date.now(),
      msgCount: 0,
      windowStart: Date.now(),
    });

    // Если это первичное подключение (не тихая ротация сокета `_renew`), досылаем свежие пакеты из буфера
    const isRenew = url.searchParams.get('renew') === '1';
    if (!isRenew) {
      this.prune();
      for (const item of this.recentMessages) {
        if (!peerId || item.senderId !== peerId) {
          try {
            server.send(item.data);
          } catch {}
        }
      }
      // Уведомляем других участников, что в комнату зашел пир (позволяет мгновенно послать hello/offer)
      this.broadcast(
        server,
        JSON.stringify({ type: 'sys:peer_joined', peers: this.state.getWebSockets().length }),
        peerId || null
      );
    }

    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketMessage(ws, msg) {
    if (typeof msg !== 'string' || msg.length === 0 || msg.length > 180_000) return;

    const meta = ws.deserializeAttachment() || {
      peerId: 'anon',
      connectedAt: Date.now(),
      msgCount: 0,
      windowStart: Date.now(),
    };
    const now = Date.now();
    if (now - meta.windowStart > 5000) {
      meta.windowStart = now;
      meta.msgCount = 0;
    }
    meta.msgCount++;
    ws.serializeAttachment(meta);

    if (meta.msgCount > 120) {
      try {
        ws.close(1008, 'rate limit');
      } catch {}
      return;
    }

    const isNew = this.recordMessage(meta.peerId, msg);
    if (!isNew) return;

    this.broadcast(ws, msg, meta.peerId !== 'anon' ? meta.peerId : null);
  }

  webSocketClose(ws) {
    try {
      ws.close(1000, 'bye');
    } catch {}
  }

  webSocketError(ws) {
    try {
      ws.close(1011, 'error');
    } catch {}
  }
}
