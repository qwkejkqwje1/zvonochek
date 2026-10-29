// ZVONochek Worker — ChatRoom: Durable Object одной приватной чат-комнаты
// (мессенджер v21). Слепой релей: хранит только шифротекст фиксированного
// размера (blob 4124 байта), ключей комнаты и seed не знает и не получает.
// Авторизация — заголовок X-Access-Token; сервер хранит только SHA-256
// хэш токена (meta.access_token_hash), сам токен выводится клиентом из
// seed через HKDF и по сети ходит только в заголовках к своему Worker.
//
// Retention (выбор фазы 1, техплан §4): alarm раз в сутки удаляет сообщения,
// у которых ack старше 7 дней, и любые старше 30 дней (жёсткий потолок).
// Rate-limit: не более 60 сообщений в минуту на комнату.
//
// API (путь внутри DO — после /chat/<roomId>):
//   POST /init  {sub?}            — установить хэш токена (идемпотентно), push-подписка
//   POST /msg   {blob, dev}       — добавить сообщение → {seq} / {seq, dup:true}
//   GET  /fetch?after=<seq>       — пропущенные сообщения по возрастанию seq
//   POST /ack   {seqs:[…]}        — подтвердить доставку
//   WS   /listen                  — hibernation; auth первым сообщением {type:'auth', token}
import { sendPush, b64u } from './push.js';

const te = new TextEncoder();
const BLOB_BYTES = 4124; // nonce(12) + plaintext(4096) + тег GCM(16)
const RATE_PER_MIN = 60;
const ACK_RETENTION_MS = 7 * 24 * 3600_000;
const HARD_RETENTION_MS = 30 * 24 * 3600_000;
const MAX_SUBS = 16;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });

async function sha256hex(data) {
  const buf = typeof data === 'string' ? te.encode(data) : data;
  const h = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`);
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS messages (seq INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT UNIQUE, blob TEXT, ts INTEGER, acked_at INTEGER)`
    );
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS subs (endpoint TEXT PRIMARY KEY, device TEXT, p256dh TEXT, auth TEXT, created INTEGER)`
    );
    this.state.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  roomId(req) {
    const m = new URL(req.url).pathname.match(/^\/chat\/([a-f0-9]{64})/);
    return m ? m[1] : '';
  }
  subPath(req) {
    const m = new URL(req.url).pathname.match(/^\/chat\/[a-f0-9]{64}(\/.*)?$/);
    return m ? m[1] || '/' : '/';
  }
  one(q, ...p) {
    return this.sql.exec(q, ...p).toArray()[0] || null;
  }
  all(q, ...p) {
    return this.sql.exec(q, ...p).toArray();
  }
  meta(k) {
    return this.one(`SELECT v FROM meta WHERE k=?`, k)?.v || null;
  }
  setMeta(k, v) {
    this.sql.exec(`INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)`, k, v);
  }

  async tokenOk(req) {
    const stored = this.meta('access_token_hash');
    if (!stored) return false;
    const given = req.headers.get('x-access-token') || '';
    if (!given) return false;
    return (await sha256hex(given)) === stored;
  }

  broadcast(obj, exceptDevice = null) {
    const msg = JSON.stringify(obj);
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() || {};
      if (!att.authed) continue;
      if (exceptDevice && att.device === exceptDevice) continue;
      try {
        ws.send(msg);
      } catch {}
    }
  }

  async pushWake(exceptDevice = null) {
    const subs = this.all(`SELECT * FROM subs`).filter((s) => s.device !== exceptDevice);
    if (!subs.length) return;
    const room = this.meta('room_id') || '';
    for (let i = 0; i < subs.length; i += 6) {
      await Promise.all(
        subs.slice(i, i + 6).map(async (s) => {
          try {
            const r = await sendPush(
              this.env,
              { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
              { t: 'chat', room: room.slice(0, 16) },
              { ttl: 120, topic: ('chat' + room).slice(0, 32) }
            );
            if (r.status === 404 || r.status === 410) {
              this.sql.exec(`DELETE FROM subs WHERE endpoint=?`, s.endpoint);
            }
          } catch {}
        })
      );
    }
  }

  async ensureAlarm() {
    try {
      const cur = await this.state.storage.getAlarm();
      if (cur === null || cur === undefined) {
        await this.state.storage.setAlarm(Date.now() + 24 * 3600_000);
      }
    } catch {}
  }

  async fetch(req) {
    const roomId = this.roomId(req);
    if (!roomId) return json({ error: 'bad room' }, 400);
    if (!this.meta('room_id')) this.setMeta('room_id', roomId);
    const path = this.subPath(req);
    const url = new URL(req.url);
    await this.ensureAlarm();

    // ---------- WebSocket: живой канал комнаты (Hibernation API) ----------
    if (path === '/listen' && req.headers.get('Upgrade') === 'websocket') {
      const pair = new WebSocketPair();
      this.state.acceptWebSocket(pair[1]);
      pair[1].serializeAttachment({ authed: false, device: null });
      return new Response(null, { status: 101, webSocket: pair[0] });
    }

    let body = {};
    if (req.method === 'POST') {
      try {
        body = await req.json();
      } catch {
        return json({ error: 'bad json' }, 400);
      }
    }

    // ---------- Инициализация комнаты / проверка токена ----------
    if (path === '/init' && req.method === 'POST') {
      const given = req.headers.get('x-access-token') || '';
      if (!given) return json({ error: 'no token' }, 401);
      const hash = await sha256hex(given);
      const stored = this.meta('access_token_hash');
      if (!stored) {
        this.setMeta('access_token_hash', hash);
        this.setMeta('created', String(Date.now()));
      } else if (stored !== hash) {
        return json({ error: 'forbidden' }, 403);
      }
      const sub = body.sub;
      if (sub?.endpoint && sub?.keys?.p256dh && sub?.keys?.auth) {
        this.sql.exec(
          `INSERT INTO subs (endpoint, device, p256dh, auth, created) VALUES (?,?,?,?,?)
           ON CONFLICT(endpoint) DO UPDATE SET device=excluded.device, p256dh=excluded.p256dh, auth=excluded.auth`,
          String(sub.endpoint),
          String(body.dev || ''),
          String(sub.keys.p256dh),
          String(sub.keys.auth),
          Date.now()
        );
        const count = this.one(`SELECT COUNT(*) AS c FROM subs`).c;
        if (count > MAX_SUBS) {
          this.sql.exec(
            `DELETE FROM subs WHERE endpoint IN (SELECT endpoint FROM subs ORDER BY created ASC LIMIT ?)`,
            count - MAX_SUBS
          );
        }
      }
      const last = this.one(`SELECT MAX(seq) AS m FROM messages`);
      return json({ ok: true, lastSeq: last?.m || 0 });
    }

    // Все остальные эндпоинты — только с верным токеном.
    if (!(await this.tokenOk(req))) return json({ error: 'unauthorized' }, 401);

    // ---------- Новое сообщение ----------
    if (path === '/msg' && req.method === 'POST') {
      const { blob, dev } = body;
      if (typeof blob !== 'string') return json({ error: 'bad blob' }, 400);
      let raw;
      try {
        raw = b64u.dec(blob);
      } catch {
        return json({ error: 'bad blob' }, 400);
      }
      if (raw.length !== BLOB_BYTES) return json({ error: 'bad blob size' }, 400);
      const now = Date.now();
      const recent = this.one(
        `SELECT COUNT(*) AS c FROM messages WHERE ts>?`,
        now - 60_000
      ).c;
      if (recent >= RATE_PER_MIN) return json({ error: 'rate limited' }, 429);
      const hash = await sha256hex(raw);
      const existing = this.one(`SELECT seq FROM messages WHERE hash=?`, hash);
      if (existing) return json({ ok: true, seq: existing.seq, dup: true });
      this.sql.exec(
        `INSERT INTO messages (hash, blob, ts) VALUES (?,?,?)`,
        hash,
        blob,
        now
      );
      const row = this.one(`SELECT seq FROM messages WHERE hash=?`, hash);
      this.broadcast({ type: 'msg', seq: row.seq, blob, ts: now }, dev || null);
      this.state.waitUntil(this.pushWake(dev || null));
      return json({ ok: true, seq: row.seq }, 201);
    }

    // ---------- Докачка пропущенных ----------
    if (path === '/fetch' && req.method === 'GET') {
      let after = Number(url.searchParams.get('after') || 0);
      if (!Number.isFinite(after) || after < 0) after = 0;
      const rows = this.all(
        `SELECT seq, blob, ts FROM messages WHERE seq>? ORDER BY seq ASC LIMIT 500`,
        after
      );
      return json({ messages: rows, lastSeq: rows.length ? rows[rows.length - 1].seq : after });
    }

    // ---------- Подтверждения доставки ----------
    if (path === '/ack' && req.method === 'POST') {
      const seqs = Array.isArray(body.seqs) ? body.seqs.slice(0, 200) : [];
      const now = Date.now();
      for (const s of seqs) {
        this.sql.exec(
          `UPDATE messages SET acked_at=? WHERE seq=? AND acked_at IS NULL`,
          now,
          Number(s)
        );
      }
      return json({ ok: true });
    }

    return json({ error: 'not found' }, 404);
  }

  async alarm() {
    const now = Date.now();
    this.sql.exec(
      `DELETE FROM messages WHERE (acked_at IS NOT NULL AND acked_at<?) OR ts<?`,
      now - ACK_RETENTION_MS,
      now - HARD_RETENTION_MS
    );
    try {
      await this.state.storage.setAlarm(now + 24 * 3600_000);
    } catch {}
  }

  async webSocketMessage(ws, msg) {
    let m;
    try {
      m = JSON.parse(typeof msg === 'string' ? msg : new TextDecoder().decode(msg));
    } catch {
      return;
    }
    const att = ws.deserializeAttachment() || {};
    if (att.authed) return; // после auth клиент по WS ничего не шлёт
    if (m?.type !== 'auth' || !m.token) {
      try {
        ws.close(1008, 'auth required');
      } catch {}
      return;
    }
    const stored = this.meta('access_token_hash');
    if (!stored || (await sha256hex(String(m.token))) !== stored) {
      try {
        ws.close(1008, 'bad token');
      } catch {}
      return;
    }
    ws.serializeAttachment({ authed: true, device: m.dev || null });
    const last = this.one(`SELECT MAX(seq) AS m FROM messages`);
    try {
      ws.send(JSON.stringify({ type: 'ready', lastSeq: last?.m || 0 }));
    } catch {}
  }

  async webSocketClose(ws) {
    try {
      ws.close();
    } catch {}
  }
}
