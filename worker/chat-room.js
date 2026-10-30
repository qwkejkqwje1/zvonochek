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
//   POST /ack   {seqs:[…], dev?, read?} — подтвердить доставку/прочтение (v25)
//   GET  /state                   — сводка v25: members_state + online (presence)
//   POST /file  {fileId, idx, total, blob} — чанк зашифрованного файла (v25)
//   GET  /file?fileId=&idx=       — отдать чанк файла (v25)
//   WS   /listen                  — hibernation; auth первым сообщением {type:'auth', token, dev}
//
// v25: сервер по-прежнему слеп к содержимому, но теперь видит МЕТАДАННЫЕ,
// которых у v21 не было: кто из устройств онлайн (presence по факту WS-подключений),
// до какого seq каждый участник дочитал (members_state) и размер файлов
// (число чанков file_chunks). Это осознанный компромисс ради «прочитано»,
// «онлайн» и файлов — зафиксирован в AUDIT-v25.
import { sendPush, b64u } from './push.js';

const te = new TextEncoder();
const BLOB_BYTES = 4124; // nonce(12) + plaintext(4096) + тег GCM(16)
const RATE_PER_MIN = 60;
const ACK_RETENTION_MS = 7 * 24 * 3600_000;
const HARD_RETENTION_MS = 30 * 24 * 3600_000;
const MAX_SUBS = 16;
// v25: файлы чанками (клиент режет по 256 КиБ открытого текста; шифротекст
// чанка ~256 КиБ + nonce/тег → base64 укладывается в лимит ниже).
const FILE_MAX_BLOB_B64 = 512 * 1024;
const FILE_MAX_CHUNKS = 40; // 40 × 256 КиБ = 10 МиБ — лимит файла на клиенте
const FILE_RATE_PER_MIN = 600;

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
    // v25: состояние чтения по устройствам (только номера seq, не содержимое)
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS members_state (dev TEXT PRIMARY KEY, delivered_seq INTEGER, read_seq INTEGER, updated INTEGER)`
    );
    // v25: чанки зашифрованных файлов; содержимое — шифротекст файловым ключом,
    // ключ живёт только внутри зашифрованного сообщения-метаданных комнаты.
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS file_chunks (file_id TEXT, idx INTEGER, blob TEXT, ts INTEGER, PRIMARY KEY (file_id, idx))`
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

  // v25: presence выводится из живых WS-сокетов (Hibernation: состояние не
  // храним в памяти DO, а пересчитываем из getWebSockets() + attachments —
  // после гибернации список восстанавливается сам).
  onlineDevices() {
    const out = new Set();
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() || {};
      if (att.authed && att.device) out.add(att.device);
    }
    return [...out];
  }

  broadcastPresence(dev, online) {
    if (!dev) return;
    this.broadcast({ type: 'presence', dev, online, ts: Date.now() }, dev);
  }

  memberStateRows() {
    return this.all(
      `SELECT dev, delivered_seq, read_seq, updated FROM members_state ORDER BY dev ASC`
    ).map((r) => ({
      dev: r.dev,
      delivered: r.delivered_seq || 0,
      read: r.read_seq || 0,
      updated: r.updated || 0,
    }));
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

    // ---------- Подтверждения доставки / прочтения ----------
    if (path === '/ack' && req.method === 'POST') {
      const seqs = Array.isArray(body.seqs) ? body.seqs.slice(0, 200) : [];
      const now = Date.now();
      let maxSeq = 0;
      for (const s of seqs) {
        const n = Number(s);
        if (!Number.isFinite(n) || n <= 0) continue;
        if (n > maxSeq) maxSeq = n;
        this.sql.exec(
          `UPDATE messages SET acked_at=? WHERE seq=? AND acked_at IS NULL`,
          now,
          n
        );
      }
      // v25: состояние чтения устройства — монотонные максимумы delivered/read.
      // Клиент v21 шлёт ack без dev — тогда ведём себя как раньше (только retention).
      const dev = typeof body.dev === 'string' && body.dev ? body.dev.slice(0, 128) : null;
      if (dev && maxSeq > 0) {
        const prev =
          this.one(`SELECT delivered_seq, read_seq FROM members_state WHERE dev=?`, dev) || {};
        const delivered = Math.max(prev.delivered_seq || 0, maxSeq);
        const read = body.read === true ? Math.max(prev.read_seq || 0, maxSeq) : prev.read_seq || 0;
        this.sql.exec(
          `INSERT OR REPLACE INTO members_state (dev, delivered_seq, read_seq, updated) VALUES (?,?,?,?)`,
          dev,
          delivered,
          read,
          now
        );
        this.broadcast({ type: 'receipt', dev, delivered, read }, dev);
      }
      return json({ ok: true });
    }

    // ---------- v25: сводка состояния комнаты (receipts + presence) ----------
    if (path === '/state' && req.method === 'GET') {
      return json({ members: this.memberStateRows(), online: this.onlineDevices() });
    }

    // ---------- v25: чанки зашифрованных файлов ----------
    if (path === '/file' && req.method === 'POST') {
      const { fileId, idx, total, blob } = body;
      if (typeof fileId !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(fileId)) {
        return json({ error: 'bad fileId' }, 400);
      }
      const nIdx = Number(idx);
      const nTotal = Number(total);
      if (!Number.isInteger(nIdx) || !Number.isInteger(nTotal) || nTotal < 1 || nTotal > FILE_MAX_CHUNKS || nIdx < 0 || nIdx >= nTotal) {
        return json({ error: 'bad chunk index' }, 400);
      }
      if (typeof blob !== 'string' || blob.length === 0 || blob.length > FILE_MAX_BLOB_B64) {
        return json({ error: 'bad chunk size' }, 400);
      }
      let raw;
      try {
        raw = b64u.dec(blob);
      } catch {
        return json({ error: 'bad blob' }, 400);
      }
      if (raw.length === 0 || raw.length > 384 * 1024) return json({ error: 'bad chunk size' }, 400);
      const now = Date.now();
      const recent = this.one(`SELECT COUNT(*) AS c FROM file_chunks WHERE ts>?`, now - 60_000).c;
      if (recent >= FILE_RATE_PER_MIN) return json({ error: 'rate limited' }, 429);
      this.sql.exec(
        `INSERT OR REPLACE INTO file_chunks (file_id, idx, blob, ts) VALUES (?,?,?,?)`,
        fileId,
        nIdx,
        blob,
        now
      );
      return json({ ok: true, idx: nIdx }, 201);
    }
    if (path === '/file' && req.method === 'GET') {
      const fileId = url.searchParams.get('fileId') || '';
      const idx = Number(url.searchParams.get('idx'));
      if (!/^[A-Za-z0-9_-]{8,64}$/.test(fileId) || !Number.isInteger(idx) || idx < 0) {
        return json({ error: 'bad params' }, 400);
      }
      const row = this.one(`SELECT blob FROM file_chunks WHERE file_id=? AND idx=?`, fileId, idx);
      if (!row) return json({ error: 'not found' }, 404);
      return json({ blob: row.blob });
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
    // v25: чанки файлов живут не дольше жёсткого потолка сообщений (30 дней)
    try {
      this.sql.exec(`DELETE FROM file_chunks WHERE ts<?`, now - HARD_RETENTION_MS);
    } catch {}
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
    if (att.authed) {
      // v25: после auth по WS живёт только эфемерный typing — ретранслируем
      // остальным без хранения. Сообщения по-прежнему идут HTTP POST /msg.
      if (m?.type === 'typing' && att.device) {
        this.broadcast({ type: 'typing', dev: att.device, ts: Date.now() }, att.device);
      }
      return;
    }
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
      ws.send(
        JSON.stringify({
          type: 'ready',
          lastSeq: last?.m || 0,
          online: this.onlineDevices(),
          members: this.memberStateRows(),
        })
      );
    } catch {}
    // v25: оповестить остальных, что устройство теперь онлайн
    if (m.dev) this.broadcastPresence(String(m.dev), true);
  }

  async webSocketClose(ws) {
    // v25: если это был последний сокет устройства — оно ушло в офлайн
    try {
      const att = ws.deserializeAttachment() || {};
      if (att.authed && att.device) {
        const stillOnline = this.state
          .getWebSockets()
          .some((s) => s !== ws && (s.deserializeAttachment() || {}).device === att.device);
        if (!stillOnline) this.broadcastPresence(att.device, false);
      }
    } catch {}
    try {
      ws.close();
    } catch {}
  }
}
