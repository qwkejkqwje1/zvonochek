// ZVONochek Worker — Inbox: Durable Object личной комнаты (коммуникатор).
// Хранит устройства и push-подписки владельца, состояние ring-звонков и
// пропущенные (SQLite, переживает эвикшн; переходы состояний — только здесь,
// сериализованно). Содержимое звонков и ключи комнат сюда не попадают:
// blob звонящего зашифрован ключом комнаты (AES-GCM) и для Worker непрозрачен.
//
// Подписи (ECDSA P-256, sign/verify WebCrypto, текст UTF-8):
//   cert:    master подписывает  `zv-device-v1|<devicePub>|<label>|<exp>`
//   register:`register|<topic>|<devicePub>|<ts>`     (ключ устройства)
//   ack:     `ack|<topic>|<ringId>|<ts>`             (ключ устройства)
//   answer:  `answer|<topic>|<ringId>|<verdict>|<ts>`(ключ устройства)
//   cancel:  `cancel|<topic>|<ringId>|<ts>`          (ключ звонящего)
//   listen:  `listen|<topic>|<devicePub>|<ts>`       (ключ устройства)
//   missed:  `missed|<topic>|<ts>`                   (ключ устройства)
import { sendPush, b64u } from './push.js';

const te = new TextEncoder();
const RING_TTL_MS = 90_000;
const PUSH_FALLBACK_MS = 3_000;
const MISSED_TTL_MS = 24 * 3600_000;
const MAX_SUBS = 8;
const SIG_SKEW_MS = 5 * 60_000;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });

async function sha256hex(str) {
  const h = await crypto.subtle.digest('SHA-256', te.encode(str));
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('');
}
async function fpOfPub(pubB64) {
  const h = await crypto.subtle.digest('SHA-256', b64u.dec(pubB64));
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('').slice(0, 32);
}
async function verifySig(pubB64, sigB64, text) {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      b64u.dec(pubB64),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      b64u.dec(sigB64),
      te.encode(text)
    );
  } catch {
    return false;
  }
}
const freshTs = (ts) => Math.abs(Date.now() - Number(ts || 0)) < SIG_SKEW_MS;

// ---------- Сертификаты устройств (v20) и цепочка восстановления (v27) ----------
// Канонический текст сертификата устройства: issuer подписывает
// `zv-device-v1|<devicePub>|<label>|<exp>`.
export function deviceCertText(devicePub, label, exp) {
  return `zv-device-v1|${devicePub}|${label || ''}|${exp}`;
}

// Прямая проверка: cert устройства подписан issuerPub (обычно master).
export async function verifyDeviceCert(issuerPub, devicePub, cert) {
  if (!issuerPub || !devicePub || !cert?.sig) return false;
  return verifySig(issuerPub, cert.sig, deviceCertText(devicePub, cert.label, cert.exp));
}

// v27: цепочка глубиной 2 для восстановленной личности:
// master → recovery (отдельный cert с label 'recovery', выпускается master
// при настройке бэкапа) → новое устройство (cert подписан recovery-ключом).
// Существующий путь master → device этой функцией НЕ заменяется.
export async function verifyDeviceChain(masterPub, recoveryPub, recoveryCert, devicePub, cert) {
  if (!recoveryPub || !recoveryCert?.sig) return false;
  if (recoveryCert.label !== 'recovery') return false; // kind-флаг recovery-сертификата
  if (!(await verifyDeviceCert(masterPub, recoveryPub, recoveryCert))) return false;
  return verifyDeviceCert(recoveryPub, devicePub, cert);
}

export class Inbox {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`);
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS subs (endpoint TEXT PRIMARY KEY, device_pub TEXT, p256dh TEXT, auth TEXT, created INTEGER)`
    );
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS devices (device_pub TEXT PRIMARY KEY, cert TEXT, label TEXT, exp INTEGER, revoked INTEGER DEFAULT 0)`
    );
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS rings (ring_id TEXT PRIMARY KEY, state TEXT, blob TEXT, from_fp TEXT, from_device_pub TEXT, created INTEGER, exp INTEGER, push_at INTEGER, push_sent INTEGER DEFAULT 0, acked_by TEXT DEFAULT '[]', answered_by TEXT)`
    );
    this.sql.exec(
      `CREATE TABLE IF NOT EXISTS missed (ring_id TEXT PRIMARY KEY, blob TEXT, from_fp TEXT, ts INTEGER, outcome TEXT)`
    );
    this.sql.exec(`CREATE TABLE IF NOT EXISTS blocked (fp_hash TEXT PRIMARY KEY)`);
    this.state.setWebSocketAutoResponse(new WebSocketRequestResponsePair('ping', 'pong'));
  }

  topic(req) {
    const m = new URL(req.url).pathname.match(/^\/inbox\/([a-f0-9]{16,64})/);
    return m ? m[1] : '';
  }
  sub(req) {
    const m = new URL(req.url).pathname.match(/^\/inbox\/[a-f0-9]{16,64}(\/.*)?$/);
    return m ? m[1] || '/' : '/';
  }
  one(q, ...p) {
    return this.sql.exec(q, ...p).toArray()[0] || null;
  }
  all(q, ...p) {
    return this.sql.exec(q, ...p).toArray();
  }

  async isDevice(devicePub) {
    const d = this.one(`SELECT device_pub FROM devices WHERE device_pub=? AND revoked=0`, devicePub);
    return !!d;
  }

  broadcast(obj, exceptDevice = null) {
    const msg = JSON.stringify(obj);
    for (const ws of this.state.getWebSockets()) {
      const att = ws.deserializeAttachment() || {};
      if (!att.devicePub || att.devicePub === exceptDevice) continue;
      try {
        ws.send(msg);
      } catch {}
    }
  }

  async scheduleAlarm() {
    const now = Date.now();
    let next = null;
    for (const r of this.all(`SELECT exp, push_at, push_sent FROM rings WHERE state='ringing'`)) {
      const t = !r.push_sent && r.push_at > now ? r.push_at : r.exp;
      next = next === null ? t : Math.min(next, t);
    }
    if (next === null) await this.state.storage.deleteAlarm().catch(() => {});
    else await this.state.storage.setAlarm(next);
  }

  myTopic() {
    return this.one(`SELECT v FROM meta WHERE k='topic'`)?.v || '';
  }

  async fetch(req) {
    const topic = this.topic(req);
    if (topic) {
      this.sql.exec(`INSERT OR IGNORE INTO meta (k, v) VALUES ('topic', ?)`, topic);
    }
    const path = this.sub(req);
    if (!topic) return json({ error: 'bad topic' }, 400);

    if (path === '/listen' && req.headers.get('Upgrade') === 'websocket') {
      const pair = new WebSocketPair();
      this.state.acceptWebSocket(pair[1]);
      pair[1].serializeAttachment({ devicePub: null, topic });
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
    const url = new URL(req.url);

    // ---------- Регистрация устройства владельца (+ push-подписка) ----------
    if (path === '/register' && req.method === 'POST') {
      const { masterPub, fp, devicePub, cert, sub, label, ts, sig, chain } = body;
      if (!masterPub || !devicePub || !cert?.sig || !sig || !freshTs(ts)) {
        return json({ error: 'bad register' }, 400);
      }
      if ((await fpOfPub(masterPub)) !== fp) return json({ error: 'fp mismatch' }, 403);
      // v27: два пути доверия. Обычный — cert подписан master напрямую.
      // Восстановленная личность — цепочка master → recovery → device:
      // cert устройства подписан recovery-ключом, а сам recovery удостоверен
      // master заранее (при настройке бэкапа). Хранится тот же формат строки
      // devices; recovery-cert кладём внутрь JSON сертификата для аудита.
      let storedCert = cert;
      if (chain?.recoveryPub && chain?.recoveryCert) {
        if (
          !(await verifyDeviceChain(masterPub, chain.recoveryPub, chain.recoveryCert, devicePub, cert))
        ) {
          return json({ error: 'bad cert chain' }, 403);
        }
        storedCert = {
          ...cert,
          recovery: { pub: chain.recoveryPub, cert: chain.recoveryCert },
        };
      } else if (!(await verifyDeviceCert(masterPub, devicePub, cert))) {
        return json({ error: 'bad cert' }, 403);
      }
      if (!(await verifySig(devicePub, sig, `register|${topic}|${devicePub}|${ts}`))) {
        return json({ error: 'bad sig' }, 403);
      }
      this.sql.exec(
        `INSERT INTO devices (device_pub, cert, label, exp, revoked) VALUES (?,?,?,?,0)
         ON CONFLICT(device_pub) DO UPDATE SET cert=excluded.cert, label=excluded.label, exp=excluded.exp`,
        devicePub,
        JSON.stringify(storedCert),
        String(label || cert.label || ''),
        Number(cert.exp || 0)
      );
      const meta = this.one(`SELECT v FROM meta WHERE k='masterFp'`);
      if (!meta) {
        this.sql.exec(`INSERT INTO meta (k, v) VALUES ('masterFp', ?)`, fp);
      }
      if (sub?.endpoint && sub?.keys?.p256dh && sub?.keys?.auth) {
        this.sql.exec(
          `INSERT INTO subs (endpoint, device_pub, p256dh, auth, created) VALUES (?,?,?,?,?)
           ON CONFLICT(endpoint) DO UPDATE SET device_pub=excluded.device_pub, p256dh=excluded.p256dh, auth=excluded.auth`,
          String(sub.endpoint),
          devicePub,
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
      return json({ ok: true });
    }

    // ---------- Публичный список устройств (для проверки подписи владельца) ----------
    if (path === '/devices' && req.method === 'GET') {
      const devices = this.all(`SELECT device_pub, cert, label, exp, revoked FROM devices`).map(
        (d) => ({ devicePub: d.device_pub, cert: JSON.parse(d.cert), label: d.label, exp: d.exp, revoked: !!d.revoked })
      );
      const meta = this.one(`SELECT v FROM meta WHERE k='masterFp'`);
      return json({ masterFp: meta?.v || null, devices });
    }

    // ---------- Новый звонок ----------
    if (path === '/ring' && req.method === 'POST') {
      const { ringId, fromFp, fromDevicePub, blob } = body;
      if (!ringId || !fromFp || !fromDevicePub || typeof blob !== 'string' || blob.length > 4096) {
        return json({ error: 'bad ring' }, 400);
      }
      const now = Date.now();
      if (this.one(`SELECT fp_hash FROM blocked WHERE fp_hash=?`, await sha256hex(fromFp))) {
        return json({ error: 'blocked' }, 403);
      }
      const hourAgo = now - 3600_000;
      if (this.one(`SELECT COUNT(*) AS c FROM rings WHERE created>?`, hourAgo).c >= 30) {
        return json({ error: 'rate limited' }, 429);
      }
      if (
        this.one(`SELECT COUNT(*) AS c FROM rings WHERE created>? AND from_fp=?`, hourAgo, fromFp).c >= 10
      ) {
        return json({ error: 'rate limited' }, 429);
      }
      const existing = this.one(`SELECT state, exp FROM rings WHERE ring_id=?`, ringId);
      if (existing) return json({ state: existing.state, exp: existing.exp });
      const active = this.one(
        `SELECT ring_id, exp FROM rings WHERE state='ringing' AND from_fp=?`,
        fromFp
      );
      if (active) return json({ state: 'ringing', exp: active.exp, ringId: active.ring_id });
      const exp = now + RING_TTL_MS;
      this.sql.exec(
        `INSERT INTO rings (ring_id, state, blob, from_fp, from_device_pub, created, exp, push_at) VALUES (?,?,?,?,?,?,?,?)`,
        ringId,
        'ringing',
        blob,
        fromFp,
        fromDevicePub,
        now,
        exp,
        now + PUSH_FALLBACK_MS
      );
      this.broadcast({ type: 'ring', ringId, blob, fromFp });
      await this.scheduleAlarm();
      return json({ state: 'ringing', exp, ringId }, 201);
    }

    const ringMatch = path.match(/^\/ring\/([A-Za-z0-9-]{8,64})(\/(ack|answer))?$/);

    // ---------- Статус звонка (поллинг вызывающего) ----------
    if (ringMatch && req.method === 'GET' && !ringMatch[2]) {
      const r = this.one(`SELECT state, exp, answered_by FROM rings WHERE ring_id=?`, ringMatch[1]);
      if (!r) return json({ error: 'not found' }, 404);
      return json({ state: r.state, exp: r.exp, answeredBy: r.answered_by || null });
    }

    // ---------- Экран входящего показан (гасит пуш этому устройству) ----------
    if (ringMatch && ringMatch[2] === 'ack' && req.method === 'POST') {
      const { devicePub, ts, sig } = body;
      if (!devicePub || !freshTs(ts) || !(await this.isDevice(devicePub))) {
        return json({ error: 'bad ack' }, 403);
      }
      if (!(await verifySig(devicePub, sig, `ack|${topic}|${ringMatch[1]}|${ts}`))) {
        return json({ error: 'bad sig' }, 403);
      }
      const r = this.one(`SELECT acked_by FROM rings WHERE ring_id=?`, ringMatch[1]);
      if (r) {
        const acked = JSON.parse(r.acked_by || '[]');
        if (!acked.includes(devicePub)) {
          acked.push(devicePub);
          this.sql.exec(`UPDATE rings SET acked_by=? WHERE ring_id=?`, JSON.stringify(acked), ringMatch[1]);
        }
      }
      return json({ ok: true });
    }

    // ---------- Ответ: принял / отклонил / отменил ----------
    if (ringMatch && ringMatch[2] === 'answer' && req.method === 'POST') {
      const ringId = ringMatch[1];
      const { verdict, devicePub, ts, sig } = body;
      const r = this.one(`SELECT * FROM rings WHERE ring_id=?`, ringId);
      if (!r) return json({ error: 'not found' }, 404);
      if (verdict === 'accepted' || verdict === 'declined') {
        if (!devicePub || !freshTs(ts) || !(await this.isDevice(devicePub))) {
          return json({ error: 'bad answer' }, 403);
        }
        if (!(await verifySig(devicePub, sig, `answer|${topic}|${ringId}|${verdict}|${ts}`))) {
          return json({ error: 'bad sig' }, 403);
        }
      } else if (verdict === 'cancelled') {
        if (!freshTs(ts) || !(await verifySig(r.from_device_pub, sig, `cancel|${topic}|${ringId}|${ts}`))) {
          return json({ error: 'bad sig' }, 403);
        }
      } else {
        return json({ error: 'bad verdict' }, 400);
      }
      const newState = verdict;
      const upd = this.sql.exec(
        `UPDATE rings SET state=?, answered_by=? WHERE ring_id=? AND state='ringing'`,
        newState,
        verdict === 'cancelled' ? null : devicePub,
        ringId
      );
      // rowsWritten недоступен единообразно — проверяем состояние чтением
      const after = this.one(`SELECT state FROM rings WHERE ring_id=?`, ringId);
      if (after.state !== newState) {
        return json({ state: after.state }, after.state === 'expired' ? 410 : 409);
      }
      this.broadcast({ type: 'ring-state', ringId, state: newState, answeredBy: devicePub || null });
      if (newState === 'accepted' || newState === 'declined') {
        this.state.waitUntil(this.pushRingDone(ringId, devicePub));
      }
      await this.scheduleAlarm();
      return json({ state: newState });
    }

    // ---------- Пропущенные ----------
    if (path === '/missed' && req.method === 'GET') {
      const devicePub = url.searchParams.get('devicePub');
      const ts = url.searchParams.get('ts');
      const sig = url.searchParams.get('sig');
      if (!devicePub || !freshTs(ts) || !(await this.isDevice(devicePub))) {
        return json({ error: 'bad missed' }, 403);
      }
      if (!(await verifySig(devicePub, sig, `missed|${topic}|${ts}`))) {
        return json({ error: 'bad sig' }, 403);
      }
      const missed = this.all(`SELECT ring_id, blob, from_fp, ts, outcome FROM missed ORDER BY ts DESC LIMIT 50`);
      return json({ missed });
    }
    if (path === '/missed/ack' && req.method === 'POST') {
      const { ringIds, devicePub, ts, sig } = body;
      if (!devicePub || !freshTs(ts) || !(await this.isDevice(devicePub))) {
        return json({ error: 'bad ack' }, 403);
      }
      if (!(await verifySig(devicePub, sig, `missed|${topic}|${ts}`))) {
        return json({ error: 'bad sig' }, 403);
      }
      if (Array.isArray(ringIds)) {
        for (const id of ringIds.slice(0, 100)) {
          this.sql.exec(`DELETE FROM missed WHERE ring_id=?`, String(id));
        }
      }
      return json({ ok: true });
    }

    return json({ error: 'not found' }, 404);
  }

  async pushRingDone(ringId, answeredByDevice) {
    const subs = this.all(`SELECT * FROM subs WHERE device_pub != ?`, answeredByDevice || '');
    for (let i = 0; i < subs.length; i += 6) {
      await Promise.all(
        subs.slice(i, i + 6).map(async (s) => {
          try {
            const r = await sendPush(
              this.env,
              { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
              { t: 'ring-done', topic: this.myTopic(), ringId },
              { ttl: 60, topic: ringId }
            );
            if (r.status === 404 || r.status === 410) {
              this.sql.exec(`DELETE FROM subs WHERE endpoint=?`, s.endpoint);
            }
          } catch {}
        })
      );
    }
  }

  async alarm() {
    const now = Date.now();
    // Истёкшие звонки → в пропущенные
    for (const r of this.all(`SELECT * FROM rings WHERE state='ringing' AND exp<=?`, now)) {
      this.sql.exec(`UPDATE rings SET state='expired' WHERE ring_id=? AND state='ringing'`, r.ring_id);
      this.sql.exec(
        `INSERT OR REPLACE INTO missed (ring_id, blob, from_fp, ts, outcome) VALUES (?,?,?,?, 'expired')`,
        r.ring_id,
        r.blob,
        r.from_fp,
        r.created
      );
      this.broadcast({ type: 'ring-state', ringId: r.ring_id, state: 'expired' });
    }
    // Push тем, кто не подтвердил показ экрана входящего за PUSH_FALLBACK_MS
    for (const r of this.all(
      `SELECT * FROM rings WHERE state='ringing' AND push_sent=0 AND push_at<=?`,
      now
    )) {
      const acked = JSON.parse(r.acked_by || '[]');
      const subs = this.all(`SELECT * FROM subs`).filter((s) => !acked.includes(s.device_pub));
      const ttl = Math.max(10, Math.floor((r.exp - now) / 1000));
      for (let i = 0; i < subs.length; i += 6) {
        await Promise.all(
          subs.slice(i, i + 6).map(async (s) => {
            try {
              const res = await sendPush(
                this.env,
                { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
                { t: 'ring', topic: this.myTopic(), ringId: r.ring_id },
                { ttl, topic: r.ring_id }
              );
              if (res.status === 404 || res.status === 410) {
                this.sql.exec(`DELETE FROM subs WHERE endpoint=?`, s.endpoint);
              }
            } catch {}
          })
        );
      }
      this.sql.exec(`UPDATE rings SET push_sent=1 WHERE ring_id=?`, r.ring_id);
    }
    // Чистка старых терминальных записей
    this.sql.exec(`DELETE FROM rings WHERE state!='ringing' AND created<?`, now - MISSED_TTL_MS);
    this.sql.exec(`DELETE FROM missed WHERE ts<?`, now - MISSED_TTL_MS);
    await this.scheduleAlarm();
  }

  async webSocketMessage(ws, msg) {
    let m;
    try {
      m = JSON.parse(typeof msg === 'string' ? msg : new TextDecoder().decode(msg));
    } catch {
      return;
    }
    const att = ws.deserializeAttachment() || {};
    if (att.devicePub) return; // после аутентификации клиент ничего не шлёт
    if (m?.type !== 'auth' || !m.devicePub || !freshTs(m.ts)) return;
    if (!(await this.isDevice(m.devicePub))) return;
    const topic = att.topic || '';
    if (!(await verifySig(m.devicePub, m.sig, `listen|${topic}|${m.devicePub}|${m.ts}`))) return;
    ws.serializeAttachment({ ...att, devicePub: m.devicePub });
    // Сразу отдаём активные звонки — вдруг приложение открылось позже ring
    for (const r of this.all(`SELECT ring_id, blob, from_fp FROM rings WHERE state='ringing'`)) {
      try {
        ws.send(JSON.stringify({ type: 'ring', ringId: r.ring_id, blob: r.blob, fromFp: r.from_fp }));
      } catch {}
    }
  }

  async webSocketClose(ws) {
    try {
      ws.close();
    } catch {}
  }
}
