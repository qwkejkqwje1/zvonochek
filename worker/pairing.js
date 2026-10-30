// ZVONochek Worker v25 — Pairing: Durable Object одной пары приветствия
// (быстрое подключение к чату по короткому коду, техплан v21 §6).
//
// Механика: владелец комнаты генерирует одноразовый код из 9 символов
// base64url (~54 бита энтропии). Ключ пары K = PBKDF2-HMAC-SHA256(код,
// соль='zv-greet-v1', 200 000) шифрует AES-GCM blob {seed, roomId} комнаты.
// Сервер хранит только шифротекст и адрес пары codeHash = SHA-256(
// 'zv-greet-v1' || код) — ни код, ни seed, ни ключ сервер не знает.
//
// Почему соль фиксированная, а не roomId: гость roomId не знает (он как раз
// и должен его получить из blob), поэтому соль не может зависеть от комнаты.
// Защита держится на: 54 бита энтропии кода + PBKDF2 200k (офлайн-перебор по
// украденному blob — ~200k хэшей на попытку) + TTL 15 минут + одноразовость
// (после успешной выдачи пара удаляется) + не более 5 попыток claim суммарно.
// Серверный дамп пары бесполезен после истечения TTL.
//
// API (путь внутри DO — после /pair):
//   POST /create {codeHash, blob, exp} — создать пару (TTL ≤ 15 мин от now)
//   POST /claim  {codeHash}            — забрать blob: 200 / 404 / 410
// DO адресуется idFromName(codeHash), поэтому codeHash внутри тела — лишь
// сверка с адресом; реальный ключ маршрутизации задаёт worker.js.

const PAIR_TTL_MS = 15 * 60_000;
const MAX_CLAIMS = 5;
const MAX_BLOB_CHARS = 4096;
// v26: постоянный алиас (#join=). Выдачи не сжигают пару, но ограничены:
// не более 30 успешных выдач в час на один codeHash, дальше 429 до конца окна.
const ALIAS_CLAIM_LIMIT = 30;
const ALIAS_CLAIM_WINDOW_MS = 3_600_000;

import { b64u } from './push.js';

const te = new TextEncoder();
const sha256hex = async (text) => {
  const h = await crypto.subtle.digest('SHA-256', typeof text === 'string' ? te.encode(text) : text);
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('');
};

// v27: проверка подписи ECDSA P-256 (для серверного бэкапа личности).
async function verifySig(pubB64, sigB64, dataBytes) {
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
      dataBytes
    );
  } catch {
    return false;
  }
}

// v27: серверный бэкап личности. Blob зашифрован ключом из фразы
// восстановления (HKDF(seed, 'zv-backup-v1')), сервер содержимого не знает —
// видит только факт существования бэкапа и его размер. Адрес: idHash =
// SHA-256(raw recoveryPub). Запись принимается только с подписью
// recovery-ключа над SHA-256(blob) — чужой бэкап по чужому адресу не
// подменить и не затереть. cert (публичный сертификат recovery-ключа от
// master) хранится рядом открыто: он нужен новому устройству для цепочки
// master → recovery → device и секретом не является.
const BACKUP_MAX_BLOB_CHARS = 64 * 1024;

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });

export class Pairing {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`);
  }

  one(q, ...p) {
    return this.sql.exec(q, ...p).toArray()[0] || null;
  }
  meta(k) {
    return this.one(`SELECT v FROM meta WHERE k=?`, k)?.v || null;
  }
  setMeta(k, v) {
    this.sql.exec(`INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)`, k, v);
  }
  dropPair() {
    this.sql.exec(`DELETE FROM meta`);
  }

  async ensureAlarm(exp) {
    try {
      await this.state.storage.setAlarm(exp + 60_000);
    } catch {}
  }

  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/pair/, '') || '/';
    let body = {};
    if (req.method === 'POST' || req.method === 'PUT') {
      try {
        body = await req.json();
      } catch {
        return json({ error: 'bad json' }, 400);
      }
    }
    const now = Date.now();

    // ---------- v27: серверный бэкап личности ----------
    // PUT /backup {idHash, pub, blob, sig, cert?} — создать/обновить.
    if (path === '/backup' && req.method === 'PUT') {
      const { idHash, pub, blob, sig, cert } = body;
      if (typeof idHash !== 'string' || !/^[a-f0-9]{64}$/.test(idHash)) {
        return json({ error: 'bad idHash' }, 400);
      }
      if (typeof pub !== 'string' || !pub) return json({ error: 'bad pub' }, 400);
      if (typeof blob !== 'string' || !blob || blob.length > BACKUP_MAX_BLOB_CHARS) {
        return json({ error: 'bad blob' }, 400);
      }
      if (typeof sig !== 'string' || !sig) return json({ error: 'bad sig' }, 400);
      let pubRaw;
      try {
        pubRaw = b64u.dec(pub);
      } catch {
        return json({ error: 'bad pub' }, 400);
      }
      if (pubRaw.length !== 65 || pubRaw[0] !== 0x04) return json({ error: 'bad pub' }, 400);
      // Адрес бэкапа обязан быть хэшем именно этого публичного ключа.
      if ((await sha256hex(pubRaw)) !== idHash) return json({ error: 'id mismatch' }, 403);
      // Подпись recovery-ключом над SHA-256(blob): без неё запись не принимаем.
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(blob)));
      if (!(await verifySig(pub, sig, digest))) return json({ error: 'bad sig' }, 403);
      this.setMeta('bk_id', idHash);
      this.setMeta('bk_pub', pub);
      this.setMeta('bk_blob', blob);
      this.setMeta('bk_cert', cert ? JSON.stringify(cert) : '');
      this.setMeta('bk_updated', String(now));
      return json({ ok: true, backup: true }, 200);
    }
    // GET /backup?idHash= — отдать blob и публичный cert (если есть).
    if (path === '/backup' && req.method === 'GET') {
      const idHash = url.searchParams.get('idHash') || '';
      if (!this.meta('bk_blob') || this.meta('bk_id') !== idHash) {
        return json({ error: 'not found' }, 404);
      }
      let cert = null;
      try {
        cert = JSON.parse(this.meta('bk_cert') || 'null');
      } catch {}
      return json({ ok: true, blob: this.meta('bk_blob'), cert });
    }

    // ---------- v26: создание постоянного алиаса ----------
    // {codeHash, blob, adminHash}: adminHash = SHA-256(admin-секрета владельца);
    // сам admin сервер не получает при создании и хранит только хэш.
    if (path === '/alias' && req.method === 'POST') {
      const { codeHash, blob, adminHash } = body;
      if (typeof codeHash !== 'string' || !/^[a-f0-9]{64}$/.test(codeHash)) {
        return json({ error: 'bad codeHash' }, 400);
      }
      if (typeof blob !== 'string' || !blob || blob.length > MAX_BLOB_CHARS) {
        return json({ error: 'bad blob' }, 400);
      }
      if (typeof adminHash !== 'string' || !/^[a-f0-9]{64}$/.test(adminHash)) {
        return json({ error: 'bad adminHash' }, 400);
      }
      if (this.meta('mode') || this.meta('blob')) {
        return json({ error: 'taken' }, 409); // адрес уже занят (алиас или пара приветствия)
      }
      this.setMeta('mode', 'alias');
      this.setMeta('code_hash', codeHash);
      this.setMeta('blob', blob);
      this.setMeta('admin_hash', adminHash);
      this.setMeta('alias_claims', '0');
      this.setMeta('alias_window', String(now));
      return json({ ok: true, alias: true }, 201);
    }

    // ---------- v26: отзыв алиаса владельцем ----------
    // {codeHash, admin}: доступ доказывается знанием admin — сервер сверяет
    // SHA-256(admin) с admin_hash из создания. Неверный admin → 403.
    if (path === '/revoke' && req.method === 'POST') {
      const { codeHash, admin } = body;
      if (this.meta('mode') !== 'alias' || this.meta('code_hash') !== codeHash) {
        return json({ error: 'not found' }, 404);
      }
      if (typeof admin !== 'string' || !admin) return json({ error: 'bad admin' }, 400);
      if ((await sha256hex(admin)) !== this.meta('admin_hash')) {
        return json({ error: 'forbidden' }, 403);
      }
      this.dropPair();
      return json({ ok: true });
    }

    // ---------- Создание пары ----------
    if (path === '/create' && req.method === 'POST') {
      if (this.meta('mode') === 'alias') {
        return json({ error: 'taken' }, 409); // алиас парой приветствия не затираем
      }
      const { codeHash, blob, exp } = body;
      if (typeof codeHash !== 'string' || !/^[a-f0-9]{64}$/.test(codeHash)) {
        return json({ error: 'bad codeHash' }, 400);
      }
      if (typeof blob !== 'string' || !blob || blob.length > MAX_BLOB_CHARS) {
        return json({ error: 'bad blob' }, 400);
      }
      const expN = Number(exp);
      if (!Number.isFinite(expN) || expN <= now) return json({ error: 'bad exp' }, 400);
      if (expN > now + PAIR_TTL_MS + 30_000) return json({ error: 'ttl too long' }, 400);
      this.setMeta('code_hash', codeHash);
      this.setMeta('blob', blob);
      this.setMeta('exp', String(expN));
      this.setMeta('claims', '0');
      await this.ensureAlarm(expN);
      return json({ ok: true, exp: expN }, 201);
    }

    // ---------- Выдача ----------
    if (path === '/claim' && req.method === 'POST') {
      const { codeHash } = body;
      // v26: алиас — НЕ одноразовый и без TTL; rate-limit 30 выдач/час.
      if (this.meta('mode') === 'alias') {
        if (this.meta('code_hash') !== codeHash || !this.meta('blob')) {
          return json({ error: 'not found' }, 404);
        }
        let windowStart = Number(this.meta('alias_window') || 0);
        let claims = Number(this.meta('alias_claims') || 0);
        if (now - windowStart > ALIAS_CLAIM_WINDOW_MS) {
          windowStart = now;
          claims = 0;
        }
        if (claims >= ALIAS_CLAIM_LIMIT) {
          return json({ error: 'rate limited' }, 429);
        }
        this.setMeta('alias_claims', String(claims + 1));
        this.setMeta('alias_window', String(windowStart));
        return json({ ok: true, blob: this.meta('blob'), alias: true });
      }
      // Пара приветствия v25: одноразовая, с TTL (поведение без изменений).
      const blob = this.meta('blob');
      const exp = Number(this.meta('exp') || 0);
      if (!blob || this.meta('code_hash') !== codeHash) {
        return json({ error: 'not found' }, 404);
      }
      if (exp <= now) {
        this.dropPair();
        return json({ error: 'expired' }, 410);
      }
      const claims = Number(this.meta('claims') || 0) + 1;
      if (claims > MAX_CLAIMS) {
        this.dropPair();
        return json({ error: 'too many attempts' }, 410);
      }
      // Успешная выдача = пара сгорает (одноразовость).
      this.dropPair();
      return json({ ok: true, blob });
    }

    return json({ error: 'not found' }, 404);
  }

  async alarm() {
    // Алиас бессрочный: alarm его не трогает (alarm ставится только парам).
    if (this.meta('mode') === 'alias') {
      try {
        await this.state.storage.deleteAlarm();
      } catch {}
      return;
    }
    // TTL истёк — пара не должна жить дольше срока в любом случае.
    this.dropPair();
    try {
      await this.state.storage.deleteAlarm();
    } catch {}
  }
}
