// ZVONochek Worker — Pairing: Durable Object коротких подключений к чату:
// пара приветствия v25 (код 9 символов), постоянный алиас v26 (#join=),
// серверный бэкап личности v27, встреча по кодовому слову v30.
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
//   POST /create {codeHash, blob, exp, nx?} — создать пару (TTL ≤ 15 мин от now;
//                v39: nx:true — 409, если по адресу уже лежит живая запись)
//   POST /claim  {codeHash}            — забрать blob: 200 / 404 / 410
//   POST /word   {codeHash, blob, exp, adminHash} — v30: встреча по
//                кодовому слову (TTL ≤ 24 ч, одноразовая, отзыв по admin)
// DO адресуется idFromName(codeHash), поэтому codeHash внутри тела — лишь
// сверка с адресом; реальный ключ маршрутизации задаёт worker.js.

const PAIR_TTL_MS = 15 * 60_000;
const MAX_CLAIMS = 5;
const MAX_BLOB_CHARS = 4096;
// v30: встреча по кодовому слову живёт дольше кода приветствия (фразу надо
// успеть передать и ввести), но остаётся одноразовой; неудачных попыток
// claim — не более 5, дальше запись сжигается, как у пары приветствия.
const WORD_TTL_MS = 24 * 3_600_000;
const WORD_MAX_CLAIMS = 5;
// v26: постоянный алиас (#join=). Выдачи не сжигают пару, но ограничены:
// не более 30 успешных выдач в час на один codeHash, дальше 429 до конца окна.
const ALIAS_CLAIM_LIMIT = 30;
const ALIAS_CLAIM_WINDOW_MS = 3_600_000;
// v38: автоочистка бесплатного Worker. Алиас живёт 30 дней с последнего
// использования (выдачи) или продления владельцем (клиент владельца продлевает
// раз в неделю, пока открывает комнату; сама комната без активности тоже
// стирается через 30 дней). Бэкап личности — 180 дней с последней заливки
// (клиент перезаливает раз в неделю при запуске): бэкап брошенной личности
// не копится вечно, а живой — не пропадает.
const ALIAS_IDLE_MS = 30 * 24 * 3_600_000;
const BACKUP_IDLE_MS = 180 * 24 * 3_600_000;

import { b64u, generateVapidJwk } from './push.js';

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
    this.sql.exec(`DELETE FROM meta WHERE k NOT LIKE 'bk_%' AND k NOT LIKE 'vapid_%'`);
  }
  dropBackup() {
    this.sql.exec(`DELETE FROM meta WHERE k LIKE 'bk_%'`);
  }

  // v38: ближайший срок среди всего, что хранит этот DO (пара/встреча — exp,
  // алиас — 30 дней простоя, бэкап — 180 дней без перезаливки).
  deadlines() {
    const out = [];
    const mode = this.meta('mode');
    if (mode === 'alias') {
      const touched = Number(this.meta('alias_touched') || 0);
      if (touched) out.push(touched + ALIAS_IDLE_MS);
    } else if (this.meta('blob')) {
      const exp = Number(this.meta('exp') || 0);
      if (exp) out.push(exp);
    }
    if (this.meta('bk_blob')) {
      const up = Number(this.meta('bk_updated') || 0);
      if (up) out.push(up + BACKUP_IDLE_MS);
    }
    return out;
  }

  async scheduleNext() {
    try {
      const d = this.deadlines();
      if (!d.length) {
        await this.state.storage.deleteAlarm();
        return;
      }
      await this.state.storage.setAlarm(Math.max(Date.now() + 1000, Math.min(...d) + 60_000));
    } catch {}
  }

  async ensureAlarm() {
    await this.scheduleNext();
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

    // ---------- v38: служебный ключ VAPID (только изнутри Worker) ----------
    // Снаружи сюда не попасть: worker.js не пробрасывает путь /pair/vapid-key,
    // а адрес этого DO — служебное имя, а не хэш кода. Генерация — под
    // blockConcurrencyWhile, чтобы два параллельных запроса не создали два
    // разных ключа (подписки на «проигравший» ключ молча не доставлялись бы).
    if (path === '/vapid-key' && req.method === 'POST' && req.headers.get('x-zv-internal') === 'vapid') {
      let jwkText = this.meta('vapid_jwk');
      if (!jwkText) {
        await this.state.blockConcurrencyWhile(async () => {
          jwkText = this.meta('vapid_jwk');
          if (!jwkText) {
            jwkText = JSON.stringify(await generateVapidJwk());
            this.setMeta('vapid_jwk', jwkText);
            this.setMeta('vapid_created', String(Date.now()));
          }
        });
      }
      return json({ ok: true, jwk: JSON.parse(jwkText) });
    }

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
      await this.scheduleNext();
      return json({ ok: true, backup: true, keepDays: BACKUP_IDLE_MS / 86_400_000 }, 200);
    }
    // v38: POST /backup {idHash, del:true, pub, ts, sig} — удалить бэкап
    // («Сменить номер» / «Стереть всё»). Подпись recovery-ключом над
    // SHA-256('zv-backup-delete-v1|'+idHash+'|'+ts), ts — не старше 10 минут.
    if (path === '/backup' && req.method === 'POST' && body.del === true) {
      const { idHash, pub, ts, sig } = body;
      if (typeof idHash !== 'string' || !/^[a-f0-9]{64}$/.test(idHash)) return json({ error: 'bad idHash' }, 400);
      if (!Number.isFinite(ts) || Math.abs(now - ts) > 10 * 60_000) return json({ error: 'stale' }, 400);
      if (this.meta('bk_id') !== idHash || this.meta('bk_pub') !== pub) return json({ ok: true, deleted: false });
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(`zv-backup-delete-v1|${idHash}|${ts}`)));
      if (typeof sig !== 'string' || !(await verifySig(pub, sig, digest))) return json({ error: 'bad sig' }, 403);
      this.dropBackup();
      await this.scheduleNext();
      return json({ ok: true, deleted: true });
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
      if (!this.meta('bk_updated')) this.setMeta('bk_updated', String(now));
      await this.scheduleNext();
      return json({ ok: true, blob: this.meta('bk_blob'), cert, updated: Number(this.meta('bk_updated') || 0) });
    }

    // ---------- v26: создание постоянного алиаса ----------
    // {codeHash, blob, adminHash}: adminHash = SHA-256(admin-секрета владельца);
    // сам admin сервер не получает при создании и хранит только хэш.
    if (path === '/alias' && req.method === 'POST') {
      const { codeHash, blob, adminHash } = body;
      if (typeof codeHash !== 'string' || !/^[a-f0-9]{64}$/.test(codeHash)) {
        return json({ error: 'bad codeHash' }, 400);
      }
      // v38: продление алиаса владельцем {codeHash, renew:true, admin} —
      // доступ, как у отзыва, по знанию admin (сервер сверяет его хэш).
      if (body.renew === true) {
        if (this.meta('mode') !== 'alias' || this.meta('code_hash') !== codeHash) {
          return json({ error: 'not found' }, 404);
        }
        if (typeof body.admin !== 'string' || !body.admin) return json({ error: 'bad admin' }, 400);
        if ((await sha256hex(body.admin)) !== this.meta('admin_hash')) {
          return json({ error: 'forbidden' }, 403);
        }
        this.setMeta('alias_touched', String(now));
        await this.scheduleNext();
        return json({ ok: true, alias: true, renewed: true, keepDays: ALIAS_IDLE_MS / 86_400_000 });
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
      this.setMeta('alias_touched', String(now));
      await this.scheduleNext();
      return json({ ok: true, alias: true, keepDays: ALIAS_IDLE_MS / 86_400_000 }, 201);
    }

    // ---------- v30: создание встречи по кодовому слову ----------
    // blob {seed, roomId} зашифрован ключом PBKDF2(фраза, 'zv-word-v1',
    // 600k) на клиенте; сервер фразы не знает — только хэш её адреса.
    if (path === '/word' && req.method === 'POST') {
      const { codeHash, blob, exp, adminHash } = body;
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
        return json({ error: 'taken' }, 409); // фраза уже занята (или адрес не пуст)
      }
      const expN = Number(exp);
      if (!Number.isFinite(expN) || expN <= now) return json({ error: 'bad exp' }, 400);
      if (expN > now + WORD_TTL_MS + 30_000) return json({ error: 'ttl too long' }, 400);
      this.setMeta('mode', 'word');
      this.setMeta('code_hash', codeHash);
      this.setMeta('blob', blob);
      this.setMeta('exp', String(expN));
      this.setMeta('claims', '0');
      this.setMeta('admin_hash', adminHash);
      await this.scheduleNext();
      return json({ ok: true, word: true, exp: expN }, 201);
    }

    // ---------- v26: отзыв алиаса владельцем ----------
    // {codeHash, admin}: доступ доказывается знанием admin — сервер сверяет
    // SHA-256(admin) с admin_hash из создания. Неверный admin → 403.
    // v30: тот же путь отзывает и встречу по кодовому слову (mode 'word').
    if (path === '/revoke' && req.method === 'POST') {
      const { codeHash, admin } = body;
      const mode = this.meta('mode');
      if ((mode !== 'alias' && mode !== 'word') || this.meta('code_hash') !== codeHash) {
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
      if (this.meta('mode') === 'alias' || this.meta('mode') === 'word') {
        return json({ error: 'taken' }, 409); // алиас/встречу парой приветствия не затираем
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
      // v39: nx — «только если свободно». Запрос привязки устройства и ответ
      // на него не затираются чужой записью по тому же адресу, пока живы.
      if (body.nx === true && this.meta('blob') && Number(this.meta('exp') || 0) > now) {
        return json({ error: 'exists' }, 409);
      }
      this.setMeta('code_hash', codeHash);
      this.setMeta('blob', blob);
      this.setMeta('exp', String(expN));
      this.setMeta('claims', '0');
      await this.scheduleNext();
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
        this.setMeta('alias_touched', String(now)); // v38: использование продлевает жизнь
        await this.scheduleNext();
        return json({ ok: true, blob: this.meta('blob'), alias: true });
      }
      // v30: встреча по кодовому слову — одноразовая, TTL 24 часа.
      if (this.meta('mode') === 'word') {
        const exp = Number(this.meta('exp') || 0);
        if (exp <= now) {
          this.dropPair();
          return json({ error: 'expired' }, 410);
        }
        if (this.meta('code_hash') !== codeHash) {
          // Неудачная попытка по угаданному адресу DO: считаем, на пятой
          // сжигаем встречу (тот же предел, что у пары приветствия).
          const fails = Number(this.meta('claims') || 0) + 1;
          if (fails >= WORD_MAX_CLAIMS) {
            this.dropPair();
            return json({ error: 'too many attempts' }, 410);
          }
          this.setMeta('claims', String(fails));
          return json({ error: 'not found' }, 404);
        }
        const blob = this.meta('blob');
        if (!blob) return json({ error: 'not found' }, 404);
        // Успешная выдача = встреча сгорает (одноразовость).
        this.dropPair();
        return json({ ok: true, blob, word: true });
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
    // v38: одна точка очистки для всего содержимого DO. Пара приветствия и
    // встреча по кодовому слову — по своему exp; алиас — после 30 дней без
    // выдач и продлений; бэкап — после 180 дней без перезаливки. Ключ VAPID
    // (служебный DO) не истекает.
    const now = Date.now();
    try {
      const mode = this.meta('mode');
      if (mode === 'alias') {
        const touched = Number(this.meta('alias_touched') || 0);
        if (!touched) this.setMeta('alias_touched', String(now)); // алиас до v38: отсчёт с сегодня
        else if (now - touched >= ALIAS_IDLE_MS) this.dropPair();
      } else if (this.meta('blob') || mode) {
        const exp = Number(this.meta('exp') || 0);
        if (!exp || exp <= now) this.dropPair();
      }
      if (this.meta('bk_blob')) {
        const up = Number(this.meta('bk_updated') || 0);
        if (!up) this.setMeta('bk_updated', String(now));
        else if (now - up >= BACKUP_IDLE_MS) this.dropBackup();
      }
    } catch {}
    await this.scheduleNext();
  }
}
