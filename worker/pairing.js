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
    if (req.method === 'POST') {
      try {
        body = await req.json();
      } catch {
        return json({ error: 'bad json' }, 400);
      }
    }
    const now = Date.now();

    // ---------- Создание пары ----------
    if (path === '/create' && req.method === 'POST') {
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

    // ---------- Выдача пары (одноразовая) ----------
    if (path === '/claim' && req.method === 'POST') {
      const { codeHash } = body;
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
    // TTL истёк — пара не должна жить дольше срока в любом случае.
    this.dropPair();
    try {
      await this.state.storage.deleteAlarm();
    } catch {}
  }
}
