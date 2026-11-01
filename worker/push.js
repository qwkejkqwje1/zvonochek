// ZVONochek Worker — Web Push: шифрование RFC 8291 (aes128gcm) и VAPID (RFC 8292)
// на чистом WebCrypto, без зависимостей. Корректность encryptPushPayload
// проверена тестовым вектором RFC 8291 Appendix A (байт-в-байт).
const te = new TextEncoder();

export const b64u = {
  enc(buf) {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < b.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '==='.slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

const concat = (...parts) => {
  const arrs = parts.map((x) => (x instanceof Uint8Array ? x : new Uint8Array(x)));
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
};

async function hkdf(ikm, salt, info, len) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, len * 8)
  );
}

// Шифрует payload для одной подписки. opts.asKeyPair и opts.salt — только для тестов
// (вектор RFC): в бою пара эфемерная на каждое сообщение, salt случайный.
export async function encryptPushPayload({ p256dh, auth, plaintext, asKeyPair = null, salt = null }) {
  const uaPublic = b64u.dec(p256dh);
  const authSecret = b64u.dec(auth);
  const pair =
    asKeyPair ||
    (await crypto.subtle.generateKeyPair({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ]));
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const uaKey = await crypto.subtle.importKey(
    'raw',
    uaPublic,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const ecdhSecret = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, pair.privateKey, 256)
  );
  const keyInfo = concat(te.encode('WebPush: info'), new Uint8Array([0]), uaPublic, asPublic);
  const ikm = await hkdf(ecdhSecret, authSecret, keyInfo, 32);
  const useSalt = salt || crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(ikm, useSalt, concat(te.encode('Content-Encoding: aes128gcm'), new Uint8Array([0])), 16);
  const nonce = await hkdf(ikm, useSalt, concat(te.encode('Content-Encoding: nonce'), new Uint8Array([0])), 12);
  const cekKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const data = concat(
    typeof plaintext === 'string' ? te.encode(plaintext) : plaintext,
    new Uint8Array([0x02]) // завершающий рекорд + делимитер паддинга (RFC 8188)
  );
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, cekKey, data)
  );
  const header = new Uint8Array(16 + 4 + 1 + asPublic.length);
  header.set(useSalt, 0);
  new DataView(header.buffer).setUint32(16, 4096); // record size, big-endian
  header[20] = asPublic.length;
  header.set(asPublic, 21);
  return { body: concat(header, ct), asPublic: b64u.enc(asPublic) };
}

// v38: VAPID без ручной настройки. Если секрет VAPID_PRIVATE_JWK не задан,
// пара ключей P-256 генерируется один раз и хранится в служебном PairingDO
// (idFromName('zv-vapid-v1'), внутренний путь /vapid-key — снаружи он
// недостижим: worker.js пробрасывает в PairingDO только белый список путей,
// адресуя их хэшем кода, а служебное имя хэшем быть не может). Раньше без
// секрета push был выключен целиком — и звонки в закрытую вкладку не доходили.
let vapidCache = null;
let vapidLoading = null;
const VAPID_DO_NAME = 'zv-vapid-v1';

async function importVapid(jwk) {
  // eslint-disable-next-line no-unused-vars
  const { key_ops, ext, alg, use, ...rest } = jwk || {};
  if (!rest.d || !rest.x || !rest.y) return null;
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    { ...rest, alg: 'ES256', ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const publicRaw = concat(new Uint8Array([4]), b64u.dec(rest.x), b64u.dec(rest.y));
  return { privateKey, publicB64: b64u.enc(publicRaw) };
}

// Генерация ключа VAPID (вызывается внутри PairingDO под blockConcurrencyWhile).
export async function generateVapidJwk() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d };
}

// Есть ли у сервера способ подписывать пуши (для /health).
export const vapidAvailable = (env) => !!(env && (env.VAPID_PRIVATE_JWK || env.PAIRING));

export async function getVapid(env) {
  if (vapidCache) return vapidCache;
  if (vapidLoading) return vapidLoading;
  const p = (async () => {
    try {
      if (env.VAPID_PRIVATE_JWK) {
        vapidCache = await importVapid(JSON.parse(env.VAPID_PRIVATE_JWK));
        return vapidCache;
      }
      if (!env.PAIRING) return null;
      const stub = env.PAIRING.get(env.PAIRING.idFromName(VAPID_DO_NAME));
      const r = await stub.fetch('https://do/pair/vapid-key', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-zv-internal': 'vapid' },
        body: '{}',
      });
      if (!r.ok) return null;
      const j = await r.json();
      vapidCache = j && j.jwk ? await importVapid(j.jwk) : null;
      return vapidCache;
    } catch {
      return null;
    }
  })();
  vapidLoading = p;
  p.then(
    () => {
      if (vapidLoading === p) vapidLoading = null;
    },
    () => {
      if (vapidLoading === p) vapidLoading = null;
    }
  );
  return p;
}

// v38: JWT VAPID кэшируется по audience (push-службе) на ~11 часов: подпись
// ECDSA на каждый пуш — лишнее CPU бесплатного тарифа.
const jwtCache = new Map(); // aud -> {value, until}
export async function vapidAuthHeader(endpoint, env) {
  const v = await getVapid(env);
  if (!v) return null;
  const aud = new URL(endpoint).origin;
  const nowS = Math.floor(Date.now() / 1000);
  const hit = jwtCache.get(aud);
  if (hit && hit.k === v.publicB64 && hit.until > nowS) return hit.value;
  const header = b64u.enc(te.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = b64u.enc(
    te.encode(
      JSON.stringify({
        aud,
        exp: nowS + 12 * 3600,
        sub: env.VAPID_SUB || 'https://github.com/qwkejkqwje1/zvonochek',
      })
    )
  );
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    v.privateKey,
    te.encode(`${header}.${payload}`)
  );
  // WebCrypto отдаёт подпись ECDSA уже в raw r||s — именно её требует JWS (RFC 8292).
  const value = `vapid t=${header}.${payload}.${b64u.enc(sig)}, k=${v.publicB64}`;
  if (jwtCache.size > 50) jwtCache.clear();
  jwtCache.set(aud, { value, k: v.publicB64, until: nowS + 11 * 3600 });
  return value;
}

// Отправляет один пуш. Возвращает HTTP-статус push-службы (404/410 = подписка мертва).
export async function sendPush(env, sub, payloadObj, { ttl = 120, topic = null, urgency = 'high' } = {}) {
  const auth = await vapidAuthHeader(sub.endpoint, env);
  if (!auth) return { status: 0, skipped: 'no-vapid' };
  const { body } = await encryptPushPayload({
    p256dh: sub.keys.p256dh,
    auth: sub.keys.auth,
    plaintext: JSON.stringify(payloadObj),
  });
  const headers = {
    Authorization: auth,
    'Content-Encoding': 'aes128gcm',
    'Content-Type': 'application/octet-stream',
    TTL: String(ttl),
    Urgency: urgency,
  };
  if (topic) headers.Topic = String(topic).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
  const res = await fetch(sub.endpoint, { method: 'POST', headers, body, signal: AbortSignal.timeout(8000) });
  return { status: res.status };
}
