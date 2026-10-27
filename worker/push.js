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

let vapidCache = null;
export async function getVapid(env) {
  if (vapidCache) return vapidCache;
  if (!env.VAPID_PRIVATE_JWK) return null;
  const jwk = JSON.parse(env.VAPID_PRIVATE_JWK);
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    { ...jwk, alg: 'ES256', ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const x = b64u.dec(jwk.x);
  const y = b64u.dec(jwk.y);
  const publicRaw = concat(new Uint8Array([4]), x, y);
  vapidCache = { privateKey, publicB64: b64u.enc(publicRaw) };
  return vapidCache;
}

export async function vapidAuthHeader(endpoint, env) {
  const v = await getVapid(env);
  if (!v) return null;
  const aud = new URL(endpoint).origin;
  const header = b64u.enc(te.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = b64u.enc(
    te.encode(
      JSON.stringify({
        aud,
        exp: Math.floor(Date.now() / 1000) + 12 * 3600,
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
  return `vapid t=${header}.${payload}.${b64u.enc(sig)}, k=${v.publicB64}`;
}

// Отправляет один пуш. Возвращает HTTP-статус push-службы (404/410 = подписка мертва).
export async function sendPush(env, sub, payloadObj, { ttl = 120, topic = null } = {}) {
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
    Urgency: 'high',
  };
  if (topic) headers.Topic = String(topic).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 32);
  const res = await fetch(sub.endpoint, { method: 'POST', headers, body });
  return { status: res.status };
}
