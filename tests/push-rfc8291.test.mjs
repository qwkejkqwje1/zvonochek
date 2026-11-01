// Web Push (worker/push.js): шифрование payload по RFC 8291 — тестовый вектор
// из Appendix A, байт-в-байт. Без этого push «уходит», но телефон не может
// его расшифровать и молча выбрасывает.
import test from 'node:test';
import assert from 'node:assert/strict';
import { encryptPushPayload, b64u } from '../worker/push.js';

const V = {
  plaintext: 'When I grow up, I want to be a watermelon',
  asPrivate: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
  asPublic: 'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  uaPublic: 'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  salt: 'DGv6ra1nlYgDCS1FRnbzlw',
  auth: 'BTBZMqHH6r4Tts7J_aSIgg',
  result:
    'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
};

test('push: шифрование RFC 8291 совпадает с вектором Appendix A', async () => {
  const pub = b64u.dec(V.asPublic);
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    d: V.asPrivate,
    x: b64u.enc(pub.slice(1, 33)),
    y: b64u.enc(pub.slice(33, 65)),
    ext: true,
  };
  const privateKey = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const publicKey = await crypto.subtle.importKey('raw', pub, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
  const { body } = await encryptPushPayload({
    p256dh: V.uaPublic,
    auth: V.auth,
    plaintext: V.plaintext,
    asKeyPair: { privateKey, publicKey },
    salt: b64u.dec(V.salt),
  });
  assert.equal(b64u.enc(body), V.result);
});

test('push: заголовок VAPID (RFC 8292) — JWT ES256 проверяется публичным ключом k', async () => {
  const { generateVapidJwk, vapidAuthHeader } = await import('../worker/push.js');
  const jwk = await generateVapidJwk();
  const env = { VAPID_PRIVATE_JWK: JSON.stringify(jwk) };
  const h = await vapidAuthHeader('https://fcm.googleapis.com/fcm/send/abc', env);
  const m = /^vapid t=([\w-]+)\.([\w-]+)\.([\w-]+), k=([\w-]+)$/.exec(h);
  assert.ok(m, h);
  const [, head, payload, sig, k] = m;
  const claims = JSON.parse(new TextDecoder().decode(b64u.dec(payload)));
  assert.equal(claims.aud, 'https://fcm.googleapis.com');
  const now = Math.floor(Date.now() / 1000);
  assert.ok(claims.exp > now && claims.exp <= now + 24 * 3600, 'exp не дальше 24 ч (требование RFC 8292)');
  assert.match(claims.sub, /^(https:|mailto:)/);
  const pub = await crypto.subtle.importKey('raw', b64u.dec(k), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    pub,
    b64u.dec(sig),
    new TextEncoder().encode(`${head}.${payload}`)
  );
  assert.ok(ok, 'подпись JWT');
  // Повторный вызов для той же push-службы — из кэша (без новой подписи).
  assert.equal(await vapidAuthHeader('https://fcm.googleapis.com/fcm/send/other', env), h);
});
