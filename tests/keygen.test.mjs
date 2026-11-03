// v41: генерация пар P-256 (crypto.js genP256KeyPair). До v41 проверялся
// несуществующий crypto.subtle.generateKeyPair, и все ключи создавались
// запасным путём на BigInt. Здесь: основной путь — нативный generateKey,
// оба пути дают одинаковую форму пары и рабочие подписи/ECDH.
import test from 'node:test';
import assert from 'node:assert/strict';
import { genP256KeyPair } from '../crypto.js';

const te = new TextEncoder();
const raw = async (k) => new Uint8Array(await crypto.subtle.exportKey('raw', k));

async function checkEcdsa(pair) {
  assert.equal(pair.privateKey.extractable, false, 'приватный ключ не должен выгружаться');
  assert.deepEqual(pair.privateKey.usages, ['sign']);
  const pub = await raw(pair.publicKey);
  assert.equal(pub.length, 65);
  assert.equal(pub[0], 4);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, te.encode('zv'));
  // Проверяем подпись ключом, импортированным заново из raw — как у собеседника.
  const imported = await crypto.subtle.importKey('raw', pub, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  assert.ok(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, imported, sig, te.encode('zv')));
}

async function checkEcdh(a, b) {
  assert.equal(a.privateKey.extractable, false);
  const pubB = await crypto.subtle.importKey('raw', await raw(b.publicKey), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const pubA = await crypto.subtle.importKey('raw', await raw(a.publicKey), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const s1 = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pubB }, a.privateKey, 256));
  const s2 = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pubA }, b.privateKey, 256));
  assert.deepEqual(s1, s2);
}

test('genP256KeyPair: основной путь — нативный crypto.subtle.generateKey', async () => {
  const orig = crypto.subtle.generateKey;
  let calls = 0;
  crypto.subtle.generateKey = function (...args) {
    calls++;
    return orig.apply(this, args);
  };
  try {
    await checkEcdsa(await genP256KeyPair());
    await checkEcdh(await genP256KeyPair(['deriveBits'], 'ECDH'), await genP256KeyPair(['deriveBits'], 'ECDH'));
  } finally {
    delete crypto.subtle.generateKey;
  }
  assert.equal(crypto.subtle.generateKey, orig);
  assert.equal(calls, 3, 'генерация обошла нативный generateKey');
});

test('genP256KeyPair: запасной путь (BigInt) даёт ту же форму пары', async () => {
  await checkEcdsa(await genP256KeyPair(['sign', 'verify'], 'ECDSA', true));
  await checkEcdh(await genP256KeyPair(['deriveBits'], 'ECDH', true), await genP256KeyPair(['deriveBits'], 'ECDH'));
});

test('genP256KeyPair: отказ generateKey — переход на запасной путь', async () => {
  crypto.subtle.generateKey = async () => {
    throw new Error('NotSupportedError');
  };
  try {
    await checkEcdsa(await genP256KeyPair());
  } finally {
    delete crypto.subtle.generateKey;
  }
});
