// v38: синхронные SHA-256/HMAC и длинные разрывы цепочек (CHAIN_MAX_GAP 1000 → 200 000).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sha256Sync, hmacSha256Sync, chainKeyAt, chainAdvanceSend, chainRecvTake, chainSendTake,
  chainInitSendState, chainInitRecvState, CHAIN_MAX_GAP, CHAIN_SKIPPED_MAX, b64u,
} from '../crypto.js';

const hex = (u8) => Buffer.from(u8).toString('hex');
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));

test('sha256Sync совпадает с WebCrypto на разных длинах (включая границы блоков)', async () => {
  const lens = [0, 1, 3, 31, 32, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 1000, 4097];
  for (let i = 0; i < 20; i++) lens.push(Math.floor(Math.random() * 3000));
  for (const len of lens) {
    const m = rnd(len);
    const ref = new Uint8Array(await crypto.subtle.digest('SHA-256', m));
    assert.equal(hex(sha256Sync(m)), hex(ref), 'len=' + len);
  }
  // известный вектор
  assert.equal(hex(sha256Sync(new TextEncoder().encode('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('hmacSha256Sync совпадает с WebCrypto HMAC (короткие, 64-байтные и длинные ключи)', async () => {
  for (const klen of [1, 16, 32, 63, 64, 65, 100, 200]) {
    for (const mlen of [0, 5, 32, 64, 300]) {
      const k = rnd(klen);
      const m = rnd(mlen);
      const key = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const ref = new Uint8Array(await crypto.subtle.sign('HMAC', key, m));
      assert.equal(hex(hmacSha256Sync(k, m)), hex(ref), `k=${klen} m=${mlen}`);
    }
  }
  const k = rnd(32);
  const key = await crypto.subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const ref = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode('zv-ck')));
  assert.equal(hex(hmacSha256Sync(k, 'zv-ck')), hex(ref), 'строковые данные');
});

test('потолок разрыва поднят: CHAIN_MAX_GAP ≥ 100 000', () => {
  assert.ok(CHAIN_MAX_GAP >= 100000);
  assert.ok(CHAIN_SKIPPED_MAX >= 64);
});

test('приём с разрывом 5000 даёт те же ключи, что и отправитель (новичок в «старом» чате)', async () => {
  const root = b64u.enc(rnd(32));
  const send = chainInitSendState(root);
  const keys = [];
  for (let i = 0; i < 5003; i++) keys.push((await chainSendTake(send)).mk);
  const recv = chainInitRecvState(root);
  const r = await chainRecvTake(recv, 5000);
  assert.equal(r.status, 'ok');
  assert.equal(hex(r.mk), hex(keys[5000]));
  assert.equal(recv.nextN, 5001);
  // skipped хранит только последние CHAIN_SKIPPED_MAX позиций
  assert.ok(recv.skipped.length <= CHAIN_SKIPPED_MAX);
  const late = await chainRecvTake(recv, 4999);
  assert.equal(late.status, 'ok');
  assert.equal(hex(late.mk), hex(keys[4999]));
  assert.equal((await chainRecvTake(recv, 4999)).status, 'unavailable', 'ключ одноразовый');
  assert.equal((await chainRecvTake(recv, 10)).status, 'unavailable', 'давно вытеснен');
  const next = await chainRecvTake(recv, 5002);
  assert.equal(hex(next.mk), hex(keys[5002]));
  const mid = await chainRecvTake(recv, 5001);
  assert.equal(hex(mid.mk), hex(keys[5001]));
});

test('разрыв больше потолка → gap без мутации состояния', async () => {
  const recv = chainInitRecvState(b64u.enc(rnd(32)));
  const before = JSON.stringify(recv);
  const r = await chainRecvTake(recv, CHAIN_MAX_GAP + 5);
  assert.equal(r.status, 'gap');
  assert.equal(JSON.stringify(recv), before);
  const r2 = await chainRecvTake(recv, 3000, 2000);
  assert.equal(r2.status, 'gap', 'локальный потолок maxGap соблюдается');
});

test('chainKeyAt выводит ключ любой позиции из корня (с контрольными точками)', async () => {
  const root = b64u.enc(rnd(32));
  const send = chainInitSendState(root);
  const keys = [];
  for (let i = 0; i < 1300; i++) keys.push((await chainSendTake(send)).mk);
  const cps = new Map();
  const k1234 = await chainKeyAt(root, 0, 1234, (n, ck) => cps.set(n, b64u.enc(ck)));
  assert.equal(hex(k1234), hex(keys[1234]));
  assert.ok(cps.has(512) && cps.has(1024));
  // с контрольной точки — тот же результат
  const kFromCp = await chainKeyAt(cps.get(1024), 1024, 1234);
  assert.equal(hex(kFromCp), hex(keys[1234]));
  assert.equal(hex(await chainKeyAt(root, 0, 0)), hex(keys[0]));
  assert.equal(await chainKeyAt(root, 10, 5), null);
  assert.equal(await chainKeyAt(root, 0, CHAIN_MAX_GAP + 1), null);
});

test('chainAdvanceSend: номера, ушедшие в сеть, повторно не выдаются', async () => {
  const root = b64u.enc(rnd(32));
  const ref = chainInitSendState(root);
  const keys = [];
  for (let i = 0; i < 700; i++) keys.push((await chainSendTake(ref)).mk);
  const st = chainInitSendState(root); // «откатившееся» состояние
  assert.equal(await chainAdvanceSend(st, 650), true);
  assert.equal(st.n, 650);
  const t = await chainSendTake(st);
  assert.equal(t.cn, 650);
  assert.equal(hex(t.mk), hex(keys[650]));
  assert.equal(await chainAdvanceSend(st, 100), false, 'назад нельзя');
  assert.equal(await chainAdvanceSend(st, st.n), false);
});
