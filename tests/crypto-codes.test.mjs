// v36: схема 2 адресов кодов/фраз (codeAccess) и совместимость со схемой ≤ v35.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  codeAccess, sealCodeBlob, openCodeBlob, codeAddrForScheme,
  greetCodeHash, aliasCodeHash, wordCodeHash,
  sealGreetPayload, openGreetPayload, sealAliasPayload, sealWordPayload, openWordPayload,
  newGreetCode, normalizeWordPhrase,
} from '../crypto.js';

test('схема 2: адрес — 64 hex, детерминирован и не равен старому SHA-256', async () => {
  const code = newGreetCode();
  const a = await codeAccess('greet', code);
  const b = await codeAccess('greet', code);
  assert.match(a.addr, /^[a-f0-9]{64}$/); // формат, который принимает worker.js
  assert.equal(a.addr, b.addr);
  assert.equal(a.legacy.addr, await greetCodeHash(code));
  assert.notEqual(a.addr, a.legacy.addr);
});

test('пространства кодов разделены: greet ≠ alias ≠ word для одной строки', async () => {
  const code = 'AbCdEfGhI';
  const [g, al, w] = await Promise.all([codeAccess('greet', code), codeAccess('alias', code), codeAccess('word', code)]);
  assert.equal(new Set([g.addr, al.addr, w.addr]).size, 3);
  assert.equal(al.legacy.addr, await aliasCodeHash(code));
});

test('фраза нормализуется одинаково в обеих схемах', async () => {
  const a = await codeAccess('word', '  Тихий   Синий  КРАН ');
  const b = await codeAccess('word', 'тихий синий кран');
  assert.equal(a.addr, b.addr);
  assert.equal(a.legacy.addr, await wordCodeHash('тихий синий кран'));
  assert.equal(normalizeWordPhrase('Ёлка  ЁЖ'), 'елка еж');
});

test('blob схемы 2 открывается ключом схемы 2 и не открывается старым', async () => {
  const acc = await codeAccess('greet', 'Zz9-_xYw1');
  const blob = await sealCodeBlob(acc.key, { seed: 'S', roomId: 'R' });
  assert.deepEqual(await openCodeBlob(acc.key, blob), { seed: 'S', roomId: 'R' });
  assert.equal(await openCodeBlob(acc.legacy.key, blob), null);
});

test('совместимость: blob клиента ≤ v35 открывается legacy-ключом схемы 2', async () => {
  const code = 'q1w2e3r4t';
  const oldBlob = await sealGreetPayload(code, { seed: 'old', roomId: 'r1' });
  const acc = await codeAccess('greet', code);
  assert.deepEqual(await openCodeBlob(acc.legacy.key, oldBlob), { seed: 'old', roomId: 'r1' });
  assert.equal(await openCodeBlob(acc.key, oldBlob), null);
  // и наоборот: старый openGreetPayload по-прежнему работает со старыми blob-ами
  assert.deepEqual(await openGreetPayload(code, oldBlob), { seed: 'old', roomId: 'r1' });
});

test('совместимость: старые alias/word blob-ы открываются legacy-ключом', async () => {
  const alias = await sealAliasPayload('AAAAAAAAA', { seed: 'a' });
  assert.deepEqual(await openCodeBlob((await codeAccess('alias', 'AAAAAAAAA')).legacy.key, alias), { seed: 'a' });
  const word = await sealWordPayload('Раз Два  Три', { seed: 'w' });
  assert.deepEqual(await openCodeBlob((await codeAccess('word', 'раз два три')).legacy.key, word), { seed: 'w' });
  assert.deepEqual(await openWordPayload('раз два три', word), { seed: 'w' });
});

test('codeAddrForScheme: схема 2 → новый адрес, без схемы → старый', async () => {
  const code = 'MnBvCxZ12';
  assert.equal(await codeAddrForScheme('alias', code, 2), (await codeAccess('alias', code)).addr);
  assert.equal(await codeAddrForScheme('alias', code, undefined), await aliasCodeHash(code));
  assert.equal(await codeAddrForScheme('word', 'А Б В', undefined), await wordCodeHash('а б в'));
});

test('битые входы не бросают исключений', async () => {
  const acc = await codeAccess('greet', 'abcdefghi');
  assert.equal(await openCodeBlob(acc.key, ''), null);
  assert.equal(await openCodeBlob(acc.key, '!!!не base64'), null);
  await assert.rejects(codeAccess('nope', 'x'));
});
