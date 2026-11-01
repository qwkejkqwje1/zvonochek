// v39: синхронизация профиля между устройствами — чистое ядро (sync-core.js)
// и криптография кода привязки (crypto.js).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  commitLocal, mergeItems, lwwWinner, chunkDelta, stableStringify, TOMB_KEEP_MS,
  personKeyOf, groupPersons, deviceLabelFromUA, utf8Len,
} from '../sync-core.js';
import {
  newLinkCode, normalizeLinkCode, formatLinkCode, parseLinkToken, linkAccess,
  linkBindOf, linkSasWords, linkRespKey, sealCodeBlob, openCodeBlob, CHAT_WORDS, b64u,
} from '../crypto.js';

const A = 'devA', B = 'devB';

test('commitLocal: новые, изменённые и исчезнувшие ключи', () => {
  let { items, changed } = commitLocal({}, { 'room:1': { nick: 'a' }, 'set:zvName': 'Аня' }, A, 1000);
  assert.deepEqual(changed.sort(), ['room:1', 'set:zvName']);
  assert.equal(items['room:1'].u, 1000);
  ({ items, changed } = commitLocal(items, { 'room:1': { nick: 'a' }, 'set:zvName': 'Аня' }, A, 2000));
  assert.deepEqual(changed, [], 'без изменений — без новых меток');
  ({ items, changed } = commitLocal(items, { 'room:1': { nick: 'b' } }, A, 3000));
  assert.deepEqual(changed.sort(), ['room:1', 'set:zvName']);
  assert.equal(items['set:zvName'].del, 1);
  assert.deepEqual(items['room:1'].v, { nick: 'b' });
});

test('commitLocal: метка монотонна даже при отставших часах', () => {
  const items = { 'set:x': { u: 5000, d: B, v: '1' } };
  const r = commitLocal(items, { 'set:x': '2' }, A, 1000);
  assert.equal(r.items['set:x'].u, 5001);
});

test('commitLocal: scope и dropKey', () => {
  const items = {
    'dev:X': { u: 1, d: A, v: { label: 'x' } },
    'call:old': { u: 1, d: A, v: { ts: 1 } },
    'rev:Y': { u: 1, d: A, v: { ts: 1 } },
  };
  const r = commitLocal(items, {}, A, 10, {
    scope: (k) => !k.startsWith('dev:') && !k.startsWith('rev:'),
    dropKey: (k) => k.startsWith('call:'),
  });
  assert.ok(r.items['dev:X'] && !r.items['dev:X'].del, 'реестр сканом не трогается');
  assert.ok(!('call:old' in r.items), 'журнал по сроку — без надгробия');
  assert.ok(r.items['rev:Y'] && !r.items['rev:Y'].del);
  assert.deepEqual(r.changed, []);
});

test('LWW: побеждает поздний, ничья — детерминированно', () => {
  const x = { u: 10, d: A, v: 1 };
  const y = { u: 11, d: B, v: 2 };
  assert.equal(lwwWinner(x, y), y);
  const p = { u: 10, d: 'a', v: 1 };
  const q = { u: 10, d: 'b', v: 2 };
  assert.equal(lwwWinner(p, q), q);
  assert.equal(lwwWinner(q, p), q, 'порядок аргументов не важен');
});

test('mergeItems: два устройства сходятся к одному состоянию', () => {
  const a = commitLocal({}, { 'room:1': { nick: 'A' }, 'contact:f': { name: 'Петя' } }, A, 100).items;
  const b = commitLocal({}, { 'room:1': { nick: 'B' }, 'set:zvName': 'Борис' }, B, 200).items;
  const ab = mergeItems(a, b, 300);
  const ba = mergeItems(b, a, 300);
  assert.equal(stableStringify(ab.items), stableStringify(ba.items));
  assert.deepEqual(ab.items['room:1'].v, { nick: 'B' });
  assert.deepEqual(ab.applied.sort(), ['room:1', 'set:zvName']);
  assert.deepEqual(ba.applied, ['contact:f']);
});

test('mergeItems: надгробие удаляет, протухшее надгробие игнорируется', () => {
  const local = { 'room:1': { u: 100, d: A, v: { nick: 'x' } } };
  const r = mergeItems(local, { 'room:1': { u: 200, d: B, del: 1 } }, 300);
  assert.equal(r.items['room:1'].del, 1);
  assert.deepEqual(r.applied, ['room:1']);
  const old = mergeItems(local, { 'room:1': { u: 200, d: B, del: 1 } }, 200 + TOMB_KEEP_MS + 1);
  assert.deepEqual(old.applied, []);
});

test('mergeItems: read — максимум, ep — объединение эпох', () => {
  const local = { 'read:r': { u: 500, d: A, v: 40 }, 'ep:r': { u: 1, d: A, v: [{ n: 1, secret: 's1', ts: 1 }] } };
  const remote = { 'read:r': { u: 100, d: B, v: 55 }, 'ep:r': { u: 2, d: B, v: [{ n: 2, secret: 's2', ts: 2 }] } };
  const r = mergeItems(local, remote, 600);
  assert.equal(r.items['read:r'].v, 55, 'поздняя метка с меньшим номером не откатывает прочтение');
  assert.deepEqual(r.items['ep:r'].v.map((e) => e.n), [1, 2]);
  const back = mergeItems(r.items, { 'read:r': { u: 900, d: B, v: 10 } }, 1000);
  assert.equal(back.items['read:r'].v, 55);
  assert.deepEqual(back.applied, []);
});

test('mergeItems: отзыв устройства окончательный, чужие префиксы отброшены', () => {
  const local = { 'rev:X': { u: 1, d: A, v: { ts: 1, by: 'master' } } };
  const r = mergeItems(local, { 'rev:X': { u: 99, d: B, del: 1 }, 'evil:1': { u: 1, d: B, v: 1 } }, 100);
  assert.ok(!r.items['rev:X'].del);
  assert.ok(!('evil:1' in r.items));
});

test('chunkDelta: куски не длиннее лимита в байтах UTF-8', () => {
  const items = {};
  for (let i = 0; i < 50; i++) items['contact:' + i] = { u: i, d: A, v: { name: 'Очень длинное имя контакта №' + i } };
  const chunks = chunkDelta(items, 1000);
  assert.ok(chunks.length > 1);
  for (const c of chunks) assert.ok(utf8Len(JSON.stringify(c)) <= 1000);
  assert.equal(chunks.reduce((n, c) => n + Object.keys(c).length, 0), 50);
  assert.equal(chunkDelta({ 'x:1': { v: 'я'.repeat(600) } }, 1000), null, 'слишком большой ключ — полный снимок');
});

test('люди вместо устройств: свои и чужие устройства группируются по master', () => {
  const own = new Set(['me1']);
  const members = {
    me1: { nick: 'Я' },
    me2: { nick: 'Я', masterPub: 'M', certOk: true },
    p1: { nick: 'Аня', masterPub: 'P', certOk: true, firstSeen: 1 },
    p2: { nick: 'Аня (ноут)', masterPub: 'P', certOk: true, firstSeen: 5 },
    fake: { nick: 'Аня', masterPub: 'P', certOk: false },
    gone: { nick: 'Ушёл', left: true },
  };
  assert.equal(personKeyOf('me2', members.me2, own, 'M'), 'self');
  const g = groupPersons(members, own, 'M');
  assert.deepEqual(g.get('self').devs.sort(), ['me1', 'me2']);
  assert.deepEqual(g.get('p:P').devs.sort(), ['p1', 'p2']);
  assert.equal(g.get('p:P').nick, 'Аня');
  assert.ok(g.has('d:fake'), 'без подтверждённого сертификата — отдельное устройство');
  assert.ok(!g.has('d:gone'));
});

test('метка устройства из User-Agent', () => {
  assert.equal(
    deviceLabelFromUA('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/126.0 Mobile Safari/537.36'),
    'Android · Chrome'
  );
  assert.equal(deviceLabelFromUA('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Version/17.5 Mobile/15E148 Safari/604.1'), 'iPhone · Safari');
  assert.equal(deviceLabelFromUA(''), 'Устройство');
});

test('код привязки: 12 цифр, формат, разбор ссылки', () => {
  const c = newLinkCode();
  assert.match(c, /^\d{12}$/);
  assert.equal(formatLinkCode('123456789012'), '1234 5678 9012');
  assert.equal(normalizeLinkCode(' 1234-5678 9012 '), '123456789012');
  assert.deepEqual(parseLinkToken('https://x/#link=123456789012.AAAAAAAAAAAAAAAAAAAAAA'), {
    code: '123456789012',
    bind: 'AAAAAAAAAAAAAAAAAAAAAA',
  });
  assert.deepEqual(parseLinkToken('1234 5678 9012'), { code: '123456789012', bind: null });
  assert.equal(parseLinkToken('12345'), null);
});

test('код привязки: адреса запроса и ответа разные, ключи открывают свои blob', async () => {
  const acc = await linkAccess('111122223333');
  const acc2 = await linkAccess('1111 2222 3333');
  assert.match(acc.req.addr, /^[a-f0-9]{64}$/);
  assert.equal(acc.req.addr, acc2.req.addr);
  assert.notEqual(acc.req.addr, acc.resp.addr);
  const blob = await sealCodeBlob(acc.req.key, { t: 'zv-link-req-v1', x: 1 });
  assert.deepEqual(await openCodeBlob(acc2.req.key, blob), { t: 'zv-link-req-v1', x: 1 });
  assert.equal(await openCodeBlob(acc.resp.key, blob), null);
});

test('код привязки: bind и контрольные слова зависят от ключей запроса', async () => {
  const req = { eB: 'e'.repeat(87), devicePub: 'd'.repeat(87), ecdhPub: 'h'.repeat(87), label: 'Android · Chrome', ts: 1 };
  const bind = await linkBindOf(req);
  assert.match(bind, /^[A-Za-z0-9_-]{22}$/);
  assert.notEqual(bind, await linkBindOf({ ...req, eB: 'f'.repeat(87) }));
  const w = await linkSasWords('123412341234', bind);
  assert.equal(w.length, 4);
  for (const x of w) assert.ok(CHAT_WORDS.includes(x));
  assert.deepEqual(w, await linkSasWords('1234 1234 1234', bind));
  assert.notDeepEqual(w, await linkSasWords('123412341235', bind));
});

test('код привязки: ключ ответа совпадает у обеих сторон ECDH', async () => {
  const gen = () => crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  const a = await gen();
  const b = await gen();
  const pub = async (k) => b64u.enc(new Uint8Array(await crypto.subtle.exportKey('raw', k.publicKey)));
  const mix = crypto.getRandomValues(new Uint8Array(32));
  const kA = await linkRespKey(a.privateKey, await pub(b), mix, 'bind');
  const kB = await linkRespKey(b.privateKey, await pub(a), mix, 'bind');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kA, new TextEncoder().encode('секрет'));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kB, ct);
  assert.equal(new TextDecoder().decode(pt), 'секрет');
  const kWrong = await linkRespKey(b.privateKey, await pub(a), mix, 'other-bind');
  await assert.rejects(crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kWrong, ct));
});
