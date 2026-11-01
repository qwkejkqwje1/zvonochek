// v38: анонимные имена для чатов и звонков (anon-names.js).
import test from 'node:test';
import assert from 'node:assert/strict';
import { anonName, randomAnonName, ANON_COUNT } from '../anon-names.js';

const FEM = /(ая|яя) /;
const MASC = /(ый|ий|ой) /;

test('имя детерминировано: одинаковое у всех участников комнаты', () => {
  const id = 'c0ffee'.repeat(8);
  assert.equal(anonName(id), anonName(id));
  assert.notEqual(anonName(id), anonName(id + '1'));
});

test('два слова с заглавной буквы, согласованы по роду', () => {
  const femNouns = new Set(['Сова', 'Рысь', 'Чайка', 'Ласточка', 'Белка', 'Выдра', 'Цапля', 'Иволга', 'Комета', 'Звезда', 'Волна', 'Река', 'Ель', 'Берёза', 'Пума', 'Синица', 'Гроза', 'Тундра']);
  for (let i = 0; i < 2000; i++) {
    const n = anonName('seed-' + i);
    assert.match(n, /^[А-ЯЁ][а-яё]+ [А-ЯЁ][а-яё]+$/, n);
    const noun = n.split(' ')[1];
    assert.ok(femNouns.has(noun) ? FEM.test(n + ' ') : MASC.test(n + ' '), `род не согласован: ${n}`);
    assert.ok(n.length <= 40, n);
  }
});

test('вариантов больше тысячи, и детерминированные имена их используют', () => {
  assert.ok(ANON_COUNT >= 1000, String(ANON_COUNT));
  const seen = new Set();
  for (let i = 0; i < 20000; i++) seen.add(anonName('room-' + i));
  assert.ok(seen.size > ANON_COUNT * 0.9, `${seen.size} из ${ANON_COUNT}`);
});

test('случайное имя — из того же словаря', () => {
  for (let i = 0; i < 200; i++) assert.match(randomAnonName(), /^[А-ЯЁ][а-яё]+ [А-ЯЁ][а-яё]+$/);
});
