import test from 'node:test';
import assert from 'node:assert/strict';
import { coalesced } from '../coalesce.js';

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

test('coalesced: пачка синхронных вызовов — один запуск', async () => {
  let runs = 0;
  const render = coalesced(async () => {
    runs++;
    await tick(5);
  });
  await Promise.all(Array.from({ length: 50 }, () => render()));
  assert.equal(runs, 1);
});

test('coalesced: вызовы во время отрисовки дают ровно один повтор', async () => {
  let runs = 0;
  let state = 0;
  let seen = -1;
  const render = coalesced(async () => {
    runs++;
    const snapshot = state;
    await tick(10);
    seen = snapshot;
  });
  const first = render();
  await tick(2); // fn уже стартовал
  state = 1;
  const a = render();
  state = 2;
  const b = render();
  assert.equal(a, b);
  await Promise.all([first, a, b]);
  assert.equal(runs, 2);
  assert.equal(seen, 2, 'последний запуск видел свежее состояние');
});

test('coalesced: ошибка не блокирует следующие запуски', async () => {
  let n = 0;
  const render = coalesced(async () => {
    n++;
    if (n === 1) throw new Error('boom');
  });
  await assert.rejects(render(), /boom/);
  await render();
  assert.equal(n, 2);
});

test('coalesced: задержка старта собирает вызовы из разных тиков', async () => {
  let runs = 0;
  const render = coalesced(() => {
    runs++;
  }, 30);
  render();
  await tick(5);
  render();
  await tick(5);
  await render();
  assert.equal(runs, 1);
});
