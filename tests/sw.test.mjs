// v41: service worker на общем origin. Сайт живёт на <user>.github.io рядом
// с другими проектами аккаунта (например, /TorrClient/): у них общие кэши и
// общий список окон. sw.js исполняется в песочнице с поддельными caches,
// clients и registration — проверяем, что чужое не трогается и не мешает.
import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { ROOT } from './helpers.mjs';

const ORIGIN = 'https://user.github.io';
const SCOPE = ORIGIN + '/zvonochek/';
const TORR = { url: ORIGIN + '/TorrClient/watch/', visibilityState: 'visible' };
const V = JSON.parse(readFileSync(path.join(ROOT, 'version.json'), 'utf8')).v;

function loadSW({ cacheKeys = [], windows = [], notifications = [] } = {}) {
  const handlers = {};
  const log = { deleted: [], shown: [], focused: [], opened: [], posted: [], closed: [] };
  const notes = notifications.map((n) => ({ ...n, close: () => log.closed.push(n.tag) }));
  const wins = windows.map((w) => ({
    ...w,
    focus: async () => log.focused.push(w.url),
    postMessage: (m) => log.posted.push([w.url, m]),
  }));
  const ctx = {
    URL,
    Request,
    Response,
    console,
    caches: {
      keys: async () => cacheKeys,
      delete: async (k) => (log.deleted.push(k), true),
      open: async () => ({ add: async () => {}, put: async () => {} }),
      match: async () => undefined,
    },
    clients: { matchAll: async () => wins, openWindow: async (u) => log.opened.push(u), claim: async () => {} },
    skipWaiting() {},
    location: new URL(SCOPE + 'sw.js'),
    registration: {
      scope: SCOPE,
      showNotification: async (title, opts) => log.shown.push({ title, ...opts }),
      getNotifications: async ({ tag }) => notes.filter((n) => n.tag === tag),
    },
    addEventListener: (type, fn) => (handlers[type] = fn),
  };
  ctx.self = ctx;
  vm.createContext(ctx);
  vm.runInContext(readFileSync(path.join(ROOT, 'sw.js'), 'utf8'), ctx, { filename: 'sw.js' });
  const fire = async (type, ev = {}) => {
    let p = Promise.resolve();
    handlers[type]({ ...ev, waitUntil: (x) => (p = x), respondWith() {} });
    await p;
  };
  const push = (payload) => fire('push', { data: { json: () => payload } });
  return { fire, push, log };
}

test('SW: при обновлении удаляет только свои старые кэши', async () => {
  const sw = loadSW({ cacheKeys: [`zvonochek-v${V - 1}`, `zvonochek-v${V}`, 'zvonochek-flags', 'tc-cache-v3', 'workbox-precache-v2'] });
  await sw.fire('activate');
  assert.deepEqual(sw.log.deleted.sort(), [`zvonochek-v${V - 1}`, 'zvonochek-flags'].sort());
});

test('SW: открытая вкладка соседнего проекта не глушит уведомление о звонке', async () => {
  const sw = loadSW({ windows: [TORR] });
  await sw.push({ t: 'ring', ringId: 'r1', topic: 't' });
  assert.equal(sw.log.shown.length, 1);
  assert.match(sw.log.shown[0].title, /Входящий звонок/);
  assert.deepEqual(sw.log.posted, [], 'чужому окну ничего не шлём');
});

test('SW: своё видимое окно — звонок показывает страница, без уведомления', async () => {
  const sw = loadSW({ windows: [{ url: SCOPE + '?x=1', visibilityState: 'visible' }] });
  await sw.push({ t: 'ring', ringId: 'r1', topic: 't' });
  assert.equal(sw.log.shown.length, 0);
  assert.equal(sw.log.posted.length, 1);
});

test('SW: ring-done без видимого окна всегда что-то показывает (иначе iOS отзывает подписку)', async () => {
  for (const [state, re] of [
    ['cancelled', /Пропущенный/],
    ['expired', /Пропущенный/],
    ['accepted', /принят на другом/],
    ['declined', /отклонён на другом/],
  ]) {
    const sw = loadSW({ windows: [TORR] });
    await sw.push({ t: 'ring-done', ringId: 'r1', state });
    assert.equal(sw.log.shown.length, 1, state);
    assert.match(sw.log.shown[0].title, re);
    assert.equal(sw.log.shown[0].silent, true);
  }
});

test('SW: ring-done заменяет показанный «Входящий» и молчит при открытом приложении', async () => {
  const own = { url: SCOPE, visibilityState: 'visible' };
  const a = loadSW({ windows: [own] });
  await a.push({ t: 'ring-done', ringId: 'r1', state: 'accepted' });
  assert.equal(a.log.shown.length, 0);
  const b = loadSW({ windows: [own], notifications: [{ tag: 'ring-r2' }] });
  await b.push({ t: 'ring-done', ringId: 'r2', state: 'expired' });
  assert.deepEqual(b.log.closed, ['ring-r2']);
  assert.match(b.log.shown[0]?.title || '', /Пропущенный/);
});

test('SW: клик по уведомлению открывает Звоночек, а не чужую вкладку', async () => {
  const sw = loadSW({ windows: [TORR] });
  await sw.fire('notificationclick', { action: 'accept', notification: { close() {}, data: { ringId: 'r9', topic: 't' } } });
  assert.deepEqual(sw.log.focused, []);
  assert.deepEqual(sw.log.opened, ['./?ring=r9&act=accept']);
});
