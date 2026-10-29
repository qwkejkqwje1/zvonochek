// ZVONochek Service Worker v22 — мгновенный старт, офлайн-оболочка и безопасные обновления
const CACHE_NAME = 'zvonochek-v22';
const CORE = [
  './',
  './index.html',
  './style.css?v=22',
  './app.js?v=22',
  './group.js?v=22',
  './store.js?v=22',
  './identity.js?v=22',
  './inbox.js?v=22',
  './chat.js?v=22',
  './signaling.js?v=22',
  './crypto.js?v=22',
  './config.js?v=22',
  './zvdiag.js?v=22',
  './icon.svg',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png',
  './icons/apple-touch-icon.png',
  './manifest.webmanifest',
  './vendor/mqtt.min.js',
  './vendor/qrcode.js',
  './vendor/secp256k1.js?v=22',
];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE_NAME).then((c) =>
      // Один отсутствующий файл не должен ломать установку всего SW.
      Promise.allSettled(CORE.map((url) => c.add(new Request(url, { cache: 'reload' }))))
    )
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('message', (e) => {
  if (e.data === 'skip-waiting') self.skipWaiting();
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  // Версию, сам SW и любые коды ответов проверяем только по сети.
  if (url.pathname.endsWith('/version.json') || url.pathname.endsWith('/sw.js')) return;
  if (req.headers.has('range')) return;

  // Навигация: сначала сеть (свежий index.html), при офлайне — кэш.
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.status === 200) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((c) => c.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(async () => (await caches.match(req)) || (await caches.match('./index.html')))
    );
    return;
  }

  // Статика: stale-while-revalidate — мгновенный ответ из кэша + фоновое обновление.
  e.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req)
        .then((res) => {
          if (res && res.status === 200) {
            const copy = res.clone();
            caches.open(CACHE_NAME).then((c) => c.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});

// ---------- Web Push коммуникатора (payload — только {t, topic, ringId}) ----------
self.addEventListener('push', (e) => {
  let d = {};
  try {
    d = e.data ? e.data.json() : {};
  } catch {}
  if (d.t === 'ring') {
    e.waitUntil(
      (async () => {
        const wins = await clients.matchAll({ type: 'window', includeUncontrolled: true });
        const visible = wins.some((w) => w.visibilityState === 'visible');
        for (const w of wins) {
          w.postMessage({ type: 'incoming-ring-push', ringId: d.ringId, topic: d.topic });
        }
        if (!visible) {
          await self.registration.showNotification('Входящий звонок ZVONochek', {
            body: 'Кто-то звонит вам по личной ссылке',
            tag: d.ringId,
            icon: './icons/icon-192.png',
            badge: './icons/icon-192.png',
            requireInteraction: true,
            renotify: false,
            data: { ringId: d.ringId, topic: d.topic },
          });
        }
      })()
    );
  } else if (d.t === 'chat') {
    // v21: wake-up приватного чата. Payload несёт только хэш-префикс комнаты:
    // ни текста, ни никнейма — уведомление принципиально пустое по смыслу.
    e.waitUntil(
      (async () => {
        const wins = await clients.matchAll({ type: 'window', includeUncontrolled: true });
        const visible = wins.some((w) => w.visibilityState === 'visible');
        for (const w of wins) w.postMessage({ type: 'chat-push', room: d.room });
        if (!visible) {
          await self.registration.showNotification('Новое сообщение — ZVONochek', {
            body: 'В приватном чате есть непрочитанное сообщение',
            tag: 'chat-' + (d.room || ''),
            icon: './icons/icon-192.png',
            badge: './icons/icon-192.png',
            data: { chat: d.room || '' },
          });
        }
      })()
    );
  } else if (d.t === 'ring-done') {
    e.waitUntil(
      self.registration
        .getNotifications({ tag: d.ringId })
        .then((ns) => ns.forEach((n) => n.close()))
        .catch(() => {})
    );
  }
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const ringId = e.notification.data?.ringId || '';
  e.waitUntil(
    (async () => {
      const wins = await clients.matchAll({ type: 'window', includeUncontrolled: true });
      for (const w of wins) {
        await w.focus();
        w.postMessage({ type: 'incoming-ring-push', ringId });
        return;
      }
      await clients.openWindow('./' + (ringId ? `?ring=${encodeURIComponent(ringId)}` : ''));
    })()
  );
});

self.addEventListener('pushsubscriptionchange', (e) => {
  // Страница при следующем старте сверит подписку и перерегистрируется в Inbox.
  e.waitUntil(
    caches.open('zvonochek-flags').then((c) => c.put('/push-resubscribe', new Response('1')))
  );
});
