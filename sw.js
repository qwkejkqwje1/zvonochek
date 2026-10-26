// ZVONochek Service Worker v12 — мгновенный старт, офлайн-оболочка и безопасные обновления
const CACHE_NAME = 'zvonochek-v12';
const CORE = [
  './',
  './index.html',
  './style.css?v=12',
  './app.js?v=12',
  './signaling.js?v=12',
  './crypto.js?v=12',
  './config.js?v=12',
  './icon.svg',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-maskable-512.png',
  './icons/apple-touch-icon.png',
  './manifest.webmanifest',
  './vendor/mqtt.min.js',
  './vendor/qrcode.js',
  './vendor/secp256k1.js?v=12',
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
