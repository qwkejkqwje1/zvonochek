// ZVONochek Service Worker v11 — мгновенная загрузка и кэширование статики с проверкой сети
const CACHE_NAME = 'zvonochek-v11';
const ASSETS = [
  './',
  './index.html',
  './style.css?v=11',
  './app.js?v=11',
  './signaling.js?v=11',
  './crypto.js?v=11',
  './config.js?v=11',
  './icon.svg',
  './manifest.webmanifest',
  './vendor/mqtt.min.js',
  './vendor/qrcode.js',
  './vendor/secp256k1.js?v=11',
];

self.addEventListener('install', (e) => {
  self.skipWaiting();
  e.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((c) => c.addAll(ASSETS))
      .catch(() => {})
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

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.endsWith('/version.json')) return; // всегда проверяем версию напрямую

  e.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.status === 200) {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(req))
  );
});
