// ZVONochek v36 — настройки мульти-транспорта, STUN/TURN и обхода блокировок.
export const CONFIG = {
  APP_NAME: 'ZVONochek',

  // Способ №2: адрес Cloudflare Worker по умолчанию (WebSocket + HTTP-поллинг
  // + выдача временных TURN-ключей). Пользователь может заменить его своим
  // Worker в настройках (localStorage zvWorkerUrl, см. getWorkerBase ниже).
  WORKER_URL: 'https://zvonochek.zerewgwe.workers.dev',

  // Web Push: публичный VAPID-ключ клиент берёт у самого Worker (/push-key),
  // приватная часть — только секрет Worker VAPID_PRIVATE_JWK (см. RELEASE.md).

  // Способ №1: публичные MQTT-брокеры (WSS). Подключаемся ко всем параллельно —
  // побеждает самый быстрый канал, дубли автоматически отбрасываются.
  // Первым идёт брокер на стандартном порту 443 (проходит через строгие файрволы).
  MQTT_BROKERS: [
    { url: 'wss://public.cloud.shiftr.io', username: 'public', password: 'public' },
    'wss://broker.emqx.io:8084/mqtt',
    'wss://broker.hivemq.com:8884/mqtt',
    'wss://test.mosquitto.org:8081/mqtt',
    'wss://mqtt.eclipseprojects.io/mqtt',
  ],

  // Способ №3: публичные Nostr-реле (WSS, порт 443). Бесплатно и устойчиво к блокировкам.
  NOSTR_RELAYS: [
    'wss://relay.damus.io',
    'wss://nos.lol',
    'wss://relay.primal.net',
    'wss://nostr.mom',
    'wss://offchain.pub',
    'wss://relay.snort.social',
    'wss://relay.nostr.band',
    'wss://nostr-pub.wellorder.net',
    'wss://relay.nostr.info',
  ],

  // Способ №5 (v35): публичный ntfy.sh — «слепой» pub/sub без регистрации.
  // Ещё один резервный канал сигналинга звонков и третий канал резервного
  // транспорта чата. Наружу, как и везде, уходит только шифротекст, а имя
  // топика — SHA-256 от внутреннего идентификатора (см. signaling.js и
  // chat-transport.js). Адрес вынесен в конфиг: свой ntfy позже поднимется
  // одной строкой здесь, без переписывания транспортов.
  NTFY_BASE: 'https://ntfy.sh',

  // Расширенный пул бесплатных STUN-серверов разных операторов и портов
  // (443/80 помогают там, где провайдер режет классический 3478).
  // STUN бесплатен и почти ничего не стоит операторам — в отличие от TURN
  // он не пропускает через себя медиа, поэтому пул можно держать широким.
  STUN: [
    'stun:stun.cloudflare.com:3478',
    'stun:stun.l.google.com:19302',
    'stun:stun1.l.google.com:19302',
    'stun:stun2.l.google.com:19302',
    'stun:stun3.l.google.com:19302',
    'stun:stun4.l.google.com:19302',
    'stun:stun.nextcloud.com:443',
    'stun:stun.relay.metered.ca:80',
    'stun:stunserver.org:3478',
    'stun:global.stun.twilio.com:3478',
  ],

  // TURN от Metered.ca (если используется динамический API-ключ на клиенте)
  METERED: { domain: '', apiKey: '' },

  // v36: статических TURN-логинов в клиенте больше НЕТ.
  // До v35 здесь лежали логин и пароль Metered/ExpressTURN — в открытом виде
  // в публичном репозитории: любой мог выбрать бесплатную квоту, и TURN
  // отказывал ровно тогда, когда без него звонок не соединяется. Теперь TURN
  // выдаёт только свой Worker (/turn): короткоживущие ключи Cloudflare
  // Realtime TURN (1000 ГБ/мес бесплатно) или ваш TURN из секретов Worker.
  // Настройка — 2 минуты, см. RELEASE.md («TURN: перенос в Worker»).
  // Массив оставлен для своих НЕсекретных ICE-серверов (например, STUN).
  EXTRA_ICE_SERVERS: [],
};

// ---------- v28: «Свой сервер» — единый резолвер адреса Worker ----------
// Все модули (чат, Inbox/дозвон, pairing/бэкап, сигналинг звонков и TURN)
// обязаны ходить в Worker ТОЛЬКО через getWorkerBase(). Значение по
// умолчанию — CONFIG.WORKER_URL выше; пользовательский адрес лежит в
// localStorage zvWorkerUrl и применяется без перезагрузки конфига.
export const DEFAULT_WORKER_URL = CONFIG.WORKER_URL;
const WORKER_ENDPOINT_SEGMENTS = new Set(['chat', 'inbox', 'pair', 'room', 'turn', 'health']);

export function normalizeWorkerUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  // http допустим только для локального Worker разработчика (wrangler dev):
  // loopback-адрес не уходит в сеть, а в проде воркер всегда https.
  const loopback = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname);
  if (!(u.protocol === 'https:' || (u.protocol === 'http:' && loopback)) || !u.hostname) return null;
  if (u.username || u.password || u.search || u.hash) return null;
  const segments = u.pathname.split('/').filter(Boolean);
  // Базовый путь допустим (например, прокси-подпуть), но адрес конкретного
  // эндпоинта (/chat/…, /inbox/…) — нет: резолвер сам дописывает эндпоинты.
  if (segments.some((s) => WORKER_ENDPOINT_SEGMENTS.has(s))) return null;
  u.pathname = '/' + segments.join('/');
  return u.toString().replace(/\/$/, '');
}

export function getWorkerBase() {
  try {
    return normalizeWorkerUrl(globalThis.localStorage?.getItem('zvWorkerUrl')) || DEFAULT_WORKER_URL;
  } catch {
    return DEFAULT_WORKER_URL;
  }
}

export function setWorkerBase(value) {
  const normalized = value == null || String(value).trim() === '' ? null : normalizeWorkerUrl(value);
  if (value != null && String(value).trim() !== '' && !normalized) return null;
  try {
    if (normalized) globalThis.localStorage?.setItem('zvWorkerUrl', normalized);
    else globalThis.localStorage?.removeItem('zvWorkerUrl');
  } catch {}
  return normalized || DEFAULT_WORKER_URL;
}

export function hasCustomWorker() {
  return getWorkerBase() !== DEFAULT_WORKER_URL;
}
