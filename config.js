// ZVONochek v14 — настройки мульти-транспорта, STUN/TURN и обхода блокировок.
export const CONFIG = {
  APP_NAME: 'ZVONochek',

  // Способ №2: адрес Cloudflare Worker (WebSocket + HTTP-поллинг + выдача временных TURN-ключей).
  // Пусто = работают публичные MQTT-брокеры и Nostr-реле.
  WORKER_URL: 'https://zvonochek.zerewgwe.workers.dev',

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

  // v14: СТАТИЧЕСКИХ TURN-КРЕДОВ В КЛИЕНТЕ БОЛЬШЕ НЕТ.
  // Раньше здесь лежали логин/пароль Metered и ExpressTURN в открытом виде:
  // их видел любой, кто открыл исходники, и мог жечь чужую квоту.
  // Теперь TURN только эфемерный и только из собственного Worker (/turn,
  // короткоживущие креды), и запрашивается ЛЕНИВО — лишь когда прямое
  // соединение и мост не справились. Нет Worker-TURN — проект честно
  // работает без TURN: direct P2P + голосовой мост через сигналинг.
};
