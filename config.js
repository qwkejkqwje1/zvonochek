// ZVONochek — настройки. Пользователям здесь ничего менять не нужно.
export const CONFIG = {
  APP_NAME: 'ZVONochek',

  // Способ №2: адрес Cloudflare Worker (запасной сигналинг + TURN).
  // Пусто = работает только способ №1 (публичные MQTT-брокеры).
  WORKER_URL: 'https://zvonochek.zerewgwe.workers.dev',

  // Способ №1: публичные MQTT-брокеры (WSS). Подключаемся ко всем сразу —
  // если один недоступен, работают остальные.
  // Брокер на порту 443 идёт первым: во многих сетях нестандартные порты закрыты.
  MQTT_BROKERS: [
    { url: 'wss://public.cloud.shiftr.io', username: 'public', password: 'public' },
    'wss://broker.emqx.io:8084/mqtt',
    'wss://broker.hivemq.com:8884/mqtt',
    'wss://test.mosquitto.org:8081/mqtt',
  ],

  // Способ №3: публичные Nostr-реле (WSS, порт 443). Бесплатно, без регистрации.
  NOSTR_RELAYS: [
    'wss://relay.damus.io',
    'wss://nos.lol',
    'wss://relay.primal.net',
    'wss://nostr.mom',
    'wss://offchain.pub',
  ],

  // Публичные STUN-серверы
  STUN: [
    'stun:stun.l.google.com:19302',
    'stun:stun1.l.google.com:19302',
    'stun:stun.cloudflare.com:3478',
  ],

  // TURN от Metered.ca: домен приложения и ключ учётных данных (credential apiKey).
  // Этот ключ по документации Metered безопасен для фронтенда (не путать с secretKey!).
  METERED: { domain: '', apiKey: '' },

  // Свои ICE/TURN-серверы (например, свой coturn), если появятся
  // TURN Metered (статические учётные данные). Видны в публичном коде, поэтому
  // лучше перенести их в секреты Worker: TURN_URLS / TURN_USERNAME / TURN_CREDENTIAL.
  EXTRA_ICE_SERVERS: [
    { urls: 'stun:stun.relay.metered.ca:80' },
    {
      urls: [
        'turn:global.relay.metered.ca:80',
        'turn:global.relay.metered.ca:80?transport=tcp',
        'turn:global.relay.metered.ca:443',
        'turns:global.relay.metered.ca:443?transport=tcp',
      ],
      username: 'b0cc17f06cf20504ab5cd581',
      credential: 'YSV26ACRA6JxZ8TQ',
    },
  ],
};
