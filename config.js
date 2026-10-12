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
  EXTRA_ICE_SERVERS: [],
};
