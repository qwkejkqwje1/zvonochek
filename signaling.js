// Пять независимых транспортов сигналинга и аварийного аудио-моста, работающих параллельно:
//   1) Публичные MQTT-брокеры поверх WSS (включая порт 443)
//   2) Cloudflare Worker WebSocket (с ротацией окна каждые 9 КБ против зависаний ТСПУ)
//   3) Cloudflare Worker HTTP-поллинг + POST (работает даже при полной блокировке WebSocket)
//   4) Публичные Nostr-реле поверх WSS (порт 443, подписанные эфемерные события)
//   5) Публичный ntfy.sh (POST + WebSocket; «слепой» pub/sub без регистрации)
// Каждое сообщение сжимается и шифруется AES-256-GCM; дубли отсекаются по mid.
import { seal, open } from './crypto.js?v=41';
import { ntfyTopic, ntfySubscribeUrl, parseNtfyFrame, fitsNtfy } from './ntfy.js?v=41';
import { schnorr, utils } from './vendor/secp256k1.js?v=41';

const hexs = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const NOSTR_KIND = 29333; // эфемерные события: реле их не хранят, только пересылают

const rid = () => crypto.getRandomValues(new Uint32Array(2)).join('-');

// ---------- ntfy ----------
// Топик ntfy — префикс + усечённый SHA-256 топика комнаты (см. ntfy.js):
// сам топик (производный секрета ссылки) публичному серверу не виден.
export const ntfyTopicForSignaling = (topic) => ntfyTopic('zv1-', topic);

// ntfy — резерв с жёсткими лимитами публичного сервера (троттлинг по IP и
// дневная квота сообщений). Через него идёт только рукопожатие, а
// периодический hello — не чаще раза в 30 с: квоты должно хватать на
// реальные звонки, а не на ожидание собеседника.
const NTFY_TYPES = new Set(['hello', 'hi', 'g_hi', 'full', 'desc', 'g_desc', 'cand', 'g_cand', 'ack', 'reset', 'bye']);
const NTFY_HELLO_EVERY = 30000;
export function ntfyWanted(type, state, now = Date.now()) {
  if (!NTFY_TYPES.has(type)) return false;
  if (type !== 'hello') return true;
  if (now - (state.helloAt || 0) < NTFY_HELLO_EVERY) return false;
  state.helloAt = now;
  return true;
}

export class Signaling {
  constructor({ topic, key, selfId, inst, brokers, workerUrl, relays, ntfyBase, onMessage, onStatus, onPeerJoined }) {
    Object.assign(this, {
      topic,
      key,
      selfId,
      inst,
      brokers: brokers || [],
      workerUrl: (workerUrl || '').replace(/\/$/, ''),
      onMessage,
      onStatus,
      onPeerJoined,
    });
    this.relays = relays || [];
    this.ntfyBase = (ntfyBase || '').replace(/\/$/, '');
    this.ntfyTopic = null; // выводится асинхронно (SHA-256), см. _ntfyTopic()
    this.ntfyState = { helloAt: 0 }; // троттлинг hello через ntfy
    this.ntfyWs = null;
    this.ntfyTimer = null;
    this.nostr = new Map(); // url -> текущий сокет
    this.nsk = utils.randomSecretKey();
    this.npk = hexs(schnorr.getPublicKey(this.nsk));
    this.ntag = 'zv-' + topic;
    this.mqttTopic = `zvonochek/v1/${topic}`;
    this.clients = [];
    this.ws = null;
    this.wsState = this.workerUrl ? 'connecting' : 'off';
    this.httpState = 'off';
    this.pollTimer = null;
    // Стартуем без предположений о часах устройства: сервер сам сообщит своё время.
    this.lastPollTs = 0;
    this.seen = new Map();
    // v36: кто из каналов доставил пакет первым и сколько копий пришло
    // впустую — видно, какой путь реально держит звонок (панель статистики).
    this.firstBy = {};
    this.dupBy = {};
    this.closed = false;
    this.onTransportUp = () => {};
  }

  start() {
    this.brokers.forEach((b) => this._mqtt(b));
    if (this.workerUrl) {
      this._ws(0, false);
      // Если через 1.8 с WebSocket к воркеру не поднялся — автоматически включаем резервный HTTP-поллинг
      setTimeout(() => {
        if (!this.closed && this.wsState !== 'up') this._startPoll();
      }, 1800);
    }
    this.relays.forEach((u) => this._nostr(u, 0));
    if (this.ntfyBase) this._ntfy(0);
    this._status();
  }

  _status() {
    const up = this.clients.filter((c) => c.connected).length;
    const nUp = [...this.nostr.values()].filter((w) => w && w.readyState === 1).length;
    this.onStatus?.({
      mqttUp: up,
      mqttTotal: this.clients.length,
      worker: this.wsState,
      workerHttp: this.httpState,
      nostrUp: nUp,
      nostrTotal: this.relays.length,
      ntfyUp: this.ntfyWs && this.ntfyWs.readyState === 1 ? 1 : 0,
      ntfyTotal: this.ntfyBase ? 1 : 0,
    });
  }

  // 1) MQTT поверх WSS.
  // v37: та же защита от ТСПУ-«заморозки» соединения после ~16 КБ, что у
  // Worker и Nostr. Брокер присылает нам и наши собственные публикации, так
  // что счётчик растёт вдвое быстрее, чем кажется. После 9 КБ на сокете
  // поднимаем новое соединение к тому же брокеру и подменяем старое только
  // когда новое подписалось (make-before-break) — без «дыры» в сигнале.
  _mqtt(b, replaces = null) {
    if (typeof mqtt === 'undefined') return null;
    const url = typeof b === 'string' ? b : b.url;
    try {
      const c = mqtt.connect(url, {
        ...(b.username ? { username: b.username, password: b.password } : {}),
        clientId: 'zv_' + Math.random().toString(16).slice(2, 12),
        clean: true,
        keepalive: 30,
        connectTimeout: 7000,
        reconnectPeriod: 3500,
        protocolVersion: 4,
      });
      c._spec = b;
      c._bytes = 0;
      c.on('connect', () => {
        if (this.closed) {
          try { c.end(true); } catch {}
          return;
        }
        c._bytes = 0; // счёт — на каждый новый сокет (в т.ч. после переподключения)
        c._renewing = false;
        c.subscribe(this.mqttTopic, { qos: 0 });
        const old = c._replaces;
        if (old) {
          c._replaces = null;
          old._next = null;
          clearTimeout(c._renewTimer);
          const i = this.clients.indexOf(old);
          if (i >= 0) this.clients[i] = c;
          else this.clients.push(c);
          setTimeout(() => {
            try { old.end(true); } catch {}
          }, 2000);
          this._status();
          return; // канал не пропадал — повторный hello не нужен
        }
        this._status();
        this.onTransportUp();
      });
      c.on('message', (_t, payload) => {
        c._bytes += payload?.length || 0;
        this._recv(payload.toString(), 'mqtt');
        this._mbudget(c);
      });
      ['close', 'offline', 'error', 'reconnect'].forEach((e) => c.on(e, () => this._status()));
      if (replaces) {
        c._replaces = replaces;
        replaces._next = c;
        // Новый сокет не поднялся за 12 с — бросаем его, старый живёт дальше
        // (следующая попытка — при следующем превышении бюджета).
        c._renewTimer = setTimeout(() => {
          if (!c._replaces) return;
          c._replaces = null;
          replaces._next = null;
          replaces._renewing = false;
          try { c.end(true); } catch {}
        }, 12000);
      } else {
        this.clients.push(c);
      }
      return c;
    } catch {
      return null;
    }
  }

  _mbudget(c) {
    if (this.closed || c._renewing || c._replaces || !c.connected || c._bytes <= 9000) return;
    if (!this.clients.includes(c)) return;
    c._renewing = true;
    if (!this._mqtt(c._spec, c)) c._renewing = false;
  }

  // 2) WebSocket к Cloudflare Worker с защитой от ТСПУ-зависания после ~16 КБ (ротация каждые 9 КБ)
  _ws(attempt, isRenew = false) {
    if (this.closed || !this.workerUrl) return;
    const base = this.workerUrl.replace(/^http/, 'ws');
    const qs = `?peer=${encodeURIComponent(this.selfId)}${isRenew ? '&renew=1' : ''}`;
    let ws;
    try {
      ws = new WebSocket(`${base}/room/${this.topic}${qs}`);
    } catch {
      this._startPoll();
      return;
    }
    ws._bytes = 0;
    ws._pongAt = Date.now();
    if (!this.ws || this.ws.readyState !== 1) {
      this.wsState = 'connecting';
      this._status();
    }
    ws.onopen = () => {
      if (this.closed) {
        try { ws.close(); } catch {}
        return;
      }
      const old = this.ws;
      this.ws = ws;
      this.wsAttempt = 0;
      this.wsState = 'up';
      this._stopPoll();
      this._status();
      if (old && old !== ws) {
        old._replaced = true;
        setTimeout(() => {
          try { old.close(); } catch {}
        }, 2000);
      }
      ws._ping = setInterval(() => {
        if (ws.readyState !== 1) return;
        if (Date.now() - ws._pongAt > 18000) {
          try { ws.close(); } catch {}
          return;
        }
        ws.send('ping');
        ws._bytes += 4;
      }, 6500);
      if (!old) this.onTransportUp();
    };
    ws.onmessage = (e) => {
      ws._pongAt = Date.now();
      if (e.data === 'pong') return;
      if (typeof e.data === 'string' && e.data.startsWith('{')) {
        try {
          const sys = JSON.parse(e.data);
          if (sys.type === 'sys:peer_joined') {
            this.onPeerJoined?.();
            return;
          }
        } catch {}
      }
      ws._bytes += (e.data && e.data.length) || 0;
      this._recv(e.data, 'worker');
      this._budget(ws);
    };
    ws.onclose = () => {
      clearInterval(ws._ping);
      if (ws._replaced || this.closed) return;
      if (this.ws && this.ws !== ws) {
        this.ws._renewing = false;
        return;
      }
      this.ws = null;
      this.wsState = 'down';
      this._startPoll(); // Мгновенно подхватываем связь через HTTP-поллинг
      this._status();
      const n = (this.wsAttempt = (this.wsAttempt || 0) + 1);
      setTimeout(() => this._ws(n, false), Math.min(12000, 500 * 2 ** Math.min(n, 5)));
    };
    ws.onerror = () => {};
  }

  _budget(ws) {
    if (ws === this.ws && ws._bytes > 9000 && !ws._renewing) {
      ws._renewing = true;
      this._ws(0, true);
    }
  }

  // 3) Резервный HTTP-поллинг + POST через Cloudflare Worker (когда WebSocket режется провайдером)
  _startPoll() {
    if (this.closed || !this.workerUrl || this.pollTimer) return;
    this.httpState = 'polling';
    this._status();

    const poll = async () => {
      if (this.closed || this.wsState === 'up') {
        this._stopPoll();
        return;
      }
      try {
        const ctl = new AbortController();
        const t = setTimeout(() => ctl.abort(), 4500);
        const url = `${this.workerUrl}/room/${this.topic}?peer=${encodeURIComponent(this.selfId)}&since=${this.lastPollTs}`;
        const r = await fetch(url, { cache: 'no-store', signal: ctl.signal });
        clearTimeout(t);
        if (r.ok) {
          const j = await r.json();
          if (this.httpState !== 'up') {
            this.httpState = 'up';
            this._status();
            this.onTransportUp();
          }
          if (Array.isArray(j.messages)) {
            for (const item of j.messages) {
              if (Number.isFinite(item.ts) && item.ts > this.lastPollTs) this.lastPollTs = item.ts;
              if (item.data) this._recv(item.data, 'worker-http');
            }
          }
          // Курсор ведём по серверным часам — иначе расхождение времени устройства
          // заставляет нас либо запрашивать будущее (пусто), либо перечитывать прошлое.
          if (Number.isFinite(j.now) && j.now > this.lastPollTs) this.lastPollTs = j.now;
        }
      } catch {
        if (this.httpState === 'up') {
          this.httpState = 'polling';
          this._status();
        }
      }
      if (!this.closed && this.wsState !== 'up') {
        this.pollTimer = setTimeout(poll, 1100);
      }
    };
    poll();
  }

  _stopPoll() {
    if (this.pollTimer) {
      clearTimeout(this.pollTimer);
      this.pollTimer = null;
    }
    this.httpState = 'off';
  }

  _httpPost(data) {
    if (!this.workerUrl || this.closed) return;
    fetch(`${this.workerUrl}/room/${this.topic}?peer=${encodeURIComponent(this.selfId)}`, {
      method: 'POST',
      body: data,
      keepalive: data.length < 32000,
    }).catch(() => {});
  }

  // 4) Публичные Nostr-реле (WSS на порту 443)
  _nostr(url, attempt) {
    if (this.closed) return;
    let ws;
    try {
      ws = new WebSocket(url);
    } catch {
      return;
    }
    ws._bytes = 0;
    ws.onopen = () => {
      if (this.closed) {
        try { ws.close(); } catch {}
        return;
      }
      const old = this.nostr.get(url);
      this.nostr.set(url, ws);
      ws._attempt = 0;
      ws.send(
        JSON.stringify([
          'REQ',
          'zv',
          { kinds: [NOSTR_KIND], '#t': [this.ntag], since: Math.floor(Date.now() / 1000) - 60 },
        ])
      );
      if (old && old !== ws) {
        old._replaced = true;
        setTimeout(() => {
          try { old.close(); } catch {}
        }, 2000);
      }
      this._status();
      if (!old) this.onTransportUp();
    };
    ws.onmessage = (e) => {
      ws._bytes += (e.data && e.data.length) || 0;
      let d;
      try {
        d = JSON.parse(e.data);
      } catch {
        return;
      }
      if (d[0] === 'EVENT' && d[2]?.kind === NOSTR_KIND && d[2].pubkey !== this.npk) {
        this._recv(String(d[2].content || ''), 'nostr');
      }
      this._nbudget(url, ws);
    };
    ws.onclose = () => {
      if (ws._replaced || this.closed) return;
      const cur = this.nostr.get(url);
      if (cur && cur !== ws) {
        cur._renewing = false;
        return;
      }
      this.nostr.delete(url);
      this._status();
      setTimeout(() => this._nostr(url, attempt + 1), Math.min(25000, 900 * 2 ** Math.min(attempt, 5)));
    };
    ws.onerror = () => {};
  }

  _nbudget(url, ws) {
    if (this.nostr.get(url) === ws && ws._bytes > 9000 && !ws._renewing) {
      ws._renewing = true;
      this._nostr(url, 0);
    }
  }

  // 5) ntfy.sh — резервный «слепой» pub/sub: подписка по WebSocket,
  // публикация обычным POST (см. send). Канал именно резервный: публичный
  // сервер троттлит по IP, поэтому голосовой мост (_sendVoice, несколько
  // чанков в секунду) через ntfy НЕ ходит — только сигналинг.
  async _ntfyTopic() {
    if (!this.ntfyTopic) this.ntfyTopic = await ntfyTopicForSignaling(this.topic);
    return this.ntfyTopic;
  }

  async _ntfy(attempt) {
    if (this.closed || !this.ntfyBase) return;
    let topic;
    try {
      topic = await this._ntfyTopic();
    } catch {
      return;
    }
    if (this.closed) return;
    let ws;
    try {
      // since пересчитывается на каждое подключение: переподключение
      // не тянет кэш старше 30 секунд.
      ws = new WebSocket(ntfySubscribeUrl(this.ntfyBase, topic));
    } catch {
      return;
    }
    this.ntfyWs = ws;
    ws.onopen = () => {
      if (this.closed) {
        try { ws.close(); } catch {}
        return;
      }
      this._status();
      this.onTransportUp();
    };
    ws.onmessage = (e) => {
      const f = parseNtfyFrame(e.data);
      if (f) this._recv(f.message, 'ntfy');
    };
    ws.onclose = () => {
      if (this.ntfyWs === ws) this.ntfyWs = null;
      this._status();
      if (this.closed) return;
      const n = attempt + 1;
      this.ntfyTimer = setTimeout(() => this._ntfy(n), Math.min(25000, 1200 * 2 ** Math.min(n, 5)));
    };
    ws.onerror = () => {};
  }

  _ntfyPost(data) {
    if (!this.ntfyBase || this.closed || !fitsNtfy(data)) return;
    this._ntfyTopic()
      .then((t) => {
        if (this.closed) return;
        // Троттлинг публичного ntfy (429 по IP) — не ошибка для нас:
        // гонку каналов в этот момент несут MQTT/Nostr/Worker.
        fetch(this.ntfyBase + '/' + t, { method: 'POST', body: data }).catch(() => {});
      })
      .catch(() => {});
  }

  async _nostrEvent(content) {
    const e = {
      pubkey: this.npk,
      created_at: Math.floor(Date.now() / 1000),
      kind: NOSTR_KIND,
      tags: [['t', this.ntag]],
      content,
    };
    const id = new Uint8Array(
      await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]))
      )
    );
    e.id = hexs(id);
    e.sig = hexs(await schnorr.signAsync(id, this.nsk));
    return JSON.stringify(['EVENT', e]);
  }

  // Голосовой чанк: шлём по 1–2 быстрым каналам, без подписи Nostr на каждый чанк
  // (schnorr-подпись на 2–3 чанка в секунду съедает батарею и процессор телефона).
  _sendVoice(data) {
    let sent = false;
    for (const c of this.clients.slice(0, 2)) {
      if (!c.connected) continue;
      try {
        c.publish(this.mqttTopic, data, { qos: 0 });
        c._bytes = (c._bytes || 0) + data.length;
        this._mbudget(c);
        sent = true;
      } catch {}
    }
    const ws = this.ws;
    if (ws?.readyState === 1) {
      try {
        ws.send(data);
        ws._bytes += data.length;
        this._budget(ws);
        sent = true;
      } catch {}
    }
    if (!sent && this.workerUrl) {
      this._httpPost(data);
      sent = true;
    }
    if (!sent) {
      const relay = [...this.nostr.values()].find((w) => w?.readyState === 1);
      if (relay) {
        this._nostrEvent(data)
          .then((ev) => {
            relay.send(ev);
            relay._bytes += ev.length;
            this._nbudget(relay, relay);
          })
          .catch(() => {});
      }
    }
  }

  // Веерная отправка во все активные каналы одновременно
  async send(msg, opts = {}) {
    if (this.closed) return;
    const full = { ...msg, from: this.selfId, inst: this.inst, mid: rid(), ts: Date.now() };
    this.seen.set(full.mid, full.ts);
    const data = await seal(this.key, full, this.topic);

    if (msg.type === 'voice' || opts.voice) {
      this._sendVoice(data);
      return;
    }

    // А) MQTT-брокеры (копия списка: _mbudget может подменить клиента)
    for (const c of [...this.clients]) {
      if (c.connected) {
        try {
          c.publish(this.mqttTopic, data, { qos: 0 });
          c._bytes = (c._bytes || 0) + data.length;
          this._mbudget(c);
        } catch {}
      }
    }

    // Б) Cloudflare Worker WebSocket (или HTTP POST фоллбэк, плюс дублирование критических пакетов рукопожатия)
    const ws = this.ws;
    const isCritical = msg.type === 'hello' || msg.type === 'hi' || msg.type === 'desc' || msg.type === 'bye';
    if (ws && ws.readyState === 1) {
      try {
        ws.send(data);
        ws._bytes += data.length;
        this._budget(ws);
      } catch {
        this._httpPost(data);
      }
      // Критические пакеты рукопожатия также кладем в HTTP-буфер воркера, если сокет близок к лимиту ротации
      if (isCritical && ws._bytes > 7500) {
        this._httpPost(data);
      }
    } else if (this.workerUrl) {
      this._httpPost(data);
    }

    // В) Nostr-реле (для голосовых чанков отправляем максимум в 2 быстрых реле, чтобы не забивать эфир)
    const nopen = [...this.nostr.entries()].filter(([, w]) => w.readyState === 1);
    if (nopen.length) {
      try {
        const targets = msg.type === 'voice' ? nopen.slice(0, 2) : nopen;
        const ev = await this._nostrEvent(data);
        for (const [url, w] of targets) {
          w.send(ev);
          w._bytes += ev.length;
          this._nbudget(url, w);
        }
      } catch (e) {
        console.warn('nostr', e);
      }
    }

    // Г) ntfy.sh — POST тем же запечатанным конвертом, байт-в-байт как в MQTT
    if (this.ntfyBase && ntfyWanted(msg.type, this.ntfyState)) this._ntfyPost(data);
  }

  // Мгновенный сигнал выхода при закрытии вкладки на смартфоне/ПК
  async sendByeBeacon() {
    if (!this.workerUrl || !navigator.sendBeacon) return;
    try {
      const full = { type: 'bye', from: this.selfId, inst: this.inst, mid: rid(), ts: Date.now() };
      const data = await seal(this.key, full, this.topic);
      navigator.sendBeacon(
        `${this.workerUrl}/room/${this.topic}?peer=${encodeURIComponent(this.selfId)}`,
        data
      );
    } catch {}
  }

  async _recv(raw, via) {
    // v41: после close() ничего не доставляем — ни из сокетов, которые ещё
    // досылают (Nostr-реле, заменяемые соединения), ни после расшифровки.
    if (this.closed || !raw || typeof raw !== 'string' || raw.length > 220000) return;
    let m;
    try {
      m = await open(this.key, raw, this.topic);
    } catch {
      return;
    }
    if (this.closed || !m || m.from === this.selfId) return;
    if (m.to && m.to !== this.selfId) return;
    if (m.toInst && m.toInst !== this.inst) return;
    // Раньше здесь отбрасывались пакеты старше 12 часов — при сбитых часах
    // устройства это ломало соединение целиком. Свежесть ограничивает сам транспорт.
    if (!m.mid) return;
    if (this.seen.has(m.mid)) {
      this.dupBy[via] = (this.dupBy[via] || 0) + 1;
      return;
    }
    this.seen.set(m.mid, Date.now());
    this.firstBy[via] = (this.firstBy[via] || 0) + 1;
    if (this.seen.size > 2500) {
      const now = Date.now();
      for (const [k, t] of this.seen) if (now - t > 300000) this.seen.delete(k);
    }
    m.via = via;
    this.onMessage(m);
  }

  /** Счётчики доставки по каналам: { first: {via: n}, dup: {via: n} }. */
  deliveryStats() {
    return { first: { ...this.firstBy }, dup: { ...this.dupBy } };
  }

  close() {
    this.closed = true;
    this._stopPoll();
    if (this.ntfyTimer) {
      clearTimeout(this.ntfyTimer);
      this.ntfyTimer = null;
    }
    this.clients.forEach((c) => {
      if (c._next) clearTimeout(c._next._renewTimer);
      try { c._next?.end(true); } catch {}
      try { c.end(true); } catch {}
    });
    try { this.ws?.close(); } catch {}
    for (const w of this.nostr.values()) {
      try { w.close(); } catch {}
    }
    try { this.ntfyWs?.close(); } catch {}
  }
}
