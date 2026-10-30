// ZVONochek v28 — транспортный слой приватного чата.
//
// Интерфейс транспорта намеренно узкий: { kind, send(blob), fetchSince(cursor),
// subscribe(cb), close() }. WorkerTransport ниже — адаптер к функциям,
// которые предоставляет chat.js (его HTTP/WS-шов исторически живёт там),
// FallbackTransport — полностью автономный резервный канал: MQTT (только
// live) + Nostr kind 1 (хранимая лента). Fallback не знает ни ключей комнат,
// ни plaintext: на входе и выходе только тот же base64-шифротекст blob,
// который ходит в Worker.
//
// Чистые функции этого модуля (топики, события Nostr, слияние лент, решения
// об уведомлениях, реестр увиденных устройств, менеджер каналов) покрыты
// Node-тестами test-v28.mjs: chat.js при импорте трогает DOM и в тестах не
// поднимается.
import { b64u, sha256hex } from './crypto.js?v=28';
import { schnorr } from './vendor/secp256k1.js';

const te = new TextEncoder();
export const bytesToHex = (bytes) =>
  [...new Uint8Array(bytes)].map((x) => x.toString(16).padStart(2, '0')).join('');
export const hexToBytes = (hex) => {
  const s = String(hex || '');
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(s)) throw new Error('bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
};

// ---------- Адреса резервного канала ----------
// roomId и так известен серверу воркера, но публичным брокерам/релеям мы его
// не показываем: наружу уходит только SHA-256(roomId) hex.
export async function chatRoomHash(roomId) {
  return sha256hex(String(roomId));
}

export async function mqttTopicForRoom(roomId) {
  return 'zvchat1/' + (await chatRoomHash(roomId));
}

export const NOSTR_CHAT_KIND = 1;
export const NOSTR_CHAT_TAG = 'zvchat1';

export function nostrFiltersForRoom(roomHash, sinceSec = 0) {
  const base = { kinds: [NOSTR_CHAT_KIND], '#t': [NOSTR_CHAT_TAG] };
  if (sinceSec > 0) base.since = Math.floor(sinceSec);
  // Первый фильтр — точный (по хэшу комнаты в теге z). Не все реле умеют
  // индексировать произвольный тег z, поэтому вторым фильтром просим ленту
  // по t и фильтруем по z уже на клиенте (parse/verify ниже это делает).
  return [{ ...base, '#z': [roomHash] }, { ...base }];
}

export function nostrEventIdBytes(event) {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);
  return crypto.subtle.digest('SHA-256', te.encode(serialized)).then((h) => new Uint8Array(h));
}

function secretBytes(secret) {
  if (secret instanceof Uint8Array) return secret;
  if (typeof secret === 'string' && /^[0-9a-fA-F]{64}$/.test(secret)) return hexToBytes(secret);
  if (typeof secret === 'string') return b64u.dec(secret);
  throw new Error('nostr secret: нужны 32 байта');
}

export async function nostrPublicKeyHex(secret) {
  return bytesToHex(schnorr.getPublicKey(secretBytes(secret)));
}

export async function createNostrEvent({ secret, roomHash, blob, createdAt }) {
  const sec = secretBytes(secret);
  const pubkey = bytesToHex(schnorr.getPublicKey(sec));
  const ts = Math.floor(createdAt || Date.now() / 1000);
  const event = {
    pubkey,
    created_at: ts,
    kind: NOSTR_CHAT_KIND,
    tags: [
      ['t', NOSTR_CHAT_TAG],
      ['z', roomHash],
      // 's' — подсказка порядка ленты (ts события): у резервного канала нет
      // серверного seq, лента сортируется по этому полю и по ts сообщения.
      ['s', String(ts)],
    ],
    content: String(blob),
  };
  const id = await nostrEventIdBytes(event);
  event.id = bytesToHex(id);
  event.sig = bytesToHex(await schnorr.signAsync(id, sec));
  return event;
}

export async function verifyNostrEvent(event, roomHash = null) {
  try {
    if (!event || event.kind !== NOSTR_CHAT_KIND || typeof event.content !== 'string') return false;
    if (!/^[0-9a-f]{64}$/.test(event.id || '') || !/^[0-9a-f]{64}$/.test(event.pubkey || '')) return false;
    if (!/^[0-9a-f]{128}$/.test(event.sig || '')) return false;
    const tags = new Map();
    for (const t of event.tags || []) if (Array.isArray(t) && t.length >= 2) tags.set(t[0], t[1]);
    if (tags.get('t') !== NOSTR_CHAT_TAG) return false;
    if (roomHash && tags.get('z') !== roomHash) return false;
    const id = await nostrEventIdBytes(event);
    if (bytesToHex(id) !== event.id) return false;
    return await schnorr.verifyAsync(hexToBytes(event.sig), id, hexToBytes(event.pubkey));
  } catch {
    return false;
  }
}

export function parseNostrRelayMessage(data) {
  try {
    const arr = typeof data === 'string' ? JSON.parse(data) : data;
    if (!Array.isArray(arr)) return null;
    if (arr[0] === 'EVENT' && arr[2] && typeof arr[2] === 'object') {
      return { type: 'event', subId: arr[1], event: arr[2] };
    }
    if (arr[0] === 'EOSE') return { type: 'eose', subId: arr[1] };
    if (arr[0] === 'CLOSED') return { type: 'closed', subId: arr[1], reason: arr[2] || '' };
    if (arr[0] === 'NOTICE') return { type: 'notice', message: arr[1] || '' };
    return { type: String(arr[0] || 'unknown') };
  } catch {
    return null;
  }
}

// ---------- Слияние лент и порядок ----------
// У сообщений основного канала есть серверный seq; у fallback-сообщений его
// нет до ресинка. Сортировка: сначала всё с seq по seq, затем бес-seq по
// (ts, hash). Дубли — по хэшу blob; версия с seq побеждает версию без него.
export function compareChatEntries(a, b) {
  const sa = Number.isFinite(a?.seq) ? a.seq : null;
  const sb = Number.isFinite(b?.seq) ? b.seq : null;
  if (sa !== null && sb !== null && sa !== sb) return sa - sb;
  if (sa !== null && sb === null) return -1;
  if (sa === null && sb !== null) return 1;
  const ta = a?.msg?.ts || a?.ts || 0;
  const tb = b?.msg?.ts || b?.ts || 0;
  if (ta !== tb) return ta - tb;
  return String(a?.hash || '').localeCompare(String(b?.hash || ''));
}

export function sortChatItems(items) {
  return [...items].sort(compareChatEntries);
}

export function mergeChatItems(existing, incoming) {
  const byHash = new Map();
  for (const it of [...(existing || []), ...(incoming || [])]) {
    if (!it?.hash) continue;
    const prev = byHash.get(it.hash);
    if (!prev || (Number.isFinite(it.seq) && !Number.isFinite(prev.seq))) byHash.set(it.hash, it);
  }
  return sortChatItems([...byHash.values()]);
}

// ---------- Уведомления: чистое решение и троттлинг ----------
// Показываем тост, если сообщение не моё и комната сейчас не перед глазами:
// либо открыта другая комната/экран, либо вкладка скрыта. Системное
// уведомление (showNotification) — только когда документ скрыт.
export function shouldNotifyMessage({
  mine = false,
  roomActive = false,
  documentHidden = false,
  now = Date.now(),
  lastShownAt = 0,
  minIntervalMs = 2000,
} = {}) {
  if (mine) return { show: false, system: false, reason: 'mine' };
  if (roomActive && !documentHidden) return { show: false, system: false, reason: 'active' };
  // lastShownAt=0 — «ещё ни разу не показывали»: троттлинг не применяется.
  if (lastShownAt > 0 && now - lastShownAt < minIntervalMs) {
    return { show: false, system: false, reason: 'throttled' };
  }
  return { show: true, system: !!documentHidden, reason: 'inactive' };
}

export class ToastGate {
  constructor(minIntervalMs = 2000) {
    this.minIntervalMs = minIntervalMs;
    this.lastByRoom = new Map();
    this.pendingByRoom = new Map();
  }
  check(roomId, opts = {}) {
    const now = opts.now || Date.now();
    const last = this.lastByRoom.get(roomId) || 0;
    const d = shouldNotifyMessage({ ...opts, now, lastShownAt: last, minIntervalMs: this.minIntervalMs });
    if (d.show) {
      const count = (this.pendingByRoom.get(roomId) || 0) + 1;
      this.pendingByRoom.set(roomId, 0);
      this.lastByRoom.set(roomId, now);
      return { ...d, count };
    }
    if (d.reason === 'throttled') {
      this.pendingByRoom.set(roomId, (this.pendingByRoom.get(roomId) || 0) + 1);
    }
    return d;
  }
}

// ---------- Реестр увиденных устройств комнаты ----------
// seen: { dev: {firstSeen, lastSeen, hasIntro, alerted} }. silent=true —
// историческая подгрузка (уже известные участники не должны поднимать
// тревогу при первом открытии комнаты клиентом v28).
export function observeDevice(seen, dev, { hasIntro = false, now = Date.now(), silent = false } = {}) {
  const out = { ...(seen || {}) };
  if (!dev || typeof dev !== 'string') return { seen: out, isNew: false, shouldAlert: false, anonymous: false };
  const prev = out[dev];
  const isNew = !prev;
  const mergedHasIntro = !!(prev?.hasIntro || hasIntro);
  out[dev] = {
    firstSeen: prev?.firstSeen || now,
    lastSeen: now,
    hasIntro: mergedHasIntro,
    alerted: !!(prev?.alerted || (isNew && !silent)),
  };
  return { seen: out, isNew, shouldAlert: isNew && !silent, anonymous: !mergedHasIntro };
}

// ---------- Статусы прочтения (для галочек) ----------
export function receiptState(entry, receipts, others) {
  if (!entry || !Number.isFinite(entry.seq)) return entry?.pendingWorkerSync ? 'pending' : 'local';
  const list = others || [];
  if (!list.length) return 'sent';
  const get = (dev) => {
    const r = receipts instanceof Map ? receipts.get(dev) : receipts?.[dev];
    return { delivered: r?.delivered || 0, read: r?.read || 0 };
  };
  if (list.every((d) => get(d).read >= entry.seq)) return 'read';
  if (list.some((d) => get(d).delivered >= entry.seq)) return 'delivered';
  return 'sent';
}

export const RECEIPT_GLYPHS = { local: '✓', pending: '✓', sent: '✓', delivered: '✓✓', read: '✓✓' };
export const RECEIPT_LABELS = {
  local: 'Отправлено',
  pending: 'Отправлено · ждёт основной сервер',
  sent: 'Отправлено',
  delivered: 'Доставлено',
  read: 'Прочитано',
};

// ---------- Менеджер каналов ----------
export class ChatTransportManager {
  constructor({ worker, fallback, thresholdMs = 8000, onModeChange, onResync, nowFn } = {}) {
    this.worker = worker || null;
    this.fallback = fallback || null;
    this.thresholdMs = thresholdMs;
    this.onModeChange = onModeChange || (() => {});
    this.onResync = onResync || (async () => {});
    this.nowFn = nowFn || (() => Date.now());
    this.mode = 'worker';
    this.workerDownSince = null;
    this.switching = false;
  }
  get kind() {
    return this.mode;
  }
  async noteWorkerFailure(now = this.nowFn()) {
    if (this.workerDownSince == null) this.workerDownSince = now;
    if (
      this.mode === 'worker' &&
      this.fallback &&
      now - this.workerDownSince >= this.thresholdMs &&
      !this.switching
    ) {
      this.switching = true;
      try {
        await this.fallback.start?.();
        this.mode = 'fallback';
        this.onModeChange('fallback');
      } finally {
        this.switching = false;
      }
    }
    return this.mode;
  }
  async noteWorkerSuccess(now = this.nowFn()) {
    this.workerDownSince = null;
    if (this.mode === 'fallback' && !this.switching) {
      this.switching = true;
      this.mode = 'resync';
      this.onModeChange('resync');
      try {
        await this.onResync();
        await this.fallback?.close?.();
        this.mode = 'worker';
        this.onModeChange('worker');
      } catch (e) {
        // Ресинк не удался — остаёмся на резервном канале, воркер попробуем
        // снова при следующем успешном health.
        this.mode = 'fallback';
        this.onModeChange('fallback');
        throw e;
      } finally {
        this.switching = false;
      }
    }
    return this.mode;
  }
  async checkHealth(healthOk, now = this.nowFn()) {
    return healthOk ? this.noteWorkerSuccess(now) : this.noteWorkerFailure(now);
  }
  async send(blob) {
    const t = this.mode === 'fallback' ? this.fallback : this.worker;
    if (!t) throw new Error('нет активного транспорта чата');
    return t.send(blob);
  }
  async fetchSince(cursor) {
    const t = this.mode === 'fallback' ? this.fallback : this.worker;
    if (!t?.fetchSince) return [];
    return t.fetchSince(cursor);
  }
  close() {
    try {
      this.worker?.close?.();
    } catch {}
    try {
      this.fallback?.close?.();
    } catch {}
  }
}

// Адаптер основного канала. Реальные send/fetch/subscribe предоставляет
// chat.js (его api() и WebSocket), здесь — только форма интерфейса.
export class WorkerTransport {
  constructor(handlers = {}) {
    this.kind = 'worker';
    this.handlers = handlers;
  }
  async send(blob) {
    if (!this.handlers.send) throw new Error('WorkerTransport: нет send');
    return this.handlers.send(blob);
  }
  async fetchSince(cursor) {
    if (!this.handlers.fetchSince) return [];
    return this.handlers.fetchSince(cursor);
  }
  subscribe(cb) {
    return this.handlers.subscribe ? this.handlers.subscribe(cb) : () => {};
  }
  close() {
    this.handlers.close?.();
  }
}

// ---------- Резервный канал: MQTT live + Nostr store ----------
export class FallbackTransport {
  constructor({
    roomId,
    brokers = [],
    relays = [],
    secret,
    onBlob,
    onStatus,
    mqttConnect,
    webSocketFactory,
    historyTimeoutMs = 1500,
  } = {}) {
    this.kind = 'fallback';
    this.roomId = roomId;
    this.brokers = brokers;
    this.relays = relays.slice(0, 3);
    this.secret = secret;
    this.onBlob = onBlob || (() => {});
    this.onStatus = onStatus || (() => {});
    this.mqttConnect = mqttConnect || ((url, opts) => globalThis.mqtt?.connect(url, opts));
    this.webSocketFactory = webSocketFactory || ((url) => new WebSocket(url));
    this.historyTimeoutMs = historyTimeoutMs;
    this.roomHash = null;
    this.topic = null;
    this.pubkey = null;
    this.mqttClients = [];
    this.sockets = new Map(); // url -> ws
    this.historyWaiters = new Map(); // subId -> {resolve, events, eose:Set}
    this.closed = false;
    this.started = false;
  }

  async start() {
    if (this.started) return this;
    this.started = true;
    this.roomHash = await chatRoomHash(this.roomId);
    this.topic = await mqttTopicForRoom(this.roomId);
    if (this.secret) this.pubkey = await nostrPublicKeyHex(this.secret);
    for (const b of this.brokers) this._connectMqtt(b);
    for (const url of this.relays) this._connectRelay(url);
    return this;
  }

  _connectMqtt(broker) {
    const url = typeof broker === 'string' ? broker : broker?.url;
    if (!url || typeof this.mqttConnect !== 'function') return;
    let client;
    try {
      client = this.mqttConnect(url, {
        ...(broker?.username ? { username: broker.username, password: broker.password } : {}),
        clientId: 'zvchat_' + Math.random().toString(16).slice(2, 12),
        clean: true,
        keepalive: 30,
        connectTimeout: 7000,
        reconnectPeriod: 3500,
        protocolVersion: 4,
      });
    } catch {
      return;
    }
    if (!client?.on) return;
    client.on('connect', () => {
      try {
        client.subscribe(this.topic, { qos: 1 });
      } catch {}
      this.onStatus({ mqtt: true });
    });
    client.on('message', (topic, payload) => {
      if (topic !== this.topic || this.closed) return;
      const blob = typeof payload === 'string' ? payload : payload?.toString?.();
      if (blob) this.onBlob(blob, { via: 'mqtt' });
    });
    this.mqttClients.push(client);
  }

  _connectRelay(url) {
    let ws;
    try {
      ws = this.webSocketFactory(url);
    } catch {
      return;
    }
    if (!ws) return;
    this.sockets.set(url, ws);
    const sendReq = (subId, sinceSec) => {
      try {
        ws.send(JSON.stringify(['REQ', subId, ...nostrFiltersForRoom(this.roomHash, sinceSec)]));
      } catch {}
    };
    ws.onopen = () => {
      if (this.closed) return;
      sendReq('live', Math.floor(Date.now() / 1000) - 3600);
      // Подхватываем ожидающие историю запросы, если fetchSince звали рано.
      for (const [subId, w] of this.historyWaiters) sendReq(subId, w.sinceSec || 0);
    };
    ws.onmessage = async (e) => {
      const parsed = parseNostrRelayMessage(e.data);
      if (!parsed) return;
      if (parsed.type === 'event') {
        const ev = parsed.event;
        if (!(await verifyNostrEvent(ev, this.roomHash))) return;
        if (parsed.subId === 'live') {
          this.onBlob(ev.content, { via: 'nostr', ts: ev.created_at * 1000, event: ev });
        } else if (this.historyWaiters.has(parsed.subId)) {
          this.historyWaiters.get(parsed.subId).events.push(ev);
        }
      } else if (parsed.type === 'eose' && this.historyWaiters.has(parsed.subId)) {
        const w = this.historyWaiters.get(parsed.subId);
        w.eose.add(url);
        if (w.eose.size >= this.sockets.size) w.finish();
      }
    };
    ws.onclose = () => {
      if (this.sockets.get(url) === ws) this.sockets.delete(url);
    };
    ws.onerror = () => {};
  }

  async publish(blob) {
    return this.send(blob);
  }

  async send(blob) {
    if (!this.started) await this.start();
    const payload = String(blob);
    let mqttSent = 0;
    for (const c of this.mqttClients) {
      if (c?.connected) {
        try {
          c.publish(this.topic, payload, { qos: 1 });
          mqttSent++;
        } catch {}
      }
    }
    let nostrSent = 0;
    if (this.secret) {
      const ev = await createNostrEvent({ secret: this.secret, roomHash: this.roomHash, blob: payload });
      const frame = JSON.stringify(['EVENT', ev]);
      for (const ws of this.sockets.values()) {
        if (ws?.readyState === 1) {
          try {
            ws.send(frame);
            nostrSent++;
          } catch {}
        }
      }
    }
    if (!mqttSent && !nostrSent) throw new Error('резервный канал: нет живых брокеров/реле');
    return { via: 'fallback', mqttSent, nostrSent, pendingWorkerSync: true };
  }

  // Хранимая лента Nostr: REQ с since по открытым реле, ждём EOSE или
  // таймаут. MQTT истории не имеет — он только live.
  async fetchSince(cursorSec = 0) {
    if (!this.started) await this.start();
    const open = [...this.sockets.values()].filter((w) => w?.readyState === 1);
    if (!open.length) return [];
    const subId = 'hist' + Math.random().toString(16).slice(2, 10);
    return new Promise((resolve) => {
      const waiter = {
        sinceSec: Math.floor(cursorSec || 0),
        events: [],
        eose: new Set(),
        finish: () => {
          clearTimeout(timer);
          this.historyWaiters.delete(subId);
          try {
            for (const ws of open) ws.send(JSON.stringify(['CLOSE', subId]));
          } catch {}
          const sorted = waiter.events.sort((a, b) => a.created_at - b.created_at);
          resolve(sorted.map((ev) => ({ blob: ev.content, ts: ev.created_at * 1000, event: ev })));
        },
      };
      const timer = setTimeout(() => waiter.finish(), this.historyTimeoutMs);
      this.historyWaiters.set(subId, waiter);
      for (const ws of open) {
        try {
          ws.send(JSON.stringify(['REQ', subId, ...nostrFiltersForRoom(this.roomHash, waiter.sinceSec)]));
        } catch {}
      }
    });
  }

  subscribe(cb) {
    const prev = this.onBlob;
    this.onBlob = (blob, meta) => {
      prev(blob, meta);
      cb(blob, meta);
    };
    return () => {
      this.onBlob = prev;
    };
  }

  async close() {
    this.closed = true;
    for (const c of this.mqttClients) {
      try {
        c.end?.(true);
      } catch {}
    }
    this.mqttClients = [];
    for (const ws of this.sockets.values()) {
      try {
        ws.close();
      } catch {}
    }
    this.sockets.clear();
    this.started = false;
  }
}
