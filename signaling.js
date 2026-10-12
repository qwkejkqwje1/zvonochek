// Два независимых канала сигналинга, работающих одновременно:
//   1) публичные MQTT-брокеры (без своего сервера)
//   2) Cloudflare Worker (WebSocket), если задан WORKER_URL
// Каждое сообщение зашифровано AES-256-GCM и отправляется во все каналы,
// получатель удаляет дубли. Брокеры и Worker видят только шифротекст.
import { seal, open } from './crypto.js?v=7';
import { schnorr, utils } from './vendor/secp256k1.js?v=7';

const hexs = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const NOSTR_KIND = 29333; // эфемерные события: реле их не хранят, только пересылают

const rid = () => crypto.getRandomValues(new Uint32Array(2)).join('-');

export class Signaling {
  constructor({ topic, key, selfId, inst, brokers, workerUrl, relays, onMessage, onStatus }) {
    Object.assign(this, { topic, key, selfId, inst, brokers, workerUrl, onMessage, onStatus });
    this.relays = relays || [];
    this.nostr = new Map(); // url -> текущий сокет
    this.nsk = utils.randomSecretKey();
    this.npk = hexs(schnorr.getPublicKey(this.nsk));
    this.ntag = 'zv-' + topic;
    this.mqttTopic = `zvonochek/v1/${topic}`;
    this.clients = [];
    this.ws = null;
    this.wsState = workerUrl ? 'connecting' : 'off';
    this.seen = new Map();
    this.closed = false;
    this.onTransportUp = () => {};
  }

  start() {
    this.brokers.forEach((url) => this._mqtt(url));
    if (this.workerUrl) this._ws(0);
    this.relays.forEach((u) => this._nostr(u, 0));
    this._status();
  }

  _status() {
    const up = this.clients.filter((c) => c.connected).length;
    const nUp = [...this.nostr.values()].filter((w) => w && w.readyState === 1).length;
    this.onStatus?.({ mqttUp: up, mqttTotal: this.clients.length, worker: this.wsState, nostrUp: nUp, nostrTotal: this.relays.length });
  }

  _mqtt(b) {
    if (typeof mqtt === 'undefined') return;
    const url = typeof b === 'string' ? b : b.url;
    const c = mqtt.connect(url, {
      ...(b.username ? { username: b.username, password: b.password } : {}),
      clientId: 'zv_' + Math.random().toString(16).slice(2, 12),
      clean: true, keepalive: 30, connectTimeout: 8000, reconnectPeriod: 4000, protocolVersion: 4,
    });
    c.on('connect', () => {
      c.subscribe(this.mqttTopic, { qos: 0 });
      this._status();
      this.onTransportUp();
    });
    c.on('message', (_t, payload) => this._recv(payload.toString(), 'mqtt'));
    ['close', 'offline', 'error', 'reconnect'].forEach((e) => c.on(e, () => this._status()));
    this.clients.push(c);
  }

  // WebSocket к Worker. Некоторые провайдеры «замораживают» соединения с Cloudflare
  // после ~16 КБ данных, поэтому: (1) следим за pong и переподключаемся при зависании;
  // (2) заранее открываем новое соединение после ~9 КБ трафика (старое закрываем позже).
  _ws(attempt) {
    if (this.closed) return;
    const base = this.workerUrl.replace(/^http/, 'ws').replace(/\/$/, '');
    let ws;
    try { ws = new WebSocket(`${base}/room/${this.topic}`); } catch { return; }
    ws._bytes = 0; ws._pongAt = Date.now();
    if (!this.ws || this.ws.readyState !== 1) { this.wsState = 'connecting'; this._status(); }
    ws.onopen = () => {
      const old = this.ws;
      this.ws = ws; this.wsAttempt = 0;
      this.wsState = 'up'; this._status();
      if (old && old !== ws) { old._replaced = true; setTimeout(() => { try { old.close(); } catch {} }, 2000); }
      ws._ping = setInterval(() => {
        if (ws.readyState !== 1) return;
        if (Date.now() - ws._pongAt > 20000) { try { ws.close(); } catch {} return; } // зависло
        ws.send('ping'); ws._bytes += 4;
      }, 7000);
      if (!old) this.onTransportUp();
    };
    ws.onmessage = (e) => {
      ws._pongAt = Date.now();
      if (e.data === 'pong') return;
      ws._bytes += e.data.length;
      this._recv(e.data, 'worker');
      this._budget(ws);
    };
    ws.onclose = () => {
      clearInterval(ws._ping);
      if (ws._replaced || this.closed) return;
      if (this.ws && this.ws !== ws) { this.ws._renewing = false; return; } // не удалось обновить — живём на старом
      this.ws = null;
      this.wsState = 'down'; this._status();
      const n = (this.wsAttempt = (this.wsAttempt || 0) + 1);
      setTimeout(() => this._ws(n), Math.min(15000, 500 * 2 ** n));
    };
    ws.onerror = () => {};
  }

  _budget(ws) {
    if (ws === this.ws && ws._bytes > 9000 && !ws._renewing) { ws._renewing = true; this._ws(0); }
  }

  // Способ №3: публичные Nostr-реле (WSS на 443). Сообщение = подписанное эфемерное событие.
  _nostr(url, attempt) {
    if (this.closed) return;
    let ws;
    try { ws = new WebSocket(url); } catch { return; }
    ws._bytes = 0;
    ws.onopen = () => {
      const old = this.nostr.get(url);
      this.nostr.set(url, ws);
      ws._attempt = 0;
      ws.send(JSON.stringify(['REQ', 'zv', { kinds: [NOSTR_KIND], '#t': [this.ntag], since: Math.floor(Date.now() / 1000) - 60 }]));
      if (old && old !== ws) { old._replaced = true; setTimeout(() => { try { old.close(); } catch {} }, 2000); }
      this._status();
      if (!old) this.onTransportUp();
    };
    ws.onmessage = (e) => {
      ws._bytes += e.data.length;
      let d; try { d = JSON.parse(e.data); } catch { return; }
      if (d[0] === 'EVENT' && d[2]?.kind === NOSTR_KIND && d[2].pubkey !== this.npk) this._recv(String(d[2].content || ''), 'nostr');
      this._nbudget(url, ws);
    };
    ws.onclose = () => {
      if (ws._replaced || this.closed) return;
      const cur = this.nostr.get(url);
      if (cur && cur !== ws) { cur._renewing = false; return; }
      this.nostr.delete(url); this._status();
      setTimeout(() => this._nostr(url, attempt + 1), Math.min(30000, 1000 * 2 ** attempt));
    };
    ws.onerror = () => {};
  }
  _nbudget(url, ws) {
    if (this.nostr.get(url) === ws && ws._bytes > 9000 && !ws._renewing) { ws._renewing = true; this._nostr(url, 0); }
  }
  async _nostrEvent(content) {
    const e = { pubkey: this.npk, created_at: Math.floor(Date.now() / 1000), kind: NOSTR_KIND, tags: [['t', this.ntag]], content };
    const id = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content])))) ;
    e.id = hexs(id);
    e.sig = hexs(await schnorr.signAsync(id, this.nsk));
    return JSON.stringify(['EVENT', e]);
  }

  async send(msg) {
    const full = { ...msg, from: this.selfId, inst: this.inst, mid: rid(), ts: Date.now() };
    const data = await seal(this.key, full, this.topic);
    for (const c of this.clients) if (c.connected) c.publish(this.mqttTopic, data, { qos: 0 });
    const ws = this.ws;
    if (ws && ws.readyState === 1) { ws.send(data); ws._bytes += data.length; this._budget(ws); }
    const nopen = [...this.nostr.entries()].filter(([, w]) => w.readyState === 1);
    if (nopen.length) {
      try {
        const ev = await this._nostrEvent(data);
        for (const [url, w] of nopen) { w.send(ev); w._bytes += ev.length; this._nbudget(url, w); }
      } catch (e) { console.warn('nostr', e); }
    }
  }

  async _recv(raw, via) {
    if (raw.length > 200000) return;
    const m = await open(this.key, raw, this.topic);
    if (!m || m.from === this.selfId) return;
    if (m.to && m.to !== this.selfId) return;
    if (m.toInst && m.toInst !== this.inst) return;
    if (Math.abs(Date.now() - m.ts) > 12 * 3600 * 1000) return; // старые сообщения (часы на телефонах бывают неточными)
    if (this.seen.has(m.mid)) return;
    this.seen.set(m.mid, Date.now());
    if (this.seen.size > 2000) for (const [k, t] of this.seen) if (Date.now() - t > 300000) this.seen.delete(k);
    m.via = via;
    this.onMessage(m);
  }

  close() {
    this.closed = true;
    this.clients.forEach((c) => { try { c.end(true); } catch {} });
    try { this.ws?.close(); } catch {}
    for (const w of this.nostr.values()) { try { w.close(); } catch {} }
  }
}
