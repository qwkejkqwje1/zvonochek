// Два независимых канала сигналинга, работающих одновременно:
//   1) публичные MQTT-брокеры (без своего сервера)
//   2) Cloudflare Worker (WebSocket), если задан WORKER_URL
// Каждое сообщение зашифровано AES-256-GCM и отправляется во все каналы,
// получатель удаляет дубли. Брокеры и Worker видят только шифротекст.
import { seal, open } from './crypto.js';

const rid = () => crypto.getRandomValues(new Uint32Array(2)).join('-');

export class Signaling {
  constructor({ topic, key, selfId, inst, brokers, workerUrl, onMessage, onStatus }) {
    Object.assign(this, { topic, key, selfId, inst, brokers, workerUrl, onMessage, onStatus });
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
    this._status();
  }

  _status() {
    const up = this.clients.filter((c) => c.connected).length;
    this.onStatus?.({ mqttUp: up, mqttTotal: this.clients.length, worker: this.wsState });
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

  async send(msg) {
    const full = { ...msg, from: this.selfId, inst: this.inst, mid: rid(), ts: Date.now() };
    const data = await seal(this.key, full, this.topic);
    for (const c of this.clients) if (c.connected) c.publish(this.mqttTopic, data, { qos: 0 });
    const ws = this.ws;
    if (ws && ws.readyState === 1) { ws.send(data); ws._bytes += data.length; this._budget(ws); }
  }

  async _recv(raw, via) {
    if (raw.length > 200000) return;
    const m = await open(this.key, raw, this.topic);
    if (!m || m.from === this.selfId) return;
    if (m.to && m.to !== this.selfId) return;
    if (m.toInst && m.toInst !== this.inst) return;
    if (Math.abs(Date.now() - m.ts) > 10 * 60 * 1000) return; // защита от повторов старых сообщений
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
  }
}
