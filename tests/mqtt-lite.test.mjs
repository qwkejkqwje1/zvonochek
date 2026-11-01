// v36: mqtt-lite — кодек пакетов MQTT 3.1.1 и поведение клиента на фейковом WebSocket.
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadScript } from './helpers.mjs';

class FakeWS {
  static all = [];
  constructor(url, proto) { this.url = url; this.proto = proto; this.readyState = 0; this.sent = []; FakeWS.all.push(this); }
  send(b) { this.sent.push(new Uint8Array(b)); }
  close() { if (this.readyState === 3) return; this.readyState = 3; setTimeout(() => this.onclose && this.onclose(), 0); }
  open() { this.readyState = 1; this.onopen && this.onopen(); }
  feed(bytes) { this.onmessage && this.onmessage({ data: new Uint8Array(bytes).buffer }); }
}
globalThis.WebSocket = FakeWS;
const mqtt = loadScript('mqtt-lite.js').mqtt;
const C = mqtt._codec;
const te = new TextEncoder();
const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

test('Remaining Length: граничные значения спецификации', () => {
  const cases = [[0, [0]], [127, [0x7f]], [128, [0x80, 0x01]], [16383, [0xff, 0x7f]], [16384, [0x80, 0x80, 0x01]], [2097151, [0xff, 0xff, 0x7f]]];
  for (const [n, bytes] of cases) assert.deepEqual([...C.encodeLength(n)], bytes, 'n=' + n);
});

test('CONNECT: имя протокола, уровень 4, флаги clean/username/password', () => {
  const p = C.encodeConnect({ clientId: 'zv', username: 'public', password: 'public', clean: true, keepalive: 30 });
  assert.equal(p[0], 0x10);
  const body = p.subarray(2);
  assert.deepEqual([...body.subarray(0, 6)], [0, 4, 0x4d, 0x51, 0x54, 0x54]); // "MQTT"
  assert.equal(body[6], 4);
  assert.equal(body[7], 0x80 | 0x40 | 0x02);
  assert.deepEqual([...body.subarray(8, 10)], [0, 30]);
});

test('PUBLISH: кодирование и разбор QoS 0 и QoS 1 (UTF-8)', () => {
  for (const qos of [0, 1]) {
    const bytes = C.encodePublish('a/б', 'привет', qos, 513);
    const pk = C.takePacket(bytes);
    assert.equal(pk.type, 3);
    const m = C.decodePublish(pk);
    assert.equal(m.topic, 'a/б');
    assert.equal(m.qos, qos);
    if (qos) assert.equal(m.id, 513);
    assert.equal(m.payload.toString(), 'привет');
    assert.equal(pk.rest.length, 0);
  }
});

test('поток: два пакета в одном кадре и пакет, разрезанный на части', () => {
  const a = C.encodePublish('t', 'x'.repeat(300), 0, 0);
  const b = C.encodePublish('t', 'y', 0, 0);
  const both = new Uint8Array(a.length + b.length); both.set(a); both.set(b, a.length);
  const p1 = C.takePacket(both); const p2 = C.takePacket(p1.rest);
  assert.equal(C.decodePublish(p1).payload.toString().length, 300);
  assert.equal(C.decodePublish(p2).payload.toString(), 'y');
  assert.equal(C.takePacket(a.subarray(0, 2)), null); // заголовок длины ещё не весь
  assert.equal(C.takePacket(a.subarray(0, a.length - 1)), null);
});

test('клиент: CONNACK → connect, публикация, PUBACK на входящий QoS 1', async () => {
  FakeWS.all = [];
  const c = mqtt.connect('wss://broker', { clientId: 'zv1', reconnectPeriod: 0, keepalive: 30 });
  const ws = FakeWS.all[0];
  assert.equal(ws.proto, 'mqtt');
  ws.open();
  assert.equal(ws.sent[0][0], 0x10); // CONNECT
  let connected = 0; c.on('connect', () => connected++);
  ws.feed([0x20, 0x02, 0x00, 0x00]);
  assert.equal(connected, 1);
  assert.equal(c.connected, true);
  c.subscribe('room', { qos: 1 });
  assert.equal(ws.sent[1][0], 0x82); // SUBSCRIBE
  c.publish('room', 'hi', { qos: 0 });
  assert.equal(ws.sent[2][0], 0x30);
  const got = [];
  c.on('message', (t, p) => got.push([t, p.toString()]));
  ws.feed(C.encodePublish('room', 'msg', 1, 7));
  assert.deepEqual(got, [['room', 'msg']]);
  assert.deepEqual([...ws.sent[3]], [0x40, 0x02, 0x00, 0x07]); // PUBACK id=7
  c.end(true);
  await tick(5);
  assert.equal(c.connected, false);
});

test('клиент: отказ брокера (CONNACK rc≠0) → error, без connect', async () => {
  FakeWS.all = [];
  const c = mqtt.connect('wss://broker', { reconnectPeriod: 0 });
  const errors = []; c.on('error', (e) => errors.push(e.message)); c.on('connect', () => assert.fail('не должно быть connect'));
  FakeWS.all[0].open();
  FakeWS.all[0].feed([0x20, 0x02, 0x00, 0x05]);
  await tick(5);
  assert.ok(errors.some((m) => m.includes('code 5')));
  assert.equal(c.connected, false);
  c.end();
});

test('клиент: переподключение после обрыва и рост паузы при неудачах', async () => {
  FakeWS.all = [];
  const c = mqtt.connect('wss://broker', { reconnectPeriod: 20, connectTimeout: 1000 });
  let reconnects = 0; c.on('reconnect', () => reconnects++);
  FakeWS.all[0].open();
  FakeWS.all[0].feed([0x20, 0x02, 0x00, 0x00]);
  FakeWS.all[0].close(); // обрыв живого соединения
  await tick(60);
  assert.equal(reconnects, 1);
  assert.equal(FakeWS.all.length, 2);
  // вторая попытка не открывается → onclose → failures=1, затем 2 (пауза удваивается)
  FakeWS.all[1].close();
  await tick(60);
  assert.equal(FakeWS.all.length, 3);
  FakeWS.all[2].close();
  await tick(25); // пауза теперь ~40 мс, третий реконнект ещё не начался
  assert.equal(FakeWS.all.length, 3);
  await tick(60);
  assert.equal(FakeWS.all.length, 4);
  c.end();
});

test('клиент: publish без соединения не бросает и сообщает ошибку в колбэк', () => {
  FakeWS.all = [];
  const c = mqtt.connect('wss://broker', { reconnectPeriod: 0 });
  let err = null;
  c.publish('t', 'x', { qos: 1 }, (e) => { err = e; });
  assert.ok(err instanceof Error);
  c.end();
});
