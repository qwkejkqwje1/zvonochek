// v37: MQTT-канал сигналинга ротирует соединение после 9 КБ (защита от
// ТСПУ-«заморозки» ~16 КБ), не теряя ни одного сообщения: старый клиент
// закрывается только после того, как новый подключился и подписался.
import test from 'node:test';
import assert from 'node:assert/strict';
import { Signaling } from '../signaling.js';

class FakeClient {
  constructor(url) {
    this.url = url;
    this.connected = false;
    this.ended = false;
    this.subs = [];
    this.pubs = [];
    this.h = {};
  }
  on(ev, fn) {
    (this.h[ev] ||= []).push(fn);
    return this;
  }
  emit(ev, ...a) {
    for (const fn of this.h[ev] || []) fn(...a);
  }
  subscribe(t) {
    this.subs.push(t);
  }
  publish(t, d) {
    this.pubs.push(d);
  }
  end() {
    this.ended = true;
    this.connected = false;
  }
  up() {
    this.connected = true;
    this.emit('connect');
  }
}

function setup() {
  const made = [];
  globalThis.mqtt = { connect: (url) => (made.push(new FakeClient(url)), made.at(-1)) };
  const sig = new Signaling({ topic: 't1', key: null, selfId: 'a', inst: 'i', brokers: [], relays: [] });
  sig._recv = async () => {};
  let ups = 0;
  sig.onTransportUp = () => ups++;
  return { sig, made, ups: () => ups };
}

test('MQTT: после 9 КБ — новый сокет, подмена только после connect', async () => {
  const { sig, made, ups } = setup();
  const c1 = sig._mqtt('wss://b1');
  c1.up();
  assert.equal(ups(), 1);
  assert.deepEqual(sig.clients, [c1]);
  const big = { length: 5000, toString: () => 'x' };
  c1.emit('message', 't', big);
  assert.equal(made.length, 1, 'до бюджета ротации нет');
  c1.emit('message', 't', big); // 10 000 > 9 000
  assert.equal(made.length, 2, 'поднят новый сокет');
  const c2 = made[1];
  assert.deepEqual(sig.clients, [c1], 'старый работает, пока новый не подключился');
  c1.emit('message', 't', big);
  assert.equal(made.length, 2, 'повторно не плодим');
  c2.up();
  assert.deepEqual(sig.clients, [c2]);
  assert.deepEqual(c2.subs, ['zvonochek/v1/t1']);
  assert.equal(ups(), 1, 'ротация не шлёт лишний hello');
  assert.equal(c1.ended, false, 'старый закрывается с задержкой (2 с перекрытия)');
  await new Promise((r) => setTimeout(r, 2100));
  assert.equal(c1.ended, true);
  sig.close();
});

test('MQTT: исходящие байты тоже считаются; закрытый сигналинг не ротирует', () => {
  const { sig, made } = setup();
  const c1 = sig._mqtt('wss://b1');
  c1.up();
  c1._bytes = 8990;
  sig._sendVoice('y'.repeat(20));
  assert.equal(c1.pubs.length, 1);
  assert.equal(made.length, 2, 'бюджет превышен отправкой');
  sig.close();
  const { sig: s2, made: m2 } = setup();
  const d1 = s2._mqtt('wss://b2');
  d1.up();
  s2.closed = true;
  d1.emit('message', 't', { length: 20000, toString: () => 'x' });
  assert.equal(m2.length, 1);
});

test('MQTT: новый сокет не поднялся за 12 с — бросаем его, старый остаётся', (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { sig, made } = setup();
  const c1 = sig._mqtt('wss://b1');
  c1.up();
  c1.emit('message', 't', { length: 9500, toString: () => 'x' });
  const c2 = made[1];
  t.mock.timers.tick(12001);
  assert.equal(c2.ended, true);
  assert.equal(c1._renewing, false, 'следующая попытка разрешена');
  assert.deepEqual(sig.clients, [c1]);
  sig.close();
});

// v41: закрытый сигналинг ничего не доставляет. После «Положить трубку»
// опоздавшее сообщение (Nostr-реле досылают с задержкой, заменяемый сокет
// живёт ещё 2 с) создавало соединение без микрофона, и в быстром
// перезвоне собеседник нас не слышал.
test('после close() сообщения не доставляются, в том числе уже расшифровываемые', async () => {
  const { deriveRoom, seal } = await import('../crypto.js');
  const room = await deriveRoom('k'.repeat(32));
  const got = [];
  const sig = new Signaling({ topic: room.topic, key: room.key, selfId: 'a', inst: 'i', brokers: [], relays: [], onMessage: (m) => got.push(m) });
  const msg = (mid) => seal(room.key, { type: 'hello', from: 'b', inst: 'j', mid }, room.topic);
  await sig._recv(await msg('m1'), 'nostr');
  assert.equal(got.length, 1, 'открытый канал доставляет');
  const inFlight = sig._recv(await msg('m2'), 'nostr'); // расшифровка идёт…
  sig.close(); // …а трубку уже положили
  await inFlight;
  await sig._recv(await msg('m3'), 'nostr');
  assert.deepEqual(got.map((m) => m.mid), ['m1']);
});
