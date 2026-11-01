// Имена топиков публичных серверов: формат и лимиты, иначе канал молчит.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ntfyTopicForSignaling, ntfyWanted } from '../signaling.js';
import { ntfyTopicForRoom, mqttTopicForRoom } from '../chat-transport.js';
import { NTFY_TOPIC_RE as NTFY_TOPIC, NTFY_MAX_BODY, fitsNtfy, ntfySubscribeUrl, parseNtfyFrame } from '../ntfy.js';

test('ntfy: топик сигналинга укладывается в лимит ntfy и стабилен', async () => {
  const t = await ntfyTopicForSignaling('zvroom/abc');
  assert.match(t, NTFY_TOPIC);
  assert.match(t, /^zv1-[0-9a-f]{48}$/);
  assert.equal(t, await ntfyTopicForSignaling('zvroom/abc'));
  assert.notEqual(t, await ntfyTopicForSignaling('zvroom/abd'));
});

test('ntfy: топик чата укладывается в лимит и не совпадает с сигналингом', async () => {
  const t = await ntfyTopicForRoom('room-1');
  assert.match(t, NTFY_TOPIC);
  assert.match(t, /^zvchat1n-[0-9a-f]{48}$/);
  assert.notEqual(t, await ntfyTopicForSignaling('room-1'));
});

test('MQTT: топик чата не раскрывает roomId', async () => {
  const t = await mqttTopicForRoom('secret-room-id');
  assert.match(t, /^zvchat1\/[0-9a-f]{64}$/);
  assert.ok(!t.includes('secret-room-id'));
});

test('ntfy: подписка — WebSocket с окном since 30 с', () => {
  const u = ntfySubscribeUrl('https://ntfy.sh/', 'zv1-x', 1000);
  assert.equal(u, 'wss://ntfy.sh/zv1-x/ws?since=970');
});

test('ntfy: тело больше 4096 байт не публикуется (сервер сделал бы вложение)', () => {
  assert.equal(fitsNtfy('a'.repeat(NTFY_MAX_BODY)), true);
  assert.equal(fitsNtfy('a'.repeat(NTFY_MAX_BODY + 1)), false);
  assert.equal(fitsNtfy('я'.repeat(2049)), false); // 4098 байт UTF-8
});

test('ntfy: из кадров подписки берутся только сообщения', () => {
  assert.deepEqual(parseNtfyFrame('{"id":"a","time":5,"event":"message","message":"blob"}'), { id: 'a', time: 5, message: 'blob' });
  assert.equal(parseNtfyFrame('{"event":"keepalive"}'), null);
  assert.equal(parseNtfyFrame('not json'), null);
});

test('ntfy: несёт только рукопожатие, hello — не чаще раза в 30 с', () => {
  const st = {};
  assert.equal(ntfyWanted('desc', st, 1000), true);
  assert.equal(ntfyWanted('cand', st, 1000), true);
  assert.equal(ntfyWanted('sig_chat', st, 1000), false);
  assert.equal(ntfyWanted('voice', st, 1000), false);
  assert.equal(ntfyWanted('hello', st, 100000), true);
  assert.equal(ntfyWanted('hello', st, 110000), false);
  assert.equal(ntfyWanted('hello', st, 131000), true);
});
