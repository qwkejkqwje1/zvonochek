// Живая проверка mqtt-lite против публичных брокеров из config.js.
// Запуск: node tests/mqtt-live.mjs  (нужен интернет; в CI не входит)
import { CONFIG } from '../config.js';
import { loadScript } from './helpers.mjs';
const mqtt = loadScript('mqtt-lite.js').mqtt;

function probe(b) {
  const url = typeof b === 'string' ? b : b.url;
  const topic = 'zvtest/' + Math.random().toString(36).slice(2);
  const t0 = Date.now();
  return new Promise((resolve) => {
    const got = new Set();
    const c = mqtt.connect(url, {
      ...(b.username ? { username: b.username, password: b.password } : {}),
      keepalive: 30, connectTimeout: 7000, reconnectPeriod: 0,
    });
    const done = (ok, why) => { clearTimeout(t); try { c.end(true); } catch {} resolve({ url, ok, why, ms: Date.now() - t0 }); };
    const t = setTimeout(() => done(false, 'timeout; got=' + [...got].join(',')), 12000);
    c.on('error', (e) => { if (!c.connected) done(false, e.message); });
    c.on('connect', () => {
      c.subscribe(topic, { qos: 1 });
      setTimeout(() => {
        c.publish(topic, 'q0-привет', { qos: 0 });
        c.publish(topic, 'q1-' + 'x'.repeat(5000), { qos: 1 });
      }, 400);
    });
    c.on('message', (tp, payload) => {
      const s = payload.toString();
      if (tp !== topic) return;
      if (s === 'q0-привет') got.add('q0');
      if (s.startsWith('q1-') && s.length === 5003) got.add('q1');
      if (got.size === 2) done(true, 'qos0+qos1 echoed (5 KB payload ok)');
    });
  });
}
const results = await Promise.all(CONFIG.MQTT_BROKERS.map(probe));
for (const r of results) console.log((r.ok ? 'ok  ' : 'FAIL') + '  ' + r.url.padEnd(42) + String(r.ms).padStart(6) + ' ms  ' + r.why);
process.exit(results.some((r) => r.ok) ? 0 : 1);
