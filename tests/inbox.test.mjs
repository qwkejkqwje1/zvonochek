// v41: сервер входящих (worker/inbox.js) — кому принадлежит номер.
// Настоящий Durable Object Inbox поверх in-memory SQLite (node:sqlite);
// сеть, push и WebSocket не используются. Атакующий знает только личную
// ссылку жертвы (#k=…&d=…) — до v41 этого хватало, чтобы зарегистрировать
// своё устройство под своим master-ключом и получать чужие звонки, push и
// пропущенные (AUDIT-v41.md).
import test from 'node:test';
import assert from 'node:assert/strict';

let DatabaseSync = null;
try {
  ({ DatabaseSync } = await import('node:sqlite'));
} catch {}
const skip = DatabaseSync ? false : 'нужен node:sqlite (Node ≥ 22.13)';

globalThis.WebSocketRequestResponsePair ??= class {
  constructor() {}
};
// Никаких настоящих запросов наружу (push-сервисы).
globalThis.fetch = async () => new Response(null, { status: 201 });
const realNow = Date.now.bind(Date);
let skew = 0;
Date.now = () => realNow() + skew;

const { Inbox } = DatabaseSync ? await import('../worker/inbox.js') : { Inbox: null };
const C = await import('../crypto.js');

const te = new TextEncoder();
const b64 = (u8) => Buffer.from(u8).toString('base64url');
const hex = (u8) => [...u8].map((x) => x.toString(16).padStart(2, '0')).join('');
const TEN_Y = 10 * 365 * 24 * 3600e3;

function newInbox() {
  const db = new DatabaseSync(':memory:');
  const exec = (q, ...p) => {
    const st = db.prepare(q);
    let rows;
    try {
      rows = st.all(...p);
    } catch (e) {
      if (!/return|data/i.test(e.message)) throw e;
      st.run(...p);
      rows = [];
    }
    return { toArray: () => rows };
  };
  const state = {
    storage: { sql: { exec }, setAlarm: async () => {}, deleteAlarm: async () => {} },
    setWebSocketAutoResponse() {},
    getWebSockets: () => [],
    acceptWebSocket() {},
    waitUntil() {},
  };
  const inbox = new Inbox(state, {});
  const A = async (topic, sub, { method = 'POST', body = null, query = '' } = {}) => {
    const res = await inbox.fetch(
      new Request(`https://w.test/inbox/${topic}${sub}${query}`, {
        method,
        headers: { 'content-type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined,
      })
    );
    let data = {};
    try {
      data = await res.json();
    } catch {}
    return { status: res.status, data };
  };
  const q = (sql, ...p) => db.prepare(sql).all(...p);
  return { inbox, db, A, q };
}

const genKey = async () => {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  return { priv: kp.privateKey, pub: b64(raw), raw };
};
const sign = async (priv, t) =>
  b64(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, te.encode(t))));
const fpOf = async (raw) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', raw))).slice(0, 32);
const certText = (d, l, e) => `zv-device-v1|${d}|${l}|${e}`;
const mkCert = async (priv, devicePub, label, exp = Date.now() + TEN_Y) => ({
  sig: await sign(priv, certText(devicePub, label, exp)),
  label,
  exp,
});

// Основное устройство: свой master, сертификат устройства от него.
async function identity(label = 'Владелец') {
  const master = await genKey();
  const device = await genKey();
  return { master, device, label, fp: await fpOf(master.raw), k: C.newSecret(), cert: await mkCert(master.priv, device.pub, label) };
}
// Подключённое устройство (v39): сертификат от того же master, метка 'Устройство'.
async function linked(owner) {
  const device = await genKey();
  return { ...owner, device, label: 'Устройство', cert: await mkCert(owner.master.priv, device.pub, 'Устройство') };
}
// Восстановленное по фразе (v27): master → recovery → новое устройство.
async function restored(owner) {
  const rec = await genKey();
  const device = await genKey();
  const recoveryCert = await mkCert(owner.master.priv, rec.pub, 'recovery');
  return {
    ...owner,
    device,
    rec,
    label: 'Владелец',
    cert: await mkCert(rec.priv, device.pub, 'Владелец'),
    chain: { recoveryPub: rec.pub, recoveryCert },
  };
}
const chatdialOf = async (id) => 'chatdial-' + hex(new Uint8Array(await crypto.subtle.digest('SHA-256', id.master.raw)));

const register = async (A, topic, id, endpoint = null) => {
  const ts = Date.now();
  return A(topic, '/register', {
    body: {
      masterPub: id.master.pub,
      fp: id.fp,
      devicePub: id.device.pub,
      cert: id.cert,
      label: id.label,
      ts,
      ...(id.chain ? { chain: id.chain } : {}),
      sub: endpoint ? { endpoint, keys: { p256dh: 'p', auth: 'a' } } : null,
      sig: await sign(id.device.priv, `register|${topic}|${id.device.pub}|${ts}`),
    },
  });
};
const answer = async (A, topic, ringId, id, verdict) => {
  const ts = Date.now();
  return A(topic, `/ring/${ringId}/answer`, {
    body: { verdict, devicePub: id.device.pub, ts, sig: await sign(id.device.priv, `answer|${topic}|${ringId}|${verdict}|${ts}`) },
  });
};
const missed = async (A, topic, id) => {
  const ts = Date.now();
  const sig = await sign(id.device.priv, `missed|${topic}|${ts}`);
  return A(topic, '/missed', {
    method: 'GET',
    query: `?devicePub=${encodeURIComponent(id.device.pub)}&ts=${ts}&sig=${encodeURIComponent(sig)}`,
  });
};
// /retire: подписью устройства, master-ключом или recovery-ключом (v41).
const retire = async (A, topic, id, by = null) => {
  const ts = Date.now();
  const text = `retire|${topic}|${id.device.pub}|${ts}`;
  const body = { devicePub: id.device.pub, ts };
  if (by === 'master') Object.assign(body, { by, masterPub: id.master.pub, sig: await sign(id.master.priv, text) });
  else if (by === 'recovery')
    Object.assign(body, {
      by,
      masterPub: id.master.pub,
      recoveryPub: id.chain.recoveryPub,
      recoveryCert: id.chain.recoveryCert,
      sig: await sign(id.rec.priv, text),
    });
  else body.sig = await sign(id.device.priv, text);
  return A(topic, '/retire', { body });
};
const revokeByMaster = async (A, topic, id, target) => {
  const ts = Date.now();
  return A(topic, '/revoke', {
    body: { target, ts, by: 'master', masterPub: id.master.pub, sig: await sign(id.master.priv, `revoke|${topic}|${target}|${ts}`) },
  });
};
const ring = async (A, topic, key, caller) => {
  const ringId = crypto.randomUUID();
  const payload = { v: 1, ringId, fromFp: caller.fp, fromDevicePub: caller.device.pub, name: 'Мама', call: 'audio', ts: Date.now() };
  const blob = await C.seal(key, payload, topic);
  return { ringId, r: await A(topic, '/ring', { body: { ringId, fromFp: caller.fp, fromDevicePub: caller.device.pub, blob } }) };
};
const activeDevices = (q) => q(`SELECT device_pub FROM devices WHERE revoked=0`).map((d) => d.device_pub);
const ownerFp = (q) => q(`SELECT v FROM meta WHERE k='masterFp'`)[0]?.v || '';

async function victimSetup() {
  const ib = newInbox();
  const victim = await identity();
  const room = await C.deriveRoom(victim.k);
  const T = room.topic;
  assert.equal((await register(ib.A, T, victim)).status, 200);
  return { ...ib, victim, room, T };
}

test('Inbox: чужой master не регистрируется по личной ссылке', { skip }, async () => {
  const { A, q, victim, T } = await victimSetup();
  const evil = await identity();
  const r = await register(A, T, evil);
  assert.equal(r.status, 403);
  assert.equal(r.data.error, 'not owner');
  assert.deepEqual(activeDevices(q), [victim.device.pub]);
  assert.equal(ownerFp(q), victim.fp);
});

test('Inbox: чужое устройство не отвечает на звонки, не читает пропущенные, не гасит и не отвязывает', { skip }, async () => {
  const { A, inbox, victim, room, T } = await victimSetup();
  const evil = await identity();
  await register(A, T, evil);
  const mom = await identity('Мама');
  const r1 = await ring(A, T, room.key, mom);
  assert.ok(r1.r.status === 200 || r1.r.status === 201, 'звонок создан');
  assert.equal((await answer(A, T, r1.ringId, evil, 'declined')).status, 403);
  const ok = await answer(A, T, r1.ringId, victim, 'accepted');
  assert.equal(ok.status, 200);
  assert.equal(ok.data.state, 'accepted');
  await ring(A, T, room.key, mom);
  try {
    skew += 91_000;
    await inbox.alarm();
    assert.equal((await missed(A, T, evil)).status, 403);
    const mine = await missed(A, T, victim);
    assert.equal(mine.status, 200);
    assert.equal(mine.data.missed.length, 1);
    assert.equal((await retire(A, T, evil)).status, 403);
    assert.equal((await retire(A, T, evil, 'master')).status, 403);
    assert.equal((await revokeByMaster(A, T, evil, victim.device.pub)).status, 403);
    assert.equal((await register(A, T, victim)).status, 200, 'владелец остался в своём номере');
  } finally {
    skew = 0;
  }
});

test('Inbox: push-подписку владельца нельзя вытеснить чужими', { skip }, async () => {
  const { A, q, victim, T } = await victimSetup();
  assert.equal((await register(A, T, victim, 'https://push.test/victim')).status, 200);
  const evil = await identity();
  for (let i = 0; i < 9; i++) assert.equal((await register(A, T, evil, `https://push.test/evil-${i}`)).status, 403);
  assert.deepEqual(
    q(`SELECT endpoint FROM subs`).map((s) => s.endpoint),
    ['https://push.test/victim']
  );
});

test('Inbox: топик дозвона из чата нельзя занять чужим ключом даже первым', { skip }, async () => {
  const victim = await identity();
  const evil = await identity();
  const CT = await chatdialOf(victim);
  const first = newInbox();
  const r = await register(first.A, CT, evil);
  assert.equal(r.status, 403);
  assert.equal(r.data.error, 'topic mismatch');
  assert.equal(ownerFp(first.q), '', 'отказ не закрепляет владельца');
  assert.equal((await register(first.A, CT, victim)).status, 200);
  assert.equal((await register(first.A, CT, await linked(victim))).status, 200);
  assert.equal((await register(first.A, CT, evil)).status, 403);
});

test('Inbox: законные устройства владельца регистрируются', { skip }, async () => {
  const { A, q, victim, T } = await victimSetup();
  const lnk = await linked(victim);
  const rst = await restored(victim);
  assert.equal((await register(A, T, lnk)).status, 200);
  assert.equal((await register(A, T, rst)).status, 200);
  assert.equal((await register(A, T, victim)).status, 200, 'повторная регистрация');
  assert.equal(activeDevices(q).length, 3);
});

test('Inbox: просроченный сертификат не принимается', { skip }, async () => {
  const { A } = newInbox();
  const id = await identity();
  id.cert = await mkCert(id.master.priv, id.device.pub, 'Владелец', Date.now() - 1000);
  const r = await register(A, (await C.deriveRoom(id.k)).topic, id);
  assert.equal(r.status, 403);
  assert.equal(r.data.error, 'cert expired');
});

test('Inbox: миграция — устройства под чужим master, попавшие до v41, удаляются', { skip }, async () => {
  const { A, db, q, victim, T } = await victimSetup();
  const evil = await identity();
  // так их оставил v40: строка устройства и push-подписка атакующего
  db.prepare(`INSERT INTO devices (device_pub, cert, label, exp, revoked) VALUES (?,?,?,?,0)`).run(
    evil.device.pub,
    JSON.stringify(evil.cert),
    'Владелец',
    evil.cert.exp
  );
  db.prepare(`INSERT INTO subs (endpoint, device_pub, p256dh, auth, created) VALUES (?,?,?,?,?)`).run(
    'https://push.test/evil',
    evil.device.pub,
    'p',
    'a',
    Date.now()
  );
  const lnk = await linked(victim);
  const rst = await restored(victim);
  await register(A, T, lnk);
  await register(A, T, rst);
  assert.equal((await register(A, T, victim)).status, 200);
  assert.deepEqual(activeDevices(q).sort(), [victim.device.pub, lnk.device.pub, rst.device.pub].sort());
  assert.equal(q(`SELECT COUNT(*) AS c FROM subs WHERE device_pub=?`, evil.device.pub)[0].c, 0);
});

test('Inbox: /retire — только владелец; подключённое устройство номер не гасит', { skip }, async () => {
  const { A, q, victim, T } = await victimSetup();
  const lnk = await linked(victim);
  await register(A, T, lnk);
  const lr = await retire(A, T, lnk);
  assert.equal(lr.status, 403);
  assert.equal(lr.data.error, 'linked device');
  const stranger = await identity();
  assert.equal((await retire(A, T, stranger)).data.error, 'bad retire', 'незарегистрированное устройство');
  assert.equal(activeDevices(q).length, 2, 'номер жив');
  // основное устройство — своей подписью
  assert.equal((await retire(A, T, victim)).status, 200);
  assert.deepEqual(activeDevices(q), []);
  assert.equal(ownerFp(q), victim.fp, 'владелец помнится после стирания');
  const evil = await identity();
  assert.equal((await register(A, T, evil)).data.error, 'not owner', 'чужой не занимает стёртый номер');
  // восстановленный владелец возвращается и гасит номер recovery-ключом
  const rst = await restored(victim);
  assert.equal((await register(A, T, rst)).status, 200);
  assert.equal((await retire(A, T, rst, 'recovery')).status, 200);
  // master-подписью — даже с устройства, которого в Inbox нет (смена номера)
  assert.equal((await register(A, T, victim)).status, 200);
  const fresh = { ...victim, device: (await genKey()) };
  assert.equal((await retire(A, T, fresh, 'master')).status, 200);
  assert.deepEqual(activeDevices(q), []);
});

test('Inbox: отзыв устройства переживает /retire и автоочистку', { skip }, async () => {
  const { A, inbox, victim, T } = await victimSetup();
  const lnk = await linked(victim);
  assert.equal((await register(A, T, lnk)).status, 200);
  assert.equal((await revokeByMaster(A, T, victim, lnk.device.pub)).status, 200);
  assert.equal((await retire(A, T, victim, 'master')).status, 200);
  const again = await register(A, T, lnk);
  assert.equal(again.status, 403);
  assert.equal(again.data.error, 'revoked');
  inbox.wipeIdle();
  assert.equal((await register(A, T, lnk)).data.error, 'revoked');
  assert.equal((await register(A, T, await identity())).data.error, 'not owner');
  assert.equal((await register(A, T, victim)).status, 200);
});
