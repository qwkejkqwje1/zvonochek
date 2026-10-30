// ZVONochek — приватный текстовый чат: комнаты по ссылке (#chat=<seed>),
// без регистрации. Сервер (ChatRoom DO) видит только шифротекст сообщений
// фиксированного размера; ключи выводятся из seed на устройстве
// (crypto.js: deriveChatKeys). Звонковый путь не затрагивается: кнопка
// «Позвонить» лишь создаёт обычную звонковую комнату и постит приглашение
// служебным сообщением. Техплан: ZVONochek-MESSENGER-TECHPLAN-v21.md.
//
// v25 — «мессенджерный» слой поверх фазы 1:
//   · presence: онлайн собеседника (WS-события сервера) и «был(а) в …»;
//   · receipts: «Отправлено / Доставлено / Прочитано» (members_state на DO);
//   · typing: «печатает…» — эфемерно, по WS, без хранения;
//   · файлы: чанки, зашифрованные отдельным файловым ключом (ключ — только
//     внутри зашифрованного сообщения type:'file'); сервер видит размер;
//   · код приветствия: одноразовый 9-символьный код быстрого подключения
//     (#greet= / ручной ввод), пара живёт на PairingDO не дольше 15 минут.
import { CONFIG } from './config.js?v=25';
import {
  b64u,
  newSecret,
  deriveChatKeys,
  encryptChatMessage,
  decryptChatMessage,
  hashChatBlob,
  newMsgId,
  FILE_CHUNK_PT,
  FILE_MAX_BYTES,
  importFileKey,
  encryptFileChunk,
  decryptFileChunk,
  newGreetCode,
  greetCodeHash,
  sealGreetPayload,
  openGreetPayload,
} from './crypto.js?v=25';
import { kvGet, kvPut, kvAll } from './store.js?v=25';
import {
  getChatDevice,
  signChatText,
  verifyChatSig,
  encryptWithVault,
  decryptWithVault,
} from './identity.js?v=25';

const $ = (s, r = document) => r.querySelector(s);
const te = new TextEncoder();

const canonical = (m) => `zv-chat-v1|${m.id}|${m.ts}|${m.devPub}|${m.type}|${m.text}`;
const chatLinkOf = (seed) => `${location.origin}${location.pathname}#chat=${seed}`;
const greetLinkOf = (code) => `${location.origin}${location.pathname}#greet=${code}`;

let cur = null; // {rec, keys, device, ws, closed, backoff, pendingCall, online:Set, receipts:Map, typing:{dev,until}|null}
let opening = false;
const fileState = new Map(); // fileId -> {progress, url, name, error, busy}

// ---------- Сервер ----------
const chatBase = (roomId) => `${CONFIG.WORKER_URL.replace(/\/$/, '')}/chat/${roomId}`;
const workerBase = () => CONFIG.WORKER_URL.replace(/\/$/, '');

async function api(roomId, token, path, opts = {}) {
  const res = await fetch(chatBase(roomId) + path, {
    method: opts.method || 'GET',
    headers: {
      'content-type': 'application/json',
      'x-access-token': token,
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = {};
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}

async function existingPushSub() {
  try {
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (!sub) return null;
    const j = sub.toJSON();
    return { endpoint: j.endpoint, keys: j.keys };
  } catch {
    return null;
  }
}

// ---------- Локальное хранилище ----------
const saveRoom = (rec) => kvPut('rooms', rec.roomId, rec);
const loadRoom = (roomId) => kvGet('rooms', roomId);

async function storeMessage(rec, entry) {
  await kvPut('messages', rec.roomId + ':' + entry.hash, { roomId: rec.roomId, ...entry });
}

async function roomMessages(roomId) {
  const all = await kvAll('messages');
  return all
    .map((x) => x.value)
    .filter((m) => m && m.roomId === roomId)
    .sort((a, b) => (a.seq || 0) - (b.seq || 0) || a.msg.ts - b.msg.ts);
}

// ---------- UI: утилиты ----------
function note(text) {
  const n = $('#chatNote');
  if (n) n.textContent = text || '';
  // v22: #chatNote находится внутри экрана комнаты — пока комната скрыта,
  // дублируем текст в #chatHomeNote на главном экране, иначе ошибки и
  // подсказки чата владелец не видит вообще (баг «кнопка молчит»).
  const h = $('#chatHomeNote');
  if (h && $('#chatroom')?.classList.contains('hidden')) h.textContent = text || '';
}
function status(text) {
  const s = $('#chatStatus');
  if (s) s.textContent = text;
}
function showChatScreen() {
  $('#home')?.classList.add('hidden');
  $('#prejoin')?.classList.add('hidden');
  $('#chatroom')?.classList.remove('hidden');
  const h = $('#chatHomeNote');
  if (h) h.textContent = ''; // v22: комната открыта — домашний дубль подсказок больше не нужен
}
function hideChatScreen() {
  $('#chatroom')?.classList.add('hidden');
  $('#home')?.classList.remove('hidden');
}

const fmtTime = (ts) =>
  new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const fmtDayTime = (ts) => {
  const d = new Date(ts);
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  return sameDay
    ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString([], { day: '2-digit', month: '2-digit' }) +
        ' ' +
        d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};
const fmtSize = (b) =>
  b > 1024 * 1024 ? (b / (1024 * 1024)).toFixed(1) + ' МБ' : Math.max(1, Math.ceil(b / 1024)) + ' КБ';
function hueOf(str) {
  let h = 0;
  for (let i = 0; i < String(str).length; i++) h = (h * 31 + String(str).charCodeAt(i)) % 360;
  return h;
}
function nickOf(devPub) {
  if (!cur) return 'Участник';
  if (devPub === cur.device.devicePub) return cur.rec.nick || 'Вы';
  return cur.rec.members?.[devPub]?.nick || 'Участник';
}

// Превью последнего сообщения комнаты и счётчик непрочитанных — для списка
// комнат на главном экране (только локальные данные).
function previewOf(m) {
  if (!m) return '';
  if (m.type === 'intro') return `${m.nick || 'Участник'} присоединился`;
  if (m.type === 'file') {
    try {
      const meta = JSON.parse(m.text || '{}');
      return 'Файл: ' + (meta.name || 'без имени');
    } catch {
      return 'Файл';
    }
  }
  if (m.type === 'system' && typeof m.text === 'string' && m.text.startsWith('call:')) {
    return 'Приглашение на звонок';
  }
  return String(m.text || '');
}
function unreadOf(rec, msgs) {
  const readSeq = rec.lastReadSeq || 0;
  return msgs.filter((it) => !it.mine && (it.seq || 0) > readSeq).length;
}

async function renderRoomList() {
  const list = $('#chatRoomsList');
  if (!list) return;
  const rooms = (await kvAll('rooms')).map((x) => x.value).filter(Boolean);
  const allMsgs = (await kvAll('messages')).map((x) => x.value).filter(Boolean);
  const byRoom = new Map();
  for (const m of allMsgs) {
    if (!byRoom.has(m.roomId)) byRoom.set(m.roomId, []);
    byRoom.get(m.roomId).push(m);
  }
  const enriched = rooms.map((r) => {
    const msgs = (byRoom.get(r.roomId) || []).sort(
      (a, b) => (a.seq || 0) - (b.seq || 0) || a.msg.ts - b.msg.ts
    );
    const last = msgs.length ? msgs[msgs.length - 1] : null;
    return { r, last, unread: unreadOf(r, msgs), lastTs: last ? last.msg.ts : r.createdAt || 0 };
  });
  enriched.sort((a, b) => b.lastTs - a.lastTs);
  list.replaceChildren();
  for (const { r, last, unread } of enriched) {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.className = 'btn small chat-room-item';
    const top = document.createElement('span');
    top.className = 'chat-room-top';
    const title = document.createElement('b');
    title.textContent = `Чат ${r.roomId.slice(0, 8)}…`;
    const when = document.createElement('span');
    when.className = 'chat-room-when';
    when.textContent = last ? fmtDayTime(last.msg.ts) : '';
    top.append(title, when);
    const bottom = document.createElement('span');
    bottom.className = 'chat-room-preview';
    const pv = document.createElement('span');
    pv.className = 'chat-room-preview-text';
    pv.textContent = last ? previewOf(last.msg) : 'Нет сообщений';
    bottom.append(pv);
    if (unread > 0) {
      const badge = document.createElement('span');
      badge.className = 'chat-unread-badge';
      badge.textContent = String(unread);
      bottom.append(badge);
    }
    btn.append(top, bottom);
    btn.onclick = async () => {
      const seed = await decryptWithVault(r.seedEnc);
      openRoomBySeed(seed);
    };
    li.append(btn);
    list.append(li);
  }
}

// ---------- Открытие комнаты ----------
async function openRoomBySeed(seedStr) {
  if (opening) return;
  opening = true;
  try {
    const seedBytes = b64u.dec(String(seedStr).trim());
    if (seedBytes.length !== 32) throw new Error('bad seed');
    const keys = await deriveChatKeys(seedBytes);
    if (cur && cur.keys.roomId === keys.roomId) return; // уже открыта эта комната
    const device = await getChatDevice();
    let rec = await loadRoom(keys.roomId);
    if (!rec) {
      rec = {
        roomId: keys.roomId,
        seedEnc: await encryptWithVault(b64u.enc(seedBytes)),
        nick: '',
        epoch: 0,
        lastSeq: 0,
        lastReadSeq: 0,
        members: {},
        introSent: false,
        createdAt: Date.now(),
      };
      await saveRoom(rec);
    }
    if (typeof rec.lastReadSeq !== 'number') rec.lastReadSeq = rec.lastSeq || 0;
    closeCurrent(false);
    cur = {
      rec,
      keys,
      device,
      ws: null,
      closed: false,
      backoff: 1000,
      pendingCall: null,
      online: new Set(),
      receipts: new Map(),
      typing: null,
      typingTimer: null,
      lastTypingSent: 0,
    };
    showChatScreen();
    $('#chatRoomTitle').textContent = `Чат ${keys.roomId.slice(0, 8)}…`;
    history.replaceState(null, '', location.pathname + '#chat=' + b64u.enc(seedBytes));
    // Инициализация на сервере (идемпотентно) + регистрация существующей push-подписки
    const sub = await existingPushSub();
    const init = await api(keys.roomId, keys.accessToken, '/init', {
      method: 'POST',
      body: { dev: device.devicePub, sub },
    });
    if (init.status === 403) {
      note('Сервер отклонил доступ к этой комнате (токен не совпал).');
      status('Ошибка доступа');
      return;
    }
    status('Подключение…');
    renderMessages().catch(() => {});
    if (!rec.nick) {
      $('#chatNickBox')?.classList.remove('hidden');
      $('#chatNickInput')?.focus();
      note('Введите никнейм — это единственная «регистрация», только для этой комнаты.');
    } else {
      $('#chatNickBox')?.classList.add('hidden');
      await sendIntroIfNeeded();
    }
    connectWs();
    await fetchMissed();
    await syncState();
    status('На связи');
    renderRoomList().catch(() => {});
  } catch (e) {
    note('Не удалось открыть чат: ' + e.message);
  } finally {
    opening = false;
  }
}

function closeCurrent(hideScreen = true) {
  if (cur) {
    cur.closed = true;
    if (cur.typingTimer) clearTimeout(cur.typingTimer);
    try {
      cur.ws?.close();
    } catch {}
    cur = null;
  }
  if (hideScreen) hideChatScreen();
}

// ---------- Сообщения ----------
async function buildMsg(type, text) {
  const m = {
    v: 1,
    id: newMsgId(),
    ts: Date.now(),
    nick: cur.rec.nick || 'Гость',
    devPub: cur.device.devicePub,
    type,
    text,
  };
  m.sig = await signChatText(canonical(m));
  return m;
}

async function sendMsg(type, text) {
  if (!cur) throw new Error('no room');
  const m = await buildMsg(type, text);
  const blob = await encryptChatMessage(cur.keys.roomKey, m);
  const hash = await hashChatBlob(blob);
  const r = await api(cur.keys.roomId, cur.keys.accessToken, '/msg', {
    method: 'POST',
    body: { blob: b64u.enc(blob), dev: cur.device.devicePub },
  });
  if (r.status === 429) throw new Error('Слишком часто: лимит 60 сообщений в минуту на комнату');
  if (r.status !== 200 && r.status !== 201) throw new Error('Сервер: ' + r.status);
  await storeMessage(cur.rec, { hash, seq: r.data.seq, msg: m, sigOk: true, mine: true });
  if (r.data.seq > cur.rec.lastSeq) {
    cur.rec.lastSeq = r.data.seq;
    cur.rec.lastReadSeq = Math.max(cur.rec.lastReadSeq || 0, r.data.seq);
    await saveRoom(cur.rec);
  }
  renderMessages().catch(() => {});
  return m;
}

async function sendIntroIfNeeded() {
  if (!cur || cur.rec.introSent || !cur.rec.nick) return;
  await sendMsg('intro', cur.rec.nick);
  cur.rec.introSent = true;
  await saveRoom(cur.rec);
}

// ---------- Доставка / прочтение (v25) ----------
const chatVisible = () =>
  !!cur && !$('#chatroom')?.classList.contains('hidden') && document.visibilityState === 'visible';

// Подтвердить прочтение всего, что уже лежит локально (lastSeq), если чат
// реально на экране. Сервер монотонно поднимает read_seq устройства и
// рассылает receipt остальным.
async function sendReadAck() {
  if (!cur || !chatVisible() || !cur.rec.lastSeq) return;
  const upto = cur.rec.lastSeq;
  if ((cur.rec.lastReadSeq || 0) >= upto) return;
  cur.rec.lastReadSeq = upto;
  await saveRoom(cur.rec);
  api(cur.keys.roomId, cur.keys.accessToken, '/ack', {
    method: 'POST',
    body: { seqs: [upto], dev: cur.device.devicePub, read: true },
  }).catch(() => {});
  renderRoomList().catch(() => {});
}

function applyReceipt(dev, delivered, read) {
  if (!cur || dev === cur.device.devicePub) return;
  const prev = cur.receipts.get(dev) || { delivered: 0, read: 0 };
  cur.receipts.set(dev, {
    delivered: Math.max(prev.delivered, delivered || 0),
    read: Math.max(prev.read, read || 0),
  });
  renderMessages().catch(() => {});
}

function applyPresence(dev, online, ts) {
  if (!cur || dev === cur.device.devicePub) return;
  if (online) cur.online.add(dev);
  else {
    cur.online.delete(dev);
    if (cur.rec.members[dev]) {
      cur.rec.members[dev].lastSeen = ts || Date.now();
      saveRoom(cur.rec).catch(() => {});
    }
  }
  renderPresence();
  renderMembersList();
}

// Синхронизация сводки при открытии: кто дочитал до какого seq + кто онлайн.
async function syncState() {
  if (!cur) return;
  const r = await api(cur.keys.roomId, cur.keys.accessToken, '/state').catch(() => null);
  if (!r || r.status !== 200 || !cur) return;
  for (const m of r.data.members || []) applyReceipt(m.dev, m.delivered, m.read);
  cur.online = new Set((r.data.online || []).filter((d) => d !== cur.device.devicePub));
  renderPresence();
  renderMembersList();
}

async function ingest(item) {
  if (!cur || !item?.blob) return;
  const raw = b64u.dec(item.blob);
  const hash = await hashChatBlob(raw);
  const key = cur.rec.roomId + ':' + hash;
  const seen = await kvGet('messages', key);
  if (!seen) {
    const msg = await decryptChatMessage(cur.keys.roomKey, raw);
    if (!msg || msg.v !== 1) return;
    let sigOk = false;
    try {
      sigOk = !!(msg.devPub && msg.sig && (await verifyChatSig(msg.devPub, msg.sig, canonical(msg))));
    } catch {}
    const mine = msg.devPub === cur.device.devicePub;
    if (msg.type === 'intro' && msg.devPub) {
      cur.rec.members[msg.devPub] = {
        ...cur.rec.members[msg.devPub],
        nick: msg.nick || msg.text || 'Участник',
        firstSeen: cur.rec.members[msg.devPub]?.firstSeen || Date.now(),
        sigOk,
      };
      await saveRoom(cur.rec);
      renderPresence();
      renderMembersList();
    }
    await storeMessage(cur.rec, { hash, seq: item.seq, msg, sigOk, mine });
    renderMessages().catch(() => {});
    if (!mine) renderRoomList().catch(() => {});
  }
  if (item.seq > cur.rec.lastSeq) {
    cur.rec.lastSeq = item.seq;
    await saveRoom(cur.rec);
  }
  // Доставка: ack на каждое сообщение (с dev — для members_state на сервере).
  api(cur.keys.roomId, cur.keys.accessToken, '/ack', {
    method: 'POST',
    body: { seqs: [item.seq], dev: cur.device.devicePub },
  }).catch(() => {});
  // Прочтение: если чат сейчас на экране, всё докачанное считаем увиденным.
  sendReadAck().catch(() => {});
}

async function fetchMissed() {
  if (!cur) return;
  const r = await api(
    cur.keys.roomId,
    cur.keys.accessToken,
    `/fetch?after=${cur.rec.lastSeq || 0}`
  ).catch(() => null);
  if (!r || r.status !== 200) return;
  for (const item of r.data.messages || []) await ingest(item);
}

// ---------- WebSocket ----------
function connectWs() {
  if (!cur || cur.closed) return;
  const url = chatBase(cur.keys.roomId).replace(/^http/, 'ws') + '/listen';
  let ws;
  try {
    ws = new WebSocket(url);
  } catch {
    scheduleReconnect();
    return;
  }
  cur.ws = ws;
  ws.onopen = () => {
    cur.backoff = 1000;
    ws.send(JSON.stringify({ type: 'auth', token: cur.keys.accessToken, dev: cur.device.devicePub }));
  };
  ws.onmessage = async (e) => {
    let m;
    try {
      m = JSON.parse(e.data);
    } catch {
      return;
    }
    if (m.type === 'msg') await ingest({ seq: m.seq, blob: m.blob, ts: m.ts });
    else if (m.type === 'ready') {
      if (Array.isArray(m.online) && cur) {
        cur.online = new Set(m.online.filter((d) => d !== cur.device.devicePub));
        renderPresence();
        renderMembersList();
      }
      if (Array.isArray(m.members)) {
        for (const s of m.members) applyReceipt(s.dev, s.delivered, s.read);
      }
      fetchMissed().catch(() => {});
    } else if (m.type === 'presence') applyPresence(m.dev, !!m.online, m.ts);
    else if (m.type === 'receipt') applyReceipt(m.dev, m.delivered, m.read);
    else if (m.type === 'typing' && cur) {
      cur.typing = { dev: m.dev, until: Date.now() + 4000 };
      renderPresence();
      if (cur.typingTimer) clearTimeout(cur.typingTimer);
      cur.typingTimer = setTimeout(() => renderPresence(), 4100);
    }
  };
  ws.onclose = () => {
    if (!cur || cur.closed) return;
    status('Офлайн, переподключение…');
    scheduleReconnect();
  };
  ws.onerror = () => {
    try {
      ws.close();
    } catch {}
  };
}
function scheduleReconnect() {
  if (!cur || cur.closed) return;
  const wait = cur.backoff;
  cur.backoff = Math.min(30000, cur.backoff * 2);
  setTimeout(() => {
    if (cur && !cur.closed) {
      connectWs();
      fetchMissed().catch(() => {});
    }
  }, wait);
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && cur && !cur.closed) {
    fetchMissed()
      .then(() => sendReadAck())
      .catch(() => {});
  }
});

// ---------- Файлы (v25) ----------
function setFileProgress(pct, label) {
  const box = $('#chatFileProgress');
  const fill = $('#chatFileProgressFill');
  const text = $('#chatFileProgressText');
  if (!box || !fill || !text) return;
  if (pct === null) {
    box.classList.add('hidden');
    return;
  }
  box.classList.remove('hidden');
  fill.style.width = Math.round(pct * 100) + '%';
  text.textContent = label || '';
}

async function uploadFile(file) {
  if (!cur) return;
  if (!cur.rec.nick) return note('Сначала введите никнейм.');
  if (file.size > FILE_MAX_BYTES) {
    return note(`Файл больше ${fmtSize(FILE_MAX_BYTES)} — лимит для чата.`);
  }
  try {
    const raw = new Uint8Array(await file.arrayBuffer());
    const keyRaw = crypto.getRandomValues(new Uint8Array(32));
    const fileKey = await importFileKey(keyRaw);
    const salt = crypto.getRandomValues(new Uint8Array(4));
    const fileId = b64u.enc(crypto.getRandomValues(new Uint8Array(12)));
    const total = Math.max(1, Math.ceil(raw.length / FILE_CHUNK_PT));
    for (let idx = 0; idx < total; idx++) {
      const chunk = raw.subarray(idx * FILE_CHUNK_PT, (idx + 1) * FILE_CHUNK_PT);
      const ct = await encryptFileChunk(fileKey, salt, idx, chunk);
      const r = await api(cur.keys.roomId, cur.keys.accessToken, '/file', {
        method: 'POST',
        body: { fileId, idx, total, blob: b64u.enc(ct) },
      });
      if (r.status !== 200 && r.status !== 201) {
        throw new Error('Сервер отклонил чанк файла: ' + r.status);
      }
      setFileProgress((idx + 1) / total, `Отправка файла ${idx + 1}/${total}…`);
    }
    const meta = {
      fileId,
      name: file.name || 'файл',
      size: raw.length,
      mime: file.type || 'application/octet-stream',
      chunks: total,
      salt: b64u.enc(salt),
      fileKey: b64u.enc(keyRaw),
    };
    await sendMsg('file', JSON.stringify(meta));
    note('Файл отправлен.');
  } catch (e) {
    note('Не удалось отправить файл: ' + e.message);
  } finally {
    setFileProgress(null);
  }
}

async function downloadFile(meta, card) {
  const st = fileState.get(meta.fileId) || {};
  if (st.busy) return;
  if (st.url) {
    // Уже скачан: для картинок превью уже в ленте, кнопка сохраняет файл.
    const a = document.createElement('a');
    a.href = st.url;
    a.download = meta.name || 'файл';
    a.click();
    return;
  }
  st.busy = true;
  st.error = '';
  fileState.set(meta.fileId, st);
  renderFileCardState(meta, card, st);
  try {
    const fileKey = await importFileKey(b64u.dec(meta.fileKey));
    const salt = b64u.dec(meta.salt);
    const parts = [];
    for (let idx = 0; idx < meta.chunks; idx++) {
      const r = await api(
        cur.keys.roomId,
        cur.keys.accessToken,
        `/file?fileId=${encodeURIComponent(meta.fileId)}&idx=${idx}`
      );
      if (r.status !== 200 || !r.data.blob) throw new Error('чанк ' + idx + ' недоступен');
      parts.push(await decryptFileChunk(fileKey, salt, idx, b64u.dec(r.data.blob)));
      st.progress = (idx + 1) / meta.chunks;
      renderFileCardState(meta, card, st);
    }
    const blob = new Blob(parts, { type: meta.mime || 'application/octet-stream' });
    st.url = URL.createObjectURL(blob);
    st.busy = false;
    fileState.set(meta.fileId, st);
    renderFileCardState(meta, card, st);
    if (!(meta.mime || '').startsWith('image/')) {
      const a = document.createElement('a');
      a.href = st.url;
      a.download = meta.name || 'файл';
      a.click();
    }
  } catch (e) {
    st.busy = false;
    st.error = 'Ошибка загрузки: ' + e.message;
    fileState.set(meta.fileId, st);
    renderFileCardState(meta, card, st);
  }
}

function renderFileCardState(meta, card, st) {
  if (!card) return;
  const btn = card.querySelector('.chat-file-btn');
  const info = card.querySelector('.chat-file-state');
  const prev = card.querySelector('.chat-file-preview');
  if (btn) {
    btn.disabled = !!st.busy;
    btn.textContent = st.busy
      ? `Загрузка ${Math.round((st.progress || 0) * 100)}%`
      : st.url
        ? 'Сохранить файл'
        : 'Скачать';
  }
  if (info) info.textContent = st.error || '';
  if (prev && st.url && (meta.mime || '').startsWith('image/') && !prev.firstChild) {
    const img = document.createElement('img');
    img.className = 'chat-file-img';
    img.alt = meta.name || 'изображение';
    img.src = st.url;
    prev.append(img);
  }
}

// ---------- Код приветствия (v25) ----------
async function pairApi(path, body) {
  const res = await fetch(workerBase() + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  let data = {};
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}

async function createInvite() {
  if (!cur) return;
  try {
    const seed = await decryptWithVault(cur.rec.seedEnc);
    const code = newGreetCode();
    const blob = await sealGreetPayload(code, { seed, roomId: cur.rec.roomId });
    const codeHash = await greetCodeHash(code);
    const r = await pairApi('/pair/create', {
      codeHash,
      blob,
      exp: Date.now() + 15 * 60_000,
    });
    if (r.status !== 200 && r.status !== 201) {
      throw new Error('сервер пар недоступен (' + r.status + ') — воркер v25 задеплоен?');
    }
    const box = $('#chatGreetBox');
    if (!box) return;
    $('#greetCode').textContent = code;
    const linkInput = $('#greetLink');
    if (linkInput) linkInput.value = greetLinkOf(code);
    const qr = $('#greetQr');
    if (qr && typeof qrcode !== 'undefined') {
      try {
        const q = qrcode(0, 'M');
        q.addData(greetLinkOf(code));
        q.make();
        qr.innerHTML = q.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
      } catch {
        qr.textContent = '';
      }
    }
    box.classList.remove('hidden');
    note('Покажите код собеседнику или отправьте короткую ссылку. Код одноразовый, действует 15 минут.');
  } catch (e) {
    note('Не удалось создать код приглашения: ' + e.message);
  }
}

async function redeemGreet(codeRaw) {
  const code = String(codeRaw || '').trim();
  if (!/^[A-Za-z0-9_-]{9}$/.test(code)) {
    note('Код подключения — 9 символов.');
    return;
  }
  try {
    note('Проверяю код подключения…');
    const codeHash = await greetCodeHash(code);
    const r = await pairApi('/pair/claim', { codeHash });
    if (r.status === 404) return note('Код не найден или уже использован.');
    if (r.status === 410) return note('Код истёк (15 минут) или лимит попыток исчерпан. Попросите новый.');
    if (r.status !== 200 || !r.data.blob) return note('Сервер пар отклонил запрос: ' + r.status);
    const payload = await openGreetPayload(code, r.data.blob);
    if (!payload?.seed) return note('Не удалось расшифровать приглашение этим кодом.');
    note('');
    await openRoomBySeed(payload.seed);
  } catch (e) {
    note('Не удалось подключиться по коду: ' + e.message);
  }
}

// ---------- Присутствие и шапка ----------
function knownMembers() {
  if (!cur) return [];
  const devs = new Set([
    cur.device.devicePub,
    ...Object.keys(cur.rec.members || {}),
    ...cur.receipts.keys(),
    ...cur.online,
  ]);
  return [...devs];
}

function renderPresence() {
  const line = $('#chatPresence');
  if (!line || !cur) return;
  const members = knownMembers();
  const others = members.filter((d) => d !== cur.device.devicePub);
  const onlineCount = others.filter((d) => cur.online.has(d)).length;
  if (cur.typing && cur.typing.until > Date.now() && cur.typing.dev !== cur.device.devicePub) {
    line.textContent = `${nickOf(cur.typing.dev)} печатает…`;
    return;
  }
  line.textContent =
    `${members.length} участника · ${onlineCount} онлайн` +
    (cur.online.size ? '' : ' · собеседники не в сети');
}

function renderMembersList() {
  const box = $('#chatMembersList');
  if (!box || !cur || box.classList.contains('hidden')) return;
  box.replaceChildren();
  for (const dev of knownMembers()) {
    const row = document.createElement('div');
    row.className = 'chat-member-row';
    const av = document.createElement('span');
    av.className = 'chat-avatar';
    av.style.background = `hsl(${hueOf(dev)} 65% 42%)`;
    av.textContent = (nickOf(dev)[0] || '?').toUpperCase();
    const dot = document.createElement('span');
    const isMe = dev === cur.device.devicePub;
    const isOnline = isMe || cur.online.has(dev);
    dot.className = 'chat-dot' + (isOnline ? ' on' : '');
    av.append(dot);
    const name = document.createElement('span');
    name.className = 'chat-member-name';
    name.textContent = nickOf(dev) + (isMe ? ' (вы)' : '');
    const seen = document.createElement('span');
    seen.className = 'chat-member-seen';
    if (isMe) seen.textContent = 'это вы';
    else if (cur.online.has(dev)) seen.textContent = 'онлайн';
    else {
      const ls = cur.rec.members?.[dev]?.lastSeen;
      seen.textContent = ls ? 'был(а) в ' + fmtTime(ls) : 'не в сети';
    }
    row.append(av, name, seen);
    box.append(row);
  }
}

// Статус прочтения своего сообщения: по сводкам receipts остальных.
function receiptLabel(it) {
  if (!cur || !it.seq) return '';
  const others = knownMembers().filter((d) => d !== cur.device.devicePub);
  if (!others.length) return 'Отправлено';
  const delivered = others.some((d) => (cur.receipts.get(d)?.delivered || 0) >= it.seq);
  const readAll = others.every((d) => (cur.receipts.get(d)?.read || 0) >= it.seq);
  if (readAll) return 'Прочитано';
  if (delivered) return 'Доставлено';
  return 'Отправлено';
}

// ---------- Рендер ----------
async function renderMessages() {
  const box = $('#chatMessages');
  if (!box || !cur) return;
  const items = await roomMessages(cur.rec.roomId);
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  box.replaceChildren();
  for (const it of items) {
    const m = it.msg;
    if (m.type === 'intro') {
      const div = document.createElement('div');
      div.className = 'chat-sys';
      div.textContent = `${m.nick || 'Участник'} присоединился к чату`;
      box.append(div);
      continue;
    }
    if (m.type === 'system' && typeof m.text === 'string' && m.text.startsWith('call:')) {
      const div = document.createElement('div');
      div.className = 'chat-sys';
      const span = document.createElement('span');
      span.textContent = `${m.nick || 'Участник'} приглашает на звонок `;
      const btn = document.createElement('button');
      btn.className = 'btn small primary';
      btn.textContent = 'Войти в звонок';
      btn.onclick = () => {
        location.hash = 'k=' + m.text.slice(5);
      };
      div.append(span, btn);
      box.append(div);
      continue;
    }
    const rowEl = document.createElement('div');
    rowEl.className = 'chat-msg-row' + (it.mine ? ' mine' : '');
    if (!it.mine) {
      const av = document.createElement('span');
      av.className = 'chat-avatar';
      av.style.background = `hsl(${hueOf(m.devPub || '')} 65% 42%)`;
      av.textContent = (m.nick || 'У')[0].toUpperCase();
      rowEl.append(av);
    }
    const div = document.createElement('div');
    div.className = 'chat-msg' + (it.mine ? ' mine' : '');
    if (m.type === 'file') {
      let meta = null;
      try {
        meta = JSON.parse(m.text || '');
      } catch {}
      if (meta && meta.fileId) {
        const card = document.createElement('div');
        card.className = 'chat-file';
        const nm = document.createElement('div');
        nm.className = 'chat-file-name';
        nm.textContent = meta.name || 'файл';
        const sz = document.createElement('div');
        sz.className = 'chat-file-size';
        sz.textContent = fmtSize(meta.size || 0);
        const pv = document.createElement('div');
        pv.className = 'chat-file-preview';
        const btn = document.createElement('button');
        btn.className = 'btn small chat-file-btn';
        btn.textContent = 'Скачать';
        const stEl = document.createElement('div');
        stEl.className = 'chat-file-state';
        btn.onclick = () => downloadFile(meta, card).catch(() => {});
        card.append(nm, sz, pv, btn, stEl);
        div.append(card);
        const st = fileState.get(meta.fileId);
        if (st) renderFileCardState(meta, card, st);
      } else {
        const body = document.createElement('div');
        body.className = 'chat-msg-text';
        body.textContent = 'Файл (повреждённые метаданные)';
        div.append(body);
      }
    } else {
      if (!it.mine) {
        const head = document.createElement('div');
        head.className = 'chat-msg-head';
        head.textContent = m.nick || 'Участник';
        div.append(head);
      }
      const body = document.createElement('div');
      body.className = 'chat-msg-text';
      body.textContent = m.text || '';
      div.append(body);
    }
    const foot = document.createElement('div');
    foot.className = 'chat-msg-foot';
    const tm = document.createElement('span');
    tm.textContent = fmtTime(m.ts);
    foot.append(tm);
    if (it.mine) {
      const rc = document.createElement('span');
      rc.className = 'chat-receipt';
      rc.textContent = receiptLabel(it);
      foot.append(rc);
    } else if (!it.sigOk) {
      const warn = document.createElement('span');
      warn.className = 'chat-receipt warn';
      warn.textContent = 'подпись не подтверждена';
      foot.append(warn);
    }
    div.append(foot);
    rowEl.append(div);
    box.append(rowEl);
  }
  if (nearBottom || !box.dataset.scrolled) {
    box.scrollTop = box.scrollHeight;
    box.dataset.scrolled = '1';
  }
}

// ---------- Проводка UI ----------
function initChatUI() {
  const create = $('#btnCreateChat');
  if (create) {
    create.onclick = async () => {
      try {
        const seed = newSecret();
        await openRoomBySeed(seed);
        note('Ссылка на чат — в адресной строке и по кнопке «Ссылка». Передайте её собеседнику вне этого чата.');
      } catch (e) {
        // v22: openRoomBySeed ловит свои ошибки сама (note теперь виден на
        // главном экране); сюда долетают только сбои вне её — показываем
        // и в note, и баннером, чтобы не было молчания.
        const text = 'Не удалось создать чат: ' + (e?.message || e);
        note(text);
        window.__zvShowDiag?.(text + ' Пришлите этот текст разработчику.');
      }
    };
  }
  const openBtn = $('#btnOpenChat');
  if (openBtn) {
    openBtn.onclick = () => {
      const raw = ($('#chatLinkInput')?.value || '').trim();
      const g = raw.match(/greet=([A-Za-z0-9_-]{9})/) || raw.match(/^([A-Za-z0-9_-]{9})$/);
      if (g) return redeemGreet(g[1]);
      const m = raw.match(/chat=([A-Za-z0-9_-]{43})/) || raw.match(/^([A-Za-z0-9_-]{43})$/);
      if (!m) return note('Вставьте ссылку на чат (#chat=…), сам ключ или код подключения из 9 символов.');
      openRoomBySeed(m[1]);
    };
  }
  const back = $('#chatBack');
  if (back) {
    back.onclick = () => {
      closeCurrent(true);
      history.replaceState(null, '', location.pathname);
      renderRoomList().catch(() => {});
    };
  }
  const nickSave = $('#chatNickSave');
  if (nickSave) {
    nickSave.onclick = async () => {
      if (!cur) return;
      const nick = ($('#chatNickInput')?.value || '').trim().slice(0, 40);
      if (!nick) return note('Никнейм не может быть пустым.');
      cur.rec.nick = nick;
      await saveRoom(cur.rec);
      $('#chatNickBox')?.classList.add('hidden');
      note('');
      await sendIntroIfNeeded();
      renderPresence();
      renderMessages().catch(() => {});
    };
  }
  const send = $('#chatSend');
  const doSend = async () => {
    const input = $('#chatInput');
    // В index.html два #chatInput (комната чата и панель звонка): берём свой.
    const myInput = $('#chatroom #chatInput') || input;
    const text = (myInput?.value || '').trim();
    if (!text || !cur) return;
    if (!cur.rec.nick) return note('Сначала введите никнейм.');
    try {
      await sendMsg('text', text);
      myInput.value = '';
    } catch (e) {
      note(e.message);
    }
  };
  if (send) send.onclick = doSend;
  const input = $('#chatroom #chatInput');
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') doSend();
    });
    // v25: «печатает…» — не чаще раза в 3 секунды, только по живому WS.
    input.addEventListener('input', () => {
      if (!cur || !input.value || cur.ws?.readyState !== 1) return;
      const now = Date.now();
      if (now - (cur.lastTypingSent || 0) < 3000) return;
      cur.lastTypingSent = now;
      try {
        cur.ws.send(JSON.stringify({ type: 'typing' }));
      } catch {}
    });
  }
  const attach = $('#chatAttach');
  const fileInput = $('#chatFileInput');
  if (attach && fileInput) {
    attach.onclick = () => fileInput.click();
    fileInput.addEventListener('change', () => {
      const f = fileInput.files?.[0];
      fileInput.value = '';
      if (f) uploadFile(f).catch(() => {});
    });
  }
  const copyBtn = $('#chatCopyLink');
  if (copyBtn) {
    copyBtn.onclick = async () => {
      if (!cur) return;
      const seed = await decryptWithVault(cur.rec.seedEnc);
      try {
        await navigator.clipboard.writeText(chatLinkOf(seed));
        note('Ссылка на чат скопирована.');
      } catch {
        note(chatLinkOf(seed));
      }
    };
  }
  const inviteBtn = $('#chatInviteBtn');
  if (inviteBtn) inviteBtn.onclick = () => createInvite();
  const greetClose = $('#greetClose');
  if (greetClose) {
    greetClose.onclick = () => $('#chatGreetBox')?.classList.add('hidden');
  }
  const greetCopy = $('#greetCopy');
  if (greetCopy) {
    greetCopy.onclick = async () => {
      const v = $('#greetLink')?.value || '';
      if (!v) return;
      try {
        await navigator.clipboard.writeText(v);
        note('Короткая ссылка скопирована.');
      } catch {
        note(v);
      }
    };
  }
  const titleBox = $('#chatTitleBox');
  if (titleBox) {
    titleBox.onclick = () => {
      const box = $('#chatMembersList');
      if (!box) return;
      box.classList.toggle('hidden');
      renderMembersList();
    };
  }
  const callBtn = $('#chatCallBtn');
  if (callBtn) {
    callBtn.onclick = async () => {
      if (!cur || !cur.rec.nick) return note('Сначала введите никнейм.');
      try {
        const secret = newSecret();
        await sendMsg('system', 'call:' + secret);
        cur.pendingCall = secret;
        note('Приглашение на звонок отправлено в чат. Нажмите «Войти в звонок» у сообщения — вы или собеседник.');
      } catch (e) {
        note(e.message);
      }
    };
  }
  const epochBtn = $('#chatEpochBtn');
  if (epochBtn) {
    epochBtn.onclick = () =>
      note('Смена эпохи появится в фазе 3: новый ключ будет завёрнут на устройства оставленных участников (техплан v21, §6).');
  }
  renderRoomList().catch(() => {});
  // v22: флаг успешной инициализации чата для watchdog в zvdiag.js.
  window.__zvChatBooted = true;
}

function checkHash() {
  const params = new URLSearchParams(location.hash.slice(1));
  const greet = params.get('greet');
  if (greet && /^[A-Za-z0-9_-]{9}$/.test(greet)) {
    $('#home')?.classList.remove('hidden');
    redeemGreet(greet);
    return;
  }
  const seed = params.get('chat');
  if (seed && /^[A-Za-z0-9_-]{43}$/.test(seed)) {
    openRoomBySeed(seed);
  } else if (cur) {
    // Ушли по звонковой ссылке или домой — закрываем чат-канал.
    closeCurrent(true);
    $('#chatroom')?.classList.add('hidden');
    $('#home')?.classList.add('hidden'); // экранами дальше управляет app.js (route)
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    initChatUI();
    checkHash();
  });
} else {
  initChatUI();
  checkHash();
}
window.addEventListener('hashchange', checkHash);

// Для тестов и отладки: чистое API модуля.
window.ZVChat = { openRoomBySeed, openFromHash: checkHash, canonical, redeemGreet };
