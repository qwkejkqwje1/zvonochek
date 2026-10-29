// ZVONochek v21 — приватный текстовый чат: комнаты по ссылке (#chat=<seed>),
// без регистрации. Сервер (ChatRoom DO) видит только шифротекст фиксированного
// размера; ключи выводятся из seed на устройстве (crypto.js: deriveChatKeys).
// Звонковый путь не затрагивается: кнопка «Позвонить» лишь создаёт обычную
// звонковую комнату и постит приглашение служебным сообщением.
// Техплан: ZVONochek-MESSENGER-TECHPLAN-v21.md.
import { CONFIG } from './config.js?v=23';
import {
  b64u,
  newSecret,
  deriveChatKeys,
  encryptChatMessage,
  decryptChatMessage,
  hashChatBlob,
  newMsgId,
} from './crypto.js?v=23';
import { kvGet, kvPut, kvAll } from './store.js?v=23';
import {
  getChatDevice,
  signChatText,
  verifyChatSig,
  encryptWithVault,
  decryptWithVault,
} from './identity.js?v=23';

const $ = (s, r = document) => r.querySelector(s);
const te = new TextEncoder();

const canonical = (m) => `zv-chat-v1|${m.id}|${m.ts}|${m.devPub}|${m.type}|${m.text}`;
const chatLinkOf = (seed) => `${location.origin}${location.pathname}#chat=${seed}`;

let cur = null; // {rec, keys, device, ws, closed, backoff, pendingCall}
let opening = false;

// ---------- Сервер ----------
const chatBase = (roomId) => `${CONFIG.WORKER_URL.replace(/\/$/, '')}/chat/${roomId}`;

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

async function renderRoomList() {
  const list = $('#chatRoomsList');
  if (!list) return;
  const rooms = (await kvAll('rooms')).map((x) => x.value).filter(Boolean);
  list.replaceChildren();
  for (const r of rooms.sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))) {
    const li = document.createElement('li');
    const btn = document.createElement('button');
    btn.className = 'btn small';
    btn.textContent = `Чат ${r.roomId.slice(0, 8)}… · ${Object.keys(r.members || {}).length} уч.`;
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
        members: {},
        introSent: false,
        createdAt: Date.now(),
      };
      await saveRoom(rec);
    }
    closeCurrent(false);
    cur = { rec, keys, device, ws: null, closed: false, backoff: 1000, pendingCall: null };
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
        nick: msg.nick || msg.text || 'Участник',
        firstSeen: cur.rec.members[msg.devPub]?.firstSeen || Date.now(),
        sigOk,
      };
      await saveRoom(cur.rec);
    }
    await storeMessage(cur.rec, { hash, seq: item.seq, msg, sigOk, mine });
    renderMessages().catch(() => {});
  }
  if (item.seq > cur.rec.lastSeq) {
    cur.rec.lastSeq = item.seq;
    await saveRoom(cur.rec);
  }
  api(cur.keys.roomId, cur.keys.accessToken, '/ack', {
    method: 'POST',
    body: { seqs: [item.seq] },
  }).catch(() => {});
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
    else if (m.type === 'ready') fetchMissed().catch(() => {});
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
    fetchMissed().catch(() => {});
  }
});

// ---------- Рендер ----------
async function renderMessages() {
  const box = $('#chatMessages');
  if (!box || !cur) return;
  const items = await roomMessages(cur.rec.roomId);
  box.replaceChildren();
  for (const it of items) {
    const m = it.msg;
    const div = document.createElement('div');
    if (m.type === 'intro') {
      div.className = 'chat-sys';
      div.textContent = `${m.nick || 'Участник'} присоединился к чату`;
    } else if (m.type === 'system' && typeof m.text === 'string' && m.text.startsWith('call:')) {
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
    } else {
      div.className = 'chat-msg' + (it.mine ? ' mine' : '');
      const head = document.createElement('div');
      head.className = 'chat-msg-head';
      head.textContent =
        `${m.nick || 'Участник'} · ${new Date(m.ts).toLocaleTimeString()}` +
        (it.sigOk ? '' : ' · подпись не подтверждена');
      const body = document.createElement('div');
      body.className = 'chat-msg-text';
      body.textContent = m.text || '';
      div.append(head, body);
    }
    box.append(div);
  }
  box.scrollTop = box.scrollHeight;
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
      const m = raw.match(/chat=([A-Za-z0-9_-]{43})/) || raw.match(/^([A-Za-z0-9_-]{43})$/);
      if (!m) return note('Вставьте ссылку на чат (#chat=…) или сам ключ.');
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
      renderMessages().catch(() => {});
    };
  }
  const send = $('#chatSend');
  const doSend = async () => {
    const input = $('#chatInput');
    const text = (input?.value || '').trim();
    if (!text || !cur) return;
    if (!cur.rec.nick) return note('Сначала введите никнейм.');
    try {
      await sendMsg('text', text);
      input.value = '';
    } catch (e) {
      note(e.message);
    }
  };
  if (send) send.onclick = doSend;
  const input = $('#chatInput');
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') doSend();
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
window.ZVChat = { openRoomBySeed, openFromHash: checkHash, canonical };
