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
//
// v26 — фазы 2 и 3 техплана + короткая ссылка + голосовые:
//   · PIN входа (фаза 2): PIN подмешивается в вывод ключей (PBKDF2 600k),
//     без PIN не выводится даже Room_ID; маркер &p=1 в ссылке; контрольная
//     фраза комнаты из 4 слов — для устной сверки;
//   · эпохи (фаза 3): случайный секрет эпохи, завёртка на ECDH-ключи
//     устройств оставленных участников (сообщения 'ecdh' и 'epoch');
//   · постоянная короткая ссылка #join=<код9>: режим алиаса PairingDO —
//     не одноразовая, отзываемая, с rate-limit выдач;
//   · картинки ≤3 МБ подгружаются и расшифровываются автоматически;
//   · голосовые сообщения: MediaRecorder → тот же файловый канал,
//     тип 'voice', плеер в ленте.
import { CONFIG, getWorkerBase } from './config.js?v=28';
import {
  b64u,
  newSecret,
  deriveChatKeys,
  derivePinIkm,
  deriveEpochRoomKey,
  wrapEpochSecret,
  unwrapEpochSecret,
  sha256hex,
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
  newJoinCode,
  aliasCodeHash,
  sealAliasPayload,
  openAliasPayload,
  REACT_EMOJIS,
  nextReactionOp,
  applyReactionState,
  applyEditOrDelete,
  applyPinState,
} from './crypto.js?v=28';
import { kvGet, kvPut, kvDel, kvAll, normalizeRoomRecord } from './store.js?v=28';
import {
  getChatDevice,
  getChatDeviceEcdh,
  getChatNostrSecret,
  signChatText,
  verifyChatSig,
  encryptWithVault,
  decryptWithVault,
} from './identity.js?v=28';
import {
  ChatTransportManager,
  FallbackTransport,
  compareChatEntries,
  shouldNotifyMessage,
  ToastGate,
  observeDevice,
  receiptState,
  RECEIPT_GLYPHS,
  RECEIPT_LABELS,
} from './chat-transport.js?v=28';

const $ = (s, r = document) => r.querySelector(s);
const te = new TextEncoder();

// Каноническая строка подписи НЕ меняется с v21: поле epoch в неё сознательно
// не входит — это лишь подсказка выбора ключа при расшифровке; подмена epoch
// ломает AEAD и сообщение отбрасывается, подпись при этом не страдает.
const canonical = (m) => `zv-chat-v1|${m.id}|${m.ts}|${m.devPub}|${m.type}|${m.text}`;
const chatLinkOf = (seed, pinProtected = false) =>
  `${location.origin}${location.pathname}#chat=${seed}${pinProtected ? '&p=1' : ''}`;
const greetLinkOf = (code) => `${location.origin}${location.pathname}#greet=${code}`;
const joinLinkOf = (code) => `${location.origin}${location.pathname}#join=${code}`;

let cur = null; // {rec, keys, keys0, device, ws, closed, backoff, pendingCall, online:Set, receipts:Map, typing, pin, pinIkm, epochKeys:Map, epochMissing}
let opening = false;
let pendingPinSeed = null; // seed, ожидающий ввода PIN (экран запроса PIN)
const fileState = new Map(); // fileId -> {progress, url, name, error, busy}
const voiceAudio = new Map(); // fileId -> HTMLAudioElement (сессионный кэш плеера)

// ---------- Сервер ----------
const chatBase = (roomId) => `${getWorkerBase().replace(/\/$/, '')}/chat/${roomId}`;
const workerBase = () => getWorkerBase().replace(/\/$/, '');

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
const saveRoom = (rec) => {
  // v27: backup.js слушает это событие и (с дебаунсом) перезаливает
  // зашифрованный бэкап списка комнат, если бэкап включён.
  try {
    window.dispatchEvent(new CustomEvent('zv-rooms-changed'));
  } catch {}
  return kvPut('rooms', rec.roomId, rec);
};
const loadRoom = (roomId) => kvGet('rooms', roomId);

async function storeMessage(rec, entry) {
  await kvPut('messages', rec.roomId + ':' + entry.hash, { roomId: rec.roomId, ...entry });
}

async function roomMessages(roomId) {
  const all = await kvAll('messages');
  return all
    .map((x) => x.value)
    .filter((m) => m && m.roomId === roomId)
    // v28: единая сортировка слияния каналов — по seq, если он есть, иначе
    // по ts+hash (сообщения резервного канала получают seq только после
    // ресинка в воркер и не должны при этом теряться или дублироваться).
    .sort(compareChatEntries);
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

// ---------- v28: уведомления о сообщениях, пока приложение живо ----------
// Серверный push с закрытым приложением сознательно не трогаем (VAPID
// отложен владельцем). Здесь: внутриприложенческий тост, системное
// уведомление через SW при скрытой вкладке и опциональный звук.
const roomTitleOf = (roomId) => `Чат ${String(roomId || '').slice(0, 8)}…`;
const notifyTextOn = () => {
  try {
    return localStorage.getItem('zvNotifyText') === '1';
  } catch {
    return false;
  }
};
const notifySoundOn = () => {
  try {
    return localStorage.getItem('zvNotifySound') === '1';
  } catch {
    return false;
  }
};
const toastGate = new ToastGate(2000);
let notifyAudioCtx = null;
function notifyBeep() {
  if (!notifySoundOn()) return;
  try {
    notifyAudioCtx = notifyAudioCtx || new (window.AudioContext || window.webkitAudioContext)();
    const ctx = notifyAudioCtx;
    const t = ctx.currentTime;
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.frequency.value = 880;
    g.gain.setValueAtTime(0.0001, t);
    g.gain.exponentialRampToValueAtTime(0.1, t + 0.02);
    g.gain.exponentialRampToValueAtTime(0.0001, t + 0.18);
    o.connect(g);
    g.connect(ctx.destination);
    o.start(t);
    o.stop(t + 0.2);
  } catch {}
}
function showChatToast({ title, body, roomId }) {
  try {
    document.querySelectorAll('.chat-toast').forEach((el) => el.remove());
    const el = document.createElement('div');
    el.className = 'chat-toast';
    const t = document.createElement('b');
    t.textContent = title;
    const b = document.createElement('span');
    b.textContent = body;
    el.append(t, b);
    el.onclick = () => {
      el.remove();
      if (cur && cur.rec.roomId === roomId) showChatScreen();
    };
    document.body.append(el);
    setTimeout(() => el.remove(), 6000);
  } catch {}
}
async function maybeNotifyMessage({ roomId, nick, preview, mine, roomActive }) {
  const d = toastGate.check(roomId, {
    mine,
    roomActive,
    documentHidden: typeof document !== 'undefined' && document.hidden,
  });
  if (!d.show) return d;
  const title = nick ? `${nick} · ${roomTitleOf(roomId)}` : roomTitleOf(roomId);
  let body = notifyTextOn() ? String(preview || 'Новое сообщение') : 'Новое сообщение';
  if (d.count > 1) body += ` (+${d.count - 1})`;
  showChatToast({ title, body, roomId });
  notifyBeep();
  if (d.system && 'Notification' in window && Notification.permission === 'granted') {
    try {
      const reg = await navigator.serviceWorker.ready;
      await reg.showNotification(title, {
        body,
        tag: 'zvchat-' + roomId,
        data: { chatRoom: roomId },
      });
    } catch {}
  }
  return d;
}

// ---------- v28: видимость устройств комнаты (без вайт-листа) ----------
// Реестр seenDevices живёт в записи комнаты. Первое появление устройства
// даёт одну локальную системную строку и, если комната не перед глазами,
// тост. Историческая подгрузка при открытии комнаты тревоги не поднимает
// (cur.syncingInitial). Это видимость, а не контроль доступа.
async function noteRoomDevice(dev, { hasIntro = false } = {}) {
  if (!cur || !dev || dev === cur.device.devicePub) return;
  const silent = !!cur.syncingInitial;
  const res = observeDevice(cur.rec.seenDevices, dev, { hasIntro, silent });
  cur.rec.seenDevices = res.seen;
  const roomId = cur.rec.roomId;
  await saveRoom(cur.rec).catch(() => {});
  if (!res.shouldAlert || !cur || cur.rec.roomId !== roomId) return;
  const entry = {
    hash: 'local-newdev-' + dev.slice(-16),
    msg: {
      v: 1,
      id: 'local-newdev-' + dev,
      ts: Date.now(),
      nick: '',
      devPub: '',
      type: 'system',
      text: 'newdev:' + dev,
    },
    sigOk: true,
    mine: false,
    reactions: {},
  };
  await storeMessage(cur.rec, entry).catch(() => {});
  if (cur && cur.rec.roomId === roomId) renderMessages().catch(() => {});
  maybeNotifyMessage({
    roomId,
    nick: '⚠ Новое устройство',
    preview: 'К комнате подключилось новое устройство',
    mine: false,
    roomActive: chatVisible(),
  }).catch(() => {});
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
// v28 (F): подпись чипа даты в ленте — «Сегодня»/«Вчера»/полная дата.
const dayLabel = (ts) => {
  const d = new Date(ts);
  const today = new Date();
  const yesterday = new Date(Date.now() - 24 * 3600_000);
  if (d.toDateString() === today.toDateString()) return 'Сегодня';
  if (d.toDateString() === yesterday.toDateString()) return 'Вчера';
  return d.toLocaleDateString([], { day: 'numeric', month: 'long', year: 'numeric' });
};
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
  if (m.deleted) return 'Сообщение удалено';
  if (m.type === 'intro') return `${m.nick || 'Участник'} присоединился`;
  if (m.type === 'voice') return 'Голосовое сообщение';
  if (m.type === 'epoch') return 'Сменена эпоха комнаты';
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
  if (m.type === 'system' && typeof m.text === 'string' && m.text.startsWith('gcall:')) {
    return 'Групповой звонок';
  }
  if (m.type === 'system' && typeof m.text === 'string' && m.text.startsWith('newdev:')) {
    return '⚠ Новое устройство в комнате';
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
    const msgs = (byRoom.get(r.roomId) || []).sort(compareChatEntries);
    // v27: превью — по последнему ВИДИМОМУ сообщению: управляющие типы
    // (реакции, правки, закрепы) и обмен ключами эпохи в превью не показываем.
    const visible = msgs.filter((x) => !CONTROL_TYPES.has(x.msg.type) && x.msg.type !== 'ecdh');
    const last = visible.length ? visible[visible.length - 1] : null;
    return { r, last, unread: unreadOf(r, visible), lastTs: last ? last.msg.ts : r.createdAt || 0 };
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
// Поиск локальной записи комнаты по seed: комнаты немного, seed сверяем
// расшифровкой seedEnc каждой записи (vault). Нужен до вывода ключей:
// PIN-защищённая комната имеет другой Room_ID, и без PIN её запись по
// Room_ID не найти.
async function findRoomBySeed(seedStr) {
  const target = String(seedStr).trim();
  const rooms = (await kvAll('rooms')).map((x) => x.value).filter(Boolean);
  for (const r of rooms) {
    try {
      if ((await decryptWithVault(r.seedEnc)) === target) return r;
    } catch {}
  }
  return null;
}

function showPinPrompt(seedStr) {
  pendingPinSeed = String(seedStr).trim();
  hideChatScreen();
  $('#chatPinBox')?.classList.remove('hidden');
  $('#chatPinEntry')?.focus();
  note('Этот чат защищён PIN-кодом: без него не выводится даже адрес комнаты. Введите PIN, который вам сообщили устно.');
}

// Ключ произвольной эпохи комнаты (лениво, с кэшем на сессию открытия).
// Эпоха 0 — базовый ключ из deriveChatKeys; эпохи ≥1 — из секрета эпохи.
async function keyForEpoch(n) {
  if (!cur) return null;
  if (cur.epochKeys.has(n)) return cur.epochKeys.get(n);
  const entry = (cur.rec.epochs || []).find((e) => e.n === n);
  if (!entry?.secret) return null;
  const seed = await decryptWithVault(cur.rec.seedEnc);
  const key = await deriveEpochRoomKey(b64u.dec(seed), b64u.dec(entry.secret), n, {
    pinIkm: cur.pinIkm,
  });
  cur.epochKeys.set(n, key);
  return key;
}

// Расшифровка blob любым известным ключом комнаты: текущая эпоха, затем
// остальные эпохи по убыванию, затем базовый ключ. Чужие/битые blob → null.
async function decryptAny(raw) {
  if (!cur) return null;
  const tried = new Set();
  const candidates = [cur.keys.roomKey, cur.keys0?.roomKey];
  const epochsDesc = [...(cur.rec.epochs || [])].sort((a, b) => b.n - a.n);
  for (const e of epochsDesc) {
    const k = await keyForEpoch(e.n);
    if (k) candidates.push(k);
  }
  for (const k of candidates) {
    if (!k || tried.has(k)) continue;
    tried.add(k);
    const m = await decryptChatMessage(k, raw);
    if (m) return m;
  }
  return null;
}

// opts.pin — PIN строкой; opts.pinProtected — ссылка помечена как PIN-комната
// (маркер &p=1): если PIN не задан и локально не сохранён, показываем экран
// запроса PIN и комнату не открываем.
async function openRoomBySeed(seedStr, opts = {}) {
  if (opening) return;
  opening = true;
  try {
    const seedBytes = b64u.dec(String(seedStr).trim());
    if (seedBytes.length !== 32) throw new Error('bad seed');
    let pin = opts.pin ? String(opts.pin) : null;
    const existing = await findRoomBySeed(seedStr);
    if (!pin && existing?.pinEnc) {
      try {
        pin = await decryptWithVault(existing.pinEnc);
      } catch {}
    }
    if (!pin && opts.pinProtected && !(existing && !existing.pinProtected)) {
      showPinPrompt(seedStr);
      return;
    }
    const pinIkm = pin ? await derivePinIkm(pin, seedBytes) : null;
    const keys0 = await deriveChatKeys(seedBytes, { pinIkm });
    if (cur && cur.keys.roomId === keys0.roomId) return; // уже открыта эта комната
    const device = await getChatDevice();
    let rec = await loadRoom(keys0.roomId);
    if (!rec && existing && existing.roomId === keys0.roomId) rec = existing;
    const freshRoom = !rec;
    if (!rec) {
      rec = {
        roomId: keys0.roomId,
        seedEnc: await encryptWithVault(b64u.enc(seedBytes)),
        nick: '',
        epoch: 0,
        lastSeq: 0,
        lastReadSeq: 0,
        members: {},
        introSent: false,
        createdAt: Date.now(),
      };
    }
    rec = normalizeRoomRecord(rec);
    if (pin) {
      rec.pinProtected = true;
      if (!rec.pinEnc) rec.pinEnc = await encryptWithVault(pin);
    }
    await saveRoom(rec);
    closeCurrent(false);
    // Ключ текущей эпохи: эпоха 0 — базовый; выше — из секрета эпохи, если
    // он у нас есть. Нет секрета (нас не оставили при ротации) — остаёмся на
    // базовом ключе: старая история читается, новые сообщения не расшифруются.
    const epochKeys = new Map([[0, keys0.roomKey]]);
    let currentKey = keys0.roomKey;
    let epochMissing = false;
    cur = {
      rec,
      keys: keys0,
      keys0,
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
      pin,
      pinIkm,
      epochKeys,
      epochMissing: false,
      // v27: состояние редактора и ленты
      replyTo: null, // {hash, name, excerpt} — цитата к следующему сообщению
      editing: null, // {hash} — редактируемое своё сообщение
      search: null, // {q, hashes:[], idx} — активный поиск по переписке
      menuTarget: null, // запись сообщения, для которой открыто меню действий
      expireTimer: null,
      draftTimer: null,
      // v28: транспорт (воркер/резерв), реестр устройств, ворота ника
      transportMode: 'worker',
      mgr: null,
      fb: null,
      healthTimer: null,
      syncingInitial: true, // до конца первой синхронизации алертов устройств нет
    };
    if (rec.epoch > 0) {
      const k = await keyForEpoch(rec.epoch);
      if (k) currentKey = k;
      else epochMissing = true;
    }
    cur.keys = { ...keys0, roomKey: currentKey };
    cur.epochMissing = epochMissing;
    const keys = cur.keys;
    showChatScreen();
    // v27: черновик этой комнаты — недописанный текст не теряется.
    const draftInput = $('#chatroom #chatInput');
    if (draftInput && rec.draft) {
      draftInput.value = rec.draft;
      // input-событие обновит видимость кнопок mic/send; typing не уйдёт —
      // WS в этот момент ещё не подключён (connectWs ниже).
      draftInput.dispatchEvent(new Event('input'));
    }
    $('#chatRoomTitle').textContent = `Чат ${keys.roomId.slice(0, 8)}…`;
    history.replaceState(
      null,
      '',
      location.pathname + '#chat=' + b64u.enc(seedBytes) + (rec.pinProtected ? '&p=1' : '')
    );
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
    // v28 (E): ник обязателен — до его ввода лента и поле ввода скрыты,
    // сообщения не рендерятся (раньше вошедший без ника молча читал чат).
    const nickGate = (on) => {
      $('#chatMessages')?.classList.toggle('hidden', on);
      $('#chatroom .chat-input-bar')?.classList.toggle('hidden', on);
      $('#chatPinBar')?.classList.toggle('hidden', on);
    };
    if (!rec.nick) {
      nickGate(true);
      $('#chatNickBox')?.classList.remove('hidden');
      $('#chatNickInput')?.focus();
      note('Введите никнейм — без него сообщения не показываются. Это единственная «регистрация», только для этой комнаты.');
    } else {
      nickGate(false);
      $('#chatNickBox')?.classList.add('hidden');
      renderMessages().catch(() => {});
      await sendIntroIfNeeded();
      await sendEcdhIfNeeded();
      await sendDialInfoIfNeeded();
    }
    connectWs();
    await fetchMissed();
    await syncState();
    await setupTransport();
    if (cur) cur.syncingInitial = false;
    status(cur && cur.transportMode === 'fallback' ? 'Резервный канал' : 'На связи');
    // v27: локальная чистка истёкших исчезающих сообщений.
    if (cur) {
      cur.expireTimer = setInterval(() => pruneExpired().catch(() => {}), 30_000);
      pruneExpired().catch(() => {});
    }
    if (epochMissing) {
      note(
        'При последней смене эпохи вас не включили в список участников: старая переписка доступна, новые сообщения вы читать не сможете. Попросите собеседника сменить эпоху ещё раз и оставить вас.'
      );
    } else if (pin && freshRoom) {
      note(
        `Контрольная фраза комнаты: ${keys.phrase}. Сверьте её голосом с тем, кто дал ссылку: если PIN введён неверно, фраза будет другой, а комната — пустой.`
      );
    }
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
    if (cur.expireTimer) clearInterval(cur.expireTimer);
    if (cur.draftTimer) clearTimeout(cur.draftTimer);
    if (cur.healthTimer) clearInterval(cur.healthTimer);
    try {
      cur.fb?.close();
    } catch {}
    cur.mgr = null;
    cur.fb = null;
    hideMsgMenu();
    try {
      cur.ws?.close();
    } catch {}
    cur = null;
  }
  if (hideScreen) hideChatScreen();
}

// ---------- Сообщения ----------
// v27: управляющие типы — применяются к состоянию комнаты/сообщений, в ленте
// пузырями не рендерятся (кроме 'ttl' — служебной строкой о смене таймера).
const CONTROL_TYPES = new Set(['react', 'edit', 'del', 'pin', 'unpin', 'ttl', 'dial']);

async function buildMsg(type, text) {
  const m = {
    v: 1,
    id: newMsgId(),
    ts: Date.now(),
    nick: cur.rec.nick || 'Гость',
    devPub: cur.device.devicePub,
    type,
    text,
    epoch: cur.rec.epoch || 0,
  };
  m.sig = await signChatText(canonical(m));
  return m;
}

// extra — дополнительные поля шифротекста (replyTo у текстовых сообщений).
async function sendMsg(type, text, extra = null) {
  if (!cur) throw new Error('no room');
  const m = await buildMsg(type, text);
  if (extra) Object.assign(m, extra);
  // v27: исчезающие сообщения — срок жизни дублируется внутри шифротекста
  // (для локального срока) и вне его (для серверной чистки по expires_at).
  const ttlSec =
    cur.rec.ttlSec > 0 && (type === 'text' || type === 'file' || type === 'voice')
      ? cur.rec.ttlSec
      : 0;
  if (ttlSec) m.ttlSec = ttlSec;
  const blob = await encryptChatMessage(cur.keys.roomKey, m);
  const hash = await hashChatBlob(blob);
  // v28 (D): резервный канал — тот же blob уходит в MQTT/Nostr, локально
  // помечается pendingWorkerSync и хранит blob для точного ресинка.
  if (cur.transportMode === 'fallback' && cur.fb) {
    await cur.fb.send(b64u.enc(blob));
    const entry = {
      hash,
      msg: m,
      sigOk: true,
      mine: true,
      reactions: {},
      pendingWorkerSync: true,
      blobB64: b64u.enc(blob),
    };
    if (ttlSec) entry.expiresAt = m.ts + ttlSec * 1000;
    await storeMessage(cur.rec, entry);
    if (CONTROL_TYPES.has(type)) await applyControlMessage(m, true).catch(() => {});
    renderMessages().catch(() => {});
    return m;
  }
  const r = await api(cur.keys.roomId, cur.keys.accessToken, '/msg', {
    method: 'POST',
    body: { blob: b64u.enc(blob), dev: cur.device.devicePub, ...(ttlSec ? { ttlSec } : {}) },
  });
  if (r.status === 429) throw new Error('Слишком часто: лимит 60 сообщений в минуту на комнату');
  if (r.status !== 200 && r.status !== 201) throw new Error('Сервер: ' + r.status);
  const entry = { hash, seq: r.data.seq, msg: m, sigOk: true, mine: true, reactions: {} };
  if (ttlSec) entry.expiresAt = m.ts + ttlSec * 1000;
  await storeMessage(cur.rec, entry);
  if (CONTROL_TYPES.has(type)) await applyControlMessage(m, true).catch(() => {});
  if (r.data.seq > cur.rec.lastSeq) {
    cur.rec.lastSeq = r.data.seq;
    cur.rec.lastReadSeq = Math.max(cur.rec.lastReadSeq || 0, r.data.seq);
    await saveRoom(cur.rec);
  }
  renderMessages().catch(() => {});
  return m;
}

// Применение управляющего сообщения к локальному состоянию. Вызывается и
// при ingest (с фактическим sigOk), и при собственной отправке (sigOk=true).
// Чужая подпись (sigOk=false) и чужие edit/del игнорируются внутри чистых
// функций crypto.js; здесь — только I/O и перерисовка.
async function applyControlMessage(msg, sigOk) {
  if (!cur || !msg || !CONTROL_TYPES.has(msg.type)) return;
  const roomId = cur.rec.roomId;
  const loadTarget = async () => {
    let target = null;
    try {
      target = JSON.parse(msg.text || '')?.target;
    } catch {}
    if (typeof target !== 'string' || !target) return null;
    const entry = await kvGet('messages', roomId + ':' + target);
    return entry ? { target, entry } : null;
  };
  try {
    if (msg.type === 'react') {
      if (!sigOk) return;
      const got = await loadTarget();
      if (!got) return;
      let data = null;
      try {
        data = JSON.parse(msg.text || '');
      } catch {}
      if (!data) return;
      got.entry.reactions = applyReactionState(got.entry.reactions, msg.devPub, data.emoji, data.op);
      await kvPut('messages', roomId + ':' + got.target, got.entry);
      renderMessages().catch(() => {});
      return;
    }
    if (msg.type === 'edit' || msg.type === 'del') {
      const got = await loadTarget();
      if (!got) return;
      // Метаданные файла нужны до применения del (текст зачищается).
      let fileId = null;
      if (msg.type === 'del' && (got.entry.msg.type === 'file' || got.entry.msg.type === 'voice')) {
        try {
          fileId = JSON.parse(got.entry.msg.text || '')?.fileId || null;
        } catch {}
      }
      if (applyEditOrDelete(got.entry, msg, sigOk)) {
        await kvPut('messages', roomId + ':' + got.target, got.entry);
        if (fileId) {
          // Удаление «для всех»: локально забываем скачанные чанки файла.
          const st = fileState.get(fileId);
          if (st?.url) URL.revokeObjectURL(st.url);
          fileState.delete(fileId);
          const a = voiceAudio.get(fileId);
          if (a) {
            try {
              a.pause();
            } catch {}
            voiceAudio.delete(fileId);
          }
        }
        renderMessages().catch(() => {});
      }
      return;
    }
    if (msg.type === 'pin' || msg.type === 'unpin') {
      const next = applyPinState(cur.rec.pinned, msg, sigOk);
      if (next !== undefined) {
        cur.rec.pinned = next;
        await saveRoom(cur.rec);
        renderMessages().catch(() => {});
      }
      return;
    }
    if (msg.type === 'ttl') {
      if (!sigOk) return;
      let ttl = null;
      try {
        ttl = Number(JSON.parse(msg.text || '')?.ttl);
      } catch {}
      if (Number.isFinite(ttl) && ttl >= 0 && ttl !== cur.rec.ttlSec) {
        cur.rec.ttlSec = ttl;
        await saveRoom(cur.rec);
        renderTtlState();
        renderMessages().catch(() => {});
      }
      return;
    }
  } catch {}
}

async function sendIntroIfNeeded() {
  if (!cur || cur.rec.introSent || !cur.rec.nick) return;
  await sendMsg('intro', cur.rec.nick);
  cur.rec.introSent = true;
  await saveRoom(cur.rec);
}

// v26, фаза 3: публикация ECDH-публичного ключа устройства в комнату — без
// него участник не может получить завёртку секрета новой эпохи. Шлётся один
// раз на комнату (флаг ecdhSent), получатели закрепляют ключ в members.
async function sendEcdhIfNeeded() {
  if (!cur || cur.rec.ecdhSent || !cur.rec.nick) return;
  const d = await getChatDeviceEcdh();
  await sendMsg('ecdh', d.ecdhPub);
  cur.rec.ecdhSent = true;
  await saveRoom(cur.rec);
}

// v28 (A): публикация данных личной идентичности для дозвона из чата.
// Отдельное управляющее сообщение 'dial' (в ленте не рендерится): masterPub
// и отпечаток публичны, cert/chain доказывают принадлежность устройства
// master-ключу. Секрет личной ссылки сюда НЕ входит: адрес дозвонa
// выводится из masterPub, а payload запечатывается ECDH-ключом устройства.
async function sendDialInfoIfNeeded() {
  if (!cur || cur.rec.dialInfoSent || !cur.rec.nick) return;
  const dev = cur.device;
  if (!dev?.masterPub) {
    cur.rec.dialInfoSent = true; // гостевое устройство: публиковать нечего
    await saveRoom(cur.rec);
    return;
  }
  await sendMsg(
    'dial',
    JSON.stringify({
      masterPub: dev.masterPub,
      masterFp: dev.masterFp || null,
      cert: dev.cert || null,
      chain: dev.chain || null,
    })
  );
  cur.rec.dialInfoSent = true;
  await saveRoom(cur.rec);
}

// ---------- Эпохи (v26, фаза 3) ----------
// Сообщение 'epoch' зашифровано ключом УХОДЯЩЕЙ эпохи (его читают все
// текущие участники), внутри — завёртки нового секрета только оставленным.
async function applyEpochMessage(msg) {
  if (!cur || !msg) return;
  let data = null;
  try {
    data = JSON.parse(msg.text || '');
  } catch {}
  if (!data || !Number.isInteger(data.n) || data.n <= 0) return;
  const n = data.n;
  if ((cur.rec.epochs || []).some((e) => e.n === n)) return; // уже применена
  const wrap = data.wraps?.[cur.device.devicePub];
  if (!wrap) {
    if (n > (cur.rec.epoch || 0)) {
      cur.epochMissing = true;
      note(
        'Собеседник сменил эпоху и не включил вас в список участников: старая переписка остаётся доступной, новые сообщения вы читать не сможете.'
      );
    }
    return;
  }
  const d = await getChatDeviceEcdh();
  const secret = await unwrapEpochSecret(d.ecdhPriv, wrap, cur.rec.roomId, n);
  if (!secret) return;
  cur.rec.epochs.push({ n, secret: b64u.enc(secret), ts: Date.now() });
  if (n > (cur.rec.epoch || 0)) {
    cur.rec.epoch = n;
    const k = await keyForEpoch(n);
    if (k) cur.keys = { ...cur.keys, roomKey: k };
  }
  cur.epochMissing = false;
  await saveRoom(cur.rec);
  renderMessages().catch(() => {});
}

function memberEcdhPub(dev) {
  if (!cur) return null;
  if (dev === cur.device.devicePub) return cur.ownEcdhPub || null;
  return cur.rec.members?.[dev]?.ecdhPub || null;
}

// Диалог ротации: список участников с чекбоксами. Участник без ecdhPub
// (старый клиент v25 или ни разу не заходил с v26) ключ эпохи получить НЕ
// может — его чекбокс заблокирован с честной пометкой, а не с обещанием
// «догоняющей» выдачи, которой в протоколе нет.
async function openEpochDialog() {
  if (!cur) return;
  if (!cur.rec.nick) return note('Сначала введите никнейм.');
  const d = await getChatDeviceEcdh();
  cur.ownEcdhPub = d.ecdhPub;
  await sendEcdhIfNeeded();
  const box = $('#epochMembers');
  const dlg = $('#chatEpochBox');
  if (!box || !dlg) return;
  box.replaceChildren();
  for (const dev of knownMembers()) {
    const isMe = dev === cur.device.devicePub;
    const pub = memberEcdhPub(dev);
    const row = document.createElement('label');
    row.className = 'chat-epoch-row';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.dataset.dev = dev;
    cb.checked = isMe || !!pub;
    cb.disabled = isMe || !pub;
    const nm = document.createElement('span');
    nm.className = 'chat-member-name';
    nm.textContent = nickOf(dev) + (isMe ? ' (вы)' : '');
    const fp = document.createElement('span');
    fp.className = 'chat-member-seen';
    fp.textContent = dev.slice(0, 10) + '…';
    row.append(cb, nm, fp);
    if (!pub && !isMe) {
      const warn = document.createElement('span');
      warn.className = 'chat-epoch-warn';
      warn.textContent =
        'нет ключа обмена (не заходил с v26) — при смене эпохи не сможет читать новые сообщения';
      row.append(warn);
    }
    box.append(row);
  }
  dlg.classList.remove('hidden');
}

async function doEpochRotate() {
  if (!cur) return;
  const box = $('#epochMembers');
  if (!box) return;
  const kept = [...box.querySelectorAll('input[type=checkbox][data-dev]')]
    .filter((cb) => cb.checked)
    .map((cb) => cb.dataset.dev);
  const me = cur.device.devicePub;
  if (!kept.includes(me)) kept.push(me);
  try {
    const d = await getChatDeviceEcdh();
    cur.ownEcdhPub = d.ecdhPub;
    const n = (cur.rec.epoch || 0) + 1;
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const wraps = {};
    for (const dev of kept) {
      const pub = dev === me ? d.ecdhPub : cur.rec.members?.[dev]?.ecdhPub;
      if (!pub) continue; // без ключа обмена завёртку не сделать
      wraps[dev] = await wrapEpochSecret(d.ecdhPriv, b64u.dec(pub), secret, cur.rec.roomId, n);
    }
    if (!wraps[me]) throw new Error('не удалось завернуть секрет эпохи для себя');
    // Сообщение эпохи уходит зашифрованным ключом уходящей эпохи.
    await sendMsg('epoch', JSON.stringify({ n, wraps }));
    cur.rec.epochs.push({ n, secret: b64u.enc(secret), ts: Date.now() });
    cur.rec.epoch = n;
    await saveRoom(cur.rec);
    const k = await keyForEpoch(n);
    if (k) cur.keys = { ...cur.keys, roomKey: k };
    $('#chatEpochBox')?.classList.add('hidden');
    note(
      `Эпоха сменена: теперь эпоха ${n}. Новые сообщения читают только оставленные участники (${Object.keys(wraps).length}); старая история у исключённых на устройствах остаётся.`
    );
    renderMessages().catch(() => {});
  } catch (e) {
    note('Не удалось сменить эпоху: ' + e.message);
  }
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
  // v28 (E): присутствие — источник реестра устройств без ника.
  noteRoomDevice(dev, { hasIntro: !!cur.rec.members[dev]?.nick }).catch(() => {});
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
    const msg = await decryptAny(raw);
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
    if (msg.type === 'ecdh' && msg.devPub && sigOk) {
      // Ключ обмена участника: закрепляем только при валидной подписи, иначе
      // завёртку эпохи можно было бы подменить чужим ключом.
      const pub = String(msg.text || '');
      if (/^[A-Za-z0-9_-]{87}$/.test(pub)) {
        cur.rec.members[msg.devPub] = { ...cur.rec.members[msg.devPub], ecdhPub: pub };
        await saveRoom(cur.rec);
      }
    }
    // v28 (A): данные личной идентичности для дозвона — только с подписью.
    if (msg.type === 'dial' && msg.devPub && sigOk) {
      try {
        const d = JSON.parse(msg.text || '');
        if (d && typeof d.masterPub === 'string' && /^[A-Za-z0-9_-]{87}$/.test(d.masterPub)) {
          cur.rec.members[msg.devPub] = {
            ...cur.rec.members[msg.devPub],
            masterPub: d.masterPub,
            masterFp: d.masterFp || null,
            cert: d.cert || null,
            chain: d.chain || null,
          };
          await saveRoom(cur.rec);
          renderMembersList();
        }
      } catch {}
    }
    if (msg.type === 'epoch') {
      await applyEpochMessage(msg).catch(() => {});
    }
    // v28 (E): реестр увиденных устройств (алерт — внутри noteRoomDevice).
    if (!mine && msg.devPub) {
      noteRoomDevice(msg.devPub, {
        hasIntro: !!cur.rec.members[msg.devPub]?.nick,
      }).catch(() => {});
    }
    // v28 (D): дедуп по id сообщения между каналами — один и тот же msg мог
    // прийти и из воркера, и из резервного канала разными blob-ами.
    const byId = (await roomMessages(cur.rec.roomId)).find(
      (x) => x.msg?.id && msg.id && x.msg.id === msg.id
    );
    if (!byId) {
      const entry = { hash, msg, sigOk, mine, reactions: {} };
      // seq есть только у воркера; у резервного канала его нет до ресинка.
      if (Number.isFinite(item.seq)) entry.seq = item.seq;
      // v27: локальный срок жизни исчезающего сообщения — из шифротекста.
      if (msg.ttlSec > 0) entry.expiresAt = msg.ts + msg.ttlSec * 1000;
      await storeMessage(cur.rec, entry);
      if (CONTROL_TYPES.has(msg.type)) {
        await applyControlMessage(msg, sigOk).catch(() => {});
      }
      renderMessages().catch(() => {});
      if (!mine) renderRoomList().catch(() => {});
      // v28 (B): уведомление, пока приложение живо.
      if (!mine && !CONTROL_TYPES.has(msg.type) && msg.type !== 'ecdh') {
        maybeNotifyMessage({
          roomId: cur.rec.roomId,
          nick: msg.nick || 'Участник',
          preview: previewOf(msg),
          mine: false,
          roomActive: chatVisible(),
        }).catch(() => {});
      }
    }
  }
  if (Number.isFinite(item.seq)) {
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

// ---------- v28: транспортный менеджер и резервный канал ----------
// Основной канал — воркер (WS + HTTP, поведение не менялось). При его
// недоступности дольше порога менеджер переключает комнату на
// FallbackTransport (MQTT live + Nostr store); сообщения этого периода
// помечаются pendingWorkerSync и при возврате воркера публикуются в него
// ровно тем же blob (серверный дедуп по хэшу съедает дубли).
async function workerHealthOk() {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 2500);
    const r = await fetch(workerBase() + '/health', { signal: ctl.signal, cache: 'no-store' });
    clearTimeout(t);
    return r.ok;
  } catch {
    return false;
  }
}
async function healthTick() {
  if (!cur || cur.closed || !cur.mgr) return;
  const ok = await workerHealthOk();
  if (!cur || cur.closed || !cur.mgr) return;
  if (ok) await cur.mgr.noteWorkerSuccess().catch(() => {});
  else await cur.mgr.noteWorkerFailure().catch(() => {});
}
function applyTransportMode(mode) {
  if (!cur) return;
  cur.transportMode = mode === 'worker' ? 'worker' : 'fallback';
  const fb = cur.transportMode === 'fallback';
  $('#chatFallbackBadge')?.classList.toggle('hidden', !fb);
  const attach = $('#chatAttach');
  if (attach) {
    attach.disabled = fb;
    attach.title = fb
      ? 'Файлы недоступны на резервном канале'
      : 'Прикрепить файл';
  }
  const mic = $('#chatMic');
  if (mic) {
    mic.disabled = fb;
    mic.title = fb ? 'Голосовые недоступны на резервном канале' : 'Голосовое сообщение';
  }
  if (fb) {
    status('Резервный канал');
    try {
      cur.ws?.close();
    } catch {}
    // Подтянуть историю из Nostr store за время отсутствия воркера
    // (fetchSince ждёт курсор в секундах, fallbackSince храним в мс).
    cur.fb
      ?.fetchSince(Math.floor((cur.rec.fallbackSince || 0) / 1000))
      .then(async (items) => {
        let maxTs = cur.rec.fallbackSince || 0;
        for (const it of items || []) {
          const blob = typeof it === 'string' ? it : it?.blob;
          if (blob) await ingest({ blob }).catch(() => {});
          const ts = typeof it === 'object' ? it?.ts || 0 : 0;
          if (ts > maxTs) maxTs = ts;
        }
        if (cur && maxTs > (cur.rec.fallbackSince || 0)) {
          cur.rec.fallbackSince = maxTs;
          saveRoom(cur.rec).catch(() => {});
        }
      })
      .catch(() => {});
  } else {
    status('На связи');
    if (!cur.ws || cur.ws.readyState > 1) connectWs();
    fetchMissed().catch(() => {});
  }
  renderPresence();
}
// Ресинк при возврате воркера: pending-сообщения публикуются в воркер тем
// же blob, затем докачивается пропущенное. Ошибка любого шага оставляет
// комнату на резервном канале (менеджер это обработает).
async function resyncToWorker() {
  if (!cur) return;
  const roomId = cur.rec.roomId;
  const items = await roomMessages(roomId);
  for (const it of items) {
    if (!it.pendingWorkerSync || !it.blobB64) continue;
    const r = await api(roomId, cur.keys.accessToken, '/msg', {
      method: 'POST',
      body: { blob: it.blobB64, dev: cur.device.devicePub },
    }).catch(() => null);
    if (!r || (r.status !== 200 && r.status !== 201 && r.status !== 409)) {
      throw new Error('ресинк: воркер отклонил сообщение (' + (r?.status || 'нет сети') + ')');
    }
    const upd = { ...it };
    delete upd.pendingWorkerSync;
    delete upd.blobB64;
    if (Number.isFinite(r.data?.seq)) upd.seq = r.data.seq;
    await kvPut('messages', roomId + ':' + it.hash, { roomId, ...upd });
  }
  await fetchMissed();
}
async function setupTransport() {
  if (!cur || cur.mgr) return;
  let secret = null;
  try {
    secret = await getChatNostrSecret();
  } catch {}
  const fb = new FallbackTransport({
    roomId: cur.keys.roomId,
    brokers: CONFIG.MQTT_BROKERS || [],
    relays: CONFIG.NOSTR_RELAYS || [],
    secret,
    onBlob: (blob) => {
      ingest({ blob }).catch(() => {});
    },
  });
  cur.fb = fb;
  cur.transportMode = 'worker';
  cur.mgr = new ChatTransportManager({
    fallback: fb,
    thresholdMs: 8000,
    onModeChange: (m) => applyTransportMode(m),
    onResync: () => resyncToWorker(),
  });
  cur.healthTimer = setInterval(() => {
    healthTick().catch(() => {});
  }, 5000);
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
    // v28 (D): живой WS воркера — сигнал менеджеру каналов.
    cur.mgr?.noteWorkerSuccess().catch(() => {});
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
    // v28 (D): обрыв WS кормит менеджер; в fallback переподключения к
    // воркеру не крутим — возвратом управляет health-цикл менеджера.
    cur.mgr?.noteWorkerFailure().catch(() => {});
    if (cur.transportMode === 'fallback') return;
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
  if (!cur || cur.closed || cur.transportMode === 'fallback') return;
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

// extra.voice = {durSec} — голосовое сообщение: тот же файловый канал и то
// же шифрование, отличается только тип сообщения ('voice') и метаданные.
async function uploadFile(file, extra = {}) {
  if (!cur) return;
  if (!cur.rec.nick) return note('Сначала введите никнейм.');
  // v28 (D): файловый канал существует только у воркера.
  if (cur.transportMode === 'fallback') {
    return note('Файлы и голосовые недоступны на резервном канале: дождитесь возврата основного сервера.');
  }
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
    if (extra.voice) meta.durSec = extra.voice.durSec || 0;
    await sendMsg(extra.voice ? 'voice' : 'file', JSON.stringify(meta));
    note(extra.voice ? 'Голосовое сообщение отправлено.' : 'Файл отправлен.');
  } catch (e) {
    note('Не удалось отправить файл: ' + e.message);
  } finally {
    setFileProgress(null);
  }
}

// opts.auto — автозагрузка (картинки ≤3 МБ и голосовые): не дёргаем
// сохранение файла по завершении, только заполняем кэш и превью/плеер.
async function downloadFile(meta, card, opts = {}) {
  const st = fileState.get(meta.fileId) || {};
  if (st.busy) return;
  if (st.url) {
    if (opts.auto) return;
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
    st.progress = 1;
    fileState.set(meta.fileId, st);
    renderFileCardState(meta, card, st);
    if (!opts.auto && !(meta.mime || '').startsWith('image/')) {
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
  const barFill = card.querySelector('.chat-file-bar-fill');
  if (barFill) {
    barFill.style.width = st.busy || st.progress ? Math.round((st.progress || 0) * 100) + '%' : '0%';
  }
  if (btn) {
    btn.disabled = !!st.busy;
    btn.textContent = st.busy
      ? `Загрузка ${Math.round((st.progress || 0) * 100)}%`
      : st.url
        ? 'Сохранить файл'
        : st.error
          ? 'Повторить'
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

// ---------- Голосовые сообщения (v26) ----------
const VOICE_MAX_MS = 10 * 60_000;
let voiceRec = null; // {mr, chunks, stream, startedAt, timer, discard}

const fmtDur = (sec) => {
  const s = Math.max(0, Math.round(sec || 0));
  return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
};

function voiceUiRecording(on) {
  $('#chatRecBar')?.classList.toggle('hidden', !on);
  const bar = $('#chatroom .chat-input-bar');
  if (bar) bar.classList.toggle('hidden', on);
}

async function startVoiceRec() {
  if (!cur) return;
  if (!cur.rec.nick) return note('Сначала введите никнейм.');
  if (voiceRec) return;
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  } catch (e) {
    return note('Нет доступа к микрофону: ' + (e?.message || e));
  }
  try {
    const mime =
      ['audio/webm;codecs=opus', 'audio/webm', 'audio/ogg;codecs=opus', 'audio/mp4'].find(
        (m) => typeof MediaRecorder !== 'undefined' && MediaRecorder.isTypeSupported(m)
      ) || '';
    const mr = new MediaRecorder(stream, mime ? { mimeType: mime } : undefined);
    const rec = { mr, chunks: [], stream, startedAt: Date.now(), timer: null, discard: false };
    voiceRec = rec;
    mr.ondataavailable = (e) => {
      if (e.data?.size) rec.chunks.push(e.data);
    };
    mr.onstop = () => finishVoiceRec(rec);
    mr.start(250);
    voiceUiRecording(true);
    const tick = () => {
      const el = $('#chatRecTime');
      if (el) el.textContent = fmtDur((Date.now() - rec.startedAt) / 1000);
      if (Date.now() - rec.startedAt >= VOICE_MAX_MS) stopVoiceRec(true); // автостоп 10 минут — отправить
    };
    tick();
    rec.timer = setInterval(tick, 250);
  } catch (e) {
    stream.getTracks().forEach((t) => t.stop());
    voiceRec = null;
    note('Не удалось начать запись: ' + (e?.message || e));
  }
}

function stopVoiceRec(send) {
  if (!voiceRec) return;
  voiceRec.discard = !send;
  try {
    voiceRec.mr.stop();
  } catch {
    finishVoiceRec(voiceRec);
  }
}

async function finishVoiceRec(rec) {
  if (voiceRec !== rec) return;
  voiceRec = null;
  if (rec.timer) clearInterval(rec.timer);
  rec.stream?.getTracks().forEach((t) => t.stop());
  voiceUiRecording(false);
  if (rec.discard || !rec.chunks.length) return;
  const type = rec.mr.mimeType || 'audio/webm';
  const blob = new Blob(rec.chunks, { type });
  const ext = type.includes('ogg') ? 'ogg' : type.includes('mp4') ? 'm4a' : 'webm';
  const durSec = Math.max(1, Math.round((Date.now() - rec.startedAt) / 1000));
  const file = new File([blob], 'voice.' + ext, { type });
  await uploadFile(file, { voice: { durSec } }).catch(() => {});
}

// Плеер голосового: play/pause, прогресс по timeupdate, перемотка кликом.
function wireVoicePlayer(wrap, meta) {
  const btn = wrap.querySelector('.chat-voice-play');
  const bar = wrap.querySelector('.chat-voice-bar');
  const fill = wrap.querySelector('.chat-voice-fill');
  const time = wrap.querySelector('.chat-voice-time');
  const total = meta.durSec || 0;
  if (time) time.textContent = fmtDur(total);
  const ensureAudio = () => {
    let a = voiceAudio.get(meta.fileId);
    if (!a) {
      const st = fileState.get(meta.fileId);
      if (!st?.url) return null;
      a = new Audio(st.url);
      voiceAudio.set(meta.fileId, a);
      a.addEventListener('timeupdate', () => {
        const dur = a.duration || total;
        if (fill && dur) fill.style.width = (a.currentTime / dur) * 100 + '%';
        if (time) time.textContent = fmtDur(a.currentTime) + ' / ' + fmtDur(dur);
      });
      a.addEventListener('ended', () => {
        if (btn) btn.textContent = '▶';
        if (fill) fill.style.width = '0%';
        if (time) time.textContent = fmtDur(total);
      });
    }
    return a;
  };
  if (btn) {
    btn.onclick = async () => {
      const st = fileState.get(meta.fileId);
      if (!st?.url && !st?.busy) {
        await downloadFile(meta, wrap.closest('.chat-file') || wrap, { auto: true }).catch(() => {});
      }
      const a = ensureAudio();
      if (!a) return;
      if (a.paused) {
        for (const other of voiceAudio.values()) if (other !== a) other.pause();
        await a.play().catch(() => {});
        btn.textContent = '⏸';
      } else {
        a.pause();
        btn.textContent = '▶';
      }
    };
  }
  if (bar) {
    bar.onclick = (e) => {
      const a = ensureAudio();
      if (!a || !a.duration) return;
      const r = bar.getBoundingClientRect();
      a.currentTime = ((e.clientX - r.left) / r.width) * a.duration;
    };
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

// Возвращает true, если комната открыта; false — если код не подошёл
// (чтобы redeemCode мог попробовать второе пространство кодов).
async function redeemGreet(codeRaw, opts = {}) {
  const code = String(codeRaw || '').trim();
  if (!/^[A-Za-z0-9_-]{9}$/.test(code)) {
    note('Код подключения — 9 символов.');
    return false;
  }
  try {
    note('Проверяю код подключения…');
    const codeHash = await greetCodeHash(code);
    const r = await pairApi('/pair/claim', { codeHash });
    if (r.status === 404) {
      if (!opts.quiet) note('Код не найден или уже использован.');
      return false;
    }
    if (r.status === 410) {
      note('Код истёк (15 минут) или лимит попыток исчерпан. Попросите новый.');
      return false;
    }
    if (r.status !== 200 || !r.data.blob) {
      note('Сервер пар отклонил запрос: ' + r.status);
      return false;
    }
    const payload = await openGreetPayload(code, r.data.blob);
    if (!payload?.seed) {
      note('Не удалось расшифровать приглашение этим кодом.');
      return false;
    }
    note('');
    await openRoomBySeed(payload.seed);
    return true;
  } catch (e) {
    note('Не удалось подключиться по коду: ' + e.message);
    return false;
  }
}

// ---------- Постоянная короткая ссылка (v26, алиас PairingDO) ----------
async function aliasCreate() {
  if (!cur) return false;
  try {
    const seed = await decryptWithVault(cur.rec.seedEnc);
    for (let attempt = 0; attempt < 5; attempt++) {
      const code = newJoinCode();
      const codeHash = await aliasCodeHash(code);
      const blob = await sealAliasPayload(code, { seed, roomId: cur.rec.roomId });
      const admin = b64u.enc(crypto.getRandomValues(new Uint8Array(16))); // 128 бит
      const adminHash = await sha256hex(admin);
      const r = await pairApi('/pair/alias', { codeHash, blob, adminHash });
      if (r.status === 409) continue; // код занят — берём другой
      if (r.status !== 200 && r.status !== 201) {
        throw new Error('сервер пар недоступен (' + r.status + ') — воркер v26 задеплоен?');
      }
      cur.rec.alias = { code, adminEnc: await encryptWithVault(admin) };
      await saveRoom(cur.rec);
      return true;
    }
    throw new Error('не удалось подобрать свободный код');
  } catch (e) {
    note('Не удалось создать короткую ссылку: ' + e.message);
    return false;
  }
}

async function aliasRevokeCurrent() {
  if (!cur?.rec.alias) return true;
  try {
    const admin = await decryptWithVault(cur.rec.alias.adminEnc);
    const codeHash = await aliasCodeHash(cur.rec.alias.code);
    const r = await pairApi('/pair/revoke', { codeHash, admin });
    if (r.status !== 200 && r.status !== 404) {
      throw new Error('сервер пар отклонил отзыв (' + r.status + ')');
    }
    cur.rec.alias = null;
    await saveRoom(cur.rec);
    return true;
  } catch (e) {
    note('Не удалось отозвать короткую ссылку: ' + e.message);
    return false;
  }
}

async function renderAliasBox() {
  const box = $('#chatAliasBox');
  if (!box || !cur) return;
  box.classList.remove('hidden');
  // Создание — автоматически при первом открытии блока.
  if (!cur.rec.alias) await aliasCreate();
  const input = $('#aliasLink');
  const state = $('#aliasState');
  if (cur.rec.alias) {
    if (input) input.value = joinLinkOf(cur.rec.alias.code);
    if (state) {
      state.textContent =
        'Постоянная короткая ссылка этой комнаты. Работает, пока вы её не отзовёте; длинная ссылка при этом остаётся главным ключом.';
    }
  } else if (state) {
    state.textContent = 'Короткая ссылка не создана.';
  }
}

// Подключение по постоянной ссылке. Возвращает true при успехе.
async function redeemJoin(codeRaw) {
  const code = String(codeRaw || '').trim();
  if (!/^[A-Za-z0-9_-]{9}$/.test(code)) {
    note('Код подключения — 9 символов.');
    return false;
  }
  try {
    note('Проверяю короткую ссылку…');
    const codeHash = await aliasCodeHash(code);
    const r = await pairApi('/pair/claim', { codeHash });
    if (r.status === 404) return false;
    if (r.status === 429) {
      note('Слишком много подключений по этому коду за час — подождите или попросите длинную ссылку.');
      return false;
    }
    if (r.status !== 200 || !r.data.blob) {
      note('Сервер пар отклонил запрос: ' + r.status);
      return false;
    }
    const payload = await openAliasPayload(code, r.data.blob);
    if (!payload?.seed) {
      note('Не удалось расшифровать приглашение этим кодом.');
      return false;
    }
    note('');
    await openRoomBySeed(payload.seed);
    return true;
  } catch (e) {
    note('Не удалось подключиться по короткой ссылке: ' + e.message);
    return false;
  }
}

// Единая точка входа для кода из 9 символов (поле на главном экране).
// Пространства разные: greet — одноразовый, join — постоянный. Порядок
// важен: СНАЧАЛА пробуем алиас (его claim ничего не сжигает), при 404 —
// greet (его claim одноразовый, поэтому он второй, а не первый).
async function redeemCode(code) {
  if (await redeemJoin(code)) return;
  await redeemGreet(code);
}

// ---------- Присутствие и шапка ----------
function knownMembers() {
  if (!cur) return [];
  const devs = new Set([
    cur.device.devicePub,
    ...Object.keys(cur.rec.members || {}),
    ...cur.receipts.keys(),
    ...cur.online,
    // v28 (E): устройства из реестра увиденных — видны, даже если молчат.
    ...Object.keys(cur.rec.seenDevices || {}),
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
    (cur.online.size ? '' : ' · собеседники не в сети') +
    (cur.transportMode === 'fallback' ? ' · резервный канал' : '');
  // v28 (A): групповой звонок имеет смысл при двух и более собеседниках.
  $('#chatGroupCallBtn')?.classList.toggle('hidden', others.length < 2);
}

function renderMembersList() {
  const box = $('#chatMembersList');
  if (!box || !cur || box.classList.contains('hidden')) return;
  box.replaceChildren();
  // v26, фаза 2: контрольная фраза комнаты — для устной сверки с собеседником.
  if (cur.keys0?.phrase) {
    const ph = document.createElement('div');
    ph.className = 'chat-phrase';
    ph.textContent =
      `Контрольная фраза: ${cur.keys0.phrase}` +
      (cur.rec.pinProtected ? ' · комната защищена PIN' : '') +
      ` · эпоха ${cur.rec.epoch || 0}`;
    box.append(ph);
  }
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
    // v28 (E): устройство без intro видно честной строкой, а не «Участник».
    const hasIntro = !!cur.rec.members?.[dev]?.nick;
    name.textContent = isMe
      ? nickOf(dev) + ' (вы)'
      : hasIntro
        ? nickOf(dev)
        : `Без ника · устройство …${dev.slice(-6)}`;
    const seen = document.createElement('span');
    seen.className = 'chat-member-seen';
    if (isMe) seen.textContent = 'это вы';
    else if (cur.online.has(dev)) seen.textContent = 'онлайн';
    else {
      const ls = cur.rec.members?.[dev]?.lastSeen;
      seen.textContent = ls ? 'был(а) в ' + fmtTime(ls) : 'не в сети';
    }
    row.append(av, name, seen);
    // v28 (A): кнопка дозвона участнику с личной идентичностью.
    if (!isMe && cur.rec.members?.[dev]?.masterPub) {
      const cb = document.createElement('button');
      cb.className = 'btn small ghost chat-member-call';
      cb.textContent = '📞';
      cb.title = 'Позвонить участнику (его телефон зазвонит)';
      cb.setAttribute('aria-label', 'Позвонить участнику');
      cb.onclick = (e) => {
        e.stopPropagation();
        dialMember(dev)
          .then((r) => {
            if (!r.dialed) note('Не удалось дозвониться участнику — отправлено приглашение в чат.');
          })
          .catch(() => {});
      };
      row.append(cb);
    }
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

// ---------- v27: цитаты, закреп, поиск, сроки жизни ----------
function excerptOf(it) {
  const m = it?.msg || {};
  if (m.deleted) return 'Сообщение удалено';
  if (m.type === 'voice') return 'Голосовое сообщение';
  if (m.type === 'file') {
    try {
      return 'Файл: ' + (JSON.parse(m.text || '{}').name || 'без имени');
    } catch {
      return 'Файл';
    }
  }
  return String(m.text || '').slice(0, 120);
}

const TTL_OPTIONS = [
  { sec: 0, label: 'Выключено' },
  { sec: 3600, label: '1 час' },
  { sec: 24 * 3600, label: '24 часа' },
  { sec: 7 * 24 * 3600, label: '7 дней' },
];
const ttlLabel = (sec) => TTL_OPTIONS.find((o) => o.sec === sec)?.label || `${sec} с`;

// Локальная чистка истёкших исчезающих сообщений (сервер чистит по своему
// expires_at независимо; здесь — чтобы не висели в ленте офлайн).
async function pruneExpired() {
  if (!cur) return;
  const items = await roomMessages(cur.rec.roomId);
  const now = Date.now();
  let removed = false;
  for (const it of items) {
    if (it.expiresAt && it.expiresAt <= now) {
      await kvDel('messages', cur.rec.roomId + ':' + it.hash);
      removed = true;
    }
  }
  if (removed && cur) renderMessages().catch(() => {});
}

function scrollToMessage(hash, flash = true) {
  const box = $('#chatMessages');
  if (!box || !hash) return;
  const el = box.querySelector(`[data-hash="${hash}"]`);
  if (!el) return;
  el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  if (flash) {
    el.classList.add('chat-flash');
    setTimeout(() => el.classList.remove('chat-flash'), 1300);
  }
}

function renderPinBar(items) {
  const bar = $('#chatPinBar');
  if (!bar || !cur) return;
  const pin = cur.rec.pinned;
  if (!pin?.hash) {
    bar.classList.add('hidden');
    return;
  }
  const target = (items || []).find((it) => it.hash === pin.hash);
  const textEl = $('#chatPinText');
  if (textEl) {
    textEl.textContent = target
      ? `${target.msg.nick || 'Участник'}: ${excerptOf(target)}`
      : 'Закреплённое сообщение';
  }
  bar.classList.remove('hidden');
}

function renderTextWithMarks(el, text, q) {
  const needle = (q || '').trim().toLowerCase();
  if (!needle) {
    el.textContent = text;
    return;
  }
  const lower = text.toLowerCase();
  let pos = 0;
  let idx = lower.indexOf(needle);
  if (idx < 0) {
    el.textContent = text;
    return;
  }
  while (idx >= 0) {
    if (idx > pos) el.append(document.createTextNode(text.slice(pos, idx)));
    const mark = document.createElement('mark');
    mark.textContent = text.slice(idx, idx + needle.length);
    el.append(mark);
    pos = idx + needle.length;
    idx = lower.indexOf(needle, pos);
  }
  if (pos < text.length) el.append(document.createTextNode(text.slice(pos)));
}

// Реакция из UI: toggle по текущему локальному состоянию.
async function toggleReaction(it, emoji) {
  if (!cur) return;
  const op = nextReactionOp(it.reactions, cur.device.devicePub, emoji);
  if (!op) return;
  try {
    await sendMsg('react', JSON.stringify({ target: it.hash, emoji, op }));
  } catch (e) {
    note(e.message);
  }
}

// ---------- v27: меню действий сообщения ----------
function hideMsgMenu() {
  $('#chatMsgMenu')?.classList.add('hidden');
  if (cur) cur.menuTarget = null;
}

function openMsgMenu(it, anchor) {
  const menu = $('#chatMsgMenu');
  if (!menu || !cur) return;
  if (cur.menuTarget?.hash === it.hash && !menu.classList.contains('hidden')) {
    hideMsgMenu();
    return;
  }
  cur.menuTarget = it;
  const editBtn = $('#msgActEdit');
  const delBtn = $('#msgActDel');
  if (editBtn) editBtn.classList.toggle('hidden', !(it.mine && it.msg.type === 'text'));
  if (delBtn) delBtn.classList.toggle('hidden', !it.mine);
  menu.classList.remove('hidden');
  const r = anchor.getBoundingClientRect();
  menu.style.top = Math.min(window.innerHeight - 240, r.bottom + 4) + 'px';
  menu.style.left = Math.max(8, Math.min(window.innerWidth - 200, r.left)) + 'px';
}

function renderReplyBar() {
  const bar = $('#chatReplyBar');
  if (!bar || !cur) return;
  if (!cur.replyTo) {
    bar.classList.add('hidden');
    return;
  }
  const t = $('#chatReplyText');
  if (t) t.textContent = `${cur.replyTo.name}: ${cur.replyTo.excerpt}`;
  bar.classList.remove('hidden');
}

function renderEditBar() {
  const bar = $('#chatEditBar');
  if (!bar || !cur) return;
  bar.classList.toggle('hidden', !cur.editing);
}

function renderTtlState() {
  const sel = $('#chatTtlSelect');
  if (sel && cur) sel.value = String(cur.rec.ttlSec || 0);
  const curEl = $('#chatTtlCurrent');
  if (curEl && cur) {
    curEl.textContent =
      cur.rec.ttlSec > 0
        ? `Сейчас: сообщения исчезают через ${ttlLabel(cur.rec.ttlSec)} после отправки.`
        : 'Сейчас: сообщения не исчезают.';
  }
}

// ---------- Рендер ----------
async function renderMessages() {
  const box = $('#chatMessages');
  if (!box || !cur) return;
  const nowMs = Date.now();
  const items = (await roomMessages(cur.rec.roomId)).filter((it) => {
    if (it.expiresAt && it.expiresAt <= nowMs) {
      kvDel('messages', cur.rec.roomId + ':' + it.hash).catch(() => {});
      return false;
    }
    return true;
  });
  renderPinBar(items);
  // v28 (F): группировка подряд идущих пузырей одного автора (пауза < 5 мин,
  // один день): аватар — у нижнего в группе, ник — у первого.
  const bubbleItems = items.filter((x) => ['text', 'file', 'voice'].includes(x.msg.type));
  const grp = new Map();
  bubbleItems.forEach((x, i) => {
    const same = (a, b) =>
      !!a &&
      !!b &&
      a.msg.devPub === b.msg.devPub &&
      Math.abs(b.msg.ts - a.msg.ts) < 5 * 60_000 &&
      new Date(a.msg.ts).toDateString() === new Date(b.msg.ts).toDateString();
    grp.set(x.hash, { first: !same(bubbleItems[i - 1], x), last: !same(x, bubbleItems[i + 1]) });
  });
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  box.replaceChildren();
  let lastDayKey = '';
  for (const it of items) {
    const m = it.msg;
    const dk = new Date(m.ts).toDateString();
    if (dk !== lastDayKey) {
      lastDayKey = dk;
      const chip = document.createElement('div');
      chip.className = 'chat-date-chip';
      chip.textContent = dayLabel(m.ts);
      box.append(chip);
    }
    if (m.type === 'intro') {
      const div = document.createElement('div');
      div.className = 'chat-sys';
      div.textContent = `${m.nick || 'Участник'} присоединился к чату`;
      box.append(div);
      continue;
    }
    if (m.type === 'ecdh') {
      continue; // служебный обмен ключами эпохи — в ленте не показываем
    }
    if (m.type === 'epoch') {
      let n = '';
      try {
        n = JSON.parse(m.text || '')?.n ?? '';
      } catch {}
      const div = document.createElement('div');
      div.className = 'chat-sys';
      div.textContent = `Эпоха сменена · ${n}`;
      box.append(div);
      continue;
    }
    if (m.type === 'ttl') {
      let sec = 0;
      try {
        sec = Number(JSON.parse(m.text || '{}')?.ttl) || 0;
      } catch {}
      const div = document.createElement('div');
      div.className = 'chat-sys';
      div.textContent =
        sec > 0 ? `Исчезающие сообщения: ${ttlLabel(sec)}` : 'Исчезающие сообщения выключены';
      box.append(div);
      continue;
    }
    if (CONTROL_TYPES.has(m.type)) {
      continue; // react/edit/del/pin/unpin уже применены к состоянию при ingest
    }
    if (m.type === 'system' && typeof m.text === 'string' && m.text.startsWith('newdev:')) {
      // v28 (E): локальная строка о новом устройстве (вне сервера).
      const div = document.createElement('div');
      div.className = 'chat-sys warn';
      div.textContent = `⚠ К комнате подключилось новое устройство (…${m.text.slice(7).slice(-6)})`;
      box.append(div);
      continue;
    }
    if (m.type === 'system' && typeof m.text === 'string' && m.text.startsWith('gcall:')) {
      const div = document.createElement('div');
      div.className = 'chat-sys';
      const span = document.createElement('span');
      span.textContent = `${m.nick || 'Участник'} создал групповой звонок `;
      const btn = document.createElement('button');
      btn.className = 'btn small primary';
      btn.textContent = 'Войти в групповой звонок';
      btn.onclick = () => {
        const secret = m.text.slice(6);
        if (window.__zvDial?.openCallLink) window.__zvDial.openCallLink(secret);
        else location.hash = 'k=' + secret;
      };
      div.append(span, btn);
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
        const secret = m.text.slice(5);
        if (window.__zvDial?.openCallLink) window.__zvDial.openCallLink(secret);
        else location.hash = 'k=' + secret;
      };
      div.append(span, btn);
      box.append(div);
      continue;
    }
    if (m.type === 'system') {
      // v28: прочие системные строки (статусы дозвонa и т.п.) — плашкой.
      const div = document.createElement('div');
      div.className = 'chat-sys';
      div.textContent = String(m.text || '');
      box.append(div);
      continue;
    }
    const g = grp.get(it.hash) || { first: true, last: true };
    const rowEl = document.createElement('div');
    rowEl.className =
      'chat-msg-row' +
      (it.mine ? ' mine' : '') +
      (g.first ? ' grp-first' : '') +
      (g.last ? ' grp-last' : '') +
      (g.last && !g.first ? '' : '') +
      (g.last ? ' tail' : '');
    rowEl.dataset.hash = it.hash; // v27: цель для цитат, закрепа и поиска
    if (!it.mine) {
      const av = document.createElement('span');
      // v28 (F): аватар виден только у нижнего сообщения группы (место в
      // раскладке сохраняется прозрачным слотом, чтобы пузыри не прыгали).
      av.className = 'chat-avatar' + (g.last ? '' : ' ghost');
      av.style.background = `hsl(${hueOf(m.devPub || '')} 65% 42%)`;
      av.textContent = (m.nick || 'У')[0].toUpperCase();
      rowEl.append(av);
    }
    const div = document.createElement('div');
    div.className = 'chat-msg' + (it.mine ? ' mine' : '') + (g.last ? ' tail' : '');
    if (!m.deleted && (m.type === 'file' || m.type === 'voice')) {
      let meta = null;
      try {
        meta = JSON.parse(m.text || '');
      } catch {}
      if (meta && meta.fileId && m.type === 'voice') {
        // Голосовое: плеер; звук автоподгружается всегда (они маленькие).
        const wrap = document.createElement('div');
        wrap.className = 'chat-voice';
        wrap.dataset.voice = meta.fileId;
        const pb = document.createElement('button');
        pb.className = 'btn small chat-voice-play';
        pb.textContent = '▶';
        pb.setAttribute('aria-label', 'Прослушать голосовое сообщение');
        const bar = document.createElement('div');
        bar.className = 'chat-voice-bar';
        const fill = document.createElement('div');
        fill.className = 'chat-voice-fill';
        bar.append(fill);
        const tm = document.createElement('span');
        tm.className = 'chat-voice-time';
        tm.textContent = fmtDur(meta.durSec || 0);
        const ste = document.createElement('div');
        ste.className = 'chat-file-state';
        wrap.append(pb, bar, tm, ste);
        div.append(wrap);
        wireVoicePlayer(wrap, meta);
        const st = fileState.get(meta.fileId);
        if (!st?.url && !st?.busy && !st?.error) {
          downloadFile(meta, wrap, { auto: true }).catch(() => {});
        } else if (st?.error) {
          ste.textContent = 'Не удалось загрузить голосовое';
        }
      } else if (meta && meta.fileId) {
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
        const barEl = document.createElement('div');
        barEl.className = 'chat-file-bar';
        const barFill = document.createElement('div');
        barFill.className = 'chat-file-bar-fill';
        barEl.append(barFill);
        const btn = document.createElement('button');
        btn.className = 'btn small chat-file-btn';
        btn.textContent = 'Скачать';
        const stEl = document.createElement('div');
        stEl.className = 'chat-file-state';
        btn.onclick = () => downloadFile(meta, card).catch(() => {});
        card.append(nm, sz, pv, barEl, btn, stEl);
        div.append(card);
        const st = fileState.get(meta.fileId);
        if (st) renderFileCardState(meta, card, st);
        // v26: картинки до 3 МБ подгружаются и расшифровываются сами.
        const isSmallImage =
          (meta.mime || '').startsWith('image/') && (meta.size || 0) <= 3 * 1024 * 1024;
        if (isSmallImage && !st?.url && !st?.busy && !st?.error) {
          downloadFile(meta, card, { auto: true }).catch(() => {});
        }
      } else {
        const body = document.createElement('div');
        body.className = 'chat-msg-text';
        body.textContent = 'Файл (повреждённые метаданные)';
        div.append(body);
      }
    } else if (m.deleted) {
      const body = document.createElement('div');
      body.className = 'chat-msg-text chat-deleted';
      body.textContent = 'Сообщение удалено';
      div.append(body);
    } else {
      if (!it.mine && g.first) {
        // v28 (F): ник — только у первого сообщения группы одного автора.
        const head = document.createElement('div');
        head.className = 'chat-msg-head';
        head.textContent = m.nick || 'Участник';
        div.append(head);
      }
      // v27: цитата-ответ — блок внутри пузыря, клик ведёт к оригиналу.
      if (m.replyTo && (m.replyTo.hash || m.replyTo.excerpt)) {
        const q = document.createElement('div');
        q.className = 'chat-quote';
        const qn = document.createElement('b');
        qn.textContent = m.replyTo.name || 'Участник';
        const qt = document.createElement('span');
        qt.textContent = m.replyTo.excerpt || '';
        q.append(qn, qt);
        q.onclick = () => scrollToMessage(m.replyTo.hash);
        div.append(q);
      }
      const body = document.createElement('div');
      body.className = 'chat-msg-text';
      renderTextWithMarks(body, m.text || '', cur.search?.q);
      div.append(body);
    }
    const foot = document.createElement('div');
    foot.className = 'chat-msg-foot';
    const tm = document.createElement('span');
    tm.textContent = fmtTime(m.ts);
    foot.append(tm);
    if (it.mine) {
      // v28 (F): статус — галочками в стиле Telegram, подпись — в title.
      const others = knownMembers().filter((d) => d !== cur.device.devicePub);
      const st = receiptState(it, cur.receipts, others);
      const rc = document.createElement('span');
      rc.className = 'chat-receipt st-' + st;
      rc.textContent = RECEIPT_GLYPHS[st] || '✓';
      rc.title = RECEIPT_LABELS[st] || '';
      foot.append(rc);
    } else if (!it.sigOk) {
      const warn = document.createElement('span');
      warn.className = 'chat-receipt warn';
      warn.textContent = 'подпись не подтверждена';
      foot.append(warn);
    }
    if (m.edited && !m.deleted) {
      const ed = document.createElement('span');
      ed.className = 'chat-edited';
      ed.textContent = 'изменено';
      foot.append(ed);
    }
    // v27: кнопка действий (ответить, реакция, закрепить; у своих — ещё
    // изменить и удалить). У удалённых и служебных действий нет.
    if (!m.deleted && (m.type === 'text' || m.type === 'file' || m.type === 'voice')) {
      const mb = document.createElement('button');
      mb.className = 'chat-act-btn';
      mb.textContent = '···';
      mb.title = 'Действия с сообщением';
      mb.setAttribute('aria-label', 'Действия с сообщением');
      mb.onclick = (e) => {
        e.stopPropagation();
        openMsgMenu(it, mb);
      };
      foot.append(mb);
    }
    div.append(foot);
    rowEl.append(div);
    // v27: чипы реакций под пузырём; клик по чипу — toggle своей реакции.
    const reactions = it.reactions || {};
    const reactedEmojis = Object.keys(reactions).filter((e) => reactions[e]?.length);
    if (reactedEmojis.length && !m.deleted) {
      const chips = document.createElement('div');
      chips.className = 'chat-reactions';
      for (const emoji of reactedEmojis) {
        const chip = document.createElement('button');
        chip.className =
          'chat-chip' + (reactions[emoji].includes(cur.device.devicePub) ? ' mine' : '');
        chip.textContent = `${emoji} ${reactions[emoji].length}`;
        chip.onclick = () => toggleReaction(it, emoji).catch(() => {});
        chips.append(chip);
      }
      rowEl.append(chips);
    }
    box.append(rowEl);
  }
  if (nearBottom || !box.dataset.scrolled) {
    box.scrollTop = box.scrollHeight;
    box.dataset.scrolled = '1';
  }
}

// ---------- v28 (A): дозвон из чата через Inbox ----------
// Чат не реализует Inbox сам: звонит публичный хук app.js
// (window.__zvDial.ringPersonal). Приглашение в чат ('call:'/'gcall:') при
// этом остаётся и как запасной путь, и как кнопка входа в звонковую
// комнату для всех участников.
const callLinkOf = (secret) => `${location.origin}${location.pathname}#k=${secret}`;
async function postCallLine(text) {
  try {
    await sendMsg('system', text);
  } catch {}
}
async function dialMember(dev, { group = false, secret = null, link = null } = {}) {
  if (!cur) return { dialed: false, reason: 'no-room' };
  const member = cur.rec.members?.[dev] || {};
  const dial = window.__zvDial;
  if (!member.masterPub || !dial?.ringPersonal) return { dialed: false, reason: 'no-dial' };
  const roomId = cur.rec.roomId;
  const sec = secret || newSecret();
  const lnk = link || callLinkOf(sec);
  const res = await dial
    .ringPersonal(member.masterPub, lnk, {
      ecdhPub: member.ecdhPub || memberEcdhPub(dev),
      name: cur.rec.nick || 'Участник чата',
      callKind: group ? 'group' : 'single',
      onState: (state) => {
        if (!cur || cur.closed || cur.rec.roomId !== roomId) return;
        const label = {
          accepted: 'принял(а) звонок',
          declined: 'отклонил(а) звонок',
          cancelled: 'звонок отменён',
          expired: 'не ответил(а) на звонок',
        }[state];
        if (label) postCallLine(`📞 ${nickOf(dev)} ${label}`);
      },
    })
    .catch((e) => ({ ok: false, error: e?.message || String(e) }));
  if (res?.ok) {
    if (!group) {
      await postCallLine('call:' + sec);
      await postCallLine(`📞 Дозвон: ${nickOf(dev)} — телефон звенит…`);
    }
    return { dialed: true, secret: sec, link: lnk };
  }
  return { dialed: false, reason: res?.error || 'ring-failed' };
}

// ---------- Проводка UI ----------
function initChatUI() {
  const create = $('#btnCreateChat');
  if (create) {
    create.onclick = async () => {
      try {
        // v26, фаза 2: опция «Защитить PIN» при создании комнаты.
        let pin = null;
        if ($('#chatPinProtect')?.checked) {
          pin = ($('#chatPinInput')?.value || '').trim();
          if (pin.length < 4) {
            return note(
              'PIN слишком короткий: минимум 4 символа, лучше слово или фраза круга — короткие цифры перебираются быстрее.'
            );
          }
          if (/^\d+$/.test(pin) && pin.length < 6) {
            note('Предупреждение: PIN только из цифр короче 6 знаков слаб; продолжаем, но лучше слово/фраза.');
          }
        }
        const seed = newSecret();
        await openRoomBySeed(seed, pin ? { pin } : {});
        note(
          pin
            ? 'Чат создан и защищён PIN: ссылка без PIN бесполезна. Сообщите PIN собеседнику устно и сверьте контрольную фразу (список участников в шапке комнаты).'
            : 'Ссылка на чат — в адресной строке и по кнопке «Ссылка». Передайте её собеседнику вне этого чата.'
        );
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
      const j = raw.match(/join=([A-Za-z0-9_-]{9})/);
      if (j) return redeemJoin(j[1]);
      const g = raw.match(/greet=([A-Za-z0-9_-]{9})/);
      if (g) return redeemGreet(g[1]);
      const bare = raw.match(/^([A-Za-z0-9_-]{9})$/);
      if (bare) return redeemCode(bare[1]); // алиас → приветствие (порядок в redeemCode)
      const m = raw.match(/chat=([A-Za-z0-9_-]{43})/) || raw.match(/^([A-Za-z0-9_-]{43})$/);
      if (!m) return note('Вставьте ссылку на чат (#chat=…), сам ключ или код подключения из 9 символов.');
      openRoomBySeed(m[1], { pinProtected: /[?&]p=1/.test(raw) || raw.includes('&p=1') });
    };
  }
  const pinProtectCheck = $('#chatPinProtect');
  if (pinProtectCheck) {
    pinProtectCheck.onchange = () =>
      $('#chatPinInput')?.classList.toggle('hidden', !pinProtectCheck.checked);
  }
  const pinGo = $('#chatPinGo');
  if (pinGo) {
    pinGo.onclick = () => {
      const pin = ($('#chatPinEntry')?.value || '').trim();
      if (!pin) return note('Введите PIN.');
      if (!pendingPinSeed) return note('Сначала откройте ссылку на чат.');
      $('#chatPinBox')?.classList.add('hidden');
      const seed = pendingPinSeed;
      pendingPinSeed = null;
      openRoomBySeed(seed, { pin, pinProtected: true });
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
      // v28 (E): ворота ника сняты — показываем ленту и ввод.
      $('#chatMessages')?.classList.remove('hidden');
      $('#chatroom .chat-input-bar')?.classList.remove('hidden');
      note('');
      await sendIntroIfNeeded();
      await sendEcdhIfNeeded();
      await sendDialInfoIfNeeded();
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
      // v27: режим редактирования — вместо нового сообщения уходит 'edit'.
      if (cur.editing) {
        await sendMsg('edit', JSON.stringify({ target: cur.editing.hash, text }));
        cur.editing = null;
        renderEditBar();
      } else {
        const extra = cur.replyTo ? { replyTo: cur.replyTo } : null;
        await sendMsg('text', text, extra);
        cur.replyTo = null;
        renderReplyBar();
      }
      myInput.value = '';
      myInput.dispatchEvent(new Event('input')); // mic/send + черновик ниже
      if (cur) {
        cur.rec.draft = '';
        saveRoom(cur.rec).catch(() => {});
      }
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
    // v27: черновик комнаты — недописанный текст переживает выход из
    // комнаты и перезагрузку (локально, в записи комнаты; дебаунс 300 мс).
    input.addEventListener('input', () => {
      if (!cur) return;
      if (cur.draftTimer) clearTimeout(cur.draftTimer);
      cur.draftTimer = setTimeout(() => {
        if (!cur) return;
        cur.rec.draft = input.value;
        saveRoom(cur.rec).catch(() => {});
      }, 300);
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
      const link = chatLinkOf(seed, cur.rec.pinProtected);
      try {
        await navigator.clipboard.writeText(link);
        note(
          cur.rec.pinProtected
            ? 'Ссылка скопирована. PIN в ней нет — сообщите его собеседнику устно, иначе ссылка бесполезна.'
            : 'Ссылка на чат скопирована.'
        );
      } catch {
        note(link);
      }
    };
  }
  const aliasBtn = $('#chatAliasBtn');
  if (aliasBtn) {
    aliasBtn.onclick = () => {
      const box = $('#chatAliasBox');
      if (!box) return;
      if (box.classList.contains('hidden')) renderAliasBox().catch(() => {});
      else box.classList.add('hidden');
    };
  }
  const aliasCopy = $('#aliasCopy');
  if (aliasCopy) {
    aliasCopy.onclick = async () => {
      const v = $('#aliasLink')?.value || '';
      if (!v) return;
      try {
        await navigator.clipboard.writeText(v);
        note('Короткая ссылка скопирована.');
      } catch {
        note(v);
      }
    };
  }
  const aliasReissue = $('#aliasReissue');
  if (aliasReissue) {
    aliasReissue.onclick = async () => {
      if (!cur) return;
      if (await aliasRevokeCurrent()) {
        if (await aliasCreate()) {
          renderAliasBox().catch(() => {});
          note('Короткая ссылка перевыпущена: старая больше не работает.');
        }
      }
    };
  }
  const aliasDisable = $('#aliasDisable');
  if (aliasDisable) {
    aliasDisable.onclick = async () => {
      if (!cur) return;
      if (await aliasRevokeCurrent()) {
        renderAliasBox().catch(() => {});
        note('Короткая ссылка отключена. Длинная ссылка комнаты продолжает работать.');
      }
    };
  }
  const aliasClose = $('#aliasClose');
  if (aliasClose) aliasClose.onclick = () => $('#chatAliasBox')?.classList.add('hidden');
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
      const others = knownMembers().filter((d) => d !== cur.device.devicePub);
      if (others.length > 1) {
        return note('В группе используйте «Групповой звонок» или кнопку 📞 у участника в списке (шапка комнаты).');
      }
      try {
        const peer = others[0];
        if (peer) {
          // v28 (A): настоящий дозвон, если у собеседника есть личная
          // идентичность в чате; иначе — прежнее приглашение с пометкой.
          const r = await dialMember(peer);
          if (r.dialed) {
            note('Дозвон идёт: у собеседника звенит телефон. Когда примет, вы оба сможете войти в звонковую комнату кнопкой у приглашения в чате.');
            return;
          }
          const secret = newSecret();
          await sendMsg('system', 'call:' + secret);
          cur.pendingCall = secret;
          note('У собеседника нет личной идентичности в чате (гостевое устройство), поэтому его телефон не зазвонит: отправлено только приглашение в чат.');
          return;
        }
        const secret = newSecret();
        await sendMsg('system', 'call:' + secret);
        cur.pendingCall = secret;
        note('Приглашение на звонок отправлено в чат. Нажмите «Войти в звонок» у сообщения — вы или собеседник.');
      } catch (e) {
        note(e.message);
      }
    };
  }
  const groupCallBtn = $('#chatGroupCallBtn');
  if (groupCallBtn) {
    groupCallBtn.onclick = async () => {
      if (!cur || !cur.rec.nick) return note('Сначала введите никнейм.');
      try {
        const secret = newSecret();
        const link = callLinkOf(secret);
        await postCallLine('gcall:' + secret);
        let dialed = 0;
        let reachable = 0;
        for (const dev of knownMembers().filter((d) => d !== cur.device.devicePub)) {
          if (!cur.rec.members?.[dev]?.masterPub) continue;
          reachable++;
          const r = await dialMember(dev, { group: true, secret, link });
          if (r.dialed) dialed++;
        }
        await postCallLine(
          dialed
            ? `📞 Групповой звонок: дозвон ${dialed} участн. — телефоны звонят`
            : '📞 Групповой звонок: приглашение в чате (дозвон недоступен — у участников нет личной идентичности в чате)'
        );
        if (reachable && !dialed) {
          note('Групповая комната создана, но дозвон не прошёл: участники войдут по приглашению в чате.');
        }
        // Создатель входит в групповую комнату сразу (механизм group.js в
        // звонковом пути подхватит комнату по ссылке, как обычную).
        if (window.__zvDial?.openCallLink) window.__zvDial.openCallLink(link);
        else location.hash = 'k=' + secret;
      } catch (e) {
        note(e.message);
      }
    };
  }
  const epochBtn = $('#chatEpochBtn');
  if (epochBtn) epochBtn.onclick = () => openEpochDialog().catch(() => {});
  const epochCancel = $('#epochCancel');
  if (epochCancel) epochCancel.onclick = () => $('#chatEpochBox')?.classList.add('hidden');
  const epochConfirm = $('#epochConfirm');
  if (epochConfirm) epochConfirm.onclick = () => doEpochRotate().catch(() => {});
  // v26: голосовые — микрофон виден при пустом поле, отправка при непустом.
  const micBtn = $('#chatMic');
  if (micBtn) micBtn.onclick = () => startVoiceRec().catch(() => {});
  const recCancel = $('#chatRecCancel');
  if (recCancel) recCancel.onclick = () => stopVoiceRec(false);
  const recSend = $('#chatRecSend');
  if (recSend) recSend.onclick = () => stopVoiceRec(true);
  const syncMicSend = () => {
    const inp = $('#chatroom #chatInput');
    const empty = !(inp?.value || '').trim();
    $('#chatMic')?.classList.toggle('hidden', !empty);
    $('#chatSend')?.classList.toggle('hidden', empty);
  };
  const micInput = $('#chatroom #chatInput');
  if (micInput) micInput.addEventListener('input', syncMicSend);
  syncMicSend();

  // ---------- v27: поиск по переписке ----------
  const searchBar = $('#chatSearchBar');
  const searchInput = $('#chatSearchInput');
  const updateSearchCount = () => {
    const c = $('#chatSearchCount');
    if (!c) return;
    if (!cur?.search) {
      c.textContent = '';
      return;
    }
    c.textContent = cur.search.hashes.length
      ? `${cur.search.idx + 1}/${cur.search.hashes.length}`
      : '0/0';
  };
  const runSearch = async () => {
    if (!cur || !searchInput) return;
    const q = searchInput.value.trim();
    if (!q) {
      cur.search = null;
      updateSearchCount();
      renderMessages().catch(() => {});
      return;
    }
    const ql = q.toLowerCase();
    const items = await roomMessages(cur.rec.roomId);
    const hashes = [];
    for (const it of items) {
      if (it.expiresAt && it.expiresAt <= Date.now()) continue;
      const m = it.msg;
      if (m.deleted) continue;
      let hay = null;
      if (m.type === 'text') hay = m.text || '';
      else if (m.type === 'file') {
        try {
          hay = JSON.parse(m.text || '{}').name || '';
        } catch {}
      }
      if (hay && hay.toLowerCase().includes(ql)) hashes.push(it.hash);
    }
    if (!cur) return;
    cur.search = { q, hashes, idx: hashes.length ? 0 : -1 };
    updateSearchCount();
    await renderMessages().catch(() => {});
    if (cur.search && cur.search.idx >= 0) scrollToMessage(cur.search.hashes[cur.search.idx], false);
  };
  const searchBtn = $('#chatSearchBtn');
  if (searchBtn && searchBar) {
    searchBtn.onclick = () => {
      const willShow = searchBar.classList.contains('hidden');
      searchBar.classList.toggle('hidden');
      if (willShow) searchInput?.focus();
      else {
        if (cur) cur.search = null;
        if (searchInput) searchInput.value = '';
        updateSearchCount();
        renderMessages().catch(() => {});
      }
    };
  }
  if (searchInput) {
    searchInput.addEventListener('input', () => runSearch().catch(() => {}));
    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        $('#chatSearchNext')?.click();
      }
    });
  }
  const searchNav = (delta) => {
    if (!cur?.search || !cur.search.hashes.length) return;
    const n = cur.search.hashes.length;
    cur.search.idx = (((cur.search.idx + delta) % n) + n) % n;
    updateSearchCount();
    scrollToMessage(cur.search.hashes[cur.search.idx]);
  };
  const sprev = $('#chatSearchPrev');
  if (sprev) sprev.onclick = () => searchNav(-1);
  const snext = $('#chatSearchNext');
  if (snext) snext.onclick = () => searchNav(1);
  const sclose = $('#chatSearchClose');
  if (sclose) sclose.onclick = () => searchBtn?.click();

  // ---------- v27: исчезающие сообщения (настройка комнаты) ----------
  const ttlBtn = $('#chatTtlBtn');
  if (ttlBtn) {
    ttlBtn.onclick = () => {
      const box = $('#chatTtlBox');
      if (!box) return;
      const willShow = box.classList.contains('hidden');
      box.classList.toggle('hidden');
      if (willShow) renderTtlState();
    };
  }
  const ttlSel = $('#chatTtlSelect');
  if (ttlSel) {
    ttlSel.onchange = async () => {
      if (!cur) return;
      if (!cur.rec.nick) return note('Сначала введите никнейм.');
      const ttl = Number(ttlSel.value) || 0;
      if (ttl === cur.rec.ttlSec) return;
      try {
        await sendMsg('ttl', JSON.stringify({ ttl }));
        note(
          ttl > 0
            ? `Исчезающие сообщения включены: новые сообщения будут жить ${ttlLabel(ttl)}.`
            : 'Исчезающие сообщения выключены.'
        );
      } catch (e) {
        note(e.message);
      }
    };
  }

  // ---------- v27: закреп ----------
  const pinTextEl = $('#chatPinText');
  if (pinTextEl) {
    pinTextEl.onclick = () => {
      if (cur?.rec.pinned?.hash) scrollToMessage(cur.rec.pinned.hash);
    };
  }
  const pinUnpinBtn = $('#chatPinUnpin');
  if (pinUnpinBtn) {
    pinUnpinBtn.onclick = async () => {
      if (!cur) return;
      try {
        await sendMsg('unpin', '{}');
      } catch (e) {
        note(e.message);
      }
    };
  }

  // ---------- v27: плашки цитаты и редактирования ----------
  const replyCancel = $('#chatReplyCancel');
  if (replyCancel) {
    replyCancel.onclick = () => {
      if (!cur) return;
      cur.replyTo = null;
      renderReplyBar();
    };
  }
  const editCancel = $('#chatEditCancel');
  if (editCancel) {
    editCancel.onclick = () => {
      if (!cur) return;
      cur.editing = null;
      renderEditBar();
      const inp = $('#chatroom #chatInput');
      if (inp) {
        inp.value = cur.rec.draft || '';
        inp.dispatchEvent(new Event('input'));
      }
    };
  }

  // ---------- v27: меню действий сообщения ----------
  const menuAct = (id, fn) => {
    const b = $(id);
    if (!b) return;
    b.onclick = () => {
      const it = cur?.menuTarget;
      hideMsgMenu();
      if (!it) return;
      try {
        const r = fn(it);
        if (r?.catch) r.catch((e) => note(e.message));
      } catch (e) {
        note(e.message);
      }
    };
  };
  menuAct('#msgActReply', (it) => {
    if (!cur) return;
    cur.replyTo = { hash: it.hash, name: it.msg.nick || 'Участник', excerpt: excerptOf(it) };
    cur.editing = null;
    renderEditBar();
    renderReplyBar();
    $('#chatroom #chatInput')?.focus();
  });
  document.querySelectorAll('.chat-react-emoji').forEach((b) => {
    b.onclick = () => {
      const it = cur?.menuTarget;
      hideMsgMenu();
      if (it) toggleReaction(it, b.dataset.emoji).catch(() => {});
    };
  });
  menuAct('#msgActPin', (it) => sendMsg('pin', JSON.stringify({ target: it.hash })));
  menuAct('#msgActEdit', (it) => {
    if (!cur) return;
    cur.editing = { hash: it.hash };
    cur.replyTo = null;
    renderReplyBar();
    renderEditBar();
    const inp = $('#chatroom #chatInput');
    if (inp) {
      inp.value = it.msg.text || '';
      inp.dispatchEvent(new Event('input'));
      inp.focus();
    }
  });
  menuAct('#msgActDel', (it) => sendMsg('del', JSON.stringify({ target: it.hash })));
  document.addEventListener('click', (e) => {
    const menu = $('#chatMsgMenu');
    if (!menu || menu.classList.contains('hidden')) return;
    if (e.target.closest('#chatMsgMenu') || e.target.closest('.chat-act-btn')) return;
    hideMsgMenu();
  });

  // ---------- v28 (B): настройки уведомлений о сообщениях ----------
  const notifyBtn = $('#chatNotifyBtn');
  if (notifyBtn) {
    const syncNotifyBtn = () => {
      if (!('Notification' in window)) {
        notifyBtn.disabled = true;
        notifyBtn.textContent = '🔔 Уведомления не поддерживаются браузером';
        return;
      }
      notifyBtn.disabled = Notification.permission === 'denied';
      notifyBtn.querySelector('span').textContent =
        Notification.permission === 'granted'
          ? '🔔 Уведомления включены'
          : Notification.permission === 'denied'
            ? '🔔 Уведомления запрещены в браузере'
            : '🔔 Включить уведомления';
    };
    notifyBtn.onclick = async () => {
      // Разрешение запрашиваем только по явному действию, не при загрузке.
      try {
        await Notification.requestPermission();
      } catch {}
      syncNotifyBtn();
      if (Notification.permission === 'granted') {
        note('Уведомления о сообщениях включены — пока приложение открыто (чат или звонки).');
      }
    };
    syncNotifyBtn();
  }
  const nt = $('#chatNotifyText');
  if (nt) {
    nt.checked = notifyTextOn();
    nt.onchange = () => {
      try {
        localStorage.setItem('zvNotifyText', nt.checked ? '1' : '0');
      } catch {}
    };
  }
  const ns = $('#chatNotifySound');
  if (ns) {
    ns.checked = notifySoundOn();
    ns.onchange = () => {
      try {
        localStorage.setItem('zvNotifySound', ns.checked ? '1' : '0');
      } catch {}
      if (ns.checked) notifyBeep();
    };
  }
  startRoomSweep();
  // v28 (B): тап по системному уведомлению чата (SW шлёт chat-notification).
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (e) => {
      if (e.data?.type !== 'chat-notification') return;
      if (cur && cur.rec.roomId === e.data.roomId) showChatScreen();
      else renderRoomList().catch(() => {});
    });
  }

  renderRoomList().catch(() => {});
  // v22: флаг успешной инициализации чата для watchdog в zvdiag.js.
  window.__zvChatBooted = true;
}

// ---------- v28 (B): живой фон для неоткрытых комнат ----------
// У неоткрытой комнаты нет WS; раз в 30 секунд лёгкий fetch по seq считает
// новые сообщения и поднимает тост/уведомление без текста переписки.
// Сообщения при этом НЕ помечаются прочитанными и не сохраняются — при
// входе в комнату их подтянет обычный fetchMissed.
const sweepState = new Map(); // roomId -> {token, lastNotifiedSeq}
let sweepStarted = false;
function startRoomSweep() {
  if (sweepStarted) return;
  sweepStarted = true;
  setInterval(() => {
    sweepOtherRooms().catch(() => {});
  }, 30000);
}
async function sweepOtherRooms() {
  const rooms = (await kvAll('rooms')).map((x) => x.value).filter(Boolean);
  for (const r of rooms) {
    if (cur && !cur.closed && cur.rec.roomId === r.roomId) continue;
    let st = sweepState.get(r.roomId);
    if (!st) {
      try {
        const seed = await decryptWithVault(r.seedEnc);
        const seedBytes = b64u.dec(seed);
        let pinIkm = null;
        if (r.pinEnc) {
          try {
            const pin = await decryptWithVault(r.pinEnc);
            if (pin) pinIkm = await derivePinIkm(pin, seedBytes);
          } catch {}
        }
        const keys = await deriveChatKeys(seedBytes, { pinIkm });
        if (keys.roomId !== r.roomId) continue;
        st = { token: keys.accessToken, lastNotifiedSeq: r.lastReadSeq || 0 };
        sweepState.set(r.roomId, st);
      } catch {
        continue;
      }
    }
    const after = Math.max(r.lastSeq || 0, st.lastNotifiedSeq);
    const res = await api(r.roomId, st.token, `/fetch?after=${after}`).catch(() => null);
    if (!res || res.status !== 200) continue;
    const items = res.data.messages || [];
    if (!items.length) continue;
    st.lastNotifiedSeq = Math.max(st.lastNotifiedSeq, ...items.map((i) => i.seq || 0));
    maybeNotifyMessage({
      roomId: r.roomId,
      nick: null,
      preview: items.length > 1 ? `Новых сообщений: ${items.length}` : 'Новое сообщение',
      mine: false,
      roomActive: false,
    }).catch(() => {});
  }
}

function checkHash() {
  const params = new URLSearchParams(location.hash.slice(1));
  const join = params.get('join');
  if (join && /^[A-Za-z0-9_-]{9}$/.test(join)) {
    $('#home')?.classList.remove('hidden');
    redeemJoin(join).then((okJoin) => {
      if (!okJoin) note('Короткая ссылка не найдена или отключена владельцем комнаты.');
    });
    return;
  }
  const greet = params.get('greet');
  if (greet && /^[A-Za-z0-9_-]{9}$/.test(greet)) {
    $('#home')?.classList.remove('hidden');
    redeemGreet(greet);
    return;
  }
  const seed = params.get('chat');
  if (seed && /^[A-Za-z0-9_-]{43}$/.test(seed)) {
    openRoomBySeed(seed, { pinProtected: params.get('p') === '1' });
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
window.ZVChat = {
  openRoomBySeed,
  openFromHash: checkHash,
  canonical,
  redeemGreet,
  redeemJoin,
  redeemCode,
};
