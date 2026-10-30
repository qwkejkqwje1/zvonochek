import { CONFIG, getWorkerBase, setWorkerBase, normalizeWorkerUrl, DEFAULT_WORKER_URL } from './config.js?v=32';
import { newSecret, deriveRoom, safetyCode, safetyCodeBridge, b64u, seal, open as openSealed, genP256KeyPair, sha256hex } from './crypto.js?v=32';
import { hasPersonal, getPersonal, ensurePersonal, signWithDevice, signWithKey, personalLinkOf, fpOfPubRaw, getChatDeviceEcdh } from './identity.js?v=32';
import { inboxRegister, inboxRing, inboxRingState, inboxAck, inboxAnswer, inboxCancel, inboxMissed, inboxMissedAck, InboxListener } from './inbox.js?v=32';
import { kvPut, kvAll } from './store.js?v=32';
import { Signaling } from './signaling.js?v=32';

export const APP_VERSION = 32;
export const APP_BUILD = '2026-10-30';
// Версия разработки пишется из одного места: главная (бейдж и подпись),
// экран подготовки, карточка подключения в начале звонка.
for (const el of document.querySelectorAll('[data-ver]')) el.textContent = 'v' + APP_VERSION;
for (const el of document.querySelectorAll('[data-build]')) el.textContent = APP_BUILD;
const $ = (s, r = document) => r.querySelector(s);
const setUse = (sel, name) => {
  const el = typeof sel === 'string' ? $(sel) : sel;
  if (el) el.setAttribute('href', '#' + name);
};
const setBtnIcon = (sel, name) => setUse((typeof sel === 'string' ? $(sel) : sel)?.querySelector('use'), name);

// Регистрация Service Worker для быстрого старта и работы PWA
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('./sw.js?v=32').catch(() => {});
}

// Автообновление: если на сайте вышла новая версия, а браузер держит старую из кэша — перезагружаемся.
fetch('version.json?t=' + Date.now(), { cache: 'no-store' })
  .then((r) => r.json())
  .then(async (j) => {
    if (j.v > APP_VERSION && sessionStorage.zvUpd !== String(j.v)) {
      sessionStorage.zvUpd = String(j.v);
      await fetch(location.pathname, { cache: 'reload' }).catch(() => {});
      location.reload();
    }
  })
  .catch(() => {});

const randHex = (n) =>
  [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
const selfId = sessionStorage.zvId || (sessionStorage.zvId = randHex(8));
const inst = randHex(6); // меняется при каждой перезагрузке страницы
const MAX_FILE_BYTES = 256 * 1024 * 1024;

// Миграция настроек v13 (один раз): у пользователей прошлых версий обработка
// звука была сохранена включённой в localStorage — сбрасываем её в «выкл»,
// чтобы новый дефолт сработал и у них, а не только на чистом профиле.
try {
  if (Number(localStorage.zvSettingsV || 0) < 13) {
    localStorage.zvNoise = '0';
    localStorage.zvEcho = '0';
    localStorage.zvAgc = '0';
    localStorage.zvComp = '0';
    localStorage.zvOpusTune = '0';
    if (!localStorage.zvBitrate) localStorage.zvBitrate = '48';
  }
  if (Number(localStorage.zvSettingsV || 0) < 14) {
    // v14: по просьбе владельца убираем VAD-гейт из пути звука по умолчанию.
    // Режим ввода становится «открытый микрофон»: гейт больше не режет голос,
    // VAD/PTT остаются только как ручные опции в настройках.
    localStorage.zvInputMode = 'open';
    localStorage.zvSettingsV = '14';
  }
} catch {}

const S = {
  secret: null,
  room: null,
  sig: null,
  pc: null,
  peer: null,
  polite: false,
  peerDialect: 'plain', // 'g' — если основной собеседник говорит с нами групповым протоколом (клиент v16)
  makingOffer: false,
  ignoreOffer: false,
  pendingCands: [],
  local: new MediaStream(),
  remote: new MediaStream(),
  rawAudioTrack: null,
  micOn: true,
  deafened: false,
  camOn: true,
  screenTrack: null,
  pttPressed: false,
  isSpeaking: false,
  vadHoldUntil: 0,
  testingMic: false,

  // Настройки устройств и звука в стиле Discord
  dev: {
    mic: localStorage.zvMic || '',
    cam: localStorage.zvCam || '',
    spk: localStorage.zvSpk || '',
  },
  audio: {
    micVol: Number(localStorage.zvMicVol ?? 100),
    peerVol: Number(localStorage.zvPeerVol ?? 100),
    inputMode: localStorage.zvInputMode || 'open', // 'open' | 'vad' | 'ptt'
    vadGate: Number(localStorage.zvVadGate ?? -45), // -75 .. -15 dB
    // v13: обработка звука и ручная настройка Opus по умолчанию ВЫКЛЮЧЕНЫ.
    // Раньше noise/echo/agc/comp были включены «из коробки» ( !== '0' ), а Opus
    // принудительно переписывался в SDP (FEC + DTX + maxaveragebitrate=24k):
    // связка браузерный DSP + DTX + наш VAD-гейт резала тихий голос и окончания
    // фраз, а после долгой паузы Opus с DTX мог «просыпаться» с задержкой.
    // Теперь чистый тракт: браузерный Opus — авто, DSP — только по явному выбору.
    noise: localStorage.zvNoise === '1',
    echo: localStorage.zvEcho === '1',
    agc: localStorage.zvAgc === '1',
    comp: localStorage.zvComp === '1',
    opusTune: localStorage.zvOpusTune === '1',
    bitrate: Number(localStorage.zvBitrate || 48), // 12, 24, 48, 64 kbps (применяется только при opusTune)
    netMode: localStorage.zvNetMode || (localStorage.zvRelay === '1' ? 'relay' : 'auto'), // 'auto' | 'bridge' | 'relay'
  },

  // Web Audio API узлы
  audioCtx: null,
  micSource: null,
  hpFilter: null,
  micGainNode: null,
  micAnalyser: null,
  gateGainNode: null,
  procDest: null,
  remoteSource: null,
  remoteCompNode: null,
  remoteGainNode: null,
  remoteAnalyser: null,
  remoteDest: null,
  meterTimer: null,
  ctxResumeAt: 0,
  audioStallN: 0,
  lastAudioBytes: -1,
  lastAudioRecoverAt: 0,

  // Аварийный аудио-мост через сигналинг (работа без TURN и при блокировке UDP)
  bridgeActive: false,
  bridgeAutoTimer: null,
  bridgeRecorder: null,
  bridgeRecTimer: null,
  bridgeNextPlayTime: 0,
  bridgeSpeakingUntil: 0,

  ice: [],
  hasTurn: false,
  roster: new Map(), // inst -> {id, name, seen} все участники комнаты (для группового режима)
  personal: null, // идентичность коммуникатора (identity.js)
  personalRoom: null, // {topic, key} личной комнаты
  inboxListener: null,
  incoming: null, // активный входящий ring {ringId, payload, fromFp}
  outCall: null, // активный исходящий ring
  linkFp: null, // &d= из открытой ссылки (личная ссылка владельца)
  autoJoinPending: false,
  pushSub: null,
  groupHook: null, // сюда регистрируется group.js (mesh для 3+ участников)
  ctrl: null,
  fileCh: null,
  sendQueue: [],
  sending: false,
  incomingFile: null,
  restartTimer: null,
  statsTimer: null,
  helloTimer: null,
  callStart: 0,
  prevStats: null,
  sigStatus: { mqttUp: 0, mqttTotal: 0, worker: 'off', workerHttp: 'off', nostrUp: 0, nostrTotal: 0 },
  unread: 0,
  wakeLock: null,
  joined: false,
  dead: new Set(),
  gen: 0,
  watchdog: null,
  resendTimer: null,
  ackReceived: false,
  log: [],
  cands: { local: {}, remote: {} },
  via: {},
  pct: 0,
  step: '',
  method: '',
  countedOk: false,
};

// ---------- Утилиты UI ----------
function show(id) {
  ['home', 'prejoin', 'call'].forEach((s) => $('#' + s).classList.toggle('hidden', s !== id));
  if (id === 'home') refreshPersonalUI().catch(() => {});
}
function syncChatOpen() {
  const call = $('#call');
  const chat = $('#chat');
  if (call && chat) call.classList.toggle('chat-open', !chat.classList.contains('hidden'));
}
let toastT;
function toast(t, ms = 3200) {
  const e = $('#toast');
  if (!e) return;
  e.textContent = t;
  e.classList.remove('hidden');
  clearTimeout(toastT);
  toastT = setTimeout(() => e.classList.add('hidden'), ms);
}
function openModal(tplId) {
  const b = $('#modalBody');
  b.replaceChildren($(tplId).content.cloneNode(true));
  $('#modal').classList.remove('hidden');
  return b;
}
function closeModal() {
  if (S.testingMic) stopMicTest();
  $('#modal').classList.add('hidden');
}
document.addEventListener('click', (e) => {
  if (S.audioCtx && S.audioCtx.state === 'suspended') {
    S.audioCtx.resume().catch(() => {});
  }
  const c = e.target.closest('[data-close]');
  if (!c) return;
  if (c.dataset.close === 'modal') closeModal();
  else {
    $('#' + c.dataset.close)?.classList.add('hidden');
    if (c.dataset.close === 'chat') syncChatOpen();
  }
});
$('#modal').addEventListener('click', (e) => {
  if (e.target.id === 'modal') closeModal();
});

const fmtSize = (b) => (b > 1e6 ? (b / 1e6).toFixed(1) + ' МБ' : Math.ceil(b / 1e3) + ' КБ');
const roomLink = () =>
  location.origin + location.pathname + '#k=' + S.secret +
  (S.personal && S.secret === S.personal.secret ? '&d=' + S.personal.fp : '');

function renderQr(el, text) {
  if (typeof qrcode === 'undefined' || !el) return;
  const q = qrcode(0, 'M');
  q.addData(text);
  q.make();
  el.innerHTML = q.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
}
async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Ссылка скопирована');
  } catch {
    toast('Не удалось скопировать');
  }
}
function beep(freq = 880, dur = 0.14) {
  try {
    const a = new (window.AudioContext || window.webkitAudioContext)();
    const o = a.createOscillator();
    const g = a.createGain();
    o.frequency.value = freq;
    g.gain.value = 0.04;
    o.connect(g).connect(a.destination);
    o.start();
    o.stop(a.currentTime + dur);
    setTimeout(() => a.close(), 350);
  } catch {}
}

// ---------- Маршрутизация и Главный экран ----------
function route() {
  const params = new URLSearchParams(location.hash.slice(1));
  // v21: ссылка приватного чата (#chat=<seed>) — обрабатывает chat.js,
  // звонковая маршрутизация ниже её не касается.
  if (params.get('chat')) {
    S.secret = null;
    show('home');
    window.ZVChat?.openFromHash?.();
    return;
  }
  const k = params.get('k');
  const d = params.get('d');
  S.linkFp = d && /^[a-f0-9]{32}$/.test(d) ? d : null;
  if (S.joined) return;
  if (k && /^[A-Za-z0-9_-]{22,}$/.test(k)) {
    S.secret = k;
    preJoin();
  } else {
    S.secret = null;
    stopLocal();
    show('home');
  }
}
window.addEventListener('hashchange', route);
$('#btnCreate').onclick = () => {
  location.hash = 'k=' + newSecret();
};
$('#btnOpenLink').onclick = () => {
  const raw = ($('#homeLinkInput').value || '').trim();
  if (!raw) return toast('Вставьте ссылку или ключ звонка');
  const m = raw.match(/k=([A-Za-z0-9_-]{22,})/) || raw.match(/^([A-Za-z0-9_-]{22,})$/);
  if (m) {
    const dm = raw.match(/d=([a-f0-9]{32})/);
    location.hash = 'k=' + m[1] + (dm ? '&d=' + dm[1] : '');
  } else {
    toast('Неверный формат ссылки или ключа');
  }
};
$('#btnBackHome').onclick = () => {
  if (S.joined) return;
  S.secret = null;
  stopLocal();
  history.replaceState(null, '', location.pathname);
  show('home');
};

// ---------- Аудио-движок Discord (Web Audio API: 0-200% Gain, VAD, Compressor, Loopback) ----------
function ensureAudioEngine() {
  if (!S.audioCtx) {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return null;
    S.audioCtx = new Ctx();
  }
  if (S.audioCtx.state === 'suspended') {
    S.audioCtx.resume().catch(() => {});
  }
  if (!S.audioCtx.onstatechange) {
    // iOS/Android усыпляют AudioContext при звонке на телефон, блокировке
    // экрана и после долгой тишины. Весь входящий звук у нас идёт через этот
    // граф (у <video id="remote"> громкость выставлена в 0), поэтому
    // suspended == полная тишина при живом WebRTC-соединении.
    S.audioCtx.onstatechange = () => {
      log('AudioContext: ' + S.audioCtx.state);
      if (S.audioCtx.state !== 'running') {
        S.audioCtx.resume().catch(() => {});
        updateRemoteAudibility();
      } else {
        updateRemoteAudibility();
      }
    };
  }
  if (!S.procDest) {
    const ctx = S.audioCtx;
    S.hpFilter = ctx.createBiquadFilter();
    S.hpFilter.type = 'highpass';
    S.hpFilter.frequency.value = S.audio.noise ? 85 : 20;

    S.micGainNode = ctx.createGain();
    S.micGainNode.gain.value = S.audio.micVol / 100;

    S.micAnalyser = ctx.createAnalyser();
    S.micAnalyser.fftSize = 512;
    S.micAnalyser.smoothingTimeConstant = 0.55;

    S.gateGainNode = ctx.createGain();
    S.gateGainNode.gain.value = 1;

    S.procDest = ctx.createMediaStreamDestination();

    S.hpFilter.connect(S.micGainNode);
    S.micGainNode.connect(S.micAnalyser);
    S.micAnalyser.connect(S.gateGainNode);
    S.gateGainNode.connect(S.procDest);

    // Цепочка обработки входящего голоса собеседника (0-200% + компрессор четкости)
    S.remoteCompNode = ctx.createDynamicsCompressor();
    S.remoteCompNode.threshold.value = -26;
    S.remoteCompNode.knee.value = 18;
    S.remoteCompNode.ratio.value = S.audio.comp ? 3.5 : 1;
    S.remoteCompNode.attack.value = 0.005;
    S.remoteCompNode.release.value = 0.18;

    S.remoteGainNode = ctx.createGain();
    S.remoteGainNode.gain.value = S.deafened ? 0 : S.audio.peerVol / 100;

    S.remoteAnalyser = ctx.createAnalyser();
    S.remoteAnalyser.fftSize = 256;

    S.remoteDest = ctx.createMediaStreamDestination();

    S.remoteCompNode.connect(S.remoteGainNode);
    S.remoteGainNode.connect(S.remoteAnalyser);
    S.remoteAnalyser.connect(S.remoteDest);
    // Также подключаем к системному выходу по умолчанию (если не выбран кастомный sinkId)
    S.remoteAnalyser.connect(ctx.destination);
  }
  startMeterLoop();
  return S.audioCtx;
}


// Куда реально звучит собеседник: через WebAudio-граф (громкость 0-200%),
// а если граф недоступен/уснул — напрямую через элемент <video id="remote">
// (громкость до 100%). Раньше при уснувшем AudioContext звук пропадал
// полностью и навсегда: элемент был заглушён, а граф молчал.
function updateRemoteAudibility() {
  const vid = $('#remote');
  if (!vid) return;
  const viaEngine = !!(S.audioCtx && S.audioCtx.state === 'running' && S.remoteSource);
  vid.volume = viaEngine || S.deafened ? 0 : Math.min(1, S.audio.peerVol / 100);
  if (S.deafened) vid.volume = 0;
}

// Попытка оживить входящий звук без пересоздания звонка.
function recoverRemoteAudio(reason) {
  const now = Date.now();
  if (now - (S.lastAudioRecoverAt || 0) < 45000) return;
  S.lastAudioRecoverAt = now;
  log('Восстанавливаем входящий звук: ' + reason);
  const ctx = ensureAudioEngine();
  ctx?.resume?.().catch(() => {});
  attachRemoteToEngine();
  updateRemoteAudibility();
  $('#remote')?.play().catch(() => {});
}

function attachMicToEngine(rawTrack) {
  S.rawAudioTrack = rawTrack;
  const ctx = ensureAudioEngine();
  if (!ctx || !rawTrack) return rawTrack;
  try {
    if (S.micSource) {
      try { S.micSource.disconnect(); } catch {}
    }
    S.micSource = ctx.createMediaStreamSource(new MediaStream([rawTrack]));
    S.micSource.connect(S.hpFilter);
    const procTrack = S.procDest.stream.getAudioTracks()[0];
    return procTrack || rawTrack;
  } catch {
    return rawTrack;
  }
}

function attachRemoteToEngine() {
  const ctx = ensureAudioEngine();
  const audioTracks = S.remote.getAudioTracks();
  if (!ctx || !audioTracks.length) return;
  try {
    if (S.remoteSource) {
      try { S.remoteSource.disconnect(); } catch {}
    }
    S.remoteSource = ctx.createMediaStreamSource(new MediaStream(audioTracks));
    S.remoteSource.connect(S.remoteCompNode);

    const outEl = $('#remoteAudioOut');
    if (outEl && S.dev.spk && 'setSinkId' in HTMLMediaElement.prototype) {
      // Если выбран конкретный динамик через setSinkId — выводим через remoteAudioOut
      try { S.remoteAnalyser.disconnect(ctx.destination); } catch {}
      outEl.srcObject = S.remoteDest.stream;
      outEl.setSinkId(S.dev.spk).catch(() => {});
      outEl.play().catch(() => {});
    } else {
      try { S.remoteAnalyser.connect(ctx.destination); } catch {}
    }
    // Приглушаем прямой звук из <video id="remote">, пока граф жив,
    // чтобы громкость регулировалась через GainNode (0-200%)
    updateRemoteAudibility();
  } catch (e) {
    console.warn('remote audio graph', e);
  }
}

let persistTimer = 0;
function persistSoon() {
  if (persistTimer) return;
  persistTimer = setTimeout(() => {
    persistTimer = 0;
    try {
      localStorage.zvMicVol = String(S.audio.micVol);
      localStorage.zvPeerVol = String(S.audio.peerVol);
      localStorage.zvInputMode = S.audio.inputMode;
      localStorage.zvVadGate = String(S.audio.vadGate);
      localStorage.zvNoise = S.audio.noise ? '1' : '0';
      localStorage.zvEcho = S.audio.echo ? '1' : '0';
      localStorage.zvAgc = S.audio.agc ? '1' : '0';
      localStorage.zvComp = S.audio.comp ? '1' : '0';
      localStorage.zvOpusTune = S.audio.opusTune ? '1' : '0';
      localStorage.zvBitrate = String(S.audio.bitrate);
      localStorage.zvNetMode = S.audio.netMode;
      localStorage.zvRelay = S.audio.netMode === 'relay' ? '1' : '0';
    } catch {}
  }, 250);
}

function syncAudioParams() {
  persistSoon();

  if (S.hpFilter) S.hpFilter.frequency.value = S.audio.noise ? 85 : 20;
  if (S.micGainNode) S.micGainNode.gain.value = S.audio.micVol / 100;
  if (S.remoteCompNode) S.remoteCompNode.ratio.value = S.audio.comp ? 3.5 : 1;
  if (S.remoteGainNode) S.remoteGainNode.gain.value = S.deafened ? 0 : S.audio.peerVol / 100;

  updateRemoteAudibility();

  // Обновляем подписи и ползунки во всех открытых панелях
  const gatePct = Math.max(0, Math.min(100, ((S.audio.vadGate + 75) / 60) * 100));
  for (const id of ['#pVadGateMark', '#qaVadGateMark', '#sVadGateMark']) {
    const el = $(id);
    if (el) el.style.left = gatePct + '%';
  }
  if ($('#pMicVol')) $('#pMicVol').value = S.audio.micVol;
  if ($('#pMicVolTxt')) $('#pMicVolTxt').textContent = S.audio.micVol + '%';
  if ($('#pPeerVol')) $('#pPeerVol').value = S.audio.peerVol;
  if ($('#pPeerVolTxt')) $('#pPeerVolTxt').textContent = S.audio.peerVol + '%';
  if ($('#qaPeerVol')) $('#qaPeerVol').value = S.audio.peerVol;
  if ($('#qaPeerVolTxt')) $('#qaPeerVolTxt').textContent = S.audio.peerVol + '%';
  if ($('#qaMicVol')) $('#qaMicVol').value = S.audio.micVol;
  if ($('#qaMicVolTxt')) $('#qaMicVolTxt').textContent = S.audio.micVol + '%';
  if ($('#quickVolLabel')) $('#quickVolLabel').textContent = S.deafened ? 'ВЫКЛ' : S.audio.peerVol + '%';
  setBtnIcon('#btnQuickAudio', S.deafened ? 'i-volume-x' : 'i-volume');
  if ($('#preInputModeText')) {
    $('#preInputModeText').textContent =
      S.audio.inputMode === 'ptt'
        ? 'Рация (нажми и говори)'
        : S.audio.inputMode === 'vad'
        ? `По голосу (${S.audio.vadGate} дБ)`
        : 'Открытый микрофон';
  }
  setUse('#preInputModeTag use', S.audio.inputMode === 'ptt' ? 'i-radio' : 'i-mic');
  if ($('#preCodecTag')) {
    $('#preCodecTag').textContent = S.audio.opusTune
      ? `Opus ${S.audio.bitrate} kbps · FEC, без DTX`
      : 'Opus · авто (настройки браузера)';
  }
  // Показываем кнопку PTT на экране звонка, если включен режим рации или активен мост
  $('#cPtt')?.classList.toggle('hidden', S.audio.inputMode !== 'ptt' && !S.bridgeActive);
}

function startMeterLoop() {
  if (S.meterTimer) return;
  const buf = new Float32Array(256);
  const rBuf = new Uint8Array(64);
  S.meterTimer = setInterval(() => {
    // 0. Сторож AudioContext: браузеры усыпляют его при блокировке экрана,
    //    входящем телефонном звонке и долгой тишине — а вместе с ним пропадал
    //    весь входящий звук при живом соединении. Будим не чаще раза в секунду.
    if (S.audioCtx && S.audioCtx.state !== 'running' && Date.now() - (S.ctxResumeAt || 0) > 1000) {
      S.ctxResumeAt = Date.now();
      S.audioCtx.resume().catch(() => {});
      updateRemoteAudibility();
    }
    // 1. Анализ локального микрофона и работа гейта (VAD / PTT)
    if (S.micAnalyser && S.rawAudioTrack && S.rawAudioTrack.readyState === 'live') {
      S.micAnalyser.getFloatTimeDomainData(buf);
      let sum = 0;
      for (let i = 0; i < buf.length; i++) sum += buf[i] * buf[i];
      const rms = Math.sqrt(sum / buf.length);
      const db = rms > 0.00001 ? Math.max(-75, Math.min(0, 20 * Math.log10(rms))) : -75;
      const pct = Math.max(0, Math.min(100, ((db + 75) / 60) * 100));

      for (const id of ['#pVadBar', '#qaVadBar', '#sVadBar']) {
        const el = $(id);
        if (el) el.style.width = (S.micOn && !S.deafened ? pct : 0) + '%';
      }
      if ($('#pDbVal')) {
        $('#pDbVal').textContent = db <= -74 ? '-∞ дБ' : Math.round(db) + ' дБ';
      }

      const now = Date.now();
      let pass = false;
      if (!S.micOn || S.deafened) {
        pass = false;
      } else if (S.audio.inputMode === 'open') {
        // Открытый микрофон (дефолт v14): гейта на пути звука нет вообще.
        // isSpeaking считаем по энергии только для индикации и моста.
        pass = true;
        S.isSpeaking = db > -55;
      } else if (S.audio.inputMode === 'ptt') {
        pass = S.pttPressed;
      } else {
        // Гистерезис: открываемся по порогу, закрываемся на 7 дБ ниже и с
        // длинным хвостом. Раньше гейт (280 мс, без гистерезиса, крутой срез
        // за 15 мс) глотал тихие слова и окончания фраз — собеседнику казалось,
        // что «громкость то пропадает, то возвращается».
        if (db >= S.audio.vadGate) {
          S.vadHoldUntil = now + 900;
        } else if (db >= S.audio.vadGate - 7 && now < S.vadHoldUntil) {
          S.vadHoldUntil = now + 300;
        }
        pass = now < S.vadHoldUntil;
      }
      if (S.audio.inputMode !== 'open') S.isSpeaking = pass;
      if (S.gateGainNode && S.audioCtx) {
        S.gateGainNode.gain.setTargetAtTime(pass ? 1 : 0, S.audioCtx.currentTime, 0.07);
      }
      $('#cMic')?.classList.toggle('speaking', pass);
      $('#preAvatarRing')?.classList.toggle('speaking', pass);
    }

    // 2. Индикация голоса собеседника (зеленое кольцо вокруг аватара как в Discord)
    let peerTalking = Date.now() < S.bridgeSpeakingUntil;
    if (!peerTalking && S.remoteAnalyser && S.pc?.connectionState === 'connected') {
      S.remoteAnalyser.getByteFrequencyData(rBuf);
      let rSum = 0;
      for (let i = 0; i < rBuf.length; i++) rSum += rBuf[i];
      if (rSum / rBuf.length > 14) peerTalking = true;
    }
    $('#peerAvatarRing')?.classList.toggle('speaking', peerTalking);
    $('#voiceWave')?.classList.toggle('hidden', !peerTalking && !S.bridgeActive);
  }, 65);
}

function toggleMicTest(btnEl) {
  const ctx = ensureAudioEngine();
  if (!ctx || !S.gateGainNode) return;
  S.testingMic = !S.testingMic;
  try {
    if (S.testingMic) {
      S.gateGainNode.connect(ctx.destination);
      toast('Проверка микрофона включена — говорите');
    } else {
      S.gateGainNode.disconnect(ctx.destination);
    }
  } catch {}
  paintMicTest();
  if (btnEl) btnEl.setAttribute('aria-pressed', String(S.testingMic));
}
function paintMicTest() {
  const labels = { '#pTestMic': ['Проверить микрофон', 'Стоп тест'], '#sTestMic': ['Проверить', 'Стоп'] };
  for (const [id, [idle, active]] of Object.entries(labels)) {
    const b = $(id);
    if (!b) continue;
    b.classList.toggle('active-test', S.testingMic);
    b.setAttribute('aria-pressed', String(S.testingMic));
    const lbl = b.querySelector('.lbl');
    if (lbl) lbl.textContent = S.testingMic ? active : idle;
    setBtnIcon(b, S.testingMic ? 'i-stop' : 'i-volume');
  }
}
function stopMicTest() {
  if (!S.testingMic) return;
  S.testingMic = false;
  try {
    S.gateGainNode?.disconnect(S.audioCtx.destination);
  } catch {}
  paintMicTest();
}

// ---------- Медиа и переключение устройств ----------
const audioC = () => ({
  deviceId: S.dev.mic ? { ideal: S.dev.mic } : undefined,
  echoCancellation: S.audio.echo,
  noiseSuppression: S.audio.noise,
  autoGainControl: S.audio.agc,
});
const videoC = () => ({
  deviceId: S.dev.cam ? { ideal: S.dev.cam } : undefined,
  // Хорошее качество по умолчанию: просим Full HD, браузер сам снизит
  // разрешение, если камера/сеть слабее; адаптация качества ниже тоже работает.
  width: { ideal: 1920 },
  height: { ideal: 1080 },
  frameRate: { ideal: 30 },
});

function stopLocal() {
  stopMicTest();
  if (S.rawAudioTrack) {
    try { S.rawAudioTrack.stop(); } catch {}
    S.rawAudioTrack = null;
  }
  S.local.getTracks().forEach((t) => {
    t.stop();
    S.local.removeTrack(t);
  });
}
function localTrack(kind) {
  return S.local.getTracks().find((t) => t.kind === kind) || null;
}

async function getTrack(kind) {
  try {
    const st = await navigator.mediaDevices.getUserMedia(
      kind === 'audio' ? { audio: audioC() } : { video: videoC() }
    );
    return st.getTracks()[0];
  } catch (e) {
    console.warn(kind, e);
    return null;
  }
}

async function startLocal() {
  stopLocal();
  let st = null;
  try {
    st = await navigator.mediaDevices.getUserMedia({
      audio: audioC(),
      video: S.camOn ? videoC() : false,
    });
  } catch {
    try {
      st = await navigator.mediaDevices.getUserMedia({ audio: audioC() });
      toast('Камера недоступна — включён аудио-режим');
    } catch {
      toast('Нет доступа к микрофону и камере');
    }
  }
  if (st) {
    for (const t of st.getTracks()) {
      if (t.kind === 'audio') {
        const proc = attachMicToEngine(t);
        proc.enabled = S.micOn && !S.deafened;
        S.local.addTrack(proc);
      } else {
        S.local.addTrack(t);
      }
    }
  }
  if (!localTrack('video')) S.camOn = false;
  syncAudioParams();
  await fillDevices();
}

async function fillDevices(prefix = 'p') {
  const list = await navigator.mediaDevices.enumerateDevices().catch(() => []);
  const fill = (sel, kind, cur) => {
    if (!sel) return;
    sel.replaceChildren(
      ...list
        .filter((d) => d.kind === kind)
        .map((d, i) => {
          const o = document.createElement('option');
          o.value = d.deviceId;
          o.textContent = d.label || `${kind === 'audioinput' ? 'Микрофон' : kind === 'videoinput' ? 'Камера' : 'Динамик'} ${i + 1}`;
          return o;
        })
    );
    if (cur) sel.value = cur;
  };
  const a = S.rawAudioTrack?.getSettings().deviceId || localTrack('audio')?.getSettings().deviceId;
  const v = localTrack('video')?.getSettings().deviceId;
  if (prefix === 'p') {
    fill($('#pMicSel'), 'audioinput', a);
    fill($('#pCamSel'), 'videoinput', v);
  } else {
    fill($('#sMic'), 'audioinput', a);
    fill($('#sCam'), 'videoinput', v);
    fill($('#sSpk'), 'audiooutput', S.dev.spk);
  }
}

async function setSendTrack(kind, track) {
  S.groupHook?.refreshTracks?.();
  if (!S.pc) return;
  const tr = S.pc.getTransceivers().find((t) => !t.stopped && t.receiver.track?.kind === kind);
  if (tr) {
    await tr.sender.replaceTrack(track);
    if (track && (tr.direction === 'recvonly' || tr.direction === 'inactive')) tr.direction = 'sendrecv';
    try {
      tr.sender.setStreams?.(S.local);
    } catch {}
  } else if (track) {
    S.pc.addTrack(track, S.local);
  }
}

async function switchDevice(kind, id) {
  if (kind === 'mic') S.dev.mic = localStorage.zvMic = id;
  else S.dev.cam = localStorage.zvCam = id;
  const k = kind === 'mic' ? 'audio' : 'video';
  if (k === 'video' && (!S.camOn || S.screenTrack)) return;
  const old = localTrack(k);
  const raw = await getTrack(k);
  if (!raw) return toast('Не удалось переключить устройство');
  if (k === 'audio' && S.rawAudioTrack && S.rawAudioTrack !== raw) {
    try { S.rawAudioTrack.stop(); } catch {}
  }
  if (old) {
    old.stop();
    S.local.removeTrack(old);
  }
  const finalTrack = k === 'audio' ? attachMicToEngine(raw) : raw;
  if (k === 'audio') finalTrack.enabled = S.micOn && !S.deafened;
  S.local.addTrack(finalTrack);
  await setSendTrack(k, finalTrack);
  refreshLocalView();
}

async function toggleMic() {
  S.micOn = !S.micOn;
  if (S.micOn && S.deafened) S.deafened = false;
  let a = localTrack('audio');
  if (!a && S.micOn) {
    const raw = await getTrack('audio');
    if (raw) {
      a = attachMicToEngine(raw);
      S.local.addTrack(a);
      await setSendTrack('audio', a);
    } else S.micOn = false;
  }
  if (a) a.enabled = S.micOn && !S.deafened;
  syncAudioParams();
  syncButtons();
  sendCtrl({ t: 'state', mic: S.micOn, cam: S.camOn || !!S.screenTrack });
}

function toggleDeafen() {
  S.deafened = !S.deafened;
  const a = localTrack('audio');
  if (a) a.enabled = S.micOn && !S.deafened;
  syncAudioParams();
  syncButtons();
  toast(S.deafened ? 'Звук и микрофон отключены (Deafen)' : 'Звук включён');
}

async function toggleCam() {
  S.camOn = !S.camOn;
  if (!S.screenTrack) {
    const old = localTrack('video');
    if (!S.camOn && old) {
      old.stop();
      S.local.removeTrack(old);
      await setSendTrack('video', null);
    }
    if (S.camOn) {
      const t = await getTrack('video');
      if (t) {
        S.local.addTrack(t);
        await setSendTrack('video', t);
      } else {
        S.camOn = false;
        toast('Камера недоступна');
      }
    }
  }
  refreshLocalView();
  syncButtons();
  sendCtrl({ t: 'state', mic: S.micOn, cam: S.camOn || !!S.screenTrack });
}

async function toggleScreen() {
  if (S.screenTrack) return stopScreen();
  try {
    const st = await navigator.mediaDevices.getDisplayMedia({
      video: { width: { ideal: 1920 }, height: { ideal: 1080 }, frameRate: { ideal: 30 } },
      audio: false,
    });
    S.screenTrack = st.getVideoTracks()[0];
    S.screenTrack.contentHint = 'detail';
    S.screenTrack.onended = stopScreen;
    const cam = localTrack('video');
    if (cam) {
      cam.stop();
      S.local.removeTrack(cam);
    }
    await setSendTrack('video', S.screenTrack);
    $('#local').srcObject = new MediaStream([S.screenTrack]);
    $('#local').classList.add('screen');
    syncButtons();
    sendCtrl({ t: 'state', mic: S.micOn, cam: true });
  } catch (e) {
    console.warn(e);
  }
}
async function stopScreen() {
  if (!S.screenTrack) return;
  S.screenTrack.onended = null;
  S.screenTrack.stop();
  S.screenTrack = null;
  $('#local').classList.remove('screen');
  let t = null;
  if (S.camOn) {
    t = await getTrack('video');
    if (t) S.local.addTrack(t);
    else S.camOn = false;
  }
  await setSendTrack('video', t);
  refreshLocalView();
  syncButtons();
  sendCtrl({ t: 'state', mic: S.micOn, cam: S.camOn });
}

function refreshLocalView() {
  const v = localTrack('video');
  for (const el of [$('#preview'), $('#local')]) {
    if (!el) continue;
    if (el.id === 'local' && S.screenTrack) continue;
    el.srcObject = v ? new MediaStream([v]) : null;
  }
  $('#previewOff')?.classList.toggle('hidden', !!v);
  $('#local')?.classList.toggle('hidden', !v && !S.screenTrack);
}
function syncButtons() {
  const micOff = !S.micOn || S.deafened;
  for (const id of ['#pMic', '#cMic']) {
    const b = $(id);
    if (!b) continue;
    b.classList.toggle('off', micOff);
    b.setAttribute('aria-pressed', String(!micOff));
    b.title = micOff ? 'Микрофон выключен' : 'Микрофон включён';
    setBtnIcon(b, micOff ? 'i-mic-off' : 'i-mic');
  }
  for (const id of ['#pCam', '#cCam']) {
    const b = $(id);
    if (!b) continue;
    b.classList.toggle('off', !S.camOn);
    b.setAttribute('aria-pressed', String(S.camOn));
    b.title = S.camOn ? 'Камера включена' : 'Камера выключена';
    setBtnIcon(b, S.camOn ? 'i-cam' : 'i-cam-off');
  }
  const deaf = $('#cDeaf');
  if (deaf) {
    deaf.classList.toggle('off', S.deafened);
    deaf.setAttribute('aria-pressed', String(S.deafened));
    setBtnIcon(deaf, S.deafened ? 'i-headphones-off' : 'i-headphones');
  }
  const scr = $('#cScreen');
  if (scr) {
    scr.classList.toggle('on', !!S.screenTrack);
    scr.setAttribute('aria-pressed', String(!!S.screenTrack));
    setBtnIcon(scr, S.screenTrack ? 'i-stop' : 'i-screen');
  }
}

// ---------- Управление Рацией (Push-To-Talk: кнопка + клавиша Пробел) ----------
function setPtt(active) {
  if (S.pttPressed === active) return;
  S.pttPressed = active;
  const btn = $('#cPtt');
  if (btn) {
    btn.classList.toggle('tx', active);
    btn.setAttribute('aria-pressed', String(active));
    const lbl = $('#pttLabel');
    if (lbl) lbl.textContent = active ? 'Передача речи…' : 'Держите для речи';
  }
  if (active && navigator.vibrate) navigator.vibrate(18);
}
const pttBtn = $('#cPtt');
if (pttBtn) {
  pttBtn.addEventListener('pointerdown', (e) => {
    e.preventDefault();
    setPtt(true);
  });
  ['pointerup', 'pointercancel', 'pointerleave'].forEach((ev) =>
    pttBtn.addEventListener(ev, () => setPtt(false))
  );
}
window.addEventListener('keydown', (e) => {
  if (e.code === 'Space' && S.joined && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
    if (S.audio.inputMode === 'ptt' || S.bridgeActive) {
      e.preventDefault();
      setPtt(true);
    }
  }
});
window.addEventListener('keyup', (e) => {
  if (e.code === 'Space' && S.pttPressed) {
    setPtt(false);
  }
});

// ---------- Экран подготовки (Лобби) ----------
async function preJoin() {
  show('prejoin');
  $('#name').value = localStorage.zvName || '';
  $('#link').value = roomLink();
  $('#callOwnerBox')?.classList.toggle('hidden', !S.linkFp || (S.personal && S.secret === S.personal.secret));
  $('#qr').classList.add('hidden');
  $('#btnShare').classList.toggle('hidden', !navigator.share);
  syncAudioParams();
  if (!window.isSecureContext || !navigator.mediaDevices) {
    $('#preMsg').textContent = 'Нужен HTTPS-адрес для доступа к микрофону.';
    return;
  }
  await startLocal();
  refreshLocalView();
  syncButtons();
  if (S.autoJoinPending) {
    S.autoJoinPending = false;
    join();
  }
}
$('#pMic').onclick = toggleMic;
$('#pCam').onclick = toggleCam;
$('#pTestMic').onclick = () => toggleMicTest($('#pTestMic'));
$('#pOpenSettings').onclick = openSettingsModal;
$('#pMicSel').onchange = (e) => switchDevice('mic', e.target.value);
$('#pCamSel').onchange = (e) => switchDevice('cam', e.target.value);
$('#pMicVol').oninput = (e) => {
  S.audio.micVol = Number(e.target.value);
  syncAudioParams();
};
$('#pPeerVol').oninput = (e) => {
  S.audio.peerVol = Number(e.target.value);
  syncAudioParams();
};
$('#btnCopy').onclick = () => copy(roomLink());
$('#btnShare').onclick = () =>
  navigator.share({ title: 'ZVONochek', text: 'Заходи в защищённый звонок:', url: roomLink() }).catch(() => {});
$('#btnQr').onclick = () => {
  const q = $('#qr');
  q.classList.toggle('hidden');
  renderQr(q, roomLink());
};
$('#btnJoin').onclick = join;

// ---------- Вход в звонок и загрузка ICE/STUN/TURN ----------
async function fetchJson(url, ms = 4000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), ms);
  try {
    const r = await fetch(url, { signal: ctl.signal });
    return r.ok ? await r.json() : null;
  } finally {
    clearTimeout(t);
  }
}
const isTurn = (s) => [].concat(s?.urls || []).some((u) => /^turns?:/.test(u));

async function loadIce() {
  // v14 — лестница маршрутов и экономия TURN:
  // старт всегда только с бесплатным STUN (direct). TURN здесь НЕ запрашиваем.
  const servers = [{ urls: CONFIG.STUN }];
  S.stunOnlyIce = servers;
  S.turnLoaded = false;
  S.hasTurn = false;
  S.turnInfo = 'TURN не запрашивался (экономия квоты)';
  return servers;
}

// Эфемерные TURN-серверы: только из собственного Worker (/turn) или из
// динамического Metered API, если он когда-нибудь будет настроен в config.
// Никаких статических логинов/паролей в клиенте (их убрали в v14).
async function fetchTurnServers() {
  const out = [];
  const info = [];
  const jobs = [];
  if (getWorkerBase()) {
    jobs.push(
      fetchJson(getWorkerBase().replace(/\/$/, '') + '/turn')
        .then((j) => {
          const l = (j?.iceServers || []).filter(isTurn);
          out.push(...l);
          info.push(l.length ? 'Worker TURN: есть' : 'Worker: без TURN (только сигнал)');
        })
        .catch(() => info.push('Worker: офлайн'))
    );
  }
  const M = CONFIG.METERED;
  if (M?.domain && M?.apiKey) {
    jobs.push(
      fetchJson(`https://${M.domain}/api/v1/turn/credentials?apiKey=${encodeURIComponent(M.apiKey)}`)
        .then((j) => {
          const l = []
            .concat(j || [])
            .filter(isTurn)
            .map((sv) => ({ ...sv, urls: [].concat(sv.urls).filter((u) => !/:53(\?|$)/.test(u)) }));
          out.push(...l);
          info.push(l.length ? 'Metered: есть' : 'Metered: пусто');
        })
        .catch(() => info.push('Metered недоступен'))
    );
  }
  await Promise.all(jobs);
  // Резерв владельца: статические креды из config.js (возвращены решением
  // от 27.10.2026). Попадают сюда, а не в стартовый ICE, поэтому трафик через
  // них идёт только при реальной необходимости (ленивая догрузка).
  const stat = (CONFIG.EXTRA_ICE_SERVERS || []).filter(isTurn);
  if (stat.length) {
    out.push(...stat);
    info.push('Статический резерв из config: есть');
  }
  S.turnInfo = info.join(', ') || 'источники TURN не настроены';
  return out;
}

// Ленивая догрузка TURN: вызываем, только когда direct не встал вовремя,
// соединение упало или пользователь сам выбрал режим «только TURN».
// Звук в этот момент уже держит мост, поэтому медленный подъём TURN
// не создаёт тишины. Повторные вызовы безопасны.
async function ensureTurnLoaded(reason = '') {
  if (S.turnLoaded || S.turnLoading) return S.hasTurn;
  S.turnLoading = true;
  try {
    const turn = await fetchTurnServers();
    if (!turn.length) {
      S.turnLoaded = true; // не дёргаем источники впустую каждый раз
      log('TURN недоступен (' + S.turnInfo + ') — остаёмся на direct + мост');
      return false;
    }
    S.turnLoaded = true;
    S.hasTurn = true;
    S.ice = [...(S.stunOnlyIce || [{ urls: CONFIG.STUN }]), ...turn];
    if (S.pc) {
      try {
        S.pc.setConfiguration(pcConfig());
        S.pc.restartIce();
      } catch {}
    }
    log('Лениво добавлен TURN (' + (reason || 'по требованию') + '): ' + S.turnInfo);
    return true;
  } finally {
    S.turnLoading = false;
  }
}

const pcConfig = () => ({
  iceServers: S.ice,
  iceTransportPolicy: S.audio.netMode === 'relay' && S.hasTurn ? 'relay' : 'all',
  bundlePolicy: 'max-bundle',
  iceCandidatePoolSize: 4, // предсбор STUN-кандидатов для ускоренного рукопожатия без TURN
});

// Ручная настройка Opus в SDP — ТОЛЬКО если пользователь сам включил её в
// настройках (opusTune). По умолчанию SDP не трогаем: браузерный Opus и так
// включает FEC по ситуации и подбирает битрейт лучше фиксированных 24 кбит/с.
// DTX не включаем даже в ручном режиме: usedtx=1 вместе с VAD-гейтом резал
// тихий голос и «съедал» первые слова после паузы в долгих разговорах.
function tuneOpusSdp(sdp) {
  if (!sdp || !S.audio.opusTune) return sdp;
  const bps = (S.audio.bitrate || 48) * 1000;
  return sdp.replace(/a=fmtp:(\d+) (.*)/g, (full, pt, params) => {
    if (!sdp.includes(`a=rtpmap:${pt} opus/48000`)) return full;
    const clean = params
      .split(';')
      .filter((kv) => !/^(useinbandfec|usedtx|maxaveragebitrate|cbr)=/.test(kv.trim()))
      .join(';');
    return `a=fmtp:${pt} ${clean};useinbandfec=1;usedtx=0;cbr=0;maxaveragebitrate=${bps}`;
  });
}

async function join() {
  stopMicTest();
  ensureAudioEngine();
  $('#btnJoin').disabled = true;
  localStorage.zvName = $('#name').value.trim();
  try {
    [S.ice, S.room] = await Promise.all([loadIce(), deriveRoom(S.secret)]);
  } catch {
    $('#btnJoin').disabled = false;
    return toast('Неверная ссылка');
  }
  if (S.audio.netMode === 'relay') await ensureTurnLoaded('режим «только TURN» из прошлых настроек');
  S.joined = true;
  show('call');
  refreshLocalView();
  syncButtons();
  syncAudioParams();
  $('#cScreen').classList.toggle('hidden', !navigator.mediaDevices.getDisplayMedia);
  $('#remote').srcObject = S.remote;
  if (S.dev.spk) $('#remote').setSinkId?.(S.dev.spk).catch(() => {});

  S.sig = new Signaling({
    topic: S.room.topic,
    key: S.room.key,
    selfId,
    inst,
    brokers: CONFIG.MQTT_BROKERS,
    workerUrl: getWorkerBase(),
    relays: CONFIG.NOSTR_RELAYS,
    onMessage: onSignal,
    onStatus: (st) => {
      S.sigStatus = st;
      updateStatus();
    },
    onPeerJoined: () => {
      // Воркер сообщил, что второй участник открыл комнату — мгновенно шлём приветствие!
      hello();
    },
  });
  S.sig.onTransportUp = () => {
    hello();
    if (!S.peer) progress(25, 'Каналы сигнала активны, ждём собеседника');
  };
  log(
    `Вход в комнату. Сигнал: MQTT (${CONFIG.MQTT_BROKERS.length}), ${
      getWorkerBase() ? 'Worker (WS+HTTP), ' : ''
    }Nostr (${CONFIG.NOSTR_RELAYS.length}); TURN: ${S.hasTurn ? 'есть' : 'нет'} (${S.turnInfo || '—'})`
  );
  progress(10, 'Подключение к каналам сигналинга…');
  S.sig.start();
  S.joinedAt = Date.now();
  // TURN-креды Worker живут 6 часов: в долгом звонке обновляем ICE-серверы
  // каждый час, иначе после истечения TTL первое же переподключение ICE
  // теряет relay-путь и звонок умирает «сам по себе».
  clearInterval(S.iceRefreshTimer);
  S.iceRefreshTimer = setInterval(async () => {
    if (!S.joined || !S.turnLoaded || !S.hasTurn) return;
    const turn = await fetchTurnServers().catch(() => null);
    if (!turn || !turn.length || !S.joined) return;
    S.ice = [...(S.stunOnlyIce || [{ urls: CONFIG.STUN }]), ...turn];
    if (S.pc) {
      try { S.pc.setConfiguration(pcConfig()); } catch {}
      log('TURN-креды обновлены (профилактика истечения TTL)');
    }
  }, 60 * 60 * 1000);
  S.helloTimer = setInterval(() => {
    if (!S.pc || (S.pc.connectionState !== 'connected' && !S.bridgeActive)) hello();
    if (!S.peer && !S.waitHinted && Date.now() - S.joinedAt > 25000) {
      S.waitHinted = true;
      log('Собеседник пока не найден. Если он уже открыл ссылку — попросите его обновить страницу');
      $('#waitText').textContent =
        'Собеседник пока не найден. Если он уже в звонке — попросите его обновить страницу';
    }
  }, 4500);
  try {
    S.wakeLock = await navigator.wakeLock?.request('screen');
  } catch {}
  setupMediaSession();
  updateStatus();
  $('#btnJoin').disabled = false;
}

function setupMediaSession() {
  if (!('mediaSession' in navigator)) return;
  try {
    navigator.mediaSession.metadata = new MediaMetadata({
      title: 'Защищённый звонок ZVONochek',
      artist: S.peer?.name || 'На связи',
    });
    navigator.mediaSession.setActionHandler('hangup', () => hangup());
  } catch {}
}

const myName = () => localStorage.zvName || 'Гость';
const webCodecsBridgeSupported = () =>
  typeof AudioEncoder !== 'undefined' &&
  typeof AudioDecoder !== 'undefined' &&
  typeof MediaStreamTrackProcessor !== 'undefined';
function hello() {
  // bc: умеем ли мы в мост 2.0 (WebCodecs) — собеседник выберет формат под нас
  S.sig?.send({ type: 'hello', name: myName(), ver: APP_VERSION, bc: webCodecsBridgeSupported() ? 1 : 0 });
}

// ---------- Аварийный Аудио-Мост через Сигналинг (работает вообще без TURN и без UDP!) ----------
function activateBridge(reason = 'Активирован аудио-мост через сигналинг') {
  if (!S.peer || S.bridgeActive) return;
  if (rosterCount() > 1) {
    log('Мост недоступен в групповом звонке (3+ участника)');
    return;
  }
  S.bridgeActive = true;
  S.bridgeNextPlayTime = 0;
  clearTimeout(S.bridgeAutoTimer);
  log(reason);
  toast('Включён мост без TURN: голос идёт через зашифрованный сигнал', 5000);
  if (!S.bridgeCounted) {
    S.bridgeCounted = true;
    countRoute('bridge');
  }
  if (!S.callStart) {
    S.callStart = Date.now();
    beep(660, 0.16);
    sysMsg(`Звонок начат · ваша версия ZVONochek v${APP_VERSION} · маршрут: мост без TURN`);
  }
  $('#bridgeBadge')?.classList.remove('hidden');
  $('#cPtt')?.classList.remove('hidden');
  showBridgeSafety();
  startBridgeRecorder();
  updateStatus();
}

function stopBridge() {
  stopBridge2();
  if (S.bridgeDec) S.bridgeDec.nextPlay = 0;
  clearTimeout(S.bridgeAutoTimer);
  clearInterval(S.bridgeRecTimer);
  S.bridgeRecTimer = null;
  if (S.bridgeRecorder && S.bridgeRecorder.state !== 'inactive') {
    try { S.bridgeRecorder.stop(); } catch {}
  }
  S.bridgeRecorder = null;
  const wasActive = S.bridgeActive;
  S.bridgeActive = false;
  S.bridgeNextPlayTime = 0;
  S.bridgeSpeakingUntil = 0;
  $('#bridgeBadge')?.classList.add('hidden');
  syncAudioParams();
  // Код сверки зависел от режима моста — возвращаем код прямого P2P-соединения.
  if (S.pc?.connectionState === 'connected') {
    showSafety();
    if (wasActive && !S.leaving) toast('Прямое P2P-соединение установлено — мост отключён');
  }
}

function getSupportedAudioMime() {
  if (typeof MediaRecorder === 'undefined') return '';
  const types = [
    'audio/webm;codecs=opus',
    'audio/ogg;codecs=opus',
    'audio/webm',
    'audio/mp4',
  ];
  return types.find((t) => MediaRecorder.isTypeSupported(t)) || '';
}

// ---------- Мост 2.0: WebCodecs Opus (альтернативный метод, v14) ----------
// Вместо кусков MediaRecorder по ~0,7 с кодируем звук настоящими Opus-кадрами
// по 20 мс (AudioEncoder) и шлём пачками ~120 мс. Задержка моста падает в разы.
// Работает только там, где есть WebCodecs + MediaStreamTrackProcessor
// (Chromium). Собеседник без WebCodecs честно получает мост 1.0: формат
// выбирается по флагу bc из hello/hi, а не по нашему желанию.
function startBridgeRecorder() {
  if (!S.bridgeCounted) {
    S.bridgeCounted = true;
    countRoute('bridge');
  }
  if (S.peer?.bridgeCodecs && webCodecsBridgeSupported() && startBridge2()) {
    S.bridgeMode = 'webcodecs';
    return;
  }
  S.bridgeMode = 'mediarecorder';
  startBridgeRecorderV1();
}

function startBridge2() {
  stopBridge2();
  const track = S.procDest?.stream?.getAudioTracks?.()[0];
  if (!track) return false;
  const sampleRate = track.getSettings?.().sampleRate || 48000;
  const st = { running: true, sampleRate, frames: [], flushTimer: null, enc: null, reader: null };
  S.bridge2 = st;
  try {
    st.enc = new AudioEncoder({
      output: (chunk) => {
        try {
          const buf = new ArrayBuffer(chunk.byteLength);
          chunk.copyTo(buf);
          st.frames.push(new Uint8Array(buf));
        } catch {}
      },
      error: (e) => {
        console.warn('bridge2 enc', e);
        if (S.bridgeActive) {
          stopBridge2();
          S.bridgeMode = 'mediarecorder';
          startBridgeRecorderV1();
        }
      },
    });
    st.enc.configure({ codec: 'opus', sampleRate, numberOfChannels: 1, bitrate: 24000 });
    const processor = new MediaStreamTrackProcessor({ track });
    st.reader = processor.readable.getReader();
    st.flushTimer = setInterval(flushBridge2Frames, 120);
    (async () => {
      try {
        while (st.running) {
          const { value, done } = await st.reader.read();
          if (done) break;
          if (!value) continue;
          // Кодируем только реальную речь: тишина не жжёт трафик сигналинга.
          if (S.micOn && !S.deafened && S.isSpeaking && st.enc.state === 'configured') {
            try { st.enc.encode(value); } catch {}
          }
          value.close();
        }
      } catch {}
    })();
    log('Мост 2.0 (WebCodecs Opus, кадры 20 мс) включён');
    return true;
  } catch (e) {
    console.warn('bridge2 start', e);
    stopBridge2();
    return false;
  }
}

function flushBridge2Frames() {
  const st = S.bridge2;
  if (!st || !st.frames.length || !S.peer) return;
  const frames = st.frames.splice(0);
  let total = 0;
  for (const f of frames) total += 2 + f.length;
  if (total < 10 || total > 60000) return;
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  let o = 0;
  for (const f of frames) {
    dv.setUint16(o, f.length);
    o += 2;
    out.set(f, o);
    o += f.length;
  }
  S.sig?.send(
    { type: 'voice2', to: S.peer.id, toInst: S.peer.inst, sr: st.sampleRate, b64: b64u.enc(out), _noZip: true },
    { voice: true }
  );
}

function stopBridge2() {
  const st = S.bridge2;
  if (!st) return;
  st.running = false;
  clearInterval(st.flushTimer);
  try { st.reader?.cancel(); } catch {}
  try { st.enc?.close(); } catch {}
  if (S.bridge2 === st) S.bridge2 = null;
}

function ensureBridgeDecoder(sr) {
  const ctx = ensureAudioEngine();
  if (!ctx || typeof AudioDecoder === 'undefined') return null;
  let d = S.bridgeDec;
  if (d && d.sampleRate === sr && d.dec.state !== 'closed') return d;
  if (d) {
    try { d.dec.close(); } catch {}
  }
  d = S.bridgeDec = { sampleRate: sr, nextPlay: 0, ts: 0, dec: null };
  d.dec = new AudioDecoder({
    output: (data) => {
      try { scheduleDecodedBridgeFrame(data); } catch {}
      try { data.close(); } catch {}
    },
    error: (e) => console.warn('bridge2 dec', e),
  });
  d.dec.configure({ codec: 'opus', sampleRate: sr, numberOfChannels: 1 });
  return d;
}

function scheduleDecodedBridgeFrame(data) {
  const ctx = S.audioCtx;
  if (!ctx || !S.bridgeDec) return;
  const frames = data.numberOfFrames;
  if (!frames) return;
  const buf = ctx.createBuffer(1, frames, data.sampleRate);
  const tmp = new Float32Array(frames);
  try {
    data.copyTo(tmp, { planeIndex: 0, format: 'f32-planar' });
  } catch {
    try { data.copyTo(tmp, { planeIndex: 0 }); } catch { return; }
  }
  buf.copyToChannel(tmp, 0);
  const src = ctx.createBufferSource();
  src.buffer = buf;
  src.connect(S.remoteCompNode || ctx.destination);
  // Маленький джиттер-буфер: не копим отставание больше ~0,35 с.
  if (S.bridgeDec.nextPlay - ctx.currentTime > 0.35) S.bridgeDec.nextPlay = 0;
  const startAt = Math.max(ctx.currentTime + 0.04, S.bridgeDec.nextPlay || 0);
  src.start(startAt);
  S.bridgeDec.nextPlay = startAt + buf.duration;
}

async function playBridgeVoice2(m) {
  if (S.deafened || !m.b64) return;
  if (typeof AudioDecoder === 'undefined') return; // мы бы и не заявили bc=1
  if (!S.bridgeActive && S.pc?.connectionState !== 'connected') {
    activateBridge('Получен голос WebCodecs от собеседника по мосту 2.0');
  }
  S.bridgeSpeakingUntil = Date.now() + 400;
  $('#peerAvatarRing')?.classList.add('speaking');
  const d = ensureBridgeDecoder(m.sr || 48000);
  if (!d) return;
  const bytes = b64u.dec(m.b64);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let o = 0;
  while (o + 2 <= bytes.byteLength) {
    const len = dv.getUint16(o);
    o += 2;
    if (len <= 0 || o + len > bytes.byteLength) break;
    const pkt = bytes.slice(o, o + len);
    o += len;
    d.ts += 20000; // кадры по 20 мс
    try {
      d.dec.decode(new EncodedAudioChunk({ type: 'key', timestamp: d.ts, duration: 20000, data: pkt }));
    } catch {}
  }
}

function startBridgeRecorderV1() {
  if (typeof MediaRecorder === 'undefined') return;
  clearInterval(S.bridgeRecTimer);
  const mime = getSupportedAudioMime();

  // Каждые ~420 мс записываем и отправляем голосовой фрагмент, если пользователь говорит
  const recordSlice = () => {
    if (!S.bridgeActive || !S.joined || !S.peer) return;
    // Если прямое P2P WebRTC-соединение уже поднялось и пользователь не форсировал режим моста — уступаем P2P
    if (S.pc?.connectionState === 'connected' && S.audio.netMode !== 'bridge') {
      stopBridge();
      return;
    }
    if (!S.micOn || S.deafened || !S.isSpeaking) return;

    const stream = S.procDest?.stream || S.local;
    if (!stream || !stream.getAudioTracks().length) return;
    try {
      const rec = new MediaRecorder(stream, {
        ...(mime ? { mimeType: mime } : {}),
        audioBitsPerSecond: 16000, // 16 Кбит/с, куски короче (400 мс) — меньше задержка моста 1.0
      });
      const chunks = [];
      rec.ondataavailable = (ev) => {
        if (ev.data && ev.data.size > 0) chunks.push(ev.data);
      };
      rec.onstop = async () => {
        if (!chunks.length || !S.bridgeActive || !S.peer) return;
        const blob = new Blob(chunks, { type: rec.mimeType || mime || 'audio/webm' });
        const buf = new Uint8Array(await blob.arrayBuffer());
        if (buf.byteLength < 60 || buf.byteLength > 45000) return;
        S.sig?.send(
          {
            type: 'voice',
            to: S.peer.id,
            toInst: S.peer.inst,
            mime: blob.type,
            b64: b64u.enc(buf),
            _noZip: true,
          },
          { voice: true }
        );
      };
      rec.start();
      setTimeout(() => {
        if (rec.state === 'recording') {
          try { rec.stop(); } catch {}
        }
      }, 400);
    } catch (e) {
      console.warn('bridge recorder', e);
    }
  };

  S.bridgeRecTimer = setInterval(recordSlice, 420);
}

async function playBridgeVoice(m) {
  if (S.deafened || !m.b64) return;
  // Если мы получили голосовой пакет по мосту, значит собеседник говорит через мост
  if (!S.bridgeActive && S.pc?.connectionState !== 'connected') {
    activateBridge('Получен голос от собеседника по каналу сигналинга');
  }
  S.bridgeSpeakingUntil = Date.now() + 750;
  $('#peerAvatarRing')?.classList.add('speaking');
  $('#voiceWave')?.classList.remove('hidden');

  const bytes = b64u.dec(m.b64);
  const ctx = ensureAudioEngine();
  if (ctx && ctx.state === 'running') {
    try {
      const copyBuf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
      const audioBuf = await ctx.decodeAudioData(copyBuf);
      const src = ctx.createBufferSource();
      src.buffer = audioBuf;
      src.connect(S.remoteCompNode || ctx.destination);
      // Не даём очереди расти: при лагах сети сбрасываем накопленное опережение.
      if (S.bridgeNextPlayTime - ctx.currentTime > 0.6) S.bridgeNextPlayTime = 0;
      const startAt = Math.max(ctx.currentTime + 0.03, S.bridgeNextPlayTime || 0);
      src.start(startAt);
      S.bridgeNextPlayTime = startAt + audioBuf.duration;
      return;
    } catch {}
  }
  // Фоллбэк для браузеров, где decodeAudioData не декодирует фрагмент контейнера напрямую
  try {
    const blob = new Blob([bytes], { type: m.mime || 'audio/webm' });
    const url = URL.createObjectURL(blob);
    const a = new Audio(url);
    a.volume = Math.min(1, S.audio.peerVol / 100);
    a.onended = () => URL.revokeObjectURL(url);
    a.play().catch(() => URL.revokeObjectURL(url));
  } catch {}
}

$('#btnForceBridge').onclick = () => {
  if (!S.peer) return toast('Дождитесь подключения собеседника к комнате');
  activateBridge('Мост без TURN включён вручную');
};

// ---------- Обработка сигналинга и ускоренное рукопожатие ----------
const stats = (() => {
  try {
    return JSON.parse(localStorage.zvStats) || { tries: 0, ok: 0 };
  } catch {
    return { tries: 0, ok: 0 };
  }
})();
const saveStats = () => {
  localStorage.zvStats = JSON.stringify(stats);
};
// Счётчики маршрутов за всё время: видно, как часто реально нужен TURN.
const routeStats = (() => {
  try {
    return JSON.parse(localStorage.zvRoutes) || { direct: 0, relay: 0, bridge: 0 };
  } catch {
    return { direct: 0, relay: 0, bridge: 0 };
  }
})();
function countRoute(kind) {
  routeStats[kind] = (routeStats[kind] || 0) + 1;
  try {
    localStorage.zvRoutes = JSON.stringify(routeStats);
  } catch {}
}
const viaName = (v) =>
  ({ mqtt: 'MQTT', worker: 'Worker WS', 'worker-http': 'Worker HTTP', nostr: 'Nostr' }[v] || v);
const to = () => ({ to: S.peer.id, toInst: S.peer.inst, gen: S.gen });

const MAX_REMOTE_PEERS = 5; // комната: я + основной собеседник + до 4 групповых (mesh)
const groupVerWarned = new Set(); // inst участников, которым уже показали предупреждение о версии
function rosterCount() {
  const now = Date.now();
  let n = 0;
  for (const [k, v] of S.roster) {
    if (now - v.seen > 90000) S.roster.delete(k);
    else n++;
  }
  return n;
}

async function onSignal(m) {
  if (S.dead.has(m.inst)) return;
  S.via[m.via] = (S.via[m.via] || 0) + 1;
  // Ростер комнаты: запоминаем всех, кого слышим (нужно для группового режима,
  // группового чата и отключения моста при 3+ участниках).
  if (m.from && m.inst && m.from !== selfId) {
    const prev = S.roster.get(m.inst);
    S.roster.set(m.inst, { id: m.from, name: m.name || prev?.name || 'Участник', seen: Date.now() });
    if (S.bridgeActive && rosterCount() > 1) {
      log('В комнате больше двух участников — мост отключён (групповой режим)');
      stopBridge();
    }
  }
  // Групповой трафик: сообщения не от основного собеседника уходят в group.js.
  const isPrimaryPeer = S.peer && S.peer.id === m.from && S.peer.inst === m.inst;
  const primaryStale =
    S.peer && !isPrimaryPeer && S.pc?.connectionState !== 'connected' && !S.bridgeActive && Date.now() - S.peer.seen > 30000;
  if (S.peer && !isPrimaryPeer && !primaryStale && ['hello', 'hi', 'g_hi', 'g_desc', 'g_cand', 'desc', 'cand'].includes(m.type)) {
    if ((m.type === 'hello' || m.type === 'hi') && m.ver && m.ver !== APP_VERSION && !groupVerWarned.has(m.inst)) {
      groupVerWarned.add(m.inst);
      log(`Участник ${m.name || ''} на версии v${m.ver}, у вас v${APP_VERSION} — для групповых звонков лучше обновиться всем`);
    }
    if (m.type === 'hello' && !S.roster.has(m.inst)) return;
    if (m.type === 'hello' && rosterCount() > MAX_REMOTE_PEERS) {
      S.sig?.send({ type: 'full', to: m.from, toInst: m.inst });
      return;
    }
    S.groupHook?.onSignal?.(m);
    return;
  }
  // Рассинхрон ролей при одновременном входе троих: собеседник может считать
  // нас «лишним» и говорить групповым протоколом (g_desc/g_cand) с нами как
  // с основным — переводим в основной протокол и обрабатываем как обычно.
  if (isPrimaryPeer && (m.type === 'g_desc' || m.type === 'g_cand')) {
    noteGDialect();
    m = { ...m, type: m.type === 'g_desc' ? 'desc' : 'cand' };
  }
  // (v18: обратный перевод не нужен — group.js говорит и понимает desc/cand.)
  switch (m.type) {
    case 'hello':
    case 'hi':
      if (!acceptPeer(m)) return;
      if (S.peer && typeof m.bc === 'number') S.peer.bridgeCodecs = !!m.bc;
      if (m.type === 'hello') {
        S.sig.send({ type: 'hi', to: m.from, toInst: m.inst, name: myName(), ver: APP_VERSION, bc: webCodecsBridgeSupported() ? 1 : 0 });
      }
      if ((m.ver || 0) !== APP_VERSION && !S.verWarned && (m.type === 'hello' || m.ver)) {
        S.verWarned = true;
        const old = (m.ver || 0) < APP_VERSION;
        const t = old
          ? 'У собеседника старая версия ZVONochek — пусть обновит страницу (Ctrl+F5)'
          : 'Доступна новая версия ZVONochek — обновите страницу (Ctrl+F5)';
        log(`Версии разные: у меня v${APP_VERSION}, у собеседника v${m.ver || '?'}`);
        toast(t, 8000);
        sysMsg(t);
      }
      break;
    case 'ack':
      if (S.peer && m.from === S.peer.id) {
        S.ackReceived = true;
        clearTimeout(S.resendTimer);
      }
      break;
    case 'reset':
      if (acceptPeer(m) && m.gen > S.gen) {
        log(`Собеседник начал попытку №${m.gen + 1}`);
        newAttempt(m.gen);
      }
      break;
    case 'desc':
    case 'cand':
      if (!acceptPeer(m)) return;
      if (typeof m.gen === 'number' && m.gen > S.gen) {
        log(`Собеседник перешёл к попытке №${m.gen + 1}`);
        newAttempt(m.gen);
      }
      if (typeof m.gen === 'number' && m.gen < S.gen) return;
      if (m.type === 'desc') await onDesc(m.desc, m.via);
      else await onCand(m.cand);
      break;
    case 'voice':
      if (acceptPeer(m)) await playBridgeVoice(m);
      break;
    case 'voice2':
      if (acceptPeer(m)) await playBridgeVoice2(m);
      break;
    case 'sig_chat':
      if (acceptPeer(m) && typeof m.text === 'string') {
        onIncomingChat(m.text);
      }
      break;
    case 'g_hi':
      // Основной собеседник отвечает групповым протоколом (у него клиент,
      // где мы — mesh-участник): запоминаем диалект и отвечаем тем же.
      if (S.peer?.id === m.from && S.peer.inst === m.inst) noteGDialect();
      break;
    case 'g_chat':
      if (typeof m.text === 'string') onIncomingChat(m.text, m.name);
      break;
    case 'bye':
      S.roster.delete(m.inst);
      S.groupHook?.onPeerBye?.(m);
      if (S.peer?.id === m.from && S.peer.inst === m.inst) peerLeft();
      break;
    case 'full':
      if (!S.peer) {
        toast('В комнате уже двое участников — звонок 1:1', 6000);
        log('Комната занята');
      }
      break;
  }
}

function acceptPeer(m) {
  const p = S.peer;
  if (p && p.id === m.from && p.inst === m.inst) {
    p.seen = Date.now();
    if (m.name && m.name !== p.name) setPeerName(m.name);
    return true;
  }
  if (p && p.id === m.from) {
    log('Собеседник переподключился');
    S.dead.add(p.inst);
    resetPC();
    setPeer(m);
    return true;
  }
  if (p) {
    const alive = S.pc?.connectionState === 'connected' || S.bridgeActive || Date.now() - p.seen < 30000;
    if (alive) {
      // Групповой режим: лишних не выгоняем, пока в комнате есть место —
      // их подберёт group.js (mesh). 'full' только при переполнении.
      if (rosterCount() <= MAX_REMOTE_PEERS) return false;
      S.sig.send({ type: 'full', to: m.from, toInst: m.inst });
      return false;
    }
    resetPC();
  }
  setPeer(m);
  return true;
}

function setPeer(m) {
  S.peer = { id: m.from, inst: m.inst, name: m.name || 'Собеседник', seen: Date.now() };
  S.polite = selfId < m.from;
  S.peerDialect = 'plain';
  S.gen = 0;
  S.countedOk = false;
  stats.tries++;
  saveStats();
  setPeerName(S.peer.name);
  log(`Собеседник найден: ${S.peer.name} (канал: ${viaName(m.via)})`);
  progress(40, 'Собеседник найден, рукопожатие…');
  createPC();

  // Если выбран режим «Только Мост без TURN» — включаем голосовой мост мгновенно!
  // В режиме «Авто» даём WebRTC 10 секунд: за это время обычный звонок успевает подняться,
  // а при блокировке UDP/отсутствии TURN автоматически включается мост через сигналинг.
  // Лестница маршрутов v14: direct сразу, TURN — лениво через 6 секунд,
  // если прямое соединение не встало. Мост при этом уже на подходе (10 с
  // для зависшего checking, мгновенно при failed), поэтому тишины не будет.
  clearTimeout(S.turnTimer);
  if (S.audio.netMode === 'relay') {
    ensureTurnLoaded('режим «только TURN» выбран заранее');
  } else if (S.audio.netMode !== 'bridge') {
    S.turnTimer = setTimeout(() => {
      if (S.joined && S.peer && S.pc?.connectionState !== 'connected') {
        ensureTurnLoaded('direct не встал за 6 секунд');
      }
    }, 6000);
  }
  clearTimeout(S.bridgeAutoTimer);
  if (S.audio.netMode === 'bridge') {
    activateBridge('Выбран режим прямого моста через сигнал (без TURN)');
  } else {
    S.bridgeAutoTimer = setTimeout(() => {
      if (!S.joined || !S.peer || S.bridgeActive) return;
      const cs = S.pc?.connectionState;
      const ice = S.pc?.iceConnectionState;
      if (cs !== 'connected' && (cs === 'failed' || cs === 'disconnected' || ice === 'checking' || ice === 'failed')) {
        activateBridge('Прямой P2P заблокирован или нет TURN — включён авто-мост через сигнал');
      }
    }, 10_000);
  }
}

function setPeerName(n) {
  S.peer.name = n;
  $('#peerAvatar').textContent = (n[0] || '?').toUpperCase();
  if ($('#peerNameTitle')) $('#peerNameTitle').textContent = n;
  setupMediaSession();
  updateStatus();
}
function newAttempt(gen) {
  resetPC(true);
  S.gen = gen;
  createPC();
}

function createPC() {
  const pc = (S.pc = new RTCPeerConnection(pcConfig()));
  S.makingOffer = false;
  S.ignoreOffer = false;
  S.pendingCands = [];
  S.ackReceived = false;
  S.cands = { local: {}, remote: {} };
  S.route = '';
  S.method = '';
  S.pcRouteCounted = false;
  S.qLevel = 0;
  S.qBad = 0;
  S.qGood = 0;
  S.qHinted = false;
  log(
    `Попытка WebRTC №${S.gen + 1}: STUN (${CONFIG.STUN.length}), TURN: ${
      S.hasTurn ? 'есть' : 'нет'
    }${S.audio.netMode === 'relay' && S.hasTurn ? ' (только TURN)' : ''}`
  );
  S.remote = new MediaStream();
  $('#remote').srcObject = S.remote;
  S.ctrl = pc.createDataChannel('ctrl', { negotiated: true, id: 0 });
  S.fileCh = pc.createDataChannel('file', { negotiated: true, id: 1 });
  S.fileCh.binaryType = 'arraybuffer';
  S.fileCh.bufferedAmountLowThreshold = 1 << 20;
  S.ctrl.onopen = () =>
    sendCtrl({ t: 'state', mic: S.micOn, cam: S.camOn || !!S.screenTrack, name: myName() });
  S.ctrl.onmessage = (e) => onCtrl(e.data);
  S.fileCh.onmessage = (e) => onFileData(e.data);
  S.fileCh.onclose = () => {
    if (S.incomingFile) {
      S.incomingFile.el.querySelector('.who').textContent = 'Передача прервана';
      S.incomingFile = null;
    }
  };

  for (const t of S.local.getTracks()) pc.addTrack(t, S.local);
  if (S.screenTrack) pc.addTrack(S.screenTrack, S.local);

  pc.ontrack = ({ track }) => {
    S.remote.addTrack(track);
    if (track.kind === 'audio') {
      attachRemoteToEngine();
      track.addEventListener('mute', () => log('Входящий аудиотрек замьючен (сеть/источник)'));
      track.addEventListener('unmute', () => {
        log('Входящий аудиотрек снова активен');
        recoverRemoteAudio('unmute входящего трека');
      });
    }
    const upd = () => updateRemoteView();
    track.onmute = upd;
    track.onunmute = upd;
    track.onended = upd;
    upd();
    $('#remote')
      .play()
      .catch((e) => {
        if (e.name === 'NotAllowedError') $('#unmuteHint').classList.remove('hidden');
      });
  };
  pc.onnegotiationneeded = async () => {
    if (S.polite && !pc.currentRemoteDescription) {
      log('Ожидаем offer от собеседника');
      return;
    }
    try {
      S.makingOffer = true;
      const offer = await pc.createOffer();
      offer.sdp = tuneOpusSdp(offer.sdp);
      await pc.setLocalDescription(offer);
    } catch (e) {
      log('Ошибка offer: ' + e.message);
      return;
    } finally {
      S.makingOffer = false;
    }
    sendDesc(pc);
  };
  pc.onicecandidate = ({ candidate }) => {
    if (pc !== S.pc) return;
    if (!candidate) {
      log(`Сбор маршрутов завершён: ${candText(S.cands.local)}`);
      return;
    }
    S.cands.local[candidate.type] = (S.cands.local[candidate.type] || 0) + 1;
    S.sig.send({ type: candMsgType(), ...to(), cand: candidate.toJSON() });
    progressDetail();
  };
  pc.oniceconnectionstatechange = () => {
    if (pc !== S.pc) return;
    const s = pc.iceConnectionState;
    if (s === 'checking') progress(75, 'Пробиваем NAT и проверяем маршруты…');
    log('ICE: ' + s);
  };
  pc.onconnectionstatechange = () => onPcState(pc);
  armWatchdog(pc, S.polite ? 19000 : 13500);
  updateStatus();
}

function armWatchdog(pc, ms) {
  clearTimeout(S.watchdog);
  S.watchdog = setTimeout(() => {
    if (pc !== S.pc || pc.connectionState === 'connected') return;
    if (!pc._extended && ['checking', 'connected'].includes(pc.iceConnectionState)) {
      pc._extended = true;
      log('Маршрут почти согласован — ждём ещё 7 с');
      armWatchdog(pc, 7000);
      return;
    }
    // Если уже активно общаемся через Мост в режиме 'bridge', не перезапускаем PC впустую
    if (S.bridgeActive && S.audio.netMode === 'bridge') return;
    const g = S.gen + 1;
    log(`WebRTC P2P не соединился за ${Math.round(ms / 1000)} с — фоновая попытка №${g + 1}`);
    hintIfNeeded();
    newAttempt(g);
    S.sig.send({ type: 'reset', ...to() });
  }, ms);
}

function waitGathering(pc, ms) {
  return new Promise((res) => {
    if (pc.iceGatheringState === 'complete') return res();
    const done = () => {
      clearTimeout(t);
      pc.removeEventListener('icegatheringstatechange', chk);
      res();
    };
    const chk = () => pc.iceGatheringState === 'complete' && done();
    const t = setTimeout(done, ms);
    pc.addEventListener('icegatheringstatechange', chk);
  });
}
const sdpCands = (sdp) => sdp.match(/^a=candidate:.*$/gm) || [];

// Двухэтапная отправка SDP: быстрый старт через 450 мс + полный пакет кандидатов после досбора
// Собеседник на клиенте v16 считает нас mesh-участником и говорит со своим
// group.js (g_desc/g_cand), а наши обычные desc/cand его маршрутизация просто
// выбрасывает. Заметив его диалект, отвечаем тем же — иначе пара висит в
// цикле offer'ов без единого answer (полевые тесты v16–v18).
function noteGDialect() {
  if (S.peerDialect === 'g') return;
  S.peerDialect = 'g';
  log('Собеседник говорит групповым протоколом — отвечаем g_desc/g_cand');
  const pc = S.pc;
  if (pc?.localDescription && pc.signalingState === 'have-local-offer') {
    const d = { type: pc.localDescription.type, sdp: tuneOpusSdp(pc.localDescription.sdp) };
    S.sig?.send({ type: 'g_desc', ...to(), desc: d });
  }
}
const descMsgType = () => (S.peerDialect === 'g' ? 'g_desc' : 'desc');
const candMsgType = () => (S.peerDialect === 'g' ? 'g_cand' : 'cand');

async function sendDesc(pc) {
  await waitGathering(pc, 450);
  if (pc !== S.pc || !pc.localDescription) return;
  const desc = {
    type: pc.localDescription.type,
    sdp: tuneOpusSdp(pc.localDescription.sdp),
  };
  S.ackReceived = false;
  S.sig.send({ type: descMsgType(), ...to(), desc });
  log(
    `Отправлен ${desc.type === 'offer' ? 'запрос (offer)' : 'ответ (answer)'} (${
      sdpCands(desc.sdp).length
    } маршр.)`
  );
  progress(55, 'Обмен ключами шифрования…');
  scheduleResend(pc, desc, 1);

  // Если сбор кандидатов ещё продолжался — через 1.8 с досылаем консолидированный SDP со всеми STUN/TURN маршрутами
  if (pc.iceGatheringState !== 'complete') {
    await waitGathering(pc, 1800);
    if (pc === S.pc && pc.localDescription && pc.connectionState !== 'connected') {
      const fullDesc = {
        type: pc.localDescription.type,
        sdp: tuneOpusSdp(pc.localDescription.sdp),
      };
      if (sdpCands(fullDesc.sdp).length > sdpCands(desc.sdp).length) {
        S.sig.send({ type: descMsgType(), ...to(), desc: fullDesc });
      }
    }
  }
}

function scheduleResend(pc, desc, n) {
  clearTimeout(S.resendTimer);
  if (n > 5) return;
  S.resendTimer = setTimeout(() => {
    if (pc !== S.pc || pc.connectionState === 'connected' || S.ackReceived) return;
    if (desc.type === 'offer' && pc.signalingState !== 'have-local-offer') return;
    const latestDesc = pc.localDescription
      ? { type: pc.localDescription.type, sdp: tuneOpusSdp(pc.localDescription.sdp) }
      : desc;
    log(`Повтор отправки ${latestDesc.type} (#${n})`);
    S.sig.send({ type: descMsgType(), ...to(), desc: latestDesc });
    scheduleResend(pc, latestDesc, n + 1);
  }, 2300);
}

async function onDesc(desc, via) {
  const pc = S.pc;
  if (!pc) return;
  // Мгновенно подтверждаем получение SDP, чтобы собеседник знал, что канал жив
  S.sig.send({ type: 'ack', ...to(), ackType: desc.type });

  const collision = desc.type === 'offer' && (S.makingOffer || pc.signalingState !== 'stable');
  S.ignoreOffer = !S.polite && collision;
  if (S.ignoreOffer) {
    log('Встречный offer — уступает вежливая сторона');
    return;
  }
  try {
    await pc.setRemoteDescription(desc);
    for (const line of sdpCands(desc.sdp || '')) {
      const t = / typ (\w+)/.exec(line)?.[1];
      if (t) S.cands.remote[t] = (S.cands.remote[t] || 0) + 1;
    }
    log(`Получен ${desc.type === 'offer' ? 'запрос (offer)' : 'ответ (answer)'} через ${viaName(via)}`);
    for (const c of S.pendingCands.splice(0)) await pc.addIceCandidate(c).catch(() => {});
    if (desc.type === 'offer') {
      const answer = await pc.createAnswer();
      answer.sdp = tuneOpusSdp(answer.sdp);
      await pc.setLocalDescription(answer);
      sendDesc(pc);
    } else {
      clearTimeout(S.resendTimer);
    }
    progress(68, 'Ключи согласованы, пробиваем маршрут…');
    progressDetail();
  } catch (e) {
    log('Ошибка SDP: ' + e.message);
    if (S.pc === pc && !S.polite) armWatchdog(pc, 1500);
  }
}

async function onCand(c) {
  if (!c || !S.pc) return;
  const t = / typ (\w+)/.exec(c.candidate || '')?.[1];
  if (t) S.cands.remote[t] = (S.cands.remote[t] || 0) + 1;
  if (!S.pc.remoteDescription) {
    S.pendingCands.push(c);
    return;
  }
  try {
    await S.pc.addIceCandidate(c);
  } catch (e) {
    if (!S.ignoreOffer) console.warn('cand', e);
  }
  progressDetail();
}

function onPcState(pc) {
  if (pc !== S.pc) return;
  const s = pc.connectionState;
  log('WebRTC соединение: ' + s);
  clearTimeout(S.restartTimer);
  if (s === 'connected') {
    clearTimeout(S.watchdog);
    clearTimeout(S.bridgeAutoTimer);
    if (S.bridgeActive && S.audio.netMode !== 'bridge') {
      log('Прямой P2P WebRTC установлен — переключаемся с моста на прямой поток');
      stopBridge();
    }
    if (!S.callStart) {
      S.callStart = Date.now();
      beep();
      sysMsg(`Звонок начат · ваша версия ZVONochek v${APP_VERSION}`);
    }
    if (S.outCall) {
      // Собеседник и так в комнате (ждал по-старому) — ring больше не нужен
      const oc = S.outCall;
      inboxCancel(getWorkerBase(), oc.topic, oc.ringId, oc.signFn, oc.fromDevicePub).catch(() => {});
      finishOutCall('connected', true);
    }
    if (!S.countedOk) {
      S.countedOk = true;
      stats.ok++;
      saveStats();
    }
    showSafety();
    startStats(true);
    applyQuality();
  } else if (s === 'disconnected') {
    progress(80, 'Связь моргнула, восстанавливаем маршрут…');
    S.restartTimer = setTimeout(
      () => S.pc === pc && pc.connectionState !== 'connected' && restartIce(),
      2200
    );
  } else if (s === 'failed') {
    progress(80, 'Перезапуск ICE-маршрутов…');
    if (S.peer && !S.bridgeActive) {
      activateBridge('WebRTC P2P оборвался — включён резервный аудио-мост');
    }
    // Звук уже держит мост — спокойно догружаем TURN и только потом restart.
    ensureTurnLoaded('ICE failed').finally(() => {
      if (S.pc === pc) restartIce();
    });
  }
  updateStatus();
}

function restartIce() {
  if (!S.pc) return;
  log('Выполняем ICE restart');
  try {
    S.pc.restartIce();
  } catch {}
  armWatchdog(S.pc, S.polite ? 17000 : 11500);
}
// De-escalation при смене сети: новая сеть (Wi-Fi <-> LTE) может дать прямой
// маршрут, поэтому сначала сбрасываем TURN и пробуем direct; TURN вернётся
// лениво через 6 секунд, только если direct снова не встанет.
function deescalateToDirect() {
  if (!S.pc) return;
  if (S.turnLoaded && S.hasTurn) {
    S.turnLoaded = false;
    S.hasTurn = false;
    S.ice = S.stunOnlyIce || [{ urls: CONFIG.STUN }];
    try { S.pc.setConfiguration(pcConfig()); } catch {}
    log('Смена сети: сначала пробуем direct без TURN (экономия квоты)');
    clearTimeout(S.turnTimer);
    S.turnTimer = setTimeout(() => {
      if (S.joined && S.pc?.connectionState !== 'connected') {
        ensureTurnLoaded('после смены сети direct не встал');
      }
    }, 6000);
  }
  restartIce();
}
window.addEventListener('online', () => S.pc && S.callStart && deescalateToDirect());
if (navigator.connection) {
  navigator.connection.addEventListener?.('change', () => {
    if (S.pc && S.callStart) {
      log('Смена типа сети — обновляем ICE маршруты');
      deescalateToDirect();
    }
  });
}

function resetPC(keepBridge = false) {
  S.bridgeCounted = false;
  clearTimeout(S.restartTimer);
  clearTimeout(S.watchdog);
  clearTimeout(S.resendTimer);
  clearInterval(S.statsTimer);
  S.statsTimer = null;
  if (!keepBridge) stopBridge();
  try {
    S.pc?.close();
  } catch {}
  S.pc = null;
  S.ctrl = null;
  S.fileCh = null;
  if (!keepBridge) S.callStart = 0;
  S.prevStats = null;
  S.remote.getTracks().forEach((t) => S.remote.removeTrack(t));
  if (!keepBridge) {
    $('#safety').classList.add('hidden');
    $('#quality').classList.add('hidden');
  }
  updateRemoteView();
}

function peerLeft() {
  const n = S.peer?.name || 'Собеседник';
  resetPC(false);
  S.peer = null;
  if ($('#peerNameTitle')) $('#peerNameTitle').textContent = 'Ожидаем собеседника…';
  sysMsg(`${n} вышел из звонка`);
  toast(`${n} вышел из звонка`);
  log(`${n} вышел`);
  progress(25, 'Ожидаем собеседника');
  updateStatus();
}

// ---------- Прогресс и диагностика ----------
const CT = {
  host: 'локальных',
  srflx: 'внешних (STUN)',
  prflx: 'пробивных (PRFLX)',
  relay: 'через TURN',
};
const candText = (o) =>
  Object.keys(o).length
    ? Object.entries(o)
        .map(([k, v]) => `${CT[k] || k} ${v}`)
        .join(', ')
    : 'нет';

function log(t) {
  const line = new Date().toLocaleTimeString('ru-RU') + '  ' + t;
  S.log.push(line);
  if (S.log.length > 350) S.log.shift();
  const el = $('#diagLog');
  if (el) {
    el.textContent = S.log.join('\n');
    el.scrollTop = 1e9;
  }
}

function progress(pct, step) {
  if ((S.pc?.connectionState === 'connected' || S.bridgeActive) && pct < 100) return;
  S.pct = pct;
  S.step = step;
  $('#connPct').textContent = pct + '%';
  $('#connStep').textContent = step;
  $('#connBar').style.width = pct + '%';
  updateStatus();
}

function progressDetail() {
  const sg = S.sigStatus;
  const workerTag = getWorkerBase()
    ? `Worker ${sg.worker === 'up' ? 'WS: есть' : sg.workerHttp === 'up' ? 'HTTP: есть' : 'нет'}`
    : null;
  const ways = [
    `MQTT ${sg.mqttUp}/${sg.mqttTotal}`,
    workerTag,
    `Nostr ${sg.nostrUp || 0}/${sg.nostrTotal || 0}`,
  ]
    .filter(Boolean)
    .join(' · ');
  $('#connMethod').textContent =
    `Сигнал: ${ways}\nМои маршруты: ${candText(S.cands?.local || {})}\nМаршруты собеседника: ${candText(
      S.cands?.remote || {}
    )}` +
    (S.peer ? `\nПопытка №${S.gen + 1}` : '') +
    (S.method ? `\nСпособ: ${S.method}` : '');
}

function hintIfNeeded() {
  const l = S.cands.local,
    r = S.cands.remote;
  let h = '';
  if (!l.srflx && !l.relay)
    h = 'Провайдер блокирует UDP/STUN — автоматически используем Мост через Сигналинг.';
  else if (!S.hasTurn)
    h = 'Симметричный NAT без TURN — голос идёт через зашифрованный Мост сигналинга.';
  else if (!r.relay && !l.relay) h = 'TURN недоступен — используем обход через Мост.';
  if (h) log('Инфо: ' + h);
}

function diagText() {
  const pct = stats.tries ? Math.round((100 * stats.ok) / stats.tries) : 0;
  return (
    `ZVONochek v${APP_VERSION} — диагностика\nБраузер: ${navigator.userAgent}\n` +
    `Успешных P2P соединений: ${stats.ok} из ${stats.tries} (${pct}%)\n` +
    `Маршруты за всё время: напрямую ${routeStats.direct || 0} · через TURN ${routeStats.relay || 0} · через мост ${routeStats.bridge || 0}\n` +
    transportText() +
    `\nМои маршруты: ${candText(S.cands?.local || {})}\nМаршруты собеседника: ${candText(
      S.cands?.remote || {}
    )}\n` +
    `Сигналы получены: ${
      Object.entries(S.via)
        .map(([k, v]) => `${viaName(k)} ${v}`)
        .join(', ') || '—'
    }\n\nЖурнал:\n` +
    S.log.join('\n')
  );
}

function openDiag() {
  const b = openModal('#tplDiag');
  const pct = stats.tries ? Math.round((100 * stats.ok) / stats.tries) : 0;
  $('#diagStats', b).textContent =
    `Успешных P2P соединений: ${stats.ok} из ${stats.tries} (${pct}%)\n` +
    `Маршруты за всё время: напрямую ${routeStats.direct || 0} · через TURN ${routeStats.relay || 0} · через мост ${routeStats.bridge || 0}\n` +
    transportText() +
    `\nМои маршруты: ${candText(S.cands?.local || {})}\nМаршруты собеседника: ${candText(
      S.cands?.remote || {}
    )}`;
  $('#diagLog', b).textContent = S.log.join('\n');
  $('#diagCopy', b).onclick = async () => {
    try {
      await navigator.clipboard.writeText(diagText());
      toast('Отчёт диагностики скопирован');
    } catch {
      toast('Не удалось скопировать');
    }
  };
}
$('#btnDiag').onclick = openDiag;

// ---------- Статус, Качество, Код безопасности ----------
function updateRemoteView() {
  const v = S.remote.getVideoTracks().find((t) => t.readyState === 'live' && !t.muted);
  const camState = S.peer?.cam !== false;
  $('#remoteOff').classList.toggle('hidden', !!(v && camState && S.pc?.connectionState === 'connected'));
}

function updateStatus() {
  const st = $('#status');
  if (!st) return;
  const s = S.pc?.connectionState;
  const sg = S.sigStatus;
  const sigUp = sg.mqttUp > 0 || sg.worker === 'up' || sg.workerHttp === 'up' || sg.nostrUp > 0;
  let text;
  let iconName;
  if (!sigUp) {
    text = 'Подключение к сети…';
    iconName = 'i-loader';
  } else if (!S.peer) {
    text = 'Ожидаем собеседника';
    iconName = 'i-users';
  } else if (s === 'connected') {
    text = S.peer.name;
    iconName = 'i-check';
  } else if (S.bridgeActive) {
    text = S.peer.name;
    iconName = 'i-shield';
  } else {
    text = `${S.pct}% · ${S.step}`;
    iconName = 'i-loader';
  }
  const statusText = $('#statusText');
  if (statusText) statusText.textContent = text;
  setUse('#statusIcon', iconName);

  const isLive = s === 'connected' || S.bridgeActive;
  $('#waitText').textContent = !S.peer
    ? S.waitHinted
      ? 'Собеседник пока не найден. Если он уже в звонке — попросите его обновить страницу'
      : 'Отправьте ссылку собеседнику'
    : s === 'connected'
    ? S.peer.cam === false
      ? 'Голосовой звонок (камера выключена)'
      : 'Защищённое P2P-соединение активно'
    : S.bridgeActive
    ? 'Голосовой мост через зашифрованный сигнал активен (без TURN/UDP)'
    : `Соединяемся с ${S.peer.name}…`;

  $('#conn').classList.toggle('hidden', isLive);
  progressDetail();
  $('#timer').classList.toggle('hidden', !S.callStart);
  const tr = $('#sTransports');
  if (tr) tr.textContent = transportText();
}

function transportText() {
  const sg = S.sigStatus;
  const wText = getWorkerBase()
    ? sg.worker === 'up'
      ? 'WebSocket на связи'
      : sg.workerHttp === 'up'
      ? 'HTTP-поллинг на связи (обход блока WS)'
      : 'подключение…'
    : 'не настроен';
  return (
    `Канал 1 — MQTT-брокеры: ${sg.mqttUp}/${sg.mqttTotal} на связи\n` +
    `Канал 2 — Cloudflare Worker: ${wText}\n` +
    `Канал 3 — Nostr-реле (порт 443): ${sg.nostrUp || 0}/${sg.nostrTotal || 0} на связи\n` +
    `TURN-ретранслятор: ${
      S.hasTurn ? 'есть (эфемерный, из Worker)' : S.turnLoaded ? 'недоступен — работаем без него' : 'не запрашивался (ленивый режим)'
    } (${S.turnInfo || '—'})\n` +
    `Маршрут звонка: ${S.bridgeActive ? 'Зашифрованный Мост через Сигналинг (без TURN)' : S.method || '—'}\n` +
    `Мост: ${S.bridgeActive ? (S.bridgeMode === 'webcodecs' ? '2.0 WebCodecs Opus' : '1.0 MediaRecorder') : 'выключен'} · WebCodecs в этом браузере: ${webCodecsBridgeSupported() ? 'есть' : 'нет'}`
  );
}

setInterval(() => {
  if (!S.callStart) return;
  const sec = Math.floor((Date.now() - S.callStart) / 1000);
  const txt = `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`;
  if ($('#timerText')) $('#timerText').textContent = txt;
}, 1000);

function startStats(now) {
  if (S.statsTimer) return;
  const tick = async () => {
    const pc = S.pc;
    if (!pc) return;
    const r = await pc.getStats().catch(() => null);
    if (!r) return;
    let pairId,
      pair,
      lost = 0,
      recv = 0,
      bytes = 0,
      audioBytes = 0,
      outLoss = 0;
    r.forEach((x) => {
      if (x.type === 'transport' && x.selectedCandidatePairId) pairId = x.selectedCandidatePairId;
    });
    r.forEach((x) => {
      if (
        x.type === 'candidate-pair' &&
        (x.id === pairId || (!pairId && (x.selected || (x.nominated && x.state === 'succeeded'))))
      )
        pair = x;
      if (x.type === 'inbound-rtp') {
        lost += x.packetsLost || 0;
        recv += x.packetsReceived || 0;
        bytes += x.bytesReceived || 0;
        if ((x.kind || x.mediaType) === 'audio') audioBytes += x.bytesReceived || 0;
      }
      if (x.type === 'remote-inbound-rtp' && x.kind === 'video' && typeof x.fractionLost === 'number')
        outLoss = Math.max(outLoss, x.fractionLost * 100);
    });
    const curNow = Date.now(),
      p = S.prevStats;
    S.prevStats = { lost, recv, bytes, now: curNow };
    if (!pair) return;
    const lc = r.get(pair.localCandidateId),
      rc = r.get(pair.remoteCandidateId);
    const relay = lc?.candidateType === 'relay' || rc?.candidateType === 'relay';
    const route = relay
      ? 'через TURN'
      : lc?.candidateType === 'host' && rc?.candidateType === 'host'
      ? 'напрямую (LAN)'
      : 'напрямую P2P';
    const proto =
      (lc?.protocol || '').toUpperCase() +
      (lc?.relayProtocol ? '/' + lc.relayProtocol.toUpperCase() : '');
    const method = `${route}, ${proto}`;
    if (method !== S.method) {
      S.method = method;
      log('Маршрут медиа: ' + method);
      if (!S.pcRouteCounted) {
        S.pcRouteCounted = true;
        countRoute(relay ? 'relay' : 'direct');
      }
    }
    progress(100, 'Соединено: ' + route);
    const rtt = Math.round((pair.currentRoundTripTime || 0) * 1000);
    let loss = 0,
      kbps = 0;
    if (p && curNow > p.now) {
      const dl = lost - p.lost,
        dr = recv - p.recv;
      loss = dl + dr > 0 ? (100 * dl) / (dl + dr) : 0;
      kbps = ((bytes - p.bytes) * 8) / (curNow - p.now);
    }
    // «Тихая смерть» звука в долгих звонках: соединение живо, а входящие
    // аудиобайты встали (уснул AudioContext / отвалился remote-трек).
    // DTX теперь выключен, поэтому даже в тишине пакеты идут — полная
    // остановка на ~10 секунд это аномалия, пробуем оживить тракт сами.
    if (S.callStart && Date.now() - S.callStart > 45000 && audioBytes > 0) {
      if (S.lastAudioBytes >= 0 && audioBytes === S.lastAudioBytes) S.audioStallN++;
      else S.audioStallN = 0;
      S.lastAudioBytes = audioBytes;
      if (S.audioStallN >= 5) {
        S.audioStallN = 0;
        recoverRemoteAudio('нет входящих аудиобайт ~10 с при живом звонке');
      }
    }
    const lvl = rtt < 200 && loss < 2 ? 'good' : rtt < 450 && loss < 7 ? 'mid' : 'bad';
    adaptQuality(outLoss, rtt);
    const q = $('#quality');
    q.classList.remove('good', 'mid', 'bad');
    q.classList.add(lvl, 'mono-pill');
    if ($('#qualityText')) {
      $('#qualityText').textContent = `${relay ? 'TURN' : 'P2P'} · ${rtt} мс · ${loss.toFixed(1)}% · ${
        kbps > 100 ? (kbps / 1000).toFixed(1) + ' Мбит/с' : Math.round(kbps) + ' Кбит/с'
      }`;
    }
    setUse('#quality use', lvl === 'bad' ? 'i-warning' : 'i-wifi');
    q.classList.remove('hidden');
    updateStatus();
  };
  S.statsTimer = setInterval(tick, 2000);
  if (now) setTimeout(tick, 300);
}

const QLEVELS = [
  { maxBitrate: 2500000, scale: 1, fps: 30 }, // Full HD по умолчанию
  { maxBitrate: 1200000, scale: 1.5, fps: 30 },
  { maxBitrate: 600000, scale: 2, fps: 24 },
  { maxBitrate: 250000, scale: 3, fps: 15 },
  { maxBitrate: 120000, scale: 4, fps: 10 },
];
async function applyQuality() {
  if (!S.pc) return;
  const L = QLEVELS[S.qLevel || 0];
  const audioBps = (S.audio.bitrate || 48) * 1000;
  for (const snd of S.pc.getSenders()) {
    if (!snd.track) continue;
    const p = snd.getParameters();
    if (!p.encodings || !p.encodings.length) p.encodings = [{}];
    if (snd.track.kind === 'audio') {
      p.encodings[0].priority = 'high';
      p.encodings[0].networkPriority = 'high';
      // Не упираем звук в потолок, пока ручная настройка Opus выключена.
      if (S.audio.opusTune) p.encodings[0].maxBitrate = audioBps;
      else delete p.encodings[0].maxBitrate;
    } else {
      p.encodings[0].maxBitrate = L.maxBitrate;
      p.encodings[0].scaleResolutionDownBy = L.scale;
      p.encodings[0].maxFramerate = L.fps;
    }
    try {
      await snd.setParameters(p);
    } catch {}
  }
}
function adaptQuality(outLoss, rtt) {
  S.qLevel ??= 0;
  S.qBad ??= 0;
  S.qGood ??= 0;
  if (outLoss > 6 || rtt > 700) {
    S.qBad++;
    S.qGood = 0;
  } else if (outLoss < 2 && rtt < 350) {
    S.qGood++;
    S.qBad = 0;
  }
  if (S.qBad >= 2 && S.qLevel < QLEVELS.length - 1) {
    S.qLevel++;
    S.qBad = 0;
    log(`Адаптация под сеть: снижаем видео (уровень ${S.qLevel})`);
    applyQuality();
  }
  if (S.qGood >= 8 && S.qLevel > 0) {
    S.qLevel--;
    S.qGood = 0;
    log(`Сеть стабильна: повышаем видео (уровень ${S.qLevel})`);
    applyQuality();
  }
  if (S.qLevel === QLEVELS.length - 1 && S.qBad >= 3 && !S.qHinted) {
    S.qHinted = true;
    toast('Слабая сеть — выключите камеру для идеального звука', 6500);
  }
}

async function showSafety() {
  const pc = S.pc;
  const a = pc?.currentLocalDescription?.sdp,
    b = pc?.currentRemoteDescription?.sdp;
  if (!a || !b) return;
  S.safety = await safetyCode(a, b);
  const el = $('#safety');
  const pill = $('#safetyPill');
  if (pill) pill.textContent = S.safety.emoji;
  el.classList.remove('hidden');
}

async function showBridgeSafety() {
  if (!S.room || !S.peer) return;
  S.safety = await safetyCodeBridge(S.room.topic, selfId, S.peer.id);
  const el = $('#safety');
  const pill = $('#safetyPill');
  if (pill) pill.textContent = S.safety.emoji;
  el.classList.remove('hidden');
}

$('#safety').onclick = () => {
  if (!S.safety) return;
  const b = openModal('#tplSafety');
  $('#safetyEmoji', b).textContent = S.safety.emoji;
  $('#safetyDigits', b).textContent = S.safety.digits;
};

// ---------- Чат (DataChannel + автоматический фоллбэк через Сигналинг) и Файлы ----------
function sendCtrl(o) {
  if (S.ctrl?.readyState === 'open') S.ctrl.send(JSON.stringify(o));
}
function onIncomingChat(text, nameOverride) {
  addMsg(nameOverride || S.peer?.name || 'Собеседник', String(text).slice(0, 5000), false);
  if ($('#chat').classList.contains('hidden')) {
    S.unread++;
    $('#unread').textContent = S.unread;
    $('#unread').classList.remove('hidden');
    beep();
  }
}
function onCtrl(raw) {
  let m;
  try {
    m = JSON.parse(raw);
  } catch {
    return;
  }
  if (m.t === 'chat' && typeof m.text === 'string') {
    onIncomingChat(m.text);
  } else if (m.t === 'state') {
    if (S.peer) {
      S.peer.cam = !!m.cam;
      S.peer.mic = !!m.mic;
      if (m.name) setPeerName(String(m.name).slice(0, 40));
    }
    updateRemoteView();
    updateStatus();
  }
}
function hideChatEmpty() {
  ($('#callChatEmpty') || $('#call #chatEmpty'))?.remove();
}
function addMsg(who, text, me) {
  hideChatEmpty();
  const d = document.createElement('div');
  d.className = 'm' + (me ? ' me' : '');
  const w = document.createElement('div');
  w.className = 'who';
  w.textContent = who;
  const t = document.createElement('div');
  t.textContent = text;
  d.append(w, t);
  $('#msgs').append(d);
  $('#msgs').scrollTop = 1e9;
  return d;
}
function sysMsg(text) {
  hideChatEmpty();
  const d = document.createElement('div');
  d.className = 'm sys';
  d.textContent = text;
  $('#msgs').append(d);
  $('#msgs').scrollTop = 1e9;
}
$('#chatForm').onsubmit = (e) => {
  e.preventDefault();
  const inp = $('#callChatInput') || $('#call #chatInput');
  const v = (inp?.value || '').trim();
  if (!v) return;
  if (rosterCount() > 1 && S.sig) {
    // Групповой чат: одно сообщение всем участникам через E2EE-сигналинг.
    S.sig.send({ type: 'g_chat', text: v, name: myName() });
    addMsg('Вы', v, true);
    if (inp) inp.value = '';
    return;
  }
  if (S.ctrl?.readyState === 'open') {
    sendCtrl({ t: 'chat', text: v });
  } else if (S.peer && S.sig) {
    // Если DataChannel ещё не открыт или заблокирован — отправляем сообщение через E2EE сигналинг!
    S.sig.send({ type: 'sig_chat', to: S.peer.id, toInst: S.peer.inst, text: v });
  } else {
    return toast('Собеседник ещё не вошёл в комнату');
  }
  addMsg('Вы', v, true);
  if (inp) inp.value = '';
};

$('#fileInput').onchange = (e) => {
  if (S.fileCh?.readyState !== 'open') {
    toast('Передача крупных файлов требует прямого P2P-соединения');
    e.target.value = '';
    return;
  }
  for (const f of e.target.files) {
    if (f.size > MAX_FILE_BYTES) {
      toast(`Файл больше ${fmtSize(MAX_FILE_BYTES)} — передача отменена`);
      continue;
    }
    S.sendQueue.push(f);
  }
  e.target.value = '';
  pumpFiles();
};
function fileBubble(who, name, size, me) {
  const d = addMsg(who, '', me);
  const row = document.createElement('div');
  row.className = 'file-row';
  const ic = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  ic.setAttribute('class', 'ic');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '#i-attach');
  ic.append(use);
  const label = document.createElement('span');
  label.textContent = `${name} · ${fmtSize(size)}`;
  row.append(ic, label);
  d.lastElementChild?.append(row);
  const p = document.createElement('div');
  p.className = 'prog';
  p.append(document.createElement('i'));
  d.append(p);
  return d;
}
const setProg = (el, v) => {
  el.querySelector('.prog i').style.width = Math.min(100, v * 100) + '%';
};
async function pumpFiles() {
  if (S.sending) return;
  S.sending = true;
  while (S.sendQueue.length) {
    const f = S.sendQueue.shift(),
      ch = S.fileCh;
    if (!ch || ch.readyState !== 'open') break;
    const el = fileBubble('Вы', f.name, f.size, true);
    const CH = Math.min(64 * 1024, S.pc.sctp?.maxMessageSize || 16384);
    ch.send(JSON.stringify({ t: 'start', name: f.name, size: f.size, mime: f.type }));
    try {
      for (let o = 0; o < f.size; o += CH) {
        if (ch.bufferedAmount > 4 << 20)
          await new Promise((r) => ch.addEventListener('bufferedamountlow', r, { once: true }));
        if (ch.readyState !== 'open') throw new Error('closed');
        ch.send(await f.slice(o, o + CH).arrayBuffer());
        setProg(el, (o + CH) / f.size);
      }
      ch.send(JSON.stringify({ t: 'end' }));
      setProg(el, 1);
    } catch {
      el.querySelector('.who').textContent = 'Отправка прервана';
    }
  }
  S.sending = false;
}
function onFileData(d) {
  if (typeof d === 'string') {
    let m;
    try {
      m = JSON.parse(d);
    } catch {
      return;
    }
    if (m.t === 'start') {
      const name = String(m.name || 'file').slice(0, 200),
        size = Number(m.size) || 0;
      if (size > MAX_FILE_BYTES) {
        S.incomingFile = null;
        sysMsg(`Собеседник пытался отправить файл больше ${fmtSize(MAX_FILE_BYTES)}`);
        return;
      }
      S.incomingFile = {
        name,
        size,
        mime: String(m.mime || ''),
        parts: [],
        got: 0,
        el: fileBubble(S.peer?.name || 'Собеседник', name, size, false),
      };
    } else if (m.t === 'end' && S.incomingFile) {
      const f = S.incomingFile;
      S.incomingFile = null;
      if (f.got !== f.size) {
        f.el.querySelector('.who').textContent = 'Передача прервана';
        return;
      }
      setProg(f.el, 1);
      const url = URL.createObjectURL(new Blob(f.parts, { type: f.mime || 'application/octet-stream' }));
      const a = document.createElement('a');
      a.className = 'dl';
      a.href = url;
      a.download = f.name;
      a.innerHTML = '<svg class="ic"><use href="#i-download"></use></svg><span>Скачать</span>';
      a.addEventListener('click', () => setTimeout(() => URL.revokeObjectURL(url), 120000), { once: true });
      f.el.append(a);
      if ($('#chat').classList.contains('hidden')) {
        S.unread++;
        $('#unread').textContent = S.unread;
        $('#unread').classList.remove('hidden');
        beep();
      }
    }
  } else if (S.incomingFile) {
    if (S.incomingFile.got + d.byteLength > S.incomingFile.size + 1024) {
      S.incomingFile.el.querySelector('.who').textContent = 'Передача прервана';
      S.incomingFile = null;
      return;
    }
    S.incomingFile.parts.push(d);
    S.incomingFile.got += d.byteLength;
    setProg(S.incomingFile.el, S.incomingFile.got / (S.incomingFile.size || 1));
  }
}

// ---------- Кнопки звонка и Панель настроек Discord ----------
$('#cMic').onclick = toggleMic;
$('#cDeaf').onclick = toggleDeafen;
$('#cCam').onclick = toggleCam;
$('#cScreen').onclick = toggleScreen;
$('#cChat').onclick = () => {
  $('#chat').classList.toggle('hidden');
  syncChatOpen();
  S.unread = 0;
  $('#unread').classList.add('hidden');
  if (!$('#chat').classList.contains('hidden')) ($('#callChatInput') || $('#call #chatInput'))?.focus();
};
$('#cInvite').onclick = () => {
  const b = openModal('#tplInvite');
  $('#iLink', b).value = roomLink();
  renderQr($('#iQr', b), roomLink());
  $('#iCopy', b).onclick = () => copy(roomLink());
};

// Быстрый всплывающий аудио-микшер в звонке
$('#btnQuickAudio').onclick = () => {
  const pop = $('#quickAudioPop');
  pop.classList.toggle('hidden');
  $('#qaBoost').checked = S.audio.comp;
  $('#qaBridgeMode').checked = S.audio.netMode === 'bridge' || S.bridgeActive;
  syncAudioParams();
};
$('#qaPeerVol').oninput = (e) => {
  S.audio.peerVol = Number(e.target.value);
  if (S.deafened && S.audio.peerVol > 0) S.deafened = false;
  syncAudioParams();
  syncButtons();
};
$('#qaMicVol').oninput = (e) => {
  S.audio.micVol = Number(e.target.value);
  syncAudioParams();
};
$('#qaBoost').onchange = (e) => {
  S.audio.comp = e.target.checked;
  syncAudioParams();
};
$('#qaBridgeMode').onchange = (e) => {
  if (e.target.checked) {
    S.audio.netMode = 'bridge';
    syncAudioParams();
    if (S.peer) activateBridge('Включён принудительный мост без TURN');
  } else {
    S.audio.netMode = 'auto';
    syncAudioParams();
    if (S.pc?.connectionState === 'connected') stopBridge();
  }
};
$('#qaMoreSettings').onclick = () => {
  $('#quickAudioPop').classList.add('hidden');
  openSettingsModal();
};

async function openSettingsModal() {
  const b = openModal('#tplSettings');
  await fillDevices('s');
  $('#sSpkWrap', b).classList.toggle('hidden', !('setSinkId' in HTMLMediaElement.prototype));

  $('#sMic', b).onchange = (e) => switchDevice('mic', e.target.value);
  $('#sCam', b).onchange = (e) => switchDevice('cam', e.target.value);
  $('#sSpk', b).onchange = (e) => {
    S.dev.spk = localStorage.zvSpk = e.target.value;
    $('#remote').setSinkId?.(e.target.value).catch(() => {});
    $('#remoteAudioOut')?.setSinkId?.(e.target.value).catch(() => {});
    attachRemoteToEngine();
  };

  // Громкость микрофона и собеседника (0-200%)
  const sMicVol = $('#sMicVol', b),
    sMicVolTxt = $('#sMicVolTxt', b);
  sMicVol.value = S.audio.micVol;
  sMicVolTxt.textContent = S.audio.micVol + '%';
  sMicVol.oninput = () => {
    S.audio.micVol = Number(sMicVol.value);
    sMicVolTxt.textContent = S.audio.micVol + '%';
    syncAudioParams();
  };

  const sPeerVol = $('#sPeerVol', b),
    sPeerVolTxt = $('#sPeerVolTxt', b);
  sPeerVol.value = S.audio.peerVol;
  sPeerVolTxt.textContent = S.audio.peerVol + '%';
  sPeerVol.oninput = () => {
    S.audio.peerVol = Number(sPeerVol.value);
    sPeerVolTxt.textContent = S.audio.peerVol + '%';
    syncAudioParams();
  };

  // Режим ввода (VAD vs PTT)
  const rOpen = $('#sModeOpen', b),
    rVad = $('#sModeVad', b),
    rPtt = $('#sModePtt', b),
    vadWrap = $('#sVadControls', b);
  if (rOpen) rOpen.checked = S.audio.inputMode === 'open';
  rVad.checked = S.audio.inputMode === 'vad';
  rPtt.checked = S.audio.inputMode === 'ptt';
  vadWrap.classList.toggle('hidden', S.audio.inputMode !== 'vad');
  const onModeChange = () => {
    S.audio.inputMode = rPtt.checked ? 'ptt' : rVad.checked ? 'vad' : 'open';
    vadWrap.classList.toggle('hidden', S.audio.inputMode !== 'vad');
    syncAudioParams();
  };
  if (rOpen) rOpen.onchange = onModeChange;
  rVad.onchange = onModeChange;
  rPtt.onchange = onModeChange;

  // Порог чувствительности голоса (VAD Gate)
  const sVadGate = $('#sVadGate', b),
    sVadGateTxt = $('#sVadGateTxt', b);
  sVadGate.value = S.audio.vadGate;
  sVadGateTxt.textContent = S.audio.vadGate + ' дБ';
  sVadGate.oninput = () => {
    S.audio.vadGate = Number(sVadGate.value);
    sVadGateTxt.textContent = S.audio.vadGate + ' дБ';
    syncAudioParams();
  };

  // Кнопка проверки микрофона
  const testBtn = $('#sTestMic', b);
  testBtn.onclick = () => toggleMicTest(testBtn);

  // Обработка звука
  const sNoise = $('#sNoise', b),
    sEcho = $('#sEcho', b),
    sAgc = $('#sAgc', b),
    sComp = $('#sComp', b);
  sNoise.checked = S.audio.noise;
  sEcho.checked = S.audio.echo;
  sAgc.checked = S.audio.agc;
  sComp.checked = S.audio.comp;

  const rebuildMicConstraints = async () => {
    S.audio.noise = sNoise.checked;
    S.audio.echo = sEcho.checked;
    S.audio.agc = sAgc.checked;
    syncAudioParams();
    if (S.rawAudioTrack) {
      try {
        await S.rawAudioTrack.applyConstraints(audioC());
      } catch {
        await switchDevice('mic', S.dev.mic);
      }
    }
  };
  sNoise.onchange = rebuildMicConstraints;
  sEcho.onchange = rebuildMicConstraints;
  sAgc.onchange = rebuildMicConstraints;
  sComp.onchange = () => {
    S.audio.comp = sComp.checked;
    syncAudioParams();
  };

  // Ручная настройка Opus: по умолчанию выключена, битрейт недоступен
  const sBitrate = $('#sBitrate', b);
  const sOpusTune = $('#sOpusTune', b);
  sBitrate.value = String(S.audio.bitrate);
  const paintOpus = () => {
    sBitrate.disabled = !S.audio.opusTune;
    sBitrate.closest('label')?.classList.toggle('disabled', !S.audio.opusTune);
  };
  if (sOpusTune) {
    sOpusTune.checked = S.audio.opusTune;
    sOpusTune.onchange = () => {
      S.audio.opusTune = sOpusTune.checked;
      paintOpus();
      syncAudioParams();
      applyQuality();
      toast(
        S.audio.opusTune
          ? 'Ручной Opus применится полностью при следующем подключении'
          : 'Opus — авто: SDP больше не переписываем'
      );
    };
  }
  paintOpus();
  sBitrate.onchange = () => {
    S.audio.bitrate = Number(sBitrate.value);
    syncAudioParams();
    applyQuality();
  };

  // Режим сети и обхода блокировок
  const sNetMode = $('#sNetMode', b);
  sNetMode.value = S.audio.netMode;
  sNetMode.onchange = async () => {
    S.audio.netMode = sNetMode.value;
    syncAudioParams();
    if (S.audio.netMode === 'bridge') {
      if (S.peer) activateBridge('Включён режим моста без TURN');
    } else if (S.audio.netMode === 'relay') {
      // «Только TURN» — единственный случай, когда TURN грузится немедленно.
      const ok = await ensureTurnLoaded('режим «только TURN» включён вручную');
      if (!ok) toast('TURN недоступен: в Worker не настроены TURN-креды. Работаем через direct + мост');
      else if (S.pc) {
        try {
          S.pc.setConfiguration(pcConfig());
          restartIce();
        } catch {}
      }
    } else {
      if (S.pc?.connectionState === 'connected') stopBridge();
      if (S.pc) {
        try {
          S.pc.setConfiguration(pcConfig());
          restartIce();
        } catch {}
      }
    }
  };

  // v28 (G): «Свой сервер» — адрес собственного Worker. Применяется всеми
  // модулями через getWorkerBase(): новые подключения сразу, слушатель
  // входящих перезапускается; идущий звонок сервер не меняет.
  const sWorkerUrl = $('#sWorkerUrl', b);
  const sWorkerState = $('#sWorkerState', b);
  const renderWorkerState = () => {
    if (sWorkerState) {
      sWorkerState.textContent =
        'Сейчас используется: ' +
        getWorkerBase() +
        (getWorkerBase() === DEFAULT_WORKER_URL ? ' (сервер по умолчанию)' : ' (свой сервер)');
    }
  };
  const restartInboxForWorkerChange = () => {
    try {
      S.inboxListener?.close?.();
    } catch {}
    try {
      S.inboxDialListener?.close?.();
    } catch {}
    S.inboxListener = null;
    S.inboxDialListener = null;
    S.chatDialTopic = null;
    startInboxListener();
  };
  if (sWorkerUrl) {
    try {
      sWorkerUrl.value = localStorage.getItem('zvWorkerUrl') || '';
    } catch {
      sWorkerUrl.value = '';
    }
    sWorkerUrl.placeholder = DEFAULT_WORKER_URL;
    renderWorkerState();
    $('#sWorkerApply', b).onclick = () => {
      const raw = sWorkerUrl.value.trim();
      if (raw && !normalizeWorkerUrl(raw)) {
        toast('Адрес сервера не принят: нужен https://… без пути к конкретному разделу');
        return;
      }
      const applied = setWorkerBase(raw || null);
      sWorkerUrl.value = raw ? applied : '';
      renderWorkerState();
      restartInboxForWorkerChange();
      toast(
        raw
          ? 'Свой сервер сохранён: ' + applied
          : 'Используется сервер по умолчанию'
      );
    };
    $('#sWorkerReset', b).onclick = () => {
      setWorkerBase(null);
      sWorkerUrl.value = '';
      renderWorkerState();
      restartInboxForWorkerChange();
      toast('Сервер сброшен на значение по умолчанию');
    };
  }

  $('#sDiag', b).onclick = openDiag;
  syncAudioParams();
  updateStatus();
}
$('#cSettings').onclick = openSettingsModal;
$('#btnHomeSettings') && ($('#btnHomeSettings').onclick = openSettingsModal);

$('#unmuteHint').onclick = () => {
  ensureAudioEngine();
  $('#remote').play().catch(() => {});
  $('#remoteAudioOut')?.play().catch(() => {});
  $('#unmuteHint').classList.add('hidden');
};
$('#cHang').onclick = hangup;

async function hangup() {
  try {
    S.sig?.send({ type: 'bye' });
    S.sig?.sendByeBeacon();
  } catch {}
  // Даём очереди отправки шанс доставить bye до закрытия сокета.
  await new Promise((r) => setTimeout(r, 200));
  S.leaving = true;
  resetPC(false);
  S.sig?.close();
  S.sig = null;
  S.peer = null;
  S.joined = false;
  clearInterval(S.helloTimer);
  clearInterval(S.iceRefreshTimer);
  S.log = [];
  S.via = {};
  if (S.screenTrack) {
    S.screenTrack.onended = null;
    S.screenTrack.stop();
    S.screenTrack = null;
  }
  stopLocal();
  try {
    S.wakeLock?.release();
  } catch {}
  $('#msgs').replaceChildren();
  $('#chat').classList.add('hidden');
  syncChatOpen();
  $('#quickAudioPop')?.classList.add('hidden');
  history.replaceState(null, '', location.pathname);
  show('home');
  $('#homeMsg').textContent = 'Звонок завершён';
  S.leaving = false;
}

window.addEventListener('pagehide', () => {
  if (S.joined) {
    S.sig?.sendByeBeacon();
    S.sig?.send({ type: 'bye' });
  }
});
document.addEventListener('visibilitychange', async () => {
  if (document.visibilityState === 'visible' && S.joined) {
    if (S.audioCtx && S.audioCtx.state !== 'running') recoverRemoteAudio('возврат на вкладку');
    try {
      S.wakeLock = await navigator.wakeLock?.request('screen');
    } catch {}
    if (S.pc && S.callStart && S.pc.connectionState !== 'connected') restartIce();
  }
});


// ---------- Коммуникатор v20: личная ссылка, дозвон с рингтоном, входящие ----------
let ringCtx = null;
let ringTimer = null;
function startRingtone() {
  stopRingtone();
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return;
    const ctx = (ringCtx = new Ctx());
    const beep = (t0, f) => {
      const o = ctx.createOscillator();
      const g = ctx.createGain();
      o.type = 'sine';
      o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, t0);
      g.gain.exponentialRampToValueAtTime(0.22, t0 + 0.03);
      g.gain.setValueAtTime(0.22, t0 + 0.36);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.42);
      o.connect(g).connect(ctx.destination);
      o.start(t0);
      o.stop(t0 + 0.45);
    };
    const cycle = () => {
      if (!ringCtx) return;
      const t = ctx.currentTime + 0.05;
      beep(t, 440);
      beep(t + 0.5, 480);
      ringTimer = setTimeout(cycle, 2300);
    };
    cycle();
  } catch {}
}
function stopRingtone() {
  clearTimeout(ringTimer);
  ringTimer = null;
  if (ringCtx) {
    ringCtx.close().catch(() => {});
    ringCtx = null;
  }
}

async function journalAdd(dir, name, outcome) {
  try {
    await kvPut('calls', `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`, {
      ts: Date.now(),
      dir,
      name: String(name || '').slice(0, 60),
      outcome,
    });
  } catch {}
}
async function renderCalls() {
  const el = $('#callsList');
  if (!el) return;
  let all = [];
  try {
    all = (await kvAll('calls')).sort((a, b) => b.value.ts - a.value.ts).slice(0, 6);
  } catch {}
  el.replaceChildren();
  if (!all.length) {
    const li = document.createElement('li');
    li.textContent = 'Пока пусто';
    el.append(li);
    return;
  }
  const names = { accepted: 'состоялся', declined: 'отклонён', missed: 'без ответа', cancelled: 'отменён', expired: 'без ответа' };
  for (const { value: v } of all) {
    const li = document.createElement('li');
    li.textContent = `${v.dir === 'in' ? 'Входящий' : 'Исходящий'} · ${v.name || 'Без имени'} · ${names[v.outcome] || v.outcome} · ${new Date(v.ts).toLocaleString()}`;
    el.append(li);
  }
}

async function refreshPersonalUI() {
  if (!$('#personalBox')) return;
  let has;
  try {
    has = await hasPersonal();
  } catch (e) {
    // v22: не молчим — владелец должен видеть, что хранилище недоступно.
    const hm = $('#homeMsg');
    if (hm) hm.textContent = 'Не удалось открыть локальное хранилище: ' + (e?.message || e);
    return;
  }
  $('#personalNone')?.classList.toggle('hidden', has);
  $('#personalMain')?.classList.toggle('hidden', !has);
  if (!has) return;
  const p = await getPersonal();
  S.personal = p;
  if (!S.personalRoom) S.personalRoom = await deriveRoom(p.secret);
  const linkEl = $('#personalLink');
  if (linkEl) linkEl.value = personalLinkOf(p);
  startInboxListener();
  loadMissed().catch(() => {});
  renderCalls();
  updatePushUI();
}

function inboxStateHandler(m) {
  if (S.incoming && m.ringId === S.incoming.ringId && m.state !== 'ringing') {
    closeIncoming();
    toast(
      m.state === 'accepted'
        ? 'Звонок принят на другом устройстве'
        : m.state === 'declined'
          ? 'Звонок отклонён на другом устройстве'
          : 'Входящий звонок завершён'
    );
  }
}

function startInboxListener() {
  if (S.inboxListener || !getWorkerBase() || !S.personal || !S.personalRoom) return;
  const p = S.personal;
  const topic = S.personalRoom.topic;
  inboxRegister(getWorkerBase(), topic, p, S.pushSub).catch(() => {});
  S.inboxListener = new InboxListener(getWorkerBase(), topic, p, {
    onRing: (m) => handleIncomingRing(m).catch(() => {}),
    onState: inboxStateHandler,
    onStatus: (st) => {
      const el = $('#personalStatus');
      if (el) {
        el.textContent =
          st === 'online'
            ? 'Вы доступны для входящих звонков по личной ссылке'
            : 'Нет связи с сервером входящих — дозвон временно недоступен';
      }
    },
  });
  S.inboxListener.connect();
  // v28: второй, аддитивный слушатель дозвонa ИЗ ЧАТА. Его topic выводится
  // из публичного masterPub владельца (chatDialTopic ниже), поэтому личная
  // ссылка в чат не публикуется; payload запечатан ECDH-ключом пары
  // «эфемерный ключ звонящего ↔ ECDH-ключ устройства из чата».
  if (!S.inboxDialListener && p.masterPub) {
    chatDialTopic(p.masterPub)
      .then((dialTopic) => {
        if (S.inboxDialListener) return;
        S.chatDialTopic = dialTopic;
        inboxRegister(getWorkerBase(), dialTopic, p, null).catch(() => {});
        S.inboxDialListener = new InboxListener(getWorkerBase(), dialTopic, p, {
          onRing: (m) => handleChatDialRing(m).catch(() => {}),
          onState: inboxStateHandler,
        });
        S.inboxDialListener.connect();
      })
      .catch(() => {});
  }
}

async function handleIncomingRing({ ringId, blob, fromFp }) {
  if (S.incoming || S.joined || !S.personalRoom) return;
  let payload = null;
  try {
    payload = await openSealed(S.personalRoom.key, blob, S.personalRoom.topic);
  } catch {}
  presentIncomingRing({ ringId, payload, fromFp, topic: S.personalRoom.topic, viaChat: false });
}

// v28: входящий дозвон из чата. blob — конверт 'ecd1.' + JSON {eph, blob}:
// внутренний blob запечатан ECDH-ключом на ECDH-публичный ключ нашего
// устройства из чата; вне чата такой ring не создать и не прочитать.
async function handleChatDialRing({ ringId, blob, fromFp }) {
  if (S.incoming || S.joined || !S.personal || !S.chatDialTopic) return;
  try {
    if (typeof blob !== 'string' || !blob.startsWith('ecd1.')) return;
    const env = JSON.parse(new TextDecoder().decode(b64u.dec(blob.slice(5))));
    const mine = await getChatDeviceEcdh();
    if (!mine?.ecdhPriv) return;
    const key = await chatDialKey(mine.ecdhPriv, b64u.dec(env.eph), S.chatDialTopic);
    const payload = await openSealed(key, env.blob, S.chatDialTopic);
    if (!payload) return;
    presentIncomingRing({ ringId, payload, fromFp, topic: S.chatDialTopic, viaChat: true });
  } catch {}
}

function presentIncomingRing({ ringId, payload, fromFp, topic, viaChat }) {
  if (S.incoming || S.joined) return;
  const name = payload?.name || 'Неизвестный';
  S.incoming = { ringId, payload, fromFp, topic };
  $('#inName').textContent = name;
  $('#inMeta').textContent = viaChat
    ? `Входящий звонок из чата · отпечаток ${String(fromFp || '').slice(0, 8)}…`
    : `Входящий звонок по личной ссылке · отпечаток ${String(fromFp || '').slice(0, 8)}…`;
  $('#inAvatar').textContent = (name.trim()[0] || '?').toUpperCase();
  $('#incomingCall')?.classList.remove('hidden');
  startRingtone();
  try {
    navigator.vibrate?.([250, 150, 250, 150, 250]);
  } catch {}
  inboxAck(getWorkerBase(), topic, ringId, S.personal).catch(() => {});
}

function closeIncoming() {
  stopRingtone();
  $('#incomingCall')?.classList.add('hidden');
  S.incoming = null;
}

$('#btnAccept') &&
  ($('#btnAccept').onclick = async () => {
    const inc = S.incoming;
    if (!inc || !S.personal) return;
    closeIncoming();
    await inboxAnswer(getWorkerBase(), inc.topic || S.personalRoom.topic, inc.ringId, 'accepted', {
      devicePub: S.personal.devicePub,
      sign: (t) => signWithDevice(t),
    }).catch(() => {});
    journalAdd('in', inc.payload?.name, 'accepted');
    S.autoJoinPending = true;
    let target = `k=${S.personal.secret}&d=${S.personal.fp}`;
    // v28: дозвон из чата несёт в запечатанном payload секрет отдельной
    // звонковой комнаты (1:1 из чата или групповой). Принявший входит именно
    // в неё, а не в личную комнату владельца — иначе чат-дозвон не сойдётся
    // с вызывающим. Обычный дозвон по личной ссылке payload без roomSecret
    // и идёт прежним путём.
    try {
      const ks = inc.payload?.roomSecret;
      if (ks && /^[A-Za-z0-9_-]{22,}$/.test(ks)) target = `k=${ks}`;
    } catch {}
    if (location.hash.slice(1) === target) preJoin();
    else location.hash = target;
  });
$('#btnDecline') &&
  ($('#btnDecline').onclick = async () => {
    const inc = S.incoming;
    if (!inc || !S.personal) return;
    closeIncoming();
    await inboxAnswer(getWorkerBase(), inc.topic || S.personalRoom.topic, inc.ringId, 'declined', {
      devicePub: S.personal.devicePub,
      sign: (t) => signWithDevice(t),
    }).catch(() => {});
    journalAdd('in', inc.payload?.name, 'declined');
  });

$('#btnCreatePersonal') &&
  ($('#btnCreatePersonal').onclick = async () => {
    try {
      await ensurePersonal(myName() || 'Владелец');
      toast('Личная ссылка создана — отправьте её тем, кто должен вам звонить');
      refreshPersonalUI().catch(() => {});
    } catch (e) {
      // v22: раньше здесь не было try/catch — любая ошибка (например,
      // заблокированная IndexedDB) умирала молча, кнопка «не работала».
      const text = 'Не удалось создать ссылку: ' + (e?.message || e);
      toast(text);
      window.__zvShowDiag?.(text + ' Пришлите этот текст разработчику.');
    }
  });
$('#btnCopyPersonal') &&
  ($('#btnCopyPersonal').onclick = () => S.personal && copy(personalLinkOf(S.personal)));
$('#btnSharePersonal') &&
  ($('#btnSharePersonal').onclick = () =>
    S.personal &&
    navigator
      .share({ title: 'ZVONochek', text: 'Моя личная ссылка для звонков:', url: personalLinkOf(S.personal) })
      .catch(() => {}));

function updatePushUI() {
  const b = $('#btnEnablePush');
  if (!b) return;
  if (!('PushManager' in window) || !CONFIG.VAPID_PUBLIC_KEY) {
    b.disabled = true;
    b.textContent = 'Уведомления недоступны на этом устройстве';
    return;
  }
  if (Notification.permission === 'denied') {
    b.disabled = true;
    b.textContent = 'Уведомления запрещены в настройках браузера';
    return;
  }
  if (S.pushSub) {
    b.disabled = true;
    b.textContent = 'Уведомления о звонках включены';
  }
}
$('#btnEnablePush') &&
  ($('#btnEnablePush').onclick = async () => {
    try {
      const perm = await Notification.requestPermission();
      if (perm !== 'granted') return toast('Разрешение на уведомления не дано');
      const reg = await navigator.serviceWorker.ready;
      let sub = await reg.pushManager.getSubscription();
      if (!sub) {
        sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: b64u.dec(CONFIG.VAPID_PUBLIC_KEY),
        });
      }
      const j = sub.toJSON();
      S.pushSub = { endpoint: j.endpoint, keys: j.keys };
      await inboxRegister(getWorkerBase(), S.personalRoom.topic, S.personal, S.pushSub);
      toast('Уведомления о звонках включены');
      updatePushUI();
    } catch (e) {
      toast('Не удалось включить уведомления: ' + e.message);
    }
  });

async function loadMissed() {
  if (!S.personal || !S.personalRoom) return;
  const r = await inboxMissed(getWorkerBase(), S.personalRoom.topic, S.personal).catch(() => null);
  const items = r?.data?.missed || [];
  S.missedIds = items.map((m) => m.ring_id);
  const box = $('#missedBox');
  const list = $('#missedList');
  if (!box || !list) return;
  box.classList.toggle('hidden', items.length === 0);
  list.replaceChildren();
  for (const m of items) {
    let name = 'Неизвестный';
    try {
      const pl = await openSealed(S.personalRoom.key, m.blob, S.personalRoom.topic);
      if (pl?.name) name = pl.name;
    } catch {}
    const li = document.createElement('li');
    li.textContent = `${name} · ${new Date(m.ts).toLocaleString()} · не ответил`;
    list.append(li);
  }
}
$('#btnMissedClear') &&
  ($('#btnMissedClear').onclick = async () => {
    if (S.missedIds?.length) {
      await inboxMissedAck(getWorkerBase(), S.personalRoom.topic, S.missedIds, S.personal).catch(() => {});
    }
    loadMissed().catch(() => {});
  });

// ---------- Исходящий дозвон владельцу личной ссылки ----------
async function startOutgoingCall() {
  if (S.outCall || !S.secret) return;
  const room = await deriveRoom(S.secret);
  let fromFp, fromDevicePub, signFn;
  if (S.personal) {
    fromFp = S.personal.fp;
    fromDevicePub = S.personal.devicePub;
    signFn = (t) => signWithDevice(t);
  } else {
    const pair = await genP256KeyPair();
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
    fromDevicePub = b64u.enc(raw);
    fromFp = await fpOfPubRaw(raw);
    signFn = (t) => signWithKey(pair.privateKey, t);
  }
  const ringId = crypto.randomUUID();
  const payload = { v: 1, ringId, fromFp, fromDevicePub, name: myName(), call: 'video', ts: Date.now() };
  const blob = await seal(room.key, payload, room.topic);
  S.outCall = { ringId, topic: room.topic, signFn, fromDevicePub, poll: null };
  $('#outgoingCall')?.classList.remove('hidden');
  const r = await inboxRing(getWorkerBase(), room.topic, { ringId, fromFp, fromDevicePub, blob }).catch(
    () => null
  );
  if (!r || (r.status !== 201 && r.status !== 200)) {
    toast('Не удалось дозвониться: сервер входящих недоступен. Можно просто подождать в комнате');
    finishOutCall('failed', true);
    return;
  }
  toast('Звоним владельцу…');
  join(); // параллельно занимаем комнату — принявший владелец войдёт сюда же
  S.outCall.poll = setInterval(pollOutCall, 2000);
}
async function pollOutCall() {
  const oc = S.outCall;
  if (!oc) return;
  const r = await inboxRingState(getWorkerBase(), oc.topic, oc.ringId).catch(() => null);
  const st = r?.data?.state;
  if (!st || st === 'ringing') return;
  if (st === 'accepted') {
    toast('Владелец принял звонок — подключаемся');
    finishOutCall('accepted', true);
  } else if (st === 'declined') {
    toast('Владелец отклонил звонок');
    journalAdd('out', 'Владелец ссылки', 'declined');
    finishOutCall('declined', true);
  } else if (st === 'expired') {
    toast('Владелец не ответил — звонок попадёт ему в пропущенные');
    journalAdd('out', 'Владелец ссылки', 'missed');
    finishOutCall('expired', true);
  } else if (st === 'cancelled') {
    finishOutCall('cancelled', true);
  }
}
function finishOutCall(reason, keepRoom = false) {
  const oc = S.outCall;
  if (!oc) return;
  clearInterval(oc.poll);
  S.outCall = null;
  $('#outgoingCall')?.classList.add('hidden');
}
$('#btnCallOwner') && ($('#btnCallOwner').onclick = startOutgoingCall);

// SW сообщает о пуше (приложение открыто) или о тапе по уведомлению:
// активный ring всё равно придёт через listen-WS при подключении слушателя —
// здесь просто будим слушателя, если главная ещё не открывалась.
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.addEventListener('message', (e) => {
    if (e.data?.type === 'incoming-ring-push') {
      refreshPersonalUI().catch(() => {});
    }
  });
}
$('#btnCancelCall') &&
  ($('#btnCancelCall').onclick = async () => {
    const oc = S.outCall;
    if (!oc) return;
    await inboxCancel(getWorkerBase(), oc.topic, oc.ringId, oc.signFn, oc.fromDevicePub).catch(() => {});
    journalAdd('out', 'Владелец ссылки', 'cancelled');
    finishOutCall('cancelled');
    hangup();
  });

// ---------- v28: публичный хук дозвона для чата ----------
// Чат не дублирует Inbox-протокол: он просит app.js (владельца дозвонa)
// зазвонить личной идентичности участника и открыть звонковую ссылку.
// payload ring несёт секрет отдельной звонковой комнаты (roomSecret), и
// принимающая сторона входит в неё (см. обработчик «Принять» выше).
const chatRings = new Map(); // ringId -> {topic, poll, onState, done}
function parseCallLink(linkOrSecret) {
  const raw = String(linkOrSecret || '').trim();
  if (!raw) return null;
  const frag = raw.includes('#') ? raw.slice(raw.indexOf('#') + 1) : raw;
  const params = new URLSearchParams(frag);
  const secret = params.get('k') || (/^[A-Za-z0-9_-]{22,}$/.test(raw) ? raw : null);
  if (!secret || !/^[A-Za-z0-9_-]{22,}$/.test(secret)) return null;
  const fp = params.get('d');
  return {
    secret,
    fp: fp && /^[a-f0-9]{32}$/.test(fp) ? fp : null,
    link: `${location.origin}${location.pathname}#k=${secret}${fp && /^[a-f0-9]{32}$/.test(fp) ? '&d=' + fp : ''}`,
  };
}
async function chatDialTopic(masterPub) {
  return 'chatdial-' + (await sha256hex(b64u.dec(masterPub)));
}
async function chatDialKey(myPriv, peerPubRaw, topic) {
  const pub = await crypto.subtle.importKey(
    'raw',
    peerPubRaw,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const bits = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, myPriv, 256);
  const base = await crypto.subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('zv-chat-dial-v1'),
      info: new TextEncoder().encode(topic),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}
async function ringPersonalFromChat(masterPub, link, opts = {}) {
  try {
    const target = parseCallLink(link);
    if (!target) return { ok: false, status: 0, error: 'неверная ссылка звонковой комнаты' };
    if (!masterPub) return { ok: false, status: 0, error: 'нет публичного ключа личности' };
    const expectedFp = await fpOfPubRaw(b64u.dec(masterPub));
    if (target.fp && target.fp !== expectedFp) {
      return { ok: false, status: 0, error: 'отпечаток ссылки не совпадает с личностью участника' };
    }
    // Адрес дозвонa из чата выводится из masterPub вызываемого, а НЕ из
    // секрета его личной ссылки: ссылка — носитель доступа, в чат она не
    // публикуется. Payload запечатан ECDH-ключом на ecdhPub устройства
    // вызываемого (чат публикует его для эпох), поэтому сервер входящих
    // payload прочитать не может.
    if (!opts.ecdhPub) return { ok: false, status: 0, error: 'у участника нет ключа обмена для дозвона' };
    const dialTopic = await chatDialTopic(masterPub);
    let fromFp, fromDevicePub;
    if (S.personal) {
      fromFp = S.personal.fp;
      fromDevicePub = S.personal.devicePub;
    } else {
      const pair = await genP256KeyPair();
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
      fromDevicePub = b64u.enc(raw);
      fromFp = await fpOfPubRaw(raw);
    }
    const ringId = crypto.randomUUID();
    const payload = {
      v: 1,
      ringId,
      fromFp,
      fromDevicePub,
      name: opts.name || myName(),
      call: 'video',
      ts: Date.now(),
      roomSecret: target.secret,
      callLink: target.link,
      callKind: opts.callKind || 'single',
    };
    const eph = await genP256KeyPair(['deriveBits'], 'ECDH');
    const dialKey = await chatDialKey(eph.privateKey, b64u.dec(opts.ecdhPub), dialTopic);
    const inner = await seal(dialKey, payload, dialTopic);
    const ephRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
    const blob =
      'ecd1.' +
      b64u.enc(
        new TextEncoder().encode(JSON.stringify({ eph: b64u.enc(ephRaw), blob: inner }))
      );
    const r = await inboxRing(getWorkerBase(), dialTopic, {
      ringId,
      fromFp,
      fromDevicePub,
      blob,
    }).catch(() => null);
    if (!r || (r.status !== 201 && r.status !== 200)) {
      return { ok: false, status: r?.status || 0, error: 'сервер входящих недоступен' };
    }
    const rec = { topic: dialTopic, onState: opts.onState, done: false, poll: null };
    chatRings.set(ringId, rec);
    const started = Date.now();
    rec.poll = setInterval(async () => {
      if (rec.done) return;
      const st = await inboxRingState(getWorkerBase(), rec.topic, ringId).catch(() => null);
      const state = st?.data?.state;
      if (state && state !== 'ringing') {
        rec.done = true;
        clearInterval(rec.poll);
        chatRings.delete(ringId);
        rec.onState?.(state, { ringId });
      } else if (Date.now() - started > 90_000) {
        rec.done = true;
        clearInterval(rec.poll);
        chatRings.delete(ringId);
        rec.onState?.('expired', { ringId });
      }
    }, 2000);
    return { ok: true, status: r.status, ringId, topic: dialTopic, state: 'ringing' };
  } catch (e) {
    return { ok: false, status: 0, error: e?.message || String(e) };
  }
}
function openCallLinkFromChat(link) {
  const target = parseCallLink(link);
  if (!target) return false;
  const hash = 'k=' + target.secret + (target.fp ? '&d=' + target.fp : '');
  if (location.hash.slice(1) === hash) {
    route();
  } else {
    location.hash = hash;
  }
  return true;
}
window.__zvDial = {
  ringPersonal: ringPersonalFromChat,
  openCallLink: openCallLinkFromChat,
};

// ---------- Групповой режим (group.js): публичный интерфейс ----------
function attachGroupAudio(track) {
  const ctx = ensureAudioEngine();
  if (!ctx || !S.remoteCompNode || !track) return null;
  try {
    const src = ctx.createMediaStreamSource(new MediaStream([track]));
    src.connect(S.remoteCompNode);
    return src;
  } catch {
    return null;
  }
}
window.ZVGroupAPI = {
  get sig() { return S.sig; },
  get local() { return S.local; },
  get selfId() { return selfId; },
  get inst() { return inst; },
  get joined() { return S.joined; },
  myName,
  log,
  toast,
  pcConfig,
  ensureTurnLoaded,
  tuneOpusSdp,
  attachGroupAudio,
  isDeafened: () => S.deafened,
  peerVol: () => S.audio.peerVol,
  registerHook: (h) => {
    S.groupHook = h;
    log('Групповой модуль подключён (mesh до ' + (MAX_REMOTE_PEERS + 1) + ' участников)');
  },
};

// v22: флаг успешной загрузки модуля для watchdog в zvdiag.js — выставляется
// только здесь, в самом конце инициализации, после всех привязок обработчиков.
window.__zvAppBooted = true;

const action = new URLSearchParams(location.search).get('action');
if (action === 'new' && !location.hash) {
  const k = newSecret();
  history.replaceState(null, '', location.pathname + '#k=' + k);
  S.secret = k;
  preJoin();
} else {
  route();
}
