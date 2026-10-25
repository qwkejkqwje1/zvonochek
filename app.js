import { CONFIG } from './config.js?v=11';
import { newSecret, deriveRoom, safetyCode, safetyCodeBridge, b64u } from './crypto.js?v=11';
import { Signaling } from './signaling.js?v=11';

export const APP_VERSION = 11;
const $ = (s, r = document) => r.querySelector(s);

// Регистрация Service Worker для быстрого старта и работы PWA
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('./sw.js?v=11').catch(() => {});
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

const S = {
  secret: null,
  room: null,
  sig: null,
  pc: null,
  peer: null,
  polite: false,
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
    inputMode: localStorage.zvInputMode || 'vad', // 'vad' | 'ptt'
    vadGate: Number(localStorage.zvVadGate ?? -45), // -75 .. -15 dB
    noise: localStorage.zvNoise !== '0',
    echo: localStorage.zvEcho !== '0',
    agc: localStorage.zvAgc !== '0',
    comp: localStorage.zvComp !== '0',
    bitrate: Number(localStorage.zvBitrate || 24), // 12, 24, 48, 64 kbps
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

  // Аварийный аудио-мост через сигналинг (работа без TURN и при блокировке UDP)
  bridgeActive: false,
  bridgeAutoTimer: null,
  bridgeRecorder: null,
  bridgeRecTimer: null,
  bridgeNextPlayTime: 0,
  bridgeSpeakingUntil: 0,

  ice: [],
  hasTurn: false,
  ctrl: null,
  fileCh: null,
  sendQueue: [],
  sending: false,
  incoming: null,
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
  else $('#' + c.dataset.close)?.classList.add('hidden');
});
$('#modal').addEventListener('click', (e) => {
  if (e.target.id === 'modal') closeModal();
});

const fmtSize = (b) => (b > 1e6 ? (b / 1e6).toFixed(1) + ' МБ' : Math.ceil(b / 1e3) + ' КБ');
const roomLink = () => location.origin + location.pathname + '#k=' + S.secret;

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
  const k = new URLSearchParams(location.hash.slice(1)).get('k');
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
    location.hash = 'k=' + m[1];
  } else {
    toast('Неверный формат ссылки или ключа');
  }
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
    // Приглушаем прямой звук из <video id="remote">, чтобы громкость регулировалась через GainNode (0-200%)
    const vid = $('#remote');
    if (vid && ctx.state === 'running') {
      vid.volume = 0;
    }
  } catch (e) {
    console.warn('remote audio graph', e);
  }
}

function syncAudioParams() {
  localStorage.zvMicVol = String(S.audio.micVol);
  localStorage.zvPeerVol = String(S.audio.peerVol);
  localStorage.zvInputMode = S.audio.inputMode;
  localStorage.zvVadGate = String(S.audio.vadGate);
  localStorage.zvNoise = S.audio.noise ? '1' : '0';
  localStorage.zvEcho = S.audio.echo ? '1' : '0';
  localStorage.zvAgc = S.audio.agc ? '1' : '0';
  localStorage.zvComp = S.audio.comp ? '1' : '0';
  localStorage.zvBitrate = String(S.audio.bitrate);
  localStorage.zvNetMode = S.audio.netMode;
  localStorage.zvRelay = S.audio.netMode === 'relay' ? '1' : '0';

  if (S.hpFilter) S.hpFilter.frequency.value = S.audio.noise ? 85 : 20;
  if (S.micGainNode) S.micGainNode.gain.value = S.audio.micVol / 100;
  if (S.remoteCompNode) S.remoteCompNode.ratio.value = S.audio.comp ? 3.5 : 1;
  if (S.remoteGainNode) S.remoteGainNode.gain.value = S.deafened ? 0 : S.audio.peerVol / 100;

  const vid = $('#remote');
  if (vid) {
    if (S.audioCtx && S.audioCtx.state === 'running' && S.remoteSource) {
      vid.volume = 0;
    } else {
      vid.volume = S.deafened ? 0 : Math.min(1, S.audio.peerVol / 100);
    }
  }

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
  if ($('#preInputModeTag')) {
    $('#preInputModeTag').textContent =
      S.audio.inputMode === 'ptt' ? '📻 Рация (Нажми и говори)' : `🎙️ По голосу (${S.audio.vadGate} дБ)`;
  }
  if ($('#preCodecTag')) {
    $('#preCodecTag').textContent = `Opus ${S.audio.bitrate} kbps + FEC`;
  }
  // Показываем кнопку PTT на экране звонка, если включен режим рации или активен мост
  $('#cPtt')?.classList.toggle('hidden', S.audio.inputMode !== 'ptt' && !S.bridgeActive);
}

function startMeterLoop() {
  if (S.meterTimer) return;
  const buf = new Float32Array(256);
  const rBuf = new Uint8Array(64);
  S.meterTimer = setInterval(() => {
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
      } else if (S.audio.inputMode === 'ptt') {
        pass = S.pttPressed;
      } else {
        if (db >= S.audio.vadGate) {
          S.vadHoldUntil = now + 280; // задержка закрытия гейта 280 мс, чтобы не глотать окончания слов
        }
        pass = now < S.vadHoldUntil;
      }
      S.isSpeaking = pass;
      if (S.gateGainNode && S.audioCtx) {
        S.gateGainNode.gain.setTargetAtTime(pass ? 1 : 0, S.audioCtx.currentTime, 0.015);
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
  for (const id of ['#pTestMic', '#sTestMic']) {
    const b = $(id);
    if (b) {
      b.classList.toggle('active-test', S.testingMic);
      b.textContent = S.testingMic ? '⏹️ Стоп тест' : '🔊 Проверить микрофон';
    }
  }
  if (btnEl) {
    btnEl.classList.toggle('active-test', S.testingMic);
    btnEl.textContent = S.testingMic ? '⏹️ Стоп' : '🔊 Проверить';
  }
}
function stopMicTest() {
  if (!S.testingMic) return;
  S.testingMic = false;
  try {
    S.gateGainNode?.disconnect(S.audioCtx.destination);
  } catch {}
  for (const id of ['#pTestMic', '#sTestMic']) {
    const b = $(id);
    if (b) {
      b.classList.remove('active-test');
      b.textContent = '🔊 Проверить микрофон';
    }
  }
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
  width: { ideal: 1280 },
  height: { ideal: 720 },
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
  toast(S.deafened ? '🔇 Звук и микрофон отключены (Deafen)' : '🔊 Звук включён');
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
      video: { frameRate: { ideal: 15 } },
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
  for (const id of ['#pMic', '#cMic']) $(id)?.classList.toggle('off', !S.micOn || S.deafened);
  for (const id of ['#pCam', '#cCam']) $(id)?.classList.toggle('off', !S.camOn);
  $('#cDeaf')?.classList.toggle('off', S.deafened);
  $('#cScreen')?.classList.toggle('on', !!S.screenTrack);
}

// ---------- Управление Рацией (Push-To-Talk: кнопка + клавиша Пробел) ----------
function setPtt(active) {
  if (S.pttPressed === active) return;
  S.pttPressed = active;
  const btn = $('#cPtt');
  if (btn) {
    btn.classList.toggle('tx', active);
    btn.textContent = active ? '🟢 ПЕРЕДАЧА РЕЧИ…' : '📻 Держите для речи';
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
  const servers = [{ urls: CONFIG.STUN }, ...CONFIG.EXTRA_ICE_SERVERS];
  const info = CONFIG.EXTRA_ICE_SERVERS.some(isTurn) ? ['Встроенный TURN ✓'] : [];
  const jobs = [];
  if (CONFIG.WORKER_URL) {
    jobs.push(
      fetchJson(CONFIG.WORKER_URL.replace(/\/$/, '') + '/turn')
        .then((j) => {
          const l = (j?.iceServers || []).filter(isTurn);
          servers.push(...l);
          info.push(l.length ? 'Worker TURN ✓' : 'Worker: без TURN (только сигнал)');
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
            .map((s) => ({ ...s, urls: [].concat(s.urls).filter((u) => !/:53(\?|$)/.test(u)) }));
          servers.push(...l);
          info.push(l.length ? 'Metered ✓' : 'Metered: пусто');
        })
        .catch(() => info.push('Metered недоступен'))
    );
  }
  await Promise.all(jobs);
  S.hasTurn = servers.some(isTurn);
  S.turnInfo = info.join(', ') || 'не настроен';
  return servers;
}

const pcConfig = () => ({
  iceServers: S.ice,
  iceTransportPolicy: S.audio.netMode === 'relay' && S.hasTurn ? 'relay' : 'all',
  bundlePolicy: 'max-bundle',
  iceCandidatePoolSize: 4, // предсбор STUN-кандидатов для ускоренного рукопожатия без TURN
});

// Настройка кодека Opus в SDP (FEC против потерь пакетов + DTX для экономии батареи + выбранный битрейт)
function tuneOpusSdp(sdp) {
  if (!sdp) return sdp;
  const bps = (S.audio.bitrate || 24) * 1000;
  return sdp.replace(/a=fmtp:(\d+) (.*)/g, (full, pt, params) => {
    if (!sdp.includes(`a=rtpmap:${pt} opus/48000`)) return full;
    const clean = params
      .split(';')
      .filter((kv) => !/^(useinbandfec|usedtx|maxaveragebitrate|cbr)=/.test(kv.trim()))
      .join(';');
    return `a=fmtp:${pt} ${clean};useinbandfec=1;usedtx=1;cbr=0;maxaveragebitrate=${bps}`;
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
    workerUrl: CONFIG.WORKER_URL,
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
      CONFIG.WORKER_URL ? 'Worker (WS+HTTP), ' : ''
    }Nostr (${CONFIG.NOSTR_RELAYS.length}); TURN: ${S.hasTurn ? 'есть' : 'нет'} (${S.turnInfo || '—'})`
  );
  progress(10, 'Подключение к каналам сигналинга…');
  S.sig.start();
  S.joinedAt = Date.now();
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
function hello() {
  S.sig?.send({ type: 'hello', name: myName(), ver: APP_VERSION });
}

// ---------- Аварийный Аудио-Мост через Сигналинг (работает вообще без TURN и без UDP!) ----------
function activateBridge(reason = 'Активирован аудио-мост через сигналинг') {
  if (!S.peer || S.bridgeActive) return;
  S.bridgeActive = true;
  clearTimeout(S.bridgeAutoTimer);
  log('🛡️ ' + reason);
  toast('🛡️ Включён Мост без TURN (голос идёт через зашифрованный сигнал)', 5000);
  if (!S.callStart) {
    S.callStart = Date.now();
    beep(660, 0.16);
  }
  $('#bridgeBadge')?.classList.remove('hidden');
  $('#cPtt')?.classList.remove('hidden');
  showBridgeSafety();
  startBridgeRecorder();
  updateStatus();
}

function stopBridge() {
  clearTimeout(S.bridgeAutoTimer);
  clearInterval(S.bridgeRecTimer);
  S.bridgeRecTimer = null;
  if (S.bridgeRecorder && S.bridgeRecorder.state !== 'inactive') {
    try { S.bridgeRecorder.stop(); } catch {}
  }
  S.bridgeRecorder = null;
  S.bridgeActive = false;
  $('#bridgeBadge')?.classList.add('hidden');
  syncAudioParams();
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

function startBridgeRecorder() {
  if (typeof MediaRecorder === 'undefined') return;
  clearInterval(S.bridgeRecTimer);
  const mime = getSupportedAudioMime();

  // Каждые 680 мс записываем и отправляем голосовой фрагмент, если пользователь говорит
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
        audioBitsPerSecond: 14000, // 14 Кбит/с — компактные пакеты ~1.1 КБ для мгновенной доставки
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
        S.sig?.send({
          type: 'voice',
          to: S.peer.id,
          toInst: S.peer.inst,
          mime: blob.type,
          b64: b64u.enc(buf),
          _noZip: true,
        });
      };
      rec.start();
      setTimeout(() => {
        if (rec.state === 'recording') {
          try { rec.stop(); } catch {}
        }
      }, 640);
    } catch (e) {
      console.warn('bridge recorder', e);
    }
  };

  S.bridgeRecTimer = setInterval(recordSlice, 660);
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
const viaName = (v) =>
  ({ mqtt: 'MQTT', worker: 'Worker WS', 'worker-http': 'Worker HTTP', nostr: 'Nostr' }[v] || v);
const to = () => ({ to: S.peer.id, toInst: S.peer.inst, gen: S.gen });

async function onSignal(m) {
  if (S.dead.has(m.inst)) return;
  S.via[m.via] = (S.via[m.via] || 0) + 1;
  switch (m.type) {
    case 'hello':
    case 'hi':
      if (!acceptPeer(m)) return;
      if (m.type === 'hello') {
        S.sig.send({ type: 'hi', to: m.from, toInst: m.inst, name: myName(), ver: APP_VERSION });
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
    case 'sig_chat':
      if (acceptPeer(m) && typeof m.text === 'string') {
        onIncomingChat(m.text);
      }
      break;
    case 'bye':
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
  S.gen = 0;
  S.countedOk = false;
  stats.tries++;
  saveStats();
  setPeerName(S.peer.name);
  log(`Собеседник найден: ${S.peer.name} (канал: ${viaName(m.via)})`);
  progress(40, 'Собеседник найден, рукопожатие…');
  createPC();

  // Если выбран режим «Только Мост без TURN» — включаем голосовой мост мгновенно!
  // А в режиме «Авто» — если за 7.5 секунд прямой WebRTC не пробил NAT/файрвол, автоматически подхватываем мостом!
  clearTimeout(S.bridgeAutoTimer);
  if (S.audio.netMode === 'bridge') {
    activateBridge('Выбран режим прямого моста через сигнал (без TURN)');
  } else {
    S.bridgeAutoTimer = setTimeout(() => {
      if (S.joined && S.peer && S.pc?.connectionState !== 'connected' && !S.bridgeActive) {
        activateBridge('Прямой P2P заблокирован или нет TURN — включён авто-мост через сигнал');
      }
    }, 7500);
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
    if (S.incoming) {
      S.incoming.el.querySelector('.who').textContent = 'Передача прервана';
      S.incoming = null;
    }
  };

  for (const t of S.local.getTracks()) pc.addTrack(t, S.local);
  if (S.screenTrack) pc.addTrack(S.screenTrack, S.local);

  pc.ontrack = ({ track }) => {
    S.remote.addTrack(track);
    if (track.kind === 'audio') {
      attachRemoteToEngine();
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
    S.sig.send({ type: 'cand', ...to(), cand: candidate.toJSON() });
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
async function sendDesc(pc) {
  await waitGathering(pc, 450);
  if (pc !== S.pc || !pc.localDescription) return;
  const desc = {
    type: pc.localDescription.type,
    sdp: tuneOpusSdp(pc.localDescription.sdp),
  };
  S.ackReceived = false;
  S.sig.send({ type: 'desc', ...to(), desc });
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
        S.sig.send({ type: 'desc', ...to(), desc: fullDesc });
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
    S.sig.send({ type: 'desc', ...to(), desc: latestDesc });
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
    restartIce();
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
window.addEventListener('online', () => S.pc && S.callStart && restartIce());
if (navigator.connection) {
  navigator.connection.addEventListener?.('change', () => {
    if (S.pc && S.callStart) {
      log('Смена типа сети — обновляем ICE маршруты');
      restartIce();
    }
  });
}

function resetPC(keepBridge = false) {
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
  const workerTag = CONFIG.WORKER_URL
    ? `Worker ${sg.worker === 'up' ? 'WS✓' : sg.workerHttp === 'up' ? 'HTTP✓' : '✗'}`
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
  if (!sigUp) text = '⏳ Подключение к сети…';
  else if (!S.peer) text = '🟢 Ожидаем собеседника';
  else if (s === 'connected') text = `🟢 ${S.peer.name}`;
  else if (S.bridgeActive) text = `🟢 ${S.peer.name}`;
  else text = `🔄 ${S.pct}% · ${S.step}`;
  st.textContent = text;

  const isLive = s === 'connected' || S.bridgeActive;
  $('#waitText').textContent = !S.peer
    ? S.waitHinted
      ? 'Собеседник пока не найден. Если он уже в звонке — попросите его обновить страницу'
      : 'Отправьте ссылку собеседнику 🔗'
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
  const wText = CONFIG.WORKER_URL
    ? sg.worker === 'up'
      ? 'WebSocket на связи ✓'
      : sg.workerHttp === 'up'
      ? 'HTTP-поллинг на связи ✓ (обход блока WS)'
      : 'подключение…'
    : 'не настроен';
  return (
    `Канал 1 — MQTT-брокеры: ${sg.mqttUp}/${sg.mqttTotal} на связи\n` +
    `Канал 2 — Cloudflare Worker: ${wText}\n` +
    `Канал 3 — Nostr-реле (порт 443): ${sg.nostrUp || 0}/${sg.nostrTotal || 0} на связи\n` +
    `TURN-ретранслятор: ${S.hasTurn ? 'есть ✓' : 'нет (авто-мост активен)'} (${S.turnInfo || '—'})\n` +
    `Маршрут звонка: ${S.bridgeActive ? 'Зашифрованный Мост через Сигналинг (без TURN)' : S.method || '—'}`
  );
}

setInterval(() => {
  if (!S.callStart) return;
  const sec = Math.floor((Date.now() - S.callStart) / 1000);
  $('#timer').textContent = `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(
    2,
    '0'
  )}`;
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
    const lvl = rtt < 200 && loss < 2 ? 'good' : rtt < 450 && loss < 7 ? 'mid' : 'bad';
    adaptQuality(outLoss, rtt);
    const q = $('#quality');
    q.className = 'pill mono-pill ' + lvl;
    q.textContent = `${{ good: '📶', mid: '📶', bad: '⚠️' }[lvl]} ${
      relay ? 'TURN' : 'P2P'
    } · ${rtt} мс · ${loss.toFixed(1)}% · ${
      kbps > 100 ? (kbps / 1000).toFixed(1) + ' Мбит/с' : Math.round(kbps) + ' Кбит/с'
    }`;
    q.classList.remove('hidden');
    updateStatus();
  };
  S.statsTimer = setInterval(tick, 2000);
  if (now) setTimeout(tick, 300);
}

const QLEVELS = [
  { maxBitrate: 1500000, scale: 1, fps: 30 },
  { maxBitrate: 600000, scale: 1.5, fps: 24 },
  { maxBitrate: 300000, scale: 2, fps: 15 },
  { maxBitrate: 120000, scale: 4, fps: 10 },
];
async function applyQuality() {
  if (!S.pc) return;
  const L = QLEVELS[S.qLevel || 0];
  const audioBps = (S.audio.bitrate || 24) * 1000;
  for (const snd of S.pc.getSenders()) {
    if (!snd.track) continue;
    const p = snd.getParameters();
    if (!p.encodings || !p.encodings.length) p.encodings = [{}];
    if (snd.track.kind === 'audio') {
      p.encodings[0].priority = 'high';
      p.encodings[0].networkPriority = 'high';
      p.encodings[0].maxBitrate = audioBps;
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
  el.textContent = '🛡️ ' + S.safety.emoji;
  el.classList.remove('hidden');
}

async function showBridgeSafety() {
  if (!S.room || !S.peer) return;
  S.safety = await safetyCodeBridge(S.room.topic, selfId, S.peer.id);
  const el = $('#safety');
  el.textContent = '🛡️ ' + S.safety.emoji;
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
function onIncomingChat(text) {
  addMsg(S.peer?.name || 'Собеседник', String(text).slice(0, 5000), false);
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
function addMsg(who, text, me) {
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
  const d = document.createElement('div');
  d.className = 'm sys';
  d.textContent = text;
  $('#msgs').append(d);
}
$('#chatForm').onsubmit = (e) => {
  e.preventDefault();
  const v = $('#chatInput').value.trim();
  if (!v) return;
  if (S.ctrl?.readyState === 'open') {
    sendCtrl({ t: 'chat', text: v });
  } else if (S.peer && S.sig) {
    // Если DataChannel ещё не открыт или заблокирован — отправляем сообщение через E2EE сигналинг!
    S.sig.send({ type: 'sig_chat', to: S.peer.id, toInst: S.peer.inst, text: v });
  } else {
    return toast('Собеседник ещё не вошёл в комнату');
  }
  addMsg('Вы', v, true);
  $('#chatInput').value = '';
};

$('#fileInput').onchange = (e) => {
  if (S.fileCh?.readyState !== 'open') {
    toast('Передача крупных файлов требует прямого P2P-соединения');
    e.target.value = '';
    return;
  }
  for (const f of e.target.files) S.sendQueue.push(f);
  e.target.value = '';
  pumpFiles();
};
function fileBubble(who, name, size, me) {
  const d = addMsg(who, `📄 ${name} (${fmtSize(size)})`, me);
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
      S.incoming = {
        name,
        size,
        mime: String(m.mime || ''),
        parts: [],
        got: 0,
        el: fileBubble(S.peer?.name || 'Собеседник', name, size, false),
      };
    } else if (m.t === 'end' && S.incoming) {
      const f = S.incoming;
      S.incoming = null;
      setProg(f.el, 1);
      const url = URL.createObjectURL(new Blob(f.parts, { type: 'application/octet-stream' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = f.name;
      a.textContent = '⬇️ Скачать';
      f.el.append(a);
      if ($('#chat').classList.contains('hidden')) {
        S.unread++;
        $('#unread').textContent = S.unread;
        $('#unread').classList.remove('hidden');
      }
    }
  } else if (S.incoming) {
    S.incoming.parts.push(d);
    S.incoming.got += d.byteLength;
    setProg(S.incoming.el, S.incoming.got / (S.incoming.size || 1));
  }
}

// ---------- Кнопки звонка и Панель настроек Discord ----------
$('#cMic').onclick = toggleMic;
$('#cDeaf').onclick = toggleDeafen;
$('#cCam').onclick = toggleCam;
$('#cScreen').onclick = toggleScreen;
$('#cChat').onclick = () => {
  $('#chat').classList.toggle('hidden');
  S.unread = 0;
  $('#unread').classList.add('hidden');
  $('#chatInput').focus();
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
  const rVad = $('#sModeVad', b),
    rPtt = $('#sModePtt', b),
    vadWrap = $('#sVadControls', b);
  rVad.checked = S.audio.inputMode === 'vad';
  rPtt.checked = S.audio.inputMode === 'ptt';
  vadWrap.classList.toggle('hidden', S.audio.inputMode === 'ptt');
  const onModeChange = () => {
    S.audio.inputMode = rPtt.checked ? 'ptt' : 'vad';
    vadWrap.classList.toggle('hidden', S.audio.inputMode === 'ptt');
    syncAudioParams();
  };
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

  // Битрейт кодека Opus
  const sBitrate = $('#sBitrate', b);
  sBitrate.value = String(S.audio.bitrate);
  sBitrate.onchange = () => {
    S.audio.bitrate = Number(sBitrate.value);
    syncAudioParams();
    applyQuality();
  };

  // Режим сети и обхода блокировок
  const sNetMode = $('#sNetMode', b);
  sNetMode.value = S.audio.netMode;
  sNetMode.onchange = () => {
    S.audio.netMode = sNetMode.value;
    syncAudioParams();
    if (S.audio.netMode === 'bridge') {
      if (S.peer) activateBridge('Включён режим моста без TURN');
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

  $('#sDiag', b).onclick = openDiag;
  syncAudioParams();
  updateStatus();
}
$('#cSettings').onclick = openSettingsModal;

$('#unmuteHint').onclick = () => {
  ensureAudioEngine();
  $('#remote').play().catch(() => {});
  $('#remoteAudioOut')?.play().catch(() => {});
  $('#unmuteHint').classList.add('hidden');
};
$('#cHang').onclick = hangup;

function hangup() {
  try {
    S.sig?.send({ type: 'bye' });
    S.sig?.sendByeBeacon();
  } catch {}
  setTimeout(() => {
    resetPC(false);
    S.sig?.close();
    S.sig = null;
    S.peer = null;
    S.joined = false;
    clearInterval(S.helloTimer);
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
    $('#quickAudioPop')?.classList.add('hidden');
    history.replaceState(null, '', location.pathname);
    show('home');
    $('#homeMsg').textContent = 'Звонок завершён';
  }, 150);
}

window.addEventListener('pagehide', () => {
  if (S.joined) {
    S.sig?.sendByeBeacon();
    S.sig?.send({ type: 'bye' });
  }
});
document.addEventListener('visibilitychange', async () => {
  if (document.visibilityState === 'visible' && S.joined) {
    try {
      S.wakeLock = await navigator.wakeLock?.request('screen');
    } catch {}
    if (S.pc && S.callStart && S.pc.connectionState !== 'connected') restartIce();
  }
});

route();
