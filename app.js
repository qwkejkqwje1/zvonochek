import { CONFIG } from './config.js?v=6';
import { newSecret, deriveRoom, safetyCode } from './crypto.js?v=6';
import { Signaling } from './signaling.js?v=6';

const $ = (s, r = document) => r.querySelector(s);
const randHex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
const selfId = sessionStorage.zvId || (sessionStorage.zvId = randHex(8));
const inst = randHex(6); // меняется при каждой перезагрузке страницы

const S = {
  secret: null, room: null, sig: null, pc: null, peer: null, polite: false,
  makingOffer: false, ignoreOffer: false, pendingCands: [],
  local: new MediaStream(), remote: new MediaStream(),
  micOn: true, camOn: true, screenTrack: null,
  dev: { mic: localStorage.zvMic || '', cam: localStorage.zvCam || '', spk: localStorage.zvSpk || '' },
  ice: [], hasTurn: false, relayOnly: localStorage.zvRelay === '1',
  ctrl: null, fileCh: null, sendQueue: [], sending: false, incoming: null,
  restartTimer: null, statsTimer: null, helloTimer: null, callStart: 0, prevStats: null,
  sigStatus: { mqttUp: 0, mqttTotal: 0, worker: 'off' }, unread: 0, wakeLock: null, joined: false, dead: new Set(),
  gen: 0, watchdog: null, resendTimer: null, log: [], cands: { local: {}, remote: {} }, via: {}, pct: 0, step: '', method: '', countedOk: false,
};

// ---------- утилиты UI ----------
function show(id) { ['home', 'prejoin', 'call'].forEach((s) => $('#' + s).classList.toggle('hidden', s !== id)); }
let toastT;
function toast(t, ms = 3000) { const e = $('#toast'); e.textContent = t; e.classList.remove('hidden'); clearTimeout(toastT); toastT = setTimeout(() => e.classList.add('hidden'), ms); }
function openModal(tplId) { const b = $('#modalBody'); b.replaceChildren($(tplId).content.cloneNode(true)); $('#modal').classList.remove('hidden'); return b; }
function closeModal() { $('#modal').classList.add('hidden'); }
document.addEventListener('click', (e) => {
  const c = e.target.closest('[data-close]'); if (!c) return;
  if (c.dataset.close === 'modal') closeModal(); else $('#' + c.dataset.close).classList.add('hidden');
});
$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });
const fmtSize = (b) => (b > 1e6 ? (b / 1e6).toFixed(1) + ' МБ' : Math.ceil(b / 1e3) + ' КБ');
const roomLink = () => location.origin + location.pathname + '#k=' + S.secret;
function renderQr(el, text) {
  if (typeof qrcode === 'undefined') return;
  const q = qrcode(0, 'M'); q.addData(text); q.make();
  el.innerHTML = q.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
}
async function copy(text) { try { await navigator.clipboard.writeText(text); toast('Ссылка скопирована'); } catch { toast('Не удалось скопировать'); } }
function beep() {
  try { const a = new AudioContext(); const o = a.createOscillator(); const g = a.createGain(); o.frequency.value = 880; g.gain.value = 0.05;
    o.connect(g).connect(a.destination); o.start(); o.stop(a.currentTime + 0.15); setTimeout(() => a.close(), 400); } catch {}
}

// ---------- маршрутизация ----------
function route() {
  const k = new URLSearchParams(location.hash.slice(1)).get('k');
  if (S.joined) return;
  if (k && /^[A-Za-z0-9_-]{22,}$/.test(k)) { S.secret = k; preJoin(); }
  else { S.secret = null; stopLocal(); show('home'); }
}
window.addEventListener('hashchange', route);
$('#btnCreate').onclick = () => { location.hash = 'k=' + newSecret(); };

// ---------- медиа ----------
const audioC = () => ({ deviceId: S.dev.mic ? { ideal: S.dev.mic } : undefined, echoCancellation: true, noiseSuppression: true, autoGainControl: true });
const videoC = () => ({ deviceId: S.dev.cam ? { ideal: S.dev.cam } : undefined, width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } });

function stopLocal() { S.local.getTracks().forEach((t) => { t.stop(); S.local.removeTrack(t); }); }
function localTrack(kind) { return S.local.getTracks().find((t) => t.kind === kind) || null; }

async function getTrack(kind) {
  try {
    const st = await navigator.mediaDevices.getUserMedia(kind === 'audio' ? { audio: audioC() } : { video: videoC() });
    return st.getTracks()[0];
  } catch (e) { console.warn(kind, e); return null; }
}

async function startLocal() {
  stopLocal();
  let st = null;
  try { st = await navigator.mediaDevices.getUserMedia({ audio: audioC(), video: S.camOn ? videoC() : false }); }
  catch { try { st = await navigator.mediaDevices.getUserMedia({ audio: audioC() }); toast('Камера недоступна — только звук'); } catch { toast('Нет доступа к микрофону и камере'); } }
  st?.getTracks().forEach((t) => S.local.addTrack(t));
  const a = localTrack('audio'); if (a) a.enabled = S.micOn;
  if (!localTrack('video')) S.camOn = false;
  await fillDevices();
}

async function fillDevices(prefix = 'p') {
  const list = await navigator.mediaDevices.enumerateDevices().catch(() => []);
  const fill = (sel, kind, cur) => {
    if (!sel) return;
    sel.replaceChildren(...list.filter((d) => d.kind === kind).map((d, i) => {
      const o = document.createElement('option'); o.value = d.deviceId; o.textContent = d.label || `${kind} ${i + 1}`; return o;
    }));
    if (cur) sel.value = cur;
  };
  const a = localTrack('audio')?.getSettings().deviceId, v = localTrack('video')?.getSettings().deviceId;
  if (prefix === 'p') { fill($('#pMicSel'), 'audioinput', a); fill($('#pCamSel'), 'videoinput', v); }
  else { fill($('#sMic'), 'audioinput', a); fill($('#sCam'), 'videoinput', v); fill($('#sSpk'), 'audiooutput', S.dev.spk); }
}

// Поставить трек в отправку без лишних пересогласований
async function setSendTrack(kind, track) {
  if (!S.pc) return;
  const tr = S.pc.getTransceivers().find((t) => !t.stopped && t.receiver.track?.kind === kind);
  if (tr) {
    await tr.sender.replaceTrack(track);
    if (track && (tr.direction === 'recvonly' || tr.direction === 'inactive')) tr.direction = 'sendrecv';
    try { tr.sender.setStreams?.(S.local); } catch {}
  } else if (track) S.pc.addTrack(track, S.local);
}

async function switchDevice(kind, id) {
  if (kind === 'mic') S.dev.mic = localStorage.zvMic = id; else S.dev.cam = localStorage.zvCam = id;
  const k = kind === 'mic' ? 'audio' : 'video';
  if (k === 'video' && (!S.camOn || S.screenTrack)) return;
  const old = localTrack(k);
  const t = await getTrack(k);
  if (!t) return toast('Не удалось переключить устройство');
  if (old) { old.stop(); S.local.removeTrack(old); }
  if (k === 'audio') t.enabled = S.micOn;
  S.local.addTrack(t);
  await setSendTrack(k, t);
  refreshLocalView();
}

async function toggleMic() {
  S.micOn = !S.micOn;
  let a = localTrack('audio');
  if (!a && S.micOn) { a = await getTrack('audio'); if (a) { S.local.addTrack(a); await setSendTrack('audio', a); } else S.micOn = false; }
  if (a) a.enabled = S.micOn;
  syncButtons(); sendCtrl({ t: 'state', mic: S.micOn, cam: S.camOn || !!S.screenTrack });
}

async function toggleCam() {
  S.camOn = !S.camOn;
  if (!S.screenTrack) {
    const old = localTrack('video');
    if (!S.camOn && old) { old.stop(); S.local.removeTrack(old); await setSendTrack('video', null); }
    if (S.camOn) {
      const t = await getTrack('video');
      if (t) { S.local.addTrack(t); await setSendTrack('video', t); } else { S.camOn = false; toast('Камера недоступна'); }
    }
  }
  refreshLocalView(); syncButtons(); sendCtrl({ t: 'state', mic: S.micOn, cam: S.camOn || !!S.screenTrack });
}

async function toggleScreen() {
  if (S.screenTrack) return stopScreen();
  try {
    const st = await navigator.mediaDevices.getDisplayMedia({ video: { frameRate: { ideal: 15 } }, audio: false });
    S.screenTrack = st.getVideoTracks()[0];
    S.screenTrack.contentHint = 'detail';
    S.screenTrack.onended = stopScreen;
    const cam = localTrack('video'); if (cam) { cam.stop(); S.local.removeTrack(cam); }
    await setSendTrack('video', S.screenTrack);
    $('#local').srcObject = new MediaStream([S.screenTrack]); $('#local').classList.add('screen');
    syncButtons(); sendCtrl({ t: 'state', mic: S.micOn, cam: true });
  } catch (e) { console.warn(e); }
}
async function stopScreen() {
  if (!S.screenTrack) return;
  S.screenTrack.onended = null; S.screenTrack.stop(); S.screenTrack = null;
  $('#local').classList.remove('screen');
  let t = null;
  if (S.camOn) { t = await getTrack('video'); if (t) S.local.addTrack(t); else S.camOn = false; }
  await setSendTrack('video', t);
  refreshLocalView(); syncButtons(); sendCtrl({ t: 'state', mic: S.micOn, cam: S.camOn });
}

function refreshLocalView() {
  const v = localTrack('video');
  for (const el of [$('#preview'), $('#local')]) {
    if (el.id === 'local' && S.screenTrack) continue;
    el.srcObject = v ? new MediaStream([v]) : null;
  }
  $('#previewOff').classList.toggle('hidden', !!v);
  $('#local').classList.toggle('hidden', !v && !S.screenTrack);
}
function syncButtons() {
  for (const id of ['#pMic', '#cMic']) $(id).classList.toggle('off', !S.micOn);
  for (const id of ['#pCam', '#cCam']) $(id).classList.toggle('off', !S.camOn);
  $('#cScreen').classList.toggle('on', !!S.screenTrack);
}

// ---------- экран подготовки ----------
async function preJoin() {
  show('prejoin');
  $('#name').value = localStorage.zvName || '';
  $('#link').value = roomLink();
  $('#qr').classList.add('hidden');
  $('#btnShare').classList.toggle('hidden', !navigator.share);
  if (!window.isSecureContext || !navigator.mediaDevices) { $('#preMsg').textContent = 'Нужен HTTPS-адрес для доступа к микрофону.'; return; }
  await startLocal(); refreshLocalView(); syncButtons();
}
$('#pMic').onclick = toggleMic;
$('#pCam').onclick = toggleCam;
$('#pMicSel').onchange = (e) => switchDevice('mic', e.target.value);
$('#pCamSel').onchange = (e) => switchDevice('cam', e.target.value);
$('#btnCopy').onclick = () => copy(roomLink());
$('#btnShare').onclick = () => navigator.share({ title: 'ZVONochek', text: 'Заходи в звонок:', url: roomLink() }).catch(() => {});
$('#btnQr').onclick = () => { const q = $('#qr'); q.classList.toggle('hidden'); renderQr(q, roomLink()); };
$('#btnJoin').onclick = join;

// ---------- вход в звонок ----------
async function fetchJson(url, ms = 5000) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), ms);
  try { const r = await fetch(url, { signal: ctl.signal }); return r.ok ? await r.json() : null; } finally { clearTimeout(t); }
}
const isTurn = (s) => [].concat(s?.urls || []).some((u) => /^turns?:/.test(u));
async function loadIce() {
  const servers = [{ urls: CONFIG.STUN }, ...CONFIG.EXTRA_ICE_SERVERS];
  const info = CONFIG.EXTRA_ICE_SERVERS.some(isTurn) ? ['Metered ✓'] : [];
  const jobs = [];
  if (CONFIG.WORKER_URL) jobs.push(fetchJson(CONFIG.WORKER_URL.replace(/\/$/, '') + '/turn')
    .then((j) => { const l = (j?.iceServers || []).filter(isTurn); servers.push(...l); info.push(l.length ? 'Worker ✓' : 'Worker: TURN не настроен'); })
    .catch(() => info.push('Worker недоступен')));
  const M = CONFIG.METERED;
  if (M?.domain && M?.apiKey) jobs.push(fetchJson(`https://${M.domain}/api/v1/turn/credentials?apiKey=${encodeURIComponent(M.apiKey)}`)
    .then((j) => { const l = [].concat(j || []).filter(isTurn).map((s) => ({ ...s, urls: [].concat(s.urls).filter((u) => !/:53(\?|$)/.test(u)) })); servers.push(...l); info.push(l.length ? 'Metered ✓' : 'Metered: пусто'); })
    .catch(() => info.push('Metered недоступен')));
  await Promise.all(jobs);
  S.hasTurn = servers.some(isTurn);
  S.turnInfo = info.join(', ') || 'не настроен';
  return servers;
}
const pcConfig = () => ({ iceServers: S.ice, iceTransportPolicy: S.relayOnly && S.hasTurn ? 'relay' : 'all', bundlePolicy: 'max-bundle' });

async function join() {
  $('#btnJoin').disabled = true;
  localStorage.zvName = $('#name').value.trim();
  try {
    [S.ice, S.room] = await Promise.all([loadIce(), deriveRoom(S.secret)]);
  } catch { $('#btnJoin').disabled = false; return toast('Неверная ссылка'); }
  S.joined = true;
  show('call'); refreshLocalView(); syncButtons();
  $('#cScreen').classList.toggle('hidden', !navigator.mediaDevices.getDisplayMedia);
  $('#remote').srcObject = S.remote;
  if (S.dev.spk) $('#remote').setSinkId?.(S.dev.spk).catch(() => {});
  S.sig = new Signaling({
    topic: S.room.topic, key: S.room.key, selfId, inst,
    brokers: CONFIG.MQTT_BROKERS, workerUrl: CONFIG.WORKER_URL,
    onMessage: onSignal, onStatus: (st) => { S.sigStatus = st; updateStatus(); },
  });
  S.sig.onTransportUp = () => { hello(); if (!S.peer) progress(25, 'Сеть на связи, ждём собеседника'); };
  log(`Вход в комнату. Способы сигнала: MQTT (${CONFIG.MQTT_BROKERS.length} брокера)${CONFIG.WORKER_URL ? ' + Worker' : ''}; TURN: ${S.hasTurn ? 'есть' : 'нет'} (${S.turnInfo || '—'})`);
  progress(10, 'Подключение к сети…');
  S.sig.start();
  S.joinedAt = Date.now();
  S.helloTimer = setInterval(() => {
    if (!S.pc || S.pc.connectionState !== 'connected') hello();
    if (!S.peer && !S.waitHinted && Date.now() - S.joinedAt > 25000) {
      S.waitHinted = true;
      log('Собеседник пока не найден. Если он уже по этой ссылке — пусть обновит страницу (Ctrl+F5)');
      $('#waitText').textContent = 'Собеседник пока не найден. Если он уже в звонке — попросите его обновить страницу';
    }
  }, 6000);
  try { S.wakeLock = await navigator.wakeLock?.request('screen'); } catch {}
  updateStatus();
  $('#btnJoin').disabled = false;
}
const myName = () => localStorage.zvName || 'Гость';
function hello() { S.sig?.send({ type: 'hello', name: myName() }); }

// ---------- обработка сигналинга ----------
// Надёжность:
//  • поколения попыток (gen): если за 14–20 с не соединились — обе стороны создают соединение заново;
//  • SDP отправляется вместе с уже найденными маршрутами (ждём сбор ICE до 2,5 с) + trickle;
//  • offer повторяется, если ответ потерялся;
//  • ICE restart при обрыве, затем полный перезапуск попытки.
const stats = (() => { try { return JSON.parse(localStorage.zvStats) || { tries: 0, ok: 0 }; } catch { return { tries: 0, ok: 0 }; } })();
const saveStats = () => { localStorage.zvStats = JSON.stringify(stats); };
const viaName = (v) => ({ mqtt: 'MQTT', worker: 'Worker' }[v] || v);
const to = () => ({ to: S.peer.id, toInst: S.peer.inst, gen: S.gen });

async function onSignal(m) {
  if (S.dead.has(m.inst)) return;
  S.via[m.via] = (S.via[m.via] || 0) + 1;
  switch (m.type) {
    case 'hello': case 'hi':
      if (!acceptPeer(m)) return;
      if (m.type === 'hello') S.sig.send({ type: 'hi', to: m.from, toInst: m.inst, name: myName() });
      break;
    case 'reset':
      if (acceptPeer(m) && m.gen > S.gen) { log(`Собеседник начал попытку №${m.gen + 1}`); newAttempt(m.gen); }
      break;
    case 'desc': case 'cand':
      if (!acceptPeer(m)) return;
      if (typeof m.gen === 'number' && m.gen > S.gen) { log(`Собеседник перешёл к попытке №${m.gen + 1}`); newAttempt(m.gen); }
      if (typeof m.gen === 'number' && m.gen < S.gen) return; // устаревшая попытка
      if (m.type === 'desc') await onDesc(m.desc, m.via); else await onCand(m.cand);
      break;
    case 'bye': if (S.peer?.id === m.from && S.peer.inst === m.inst) peerLeft(); break; // не «хороним» навсегда: на телефоне вкладка может вернуться
    case 'full': if (!S.peer) { toast('В комнате уже двое — звонок 1:1', 6000); log('Комната занята'); } break;
  }
}

function acceptPeer(m) {
  const p = S.peer;
  if (p && p.id === m.from && p.inst === m.inst) { p.seen = Date.now(); if (m.name && m.name !== p.name) setPeerName(m.name); return true; }
  if (p && p.id === m.from) { log('Собеседник перезагрузил страницу'); S.dead.add(p.inst); resetPC(); setPeer(m); return true; }
  if (p) {
    const alive = S.pc?.connectionState === 'connected' || Date.now() - p.seen < 30000;
    if (alive) { S.sig.send({ type: 'full', to: m.from, toInst: m.inst }); return false; }
    resetPC();
  }
  setPeer(m);
  return true;
}
function setPeer(m) {
  S.peer = { id: m.from, inst: m.inst, name: m.name || 'Собеседник', seen: Date.now() };
  S.polite = selfId < m.from;
  S.gen = 0; S.countedOk = false;
  stats.tries++; saveStats();
  setPeerName(S.peer.name);
  log(`Собеседник найден: ${S.peer.name} (сигнал пришёл через ${viaName(m.via)})`);
  progress(40, 'Собеседник найден');
  createPC();
}
function setPeerName(n) { S.peer.name = n; $('#peerAvatar').textContent = (n[0] || '?').toUpperCase(); updateStatus(); }
function newAttempt(gen) { resetPC(); S.gen = gen; createPC(); }

function createPC() {
  const pc = (S.pc = new RTCPeerConnection(pcConfig()));
  S.makingOffer = false; S.ignoreOffer = false; S.pendingCands = [];
  S.cands = { local: {}, remote: {} }; S.route = ''; S.method = '';
  log(`Попытка №${S.gen + 1}: STUN ${CONFIG.STUN.length}, TURN ${S.hasTurn ? 'есть' : 'нет'}${S.relayOnly && S.hasTurn ? ', только TURN' : ''}`);
  S.remote = new MediaStream(); $('#remote').srcObject = S.remote;
  S.ctrl = pc.createDataChannel('ctrl', { negotiated: true, id: 0 });
  S.fileCh = pc.createDataChannel('file', { negotiated: true, id: 1 });
  S.fileCh.binaryType = 'arraybuffer';
  S.fileCh.bufferedAmountLowThreshold = 1 << 20;
  S.ctrl.onopen = () => sendCtrl({ t: 'state', mic: S.micOn, cam: S.camOn || !!S.screenTrack, name: myName() });
  S.ctrl.onmessage = (e) => onCtrl(e.data);
  S.fileCh.onmessage = (e) => onFileData(e.data);
  S.fileCh.onclose = () => { if (S.incoming) { S.incoming.el.querySelector('.who').textContent = 'Передача прервана'; S.incoming = null; } };

  for (const t of S.local.getTracks()) pc.addTrack(t, S.local);
  if (S.screenTrack) pc.addTrack(S.screenTrack, S.local);

  pc.ontrack = ({ track }) => {
    S.remote.addTrack(track);
    const upd = () => updateRemoteView();
    track.onmute = upd; track.onunmute = upd; track.onended = upd; upd();
    $('#remote').play().catch((e) => { if (e.name === 'NotAllowedError') $('#unmuteHint').classList.remove('hidden'); });
  };
  pc.onnegotiationneeded = async () => {
    try { S.makingOffer = true; await pc.setLocalDescription(); }
    catch (e) { log('Ошибка offer: ' + e.message); return; }
    finally { S.makingOffer = false; }
    sendDesc(pc);
  };
  pc.onicecandidate = ({ candidate }) => {
    if (pc !== S.pc) return;
    if (!candidate) { log(`Сбор маршрутов завершён: ${candText(S.cands.local)}`); return; }
    S.cands.local[candidate.type] = (S.cands.local[candidate.type] || 0) + 1;
    S.sig.send({ type: 'cand', ...to(), cand: candidate.toJSON() });
    progressDetail();
  };
  pc.oniceconnectionstatechange = () => {
    if (pc !== S.pc) return;
    const s = pc.iceConnectionState;
    if (s === 'checking') progress(75, 'Проверка маршрутов…');
    log('ICE: ' + s);
  };
  pc.onconnectionstatechange = () => onPcState(pc);
  armWatchdog(pc, S.polite ? 20000 : 14000);
  updateStatus();
}

function armWatchdog(pc, ms) {
  clearTimeout(S.watchdog);
  S.watchdog = setTimeout(() => {
    if (pc !== S.pc || pc.connectionState === 'connected') return;
    if (!pc._extended && ['checking', 'connected'].includes(pc.iceConnectionState)) {
      pc._extended = true; log('Маршрут почти найден — жду ещё 8 с'); armWatchdog(pc, 8000); return;
    }
    const g = S.gen + 1;
    log(`Не соединились за ${ms / 1000} с — начинаю попытку №${g + 1}`);
    hintIfNeeded();
    newAttempt(g);
    S.sig.send({ type: 'reset', ...to() });
  }, ms);
}

function waitGathering(pc, ms) {
  return new Promise((res) => {
    if (pc.iceGatheringState === 'complete') return res();
    const done = () => { clearTimeout(t); pc.removeEventListener('icegatheringstatechange', chk); res(); };
    const chk = () => pc.iceGatheringState === 'complete' && done();
    const t = setTimeout(done, ms);
    pc.addEventListener('icegatheringstatechange', chk);
  });
}
const sdpCands = (sdp) => (sdp.match(/^a=candidate:.*$/gm) || []);

async function sendDesc(pc) {
  await waitGathering(pc, 2500);
  if (pc !== S.pc || !pc.localDescription) return;
  const desc = pc.localDescription.toJSON();
  S.sig.send({ type: 'desc', ...to(), desc });
  log(`Отправлен ${desc.type === 'offer' ? 'запрос (offer)' : 'ответ (answer)'} с ${sdpCands(desc.sdp).length} маршрутами`);
  progress(55, 'Обмен ключами шифрования…');
  scheduleResend(pc, desc, 1);
}
function scheduleResend(pc, desc, n) {
  clearTimeout(S.resendTimer);
  if (n > 3) return;
  S.resendTimer = setTimeout(() => {
    if (pc !== S.pc || pc.connectionState === 'connected' || pc.localDescription?.sdp !== desc.sdp) return;
    if (desc.type === 'offer' && pc.signalingState !== 'have-local-offer') return;
    log(`Нет соединения — повторяю ${desc.type} (${n})`);
    S.sig.send({ type: 'desc', ...to(), desc });
    scheduleResend(pc, desc, n + 1);
  }, desc.type === 'offer' ? 4000 : 3000);
}

async function onDesc(desc, via) {
  const pc = S.pc;
  const collision = desc.type === 'offer' && (S.makingOffer || pc.signalingState !== 'stable');
  S.ignoreOffer = !S.polite && collision;
  if (S.ignoreOffer) { log('Встречный offer — уступает собеседник'); return; }
  try {
    await pc.setRemoteDescription(desc);
    for (const line of sdpCands(desc.sdp)) { const t = / typ (\w+)/.exec(line)?.[1]; if (t) S.cands.remote[t] = (S.cands.remote[t] || 0) + 1; }
    log(`Получен ${desc.type === 'offer' ? 'запрос (offer)' : 'ответ (answer)'} через ${viaName(via)}`);
    for (const c of S.pendingCands.splice(0)) await pc.addIceCandidate(c).catch(() => {});
    if (desc.type === 'offer') { await pc.setLocalDescription(); sendDesc(pc); }
    else clearTimeout(S.resendTimer);
    progress(65, 'Ключи согласованы, ищем маршрут…');
    progressDetail();
  } catch (e) { log('Ошибка SDP: ' + e.message); }
}
async function onCand(c) {
  if (!c) return;
  const t = / typ (\w+)/.exec(c.candidate || '')?.[1];
  if (t) S.cands.remote[t] = (S.cands.remote[t] || 0) + 1;
  if (!S.pc.remoteDescription) { S.pendingCands.push(c); return; }
  try { await S.pc.addIceCandidate(c); } catch (e) { if (!S.ignoreOffer) console.warn('cand', e); }
  progressDetail();
}

function onPcState(pc) {
  if (pc !== S.pc) return;
  const s = pc.connectionState;
  log('Соединение: ' + s);
  clearTimeout(S.restartTimer);
  if (s === 'connected') {
    clearTimeout(S.watchdog);
    if (!S.callStart) { S.callStart = Date.now(); beep(); }
    if (!S.countedOk) { S.countedOk = true; stats.ok++; saveStats(); }
    showSafety();
    startStats(true);
  } else if (s === 'disconnected') {
    progress(80, 'Связь прервалась, восстанавливаем…');
    S.restartTimer = setTimeout(() => S.pc === pc && pc.connectionState !== 'connected' && restartIce(), 2500);
  } else if (s === 'failed') { progress(80, 'Перезапуск маршрутов…'); restartIce(); }
  updateStatus();
}
function restartIce() {
  if (!S.pc) return;
  log('ICE restart');
  try { S.pc.restartIce(); } catch {}
  armWatchdog(S.pc, S.polite ? 18000 : 12000); // не помог restart — полный перезапуск попытки
}
window.addEventListener('online', () => S.pc && restartIce());

function resetPC() {
  clearTimeout(S.restartTimer); clearTimeout(S.watchdog); clearTimeout(S.resendTimer);
  clearInterval(S.statsTimer); S.statsTimer = null;
  try { S.pc?.close(); } catch {}
  S.pc = null; S.ctrl = null; S.fileCh = null; S.callStart = 0; S.prevStats = null;
  S.remote.getTracks().forEach((t) => S.remote.removeTrack(t));
  $('#safety').classList.add('hidden'); $('#quality').classList.add('hidden');
  updateRemoteView();
}
function peerLeft() {
  const n = S.peer?.name || 'Собеседник';
  resetPC(); S.peer = null;
  sysMsg(`${n} вышел из звонка`); toast(`${n} вышел из звонка`); log(`${n} вышел`);
  progress(25, 'Ожидаем собеседника');
  updateStatus();
}

// ---------- прогресс и диагностика ----------
const CT = { host: 'локальных', srflx: 'внешних (STUN)', prflx: 'внешних', relay: 'через TURN' };
const candText = (o) => Object.keys(o).length ? Object.entries(o).map(([k, v]) => `${CT[k] || k} ${v}`).join(', ') : 'нет';
function log(t) {
  const line = new Date().toLocaleTimeString('ru-RU') + '  ' + t;
  S.log.push(line); if (S.log.length > 300) S.log.shift();
  const el = $('#diagLog'); if (el) { el.textContent = S.log.join('\n'); el.scrollTop = 1e9; }
}
function progress(pct, step) {
  if (S.pc?.connectionState === 'connected' && pct < 100) return;
  S.pct = pct; S.step = step;
  $('#connPct').textContent = pct + '%'; $('#connStep').textContent = step;
  $('#connBar').style.width = pct + '%';
  updateStatus();
}
function progressDetail() {
  const sg = S.sigStatus;
  const ways = [`MQTT ${sg.mqttUp}/${sg.mqttTotal}`, CONFIG.WORKER_URL ? `Worker ${sg.worker === 'up' ? '✓' : '✗'}` : null].filter(Boolean).join(' · ');
  $('#connMethod').textContent =
    `Сигнал: ${ways}\nМои маршруты: ${candText(S.cands?.local || {})}\nМаршруты собеседника: ${candText(S.cands?.remote || {})}` +
    (S.peer ? `\nПопытка №${S.gen + 1}` : '') + (S.method ? `\nСпособ: ${S.method}` : '');
}
function hintIfNeeded() {
  const l = S.cands.local, r = S.cands.remote;
  let h = '';
  if (!l.srflx && !l.relay) h = 'Ваша сеть не пускает к STUN/TURN-серверам (возможно, блокируется UDP).';
  else if (!S.hasTurn) h = 'Сети не дают соединиться напрямую. Нужен TURN-ретранслятор.';
  else if (!r.relay && !l.relay) h = 'TURN-сервер недоступен из сети.';
  if (h) { log('Подсказка: ' + h); toast(h, 6000); }
}
function diagText() {
  const pct = stats.tries ? Math.round((100 * stats.ok) / stats.tries) : 0;
  return `ZVONochek — диагностика\nБраузер: ${navigator.userAgent}\n` +
    `Успешных соединений на этом устройстве: ${stats.ok} из ${stats.tries} (${pct}%)\n` +
    transportText() + `\nМои маршруты: ${candText(S.cands?.local || {})}\nМаршруты собеседника: ${candText(S.cands?.remote || {})}\n` +
    `Сигналы получены: ${Object.entries(S.via).map(([k, v]) => `${viaName(k)} ${v}`).join(', ') || '—'}\n\nЖурнал:\n` + S.log.join('\n');
}
function openDiag() {
  const b = openModal('#tplDiag');
  const pct = stats.tries ? Math.round((100 * stats.ok) / stats.tries) : 0;
  $('#diagStats', b).textContent = `Успешных соединений на этом устройстве: ${stats.ok} из ${stats.tries} (${pct}%)\n` + transportText() +
    `\nМои маршруты: ${candText(S.cands?.local || {})}\nМаршруты собеседника: ${candText(S.cands?.remote || {})}`;
  $('#diagLog', b).textContent = S.log.join('\n');
  $('#diagCopy', b).onclick = async () => { try { await navigator.clipboard.writeText(diagText()); toast('Диагностика скопирована'); } catch { toast('Не удалось скопировать'); } };
}
$('#btnDiag').onclick = openDiag;

// ---------- статус, качество, безопасность ----------
function updateRemoteView() {
  const v = S.remote.getVideoTracks().find((t) => t.readyState === 'live' && !t.muted);
  const camState = S.peer?.cam !== false;
  $('#remoteOff').classList.toggle('hidden', !!(v && camState && S.pc?.connectionState === 'connected'));
}
function updateStatus() {
  const st = $('#status'); if (!st) return;
  const s = S.pc?.connectionState;
  const sg = S.sigStatus;
  const sigUp = sg.mqttUp > 0 || sg.worker === 'up';
  let text;
  if (!sigUp) text = '⏳ Подключение к сети…';
  else if (!S.peer) text = '🟢 Ожидаем собеседника';
  else if (s === 'connected') text = `🟢 ${S.peer.name}`;
  else text = `🔄 ${S.pct}% · ${S.step}`;
  st.textContent = text;
  $('#waitText').textContent = !S.peer ? (S.waitHinted ? 'Собеседник пока не найден. Если он уже в звонке — попросите его обновить страницу' : 'Ожидаем собеседника… Отправьте ему ссылку 🔗') : s === 'connected' ? (S.peer.name + (S.peer.cam === false ? ' — камера выключена' : '')) : `Соединяемся с ${S.peer.name}…`;
  $('#conn').classList.toggle('hidden', s === 'connected');
  progressDetail();
  $('#timer').classList.toggle('hidden', !S.callStart);
  const tr = $('#sTransports');
  if (tr) tr.textContent = transportText();
}
function transportText() {
  const sg = S.sigStatus;
  return `Способ 1 — MQTT-брокеры: ${sg.mqttUp}/${sg.mqttTotal} на связи\n` +
    `Способ 2 — Cloudflare Worker: ${CONFIG.WORKER_URL ? ({ up: 'на связи ✓', down: 'нет связи ✗', connecting: 'подключение…' }[sg.worker]) : 'не настроен'}\n` +
    `TURN-ретранслятор: ${S.hasTurn ? 'есть ✓' : 'нет (только P2P)'} (${S.turnInfo || '—'})\n` +
    `Маршрут звонка: ${S.method || '—'}`;
}
setInterval(() => {
  if (!S.callStart) return;
  const sec = Math.floor((Date.now() - S.callStart) / 1000);
  $('#timer').textContent = `${String(Math.floor(sec / 60)).padStart(2, '0')}:${String(sec % 60).padStart(2, '0')}`;
}, 1000);

function startStats(now) {
  if (S.statsTimer) return;
  const tick = async () => {
    const pc = S.pc; if (!pc) return;
    const r = await pc.getStats().catch(() => null); if (!r) return;
    let pairId, pair, lost = 0, recv = 0, bytes = 0;
    r.forEach((x) => { if (x.type === 'transport' && x.selectedCandidatePairId) pairId = x.selectedCandidatePairId; });
    r.forEach((x) => {
      if (x.type === 'candidate-pair' && (x.id === pairId || (!pairId && (x.selected || (x.nominated && x.state === 'succeeded'))))) pair = x;
      if (x.type === 'inbound-rtp') { lost += x.packetsLost || 0; recv += x.packetsReceived || 0; bytes += x.bytesReceived || 0; }
    });
    const now = Date.now(), p = S.prevStats; S.prevStats = { lost, recv, bytes, now };
    if (!pair) return;
    const lc = r.get(pair.localCandidateId), rc = r.get(pair.remoteCandidateId);
    const relay = lc?.candidateType === 'relay' || rc?.candidateType === 'relay';
    const route = relay ? 'через TURN (ретранслятор)' : lc?.candidateType === 'host' && rc?.candidateType === 'host' ? 'напрямую (локальная сеть)' : 'напрямую P2P (через STUN)';
    const proto = (lc?.protocol || '').toUpperCase() + (lc?.relayProtocol ? '/' + lc.relayProtocol.toUpperCase() : '');
    const method = `${route}, ${proto}`;
    if (method !== S.method) { S.method = method; log('Способ соединения: ' + method); }
    progress(100, 'Соединено: ' + route);
    const rtt = Math.round((pair.currentRoundTripTime || 0) * 1000);
    let loss = 0, kbps = 0;
    if (p) { const dl = lost - p.lost, dr = recv - p.recv; loss = dl + dr > 0 ? (100 * dl) / (dl + dr) : 0; kbps = ((bytes - p.bytes) * 8) / (now - p.now); }
    const lvl = rtt < 200 && loss < 2 ? 'good' : rtt < 450 && loss < 7 ? 'mid' : 'bad';
    const q = $('#quality');
    q.className = 'pill ' + lvl;
    q.textContent = `${{ good: '📶', mid: '📶', bad: '⚠️' }[lvl]} ${relay ? 'TURN' : 'P2P'} · ${rtt} мс · ${loss.toFixed(1)}% · ${(kbps / 1000).toFixed(1)} Мбит/с`;
    q.title = `Качество: ${{ good: 'хорошее', mid: 'среднее', bad: 'плохое' }[lvl]}. Маршрут: ${S.route}`;
    updateStatus();
  };
  S.statsTimer = setInterval(tick, 2000);
  if (now) setTimeout(tick, 300);
}

async function showSafety() {
  const pc = S.pc;
  const a = pc.currentLocalDescription?.sdp, b = pc.currentRemoteDescription?.sdp;
  if (!a || !b) return;
  S.safety = await safetyCode(a, b);
  const el = $('#safety'); el.textContent = '🛡️ ' + S.safety.emoji; el.classList.remove('hidden');
}
$('#safety').onclick = () => {
  if (!S.safety) return;
  const b = openModal('#tplSafety');
  $('#safetyEmoji', b).textContent = S.safety.emoji; $('#safetyDigits', b).textContent = S.safety.digits;
};

// ---------- чат и файлы ----------
function sendCtrl(o) { if (S.ctrl?.readyState === 'open') S.ctrl.send(JSON.stringify(o)); }
function onCtrl(raw) {
  let m; try { m = JSON.parse(raw); } catch { return; }
  if (m.t === 'chat' && typeof m.text === 'string') {
    addMsg(S.peer?.name || 'Собеседник', m.text.slice(0, 5000), false);
    if ($('#chat').classList.contains('hidden')) { S.unread++; $('#unread').textContent = S.unread; $('#unread').classList.remove('hidden'); beep(); }
  } else if (m.t === 'state') {
    if (S.peer) { S.peer.cam = !!m.cam; S.peer.mic = !!m.mic; if (m.name) setPeerName(String(m.name).slice(0, 40)); }
    updateRemoteView(); updateStatus();
  }
}
function addMsg(who, text, me) {
  const d = document.createElement('div'); d.className = 'm' + (me ? ' me' : '');
  const w = document.createElement('div'); w.className = 'who'; w.textContent = who;
  const t = document.createElement('div'); t.textContent = text;
  d.append(w, t); $('#msgs').append(d); $('#msgs').scrollTop = 1e9; return d;
}
function sysMsg(text) { const d = document.createElement('div'); d.className = 'm sys'; d.textContent = text; $('#msgs').append(d); }
$('#chatForm').onsubmit = (e) => {
  e.preventDefault();
  const v = $('#chatInput').value.trim(); if (!v) return;
  if (S.ctrl?.readyState !== 'open') return toast('Собеседник ещё не подключён');
  sendCtrl({ t: 'chat', text: v }); addMsg('Вы', v, true); $('#chatInput').value = '';
};
$('#fileInput').onchange = (e) => {
  if (S.fileCh?.readyState !== 'open') { toast('Собеседник ещё не подключён'); e.target.value = ''; return; }
  for (const f of e.target.files) S.sendQueue.push(f);
  e.target.value = ''; pumpFiles();
};
function fileBubble(who, name, size, me) {
  const d = addMsg(who, `📄 ${name} (${fmtSize(size)})`, me);
  const p = document.createElement('div'); p.className = 'prog'; p.append(document.createElement('i')); d.append(p);
  return d;
}
const setProg = (el, v) => { el.querySelector('.prog i').style.width = Math.min(100, v * 100) + '%'; };
async function pumpFiles() {
  if (S.sending) return; S.sending = true;
  while (S.sendQueue.length) {
    const f = S.sendQueue.shift(), ch = S.fileCh;
    if (!ch || ch.readyState !== 'open') break;
    const el = fileBubble('Вы', f.name, f.size, true);
    const CH = Math.min(64 * 1024, S.pc.sctp?.maxMessageSize || 16384);
    ch.send(JSON.stringify({ t: 'start', name: f.name, size: f.size, mime: f.type }));
    try {
      for (let o = 0; o < f.size; o += CH) {
        if (ch.bufferedAmount > 4 << 20) await new Promise((r) => ch.addEventListener('bufferedamountlow', r, { once: true }));
        if (ch.readyState !== 'open') throw new Error('closed');
        ch.send(await f.slice(o, o + CH).arrayBuffer());
        setProg(el, (o + CH) / f.size);
      }
      ch.send(JSON.stringify({ t: 'end' })); setProg(el, 1);
    } catch { el.querySelector('.who').textContent = 'Отправка прервана'; }
  }
  S.sending = false;
}
function onFileData(d) {
  if (typeof d === 'string') {
    let m; try { m = JSON.parse(d); } catch { return; }
    if (m.t === 'start') {
      const name = String(m.name || 'file').slice(0, 200), size = Number(m.size) || 0;
      S.incoming = { name, size, mime: String(m.mime || ''), parts: [], got: 0, el: fileBubble(S.peer?.name || 'Собеседник', name, size, false) };
    } else if (m.t === 'end' && S.incoming) {
      const f = S.incoming; S.incoming = null; setProg(f.el, 1);
      const url = URL.createObjectURL(new Blob(f.parts, { type: 'application/octet-stream' }));
      const a = document.createElement('a'); a.href = url; a.download = f.name; a.textContent = '⬇️ Скачать';
      f.el.append(a);
      if ($('#chat').classList.contains('hidden')) { S.unread++; $('#unread').textContent = S.unread; $('#unread').classList.remove('hidden'); }
    }
  } else if (S.incoming) {
    S.incoming.parts.push(d); S.incoming.got += d.byteLength;
    setProg(S.incoming.el, S.incoming.got / (S.incoming.size || 1));
  }
}

// ---------- кнопки звонка ----------
$('#cMic').onclick = toggleMic;
$('#cCam').onclick = toggleCam;
$('#cScreen').onclick = toggleScreen;
$('#cChat').onclick = () => { $('#chat').classList.toggle('hidden'); S.unread = 0; $('#unread').classList.add('hidden'); $('#chatInput').focus(); };
$('#cInvite').onclick = () => {
  const b = openModal('#tplInvite'); $('#iLink', b).value = roomLink(); renderQr($('#iQr', b), roomLink());
  $('#iCopy', b).onclick = () => copy(roomLink());
};
$('#cSettings').onclick = async () => {
  const b = openModal('#tplSettings');
  await fillDevices('s');
  $('#sSpkWrap', b).classList.toggle('hidden', !('setSinkId' in HTMLMediaElement.prototype));
  $('#sMic', b).onchange = (e) => switchDevice('mic', e.target.value);
  $('#sCam', b).onchange = (e) => switchDevice('cam', e.target.value);
  $('#sSpk', b).onchange = (e) => { S.dev.spk = localStorage.zvSpk = e.target.value; $('#remote').setSinkId?.(e.target.value).catch(() => {}); };
  const r = $('#sRelay', b); r.checked = S.relayOnly; r.disabled = !S.hasTurn;
  r.onchange = () => {
    S.relayOnly = r.checked; localStorage.zvRelay = r.checked ? '1' : '0';
    if (S.pc) { S.pc.setConfiguration(pcConfig()); restartIce(); }
  };
  $('#sDiag', b).onclick = openDiag;
  updateStatus();
};
$('#unmuteHint').onclick = () => { $('#remote').play().catch(() => {}); $('#unmuteHint').classList.add('hidden'); };
$('#cHang').onclick = hangup;

function hangup() {
  try { S.sig?.send({ type: 'bye' }); } catch {}
  setTimeout(() => {
    resetPC(); S.sig?.close(); S.sig = null; S.peer = null; S.joined = false;
    clearInterval(S.helloTimer); S.log = []; S.via = {};
    if (S.screenTrack) { S.screenTrack.onended = null; S.screenTrack.stop(); S.screenTrack = null; }
    stopLocal();
    try { S.wakeLock?.release(); } catch {}
    $('#msgs').replaceChildren(); $('#chat').classList.add('hidden');
    history.replaceState(null, '', location.pathname);
    show('home'); $('#homeMsg').textContent = 'Звонок завершён';
  }, 150);
}
window.addEventListener('pagehide', () => { if (S.joined) S.sig?.send({ type: 'bye' }); });
document.addEventListener('visibilitychange', async () => {
  if (document.visibilityState === 'visible' && S.joined) {
    try { S.wakeLock = await navigator.wakeLock?.request('screen'); } catch {}
    if (S.pc && S.pc.connectionState !== 'connected') restartIce();
  }
});

route();
