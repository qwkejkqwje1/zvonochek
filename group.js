// ZVONochek — групповой режим (mesh): дополнительные участники комнаты сверх
// основного собеседника. Каждый дополнительный участник = отдельное
// RTCPeerConnection (mesh), своя видеоплитка и свой аудиопоток в общий тракт.
// Групповой чат идёт через сигналинг (g_chat, обрабатывает app.js).
// Мост в группе не работает: при 3+ участниках app.js его отключает.
//
// Протокол поверх существующего сигналинга (все сообщения зашифрованы AES-GCM):
//   hello / hi  — app.js маршрутизирует сюда всё, что не от основного пира
//   g_hi        — наш ответ на чужой hello
//   g_desc      — SDP (offer/answer) групповой сессии
//   g_cand      — ICE-кандидаты групповой сессии
const API = window.ZVGroupAPI;
if (API) {
  const $ = (s, r = document) => r.querySelector(s);
  const sessions = new Map(); // inst -> session

  const tilesEl = () => $('#tiles');

  function ensureTile(sess) {
    const box = tilesEl();
    if (!box) return null;
    box.classList.remove('hidden');
    if (sess.tile) return sess.tile;
    const tile = document.createElement('div');
    tile.className = 'tile';
    const vid = document.createElement('video');
    vid.autoplay = true;
    vid.playsInline = true;
    vid.muted = true; // звук идёт через общий аудиотракт (или фолбэк ниже)
    const label = document.createElement('span');
    label.className = 'tile-name';
    label.textContent = sess.name || 'Участник';
    tile.append(vid, label);
    box.append(tile);
    sess.tile = tile;
    sess.videoEl = vid;
    return tile;
  }

  function dropTile(sess) {
    sess.tile?.remove();
    sess.tile = null;
    sess.videoEl = null;
    if (!sessions.size) tilesEl()?.classList.add('hidden');
  }

  function createSession(m) {
    const sess = {
      key: m.inst,
      id: m.from,
      inst: m.inst,
      name: m.name || 'Участник',
      pc: null,
      remote: new MediaStream(),
      polite: API.selfId < m.from,
      makingOffer: false,
      ignoreOffer: false,
      pending: [],
      tile: null,
      videoEl: null,
      audioSrc: null,
      dead: false,
    };
    sessions.set(sess.inst, sess);
    const pc = (sess.pc = new RTCPeerConnection(API.pcConfig()));
    for (const t of API.local.getTracks()) {
      try { pc.addTrack(t, API.local); } catch {}
    }
    pc.ontrack = ({ track }) => {
      sess.remote.addTrack(track);
      ensureTile(sess);
      if (track.kind === 'video' && sess.videoEl) {
        sess.videoEl.srcObject = new MediaStream(sess.remote.getVideoTracks());
      }
      if (track.kind === 'audio') {
        sess.audioSrc = API.attachGroupAudio(track);
        if (!sess.audioSrc && sess.videoEl) {
          // Фолбэк: звук прямо из плитки, если аудиотракт недоступен
          sess.videoEl.muted = false;
          sess.videoEl.volume = API.isDeafened() ? 0 : Math.min(1, API.peerVol() / 100);
          sess.videoEl.srcObject = sess.remote;
        }
      }
      API.log(`Группа: медиа от ${sess.name}`);
    };
    pc.onnegotiationneeded = async () => {
      if (sess.polite && !pc.currentRemoteDescription) return; // offer делает старшая сторона
      try {
        sess.makingOffer = true;
        const offer = await pc.createOffer();
        offer.sdp = API.tuneOpusSdp(offer.sdp);
        await pc.setLocalDescription(offer);
        sendDesc(sess);
      } catch (e) {
        API.log('Группа: ошибка offer: ' + e.message);
      } finally {
        sess.makingOffer = false;
      }
    };
    pc.onicecandidate = ({ candidate }) => {
      if (candidate) {
        API.sig?.send({ type: 'g_cand', to: sess.id, toInst: sess.inst, cand: candidate.toJSON() });
      }
    };
    pc.onconnectionstatechange = () => {
      API.log(`Группа: ${sess.name} — ${pc.connectionState}`);
      if (pc.connectionState === 'failed') {
        API.ensureTurnLoaded('групповое соединение не встало').finally(() => {
          try { pc.restartIce(); } catch {}
        });
      }
      if (pc.connectionState === 'closed') closeSession(sess);
    };
    ensureTile(sess);
    API.log(`Группа: участник ${sess.name} (mesh)`);
    return sess;
  }

  function sendDesc(sess) {
    const pc = sess.pc;
    if (!pc?.localDescription) return;
    API.sig?.send({
      type: 'g_desc',
      to: sess.id,
      toInst: sess.inst,
      desc: { type: pc.localDescription.type, sdp: API.tuneOpusSdp(pc.localDescription.sdp) },
    });
  }

  async function onDesc(sess, desc) {
    const pc = sess.pc;
    if (!pc) return;
    const collision = desc.type === 'offer' && (sess.makingOffer || pc.signalingState !== 'stable');
    sess.ignoreOffer = !sess.polite && collision;
    if (sess.ignoreOffer) return;
    try {
      await pc.setRemoteDescription(desc);
      for (const c of sess.pending.splice(0)) await pc.addIceCandidate(c).catch(() => {});
      if (desc.type === 'offer') {
        const answer = await pc.createAnswer();
        answer.sdp = API.tuneOpusSdp(answer.sdp);
        await pc.setLocalDescription(answer);
        sendDesc(sess);
      }
    } catch (e) {
      API.log('Группа: ошибка SDP: ' + e.message);
    }
  }

  function closeSession(sess) {
    if (sess.dead) return;
    sess.dead = true;
    try { sess.audioSrc?.disconnect(); } catch {}
    try { sess.pc?.close(); } catch {}
    sessions.delete(sess.inst);
    dropTile(sess);
    API.log(`Группа: ${sess.name} отключился`);
  }

  function onSignal(m) {
    if (!API.joined) return;
    switch (m.type) {
      case 'hello':
      case 'hi':
      case 'g_hi': {
        let sess = sessions.get(m.inst);
        if (!sess) sess = createSession(m);
        else if (m.name) {
          sess.name = m.name;
          const lbl = sess.tile?.querySelector('.tile-name');
          if (lbl) lbl.textContent = m.name;
        }
        if (m.type === 'hello') {
          API.sig?.send({ type: 'g_hi', to: m.from, toInst: m.inst, name: API.myName() });
        }
        break;
      }
      case 'g_desc': {
        const sess = sessions.get(m.inst) || createSession(m);
        onDesc(sess, m.desc);
        break;
      }
      case 'g_cand': {
        const sess = sessions.get(m.inst);
        if (!sess || !m.cand) return;
        if (!sess.pc?.remoteDescription) {
          sess.pending.push(m.cand);
          return;
        }
        sess.pc.addIceCandidate(m.cand).catch(() => {});
        break;
      }
    }
  }

  function refreshTracks() {
    for (const sess of sessions.values()) {
      if (!sess.pc) continue;
      for (const sender of sess.pc.getSenders()) {
        const kind = sender.track?.kind;
        if (!kind) continue;
        const fresh = API.local.getTracks().find((t) => t.kind === kind) || null;
        if (sender.track !== fresh) sender.replaceTrack(fresh).catch(() => {});
      }
    }
  }

  API.registerHook({
    onSignal,
    onPeerBye: (m) => {
      const sess = sessions.get(m.inst);
      if (sess) closeSession(sess);
    },
    refreshTracks,
    // Для отладки из консоли
    _sessions: sessions,
  });
}
