// ZVONochek — клиент Inbox (коммуникатор): регистрация устройства, дозвон,
// слушатель входящих по WebSocket, ответы и пропущенные. Протокол и подписи —
// см. worker/inbox.js. Ring идёт ТОЛЬКО через Worker (не через публичные
// транспорты — иначе «кому звонят» узнали бы все наблюдатели сигналинга).
import { signWithDevice } from './identity.js?v=24';

const base = (workerUrl, topic) => `${workerUrl.replace(/\/$/, '')}/inbox/${topic}`;

async function post(workerUrl, topic, path, body) {
  const res = await fetch(base(workerUrl, topic) + path, {
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

export async function inboxRegister(workerUrl, topic, bundle, sub = null) {
  const ts = Date.now();
  const sig = await signWithDevice(`register|${topic}|${bundle.devicePub}|${ts}`);
  return post(workerUrl, topic, '/register', {
    masterPub: bundle.masterPub,
    fp: bundle.fp,
    devicePub: bundle.devicePub,
    cert: bundle.cert,
    label: bundle.label,
    sub: sub
      ? {
          endpoint: sub.endpoint,
          keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth },
        }
      : null,
    ts,
    sig,
  });
}

export async function inboxRing(workerUrl, topic, { ringId, fromFp, fromDevicePub, blob }) {
  return post(workerUrl, topic, '/ring', { ringId, fromFp, fromDevicePub, blob });
}

export async function inboxRingState(workerUrl, topic, ringId) {
  const res = await fetch(`${base(workerUrl, topic)}/ring/${ringId}`);
  let data = {};
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}

export async function inboxAck(workerUrl, topic, ringId, bundle) {
  const ts = Date.now();
  const sig = await signWithDevice(`ack|${topic}|${ringId}|${ts}`);
  return post(workerUrl, topic, `/ring/${ringId}/ack`, { devicePub: bundle.devicePub, ts, sig });
}

export async function inboxAnswer(workerUrl, topic, ringId, verdict, signer) {
  const ts = Date.now();
  const sig = await signer.sign(`answer|${topic}|${ringId}|${verdict}|${ts}`);
  return post(workerUrl, topic, `/ring/${ringId}/answer`, {
    verdict,
    devicePub: signer.devicePub,
    ts,
    sig,
  });
}

export async function inboxCancel(workerUrl, topic, ringId, callerSign, callerPub) {
  const ts = Date.now();
  const sig = await callerSign(`cancel|${topic}|${ringId}|${ts}`);
  return post(workerUrl, topic, `/ring/${ringId}/answer`, {
    verdict: 'cancelled',
    devicePub: callerPub,
    ts,
    sig,
  });
}

export async function inboxMissed(workerUrl, topic, bundle) {
  const ts = Date.now();
  const sig = await signWithDevice(`missed|${topic}|${ts}`);
  const qs = new URLSearchParams({ devicePub: bundle.devicePub, ts: String(ts), sig });
  const res = await fetch(`${base(workerUrl, topic)}/missed?${qs}`);
  let data = {};
  try {
    data = await res.json();
  } catch {}
  return { status: res.status, data };
}

export async function inboxMissedAck(workerUrl, topic, ringIds, bundle) {
  const ts = Date.now();
  const sig = await signWithDevice(`missed|${topic}|${ts}`);
  return post(workerUrl, topic, '/missed/ack', {
    ringIds,
    devicePub: bundle.devicePub,
    ts,
    sig,
  });
}

// Слушатель входящих: держит WS на Inbox, переподключается с бэкоффом.
// onRing({ringId, blob, fromFp}), onState({ringId, state, answeredBy}).
export class InboxListener {
  constructor(workerUrl, topic, bundle, { onRing, onState, onStatus } = {}) {
    this.workerUrl = workerUrl;
    this.topic = topic;
    this.bundle = bundle;
    this.onRing = onRing;
    this.onState = onState;
    this.onStatus = onStatus;
    this.ws = null;
    this.closed = false;
    this.backoff = 1000;
    this.pingTimer = null;
  }
  connect() {
    if (this.closed) return;
    const url =
      base(this.workerUrl, this.topic).replace(/^http/, 'ws') + '/listen';
    let ws;
    try {
      ws = new WebSocket(url);
    } catch {
      this.retry();
      return;
    }
    this.ws = ws;
    ws.onopen = async () => {
      this.backoff = 1000;
      try {
        const ts = Date.now();
        const sig = await signWithDevice(`listen|${this.topic}|${this.bundle.devicePub}|${ts}`);
        ws.send(JSON.stringify({ type: 'auth', devicePub: this.bundle.devicePub, ts, sig }));
        this.onStatus?.('online');
      } catch {}
      clearInterval(this.pingTimer);
      this.pingTimer = setInterval(() => {
        try {
          ws.send('ping');
        } catch {}
      }, 25000);
    };
    ws.onmessage = (e) => {
      let m;
      try {
        m = JSON.parse(e.data);
      } catch {
        return;
      }
      if (m.type === 'ring') this.onRing?.(m);
      else if (m.type === 'ring-state') this.onState?.(m);
    };
    ws.onclose = () => {
      clearInterval(this.pingTimer);
      this.onStatus?.('offline');
      this.retry();
    };
    ws.onerror = () => {
      try {
        ws.close();
      } catch {}
    };
  }
  retry() {
    if (this.closed) return;
    const wait = this.backoff;
    this.backoff = Math.min(30000, this.backoff * 2);
    setTimeout(() => this.connect(), wait);
  }
  close() {
    this.closed = true;
    clearInterval(this.pingTimer);
    try {
      this.ws?.close();
    } catch {}
  }
}
