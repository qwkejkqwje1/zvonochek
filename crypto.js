// Шифрование сигналинга и голосового моста: секрет живёт только во #фрагменте ссылки
// и никогда не уходит ни на GitHub, ни на брокеры, ни в Worker.
const te = new TextEncoder();
const td = new TextDecoder();

export const b64u = {
  enc(buf) {
    const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    const chunk = 0x8000;
    for (let i = 0; i < b.length; i += chunk) {
      s += String.fromCharCode.apply(null, b.subarray(i, i + chunk));
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  dec(str) {
    const s = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '==='.slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

const hex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');

export function newSecret() {
  return b64u.enc(crypto.getRandomValues(new Uint8Array(32))); // 256 бит
}

// Из одного секрета через HKDF-SHA256 получаем:
//  - topic: публичный идентификатор комнаты (по нему нельзя восстановить ключ)
//  - key:   AES-256-GCM ключ для всех сообщений сигналинга и резервного аудио-моста
export async function deriveRoom(secret) {
  const raw = b64u.dec(secret);
  if (raw.length < 16) throw new Error('bad secret');
  const base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const salt = te.encode('ZVONochek/v1');
  const topicBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode('topic') },
    base,
    128
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: te.encode('aes-256-gcm') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  return { topic: hex(topicBits), key };
}

async function pipe(bytes, stream) {
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
}
const canZip = typeof CompressionStream !== 'undefined' && typeof DecompressionStream !== 'undefined';

// Сообщения сжимаются (deflate) и шифруются AES-256-GCM: z2 = сжато, z1 = без сжатия
export async function seal(key, obj, aad) {
  let pt = te.encode(JSON.stringify(obj));
  let tag = 'z1';
  // Сжимаем текстовые JSON/SDP пакеты, но не тратим ресурсы на уже сжатое аудио Opus
  if (canZip && pt.length > 300 && !obj._noZip) {
    try {
      pt = await pipe(pt, new CompressionStream('deflate-raw'));
      tag = 'z2';
    } catch {}
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: te.encode(aad + tag) },
    key,
    pt
  );
  return tag + '.' + b64u.enc(iv) + '.' + b64u.enc(ct);
}

export async function open(key, str, aad) {
  const p = String(str).split('.');
  if (p.length !== 3 || (p[0] !== 'z1' && p[0] !== 'z2')) return null;
  try {
    let pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64u.dec(p[1]), additionalData: te.encode(aad + p[0]) },
        key,
        b64u.dec(p[2])
      )
    );
    if (p[0] === 'z2') pt = await pipe(pt, new DecompressionStream('deflate-raw'));
    return JSON.parse(td.decode(pt));
  } catch {
    return null; // чужое или поврежденное сообщение — молча игнорируем
  }
}

// Код безопасности: хэш от DTLS-отпечатков обеих сторон (или ключей комнаты в режиме моста).
// Если у обоих собеседников он одинаковый — посредника (MITM) нет.
const EMOJI = [
  '🐶','🐱','🦊','🐻','🐼','🐨','🐯','🦁','🐮','🐷','🐸','🐵','🐔','🐧','🐦','🦄',
  '🐝','🦋','🐢','🐙','🐬','🐳','🌵','🌲','🌻','🍄','🌙','⭐','🔥','🌈','❄️','⚡',
  '🍎','🍋','🍉','🍇','🍓','🍒','🍑','🍍','🥕','🌽','🍕','🍔','🍩','🍪','🎂','☕',
  '⚽','🏀','🎸','🎹','🎲','🚀','🚲','🚗','⛵','✈️','🏠','🔑','🎁','📚','💡','🔔',
];

export async function safetyCode(sdpA, sdpB) {
  const fp = (sdp) =>
    (sdp.match(/a=fingerprint:\S+ \S+/g) || [])
      .map((s) => s.toUpperCase())
      .sort()
      .join('|');
  const parts = [fp(sdpA), fp(sdpB)].sort().join('#');
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(parts)));
  const emoji = [0, 1, 2, 3, 4].map((i) => EMOJI[h[i] % 64]).join(' ');
  const digits = (((h[5] << 16) | (h[6] << 8) | h[7]) % 1000000).toString().padStart(6, '0');
  return { emoji, digits: digits.slice(0, 3) + ' ' + digits.slice(3) };
}

export async function safetyCodeBridge(topic, idA, idB) {
  const parts = ['bridge', topic, ...[String(idA), String(idB)].sort()].join('#');
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(parts)));
  const emoji = [0, 1, 2, 3, 4].map((i) => EMOJI[h[i] % 64]).join(' ');
  const digits = (((h[5] << 16) | (h[6] << 8) | h[7]) % 1000000).toString().padStart(6, '0');
  return { emoji, digits: digits.slice(0, 3) + ' ' + digits.slice(3) };
}
