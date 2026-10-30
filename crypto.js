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


// =======================================================================
// v21: приватный текстовый чат (комнаты по ссылке). Отдельный вывод ключей,
// звонковый deriveRoom выше НЕ используется и не меняется.
// Техплан: ZVONochek-MESSENGER-TECHPLAN-v21.md.
//
// Из seed (256 бит, живёт только во #фрагменте ссылки и в IndexedDB)
// через HKDF-SHA256 с раздельными info-метками выводятся:
//  - roomId:      публичный адрес Durable Object комнаты (hex, 64 символа)
//  - roomKey:     AES-256-GCM ключ эпохи (невыгружаемый)
//  - accessToken: клиент предъявляет серверу; сервер хранит только SHA-256
// opts.epoch — фаза 3 (ротация), входит в метку ключа; фаза 1: 0.
// opts.pinIkm — фаза 2 (PIN): результат медленного KDF, подмешивается в IKM.
// =======================================================================
export const CHAT_PT_SIZE = 4096; // размер plaintext-блока с паддингом
export const CHAT_BLOB_SIZE = 12 + CHAT_PT_SIZE + 16; // nonce + ct + тег = 4124

export async function sha256hex(data) {
  const buf = typeof data === 'string' ? te.encode(data) : data;
  const h = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export function newMsgId() {
  return crypto.randomUUID();
}

// Контрольная фраза комнаты (фаза 2, техплан §5): слова из фиксированного
// списка в клиенте. Техплан предлагал список из 2048 слов × 3 слова (33 бита
// отпечатка); здесь — 256 слов × 4 слова (32 бита): сопоставимая энтропия
// при списке, который можно держать в одном файле без внешней зависимости.
// Слова выводятся из ключа комнаты отдельной HKDF-меткой (см. deriveChatKeys),
// поэтому у собеседников с одинаковым seed+PIN фраза совпадает, а при разном
// PIN — различается: это и ловит ошибку ввода PIN при устной сверке.
export const CHAT_WORDS = [
  'able','acid','aged','also','area','army','atom','aunt','auto','baby','back','bait','bake','bald','ball','band',
  'bank','bare','bark','barn','base','bath','bead','beam','bean','bear','beat','beef','beer','bell','belt','bend',
  'bent','best','bike','bill','bird','bite','blow','blue','boat','body','boil','bold','bolt','bomb','bond','bone',
  'book','boot','bore','born','boss','both','bowl','bulk','bull','burn','bury','bush','busy','cage','cake','calm',
  'came','camp','cane','cape','card','care','carp','cart','case','cash','cast','cave','cell','cent','chef','chin',
  'chip','city','clad','claw','clay','clip','club','clue','coal','coat','code','coil','coin','cold','colt','comb',
  'come','cook','cool','cope','copy','cord','core','corn','cost','cozy','crab','crew','crib','crop','crow','cube',
  'cure','curl','cute','dawn','days','dead','deal','dear','debt','deck','deed','deem','deep','deer','desk','dial',
  'dice','diet','dirt','dish','disk','dive','dock','doll','dome','done','doom','door','dose','dots','dove','down',
  'drag','draw','drip','drop','drum','duck','duct','dude','duel','dull','dump','dune','dusk','dust','duty','each',
  'earl','earn','ease','east','easy','echo','edge','edit','eggs','else','emit','epic','even','ever','exam','exit',
  'face','fact','fade','fail','fair','fake','fame','farm','fast','fate','fear','feed','feel','feet','fell','felt',
  'fern','file','fill','film','find','fine','fire','firm','fish','fist','fits','five','flag','flat','flaw','fled',
  'flex','flip','flow','foam','foil','fold','folk','fond','font','food','fool','foot','ford','fork','form','fort',
  'foul','four','free','frog','from','fuel','full','fund','funk','gain','gala','game','gasp','gate','gave','gaze',
  'gear','gems','germ','gift','girl','give','glad','glow','glue','goat','gold','golf','gone','gong','good','gray',
];

export async function deriveChatKeys(seedBytes, opts = {}) {
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length < 32) {
    throw new Error('bad seed');
  }
  const epoch = Number(opts.epoch || 0);
  let ikm = seedBytes;
  if (opts.pinIkm) {
    // Фаза 2: IKM = seed || pinIkm (pinIkm — выход PBKDF2 от PIN, 32 байта)
    ikm = new Uint8Array(seedBytes.length + opts.pinIkm.length);
    ikm.set(seedBytes, 0);
    ikm.set(opts.pinIkm, seedBytes.length);
  }
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, [
    'deriveBits',
    'deriveKey',
  ]);
  const salt = te.encode('ZVONochek/chat/v1');
  const hk = (info) => ({ name: 'HKDF', hash: 'SHA-256', salt, info: te.encode(info) });
  const roomIdBits = await crypto.subtle.deriveBits(hk('chat/v1/room-id'), base, 256);
  const roomKey = await crypto.subtle.deriveKey(
    hk(`chat/v1/room-key/e${epoch}`),
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  const tokenBits = await crypto.subtle.deriveBits(hk('chat/v1/access-token'), base, 256);
  // Контрольная фраза: отдельная метка, НЕ зависит от эпохи — фраза у комнаты
  // одна на всю жизнь; зависит от seed и PIN (через общий IKM).
  const phraseBits = new Uint8Array(await crypto.subtle.deriveBits(hk('chat/v1/phrase'), base, 32));
  const phrase = [...phraseBits].map((b) => CHAT_WORDS[b]).join(' ');
  return {
    roomId: hex(roomIdBits),
    roomKey,
    accessToken: b64u.enc(tokenBits),
    epoch,
    phrase,
  };
}

// =======================================================================
// v26, фаза 2 (техплан §5): PIN входа. PIN → PBKDF2-HMAC-SHA256, 600 000
// итераций, соль = 'ZVONochek/chat/pin/v1' || Room_ID-кандидат из seed-only
// вывода. Результат (pinIkm, 32 байта) подмешивается в IKM deriveChatKeys:
// без PIN выводятся ДРУГИЕ Room_ID, ключ и токен — сервер такую комнату
// «не знает», PIN в ссылке не передаётся и на устройстве хранится только
// зашифрованным vault-ключом (как seed).
// =======================================================================
export const PIN_PBKDF2_ITER = 600_000;
export const PIN_SALT_PREFIX = 'ZVONochek/chat/pin/v1';

export async function derivePinIkm(pin, seedBytes) {
  const cand = await deriveChatKeys(seedBytes); // seed-only кандидат Room_ID
  const salt = new Uint8Array([
    ...te.encode(PIN_SALT_PREFIX),
    ...te.encode(cand.roomId),
  ]);
  const base = await crypto.subtle.importKey('raw', te.encode(String(pin)), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PIN_PBKDF2_ITER, hash: 'SHA-256' },
    base,
    256
  );
  return new Uint8Array(bits);
}

// =======================================================================
// v26, фаза 3 (техплан §6): эпохи. Секрет эпохи — случайные 256 бит, НЕ
// выводится из seed: ключ эпохи = HKDF(seed ‖ pinIkm? ‖ epochSecret) с
// меткой chat/v1/room-key/e<N>. Room_ID и access-token при ротации НЕ
// меняются (выводятся из seed+PIN, как в эпохе 0): серверная комната та же,
// меняется только ключ шифрования сообщений. У кого нет секрета эпохи —
// новые сообщения не расшифровываются (AEAD), старая история при этом
// остаётся читаемой ключами прошлых эпох.
// =======================================================================
export async function deriveEpochRoomKey(seedBytes, epochSecret, epoch, opts = {}) {
  if (!(epochSecret instanceof Uint8Array) || epochSecret.length !== 32) {
    throw new Error('bad epoch secret');
  }
  const parts = [seedBytes];
  if (opts.pinIkm) parts.push(opts.pinIkm);
  parts.push(epochSecret);
  const ikm = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let off = 0;
  for (const p of parts) {
    ikm.set(p, off);
    off += p.length;
  }
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
  const salt = te.encode('ZVONochek/chat/v1');
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: te.encode(`chat/v1/room-key/e${Number(epoch)}`),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Завёртка секрета эпохи на ECDH-ключ устройства участника: эфемерная пара
// отправителя → ECDH → HKDF → AES-256-GCM. В сообщение 'epoch' кладётся
// {eph, iv, ct} (base64url) на каждого оставленного участника.
async function epochWrapKey(sharedBits, roomId, epoch) {
  const base = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: te.encode('ZVONochek/chat/v1'),
      info: te.encode(`chat/v1/epoch-wrap|${roomId}|${Number(epoch)}`),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function wrapEpochSecret(myEcdhPriv, peerEcdhPubRaw, secretBytes, roomId, epoch) {
  const eph = await genP256KeyPair(['deriveBits'], 'ECDH');
  const ephRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const peerKey = await crypto.subtle.importKey(
    'raw',
    peerEcdhPubRaw,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerKey }, eph.privateKey, 256);
  const wk = await epochWrapKey(shared, roomId, epoch);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wk, secretBytes));
  return { eph: b64u.enc(ephRaw), iv: b64u.enc(iv), ct: b64u.enc(ct) };
}

// Обратная операция на стороне получателя; любая ошибка (не его завёртка,
// битые данные) → null, без исключений наружу.
export async function unwrapEpochSecret(myEcdhPriv, wrap, roomId, epoch) {
  try {
    if (!wrap?.eph || !wrap?.iv || !wrap?.ct) return null;
    const ephKey = await crypto.subtle.importKey(
      'raw',
      b64u.dec(wrap.eph),
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );
    const shared = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: ephKey },
      myEcdhPriv,
      256
    );
    const wk = await epochWrapKey(shared, roomId, epoch);
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64u.dec(wrap.iv) },
      wk,
      b64u.dec(wrap.ct)
    );
    const out = new Uint8Array(pt);
    return out.length === 32 ? out : null;
  } catch {
    return null;
  }
}

// Шифрование одного сообщения: plaintext доводится до ровно CHAT_PT_SIZE
// байт (2 байта длины JSON + JSON + случайный паддинг), blob на проводе —
// nonce(12) || ciphertext. Возвращает Uint8Array длиной CHAT_BLOB_SIZE.
export async function encryptChatMessage(roomKey, msgObj) {
  const json = te.encode(JSON.stringify(msgObj));
  if (json.length > CHAT_PT_SIZE - 2) throw new Error('message too long');
  const pt = new Uint8Array(CHAT_PT_SIZE);
  new DataView(pt.buffer).setUint16(0, json.length, false);
  pt.set(json, 2);
  crypto.getRandomValues(pt.subarray(2 + json.length));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, roomKey, pt)
  );
  const blob = new Uint8Array(CHAT_BLOB_SIZE);
  blob.set(nonce, 0);
  blob.set(ct, 12);
  return blob;
}

// Обратное преобразование; при любом несоответствии (размер, тег AEAD,
// длина, JSON) возвращает null — чужие и битые blob молча отбрасываются.
export async function decryptChatMessage(roomKey, blob) {
  if (!(blob instanceof Uint8Array) || blob.length !== CHAT_BLOB_SIZE) return null;
  try {
    const pt = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: blob.subarray(0, 12) },
        roomKey,
        blob.subarray(12)
      )
    );
    const len = new DataView(pt.buffer, pt.byteOffset).getUint16(0, false);
    if (len > CHAT_PT_SIZE - 2) return null;
    return JSON.parse(td.decode(pt.subarray(2, 2 + len)));
  } catch {
    return null;
  }
}

// Хэш шифротекста для дедупа (клиент и сервер считают одинаково — по
// сырым байтам blob).
export async function hashChatBlob(blob) {
  return sha256hex(blob);
}

// =======================================================================
// v24: fallback генерации пары ключей P-256 без subtle.generateKeyPair.
// Диагноз (проба v23 у владельца): secure=true, subtle есть, sign /
// importKey / encrypt / digest — функции, но generateKeyPair ===
// undefined. Из-за этого падали ensurePersonal / ensureDevice /
// ensureGuestDevice (identity.js) и гостевой ключ исходящего дозвона
// (app.js); звонки при этом работали — generateKeyPair им не нужен.
//
// Конструкция: если нативная generateKeyPair есть — используется ОНА
// (основной путь, поведение не меняется). Fallback включается только при
// её отсутствии: приватный скаляр d — случайные 32 байта (rejection
// sampling в [1, n-1]), публичная точка Q = d·G считается здесь на BigInt
// (константы кривой — SEC 2 / FIPS 186-4), после чего обе половины пары
// импортируются в обычные CryptoKey через subtle.importKey('jwk', …).
// Результат неотличим для остального кода: те же CryptoKey, приватный
// неэкспортируемый. Математика проверена тестом tests-v21/test-p256gen.mjs
// на векторах openssl (d, x, y совпадают байт-в-байт).
// Отдельным модулем не вынесено сознательно: по конвенциям проекта вся
// криптография живёт в crypto.js, а новый файл потребовал бы ещё и
// проводки через service worker (CORE) и ?v= импорты.
// =======================================================================
const P256 = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn, // p - 3
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
};

const bytesToBigInt = (bytes) => {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
};
const bigIntToBytes32 = (v) => {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};
const modP = (v) => ((v % P256.p) + P256.p) % P256.p;

// Обратный элемент по модулю p — расширенный алгоритм Евклида.
function modInvP(v) {
  let [oldR, r] = [modP(v), P256.p];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('p256: not invertible');
  return modP(oldS);
}

// Аффинные точки: {x, y} BigInt, точка на бесконечности — null.
// Одна инверсия на сложение: для разовой генерации ключа это десятки
// миллисекунд — приемлемо, fallback не на горячем пути.
function p256PointAdd(Pt, Qt) {
  if (Pt === null) return Qt;
  if (Qt === null) return Pt;
  const { p, a } = P256;
  let lambda;
  if (Pt.x === Qt.x) {
    if (modP(Pt.y + Qt.y) === 0n) return null; // P + (-P), включая удвоение при y=0
    lambda = modP((3n * Pt.x * Pt.x + a) * modInvP(2n * Pt.y)); // удвоение
  } else {
    lambda = modP((Qt.y - Pt.y) * modInvP(Qt.x - Pt.x));
  }
  const x = modP(lambda * lambda - Pt.x - Qt.x);
  const y = modP(lambda * (Pt.x - x) - Pt.y);
  return { x, y };
}

function p256PointMul(k) {
  let result = null;
  let addend = { x: P256.gx, y: P256.gy };
  while (k > 0n) {
    if (k & 1n) result = p256PointAdd(result, addend);
    addend = p256PointAdd(addend, addend);
    k >>= 1n;
  }
  return result;
}

// Чистая часть fallback (экспортируется для векторных тестов):
// приватный скаляр (32 байта) → координаты публичной точки по 32 байта.
export function p256PubFromPriv(dBytes) {
  if (!(dBytes instanceof Uint8Array) || dBytes.length !== 32) {
    throw new Error('p256: bad private scalar');
  }
  const d = bytesToBigInt(dBytes);
  if (d < 1n || d >= P256.n) throw new Error('p256: scalar out of range');
  const Q = p256PointMul(d);
  return { x: bigIntToBytes32(Q.x), y: bigIntToBytes32(Q.y) };
}

// Fallback-пара из готового скаляра: JWK → subtle.importKey.
// Usages разносятся по половинам, как у нативной пары: публичная —
// ECDSA ['verify'] / ECDH [], приватная — вызывающие usages без
// публичных операций (importKey приватного JWK с 'verify' отклоняется
// WebCrypto: "Unsupported key usage").
export async function p256KeyPairFromPriv(dBytes, usages = ['sign', 'verify'], algName = 'ECDSA') {
  const { x, y } = p256PubFromPriv(dBytes);
  const alg = { name: algName, namedCurve: 'P-256' };
  const pubUsages = algName === 'ECDH' ? [] : ['verify'];
  const privUsages =
    algName === 'ECDH'
      ? usages.filter((u) => u === 'deriveKey' || u === 'deriveBits')
      : usages.filter((u) => u === 'sign');
  const pubJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: b64u.enc(x),
    y: b64u.enc(y),
    ext: true,
    key_ops: pubUsages,
  };
  const privJwk = { ...pubJwk, d: b64u.enc(dBytes), key_ops: privUsages };
  // Публичный импортируется extractable=true: у нативной пары, созданной
  // generateKeyPair(..., false, ...), публичная половина всё равно
  // экспортируема (identity.js достаёт из неё raw) — повторяем семантику.
  // Приватный — строго неэкспортируемый.
  const publicKey = await crypto.subtle.importKey('jwk', pubJwk, alg, true, pubUsages);
  const privateKey = await crypto.subtle.importKey('jwk', privJwk, alg, false, privUsages);
  return { publicKey, privateKey };
}

// Генерация пары P-256: нативный generateKeyPair, если он есть; иначе
// fallback выше. forceFallback — только для тестов.
export async function genP256KeyPair(usages = ['sign', 'verify'], algName = 'ECDSA', forceFallback = false) {
  if (!forceFallback && typeof crypto?.subtle?.generateKeyPair === 'function') {
    return crypto.subtle.generateKeyPair({ name: algName, namedCurve: 'P-256' }, false, [
      ...usages,
    ]);
  }
  for (;;) {
    const dBytes = crypto.getRandomValues(new Uint8Array(32));
    const d = bytesToBigInt(dBytes);
    if (d >= 1n && d < P256.n) return p256KeyPairFromPriv(dBytes, usages, algName);
  }
}

// =======================================================================
// v25: файлы в чате и коды приветствия.
//
// ФАЙЛЫ. Файл шифруется отдельным случайным ключом (32 байта, живёт только
// внутри зашифрованного ключом комнаты сообщения-метаданных type:'file').
// Чанки по 256 КиБ открытого текста; nonce чанка строится детерминированно:
// 4 байта случайной соли файла || 8 байт big-endian индекса. Уникальность
// пары (ключ, nonce) гарантирована: ключ одноразовый на файл, индекс не
// повторяется внутри файла. Сервер видит число чанков и их размер — в
// отличие от текста, файлы паддинг до фиксированного размера НЕ получают
// (осознанный компромисс, AUDIT-v25).
// =======================================================================
export const FILE_CHUNK_PT = 256 * 1024;
// v27: лимит файла поднят с 10 до 25 МБ. Потолок задаёт не код, а бесплатный
// тариф Cloudflare: хранилище Durable Object (SQLite) на free-плане — общий
// объём по аккаунту, и 25 МБ × разумное число комнат укладывается в него с
// запасом; дальше упираемся в квоту, а не в протокол (чанки те же 256 КиБ).
export const FILE_MAX_BYTES = 25 * 1024 * 1024;
export const FILE_MAX_CHUNKS = 100; // 100 × 256 КиБ = 25 МиБ — синхронно с ChatRoom DO

export async function importFileKey(rawBytes) {
  if (!(rawBytes instanceof Uint8Array) || rawBytes.length !== 32) {
    throw new Error('bad file key');
  }
  return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
}

function fileChunkNonce(salt, idx) {
  const nonce = new Uint8Array(12);
  nonce.set(salt.subarray(0, 4), 0);
  new DataView(nonce.buffer).setBigUint64(4, BigInt(idx), false);
  return nonce;
}

export async function encryptFileChunk(fileKey, salt, idx, ptBytes) {
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: fileChunkNonce(salt, idx) },
    fileKey,
    ptBytes
  );
  return new Uint8Array(ct);
}

export async function decryptFileChunk(fileKey, salt, idx, ctBytes) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fileChunkNonce(salt, idx) },
    fileKey,
    ctBytes
  );
  return new Uint8Array(pt);
}

// =======================================================================
// КОД ПРИВЕТСТВИЯ (быстрое подключение, техплан v21 §6). Код — 9 символов
// base64url (~54 бита). Ключ пары: PBKDF2-HMAC-SHA256(код, соль GREET_SALT,
// 200 000). Соль фиксированная строковая, а НЕ roomId: гость roomId не
// знает — он и есть полезная нагрузка blob ({seed, roomId} внутри
// шифротекста). Адрес пары на сервере: codeHash = SHA-256(GREET_SALT||код),
// сам код и seed сервер не получает. Защита: энтропия кода + медленный KDF +
// TTL 15 минут + одноразовость и лимит попыток claim на сервере.
// =======================================================================
export const GREET_SALT = 'zv-greet-v1';
export const GREET_CODE_LEN = 9;
const GREET_PBKDF2_ITER = 200_000;

export function newGreetCode() {
  // 54 бита: 7 случайных байт → 10 base64url-символов, берём первые 9 (54 бита)
  return b64u.enc(crypto.getRandomValues(new Uint8Array(7))).slice(0, GREET_CODE_LEN);
}

export async function greetCodeHash(code) {
  return sha256hex(GREET_SALT + String(code).trim());
}

async function deriveCodeKey(code, salt, iterations) {
  const base = await crypto.subtle.importKey('raw', te.encode(String(code).trim()), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: te.encode(salt), iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function sealCodePayload(code, salt, iterations, payloadObj) {
  const key = await deriveCodeKey(code, salt, iterations);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(payloadObj)))
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return b64u.enc(out);
}

async function openCodePayload(code, salt, iterations, blobB64) {
  try {
    const key = await deriveCodeKey(code, salt, iterations);
    const raw = b64u.dec(blobB64);
    if (raw.length < 13) return null;
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.subarray(0, 12) },
      key,
      raw.subarray(12)
    );
    return JSON.parse(td.decode(pt));
  } catch {
    return null;
  }
}

// Запечатать {seed, roomId} под ключом из кода → base64url(nonce||ct).
export async function sealGreetPayload(code, payloadObj) {
  return sealCodePayload(code, GREET_SALT, GREET_PBKDF2_ITER, payloadObj);
}

// Открыть payload кодом; неверный код/битый blob → null.
export async function openGreetPayload(code, blobB64) {
  return openCodePayload(code, GREET_SALT, GREET_PBKDF2_ITER, blobB64);
}

// =======================================================================
// v26: ПОСТОЯННАЯ КОРОТКАЯ ССЫЛКА (#join=<код>) — режим алиаса PairingDO.
// Тот же приём, что код приветствия (PBKDF2 → AES-GCM blob {seed, roomId}),
// но: отдельное пространство (соль 'zv-alias-v1' — greet-код алиас не
// откроет и наоборот), пара НЕ одноразовая и без TTL, зато отзываемая
// (revoke по admin-секрету владельца) и с rate-limit выдач на сервере.
// Честная рамка: ≈54 бита энтропии кода против 256 бит длинной ссылки;
// компенсации — медленный KDF, rate-limit, отзываемость и комбинация с PIN
// (фаза 2). Длинная ссылка остаётся главным ключом комнаты.
// =======================================================================
export const ALIAS_SALT = 'zv-alias-v1';
const ALIAS_PBKDF2_ITER = 200_000;

export function newJoinCode() {
  return newGreetCode(); // тот же формат: 9 символов base64url, ~54 бита
}

export async function aliasCodeHash(code) {
  return sha256hex(ALIAS_SALT + String(code).trim());
}

export async function sealAliasPayload(code, payloadObj) {
  return sealCodePayload(code, ALIAS_SALT, ALIAS_PBKDF2_ITER, payloadObj);
}

export async function openAliasPayload(code, blobB64) {
  return openCodePayload(code, ALIAS_SALT, ALIAS_PBKDF2_ITER, blobB64);
}

// =======================================================================
// v27: мессенджерные управляющие сообщения (реакции, правки, удаление,
// закреп) — ЧИСТЫЕ функции состояния. Живут здесь, потому что chat.js при
// импорте трогает DOM и в Node-тестах не поднимается; вся логика применения
// управляющих сообщений вынесена в тестируемые чистые функции, а chat.js
// только вызывает их при ingest и при собственной отправке.
//
// Модель: управляющие сообщения — обычные подписанные сообщения чата
// (type 'react' | 'edit' | 'del' | 'pin' | 'unpin' | 'ttl'), цель — по
// хэшу blob целевого сообщения (entry.hash в локальном хранилище).
// =======================================================================
export const REACT_EMOJIS = ['❤️', '👍', '🔥', '😂', '😮', '💩', '👎'];

// Состояние реакций одного сообщения: {emoji: [devPub, ...]}.
// Возвращает СЛЕДУЮЩУЮ операцию для dev: если dev уже ставил этот emoji —
// 'remove' (toggle), иначе 'add'. Неизвестный emoji → null (нельзя отправить).
export function nextReactionOp(reactions, dev, emoji) {
  if (!REACT_EMOJIS.includes(emoji) || !dev) return null;
  const list = reactions?.[emoji] || [];
  return list.includes(dev) ? 'remove' : 'add';
}

// Применение одной реакции к состоянию. Чистая: возвращает новый объект,
// входной не мутирует. Чужие/неизвестные emoji и пустые dev игнорируются.
export function applyReactionState(reactions, dev, emoji, op) {
  const out = {};
  for (const [k, v] of Object.entries(reactions || {})) {
    if (Array.isArray(v) && v.length) out[k] = [...v];
  }
  if (!REACT_EMOJIS.includes(emoji) || !dev || (op !== 'add' && op !== 'remove')) return out;
  const list = out[emoji] || [];
  const has = list.includes(dev);
  if (op === 'add' && !has) list.push(dev);
  if (op === 'remove' && has) list.splice(list.indexOf(dev), 1);
  if (list.length) out[emoji] = list;
  else delete out[emoji];
  return out;
}

// Применение 'edit'/'del' к локальной записи сообщения (entry = {msg, ...}).
// Правила: подпись обязана быть валидна (sigOk посчитан вызывающим через
// verifyChatSig), автор управляющего сообщения обязан совпадать с автором
// оригинала, удалённое сообщение больше не редактируется и не удаляется
// повторно. Мутирует entry.msg при успехе; возвращает true, если применено.
export function applyEditOrDelete(entry, ctrlMsg, sigOk) {
  if (!entry?.msg || !ctrlMsg || !sigOk) return false;
  if (ctrlMsg.devPub !== entry.msg.devPub) return false; // только автор оригинала
  if (entry.msg.deleted) return false;
  if (ctrlMsg.type === 'edit') {
    let text = null;
    try {
      text = JSON.parse(ctrlMsg.text || '')?.text;
    } catch {}
    if (typeof text !== 'string' || !text) return false;
    entry.msg.text = text;
    entry.msg.edited = true;
    return true;
  }
  if (ctrlMsg.type === 'del') {
    entry.msg.deleted = true;
    entry.msg.text = '';
    return true;
  }
  return false;
}

// Применение 'pin'/'unpin': активен один закреп, последний побеждает.
// Возвращает новое значение pinned (или undefined — «без изменений», если
// подпись невалидна). pinned: {hash, by, ts} | null.
export function applyPinState(current, ctrlMsg, sigOk) {
  if (!ctrlMsg || !sigOk) return undefined;
  if (ctrlMsg.type === 'pin') {
    let target = null;
    try {
      target = JSON.parse(ctrlMsg.text || '')?.target;
    } catch {}
    if (typeof target !== 'string' || !target) return undefined;
    return { hash: target, by: ctrlMsg.devPub, ts: ctrlMsg.ts || 0 };
  }
  if (ctrlMsg.type === 'unpin') return null;
  return undefined;
}

// =======================================================================
// v27: фраза восстановления личности и серверный бэкап (этап 4 техплана
// v15, адаптированный под серверное хранение в PairingDO).
//
// Seed бэкапа — 128 бит. Кодировка фразы: seed (16 байт) + первый байт
// SHA-256(seed) = 17 байт; каждый байт — одно слово из CHAT_WORDS (256
// слов, тот же список, что у контрольной фразы комнаты). Итого 17 слов:
// 16 слов данных + 1 контрольное. Ошибка в любом слове ловится контрольной
// суммой при вводе (decode бросает понятную ошибку), неизвестное слово —
// тоже. Фраза = полная власть над личностью: по ней выводятся И ключ
// бэкапа (шифрование списка комнат), И recovery-пара (подпись бэкапа и
// сертификатов новых устройств).
// =======================================================================
export const RECOVERY_WORDS_COUNT = 17;
export const RECOVERY_SEED_BYTES = 16;

export async function mnemonicEncode(seedBytes) {
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length !== RECOVERY_SEED_BYTES) {
    throw new Error('mnemonic: нужен seed ровно 16 байт');
  }
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', seedBytes));
  const all = new Uint8Array(RECOVERY_SEED_BYTES + 1);
  all.set(seedBytes, 0);
  all[RECOVERY_SEED_BYTES] = h[0];
  return [...all].map((b) => CHAT_WORDS[b]).join(' ');
}

export async function mnemonicDecode(phrase) {
  const words = String(phrase || '')
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  if (words.length !== RECOVERY_WORDS_COUNT) {
    throw new Error(`Фраза восстановления — ${RECOVERY_WORDS_COUNT} слов, получено ${words.length}`);
  }
  const bytes = new Uint8Array(RECOVERY_WORDS_COUNT);
  for (let i = 0; i < words.length; i++) {
    const idx = CHAT_WORDS.indexOf(words[i]);
    if (idx < 0) throw new Error(`Слова «${words[i]}» нет в списке слов ZVONochek`);
    bytes[i] = idx;
  }
  const seed = bytes.subarray(0, RECOVERY_SEED_BYTES);
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', seed));
  if (bytes[RECOVERY_SEED_BYTES] !== h[0]) {
    throw new Error('Контрольная сумма фразы не сошлась: где-то ошибка в словах');
  }
  return new Uint8Array(seed);
}

// Recovery-пара из seed: скаляр = HKDF(seed, 'zv-recovery-v1'), публичная
// точка — существующей механикой p256KeyPairFromPriv (v24). Вывод
// детерминирован: одна фраза → одна пара на любом устройстве.
export async function deriveRecoveryPair(seedBytes) {
  if (!(seedBytes instanceof Uint8Array) || seedBytes.length !== RECOVERY_SEED_BYTES) {
    throw new Error('recovery: нужен seed 16 байт');
  }
  const base = await crypto.subtle.importKey('raw', seedBytes, 'HKDF', false, ['deriveBits']);
  for (let counter = 0; ; counter++) {
    const info = counter === 0 ? 'zv-recovery-v1' : `zv-recovery-v1/${counter}`;
    const bits = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: te.encode('ZVONochek/v27'), info: te.encode(info) },
        base,
        256
      )
    );
    try {
      const pair = await p256KeyPairFromPriv(bits, ['sign'], 'ECDSA');
      const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
      return { publicKey: pair.publicKey, privateKey: pair.privateKey, pubRaw, pubB64: b64u.enc(pubRaw) };
    } catch {
      // Скаляр вне [1, n-1] — шанс ~2^-128, но вывод обязан быть тотальным:
      // следующая попытка с другим info даёт независимый скаляр.
      continue;
    }
  }
}

async function deriveBackupKey(seedBytes) {
  const base = await crypto.subtle.importKey('raw', seedBytes, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: te.encode('ZVONochek/v27'), info: te.encode('zv-backup-v1') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Запечатать объект бэкапа ключом из seed → base64url(iv || ct).
export async function sealBackup(seedBytes, obj) {
  const key = await deriveBackupKey(seedBytes);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj)))
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return b64u.enc(out);
}

// Открыть бэкап; неверный seed / битый blob → null (не исключение).
export async function openBackup(seedBytes, blobB64) {
  try {
    const key = await deriveBackupKey(seedBytes);
    const raw = b64u.dec(blobB64);
    if (raw.length < 13) return null;
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.subarray(0, 12) },
      key,
      raw.subarray(12)
    );
    return JSON.parse(td.decode(pt));
  } catch {
    return null;
  }
}

// Адрес серверного бэкапа: SHA-256 от сырого (65 байт) recovery-публичного
// ключа, hex — совпадает с проверкой на стороне PairingDO.
export async function backupIdHash(pubRaw) {
  return sha256hex(pubRaw);
}
