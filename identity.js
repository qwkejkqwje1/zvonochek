// ZVONochek — идентичность коммуникатора (техплан, этап 1).
// Master-ключ ECDSA P-256 (приватная часть — невыгружаемый CryptoKey в
// IndexedDB) удостоверяет ключи устройств; секрет личной ссылки зашифрован
// vault-ключом устройства. Личная ссылка: #k=<секрет>&d=<fp>, где fp — первые
// 32 hex SHA-256 от X9.62-представления master-публичного ключа.
import { b64u, newSecret, genP256KeyPair } from './crypto.js?v=25';
import { kvGet, kvPut } from './store.js?v=25';

const te = new TextEncoder();
let cached = null; // {secret, masterPub, masterPriv, fp, devicePub, devicePriv, cert, label}

export async function fpOfPubRaw(rawBytes) {
  const h = await crypto.subtle.digest('SHA-256', rawBytes);
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

async function getVaultKey() {
  let key = await kvGet('vault', 'key');
  if (!key) {
    key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ]);
    await kvPut('vault', 'key', key);
  }
  return key;
}

export async function hasPersonal() {
  try {
    return !!(await kvGet('identity', 'personal'));
  } catch {
    return false;
  }
}

async function ensureDevice(masterPriv, label) {
  let dev = await kvGet('devices', 'self');
  if (dev?.devicePriv && dev?.cert) return dev;
  const pair = await genP256KeyPair();
  const devicePub = b64u.enc(await crypto.subtle.exportKey('raw', pair.publicKey));
  const exp = Date.now() + 10 * 365 * 24 * 3600_000; // сертификат устройства на 10 лет
  const certText = `zv-device-v1|${devicePub}|${label}|${exp}`;
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    masterPriv,
    te.encode(certText)
  );
  dev = {
    devicePub,
    devicePriv: pair.privateKey,
    cert: { sig: b64u.enc(sig), label, exp },
    label,
  };
  await kvPut('devices', 'self', dev);
  return dev;
}

// Создаёт идентичность при первом вызове, дальше — только читает.
export async function ensurePersonal(label = 'Владелец') {
  if (cached) return cached;
  const vault = await getVaultKey();
  let rec = await kvGet('identity', 'personal');
  if (!rec) {
    const pair = await genP256KeyPair();
    const masterPub = b64u.enc(await crypto.subtle.exportKey('raw', pair.publicKey));
    const secret = newSecret();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vault, te.encode(secret));
    const secretEnc = b64u.enc(new Uint8Array([...iv, ...new Uint8Array(ct)]));
    rec = { masterPub, masterPriv: pair.privateKey, secretEnc, createdAt: Date.now() };
    await kvPut('identity', 'personal', rec);
  }
  const raw = b64u.dec(rec.secretEnc);
  const secretBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.subarray(0, 12) },
    vault,
    raw.subarray(12)
  );
  const secret = new TextDecoder().decode(secretBytes);
  const fp = await fpOfPubRaw(b64u.dec(rec.masterPub));
  const dev = await ensureDevice(rec.masterPriv, label);
  cached = {
    secret,
    masterPub: rec.masterPub,
    masterPriv: rec.masterPriv,
    fp,
    devicePub: dev.devicePub,
    devicePriv: dev.devicePriv,
    cert: dev.cert,
    label: dev.label,
  };
  return cached;
}

export async function getPersonal() {
  if (cached) return cached;
  return (await hasPersonal()) ? ensurePersonal() : null;
}

export function personalLinkOf(bundle) {
  return `${location.origin}${location.pathname}#k=${bundle.secret}&d=${bundle.fp}`;
}

export async function signWithDevice(text) {
  const p = await getPersonal();
  if (!p) throw new Error('no identity');
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    p.devicePriv,
    te.encode(text)
  );
  return b64u.enc(sig);
}

// Подпись произвольным ключом (для гостевого эфемерного ключа вызывающего).
export async function signWithKey(key, text) {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(text));
  return b64u.enc(sig);
}


// ---------- v21: чат — гостевое устройство, vault-хелперы, проверка подписей ----------
// У гостя без личной идентичности создаётся локальная пара устройства
// (без master-сертификата): сертификат в чате не требуется, закрепление
// собеседника идёт по TOFU из intro-сообщения. Существующий API выше не меняется.
export async function encryptWithVault(text) {
  const vault = await getVaultKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, vault, te.encode(text));
  return b64u.enc(new Uint8Array([...iv, ...new Uint8Array(ct)]));
}

export async function decryptWithVault(enc) {
  const vault = await getVaultKey();
  const raw = b64u.dec(enc);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: raw.subarray(0, 12) },
    vault,
    raw.subarray(12)
  );
  return new TextDecoder().decode(pt);
}

export async function ensureGuestDevice(label = 'Гость') {
  let dev = await kvGet('devices', 'guest');
  if (dev?.devicePriv && dev?.devicePub) return dev;
  const pair = await genP256KeyPair();
  const devicePub = b64u.enc(await crypto.subtle.exportKey('raw', pair.publicKey));
  dev = { devicePub, devicePriv: pair.privateKey, cert: null, label, guest: true };
  await kvPut('devices', 'guest', dev);
  return dev;
}

// Устройство для подписи сообщений чата: личное, если идентичность есть,
// иначе гостевое. Возвращает {devicePub, devicePriv, cert, guest}.
export async function getChatDevice() {
  const p = await getPersonal();
  if (p) {
    return { devicePub: p.devicePub, devicePriv: p.devicePriv, cert: p.cert, guest: false };
  }
  const g = await ensureGuestDevice();
  return { devicePub: g.devicePub, devicePriv: g.devicePriv, cert: null, guest: true };
}

export async function signChatText(text) {
  const d = await getChatDevice();
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    d.devicePriv,
    te.encode(text)
  );
  return b64u.enc(sig);
}

export async function verifyChatSig(devicePubB64, sigB64, text) {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      b64u.dec(devicePubB64),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      b64u.dec(sigB64),
      te.encode(text)
    );
  } catch {
    return false;
  }
}
