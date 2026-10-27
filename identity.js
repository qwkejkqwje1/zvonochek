// ZVONochek — идентичность коммуникатора (техплан, этап 1).
// Master-ключ ECDSA P-256 (приватная часть — невыгружаемый CryptoKey в
// IndexedDB) удостоверяет ключи устройств; секрет личной ссылки зашифрован
// vault-ключом устройства. Личная ссылка: #k=<секрет>&d=<fp>, где fp — первые
// 32 hex SHA-256 от X9.62-представления master-публичного ключа.
import { b64u, newSecret } from './crypto.js?v=20';
import { kvGet, kvPut } from './store.js?v=20';

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
  const pair = await crypto.subtle.generateKeyPair({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ]);
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
    const pair = await crypto.subtle.generateKeyPair(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify']
    );
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
