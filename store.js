// ZVONochek — тонкая обёртка над IndexedDB для коммуникатора:
// vault-ключ, идентичность, устройства, журнал звонков.
// Все хранилища — с внешними ключами (put(value, key)).
const DB_NAME = 'zvonochek';
const DB_VERSION = 2; // v21: добавлены сторы чата (rooms, messages); существующие данные не трогаются
const STORES = ['vault', 'identity', 'devices', 'calls', 'missed', 'rooms', 'messages'];

let dbPromise = null;
export function idb() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    let settled = false;
    const fail = (e) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      dbPromise = null; // позволяем повторную попытку после закрытия чужих вкладок
      reject(e);
    };
    // v22: апгрейд базы может молча висеть, если старая версия открыта в другой
    // вкладке или в установленном PWA, — не висим молча дольше 10 секунд.
    const timer = setTimeout(() => fail(new Error('База данных не отвечает (10 с)')), 10000);
    req.onupgradeneeded = () => {
      const db = req.result;
      for (const name of STORES) {
        if (!db.objectStoreNames.contains(name)) db.createObjectStore(name);
      }
    };
    req.onblocked = () =>
      fail(
        new Error(
          'База данных заблокирована: закройте другие вкладки и установленное приложение ZVONochek, затем обновите страницу'
        )
      );
    req.onsuccess = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const db = req.result;
      // Если другая вкладка захочет поднять версию — отпускаем соединение,
      // чтобы не блокировать её апгрейд (и не висеть самим в onblocked у неё).
      db.onversionchange = () => {
        try {
          db.close();
        } catch {}
        dbPromise = null;
      };
      resolve(db);
    };
    req.onerror = () => fail(req.error);
  });
  return dbPromise;
}

function tx(store, mode, fn) {
  return idb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const t = db.transaction(store, mode);
        const req = fn(t.objectStore(store));
        if (req) {
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        } else {
          t.oncomplete = () => resolve(undefined);
          t.onerror = () => reject(t.error);
        }
      })
  );
}

export const kvGet = (store, key) => tx(store, 'readonly', (s) => s.get(key));
export const kvPut = (store, key, value) => tx(store, 'readwrite', (s) => s.put(value, key));
export const kvDel = (store, key) => tx(store, 'readwrite', (s) => s.delete(key));
export const kvAll = (store) =>
  idb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const out = [];
        const t = db.transaction(store, 'readonly');
        const req = t.objectStore(store).openCursor();
        req.onsuccess = () => {
          const cur = req.result;
          if (cur) {
            out.push({ key: cur.key, value: cur.value });
            cur.continue();
          } else resolve(out);
        };
        req.onerror = () => reject(req.error);
      })
  );
