// Статические проверки сборки: целостность разметки, версий, кэша SW и
// синтаксиса. Ловят то, что иначе всплывает только у пользователя:
// «кнопка молчит» (нет id), белый экран (старый кэш), пустая иконка.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { ROOT } from './helpers.mjs';

const read = (f) => readFileSync(path.join(ROOT, f), 'utf8');
const html = read('index.html');
const clientJs = [
  ...readdirSync(ROOT).filter((f) => f.endsWith('.js')),
  ...readdirSync(path.join(ROOT, 'vendor')).map((f) => 'vendor/' + f),
];
const uiJs = clientJs.filter((f) => !f.startsWith('vendor/') && f !== 'sw.js');
const all = (re, s) => [...s.matchAll(re)].map((m) => m[1]);

test('каждый #id из JS есть в index.html', () => {
  const ids = new Set(all(/\bid="([^"]+)"/g, html));
  const missing = [];
  for (const f of uiJs) {
    const src = read(f);
    const refs = [
      ...all(/\$\(\s*['"`]#([\w-]+)['"`]/g, src),
      ...all(/getElementById\(\s*['"`]([\w-]+)['"`]/g, src),
      ...all(/querySelector(?:All)?\(\s*['"`]#([\w-]+)['"`]/g, src),
    ];
    for (const id of refs) if (!ids.has(id)) missing.push(`${f}: #${id}`);
  }
  assert.deepEqual(missing, []);
});

test('id в index.html уникальны', () => {
  const seen = new Map();
  for (const id of all(/\bid="([^"]+)"/g, html)) seen.set(id, (seen.get(id) || 0) + 1);
  const dup = [...seen].filter(([, n]) => n > 1).map(([id]) => id);
  assert.deepEqual(dup, []);
});

test('каждая иконка #i-* описана в спрайте', () => {
  const symbols = new Set(all(/<symbol id="(i-[\w-]+)"/g, html));
  const used = new Set([
    ...all(/href="#(i-[\w-]+)"/g, html),
    ...uiJs.flatMap((f) => all(/['"`]#(i-[\w-]+)['"`]/g, read(f))),
  ]);
  assert.deepEqual([...used].filter((i) => !symbols.has(i)), []);
});

test('версия одна везде: version.json, APP_VERSION, package.json, кэш SW и все ?v=', () => {
  const v = JSON.parse(read('version.json')).v;
  assert.equal(Number(read('app.js').match(/APP_VERSION\s*=\s*(\d+)/)[1]), v);
  assert.match(read('sw.js'), new RegExp(`CACHE_NAME\\s*=\\s*'zvonochek-v${v}'`));
  assert.equal(Number(JSON.parse(read('package.json')).version.split('.')[0]), v);
  const stale = [];
  for (const f of ['index.html', 'sw.js', ...clientJs]) {
    for (const q of all(/\?v=(\d+)/g, read(f))) if (Number(q) !== v) stale.push(`${f}: ?v=${q}`);
  }
  assert.deepEqual(stale, []);
});

test('SW кэширует все модули приложения, и все они существуют', () => {
  const core = all(/'\.\/([^']*)'/g, read('sw.js').match(/const CORE = \[([\s\S]*?)\];/)[1]).map(
    (u) => u.replace(/\?.*$/, '') || 'index.html'
  );
  for (const f of core) assert.ok(existsSync(path.join(ROOT, f)), `нет файла ${f}`);
  const imported = new Set(all(/<script[^>]*src="([^"?]+)/g, html));
  for (const f of clientJs) for (const m of all(/from '\.\/([^'?]+)/g, read(f))) imported.add(m);
  assert.deepEqual([...imported].filter((f) => !core.includes(f)), []);
});

test('wrangler.toml в корне и в worker/ совпадают (кроме пути main)', () => {
  const norm = (s) => s.replace(/^main = .*$/m, '').replace(/#.*$/gm, '').replace(/\s+/g, ' ').trim();
  assert.equal(norm(read('wrangler.toml')), norm(read('worker/wrangler.toml')));
});

test('синтаксис всех JS (node --check)', () => {
  const files = [...clientJs, ...readdirSync(path.join(ROOT, 'worker')).filter((f) => f.endsWith('.js')).map((f) => 'worker/' + f)];
  for (const f of files) {
    const r = spawnSync(process.execPath, ['--check', path.join(ROOT, f)], { encoding: 'utf8' });
    assert.equal(r.status, 0, `${f}: ${r.stderr}`);
  }
});

// Уровень языка: zvdiag.js обязан работать в самых старых браузерах (он
// показывает, почему не запустилось остальное), классические скрипты —
// ES2017, модули — ES2020 (Chrome 80+, Safari 13.1+, Firefox 74+).
// Нужен acorn из devDependencies; без него проверка пропускается.
test('уровень ECMAScript по файлам', async (t) => {
  let acorn;
  try {
    acorn = await import('acorn');
  } catch {
    return t.skip('acorn не установлен (npm install)');
  }
  const level = (f) =>
    f === 'zvdiag.js' ? [5, 'script'] : ['mqtt-lite.js', 'vendor/qrcode.js'].includes(f) ? [2017, 'script'] : f === 'sw.js' ? [2020, 'script'] : [2020, 'module'];
  for (const f of clientJs) {
    const [ecmaVersion, sourceType] = level(f);
    assert.doesNotThrow(() => acorn.parse(read(f), { ecmaVersion, sourceType }), `${f}: выше ES${ecmaVersion}`);
  }
});

test('относительные ссылки в документации ведут на существующие файлы', () => {
  const docs = [
    ...readdirSync(ROOT).filter((f) => f.endsWith('.md')),
    'worker/README.md',
  ];
  const broken = [];
  for (const doc of docs) {
    for (const href of all(/\]\(([^)\s]+)\)/g, read(doc))) {
      if (/^(https?:|mailto:|#)/.test(href)) continue;
      const target = path.join(ROOT, path.dirname(doc), href.replace(/#.*$/, ''));
      if (!existsSync(target)) broken.push(`${doc} → ${href}`);
    }
  }
  assert.deepEqual(broken, []);
});

// v39: правила доверия синхронизации устройств. Поведенчески их проверяет
// e2e «профиль»; здесь — страховка от случайного удаления проверок при
// правках (каждая закрывает конкретную атаку украденного устройства).
test('devices.js: rekey, реестр и история принимаются только с подписями', () => {
  const src = read('devices.js');
  const fn = (name) => {
    const i = src.search(new RegExp(`(async )?function ${name}\\(`));
    assert.ok(i >= 0, `нет функции ${name}`);
    return src.slice(i, src.indexOf('\n}\n', i));
  };
  // rekey от чужого устройства — только с подписью master/фразы, ДО разбора завёрток.
  const hr = fn('handleRekey');
  assert.ok(hr.indexOf('verifyRekeyAuth') >= 0 && hr.indexOf('verifyRekeyAuth') < hr.indexOf('wraps?.['), 'handleRekey без verifyRekeyAuth');
  assert.match(fn('verifyRekeyAuth'), /masterCandidates\(\)\.includes[\s\S]*adminProofOk[\s\S]*K\.gid/);
  assert.match(fn('doRekey'), /adminSigner[\s\S]*rekeyText\([\s\S]*post\('rekey', \{ wraps, auth/);
  // dev:X — сертификат + подпись самого X; удаление — только с отзывом.
  const ar = fn('acceptRemote');
  assert.match(ar, /devItemOk/);
  assert.match(ar, /out\['rev:' \+ dev\] && !isRevoked\(dev\)/);
  assert.match(fn('devItemOk'), /certTrusted[\s\S]*verifyChatSig\(dev, v\.esig, devText\([\s\S]*mainText/);
  // Запрос привязки несёт подпись записи реестра, основное её проверяет.
  assert.match(src, /typeof req\.esig === 'string' &&\s*\(await verifyChatSig\(req\.devicePub, req\.esig/);
  // История переписки — только от подключившего устройства и один раз.
  assert.match(fn('processMsg'), /env\.dev === st\.addedBy && st\.histExpected && !st\.histDone/);
});
