// Сквозной прогон в настоящем Chromium: два независимых профиля (Анна и
// Борис) общаются через локальный Worker. Проверяются чат (ник, сообщения,
// ответ, реакция, список комнат) и звонок (соединение, статистика,
// журнал). Скриншоты — в tests/e2e/shots при SHOTS=1.
//
//   npm run worker:dev            # локальный Worker на :8787 (отдельный терминал)
//   npm run e2e                   # CHROMIUM_PATH=… — свой Chromium, если нужно
//
// Переменные: WORKER_URL (по умолчанию http://127.0.0.1:8787), PORT сайта
// (8765 — этот Origin разрешён воркеру в «npm run worker:dev»),
// VIEWPORTS (390x844,1440x900), CHROMIUM_PATH, SHOTS=1.
import http from 'node:http';
import { readFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { chromium } from 'playwright-core';
import { ROOT } from '../helpers.mjs';

const WORKER = process.env.WORKER_URL || 'http://127.0.0.1:8787';
const PORT = Number(process.env.PORT || 8765);
const VIEWPORTS = (process.env.VIEWPORTS || '390x844,1440x900').split(',').map((v) => v.split('x').map(Number));
const SHOTS = process.env.SHOTS === '1' ? path.join(ROOT, 'tests/e2e/shots') : null;
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.webmanifest': 'application/manifest+json' };

// ---------- статика ----------
function serve() {
  const srv = http.createServer(async (req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '') || 'index.html';
    const file = path.join(ROOT, rel);
    if (!file.startsWith(ROOT) || rel.startsWith('node_modules')) return res.writeHead(403).end();
    try {
      const body = await readFile(file);
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' }).end(body);
    } catch {
      res.writeHead(404).end();
    }
  });
  return new Promise((r) => srv.listen(PORT, '127.0.0.1', () => r(srv)));
}

// ---------- помощники ----------
async function profile(browser, base, [w, h], label, errors) {
  const ctx = await browser.newContext({
    viewport: { width: w, height: h },
    deviceScaleFactor: SHOTS ? 2 : 1,
    bypassCSP: true, // CSP сайта разрешает только боевой Worker
    permissions: ['microphone', 'camera'],
  });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(`${label}: ${e.message}`));
  await page.goto(base);
  await page.evaluate((u) => localStorage.setItem('zvWorkerUrl', u), WORKER);
  await page.reload();
  await page.waitForFunction(() => window.__zvAppBooted && window.__zvChatBooted);
  return page;
}
const shot = async (page, name, [w]) => SHOTS && page.screenshot({ path: path.join(SHOTS, `${name}-${w}.png`) });
const isShown = (page, sel) =>
  page.evaluate((s) => {
    const e = document.querySelector(s);
    return !!e && !e.classList.contains('hidden') && e.offsetParent !== null;
  }, sel);
async function until(fn, ms = 30000, step = 500) {
  for (let t = 0; t < ms; t += step) {
    if (await fn()) return true;
    await new Promise((r) => setTimeout(r, step));
  }
  return false;
}

// ---------- сценарии ----------
async function chatScenario(browser, base, vp, errors) {
  const A = await profile(browser, base, vp, 'A', errors);
  await A.click('#btnCreateChat');
  await A.waitForSelector('#chatNickBox:not(.hidden)');
  await A.fill('#chatNickInput', 'Анна');
  await A.click('#chatNickSave');
  await A.waitForSelector('.tg-chat-welcome-acts'); // пустая комната — карточка приглашения
  await shot(A, 'chat-empty', vp);
  const send = async (p, text) => {
    await p.fill('#chatInput', text);
    await p.press('#chatInput', 'Enter');
    await p.waitForTimeout(300);
  };
  await send(A, 'Привет! Это наш зашифрованный чат 🔒');
  const link = A.url();

  const B = await profile(browser, base, vp, 'B', errors);
  await B.goto(link);
  await B.waitForSelector('#chatNickBox:not(.hidden)');
  await B.fill('#chatNickInput', 'Борис');
  await B.click('#chatNickSave');
  assert.ok(await until(() => B.locator('.chat-msg-row:not(.mine)').count().then((n) => n >= 1)), 'Борис не получил сообщение Анны');
  await send(B, 'Привет! Всё вижу.');
  assert.ok(await until(() => A.locator('.chat-msg-row:not(.mine)').count().then((n) => n >= 1)), 'Анна не получила ответ');

  // ответ через меню сообщения + реакция
  const target = B.locator('.chat-msg-row:not(.mine) .chat-msg').last();
  await target.click({ button: 'right' });
  await B.click('#chatMsgMenu .chat-react-emoji[data-emoji="👍"]');
  await B.waitForTimeout(600);
  await target.click({ button: 'right' });
  await B.click('#msgActReply');
  assert.ok(await isShown(B, '#chatReplyBar'), 'нет плашки ответа');
  await send(B, 'Договорились!');
  assert.ok(await until(() => A.locator('.chat-quote').count().then((n) => n >= 1)), 'цитата не дошла');
  assert.ok(await until(() => A.locator('.chat-chip').count().then((n) => n >= 1)), 'реакция не дошла');
  await shot(A, 'chat-A', vp);
  await shot(B, 'chat-B', vp);

  // личный чат: заголовок — имя собеседника, без аватаров у пузырей
  assert.equal(await A.textContent('#chatRoomTitle'), 'Борис');
  assert.equal(await A.locator('#chatMessages.duo .chat-msg-row .chat-avatar').count(), 0);
  if (vp[0] < 920) await A.click('#chatBack');
  await A.waitForTimeout(500);
  assert.match(await A.textContent('#chatRoomsList'), /Договорились!/);
  await shot(A, 'chat-list', vp);
  await A.context().close();
  await B.context().close();
}

async function callScenario(browser, base, vp, errors) {
  const A = await profile(browser, base, vp, 'A', errors);
  await A.click('[data-home-tab="calls"]');
  await A.click('#btnCreate');
  await A.waitForSelector('#prejoin:not(.hidden)');
  await A.fill('#name', 'Анна');
  await shot(A, 'prejoin', vp);
  await A.click('#btnJoin');
  await A.waitForSelector('#call:not(.hidden)');
  const link = A.url();

  const B = await profile(browser, base, vp, 'B', errors);
  await B.goto(link);
  await B.waitForSelector('#prejoin:not(.hidden)');
  await B.fill('#name', 'Борис');
  await B.click('#btnJoin');
  const connected = await until(async () => (await isShown(A, '#quality')) && (await isShown(B, '#quality')), 40000);
  assert.ok(connected, 'звонок не соединился');
  await A.waitForTimeout(3000);
  await shot(A, 'call', vp);
  await A.click('#quality');
  await A.waitForSelector('#callStats:not(.hidden)');
  await A.waitForTimeout(2200);
  await shot(A, 'call-stats', vp);
  await A.keyboard.press('Escape');
  await A.click('#cHang');
  await A.waitForTimeout(1500);
  // журнал звонков и статистика на вкладке «Звонки»
  assert.ok(await until(() => A.locator('.call-li').count().then((n) => n >= 1), 8000), 'звонок не попал в журнал');
  await shot(A, 'calls-tab', vp);
  await A.context().close();
  await B.context().close();
}

// ---------- запуск ----------
const health = await fetch(WORKER + '/health').then((r) => r.json()).catch(() => null);
if (!health?.ok) {
  console.error(`Worker недоступен: ${WORKER}. Запустите «npm run worker:dev» или задайте WORKER_URL.`);
  process.exit(2);
}
if (SHOTS) await mkdir(SHOTS, { recursive: true });
const srv = await serve();
const base = `http://127.0.0.1:${srv.address().port}/`;
const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || undefined,
  args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream', '--autoplay-policy=no-user-gesture-required'],
});
let failed = 0;
for (const vp of VIEWPORTS) {
  for (const [name, fn] of [['чат', chatScenario], ['звонок', callScenario]]) {
    const errors = [];
    const t0 = Date.now();
    try {
      await fn(browser, base, vp, errors);
      assert.deepEqual(errors, [], 'ошибки страницы');
      console.log(`✔ ${name} ${vp.join('×')} (${((Date.now() - t0) / 1000).toFixed(1)} с)`);
    } catch (e) {
      failed++;
      console.log(`✖ ${name} ${vp.join('×')}: ${e.message}`);
    }
  }
}
await browser.close();
srv.close();
process.exit(failed ? 1 : 0);
