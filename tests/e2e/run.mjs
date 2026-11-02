// Сквозной прогон в настоящем Chromium: два независимых профиля (Анна и
// Борис) общаются через локальный Worker. Проверяются чат (ник, сообщения,
// ответ, реакция, список комнат), звонок (соединение, статистика,
// журнал) и v38-сценарий «номер» (дозвон по личной ссылке, контакт из
// журнала, смена номера, стирание данных) и v39-сценарий «профиль» (второе
// устройство по коду: тот же номер, чаты, контакты, свои сообщения — «мои»,
// отвязка), v40-сценарий «перезвон» (второй звонок без перезагрузки:
// голос Анны доходит, эхоподавление включено). Скриншоты — в
// tests/e2e/shots при SHOTS=1.
//
//   npm run worker:dev            # локальный Worker на :8787 (отдельный терминал)
//   npm run e2e                   # CHROMIUM_PATH=… — свой Chromium, если нужно
//
// Переменные: WORKER_URL (по умолчанию http://127.0.0.1:8787), PORT сайта
// (8765 — этот Origin разрешён воркеру в «npm run worker:dev»),
// VIEWPORTS (390x844,1440x900), CHROMIUM_PATH, SHOTS=1, ONLY=<сценарий>
// (чат | звонок | номер | профиль | перезвон), DEBUG=1 — консоль страниц в вывод.
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
async function profile(browser, base, [w, h], label, errors, init = null) {
  const ctx = await browser.newContext({
    viewport: { width: w, height: h },
    deviceScaleFactor: SHOTS ? 2 : 1,
    bypassCSP: true, // CSP сайта разрешает только боевой Worker
    permissions: ['microphone', 'camera'],
  });
  if (init) await ctx.addInitScript(init);
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(`${label}: ${e.message}`));
  if (process.env.DEBUG === '1') {
    page.on('console', (m) => console.log(`  [${label}] ${m.type()}: ${m.text()}`));
    page.on('response', (r) => r.status() >= 400 && console.log(`  [${label}] HTTP ${r.status()} ${r.request().method()} ${r.url()}`));
  }
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
  // v37: голос с RED, подсказка приёма от собеседника и строка «Режим видео»
  const statsText = () => A.locator('#callStatsBody').innerText();
  let st = await statsText();
  assert.match(st, /Opus \+ RED/, 'RED не согласован:\n' + st);
  assert.match(st, /Режим видео/, 'нет строки «Режим видео»:\n' + st);
  assert.ok(await until(async () => /собеседнику ≤\d+p/.test(await statsText()), 8000), 'подсказка vcap не дошла:\n' + (await statsText()));
  // Блокировка экрана у Бориса → Анна ставит своё видео на паузу, разблокировка — снова шлёт
  await B.evaluate(() => document.querySelector('#cLock').click());
  assert.ok(await until(async () => /собеседник свернул/.test(await statsText()), 9000), 'пауза видео не сработала:\n' + (await statsText()));
  await B.evaluate(() => {
    const b = document.querySelector('#btnUnlockCall');
    b.click();
    b.click();
  });
  assert.ok(await until(async () => /собеседнику ≤\d+p/.test(await statsText()), 9000), 'видео не вернулось после разблокировки');
  await A.keyboard.press('Escape');
  await A.click('#cHang');
  await A.waitForTimeout(1500);
  // журнал звонков и статистика на вкладке «Звонки»
  assert.ok(await until(() => A.locator('.call-li').count().then((n) => n >= 1), 8000), 'звонок не попал в журнал');
  await shot(A, 'calls-tab', vp);
  await A.context().close();
  await B.context().close();
}

// v40: «перезвон» — Анна кладёт трубку и снова входит по ссылке без
// перезагрузки. До v40 stopLocal() останавливал обработанный трек микрофона
// (MediaStreamDestination), а attachMicToEngine() возвращал его же мёртвым:
// во втором звонке Борис получал от Анны 0 байт звука.
const pcHook = () => {
  const O = window.RTCPeerConnection;
  window.__pcs = [];
  window.RTCPeerConnection = function (...a) {
    const pc = new O(...a);
    window.__pcs.push(pc);
    return pc;
  };
  window.RTCPeerConnection.prototype = O.prototype;
  const gum = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  window.__aec = [];
  navigator.mediaDevices.getUserMedia = async (c) => {
    const st = await gum(c);
    for (const t of st.getAudioTracks()) window.__aec.push(t.getSettings().echoCancellation);
    return st;
  };
};
// Сколько байт входящего звука пришло за ms на последнем соединённом PC.
const audioInDelta = async (page, ms = 3000) => {
  const bytes = () =>
    page.evaluate(async () => {
      const pc = (window.__pcs || []).filter((x) => x.connectionState === 'connected').pop();
      if (!pc) return -1;
      let n = 0;
      (await pc.getStats()).forEach((r) => {
        if (r.type === 'inbound-rtp' && r.kind === 'audio') n += r.bytesReceived || 0;
      });
      return n;
    });
  const a = await bytes();
  await page.waitForTimeout(ms);
  const b = await bytes();
  return a < 0 || b < 0 ? -1 : b - a;
};
async function recallScenario(browser, base, vp, errors) {
  const A = await profile(browser, base, vp, 'A', errors, pcHook);
  await A.click('[data-home-tab="calls"]');
  await A.click('#btnCreate');
  await A.waitForSelector('#prejoin:not(.hidden)');
  await A.fill('#name', 'Анна');
  await A.click('#btnJoin');
  await A.waitForSelector('#call:not(.hidden)');
  const link = A.url();
  const B = await profile(browser, base, vp, 'B', errors, pcHook);
  await B.goto(link);
  await B.waitForSelector('#prejoin:not(.hidden)');
  await B.fill('#name', 'Борис');
  await B.click('#btnJoin');
  const both = async () => (await isShown(A, '#quality')) && (await isShown(B, '#quality'));
  assert.ok(await until(both, 40000), 'звонок №1 не соединился');
  await A.waitForTimeout(1000);
  assert.ok((await audioInDelta(B)) > 1000, 'звонок №1: голос Анны не доходит до Бориса');
  assert.ok(
    (await A.evaluate(() => window.__aec)).every((v) => v !== false),
    'эхоподавление выключено по умолчанию'
  );
  await A.click('#cHang');
  await A.waitForSelector('#home:not(.hidden)');
  await A.waitForTimeout(1500);
  await A.click('[data-home-tab="calls"]').catch(() => {});
  await A.fill('#homeLinkInput', link);
  await A.click('#btnOpenLink');
  await A.waitForSelector('#prejoin:not(.hidden)');
  await A.waitForTimeout(800);
  assert.equal(
    await A.evaluate(() => window.ZVGroupAPI.local.getAudioTracks()[0]?.readyState),
    'live',
    'трек микрофона в лобби после перезахода мёртв'
  );
  await A.click('#btnJoin');
  assert.ok(await until(both, 40000), 'звонок №2 не соединился');
  await A.waitForTimeout(1000);
  const rx2 = await audioInDelta(B);
  assert.ok(rx2 > 1000, `звонок №2: голос Анны не доходит до Бориса (${rx2} байт за 3 с)`);
  await A.context().close();
  await B.context().close();
}

// v38: личный номер → звонок с «обратным номером» → контакт из журнала →
// «Сменить номер» (старая ссылка отвечает 404) → «Стереть всё».
async function numberScenario(browser, base, vp, errors) {
  const mkPersonal = async (p) => {
    await p.click('[data-home-tab="personal"]');
    await p.click('#btnCreatePersonal');
    await p.waitForSelector('#personalMain:not(.hidden)');
    assert.ok(await until(async () => /доступны/.test((await p.textContent('#personalStatus')) || ''), 15000), 'Inbox не подключился');
    return p.inputValue('#personalLink');
  };
  const A = await profile(browser, base, vp, 'A', errors);
  const linkA1 = await mkPersonal(A);
  const B = await profile(browser, base, vp, 'B', errors);
  await mkPersonal(B);
  const ring = async (link) => {
    await B.goto(link);
    await B.waitForSelector('#prejoin:not(.hidden)');
    await B.waitForSelector('#callOwnerBox:not(.hidden)');
    await B.click('#btnCallOwner');
  };
  await ring(linkA1);
  await A.waitForSelector('#incomingCall:not(.hidden)', { timeout: 15000 });
  await shot(A, 'incoming', vp);
  await A.click('#btnAccept');
  const connected = await until(async () => (await isShown(A, '#quality')) && (await isShown(B, '#quality')), 40000);
  assert.ok(connected, 'звонок по личной ссылке не соединился');
  await A.waitForTimeout(2500);
  const inCall = (p) => p.evaluate(() => !document.querySelector('#call').classList.contains('hidden'));
  await B.click('#cHang');
  await A.waitForTimeout(1500);
  if (await inCall(A)) await A.click('#cHang');
  await A.waitForTimeout(1000);
  // журнал Анны: у входящего от Бориса есть «Перезвонить», номер — в контакты
  await A.click('[data-home-tab="calls"]');
  assert.ok(await until(() => A.locator('#callsList .call-back').count().then((n) => n >= 1), 8000), 'нет кнопки обратного звонка');
  await A.locator('#callsList .call-li.has-menu').first().click();
  await A.click('#contactActSave');
  await A.fill('#contactAddName', 'Борис');
  await A.click('#contactAddSave');
  assert.ok(await until(async () => /Борис/.test((await A.textContent('#contactsList')) || ''), 5000), 'контакт не сохранился');
  await shot(A, 'contacts', vp);
  // «Сменить номер»: новая ссылка, старая отвечает «не обслуживается»
  await A.click('[data-home-tab="personal"]');
  await A.click('#btnChangeNumber');
  await A.click('#dangerGo');
  await A.click('#dangerGo');
  assert.ok(await until(async () => /Готово/.test((await A.textContent('#dangerNote')) || ''), 20000), 'номер не сменился: ' + (await A.textContent('#dangerNote')));
  const linkA2 = await A.inputValue('#personalLink');
  assert.notEqual(linkA2, linkA1, 'ссылка не изменилась');
  assert.ok(await until(async () => /доступны/.test((await A.textContent('#personalStatus')) || ''), 15000), 'новый Inbox не подключился');
  if (await inCall(B)) await B.click('#cHang');
  await ring(linkA1);
  assert.ok(await until(async () => /не обслуживается/.test((await B.textContent('#toast')) || ''), 10000), 'старая ссылка всё ещё звонит');
  await B.click('#btnBackHome').catch(() => {});
  await ring(linkA2);
  await A.waitForSelector('#incomingCall:not(.hidden)', { timeout: 15000 });
  await A.click('#btnDecline');
  await A.waitForTimeout(800);
  // «Стереть всё»: после перезагрузки — ни номера, ни контактов
  await A.click('[data-home-tab="personal"]');
  await A.click('#btnWipeAll');
  await A.click('#dangerGo');
  await A.click('#dangerGo');
  const wiped = await until(
    () => A.evaluate(() => !!window.__zvAppBooted && localStorage.getItem('zvWorkerUrl') === null).catch(() => false),
    20000
  );
  assert.ok(wiped, 'localStorage не очищен: ' + (await A.textContent('#dangerNote').catch(() => '')));
  await A.evaluate((u) => localStorage.setItem('zvWorkerUrl', u), WORKER);
  await A.reload();
  await A.waitForFunction(() => window.__zvAppBooted);
  await A.click('[data-home-tab="personal"]');
  assert.ok(await isShown(A, '#personalNone'), 'личность не стёрта');
  await A.click('[data-home-tab="calls"]');
  assert.equal(await A.locator('#contactsList .contact-li').count(), 0, 'контакты не стёрты');
  await A.context().close();
  await B.context().close();
}

// v39: второе устройство того же человека. Анна (A) с номером, чатом с
// Борисом (C) и контактом подключает ноутбук (A2) по 12-значному коду.
async function linkScenario(browser, base, vp, errors) {
  const mkPersonal = async (p) => {
    await p.click('[data-home-tab="personal"]');
    await p.click('#btnCreatePersonal');
    await p.waitForSelector('#personalMain:not(.hidden)');
    assert.ok(await until(async () => /доступны/.test((await p.textContent('#personalStatus')) || ''), 15000), 'Inbox не подключился');
    return p.inputValue('#personalLink');
  };
  const send = async (p, text) => {
    await p.fill('#chatInput', text);
    await p.press('#chatInput', 'Enter');
    await p.waitForTimeout(300);
  };
  const openFirstRoom = async (p) => {
    await p.click('[data-home-tab="chats"]');
    await p.waitForSelector('#chatRoomsList .tg-chat-item', { timeout: 20000 });
    await p.locator('#chatRoomsList .tg-chat-item').first().click();
    await p.waitForSelector('#chatInput', { state: 'visible', timeout: 20000 });
  };
  const rowCount = (p, sel, text) => p.locator(sel, { hasText: text }).count();
  // Из чата на главную: на телефоне — «назад», на широком экране — домой из сайдбара
  const leaveChat = (p) => p.click(vp[0] < 920 ? '#chatBack' : '#chatSidebarHomeBtn');
  const t0 = Date.now();
  const step = (name) => process.env.DEBUG === '1' && console.log(`  · ${((Date.now() - t0) / 1000).toFixed(1)} с: ${name}`);

  const A = await profile(browser, base, vp, 'A', errors);
  const linkA = await mkPersonal(A);
  const C = await profile(browser, base, vp, 'C', errors);
  const linkC = await mkPersonal(C);
  step('номера созданы');
  await A.click('[data-home-tab="chats"]');
  await A.click('#btnCreateChat');
  await A.waitForSelector('#chatNickBox:not(.hidden)');
  await A.fill('#chatNickInput', 'Анна');
  await A.click('#chatNickSave');
  await A.waitForSelector('.tg-chat-welcome-acts');
  await send(A, 'Сообщение с телефона');
  await C.goto(A.url());
  await C.waitForSelector('#chatNickBox:not(.hidden)');
  await C.fill('#chatNickInput', 'Борис');
  await C.click('#chatNickSave');
  assert.ok(await until(() => rowCount(C, '.chat-msg-row:not(.mine)', 'Сообщение с телефона').then((n) => n >= 1)), 'Борис не получил сообщение');
  await send(C, 'Привет, Анна');
  assert.ok(await until(() => rowCount(A, '.chat-msg-row:not(.mine)', 'Привет, Анна').then((n) => n >= 1)), 'Анна не получила ответ');
  await leaveChat(A);
  await A.click('[data-home-tab="calls"]');
  await A.click('#btnContactAdd');
  await A.fill('#contactAddName', 'Борис');
  await A.fill('#contactAddLink', linkC);
  await A.click('#contactAddSave');
  assert.ok(await until(async () => /Борис/.test((await A.textContent('#contactsList')) || ''), 5000), 'контакт не сохранился');

  step('чат и контакт готовы');
  // Новое устройство показывает код и контрольные слова
  const A2 = await profile(browser, base, vp, 'A2', errors);
  await A2.click('[data-home-tab="personal"]');
  await A2.click('#btnLinkNew');
  assert.ok(await until(async () => /\d{4}/.test((await A2.textContent('#linkNewCode')) || ''), 20000), 'нет кода привязки');
  await A2.evaluate(() => {
    window.__e2ePreLink = 1; // исчезнет при перезагрузке после привязки
  });
  const code = (await A2.textContent('#linkNewCode')).trim();
  const words = (await A2.textContent('#linkNewWords')).trim();
  assert.ok(words.length > 3, 'нет контрольных слов');
  await shot(A2, 'link-new', vp);
  // Основное: «Подключить устройство» → код → сверка слов → подтверждение
  await A.click('[data-home-tab="personal"]');
  await A.waitForSelector('#devicesCard:not(.hidden)');
  await A.click('#btnLinkDevice');
  await A.fill('#linkCodeInput', code);
  await A.click('#btnLinkFind');
  await A.waitForSelector('#linkConfirmBox:not(.hidden)', { timeout: 20000 });
  assert.equal((await A.textContent('#linkReqWords')).trim(), words, 'контрольные слова не совпали');
  await shot(A, 'link-confirm', vp);
  await A.click('#btnLinkConfirm');
  step('подтверждено на основном');
  // A2 получает профиль, историю и перезагружается (?linked=1)
  const linked = await until(
    () =>
      A2.evaluate(
        () => !window.__e2ePreLink && !!window.__zvAppBooted && !!window.__zvChatBooted && !!window.ZVDevices?.isLinkedDevice?.()
      ).catch(() => false),
    150000,
    1000
  );
  assert.ok(linked, 'новое устройство не подключилось: ' + ((await A2.textContent('#linkNewStatus').catch(() => '')) || ''));
  step('второе устройство перезагрузилось');
  await A2.click('[data-home-tab="personal"]');
  await A2.waitForSelector('#personalMain:not(.hidden)');
  assert.equal(await A2.inputValue('#personalLink'), linkA, 'на втором устройстве другой номер');
  assert.ok(await until(() => A2.locator('#devicesList .device-row').count().then((n) => n === 2), 20000), 'в списке устройств нет двух строк');
  assert.ok(await until(() => A.locator('#devicesList .device-row').count().then((n) => n === 2), 20000), 'основное не видит второе устройство');
  await shot(A2, 'devices', vp);
  await shot(A, 'devices-main', vp);
  // Контакт приехал
  await A2.click('[data-home-tab="calls"]');
  assert.ok(await until(async () => /Борис/.test((await A2.textContent('#contactsList')) || ''), 30000), 'контакт не синхронизировался');
  // Чат приехал, история — своя «моя», чужая — чужая
  await openFirstRoom(A2);
  assert.ok(await until(() => rowCount(A2, '.chat-msg-row.mine', 'Сообщение с телефона').then((n) => n >= 1), 30000), 'своё старое сообщение не «моё» на втором устройстве');
  assert.ok(await until(() => rowCount(A2, '.chat-msg-row:not(.mine)', 'Привет, Анна').then((n) => n >= 1), 30000), 'нет сообщения Бориса на втором устройстве');
  step('история на втором устройстве');
  await send(A2, 'Сообщение с ноутбука');
  await shot(A2, 'link-chat', vp);
  // У Анны на телефоне — «моё»; у Бориса — от Анны, устройство подтверждено профилем
  await openFirstRoom(A);
  assert.ok(await until(() => rowCount(A, '.chat-msg-row.mine', 'Сообщение с ноутбука').then((n) => n >= 1), 30000), 'сообщение со второго устройства не «моё» на основном');
  assert.ok(await until(() => rowCount(C, '.chat-msg-row:not(.mine)', 'Сообщение с ноутбука').then((n) => n >= 1), 30000), 'Борис не получил сообщение со второго устройства');
  assert.ok(
    await until(async () => /Анна: новое устройство \(подтверждено/.test((await C.textContent('#chatMessages')) || ''), 15000),
    'у Бориса новое устройство Анны не опознано как её'
  );
  assert.equal(await C.textContent('#chatRoomTitle'), 'Анна', 'у Бориса чат перестал быть личным');
  await shot(C, 'link-peer', vp);
  // Смена номера на основном: отмеченное второе устройство получает новый
  await leaveChat(A);
  await A.click('[data-home-tab="personal"]');
  step('сообщения сошлись, меняем номер');
  if (process.env.DEBUG === '1') {
    await A2.evaluate(() => {
      window.__e2eEv = [];
      for (const n of ['zv-inbox-authfail', 'zv-inbox-revoked', 'zv-identity-changed', 'zv-devices-changed']) {
        window.addEventListener(n, () => window.__e2eEv.push(n + '@' + Date.now()));
      }
    });
  }
  await A.click('#btnChangeNumber');
  assert.ok(await isShown(A, '#dangerKeepBox'), 'нет выбора устройств при смене номера');
  await shot(A, 'rotate-keep', vp);
  await A.click('#dangerGo');
  await A.click('#dangerGo');
  assert.ok(await until(async () => /Готово/.test((await A.textContent('#dangerNote')) || ''), 30000), 'номер не сменился: ' + (await A.textContent('#dangerNote')));
  step('номер сменён на основном');
  const linkAnew = await A.inputValue('#personalLink');
  assert.notEqual(linkAnew, linkA, 'ссылка не изменилась');
  await leaveChat(A2);
  await A2.click('[data-home-tab="personal"]');
  assert.ok(
    await until(async () => (await A2.inputValue('#personalLink').catch(() => '')) === linkAnew, 90000, 1000),
    'второе устройство не получило новый номер'
  );
  step('новый номер на втором устройстве');
  assert.ok(await until(async () => /доступны/.test((await A2.textContent('#personalStatus')) || ''), 20000), 'второе устройство не слушает новый номер');
  step('новый номер на обоих, звоним');
  // Звонок на номер звонит на обоих устройствах; ответ на одном гасит другое
  const inCall = (p) => p.evaluate(() => !document.querySelector('#call').classList.contains('hidden'));
  await C.goto(linkAnew);
  await C.waitForSelector('#prejoin:not(.hidden)');
  await C.waitForSelector('#callOwnerBox:not(.hidden)');
  await C.click('#btnCallOwner');
  await A.waitForSelector('#incomingCall:not(.hidden)', { timeout: 20000 });
  await A2.waitForSelector('#incomingCall:not(.hidden)', { timeout: 20000 });
  await shot(A2, 'link-incoming', vp);
  await A2.click('#btnAccept');
  assert.ok(await until(async () => !(await isShown(A, '#incomingCall')), 15000), 'основное звонит после ответа на втором');
  assert.ok(await until(async () => (await isShown(A2, '#quality')) && (await isShown(C, '#quality')), 40000), 'звонок на второе устройство не соединился');
  await A2.waitForTimeout(1500);
  await C.click('#cHang');
  await A2.waitForTimeout(1500);
  if (await inCall(A2)) await A2.click('#cHang');
  await A2.waitForTimeout(800);
  step('звонок принят на втором, отвязываем');
  if (process.env.DEBUG === '1') console.log('  A2 events:', await A2.evaluate(() => (window.__e2eEv || []).map((x) => x.replace(/@(\d+)/, (m, t) => '@' + ((t - performance.timeOrigin) / 1000).toFixed(1)))).catch(() => 'reloaded'));
  // Отвязка: «Отвязать» × 2 на основном → второе стирает себя
  const unlinkBtn = A.locator('#devicesList .device-row:not(.self) button');
  await unlinkBtn.click();
  await unlinkBtn.click();
  assert.ok(await until(async () => /отвязано/.test((await A.textContent('#devicesNote')) || ''), 30000), 'отвязка не прошла: ' + (await A.textContent('#devicesNote')));
  const wiped = await until(
    () => A2.evaluate(() => !!window.__zvAppBooted && localStorage.getItem('zvWorkerUrl') === null).catch(() => false),
    90000,
    1000
  );
  assert.ok(wiped, 'отвязанное устройство не стёрло данные');
  assert.equal(await A.locator('#devicesList .device-row').count(), 1, 'отвязанное устройство осталось в списке');
  assert.equal(await A.inputValue('#personalLink'), linkAnew, 'номер основного изменился после отвязки');
  await A.context().close();
  await A2.context().close();
  await C.context().close();
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
  let list = [['чат', chatScenario], ['звонок', callScenario]];
  if (vp === VIEWPORTS[0]) list.push(['номер', numberScenario], ['профиль', linkScenario], ['перезвон', recallScenario]);
  if (process.env.ONLY) list = list.filter(([n]) => n === process.env.ONLY);
  for (const [name, fn] of list) {
    const errors = [];
    const t0 = Date.now();
    try {
      await fn(browser, base, vp, errors);
      assert.deepEqual(errors, [], 'ошибки страницы');
      console.log(`✔ ${name} ${vp.join('×')} (${((Date.now() - t0) / 1000).toFixed(1)} с)`);
    } catch (e) {
      failed++;
      console.log(`✖ ${name} ${vp.join('×')}: ${e.message}`);
      if (SHOTS) {
        for (const [i, ctx] of browser.contexts().entries()) {
          for (const [j, pg] of ctx.pages().entries()) {
            await pg.screenshot({ path: path.join(SHOTS, `fail-${name}-${i}${j}.png`) }).catch(() => {});
          }
        }
      }
      for (const ctx of browser.contexts()) await ctx.close().catch(() => {});
    }
  }
}
await browser.close();
srv.close();
process.exit(failed ? 1 : 0);
