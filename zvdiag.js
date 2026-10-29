// ZVONochek v24 — ранняя диагностика загрузки (классический скрипт, НЕ модуль).
// Подключается в index.html ПЕРЕД модульными скриптами, чтобы перехватить и их
// ошибки загрузки. Отдельным файлом, а не inline: CSP страницы
// (script-src 'self') запрещает inline-скрипты — inline-вариант молча не
// выполнился бы, то есть повторил бы ровно тот класс бага, который чинит v22.
// Собирает window.__zvErrors (события error + unhandledrejection), дублирует
// в localStorage 'zvLastErrors' (макс. 10) и показывает видимый баннер
// #zvDiag при сбое загрузки модулей (watchdog, 9 с после DOMContentLoaded).
// v23: проба окружения window.__zvProbe() — WebCrypto присутствует не всегда
// полностью: у владельца v22 баннер показал «crypto.subtle.generateKeyPair
// is not a function» при живом importKey/deriveKey (звонки работали, а
// генерация ключей — нет). Поэтому окружение проверяется СРАЗУ при загрузке,
// а не по нажатию кнопки, и его сводка дописывается к каждому баннеру.
(function () {
  var MAX = 10;
  window.__zvErrors = [];
  function pushErr(msg, src) {
    try {
      window.__zvErrors.push({ msg: String(msg || 'unknown error'), src: String(src || ''), ts: Date.now() });
      if (window.__zvErrors.length > MAX) window.__zvErrors.splice(0, window.__zvErrors.length - MAX);
      try {
        localStorage.setItem('zvLastErrors', JSON.stringify(window.__zvErrors));
      } catch (x) {}
    } catch (x) {}
  }
  window.addEventListener('error', function (ev) {
    pushErr(ev.message || (ev.error && ev.error.message) || 'error', ev.filename || '');
  });
  window.addEventListener('unhandledrejection', function (ev) {
    var r = ev.reason;
    pushErr('unhandledrejection: ' + ((r && r.message) || r || 'unknown'), '');
  });
  // ---------- Проба окружения (v23) ----------
  window.__zvProbe = function () {
    var s = null;
    try {
      s = window.crypto && window.crypto.subtle ? window.crypto.subtle : null;
    } catch (x) {}
    var ua = '';
    try {
      ua = String(navigator.userAgent || '').slice(0, 80);
    } catch (x) {}
    return {
      ua: ua,
      secure: !!window.isSecureContext,
      subtle: typeof (window.crypto && window.crypto.subtle),
      gen: s ? typeof s.generateKeyPair : 'undefined',
      sign: s ? typeof s.sign : 'undefined',
      imp: s ? typeof s.importKey : 'undefined',
      enc: s ? typeof s.encrypt : 'undefined',
    };
  };
  window.__zvEnvText = function () {
    var p = window.__zvProbe();
    return (
      'secure=' + p.secure +
      ', subtle=' + p.subtle +
      ', generateKeyPair=' + p.gen +
      ', sign=' + p.sign +
      ', importKey=' + p.imp +
      ', encrypt=' + p.enc +
      ', UA: ' + p.ua
    );
  };
  window.__zvShowDiag = function (text) {
    try {
      text = String(text);
      if (text.indexOf('[окружение:') === -1) {
        try {
          text += ' [окружение: ' + window.__zvEnvText() + ']';
        } catch (x) {}
      }
      var d = document.getElementById('zvDiag');
      if (!d) {
        d = document.createElement('div');
        d.id = 'zvDiag';
        d.className = 'zv-diag';
        (document.body || document.documentElement).appendChild(d);
      }
      d.textContent = text + ' ✕';
      // Закрытие по клику на баннер (обработчик вешается один раз на элемент).
      if (!d.__zvCloseBound) {
        d.__zvCloseBound = true;
        d.addEventListener('click', function () {
          try {
            d.classList.add('hidden');
            d.style.display = 'none';
          } catch (x) {}
        });
      }
      d.classList.remove('hidden');
      d.style.display = 'block';
    } catch (x) {}
  };
  function errorsText() {
    if (!window.__zvErrors.length) return 'ошибок не зафиксировано — сообщите разработчику';
    return window.__zvErrors
      .map(function (e) {
        return e.msg + (e.src ? ' (' + e.src + ')' : '');
      })
      .join(' | ');
  }
  function watchdog() {
    var missing = [];
    if (!window.__zvAppBooted) missing.push('приложения');
    if (!window.__zvChatBooted) missing.push('чата');
    if (!missing.length) return; // оба модуля живы; ошибки остаются в __zvErrors/localStorage, баннер не показываем
    var what =
      missing.length === 2 ? 'Модули приложения и чата не загрузились' : 'Модуль ' + missing[0] + ' не загрузился';
    window.__zvShowDiag('ZVONochek: ' + what + '. Ошибки: ' + errorsText() + '. Пришлите этот текст разработчику.');
  }
  // v23: проверка окружения при загрузке. Если WebCrypto нет совсем,
  // ничего не заработает — предупреждаем сразу, а не по нажатию.
  // v24: отсутствие только generateKeyPair больше НЕ фатально — у
  // identity.js/app.js есть fallback генерации пары P-256 (crypto.js:
  // genP256KeyPair считает публичную точку на BigInt и импортирует пару
  // через importKey, который в таких окружениях жив). Поэтому при живом
  // subtle и мёртвом generateKeyPair баннер не показываем; проба
  // (__zvProbe/__zvEnvText) по-прежнему дописывается к любому баннеру.
  function envCheck() {
    var p = window.__zvProbe();
    if (p.subtle !== 'object') {
      window.__zvShowDiag(
        'Этот браузер не даёт работать с шифрованием (нет crypto.subtle) — ' +
          'звонки, личная ссылка и чаты здесь не заработают. ' +
          'Откройте сайт в актуальном Chrome/Firefox/Safari по https.'
      );
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      envCheck();
      setTimeout(watchdog, 9000);
    });
  } else {
    envCheck();
    setTimeout(watchdog, 9000);
  }
})();
