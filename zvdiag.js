// ZVONochek v22 — ранняя диагностика загрузки (классический скрипт, НЕ модуль).
// Подключается в index.html ПЕРЕД модульными скриптами, чтобы перехватить и их
// ошибки загрузки. Отдельным файлом, а не inline: CSP страницы
// (script-src 'self') запрещает inline-скрипты — inline-вариант молча не
// выполнился бы, то есть повторил бы ровно тот класс бага, который чинит v22.
// Собирает window.__zvErrors (события error + unhandledrejection), дублирует
// в localStorage 'zvLastErrors' (макс. 10) и показывает видимый баннер
// #zvDiag при сбое загрузки модулей (watchdog, 9 с после DOMContentLoaded).
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
  window.__zvShowDiag = function (text) {
    try {
      var d = document.getElementById('zvDiag');
      if (!d) {
        d = document.createElement('div');
        d.id = 'zvDiag';
        d.className = 'zv-diag';
        (document.body || document.documentElement).appendChild(d);
      }
      d.textContent = text;
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
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(watchdog, 9000);
    });
  } else {
    setTimeout(watchdog, 9000);
  }
})();
