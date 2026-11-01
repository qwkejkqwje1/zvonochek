# Свой сервер за 5 минут

ZVONochek состоит из двух частей:

- **Сайт (клиент)** — статические файлы на GitHub Pages, одинаковые у всех.
- **Worker (сервер)** — Cloudflare Worker: сигнал звонков, чаты, дозвон,
  коды, резервные копии, (по желанию) выдача ключей TURN. По умолчанию приложение ходит
  в Worker владельца проекта. Свой Worker — это ваши комнаты, сообщения и
  копии только на вашем аккаунте Cloudflare (бесплатного тарифа хватает).

## Шаг 1. Развернуть Worker

**Кнопкой:**

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/qwkejkqwje1/zvonochek)

Войдите в Cloudflare → **Deploy**. Конфиг берётся из корневого
`wrangler.toml`: все Durable Objects (Room, Inbox, ChatRoom, Pairing) и
миграции уже описаны.

**Или из терминала** (Node.js ≥ 22), в корне репозитория:

```bash
npx wrangler login
npx wrangler deploy
```

## Шаг 2. Проверить

Cloudflare покажет адрес вида `https://zvonochek.<аккаунт>.workers.dev`.
Откройте `…/health` — ответ `{"ok":true,"app":"ZVONochek","v":39,…,"push":true,…,"devices":true,"revoke":true,"linkNx":true,…}`.

## Шаг 3. Подключить приложение

ZVONochek → **Настройки** → **«Свой сервер»** → вставьте адрес →
**«Применить»**. Чаты, дозвон, коды, копии и сигнал звонков пойдут в ваш
Worker. **«Сбросить»** возвращает сервер по умолчанию.

## Шаг 4. TURN (необязательно)

TURN уже работает из `config.js` (Metered и ExpressTURN, бесплатные логины
владельца) — свой Worker для этого не нужен. Свой TURN в Worker имеет смысл,
только если хочется спрятать логины из клиента или общая квота кончается:
секреты `TURN_URLS`, `TURN_USERNAME`, `TURN_CREDENTIAL` (любой TURN, в т. ч.
Metered) или `METERED_DOMAIN` + `METERED_API_KEY`. Cloudflare Realtime TURN
тоже поддерживается (`TURN_KEY_ID`, `TURN_KEY_API_TOKEN`), но требует
привязать карту. Подробнее и push-уведомления — в [RELEASE.md](RELEASE.md)
и [worker/README.md](worker/README.md). Проверка: `/health` → `"turn": true`.

## Что важно знать

- **Свой сайт.** Если разворачиваете и копию сайта (форк + GitHub Pages),
  добавьте её адрес в `ALLOWED_ORIGINS` в `wrangler.toml`: Worker отвечает
  только разрешённым сайтам.
- **Смена сервера не переносит данные.** Комнаты, коды, копии и
  пропущенные звонки живут там, где созданы. Ссылки остаются прежними —
  на новом сервере комнаты просто пусты, пока в них не напишут.
- **Push при закрытом приложении** работает сразу: с v38 Worker сам
  создаёт ключ VAPID (секрет `VAPID_PRIVATE_JWK` — по желанию). На каждом
  устройстве нужно один раз разрешить уведомления — [RELEASE.md](RELEASE.md), §3.
- **Автоочистка** включена: чаты без сообщений — 30 дней, алиасы — 30 дней
  простоя, входящие — 30/90 дней, резервные копии — 180 дней без обновления.
  Хранилище бесплатного тарифа не забивается брошенными данными.
