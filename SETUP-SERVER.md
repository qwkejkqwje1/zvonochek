# Свой сервер за 5 минут

ZVONochek состоит из двух частей:

- **Сайт (клиент)** — статические файлы на GitHub Pages, одинаковые у всех.
- **Worker (сервер)** — Cloudflare Worker: сигнал звонков, чаты, дозвон,
  коды, резервные копии, выдача ключей TURN. По умолчанию приложение ходит
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
Откройте `…/health` — ответ `{"ok":true,"app":"ZVONochek","v":36,…}`.

## Шаг 3. Подключить приложение

ZVONochek → **Настройки** → **«Свой сервер»** → вставьте адрес →
**«Применить»**. Чаты, дозвон, коды, копии и сигнал звонков пойдут в ваш
Worker. **«Сбросить»** возвращает сервер по умолчанию.

## Шаг 4. TURN — чтобы звонки проходили везде (рекомендуется)

Без TURN звонки через «жёсткий» NAT идут через мост: только голос.
Cloudflare Realtime TURN бесплатен до 1000 ГБ в месяц:

```bash
npx wrangler secret put TURN_KEY_ID
npx wrangler secret put TURN_KEY_API_TOKEN
```

Другие варианты (Metered, свой coturn) и push-уведомления — в
[RELEASE.md](RELEASE.md). Проверка: `/health` → `"turn": true`.

## Что важно знать

- **Свой сайт.** Если разворачиваете и копию сайта (форк + GitHub Pages),
  добавьте её адрес в `ALLOWED_ORIGINS` в `wrangler.toml`: Worker отвечает
  только разрешённым сайтам.
- **Смена сервера не переносит данные.** Комнаты, коды, копии и
  пропущенные звонки живут там, где созданы. Ссылки остаются прежними —
  на новом сервере комнаты просто пусты, пока в них не напишут.
- **Push при закрытом приложении** — необязательно: пока приложение
  открыто, звонки и сообщения приходят и так. Включение — RELEASE.md, §5.
