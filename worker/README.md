# Cloudflare Worker ZVONochek (v36)

«Слепой» сервер: хранит и пересылает только шифротекст, ключей не знает.

| Файл | Назначение |
|---|---|
| `worker.js` | маршрутизация, CORS, `/health`, `/turn`, комнаты сигналинга (Room) |
| `chat-room.js` | чат-комната (ChatRoom): сообщения, файлы, прочтения, presence |
| `inbox.js` | дозвон на личную ссылку и пропущенные (Inbox) |
| `pairing.js` | коды, короткие ссылки, кодовые фразы, резервные копии (Pairing) |
| `push.js` | Web Push (RFC 8291/8292) с VAPID |

## Деплой

Из корня репозитория: `npx wrangler deploy` (корневой `wrangler.toml`,
`main = "worker/worker.js"`). Для Workers Builds с корневой папкой `worker`
есть `worker/wrangler.toml` — он совпадает с корневым, кроме пути `main`
(это проверяет `npm test`). Локально: `npm run worker:dev`.

## Переменные и секреты

| Имя | Что это |
|---|---|
| `ALLOWED_ORIGINS` | сайты через запятую, которым отвечает Worker; пусто — любой (только для разработки) |
| `TURN_KEY_ID` + `TURN_KEY_API_TOKEN` | Cloudflare Realtime TURN (рекомендуется) |
| `METERED_DOMAIN` + `METERED_API_KEY` | Metered.ca (`METERED_API_TOKEN` — синоним ключа) |
| `TURN_URLS` + `TURN_USERNAME` + `TURN_CREDENTIAL` | свой coturn |
| `VAPID_PRIVATE_JWK` | приватный ключ push (JWK P-256); публичный отдаёт `/push-key` |

Секреты задаются `npx wrangler secret put <ИМЯ>` или в панели
Cloudflare → Worker → **Settings → Variables and Secrets**.

## Эндпоинты

- `GET /health` — `{"ok":true,"v":36,"turn":…,"push":…}`.
- `GET /turn` — временные ICE-серверы: провайдеры опрашиваются параллельно
  (таймаут 3,5 с), порт 53 отбрасывается, `turns:`/443/TCP — первыми;
  не больше 20 запросов в минуту с IP.
- `/room/<id>` — сигнал звонка: WebSocket с кольцевым буфером и
  HTTP-поллинг `GET ?since=` / `POST`, если WebSocket режут.
- `/chat/<roomId>/…` — API чата (см. заголовок `chat-room.js`).
- `/inbox/…`, `/pair/…`, `/push-key` — дозвон, коды и копии, ключ push.
