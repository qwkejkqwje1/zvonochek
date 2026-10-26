# Cloudflare Worker для ZVONochek v12

Деплой из этого же репозитория GitHub:
- В панели Cloudflare: **Workers & Pages** → **zvonochek** → **Settings** → **Build** → **Root directory: `worker`** (или корень `/`, так как `wrangler.toml` лежит в обеих папках).

## Возможности Worker v12
- **Без TURN Worker полностью работоспособен:** обеспечивает быстрый WebSocket-сигналинг, кольцевой буфер истории пакетов для мгновенного рукопожатия, резервный HTTP-поллинг (`GET /room/:id?since=...` и `POST /room/:id`) при блокировке WebSocket и передачу зашифрованных голосовых пакетов в режиме «Мост без TURN».
- **Параллельная выдача TURN-ключей (`/turn`):** опрашивает провайдеров одновременно с таймаутом 3,5 с, отсекает порт `:53` и сортирует `turns:` / порт `:443` первыми для пробития DPI.
- **Строгий CORS:** для чужих Origin не отдаётся `Access-Control-Allow-Origin: *`; список задаётся в `ALLOWED_ORIGINS`. Пустой список разрешает любой Origin (эхо адреса), поэтому для продакшена его лучше заполнить.

## Подключение TURN (опционально)
Значения добавляются в **Settings → Variables and Secrets**:
- **Metered.ca** (бесплатный тариф): `METERED_DOMAIN` (например `zvonochek.metered.live`), `METERED_API_KEY`
- **Свой coturn / ExpressTURN**: `TURN_URLS` (через запятую), `TURN_USERNAME`, `TURN_CREDENTIAL`
- **Cloudflare Calls TURN**: `TURN_KEY_ID`, `TURN_KEY_API_TOKEN`

Проверка работы воркера: `https://zvonochek.zerewgwe.workers.dev/health` → `{"ok":true,"app":"ZVONochek","v":12,"turn":...}`
