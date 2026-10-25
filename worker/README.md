# Cloudflare Worker для ZVONochek v11

Деплой из этого же репозитория GitHub:
- В панели Cloudflare: **Workers & Pages** → **zvonochek** → **Settings** → **Build** → **Root directory: `worker`** (или корень `/`, так как `wrangler.toml` лежит в обеих папках).

## Возможности Worker v11
- **Без TURN Worker полностью работоспособен:** обеспечивает быстрый WebSocket-сигналинг, кольцевой буфер истории пакетов для мгновенного рукопожатия, резервный HTTP-поллинг (`GET /room/:id?since=...` и `POST /room/:id`) при блокировке WebSocket и передачу зашифрованных голосовых пакетов в режиме «Мост без TURN».
- **Параллельная выдача TURN-ключей (`/turn`):** опрашивает провайдеров одновременно с таймаутом 3,5 с, отсекает порт `:53` и сортирует `turns:` / порт `:443` первыми для пробития DPI.

## Подключение TURN (опционально)
Значения добавляются в **Settings → Variables and Secrets**:
- **Metered.ca** (бесплатный тариф): `METERED_DOMAIN` (например `zvonochek.metered.live`), `METERED_API_KEY`
- **Свой coturn / ExpressTURN**: `TURN_URLS` (через запятую), `TURN_USERNAME`, `TURN_CREDENTIAL`
- **Cloudflare Calls TURN**: `TURN_KEY_ID`, `TURN_KEY_API_TOKEN`

Проверка работы воркера: `https://zvonochek.zerewgwe.workers.dev/health` → `{"ok":true,"app":"ZVONochek","v":11,"turn":...}`
