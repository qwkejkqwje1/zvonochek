# Cloudflare Worker для ZVONochek

Деплой: Cloudflare → Workers & Pages → zvonochek → Settings → Build → **Root directory: `worker`**.

Без TURN Worker тоже работает: даёт запасной сигналинг (способ №2).

TURN можно подключить любым из способов. Значения добавляются в Settings → Variables and Secrets как **Secret**:
- **Metered.ca** (бесплатно, без карты): `METERED_DOMAIN` (например `zvonochek.metered.live`), `METERED_API_KEY`
- **Свой coturn или другой TURN**: `TURN_URLS` (через запятую), `TURN_USERNAME`, `TURN_CREDENTIAL`
- **Cloudflare TURN** (нужна карта): `TURN_KEY_ID`, `TURN_KEY_API_TOKEN`

Проверка: `https://zvonochek.zerewgwe.workers.dev/health` → `{"ok":true,...,"turn":true}`
