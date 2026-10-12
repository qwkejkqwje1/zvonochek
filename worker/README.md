# Cloudflare Worker для ZVONochek

Деплоится автоматически через GitHub Actions (`.github/workflows/deploy-worker.yml`).

Нужны 4 секрета в репозитории (Settings → Secrets and variables → Actions):
- `CLOUDFLARE_API_TOKEN` — API-токен Cloudflare (шаблон «Edit Cloudflare Workers»)
- `CLOUDFLARE_ACCOUNT_ID` — ID аккаунта Cloudflare
- `TURN_KEY_ID` — ID TURN-ключа (Cloudflare → Realtime → TURN Server)
- `TURN_KEY_API_TOKEN` — API-токен этого TURN-ключа

Затем откройте Actions → Deploy Worker → Run workflow.
Адрес Worker будет вида `https://zvonochek.<поддомен>.workers.dev`. Его нужно вписать в `WORKER_URL` в `config.js`.

Проверка: откройте `https://zvonochek.<поддомен>.workers.dev/health`. Должно быть `{"ok":true,...,"turn":true}`.
