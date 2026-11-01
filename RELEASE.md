# Выпуск v36 — что сделать владельцу

Порядок: **TURN → отзыв старых логинов → Worker → сайт → проверка.**
Клиент v36 совместим и с уже работающим Worker v32, поэтому сайт можно
публиковать сразу; TURN и деплой Worker — лучше в тот же день.

## 1. TURN: перенос в Worker (обязательно)

В v35 логины и пароли TURN лежали в `config.js` открытым текстом. В v36 их
в клиенте нет: короткоживущие ключи выдаёт ваш Worker по запросу `/turn`.
Без TURN звонки через «жёсткий» NAT (мобильный интернет, офисные сети)
пойдут через мост — только голос и с большей задержкой.

Достаточно одного варианта. Команды выполняются в корне репозитория.

**А. Cloudflare Realtime TURN — рекомендуется** (1000 ГБ в месяц бесплатно).
Панель Cloudflare → **Realtime** → **TURN Server** → **Create** → скопируйте
**Turn Token ID** и **API Token**:

```bash
npx wrangler secret put TURN_KEY_ID          # Turn Token ID
npx wrangler secret put TURN_KEY_API_TOKEN   # API Token
```

**Б. Metered.ca:** `METERED_DOMAIN` (например `myapp.metered.live`) и
`METERED_API_KEY` — тоже через `npx wrangler secret put`.

**В. Свой coturn:** `TURN_URLS` (через запятую, например
`turns:turn.example.org:443?transport=tcp,turn:turn.example.org:3478`),
`TURN_USERNAME`, `TURN_CREDENTIAL`.

Проверка: `https://<ваш-worker>/health` → `"turn": true`.

## 2. Отозвать старые логины TURN (обязательно)

Логины Metered (`global.relay.metered.ca`) и ExpressTURN
(`free.expressturn.com`) из v35 навсегда остались в истории публичного
репозитория — удаление из файла их не отзывает. В панелях Metered и
ExpressTURN удалите эти учётные данные или смените пароль. Новые сразу
кладите только в секреты Worker (шаг 1).

## 3. Деплой Worker v36

```bash
npx wrangler deploy        # из корня: wrangler.toml → worker/worker.js
```

Если подключены Workers Builds с корневой папкой `worker`, достаточно пуша:
`worker/wrangler.toml` совпадает с корневым (это проверяет `npm test`).
Новых миграций Durable Objects нет. Проверка: `/health` → `"v": 36`.

`ALLOWED_ORIGINS` (в `wrangler.toml`) — адреса сайтов через запятую, которым
Worker отвечает. Для своей копии сайта добавьте её адрес.

## 4. Публикация сайта

Залейте содержимое архива в ветку `main` репозитория (GitHub Pages обновится
сам; файл `.nojekyll` нужен). Проверка:
`https://qwkejkqwje1.github.io/zvonochek/version.json` → `{"v":36}`.
Открытые вкладки сами перезагрузятся на новую версию при следующем
открытии; Service Worker сменит кэш на `zvonochek-v36`.

## 5. Push при закрытом приложении (по желанию)

Пока приложение открыто, звонки и сообщения приходят и без этого шага.
Для push нужен секрет `VAPID_PRIVATE_JWK`. Публичный ключ клиент берёт у
Worker (`/push-key`), поэтому новую пару можно сгенерировать в любой момент:

```bash
node -e "crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign']).then(k=>crypto.subtle.exportKey('jwk',k.privateKey)).then(j=>console.log(JSON.stringify(j)))"
npx wrangler secret put VAPID_PRIVATE_JWK   # вставьте JSON из первой команды
```

Проверка: `/health` → `"push": true`; затем в приложении «Мой номер» →
«Включить уведомления о звонках» на каждом устройстве (на iPhone — после
установки на главный экран, iOS ≥ 16.4).

## 6. Проверка после выпуска (5 минут)

1. Два устройства в разных сетях (Wi-Fi и мобильный интернет): звонок по
   ссылке → в «Качестве связи» маршрут P2P или TURN, не «Мост».
2. Чат: сообщение, ответ, реакция, файл; закрыть и открыть вкладку —
   история на месте.
3. Во время звонка «Настройки» → «Журнал диагностики»: видно, какие каналы
   сигнала на связи (MQTT, Worker, Nostr, ntfy).
4. Личная ссылка: звонок на неё — рингтон на втором устройстве.

Перед публикацией разработчику: `npm ci && npm test` (и при наличии
Chromium — `npm run worker:dev` + `npm run e2e`).
