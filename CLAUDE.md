# CLAUDE.md

Этот файл — контекст для Claude Code при работе с этим репозиторием.

## Что это за проект

TRC20 Address Checker — сервис определения принадлежности TRON-адреса (биржа / контракт / скам / неизвестный). Три интерфейса (REST API, Telegram-бот, веб-форма) поверх одного ядра.

Целевой деплой: **Railway** (один контейнер, API + бот в одном процессе, persistent volume на `/data`).

## Архитектура

```
core/                # ядро (без сторонних зависимостей кроме httpx + aiosqlite)
├── models.py        # AddressVerdict, RiskLevel, EntityType, is_valid_trc20_address (base58check)
├── aggregator.py    # check_address() — главная точка входа
├── cache.py         # SQLite-кеш на 7 дней
├── cluster.py       # накопительная кластеризация депозитников бирж (SQLite на /data)
├── balance.py       # извлечение балансов TRX/USDT из ответа TronScan
├── aml_external.py  # внешний AML #1 — Swapster (PUT /aml → POST /aml)
├── aml_bitok.py     # внешний AML #2 — Bitok KYT (HMAC-подпись, manual-checks)
└── providers/
    ├── tronscan.py  # GET /api/accountv2 — метки бирж и контрактов
    ├── goplus.py    # GET /api/v1/address_security/{addr} — риск-флаги
    ├── flow.py      # GET /api/token_trc20/transfers — анализ контрагентов (связи с биржами)
    ├── ofac.py      # OFAC SDN TRX-список (0xB10C) — прямой матч санкционных адресов
    └── local.py     # ручные метки (наивысший приоритет)

api/main.py          # FastAPI + lifespan-запуск бота фоновой задачей
bot/main.py          # aiogram 3 — dp определён на верхнем уровне, импортируется из api/main.py
web/                 # index.html + static/{styles.css, app.js}
tests/               # 69 тестов, моки на провайдеров через unittest.mock
```

## Поток данных

1. `check_address(addr)` валидирует TRC20 (base58check, префикс 0x41, длина 25 байт)
2. Смотрит SQLite-кеш (TTL из `CACHE_TTL_SECONDS`, по умолчанию 7 дней)
3. Параллельно (`asyncio.gather`) дёргает TronScan + GoPlus + flow (переводы) + OFAC-список
4. `_apply_tronscan` → `_apply_goplus` (только собирает флаги) → `_apply_flow` → `_compute_aml` → `_apply_local` (локальная БД имеет приоритет)
5. Внешние AML (Swapster + Bitok) — параллельно, если адрес не биржа/контракт; затем `_relabel_from_swapster` → `_label_from_bitok` → `_apply_external_aml_risk`
6. Записывает результат в кеш и возвращает `AddressVerdict`

### AML-модель (`_compute_aml` — централизованная риск-логика)

Все решения о `risk_level` / `risk_score` (0-100) приняты здесь, не в провайдерах.
- **Прямое попадание в OFAC SDN** → `EntityType.SANCTIONED`, скор 100, DANGEROUS.
- **GoPlus critical-флаг на адресе** (`CRITICAL_GOPLUS_FLAGS`) → скор 90, DANGEROUS, тип SCAM если был UNKNOWN.
- **Косвенная экспозиция** (1 хоп): доля объёма переводов с/на санкционные адреса → драйвер скора для НЕ-сервисов. Считается по сумме (`_amount`, нормализация по decimals; аппроксимация — оборот в основном USDT).
- **Entity-awareness (ключ против ложных срабатываний):** известные сервисы (`EXCHANGE`/`CONTRACT`) НЕ клеймятся грязными за КОСВЕННУЮ экспозицию (скор ≤10), но прямая санкция/скам роняет и их. Экспозиция всё равно показывается в `verdict.aml` для прозрачности.
- `verdict.aml`: `{direct_sanctioned, sanctions_exposure_pct, exchange_exposure_pct, other_exposure_pct, transfers_analyzed, sanctioned_counterparties, goplus_critical_flags}`.
- **2-й хоп** (`_fetch_hop2`): для кошельков/неизвестных раскрываем топ-`AML_HOP2_LIMIT` (12) неизвестных посредников по объёму, считаем ИХ санкционную экспозицию. Косвенная экспозиция = Σ(наша доля через посредника × его «грязность»), входит в скор с весом `HOP2_WEIGHT=0.6`. Биржи/контракты/прямые санкции НЕ раскрываем (бессмысленно + дорого). Отключается `AML_HOP2=0`. Параллельные запросы внутри одного `httpx.AsyncClient`.
- **Глубже 2 хопов / amount-в-USD** — задел на будущее (нужны платные AML-API типа Crystal/TRM для Crystal-grade точности).

### Внешние AML-сервисы (Swapster + Bitok)

Два независимых KYT-провайдера, оба вызываются **параллельно** в конце `check_address`
и кладутся в вердикт: `verdict.external_aml` (Swapster, `core/aml_external.py`) и
`verdict.bitok_aml` (Bitok, `core/aml_bitok.py`). Формат ответа у обоих **одинаковый**,
поэтому бот и веб рисуют их одним кодом:

```
{available, provider, pending, risk_score(0-100|None), risk_level(safe|caution|dangerous),
 level_raw, entity, entity_category, entity_category_ru, entities[], reason, details}
```

- **Туннель** (`_AML_SKIP_TYPES` = `EXCHANGE`/`CONTRACT`): для бирж, их депозитников и
  контрактов платные KYT НЕ дёргаем — их AML-скор ничего не говорит о владельце, а именно
  таких проверок больше всего. Скам/санкции туннель НЕ отсекает: там второе мнение ценно.
  В вердикте вместо результата лежит `{"skipped": true, "reason": ...}`.
- **Bitok** (`core/aml_bitok.py`): HMAC-SHA256-подпись (`API-KEY-ID` / `API-TIMESTAMP` мс /
  `API-SIGNATURE` = base64(HMAC(secret, `METHOD\nENDPOINT\nTS[\nBODY]`))). Флоу:
  `POST /v1/manual-checks/check-address/` → поллинг `GET /v1/manual-checks/{id}/` до
  `check_status == "checked"` → best-effort `address-exposure/` (имя сущности) и `risks/`
  (категории экспозиции). Родная шкала `none|low|medium|high|severe` → наша
  `safe|caution|dangerous`. Тело шлём ровно той compact-JSON строкой, что подписали —
  иначе 401.
- **`_label_from_bitok`**: Bitok знает off-chain имя сущности («Tether blacklist», «Binance»)
  там, где у TronScan метки нет. Ставим её ТОЛЬКО если своей метки нет вообще
  (`entity_type == UNKNOWN` и `entity` пусто/«No public labels»); категория маппится в тип
  через `_BITOK_CATEGORY_TYPE`.
- **`_apply_external_aml_risk`**: внешний AML может только **поднять** итоговый вердикт
  (`caution`/`dangerous` → `verdict.risk_level`, `risk_score = max(...)`, плюс поясняющий
  флаг). Понижать нельзя: чистый ответ KYT не отменяет наши on-chain находки, а `UNKNOWN`
  («меток нет») не должен превращаться в «безопасно» из-за отсутствия данных у сервиса.
  Выключается `EXTERNAL_AML_AFFECTS_RISK=0` (сервисы остаются в выводе, вердикт не трогают).

### flow-анализ (связи с биржами)

`_apply_flow` смотрит последние ~50 TRC20-переводов и считает контрагентов с биржевыми
метками (через `EXCHANGE_KEYWORDS`). Если адрес не опознан сильнее (контракт/прямая
метка/скам), он помечается `EntityType.WALLET` — «Кошелёк (связан с Bybit/...)», а связи
кладутся в `verdict.exchange_links` (`[{name, deposits, withdrawals, total}]`).
Это **эвристика**: «часто шлёт на Bybit» ≠ «принадлежит Bybit». Сам адрес — это кошелёк
пользователя, а не биржа; метку имеет контрагент перевода.

**Биржа vs личный кошелёк** (частый вопрос): решает, ЧЕЙ адрес помечен. Если `publicTag`
у САМОГО адреса → `EXCHANGE` (проверяется первым в `_apply_tronscan`). Если помечен только
контрагент → `WALLET` «Личный кошелёк (связан с …)» + флаг «не биржа». Нетегированный сервис
ловим эвристикой: `totalTransactionCount > 50000` → «Возможно сервис/биржа (нетегирован)».

**Депозитный/транзитный адрес биржи** (`_detect_exchange_deposit`): депозитники бирж НЕ размечены
тегами, но узнаются по **funnel-паттерну** (поведение «deposit address», как у Arkham/Chainalysis,
но без их off-chain кластеризации — только on-chain эвристика):
- адрес ПОЛУЧАЕТ средства от сторонних адресов и пересылает почти весь отток на ОДНУ биржу
  (концентрация оттока ≥ `DEPOSIT_CONCENTRATION` = 0.9);
- сам ОТ этой биржи ничего не получает — иначе это личный торговый кошелёк (и заводит, и выводит).
  Это ключевой дискриминатор против ложняка;
- транзит: пересылает ≥ `DEPOSIT_FORWARD_RATIO` (0.5) полученного, ≥2 входящих перевода.

Суммы НЕ обязаны совпадать 1:1 — депозитник часто **агрегирует** несколько приходов в один вывод
(4129.33 + 10 + 20 → 4159.33 на Bybit), поэтому смотрим концентрацию и пересылку по ОБЪЁМУ, а не
совпадение сумм (старый sweep-1:1 остался только как `matched_pairs` для UI). При совпадении →
`EntityType.EXCHANGE` «Депозитный кошелёк {биржа}», `SAFE`, детали в
`verdict.raw_labels.flow.deposit_pattern` (`{exchange, concentration, forwarded_pct, in_sources,
matched_pairs, sanctioned}`). Запускается в `_apply_flow` до WALLET-ветки. **Санкционная биржа**
(HTX и т.п.): метку депозитника ставим так же, но риск НЕ маскируем — `deposit_pattern.sanctioned`
поднимает адрес в `_compute_aml` (через `self_sanctioned_exch`) до `EntityType.SANCTIONED`, скор
100, `DANGEROUS`.

### Кластеризация депозитников (`core/cluster.py` + `_apply_cluster`)

On-chain deposit-clustering (как у Arkham, но без их off-chain интела — common-input/co-spend на
TRON неприменим, это account-модель). Когда `_detect_exchange_deposit` опознаёт депозитник, он
возвращает **якорь** `deposit_pattern.hot_wallet` — адрес хот/сборного кошелька биржи, на который
уходит больше всего оттока. `_apply_cluster` пишет `address → {exchange, hot_wallet, sanctioned}`
в `core/cluster.py` (SQLite на `/data/cluster.db`, отдельный от кеша файл) и дополняет вердикт:
`verdict.raw_labels.cluster = {exchange, hot_wallet, siblings_on_anchor, siblings_sample,
known_deposits_exchange}`. Разные депозитники ОДНОЙ биржи пересылают на ОДИН якорь, поэтому БД
со временем растёт в граф — по якорю видно, сколько родственных депозитных адресов уже
атрибутировано (`siblings_on_anchor` — точный сигнал по хот-кошельку, `known_deposits_exchange`
— шире по имени биржи). Провайдер необязательный: любая ошибка SQLite ловится и НЕ роняет проверку
(в тестах без `/data` просто деградирует — `cluster` не добавляется). Инициализация БД —
`cluster.init_db()` в lifespan `api/main.py` и в `bot/main.py` рядом с `cache.init_db()`.

## Команды для разработки

```bash
# Установить зависимости
pip install -r requirements.txt

# Прогнать тесты (должны быть все зелёные: 69/69)
pytest -v

# Локальный запуск (API + bot, если BOT_TOKEN задан; иначе только API)
export BOT_TOKEN=...           # опционально
export CACHE_PATH=./cache.db   # для локальной разработки, чтобы не писать в /data
uvicorn api.main:app --reload

# Smoke test API
curl http://localhost:8000/health
curl http://localhost:8000/check/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
```

## Переменные окружения

| Имя | Обязательно | Что делает |
|---|---|---|
| `BOT_TOKEN` | нет (но бот без него выключен) | Токен Telegram-бота от @BotFather |
| `TRONSCAN_API_KEY` | нет | Повышает лимиты TronScan API |
| `GOPLUS_API_KEY` | нет | Повышает лимиты GoPlus API |
| `API_KEY` | нет | Если задано — REST API требует `?api_key=...` |
| `ALLOWED_TG_IDS` | **да, иначе бот никого не пустит** | Белый список Telegram user_id (через запятую/пробел). Единственный способ попасть в бота: пусто = закрыт для всех (fail-closed) |
| `WEB_PASSWORD` | нет | Пароль на веб-сайт (HTTP Basic Auth на `/` и `/check`). Пусто = сайт открыт |
| `WEB_USER` | нет | Логин для веб-пароля (по умолчанию `admin`) |
| `CACHE_PATH` | нет | Путь к SQLite-кешу (по умолчанию `/data/cache.db`) |
| `CLUSTER_PATH` | нет | Путь к SQLite кластеризации депозитников (по умолчанию `/data/cluster.db`) |
| `CACHE_TTL_SECONDS` | нет | TTL кеша (по умолчанию 604800 = 7 дней) |
| `AML_HOP2` | нет | 2-хоп анализ связанных кошельков (по умолч. вкл; `0` — выкл) |
| `AML_HOP2_LIMIT` | нет | Сколько посредников раскрывать во 2-м хопе (по умолч. 12) |
| `AML_HOP2_CONCURRENCY` | нет | Лимит параллельных hop2-запросов к TronScan (по умолч. 4, чтобы не бить в QPS) |
| `SWAPSTER_API_TOKEN` | нет (без него Swapster «не настроен») | Токен AML-API Swapster |
| `SWAPSTER_API_BASE_URL` | нет | По умолчанию `https://api.swapster.fi` (тест: `https://test-api.swapster.fi`) |
| `SWAPSTER_PROXY_URL` | нет | Прокси со статичным IP под whitelist Swapster |
| `SWAPSTER_TIMEOUT_SECONDS` | нет | Таймаут Swapster (по умолч. 30) |
| `BITOK_API_KEY_ID` | нет (без него Bitok «не настроен») | API Key ID из кабинета Bitok KYT |
| `BITOK_API_SECRET` | нет | API Secret (показывается один раз при создании ключа) |
| `BITOK_API_BASE_URL` | нет | По умолчанию `https://kyt-api.bitok2.org` (контур РФ) |
| `BITOK_NETWORK` | нет | Сеть для проверки (по умолч. `TRX`) |
| `BITOK_TIMEOUT_SECONDS` | нет | Общий таймаут проверки Bitok, он же бюджет поллинга (по умолч. 45) |
| `EXTERNAL_AML_AFFECTS_RISK` | нет | `0` — внешние AML показываются, но не меняют итоговый вердикт (по умолч. влияют) |
| `AML_EXCHANGE_ENTITY_THRESHOLD` | нет | Доля биржевой сущности Swapster, при которой транзит помечается биржей (по умолч. 0.9) |
| `PORT` | нет | Порт HTTP, Railway задаёт сам |

## Соглашения в коде

- **Python 3.12+**, type hints везде через `from __future__ import annotations`
- **async-first**: все провайдеры и кеш — async, через `httpx.AsyncClient` и `aiosqlite`
- **Никаких сторонних эффектов при импорте**: `dp` в `bot/main.py` создаётся на модульном уровне, но polling стартует только из `if __name__ == "__main__"` или явно из `api/main.py` через lifespan
- **Провайдер не падает на пользователя**: если внешний API недоступен, провайдер возвращает `{}` (см. `except httpx.HTTPError`). Агрегатор просто продолжит с тем, что есть
- **Свежесть по умолчанию везде** (AML требует актуальных транзакций): бот вызывает `check_address(addr, use_cache=False)`; REST-эндпоинт `/check/{addr}` тоже свежий по умолчанию, кеш включается только явным `?cache=true`. Веб-форма ходит через API → тоже свежая. Кеш-инфраструктура (SQLite на `/data`) сохранена для опционального использования
- **Доступ к боту только по TG ID** (`bot/main.py`): `AccessMiddleware` висит и на `dp.message`, и на `dp.callback_query` (инлайн-кнопки тоже под гейтом) и зовёт `_is_allowed` — **fail-closed**: пропускаем ТОЛЬКО user_id из `ALLOWED_TG_IDS`, пустой список = бот закрыт для всех, апдейт без пользователя (анонимный админ канала) = отказ. Открытого дефолта нет намеренно: каждая проверка жжёт платные лимиты KYT. Незнакомцу в отказе показывается его собственный user_id (в колбэке — алертом, иначе у него крутится спиннер), админ добавляет id в env и передеплоивает. Строку о режиме доступа при старте печатает общий `log_access_mode()` (зовут и `main()`, и lifespan `api/main.py`) — три ветки: список разобран → info; задан, но ни один id не распознан → error с сырым значением (частая ошибка: кавычки из raw-редактора Railway, `@username`, id канала — `_parse_ids` их срезает/отбрасывает); не задан → error. Размер белого списка виден в `/health` (`bot_whitelist`), чтобы пустой список диагностировался без логов. Отказ отправляется best-effort (ошибка Telegram API гасится — юзер мог заблокировать бота), но выход из обработчика безусловный. Тесты `test_access_middleware_registered_on_dispatcher` и `test_every_observer_with_handlers_is_gated` проверяют саму проводку на живом `dp`: тесты класса в отрыве от `dp` пропускают удаление регистрации
- **Пароль на веб-сайт** (`api/main.py`): `require_web_auth` (HTTP Basic Auth, `secrets.compare_digest`) на `/` и `/check`. Включается `WEB_PASSWORD` (+`WEB_USER`, по умолч. `admin`); пусто = сайт открыт. `/health` НЕ закрыт (нужен Railway-healthcheck'у). Веб-форма ходит на `/check` относительным URL → браузер сам дошлёт Basic-креды того же origin. Бот не затронут — он зовёт `check_address()` напрямую, мимо HTTP

## Интерфейс бота (`bot/main.py`)

Одно сообщение = весь вердикт. Порядок блоков (`format_verdict`):

1. Шапка: `🔴 ОПАСНО · риск 87/100` + шкала `▰▰▰▰▰▰▰▰▱▱` (`_score_bar`)
2. Сущность, тип, адрес в `<code>` (копируется тапом), баланс USDT/TRX
3. **⚠️ Что нашли** — `verdict.risk_flags` (первые 8), технические флаги провайдеров
   переводятся в русский через `_flag_ru`
4. **🏦 Связи с биржами** — `verdict.exchange_links` (топ-5, санкционные помечены)
5. **🧭 Экспозиция** — разбивка объёма из `verdict.aml` + строка 2-го хопа
6. **🔗 Кластер** — `raw_labels.cluster` (сколько родственных депозитников известно)
7. **🔍 AML-сервисы** — Swapster и Bitok одним рендером (`_aml_provider_lines`)
8. Источники

Правила: весь пользовательский текст экранируется (`_esc`) — метки приходят из внешних
API; длина режется по `TG_MESSAGE_LIMIT` (4096). Пока идёт проверка (десятки секунд из-за
двух KYT), бот шлёт сообщение-прогресс и **правит его же** готовым вердиктом. Под вердиктом
инлайн-кнопки: «🔄 Перепроверить» (callback `recheck:{address}`, хендлер `on_recheck`
правит то же сообщение; «message is not modified» — нормальный исход) и ссылка на TronScan.
`AccessMiddleware` навешен и на `dp.message`, и на `dp.callback_query`.

## Как добавить новый провайдер

1. Создать `core/providers/новый.py` с async-функцией `fetch_*(address, client) -> dict`
2. В `core/aggregator.py`:
   - Импортировать
   - Добавить в `asyncio.gather` рядом с tronscan/goplus
   - Написать `_apply_новый(data, verdict)` (по образцу существующих)
   - Вызвать после `_apply_goplus`, до `_apply_local` (локальные метки всегда последние)
3. Добавить тест в `tests/test_core.py` с моком через `unittest.mock.AsyncMock`

## Как добавить новую биржу для распознавания

`core/aggregator.py` → словарь `EXCHANGE_KEYWORDS`. Ключ — подстрока в `publicTag` от TronScan в нижнем регистре, значение — каноническое имя для UI.

## Санкционные биржи (`SANCTIONED_EXCHANGES`)

`core/aggregator.py` → `SANCTIONED_EXCHANGES` — биржи под санкциями (UK A7-пакет 26.05.2026: HTX/Huobi, EXMO, Bitpapa, Rapira, Aifory, Arvix, ABCEX; OFAC: Garantex/Grinex/Cryptex). Ловятся по тегам TronScan: и сам хот-кошелёк (→ `EntityType.SANCTIONED`, скор 100), и переводы с/на них через flow (категория `sanctioned_exchange` в экспозиции, поднимает риск). Чтобы добавить биржу — впиши `подстрока_тега: "Каноническое имя"`. UK санкционирует юрлица (адреса публикуются не всегда), поэтому покрытие = тегированные хот-кошельки + экспозиция, а не каждый адрес.

## Реальная структура ответа TronScan `accountv2` (важно для `_apply_tronscan`)

Проверено на живом API (нужен `TRONSCAN_API_KEY`):

| Тип адреса | `accountType` | Как распознать | Где имя |
|---|---|---|---|
| Контракт | `2` | сам адрес присутствует ключом в `contractMap` со значением `true` | `name` (напр. `"TetherToken"`) |
| Биржа / размеченный | `0` | `publicTag` / `addressTag` (напр. `"Binance-Hot 4"`, `"HTX 1"`) | `publicTag` |
| Неразмеченный (в т.ч. депозитники бирж) | `0` | тегов нет (`publicTag: null`) | — → `unknown` |

- **Поля `isContract` в ответе НЕТ** — не полагаться на него (была причина бага: контракты не определялись).
- `publicTag`/`addressTag` могут приходить как `null`, а не `""` — фильтровать через `if v`.
- Депозитные адреса бирж индивидуальны и **не размечены** — корректный ответ `unknown`, не баг.

## Известные ограничения

- **Нельзя определить клиентский кошелёк** (TronLink, Trust Wallet и т.д.) — это софт, а не on-chain сущность
- **Приватные кошельки без меток вернутся как `unknown`** — это by design (приватность TRON)
- **Для compliance-grade точности** нужны платные источники (Arkham, TRM, Chainalysis) — структура агрегатора готова к их добавлению

## Деплой на Railway

См. README.md. Ключевые моменты:
- Билдится из `Dockerfile` (Railway автодетектит)
- `railway.json` задаёт healthcheck `/health` и restart policy
- **Обязательно добавить volume на `/data`** иначе SQLite-кеш умрёт при каждом деплое
- `PORT` Railway передаёт сам — в Dockerfile `CMD` использует `${PORT:-8000}`
- **НЕ задавать `startCommand` в `railway.json`** — Railway запускает его без шелла, и `$PORT` не разворачивается (uvicorn падает `Invalid value for '--port': '$PORT'`). Команду берём из `Dockerfile` `CMD` (shell-форма, `${PORT:-8000}` разворачивается)
- **`TRONSCAN_API_KEY` теперь де-факто обязателен**: без ключа эндпоинт `/api/accountv2` отдаёт `401 Unauthorized`, метки бирж/контрактов не приходят, и всё определяется как `unknown`. Ключ берётся бесплатно на tronscan.org → My Account → API Keys. GoPlus при этом работает без ключа (отдаёт только риск-флаги, не метки сущностей)

## Что НЕ делать

- Не запускать бот отдельным процессом на Railway — поломается shared cache между API и ботом. Если в будущем понадобится разделение, перевести кеш с SQLite на Postgres или Redis
- Не коммитить `.env` с реальным `BOT_TOKEN` — в `.gitignore` он уже указан, но проверять перед каждым коммитом
- Не убирать `if __name__ == "__main__"` в `bot/main.py` — иначе при импорте модуля из API запустятся два poll-а параллельно и Telegram отдаст 409 Conflict
