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
└── providers/
    ├── tronscan.py  # GET /api/accountv2 — метки бирж и контрактов
    ├── goplus.py    # GET /api/v1/address_security/{addr} — риск-флаги
    ├── flow.py      # GET /api/token_trc20/transfers — анализ контрагентов (связи с биржами)
    ├── ofac.py      # OFAC SDN TRX-список (0xB10C) — прямой матч санкционных адресов
    └── local.py     # ручные метки (наивысший приоритет)

api/main.py          # FastAPI + lifespan-запуск бота фоновой задачей
bot/main.py          # aiogram 3 — dp определён на верхнем уровне, импортируется из api/main.py
web/                 # index.html + static/{styles.css, app.js}
tests/test_core.py   # 21 тестов, моки на провайдеров через unittest.mock
```

## Поток данных

1. `check_address(addr)` валидирует TRC20 (base58check, префикс 0x41, длина 25 байт)
2. Смотрит SQLite-кеш (TTL из `CACHE_TTL_SECONDS`, по умолчанию 7 дней)
3. Параллельно (`asyncio.gather`) дёргает TronScan + GoPlus + flow (переводы) + OFAC-список
4. `_apply_tronscan` → `_apply_goplus` (только собирает флаги) → `_apply_flow` → `_compute_aml` → `_apply_local` (локальная БД имеет приоритет)
5. Записывает результат в кеш и возвращает `AddressVerdict`

### AML-модель (`_compute_aml` — централизованная риск-логика)

Все решения о `risk_level` / `risk_score` (0-100) приняты здесь, не в провайдерах.
- **Прямое попадание в OFAC SDN** → `EntityType.SANCTIONED`, скор 100, DANGEROUS.
- **GoPlus critical-флаг на адресе** (`CRITICAL_GOPLUS_FLAGS`) → скор 90, DANGEROUS, тип SCAM если был UNKNOWN.
- **Косвенная экспозиция** (1 хоп): доля объёма переводов с/на санкционные адреса → драйвер скора для НЕ-сервисов. Считается по сумме (`_amount`, нормализация по decimals; аппроксимация — оборот в основном USDT).
- **Entity-awareness (ключ против ложных срабатываний):** известные сервисы (`EXCHANGE`/`CONTRACT`) НЕ клеймятся грязными за КОСВЕННУЮ экспозицию (скор ≤10), но прямая санкция/скам роняет и их. Экспозиция всё равно показывается в `verdict.aml` для прозрачности.
- `verdict.aml`: `{direct_sanctioned, sanctions_exposure_pct, exchange_exposure_pct, other_exposure_pct, transfers_analyzed, sanctioned_counterparties, goplus_critical_flags}`.
- **2-й хоп** (`_fetch_hop2`): для кошельков/неизвестных раскрываем топ-`AML_HOP2_LIMIT` (12) неизвестных посредников по объёму, считаем ИХ санкционную экспозицию. Косвенная экспозиция = Σ(наша доля через посредника × его «грязность»), входит в скор с весом `HOP2_WEIGHT=0.6`. Биржи/контракты/прямые санкции НЕ раскрываем (бессмысленно + дорого). Отключается `AML_HOP2=0`. Параллельные запросы внутри одного `httpx.AsyncClient`.
- **Глубже 2 хопов / amount-в-USD** — задел на будущее (нужны платные AML-API типа Crystal/TRM для Crystal-grade точности).

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

**Депозитный адрес биржи** (`_detect_exchange_deposit`): депозитники бирж НЕ размечены тегами,
но узнаются по sweep-паттерну — сумма ПРИХОДИТ от стороннего адреса и ровно столько же УХОДИТ
на биржу (587.32 in → 587.32 out на Bybit, 400 → 400, …). Матчим входящие/исходящие суммы по
центам (sweep шлёт ровно полученный USDT — комиссия в TRX/energy, не в токене), требуем ≥2
совпадающих пар на ОДНУ биржу. При совпадении → `EntityType.EXCHANGE` «Депозитный кошелёк
{биржа}», `SAFE`, детали в `verdict.raw_labels.flow.deposit_pattern` (`{exchange, matched_pairs,
coverage}`). Центовое совпадение + порог ≥2 пары исключают ложняк на активных трейдерах. Если
sweep идёт на САНКЦИОННУЮ биржу — короткого замыкания нет: риск не маскируем, отдаём в
`_compute_aml` (категория `sanctioned_exchange`). Запускается в `_apply_flow` до WALLET-ветки.

## Команды для разработки

```bash
# Установить зависимости
pip install -r requirements.txt

# Прогнать тесты (должны быть все зелёные: 23/23)
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
| `CACHE_PATH` | нет | Путь к SQLite (по умолчанию `/data/cache.db`) |
| `CACHE_TTL_SECONDS` | нет | TTL кеша (по умолчанию 604800 = 7 дней) |
| `AML_HOP2` | нет | 2-хоп анализ связанных кошельков (по умолч. вкл; `0` — выкл) |
| `AML_HOP2_LIMIT` | нет | Сколько посредников раскрывать во 2-м хопе (по умолч. 12) |
| `AML_HOP2_CONCURRENCY` | нет | Лимит параллельных hop2-запросов к TronScan (по умолч. 4, чтобы не бить в QPS) |
| `PORT` | нет | Порт HTTP, Railway задаёт сам |

## Соглашения в коде

- **Python 3.12+**, type hints везде через `from __future__ import annotations`
- **async-first**: все провайдеры и кеш — async, через `httpx.AsyncClient` и `aiosqlite`
- **Никаких сторонних эффектов при импорте**: `dp` в `bot/main.py` создаётся на модульном уровне, но polling стартует только из `if __name__ == "__main__"` или явно из `api/main.py` через lifespan
- **Провайдер не падает на пользователя**: если внешний API недоступен, провайдер возвращает `{}` (см. `except httpx.HTTPError`). Агрегатор просто продолжит с тем, что есть
- **Свежесть по умолчанию везде** (AML требует актуальных транзакций): бот вызывает `check_address(addr, use_cache=False)`; REST-эндпоинт `/check/{addr}` тоже свежий по умолчанию, кеш включается только явным `?cache=true`. Веб-форма ходит через API → тоже свежая. Кеш-инфраструктура (SQLite на `/data`) сохранена для опционального использования

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
