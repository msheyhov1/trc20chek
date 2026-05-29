# TRC20 Address Checker — Railway edition

Один сервис (FastAPI + Telegram-бот в одном процессе), готовый к деплою на Railway.

## Что внутри

- **REST API** (`FastAPI`) на корневом URL — `GET /check/{address}`
- **Telegram-бот** запускается фоновой задачей того же процесса
- **Веб-форма** — на корне `/`
- **SQLite кеш** — на персистентном диске Railway (`/data/cache.db`)

## Деплой на Railway: по шагам

### 1. Загрузить код на GitHub

Создайте на GitHub пустой репозиторий, например `trc20-checker`. Затем локально:

```bash
cd trc20-checker
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/ВАШ_USER/trc20-checker.git
git push -u origin main
```

### 2. Создать проект в Railway

1. Откройте <https://railway.app> → Sign in (через GitHub)
2. **New Project** → **Deploy from GitHub repo**
3. Выберите ваш `trc20-checker`
4. Railway автоматически найдёт `Dockerfile` и начнёт сборку

### 3. Добавить переменные окружения

В дашборде сервиса → **Variables** → **+ New Variable**:

| Имя | Значение |
|---|---|
| `BOT_TOKEN` | Токен от @BotFather (обязательно) |
| `TRONSCAN_API_KEY` | (опционально) |
| `GOPLUS_API_KEY` | (опционально) |
| `API_KEY` | (опционально, защита API) |
| `CACHE_TTL_SECONDS` | `604800` |

### 4. Добавить персистентный диск

Без этого кеш будет теряться при каждом редеплое.

В дашборде сервиса → **Settings** → **Volumes** → **+ New Volume**:
- **Mount path:** `/data`
- Размер: 1 GB (бесплатного хватит надолго)

После добавления Railway пересоберёт сервис.

### 5. Сделать API публично доступным

В **Settings** → **Networking** → **Generate Domain**.
Получите ссылку вида `https://trc20-checker-production.up.railway.app`.

### 6. Проверка

Откройте в браузере:
- `https://ваш-домен/health` — должно быть `{"status":"ok","bot_enabled":true}`
- `https://ваш-домен/` — веб-форма
- `https://ваш-домен/check/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` — проверка USDT-контракта

И напишите вашему боту в Telegram — он ответит.

## Локальная разработка (опционально)

```bash
pip install -r requirements.txt
export BOT_TOKEN=  # можно пустым — будет API-only mode
export CACHE_PATH=./cache.db
uvicorn api.main:app --reload
```

## Тесты

```bash
pytest -v
```

11 тестов, проверяют валидацию TRC20, агрегацию провайдеров, обнаружение биржи/контракта/скама.

## Кастомизация

См. `core/providers/local.py` — туда можно добавлять собственные метки (имеют наивысший приоритет).

См. `core/aggregator.py` → `EXCHANGE_KEYWORDS` — список бирж для нормализации.

## Стоимость

- Бесплатный тариф Railway: **$5 кредитов/месяц** (хватит на ваш сценарий — 100 запросов/день)
- Если выйдете за лимит — Pro $5/мес + потребление поверх (мизер для такого приложения)
