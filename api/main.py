"""FastAPI + Telegram-бот в одном процессе (вариант для Railway).

API живёт на HTTP-порту, а бот стартует фоновой asyncio-задачей
при старте приложения. Один контейнер, один деплой, один диск.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

from api.ratelimit import RateLimiter
from core import check_address, history, labels, watchlist
from core.aggregator import RULESET_VERSION
from core.cache import init_db
from core.cluster import init_db as init_cluster_db
from core.models import is_valid_trc20_address
from core.providers.local import LOCAL_LABELS

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")

API_KEY = os.getenv("API_KEY", "")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
WEB_DIR = Path(__file__).parent.parent / "web"

# Пароль на веб-сайт (HTTP Basic Auth). Пусто = гейт выключен (сайт открыт).
WEB_PASSWORD = os.getenv("WEB_PASSWORD", "")
WEB_USER = os.getenv("WEB_USER", "admin")
# Осознанное согласие держать сайт открытым без пароля и без API-ключа.
# Без него незащищённый /check отвечает 503: каждая проверка тратит платные
# лимиты KYT, поэтому «открыт всем по умолчанию» — неприемлемый дефолт (у бота
# гейт fail-closed, здесь теперь так же).
WEB_PUBLIC = os.getenv("WEB_PUBLIC", "") not in ("", "0", "false", "False")
# Разрешить CORS с любого origin. По умолчанию выключено: веб-форма ходит на
# свой же origin относительным URL и в CORS не нуждается.
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
# Сколько адресов принимает POST /check/batch за один запрос.
BATCH_MAX = int(os.getenv("BATCH_MAX_ADDRESSES", "25"))
# Сколько прокси перед приложением ДОПИСЫВАЮТ адрес в X-Forwarded-For. У Railway
# это один край. 0 — заголовок не читать вовсе (прямой доступ без прокси).
TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "1"))

_basic = HTTPBasic(auto_error=False)
limiter = RateLimiter()

# Состояние локальных хранилищ: заполняется в lifespan, видно в /health.
storage_status: dict[str, str] = {
    "cache": "unknown",
    "cluster": "unknown",
    "history": "unknown",
    "labels": "unknown",
    "watchlist": "unknown",
}


def require_web_auth(
    credentials: HTTPBasicCredentials | None = Depends(_basic),
) -> None:
    """Гейт сайта по логину/паролю. Если WEB_PASSWORD не задан — пропускаем всех.
    Сравнение через secrets.compare_digest (защита от timing-атак)."""
    if not WEB_PASSWORD:
        return
    ok = credentials is not None and secrets.compare_digest(
        credentials.username, WEB_USER
    ) and secrets.compare_digest(credentials.password, WEB_PASSWORD)
    if not ok:
        raise HTTPException(
            status_code=401,
            detail="Требуется авторизация",
            headers={"WWW-Authenticate": 'Basic realm="TRC20 Checker"'},
        )


def is_protected() -> bool:
    """Закрыт ли сервис хоть чем-нибудь: паролем, API-ключом или явным согласием."""
    return bool(WEB_PASSWORD or API_KEY or WEB_PUBLIC)


def client_ip(request: Request) -> str:
    """IP клиента за доверенными прокси.

    Каждый прокси ДОПИСЫВАЕТ адрес в конец X-Forwarded-For, а начало заголовка
    присылает сам клиент — и может написать туда что угодно. Раньше брался
    ПЕРВЫЙ адрес: лимит «2 проверки на IP» пропускал 10 из 10 запросов, если
    менять заголовок. Верим только последним TRUSTED_PROXY_HOPS записям."""
    fwd = request.headers.get("x-forwarded-for", "")
    parts = [p.strip() for p in fwd.split(",") if p.strip()]
    if parts and TRUSTED_PROXY_HOPS > 0:
        return parts[max(0, len(parts) - TRUSTED_PROXY_HOPS)]
    return request.client.host if request.client else "unknown"


async def _run_bot():
    """Запускает Telegram-бота. Импортируем модуль лениво,
    чтобы API мог стартовать без BOT_TOKEN (на этапе теста)."""
    if not BOT_TOKEN:
        log.warning("BOT_TOKEN not set — Telegram bot disabled, API-only mode")
        return
    try:
        from aiogram import Bot

        from bot.main import dp, log_access_mode

        log_access_mode(log)
        bot = Bot(BOT_TOKEN)
        log.info("Starting Telegram bot polling...")
        await dp.start_polling(bot)
    except asyncio.CancelledError:
        log.info("Bot polling cancelled")
        raise
    except Exception:
        log.exception("Bot crashed")


async def _run_watchlist(stop: asyncio.Event) -> None:
    """Фоновая перепроверка наблюдаемых адресов.

    Живёт в том же процессе намеренно: отдельный процесс завёл бы второй
    polling бота, и Telegram ответил бы 409 Conflict."""
    if not watchlist.is_enabled() or storage_status.get("watchlist") != "ok":
        return
    if not BOT_TOKEN:
        log.info("Мониторинг адресов: BOT_TOKEN не задан, уведомлять некуда")
        return
    from aiogram import Bot
    from aiogram.enums import ParseMode

    bot = Bot(BOT_TOKEN)

    async def notify(chat_id: int, text: str) -> None:
        await bot.send_message(chat_id, text, parse_mode=ParseMode.HTML)

    async def check(address: str):
        return await check_address(address, use_cache=False, source="watchlist")

    try:
        await watchlist.run_loop(check, notify, stop)
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("Мониторинг адресов остановлен из-за ошибки")
    finally:
        await bot.session.close()


async def _init_storage(name: str, init) -> None:
    """Инициализация НЕобязательного хранилища.

    Кеш выключен по умолчанию (свежесть везде), а кластеризация и так глушит
    любые ошибки SQLite. Раньше сбой init_db ронял старт целиком: не подключённый
    volume или read-only диск превращались в restart-loop из-за опциональной
    функции. Теперь сервис поднимается и честно показывает деградацию в /health."""
    try:
        await init()
        storage_status[name] = "ok"
    except Exception as e:
        storage_status[name] = "unavailable"
        what = {
            "cache": "кеш проверок выключен",
            "cluster": "кластеризация депозитников выключена",
            "history": "журнал проверок не ведётся",
            "labels": "ручные метки недоступны",
            "watchlist": "мониторинг адресов выключен",
        }.get(name, f"{name} выключено")
        log.error(
            "Хранилище %s недоступно (%s): сервис работает, но %s. "
            "Проверьте, что volume смонтирован на /data (см. DEPLOY_PLAN.md).",
            name, e, what,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _init_storage("cache", init_db)
    await _init_storage("cluster", init_cluster_db)
    await _init_storage("history", history.init_db)
    # Предзаданные метки из local.py засеваются в БД, не перетирая правки оператора.
    await _init_storage("labels", lambda: labels.init_db(LOCAL_LABELS))
    await _init_storage("watchlist", watchlist.init_db)
    await history.prune()
    if WEB_PASSWORD:
        log.info("Web auth ENABLED (user=%s)", WEB_USER)
    elif API_KEY:
        log.info("Web password не задан, но включена защита API_KEY")
    elif WEB_PUBLIC:
        log.warning(
            "Сайт ОТКРЫТ всем (WEB_PUBLIC=1). Каждая проверка тратит платные "
            "лимиты KYT; действуют лимиты %s", limiter.stats()
        )
    else:
        log.error(
            "Ни WEB_PASSWORD, ни API_KEY не заданы — /check отвечает 503. "
            "Задайте пароль/ключ либо WEB_PUBLIC=1, если сайт должен быть открыт."
        )
    bot_task = asyncio.create_task(_run_bot())
    watch_stop = asyncio.Event()
    watch_task = asyncio.create_task(_run_watchlist(watch_stop))
    try:
        yield
    finally:
        watch_stop.set()
        for task in (bot_task, watch_task):
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass


app = FastAPI(
    title="TRC20 Address Checker",
    version="2.0.0",
    description="Определение принадлежности TRC20-адреса (биржа / контракт / скам).",
    lifespan=lifespan,
    # Схему API закрываем тем же гейтом, что и сайт: при заданном WEB_PASSWORD
    # публичный /docs выдавал устройство сервиса всем желающим.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )


@app.get("/health")
async def health():
    # Размер белого списка — чтобы пустой ALLOWED_TG_IDS было видно без логов
    # (бот при этом «здоров», но не отвечает никому). Импорт ленивый и мягкий:
    # healthcheck Railway не должен падать из-за бота.
    try:
        from bot.main import ALLOWED_TG_IDS

        whitelist = len(ALLOWED_TG_IDS)
    except Exception:  # pragma: no cover — аварийный путь импорта
        whitelist = None
    return {
        "status": "ok",
        "bot_enabled": bool(BOT_TOKEN),
        "bot_whitelist": whitelist,
        # Что реально сконфигурировано — чтобы «почему всё unknown» не требовало логов
        "providers": _provider_config(),
        "storage": dict(storage_status),
        "web_protected": is_protected(),
        "rate_limit": limiter.stats(),
    }


def _provider_config() -> dict[str, bool]:
    """Какие источники сконфигурированы. Отсутствие ключа — штатная причина
    того, что вердикты выходят пустыми, и её надо видеть без чтения логов."""
    from core import aml_bitok, aml_external
    from core.providers import flow, goplus

    return {
        "tronscan_key": bool(flow.TRONSCAN_API_KEY),
        "goplus_key": bool(goplus.GOPLUS_API_KEY),
        "swapster": aml_external.is_configured(),
        "bitok": aml_bitok.is_configured(),
    }


def _authorize(
    request: Request, api_key: str | None, cost: int = 1, record: bool = True
) -> bool:
    """Проверка ключа (заголовок X-API-Key или ?api_key=) и лимитов.

    Возвращает True, если запрос идёт под лимитами (публичный доступ), — тогда
    вызывающий списывает квоту через _consume за каждую РЕАЛЬНУЮ проверку.
    `cost` — сколько проверок нужно, чтобы отказать сразу, а не на середине."""
    if API_KEY:
        header_key = request.headers.get("x-api-key")
        # Query-параметр оставлен для совместимости, но он попадает в логи и
        # историю браузера — заголовок предпочтительнее.
        provided = header_key or api_key
        if not provided or not secrets.compare_digest(provided, API_KEY):
            raise HTTPException(status_code=401, detail="Invalid API key")
        return False
    if not is_protected():
        raise HTTPException(
            status_code=503,
            detail=(
                "Сервис не сконфигурирован для публичного доступа: задайте "
                "WEB_PASSWORD или API_KEY, либо WEB_PUBLIC=1, если он должен быть открыт."
            ),
        )
    allowed, reason = limiter.check(client_ip(request), max(1, cost))
    if not allowed:
        raise HTTPException(status_code=429, detail=reason)
    if record:
        _consume(request)
    return True


def _consume(request: Request) -> None:
    """Списать одну проверку с лимитов."""
    limiter.record(client_ip(request))


def _authorize_read(request: Request, api_key: str | None) -> None:
    """Гейт для читающих эндпоинтов. Лимит проверок к ним не применяется: они
    не тратят платные лимиты KYT, ограничивать их незачем."""
    if API_KEY:
        provided = request.headers.get("x-api-key") or api_key
        if not provided or not secrets.compare_digest(provided, API_KEY):
            raise HTTPException(status_code=401, detail="Invalid API key")
        return
    if not is_protected():
        raise HTTPException(
            status_code=503,
            detail=(
                "Сервис не сконфигурирован для публичного доступа: задайте "
                "WEB_PASSWORD или API_KEY, либо WEB_PUBLIC=1."
            ),
        )


@app.get("/check/{address}")
async def check(
    request: Request,
    address: str,
    cache: bool = Query(False, description="Использовать кеш (по умолчанию выкл — всегда свежие данные для AML)"),
    api_key: str | None = Query(None, description="API key (лучше передавать заголовком X-API-Key)"),
    _auth: None = Depends(require_web_auth),
):
    limited = _authorize(request, api_key, record=False)
    if not is_valid_trc20_address(address):
        # Опечатка в адресе квоту не тратит: проверки не было.
        raise HTTPException(status_code=400, detail="Invalid TRC20 address format")
    if limited:
        _consume(request)

    # По умолчанию свежий запрос (AML требует актуальных транзакций).
    # Кеш — только по явному ?cache=true.
    verdict = await check_address(address, use_cache=cache)
    return verdict.to_dict()


@app.post("/check/batch")
async def check_batch(
    request: Request,
    addresses: list[str] = Body(..., embed=True, description="Список TRC20-адресов"),
    api_key: str | None = Query(None, description="API key (лучше заголовком X-API-Key)"),
    _auth: None = Depends(require_web_auth),
):
    """Пакетная проверка. Проверки идут ПОСЛЕДОВАТЕЛЬНО: каждая тратит платные
    лимиты KYT, и параллельный запуск упёрся бы в них же, только быстрее."""
    if len(addresses) > BATCH_MAX:
        raise HTTPException(
            status_code=400,
            detail=f"За раз можно проверить не больше {BATCH_MAX} адресов",
        )
    # Лимит списывается за каждый ПРОВЕРЕННЫЙ адрес: иначе батч обходил бы
    # защиту квоты. Но сначала — хватит ли квоты на весь пакет: раньше пакет
    # падал на середине, а уже списанное пропадало без единой проверки.
    valid = [a for a in addresses if is_valid_trc20_address(a)]
    limited = _authorize(request, api_key, cost=len(valid), record=False)

    results = []
    for addr in addresses:
        if not is_valid_trc20_address(addr):
            results.append({"address": addr, "error": "Invalid TRC20 address format"})
            continue
        if limited:
            _consume(request)
        verdict = await check_address(addr, use_cache=False, source="batch")
        results.append(verdict.to_dict())
    return {"results": results}


@app.get("/history")
async def history_endpoint(
    request: Request,
    limit: int = Query(20, ge=1, le=200, description="Сколько записей вернуть"),
    address: str | None = Query(None, description="Только по одному адресу"),
    api_key: str | None = Query(None, description="API key (лучше заголовком X-API-Key)"),
    _auth: None = Depends(require_web_auth),
):
    """Журнал проверок. Отвечает на вопрос «что я уже смотрел» и показывает,
    как менялся вердикт по адресу."""
    _authorize_read(request, api_key)
    if address and not is_valid_trc20_address(address):
        raise HTTPException(status_code=400, detail="Invalid TRC20 address format")
    return {"items": await history.recent(limit=limit, address=address)}


@app.get("/stats")
async def stats_endpoint(
    request: Request,
    api_key: str | None = Query(None, description="API key (лучше заголовком X-API-Key)"),
    _auth: None = Depends(require_web_auth),
):
    """Сколько проверок сделано. Прямой индикатор расхода платных лимитов KYT:
    раньше это было видно только по счёту от провайдера."""
    _authorize_read(request, api_key)
    from core.aggregator import inflight_count

    return {
        "checks": await history.stats(),
        "labels": labels.count(),
        "watchlist": await watchlist.stats(),
        "rate_limit": limiter.stats(),
        "in_flight": inflight_count(),
        "ruleset_version": RULESET_VERSION,
    }


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    @app.get("/")
    async def index(_auth: None = Depends(require_web_auth)):
        return FileResponse(WEB_DIR / "index.html")
