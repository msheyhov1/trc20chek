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

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles

from api.ratelimit import RateLimiter
from core import check_address
from core.cache import init_db
from core.cluster import init_db as init_cluster_db
from core.models import is_valid_trc20_address

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

_basic = HTTPBasic(auto_error=False)
limiter = RateLimiter()

# Состояние локальных хранилищ: заполняется в lifespan, видно в /health.
storage_status: dict[str, str] = {"cache": "unknown", "cluster": "unknown"}


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
    """IP клиента с учётом прокси Railway (X-Forwarded-For — первый в цепочке)."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
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
        what = "кеш проверок выключен" if name == "cache" else (
            "кластеризация депозитников выключена"
        )
        log.error(
            "Хранилище %s недоступно (%s): сервис работает, но %s. "
            "Проверьте, что volume смонтирован на /data (см. DEPLOY_PLAN.md).",
            name, e, what,
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _init_storage("cache", init_db)
    await _init_storage("cluster", init_cluster_db)
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
    try:
        yield
    finally:
        bot_task.cancel()
        try:
            await bot_task
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


def _authorize(request: Request, api_key: str | None) -> None:
    """Проверка ключа (заголовок X-API-Key или ?api_key=) и лимитов."""
    if API_KEY:
        header_key = request.headers.get("x-api-key")
        # Query-параметр оставлен для совместимости, но он попадает в логи и
        # историю браузера — заголовок предпочтительнее.
        provided = header_key or api_key
        if not provided or not secrets.compare_digest(provided, API_KEY):
            raise HTTPException(status_code=401, detail="Invalid API key")
        return
    if not is_protected():
        raise HTTPException(
            status_code=503,
            detail=(
                "Сервис не сконфигурирован для публичного доступа: задайте "
                "WEB_PASSWORD или API_KEY, либо WEB_PUBLIC=1, если он должен быть открыт."
            ),
        )
    allowed, reason = limiter.check(client_ip(request))
    if not allowed:
        raise HTTPException(status_code=429, detail=reason)
    limiter.record(client_ip(request))


@app.get("/check/{address}")
async def check(
    request: Request,
    address: str,
    cache: bool = Query(False, description="Использовать кеш (по умолчанию выкл — всегда свежие данные для AML)"),
    api_key: str | None = Query(None, description="API key (лучше передавать заголовком X-API-Key)"),
    _auth: None = Depends(require_web_auth),
):
    _authorize(request, api_key)

    if not is_valid_trc20_address(address):
        raise HTTPException(status_code=400, detail="Invalid TRC20 address format")

    # По умолчанию свежий запрос (AML требует актуальных транзакций).
    # Кеш — только по явному ?cache=true.
    verdict = await check_address(address, use_cache=cache)
    return verdict.to_dict()


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    @app.get("/")
    async def index(_auth: None = Depends(require_web_auth)):
        return FileResponse(WEB_DIR / "index.html")
