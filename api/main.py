"""FastAPI + Telegram-бот в одном процессе (вариант для Railway).

API живёт на HTTP-порту, а бот стартует фоновой asyncio-задачей
при старте приложения. Один контейнер, один деплой, один диск.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from core import check_address
from core.cache import init_db
from core.models import is_valid_trc20_address

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")

API_KEY = os.getenv("API_KEY", "")
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
WEB_DIR = Path(__file__).parent.parent / "web"


async def _run_bot():
    """Запускает Telegram-бота. Импортируем модуль лениво,
    чтобы API мог стартовать без BOT_TOKEN (на этапе теста)."""
    if not BOT_TOKEN:
        log.warning("BOT_TOKEN not set — Telegram bot disabled, API-only mode")
        return
    try:
        from bot.main import dp
        from aiogram import Bot

        bot = Bot(BOT_TOKEN)
        log.info("Starting Telegram bot polling...")
        await dp.start_polling(bot)
    except asyncio.CancelledError:
        log.info("Bot polling cancelled")
        raise
    except Exception:
        log.exception("Bot crashed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
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
    version="1.0.0",
    description="Определение принадлежности TRC20-адреса (биржа / контракт / скам).",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    return {"status": "ok", "bot_enabled": bool(BOT_TOKEN)}


@app.get("/check/{address}")
async def check(
    address: str,
    cache: bool = Query(False, description="Использовать кеш (по умолчанию выкл — всегда свежие данные для AML)"),
    api_key: str | None = Query(None, description="API key (если включена защита)"),
):
    if API_KEY and api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    if not is_valid_trc20_address(address):
        raise HTTPException(status_code=400, detail="Invalid TRC20 address format")

    # По умолчанию свежий запрос (AML требует актуальных транзакций).
    # Кеш — только по явному ?cache=true.
    verdict = await check_address(address, use_cache=cache)
    return verdict.to_dict()


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")

    @app.get("/")
    async def index():
        return FileResponse(WEB_DIR / "index.html")
