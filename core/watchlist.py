"""Мониторинг адресов: периодическая перепроверка и уведомление об изменениях.

Зачем: главный сценарий повторной проверки — «изменилось ли что-нибудь по моему
контрагенту». Журнал (core/history.py) уже отвечает на этот вопрос при ручной
проверке, но узнать об изменении хочется без неё: адрес, чистый вчера, сегодня
может оказаться в блэклисте Tether или в новом санкционном пакете.

Как устроено: список адресов на том же volume, фоновая asyncio-задача в том же
процессе (отдельный процесс завёл бы второй polling бота и 409 от Telegram).
Частота ограничена: каждая перепроверка тратит платные лимиты KYT, поэтому
интервал считается на адрес, а не «все сразу каждую минуту».

Хранилище необязательное: ошибки SQLite глушатся и не ломают сервис.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any

import aiosqlite

log = logging.getLogger(__name__)

WATCHLIST_PATH = Path(os.getenv("WATCHLIST_PATH", "/data/watchlist.db"))
ENABLED = os.getenv("WATCHLIST_ENABLED", "1") not in ("0", "false", "False")
# Как часто перепроверять один адрес (по умолчанию раз в 12 часов).
INTERVAL_SECONDS = int(os.getenv("WATCHLIST_INTERVAL_SECONDS", str(12 * 3600)))
# Как часто просыпается фоновая задача.
TICK_SECONDS = int(os.getenv("WATCHLIST_TICK_SECONDS", "300"))
# Сколько адресов проверять за один тик — прямое ограничение расхода KYT.
BATCH_PER_TICK = int(os.getenv("WATCHLIST_BATCH_PER_TICK", "3"))
# Сколько адресов может вести один пользователь.
MAX_PER_USER = int(os.getenv("WATCHLIST_MAX_PER_USER", "20"))


def is_enabled() -> bool:
    return ENABLED


async def init_db() -> None:
    if not ENABLED:
        return
    WATCHLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(WATCHLIST_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS watchlist (
                address     TEXT NOT NULL,
                chat_id     INTEGER NOT NULL,
                added_at    REAL,
                last_check  REAL DEFAULT 0,
                last_level  TEXT,
                last_score  INTEGER,
                PRIMARY KEY (address, chat_id)
            )
            """
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_watch_due ON watchlist(last_check)"
        )
        await db.commit()


async def add(address: str, chat_id: int) -> tuple[bool, str]:
    """Добавить адрес в наблюдение. (успех, сообщение для пользователя)."""
    if not ENABLED:
        return False, "Мониторинг выключен (WATCHLIST_ENABLED=0)"
    try:
        async with aiosqlite.connect(WATCHLIST_PATH) as db:
            async with db.execute(
                "SELECT COUNT(*) FROM watchlist WHERE chat_id = ?", (chat_id,)
            ) as cur:
                current = (await cur.fetchone())[0]
            if current >= MAX_PER_USER:
                return False, (
                    f"Достигнут лимит наблюдаемых адресов ({MAX_PER_USER}). "
                    f"Каждая перепроверка тратит платные лимиты AML-сервисов."
                )
            await db.execute(
                "INSERT OR IGNORE INTO watchlist (address, chat_id, added_at) "
                "VALUES (?, ?, ?)",
                (address, chat_id, time.time()),
            )
            await db.commit()
    except Exception as e:
        log.warning("Мониторинг: не удалось добавить %s (%s)", address, e)
        return False, f"Не удалось сохранить: {e}"
    hours = INTERVAL_SECONDS // 3600
    return True, f"Адрес под наблюдением. Перепроверка примерно раз в {hours} ч."


async def remove(address: str, chat_id: int) -> bool:
    if not ENABLED:
        return False
    try:
        async with aiosqlite.connect(WATCHLIST_PATH) as db:
            cur = await db.execute(
                "DELETE FROM watchlist WHERE address = ? AND chat_id = ?",
                (address, chat_id),
            )
            await db.commit()
            return bool(cur.rowcount)
    except Exception:
        return False


async def list_for(chat_id: int) -> list[dict[str, Any]]:
    if not ENABLED:
        return []
    try:
        async with aiosqlite.connect(WATCHLIST_PATH) as db:
            async with db.execute(
                "SELECT address, last_check, last_level, last_score FROM watchlist "
                "WHERE chat_id = ? ORDER BY added_at DESC",
                (chat_id,),
            ) as cur:
                rows = await cur.fetchall()
    except Exception:
        return []
    return [
        {"address": r[0], "last_check": r[1], "last_level": r[2], "last_score": r[3]}
        for r in rows
    ]


async def due(limit: int | None = None) -> list[dict[str, Any]]:
    """Адреса, которым пора на перепроверку."""
    if not ENABLED:
        return []
    limit = limit or BATCH_PER_TICK
    cutoff = time.time() - INTERVAL_SECONDS
    try:
        async with aiosqlite.connect(WATCHLIST_PATH) as db:
            async with db.execute(
                "SELECT address, chat_id, last_level, last_score FROM watchlist "
                "WHERE last_check < ? ORDER BY last_check ASC LIMIT ?",
                (cutoff, limit),
            ) as cur:
                rows = await cur.fetchall()
    except Exception:
        return []
    return [
        {"address": r[0], "chat_id": r[1], "last_level": r[2], "last_score": r[3]}
        for r in rows
    ]


async def mark_checked(address: str, chat_id: int, level: str, score: int) -> None:
    if not ENABLED:
        return
    try:
        async with aiosqlite.connect(WATCHLIST_PATH) as db:
            await db.execute(
                "UPDATE watchlist SET last_check = ?, last_level = ?, last_score = ? "
                "WHERE address = ? AND chat_id = ?",
                (time.time(), level, score, address, chat_id),
            )
            await db.commit()
    except Exception as e:
        log.warning("Мониторинг: не удалось отметить %s (%s)", address, e)


async def stats() -> dict[str, Any]:
    if not ENABLED:
        return {"enabled": False}
    try:
        async with aiosqlite.connect(WATCHLIST_PATH) as db:
            async with db.execute(
                "SELECT COUNT(*), COUNT(DISTINCT address), COUNT(DISTINCT chat_id) "
                "FROM watchlist"
            ) as cur:
                total, addrs, users = await cur.fetchone()
    except Exception as e:
        return {"enabled": True, "error": str(e)}
    return {
        "enabled": True,
        "subscriptions": total,
        "addresses": addrs,
        "users": users,
        "interval_hours": INTERVAL_SECONDS // 3600,
    }


async def run_loop(check_fn, notify_fn, stop: asyncio.Event | None = None) -> None:
    """Фоновая перепроверка.

    `check_fn(address)` → вердикт, `notify_fn(chat_id, text)` → отправка.
    Уведомляем ТОЛЬКО при смене уровня риска: рассылка «всё по-прежнему»
    каждые 12 часов — это спам, от которого отключаются.
    """
    if not ENABLED:
        log.info("Мониторинг адресов выключен")
        return
    log.info(
        "Мониторинг адресов: тик каждые %d с, до %d адресов за тик, "
        "интервал на адрес %d ч",
        TICK_SECONDS, BATCH_PER_TICK, INTERVAL_SECONDS // 3600,
    )
    while not (stop and stop.is_set()):
        try:
            await tick(check_fn, notify_fn)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Мониторинг: сбой в тике")
        try:
            if stop:
                await asyncio.wait_for(stop.wait(), timeout=TICK_SECONDS)
            else:  # pragma: no cover — путь без стоп-события
                await asyncio.sleep(TICK_SECONDS)
        except TimeoutError:
            continue


async def tick(check_fn, notify_fn) -> int:
    """Один проход. Возвращает число отправленных уведомлений."""
    notified = 0
    for item in await due():
        address, chat_id = item["address"], item["chat_id"]
        try:
            verdict = await check_fn(address)
        except Exception as e:
            log.warning("Мониторинг: проверка %s не удалась (%s)", address, e)
            continue
        level, score = verdict.risk_level.value, verdict.risk_score
        previous = item.get("last_level")
        await mark_checked(address, chat_id, level, score)
        if previous is None or previous == level:
            continue
        try:
            await notify_fn(chat_id, _change_text(verdict, previous, item.get("last_score")))
            notified += 1
        except Exception as e:
            log.warning("Мониторинг: не удалось уведомить chat_id=%s (%s)", chat_id, e)
    return notified


def _change_text(verdict, previous_level: str, previous_score: int | None) -> str:
    grew = _ORDER.get(verdict.risk_level.value, 0) > _ORDER.get(previous_level, 0)
    head = "🔺 Риск вырос" if grew else "🔻 Риск снизился"
    return (
        f"<b>{head}</b> по наблюдаемому адресу\n"
        f"<code>{verdict.address}</code>\n\n"
        f"Было: {previous_level} ({previous_score if previous_score is not None else '?'}/100)\n"
        f"Стало: {verdict.risk_level.value} ({verdict.risk_score}/100)\n"
        f"Сущность: {verdict.entity or '—'}"
    )


_ORDER = {"unknown": 0, "safe": 1, "caution": 2, "dangerous": 3}
