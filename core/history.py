"""Журнал проверок на persistent volume.

Зачем: кеш по умолчанию выключен (свежесть важнее), поэтому обязательный для
деплоя том `/data` фактически держал только базу кластеризации. Журнал даёт то,
чего в сервисе не было совсем:

  • сравнение с прошлым результатом — «в прошлый раз риск был 20, сейчас 80»,
    самое ценное при повторной проверке контрагента;
  • историю в боте и вебе вместо повторного ввода адреса;
  • видимый расход платных лимитов KYT по факту, а не по счёту от провайдера;
  • выгрузку для комплаенса.

Хранилище необязательное: любая ошибка SQLite ловится и НЕ роняет проверку —
так же, как в core/cluster.py. Ретеншн ограничен и по времени, и по числу
записей, чтобы база не росла бесконечно на том же диске, что и кеш.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import aiosqlite

log = logging.getLogger(__name__)

HISTORY_PATH = Path(os.getenv("HISTORY_PATH", "/data/history.db"))
# 0 — не ограничивать по времени
RETENTION_DAYS = int(os.getenv("HISTORY_RETENTION_DAYS", "180"))
MAX_ROWS = int(os.getenv("HISTORY_MAX_ROWS", "50000"))
ENABLED = os.getenv("HISTORY_ENABLED", "1") not in ("0", "false", "False")


def is_enabled() -> bool:
    return ENABLED


async def init_db() -> None:
    if not ENABLED:
        return
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(HISTORY_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS checks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                address     TEXT NOT NULL,
                checked_at  REAL NOT NULL,
                risk_level  TEXT,
                risk_score  INTEGER,
                entity      TEXT,
                entity_type TEXT,
                source      TEXT,
                payload     TEXT
            )
            """
        )
        # Миграция: признак полноты проверки появился позже таблицы, а том на
        # Railway переживает редеплой. Дубликат колонки — не ошибка.
        try:
            await db.execute("ALTER TABLE checks ADD COLUMN complete INTEGER DEFAULT 1")
        except Exception:
            pass
        await db.execute("CREATE INDEX IF NOT EXISTS idx_checks_addr ON checks(address)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_checks_time ON checks(checked_at)")
        # Кто что смотрел в боте. Отдельно от checks: общий журнал — это учёт
        # расхода и сравнение с прошлым, а /history в боте показывал каждому
        # проверки ВСЕХ пользователей из белого списка.
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS views (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                address     TEXT NOT NULL,
                checked_at  REAL NOT NULL,
                risk_level  TEXT,
                risk_score  INTEGER,
                entity      TEXT
            )
            """
        )
        await db.execute("CREATE INDEX IF NOT EXISTS idx_views_user ON views(user_id, id)")
        await db.commit()


async def record(verdict: Any, source: str = "api") -> None:
    """Записать проверку. Ошибки глушатся: журнал не должен ломать проверку."""
    if not ENABLED:
        return
    try:
        async with aiosqlite.connect(HISTORY_PATH) as db:
            await db.execute(
                "INSERT INTO checks (address, checked_at, risk_level, risk_score, "
                "entity, entity_type, source, payload, complete) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    verdict.address,
                    time.time(),
                    verdict.risk_level.value,
                    verdict.risk_score,
                    verdict.entity,
                    verdict.entity_type.value,
                    source,
                    json.dumps(verdict.to_dict(), ensure_ascii=False),
                    0 if _degraded(verdict) else 1,
                ),
            )
            await db.commit()
    except Exception as e:
        log.warning("Журнал проверок: не удалось записать %s (%s)", verdict.address, e)
        return
    await _maybe_prune()


def _degraded(verdict: Any) -> bool:
    check = getattr(verdict, "is_degraded", None)
    return bool(check()) if callable(check) else False


# Чистка раньше шла только при старте: сервис, работающий месяцами без
# рестарта, копил журнал без ограничений. Теперь — не чаще раза в сутки.
PRUNE_EVERY_SECONDS = 24 * 3600
_last_prune = 0.0


async def _maybe_prune() -> None:
    global _last_prune
    now = time.time()
    if now - _last_prune < PRUNE_EVERY_SECONDS:
        return
    _last_prune = now
    await prune()


async def record_view(user_id: int, verdict: Any) -> None:
    """Пользователь бота посмотрел вердикт — для его личного /history."""
    if not ENABLED:
        return
    try:
        async with aiosqlite.connect(HISTORY_PATH) as db:
            await db.execute(
                "INSERT INTO views (user_id, address, checked_at, risk_level, "
                "risk_score, entity) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, verdict.address, time.time(), verdict.risk_level.value,
                 verdict.risk_score, verdict.entity),
            )
            await db.commit()
    except Exception as e:
        log.warning("Журнал просмотров: не удалось записать (%s)", e)


async def recent_views(user_id: int, limit: int = 10) -> list[dict[str, Any]]:
    """Последние проверки ОДНОГО пользователя, без повторов адреса."""
    if not ENABLED:
        return []
    limit = max(1, min(limit, 200))
    try:
        async with aiosqlite.connect(HISTORY_PATH) as db:
            async with db.execute(
                "SELECT address, MAX(checked_at), risk_level, risk_score, entity "
                "FROM views WHERE user_id = ? GROUP BY address "
                "ORDER BY MAX(id) DESC LIMIT ?",
                (user_id, limit),
            ) as cur:
                rows = await cur.fetchall()
    except Exception:
        return []
    return [
        {"address": r[0], "checked_at": r[1], "risk_level": r[2],
         "risk_score": r[3], "entity": r[4]}
        for r in rows
    ]


async def previous(address: str, before_id: int | None = None) -> dict[str, Any] | None:
    """Предыдущая проверка адреса (без учёта самой свежей, если передан id)."""
    if not ENABLED:
        return None
    try:
        async with aiosqlite.connect(HISTORY_PATH) as db:
            # Только полные проверки: сравнение «было/стало» с проверкой, где
            # TronScan не ответил, выдаёт сбой источника за смену риска.
            sql = (
                "SELECT id, checked_at, risk_level, risk_score, entity, entity_type "
                "FROM checks WHERE address = ? AND COALESCE(complete, 1) = 1"
            )
            params: list[Any] = [address]
            if before_id is not None:
                sql += " AND id < ?"
                params.append(before_id)
            sql += " ORDER BY id DESC LIMIT 1"
            async with db.execute(sql, params) as cur:
                row = await cur.fetchone()
    except Exception:
        return None
    if not row:
        return None
    return {
        "id": row[0],
        "checked_at": row[1],
        "risk_level": row[2],
        "risk_score": row[3],
        "entity": row[4],
        "entity_type": row[5],
    }


async def recent(limit: int = 20, address: str | None = None) -> list[dict[str, Any]]:
    """Последние проверки, опционально по одному адресу."""
    if not ENABLED:
        return []
    limit = max(1, min(limit, 200))
    try:
        async with aiosqlite.connect(HISTORY_PATH) as db:
            sql = (
                "SELECT address, checked_at, risk_level, risk_score, entity, "
                "entity_type, source FROM checks"
            )
            params: list[Any] = []
            if address:
                sql += " WHERE address = ?"
                params.append(address)
            sql += " ORDER BY id DESC LIMIT ?"
            params.append(limit)
            async with db.execute(sql, params) as cur:
                rows = await cur.fetchall()
    except Exception:
        return []
    return [
        {
            "address": r[0],
            "checked_at": r[1],
            "risk_level": r[2],
            "risk_score": r[3],
            "entity": r[4],
            "entity_type": r[5],
            "source": r[6],
        }
        for r in rows
    ]


async def stats() -> dict[str, Any]:
    """Сколько проверок сделано. Прямой индикатор расхода платных лимитов KYT."""
    if not ENABLED:
        return {"enabled": False}
    try:
        async with aiosqlite.connect(HISTORY_PATH) as db:
            async with db.execute("SELECT COUNT(*), COUNT(DISTINCT address) FROM checks") as cur:
                total, uniq = await cur.fetchone()
            day_ago = time.time() - 86400
            async with db.execute(
                "SELECT COUNT(*) FROM checks WHERE checked_at > ?", (day_ago,)
            ) as cur:
                last_day = (await cur.fetchone())[0]
            async with db.execute(
                "SELECT risk_level, COUNT(*) FROM checks GROUP BY risk_level"
            ) as cur:
                by_level = {r[0]: r[1] for r in await cur.fetchall()}
    except Exception as e:
        return {"enabled": True, "error": str(e)}
    return {
        "enabled": True,
        "total": total,
        "unique_addresses": uniq,
        "last_24h": last_day,
        "by_risk_level": by_level,
    }


async def prune() -> int:
    """Чистка по ретеншну и по числу записей. Возвращает число удалённых."""
    if not ENABLED:
        return 0
    removed = 0
    try:
        async with aiosqlite.connect(HISTORY_PATH) as db:
            if RETENTION_DAYS > 0:
                cutoff = time.time() - RETENTION_DAYS * 86400
                cur = await db.execute("DELETE FROM checks WHERE checked_at < ?", (cutoff,))
                removed += cur.rowcount or 0
            if RETENTION_DAYS > 0:
                cur = await db.execute("DELETE FROM views WHERE checked_at < ?", (cutoff,))
                removed += cur.rowcount or 0
            if MAX_ROWS > 0:
                for table in ("checks", "views"):
                    cur = await db.execute(
                        f"DELETE FROM {table} WHERE id NOT IN "  # noqa: S608
                        f"(SELECT id FROM {table} ORDER BY id DESC LIMIT ?)",
                        (MAX_ROWS,),
                    )
                    removed += cur.rowcount or 0
            await db.commit()
    except Exception as e:
        log.warning("Журнал проверок: чистка не удалась (%s)", e)
        return 0
    if removed:
        log.info("Журнал проверок: удалено %d устаревших записей", removed)
    return removed
