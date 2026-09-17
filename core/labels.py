"""Ручные метки адресов в SQLite на persistent volume.

Раньше, чтобы пометить адрес, нужно было править `core/providers/local.py`,
коммитить и ждать пересборки на Railway. Для «это наш горячий кошелёк» или
«этого скамера я знаю лично» — непропорционально дорого.

Метки из `local.py` остаются как предзаданные: они засеваются в базу при старте
и не перетирают то, что оператор поменял вручную. Приоритет у ручных меток
наивысший (см. `_apply_local` в агрегаторе), поэтому запись сюда — сильное
действие, и оно журналируется вместе с автором.

Хранилище необязательное: ошибка SQLite не роняет проверку, агрегатор просто
работает без ручных меток.
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Any

import aiosqlite

from .models import EntityType, RiskLevel

log = logging.getLogger(__name__)

LABELS_PATH = Path(os.getenv("LABELS_PATH", "/data/labels.db"))

# Кеш в памяти: агрегатор читает метки синхронно на каждой проверке, а ходить в
# SQLite за одной строкой на каждый запрос незачем — меток единицы, меняются редко.
_cache: dict[str, dict[str, str]] = {}
_loaded = False


def _valid(entity_type: str | None, risk_level: str | None) -> tuple[str | None, str | None]:
    """Проверка значений против перечислений. Неизвестное отбрасываем с warning,
    иначе метка молча не применится и это будет непонятно."""
    et = rl = None
    if entity_type:
        try:
            et = EntityType(entity_type).value
        except ValueError:
            log.warning("Метка: неизвестный entity_type %r", entity_type)
    if risk_level:
        try:
            rl = RiskLevel(risk_level).value
        except ValueError:
            log.warning("Метка: неизвестный risk_level %r", risk_level)
    return et, rl


async def init_db(seed: dict[str, dict[str, str]] | None = None) -> None:
    """Создать таблицу, засеять предзаданные метки и наполнить кеш."""
    global _loaded
    LABELS_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(LABELS_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS labels (
                address     TEXT PRIMARY KEY,
                entity      TEXT,
                entity_type TEXT,
                risk_level  TEXT,
                note        TEXT,
                author      TEXT,
                updated_at  REAL
            )
            """
        )
        # Предзаданные метки не перетирают правки оператора: INSERT OR IGNORE.
        for addr, data in (seed or {}).items():
            et, rl = _valid(data.get("entity_type"), data.get("risk_level"))
            await db.execute(
                "INSERT OR IGNORE INTO labels (address, entity, entity_type, risk_level, "
                "note, author, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (addr, data.get("entity"), et, rl, data.get("note"), "local.py", time.time()),
            )
        await db.commit()
    await reload()
    _loaded = True


async def reload() -> int:
    """Перечитать все метки в память. Возвращает их число."""
    global _cache
    try:
        async with aiosqlite.connect(LABELS_PATH) as db:
            async with db.execute(
                "SELECT address, entity, entity_type, risk_level, note FROM labels"
            ) as cur:
                rows = await cur.fetchall()
    except Exception as e:
        log.warning("Метки: не удалось прочитать базу (%s)", e)
        return len(_cache)
    _cache = {
        r[0]: {
            k: v
            for k, v in (("entity", r[1]), ("entity_type", r[2]), ("risk_level", r[3]), ("note", r[4]))
            if v
        }
        for r in rows
    }
    return len(_cache)


def lookup(address: str) -> dict[str, str] | None:
    """Синхронное чтение из кеша — так же, как это делал local.lookup()."""
    return _cache.get(address)


def count() -> int:
    return len(_cache)


def is_loaded() -> bool:
    return _loaded


async def put(
    address: str,
    entity: str | None = None,
    entity_type: str | None = None,
    risk_level: str | None = None,
    note: str | None = None,
    author: str = "?",
) -> dict[str, Any]:
    """Создать или обновить метку. Возвращает то, что записано."""
    et, rl = _valid(entity_type, risk_level)
    async with aiosqlite.connect(LABELS_PATH) as db:
        await db.execute(
            """
            INSERT INTO labels (address, entity, entity_type, risk_level, note, author, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
                entity      = excluded.entity,
                entity_type = excluded.entity_type,
                risk_level  = excluded.risk_level,
                note        = excluded.note,
                author      = excluded.author,
                updated_at  = excluded.updated_at
            """,
            (address, entity, et, rl, note, author, time.time()),
        )
        await db.commit()
    await reload()
    log.info("Метка сохранена: %s автором %s (risk_level=%s)", address, author, rl)
    return {"address": address, "entity": entity, "entity_type": et,
            "risk_level": rl, "note": note}


async def delete(address: str) -> bool:
    """Удалить метку. False, если её и не было."""
    async with aiosqlite.connect(LABELS_PATH) as db:
        cur = await db.execute("DELETE FROM labels WHERE address = ?", (address,))
        await db.commit()
        removed = bool(cur.rowcount)
    await reload()
    if removed:
        log.info("Метка удалена: %s", address)
    return removed


async def all_labels(limit: int = 50) -> list[dict[str, Any]]:
    try:
        async with aiosqlite.connect(LABELS_PATH) as db:
            async with db.execute(
                "SELECT address, entity, entity_type, risk_level, note, author, updated_at "
                "FROM labels ORDER BY updated_at DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ) as cur:
                rows = await cur.fetchall()
    except Exception:
        return []
    return [
        {
            "address": r[0], "entity": r[1], "entity_type": r[2], "risk_level": r[3],
            "note": r[4], "author": r[5], "updated_at": r[6],
        }
        for r in rows
    ]
