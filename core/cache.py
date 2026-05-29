"""SQLite-кеш результатов проверок.

Хранит JSON-результат по адресу с TTL 7 дней.
Метки бирж/контрактов меняются редко, кеш сильно снижает нагрузку и латентность.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import aiosqlite

CACHE_PATH = Path(os.getenv("CACHE_PATH", "/data/cache.db"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", str(7 * 24 * 3600)))


async def init_db() -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(CACHE_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS verdict_cache (
                address     TEXT PRIMARY KEY,
                payload     TEXT NOT NULL,
                stored_at   INTEGER NOT NULL
            )
            """
        )
        await db.commit()


async def get(address: str) -> dict[str, Any] | None:
    async with aiosqlite.connect(CACHE_PATH) as db:
        async with db.execute(
            "SELECT payload, stored_at FROM verdict_cache WHERE address = ?",
            (address,),
        ) as cur:
            row = await cur.fetchone()
    if not row:
        return None
    payload, stored_at = row
    if time.time() - stored_at > CACHE_TTL_SECONDS:
        return None
    return json.loads(payload)


async def put(address: str, payload: dict[str, Any]) -> None:
    async with aiosqlite.connect(CACHE_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO verdict_cache (address, payload, stored_at) "
            "VALUES (?, ?, ?)",
            (address, json.dumps(payload, ensure_ascii=False), int(time.time())),
        )
        await db.commit()
