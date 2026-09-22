"""Накопительная кластеризация депозитных адресов бирж (on-chain).

Когда агрегатор опознаёт депозитный/транзитный адрес биржи (funnel-паттерн,
см. `_detect_exchange_deposit`), мы пишем его в локальную БД вместе с «якорем» —
адресом хот/сборного кошелька биржи, на который он пересылает средства.

Идея кластеризации (как у Arkham, но без их off-chain интела — только on-chain):
разные депозитники ОДНОЙ биржи пересылают на ОДИН и тот же якорь. Поэтому со
временем БД растёт в граф: по якорю видно, сколько родственных депозитных
адресов мы уже атрибутировали к этой бирже. Каждая проверка докидывает узлы.

Хранилище — SQLite на том же persistent volume `/data`, что и кеш. Провайдер
необязательный: любая ошибка БД не должна ронять проверку адреса.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import aiosqlite

CLUSTER_PATH = Path(os.getenv("CLUSTER_PATH", "/data/cluster.db"))


async def init_db() -> None:
    CLUSTER_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(CLUSTER_PATH) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS deposit_cluster (
                address     TEXT PRIMARY KEY,
                exchange    TEXT NOT NULL,
                hot_wallet  TEXT,
                sanctioned  INTEGER DEFAULT 0,
                first_seen  REAL,
                last_seen   REAL
            )
            """
        )
        # Миграция: уверенность атрибуции появилась позже таблицы, а том с базой
        # на Railway переживает редеплой. Дубликат колонки — не ошибка.
        try:
            await db.execute(
                "ALTER TABLE deposit_cluster ADD COLUMN confidence TEXT DEFAULT 'high'"
            )
        except Exception:
            pass
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_cluster_hot ON deposit_cluster(hot_wallet)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_cluster_exch ON deposit_cluster(exchange)"
        )
        await db.commit()


async def record(
    address: str,
    exchange: str,
    hot_wallet: str | None,
    sanctioned: bool = False,
    confidence: str = "high",
) -> None:
    """Атрибутировать депозитный адрес к бирже/якорю (upsert).

    `confidence` = "medium" у адресов, опознанных по одному свипу. Пишем их
    тоже — факт «этот якорь принадлежит такой-то бирже» взят из тега и от нашей
    догадки не зависит, — но в отчётном счётчике родственных депозитников они
    не участвуют: подменять измерение догадкой там нельзя."""
    now = time.time()
    try:
        async with aiosqlite.connect(CLUSTER_PATH) as db:
            await db.execute(
                """
                INSERT INTO deposit_cluster
                    (address, exchange, hot_wallet, sanctioned, confidence,
                     first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(address) DO UPDATE SET
                    exchange   = excluded.exchange,
                    hot_wallet = excluded.hot_wallet,
                    sanctioned = excluded.sanctioned,
                    confidence = excluded.confidence,
                    last_seen  = excluded.last_seen
                """,
                (address, exchange, hot_wallet, int(sanctioned), confidence, now, now),
            )
            await db.commit()
    except Exception:
        pass  # кластеризация необязательна — не валим проверку адреса


async def cluster_info(
    exchange: str, hot_wallet: str | None, exclude: str
) -> dict[str, Any]:
    """Сколько родственных депозитников этого якоря/биржи мы уже знаем.

    `siblings_on_anchor` — самый точный сигнал: адреса, пересылающие на ТОТ ЖЕ
    хот-кошелёк. `known_deposits_exchange` — шире, по имени биржи."""
    try:
        async with aiosqlite.connect(CLUSTER_PATH) as db:
            siblings: list[str] = []
            n_anchor = 0
            if hot_wallet:
                async with db.execute(
                    "SELECT address FROM deposit_cluster "
                    "WHERE hot_wallet = ? AND address != ? AND confidence = 'high' "
                    "ORDER BY last_seen DESC LIMIT 5",
                    (hot_wallet, exclude),
                ) as cur:
                    siblings = [r[0] for r in await cur.fetchall()]
                async with db.execute(
                    "SELECT COUNT(*) FROM deposit_cluster "
                    "WHERE hot_wallet = ? AND address != ? AND confidence = 'high'",
                    (hot_wallet, exclude),
                ) as cur:
                    n_anchor = (await cur.fetchone())[0]
            async with db.execute(
                "SELECT COUNT(*) FROM deposit_cluster "
                "WHERE exchange = ? AND address != ? AND confidence = 'high'",
                (exchange, exclude),
            ) as cur:
                n_exch = (await cur.fetchone())[0]
    except Exception:
        return {}
    return {
        "exchange": exchange,
        "hot_wallet": hot_wallet,
        "siblings_on_anchor": n_anchor,
        "siblings_sample": siblings,
        "known_deposits_exchange": n_exch,
    }


async def anchors_for(addresses: set[str] | list[str]) -> dict[str, str]:
    """Какие из этих адресов мы уже знаем как якоря (хот-кошельки) бирж.

    Зачем: funnel-эвристика опознаёт биржу в оттоке по тегу TronScan из ответа
    о переводах, а тег там есть не всегда — и тогда депозитник биржи выглядит
    личным кошельком. Но якорь мы могли выучить на прошлой проверке, когда тег
    был на месте. Так накопленная база начинает работать на атрибуцию, а не
    только на счётчик родственных адресов в отчёте.

    Возвращает `{адрес: биржа}`. Ошибка БД — пустой словарь: кластеризация
    необязательна и не должна ронять проверку."""
    addrs = [a for a in dict.fromkeys(addresses) if a]
    if not addrs:
        return {}
    # Чанки: SQLite по умолчанию держит до 999 переменных в запросе, а список
    # контрагентов упирается в число переводов и может расти.
    out: dict[str, str] = {}
    try:
        async with aiosqlite.connect(CLUSTER_PATH) as db:
            for i in range(0, len(addrs), 500):
                chunk = addrs[i : i + 500]
                placeholders = ",".join("?" * len(chunk))
                async with db.execute(
                    f"SELECT hot_wallet, exchange, COUNT(*) AS n FROM deposit_cluster "  # noqa: S608
                    f"WHERE hot_wallet IN ({placeholders}) "
                    f"GROUP BY hot_wallet, exchange ORDER BY n",
                    chunk,
                ) as cur:
                    # ORDER BY n по возрастанию: при конфликте имён побеждает
                    # биржа, к которой на этот якорь привязано больше адресов.
                    for hot, exchange, _n in await cur.fetchall():
                        out[hot] = exchange
    except Exception:
        return {}
    return out
