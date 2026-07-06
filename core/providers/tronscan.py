"""TronScan API provider.

Основной эндпоинт — https://apilist.tronscanapi.com/api/account (бесплатный,
работает без ключа и отдаёт те же поля, что нужны агрегатору: теги addressTag/
publicTag/redTag/..., accountType/contractMap для контрактов, totalTransactionCount).

Раньше использовался /api/accountv2, но TronScan закрыл его за платным ключом
(отдаёт HTTP 401 без валидного TRON-PRO-API-KEY), из-за чего пропадали ВСЕ метки
и любой адрес определялся как «unknown». accountv2 оставлен как fallback — если
задан рабочий TRONSCAN_API_KEY, он может дать чуть более полные данные.

Ключ TRONSCAN_API_KEY опционален: и без него всё работает, с ним — выше лимиты.
"""
from __future__ import annotations

import os
from typing import Any

import httpx

TRONSCAN_BASE = "https://apilist.tronscanapi.com"
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "")


async def _get(path: str, address: str, client: httpx.AsyncClient) -> dict[str, Any]:
    headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if TRONSCAN_API_KEY else {}
    r = await client.get(
        f"{TRONSCAN_BASE}{path}",
        params={"address": address},
        headers=headers,
        timeout=10.0,
    )
    r.raise_for_status()
    return r.json() or {}


async def fetch_account(address: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Данные по адресу из TronScan. Возвращает {} только если оба эндпоинта недоступны.

    Основной путь — бесплатный /api/account. Если он почему-то упал, а ключ задан,
    пробуем /api/accountv2 (платный) как запасной вариант.
    """
    try:
        return await _get("/api/account", address, client)
    except (httpx.HTTPError, ValueError):
        pass
    if TRONSCAN_API_KEY:
        try:
            return await _get("/api/accountv2", address, client)
        except (httpx.HTTPError, ValueError):
            pass
    return {}
