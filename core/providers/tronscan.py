"""TronScan API provider.

Использует публичный эндпоинт https://apilist.tronscanapi.com/api/accountv2
Ключ TRONSCAN_API_KEY опционален — без него лимит ниже, но работает.
"""
from __future__ import annotations

import os
from typing import Any

import httpx

TRONSCAN_BASE = "https://apilist.tronscanapi.com"
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "")


async def fetch_account(address: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Запрос данных по адресу в TronScan. Возвращает {} при ошибке."""
    headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if TRONSCAN_API_KEY else {}
    try:
        r = await client.get(
            f"{TRONSCAN_BASE}/api/accountv2",
            params={"address": address},
            headers=headers,
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json() or {}
    except (httpx.HTTPError, ValueError):
        return {}
