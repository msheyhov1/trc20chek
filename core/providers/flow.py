"""TronScan flow-провайдер: анализ контрагентов по TRC20-переводам.

Берёт последние переводы адреса через публичный эндпоинт
https://apilist.tronscanapi.com/api/token_trc20/transfers — он отдаёт метку
контрагента (`from_address_tag` / `to_address_tag`) прямо в ответе, поэтому
по одному запросу видно, с какими размеченными биржами связан адрес.

Ключ не обязателен (эндпоинт публичный), но `TRONSCAN_API_KEY` повышает лимит.
"""
from __future__ import annotations

import os
from typing import Any

import httpx

TRONSCAN_BASE = "https://apilist.tronscanapi.com"
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "")
TRANSFERS_LIMIT = 50


async def fetch_transfers(address: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Последние TRC20-переводы адреса. Возвращает [] при ошибке."""
    headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if TRONSCAN_API_KEY else {}
    try:
        r = await client.get(
            f"{TRONSCAN_BASE}/api/token_trc20/transfers",
            params={
                "limit": TRANSFERS_LIMIT,
                "start": 0,
                "relatedAddress": address,
            },
            headers=headers,
            timeout=10.0,
        )
        r.raise_for_status()
        data = r.json() or {}
        return data.get("token_transfers") or []
    except (httpx.HTTPError, ValueError):
        return []
