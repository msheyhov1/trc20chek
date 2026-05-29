"""GoPlus Security API provider.

Эндпоинт: https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id=tron
GOPLUS_API_KEY опционален. Бесплатный анонимный доступ ~30 RPM.
"""
from __future__ import annotations

import os
from typing import Any

import httpx

GOPLUS_BASE = "https://api.gopluslabs.io"
GOPLUS_API_KEY = os.getenv("GOPLUS_API_KEY", "")


async def fetch_address_security(address: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Возвращает result-объект с риск-флагами. {} при ошибке."""
    headers = {"Authorization": GOPLUS_API_KEY} if GOPLUS_API_KEY else {}
    try:
        r = await client.get(
            f"{GOPLUS_BASE}/api/v1/address_security/{address}",
            params={"chain_id": "tron"},
            headers=headers,
            timeout=10.0,
        )
        r.raise_for_status()
        data = r.json() or {}
        if data.get("code") == 1:
            return data
        return {}
    except (httpx.HTTPError, ValueError):
        return {}
