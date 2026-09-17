"""GoPlus Security API provider.

Эндпоинт: https://api.gopluslabs.io/api/v1/address_security/{address}?chain_id=tron
GOPLUS_API_KEY опционален. Бесплатный анонимный доступ ~30 RPM.

Ошибки (сеть, HTTP, `code != 1` — например, превышен лимит) → ProviderError.
Раньше провайдер молча возвращал {} и в вердикте это было неотличимо от «флагов нет».
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from .base import ProviderError

GOPLUS_BASE = "https://api.gopluslabs.io"
GOPLUS_API_KEY = os.getenv("GOPLUS_API_KEY", "")


async def fetch_address_security(address: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Возвращает объект ответа GoPlus (с `result` внутри). ProviderError при сбое."""
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
    except (httpx.HTTPError, ValueError) as e:
        raise ProviderError(f"GoPlus: {e}") from e
    if not isinstance(data, dict):
        raise ProviderError("GoPlus: unexpected response shape")
    if data.get("code") != 1:
        raise ProviderError(f"GoPlus: code={data.get('code')} {data.get('message') or ''}".strip())
    return data
