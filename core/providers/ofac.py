"""OFAC SDN — прямой матч санкционных адресов (TRON/TRX).

Источник: репозиторий 0xB10C, который ночью извлекает крипто-адреса из
официального OFAC SDN-списка (Specially Designated Nationals) США.
Список TRX небольшой (десятки адресов), тянем целиком и кешируем в памяти
на сутки. Это даёт ТОЧНОЕ определение «адрес сам по себе санкционный»
без ложных срабатываний (в отличие от косвенной экспозиции).

Ключ не нужен — это публичный raw-файл на GitHub.
"""
from __future__ import annotations

import time

import httpx

SANCTIONS_URL = (
    "https://raw.githubusercontent.com/0xB10C/"
    "ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_TRX.txt"
)
REFRESH_SECONDS = 24 * 3600

# Модульный кеш: список меняется редко, тянуть на каждый запрос незачем.
_cache: dict[str, object] = {"set": None, "ts": 0.0}


async def fetch_sanctioned_set(client: httpx.AsyncClient) -> set[str]:
    """Множество санкционных TRX-адресов. При сбое отдаёт прошлый кеш или пусто."""
    now = time.time()
    cached = _cache["set"]
    if isinstance(cached, set) and now - float(_cache["ts"]) < REFRESH_SECONDS:
        return cached
    try:
        r = await client.get(SANCTIONS_URL, timeout=10.0)
        r.raise_for_status()
        addrs = {ln.strip() for ln in r.text.splitlines() if ln.strip()}
        if addrs:
            _cache["set"] = addrs
            _cache["ts"] = now
        return addrs
    except httpx.HTTPError:
        return cached if isinstance(cached, set) else set()
