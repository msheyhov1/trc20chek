"""OFAC SDN — прямой матч санкционных адресов (TRON/TRX).

Источник: репозиторий 0xB10C, который ночью извлекает крипто-адреса из
официального OFAC SDN-списка (Specially Designated Nationals) США.
Список TRX небольшой (сотни адресов), тянем целиком и кешируем в памяти
на сутки. Это даёт ТОЧНОЕ определение «адрес сам по себе санкционный»
без ложных срабатываний (в отличие от косвенной экспозиции).

Ключ не нужен — это публичный raw-файл на GitHub.

Деградация (в порядке предпочтения), чтобы проверка санкций не отключалась
молча из-за одного недоступного хоста:
  1. живой список с GitHub                 → source = "live"
  2. прошлый ответ из памяти (даже старый)  → source = "cache"
  3. снимок, вшитый в репозиторий           → source = "bundled" (docs/research)
  4. ничего                                 → source = "none" + ProviderError
"""
from __future__ import annotations

import time
from pathlib import Path

import httpx

from .base import ProviderError

SANCTIONS_URL = (
    "https://raw.githubusercontent.com/0xB10C/"
    "ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_TRX.txt"
)
REFRESH_SECONDS = 24 * 3600

# Снимок списка на дату проверки источников — запасной вариант при недоступном GitHub.
BUNDLED_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "docs" / "research" / "ofac_sanctioned_trx_2026-09-17.txt"
)

# Модульный кеш: список меняется редко, тянуть на каждый запрос незачем.
_cache: dict[str, object] = {"set": None, "ts": 0.0, "source": "none"}


def _parse(text: str) -> set[str]:
    return {ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")}


def _bundled() -> set[str]:
    try:
        return _parse(BUNDLED_PATH.read_text(encoding="utf-8"))
    except OSError:
        return set()


def last_source() -> str:
    """Откуда взят список в последнем вызове: live | cache | bundled | none."""
    return str(_cache.get("source") or "none")


async def fetch_sanctioned_set(client: httpx.AsyncClient) -> set[str]:
    """Множество санкционных TRX-адресов. При сбое сети — прошлый кеш, затем
    вшитый снимок; ProviderError только если нет вообще ничего."""
    now = time.time()
    cached = _cache["set"]
    if isinstance(cached, set) and now - float(_cache["ts"]) < REFRESH_SECONDS:
        _cache["source"] = "live" if _cache.get("source") == "live" else "cache"
        return cached
    try:
        r = await client.get(SANCTIONS_URL, timeout=10.0)
        r.raise_for_status()
        addrs = _parse(r.text)
        if addrs:
            _cache.update({"set": addrs, "ts": now, "source": "live"})
            return addrs
    except httpx.HTTPError:
        pass
    if isinstance(cached, set) and cached:
        _cache["source"] = "cache"
        return cached
    bundled = _bundled()
    if bundled:
        _cache["source"] = "bundled"
        return bundled
    _cache["source"] = "none"
    raise ProviderError("OFAC: список недоступен (сеть, кеш и вшитый снимок пусты)")
