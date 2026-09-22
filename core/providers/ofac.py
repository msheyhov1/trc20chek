"""OFAC SDN — прямой матч санкционных адресов (TRON).

Источник: репозиторий 0xB10C, который ночью извлекает крипто-адреса из
официального OFAC SDN-списка (Specially Designated Nationals) США.

Ключ не нужен — это публичные raw-файлы на GitHub.

## Почему файлов несколько

Фид разложен ПО АКТИВАМ, а не по сетям, и OFAC перечисляет адрес вместе с тем
активом, который через него шёл. TRON-адреса из-за этого лежат не только в
`sanctioned_addresses_TRX.txt`: замер 22.09.2026 (docs/research/ofac_assets.md)

    TRX  — 254 адреса, все TRON
    USDT —  94 записи, из них 79 TRON-формата, и все 79 ОТСУТСТВУЮТ в TRX
    XBT  — 532 записи, из них 1 TRON-формата, тоже не в TRX

То есть чтение одного файла TRX давало 254 адреса вместо 334: 80 санкционных
TRON-адресов проходили проверку без пометки «санкционный напрямую» — ровно тот
сценарий, ради которого сервис существует. Логично, что они в файле USDT: на
TRON основной оборот именно в USDT.

Поэтому тянем несколько файлов и ОБЪЕДИНЯЕМ множества, а каждую строку
фильтруем через `is_valid_trc20_address` — в файлах USDT/XBT лежат и адреса
других сетей, они не должны попасть в наше множество.

Состав файлов меняется через env `OFAC_ASSETS` (коды активов через запятую),
чтобы новый актив не требовал редеплоя.

## Деградация

Чтобы проверка санкций не отключалась молча из-за одного недоступного хоста:
  1. живой список с GitHub                 → source = "live"
  2. прошлый ответ из памяти (даже старый)  → source = "cache"
  3. снимок, вшитый в репозиторий           → source = "bundled"
  4. ничего                                 → source = "none" + ProviderError

Живым результат считается, только если скачались ВСЕ запрошенные файлы.
Частичное объединение опаснее устаревшего снимка: недостающий файл — это молча
пропавшие сотни адресов, а снимок отстаёт максимум на дни и это видно в
provider_status.
"""
from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import httpx

from ..models import is_valid_trc20_address
from .base import ProviderError

LISTS_BASE = (
    "https://raw.githubusercontent.com/0xB10C/"
    "ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_"
)


def _assets() -> tuple[str, ...]:
    """Какие файлы фида читать. TRX — родной актив сети, USDT — основной оборот
    TRON и второй по величине источник TRON-адресов, USDC — на случай, если
    следующий листинг попадёт туда, XBT — там уже лежит один TRON-адрес."""
    raw = os.getenv("OFAC_ASSETS", "").strip()
    if not raw:
        return ("TRX", "USDT", "USDC", "XBT")
    out = tuple(a.strip().upper() for a in raw.replace(";", ",").split(",") if a.strip())
    return out or ("TRX",)


ASSETS: tuple[str, ...] = _assets()
REFRESH_SECONDS = 24 * 3600

# Снимок списка — запасной вариант при недоступном GitHub. Лежит ВНУТРИ пакета
# core, а не в docs/: Dockerfile копирует только core/api/bot/web, поэтому из
# docs/ файл в образ бы не попал и fallback молча не работал бы в проде.
BUNDLED_PATH = Path(__file__).resolve().parent.parent / "data" / "ofac_sanctioned_trx.txt"

# Модульный кеш: список меняется редко, тянуть на каждый запрос незачем.
_cache: dict[str, object] = {"set": None, "ts": 0.0, "source": "none", "assets": ()}


def _parse(text: str) -> set[str]:
    """Строки файла → множество TRON-адресов.

    Фильтр по формату обязателен: в файлах по активам лежат адреса всех сетей
    (ETH, BTC, …), а `_cache` используется как множество «санкционных TRON»."""
    return {
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.startswith("#") and is_valid_trc20_address(ln.strip())
    }


def _bundled() -> set[str]:
    try:
        return _parse(BUNDLED_PATH.read_text(encoding="utf-8"))
    except OSError:
        return set()


def last_source() -> str:
    """Откуда взят список в последнем вызове: live | cache | bundled | none."""
    return str(_cache.get("source") or "none")


def last_assets() -> tuple[str, ...]:
    """Какие файлы фида дали последний живой список (для отчёта и тестов)."""
    got = _cache.get("assets")
    return tuple(got) if isinstance(got, tuple | list) else ()


async def _fetch_asset(asset: str, client: httpx.AsyncClient) -> set[str] | None:
    """Один файл фида. None — файл не скачался (ошибка сети/HTTP)."""
    try:
        r = await client.get(f"{LISTS_BASE}{asset}.txt", timeout=10.0)
        r.raise_for_status()
    except httpx.HTTPError:
        return None
    return _parse(r.text)


async def fetch_sanctioned_set(client: httpx.AsyncClient) -> set[str]:
    """Множество санкционных TRON-адресов из всех файлов `ASSETS`.

    При сбое сети — прошлый кеш, затем вшитый снимок; ProviderError только
    если нет вообще ничего."""
    now = time.time()
    cached = _cache["set"]
    if isinstance(cached, set) and now - float(_cache["ts"]) < REFRESH_SECONDS:
        _cache["source"] = "live" if _cache.get("source") == "live" else "cache"
        return cached

    results = await asyncio.gather(*[_fetch_asset(a, client) for a in ASSETS])
    if all(r is not None for r in results):
        addrs: set[str] = set()
        for r in results:
            addrs |= r or set()
        if addrs:
            _cache.update({"set": addrs, "ts": now, "source": "live", "assets": ASSETS})
            return addrs

    if isinstance(cached, set) and cached:
        _cache["source"] = "cache"
        return cached
    bundled = _bundled()
    if bundled:
        _cache["source"] = "bundled"
        return bundled
    _cache["source"] = "none"
    raise ProviderError("OFAC: список недоступен (сеть, кеш и вшитый снимок пусты)")
