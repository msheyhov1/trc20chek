"""Блокировка адреса эмитентом стейблкоина (Tether, USDT-TRC20).

Зачем это важнее прочих сигналов: сервис отвечает на вопрос «можно ли сюда
отправлять USDT», а блокировка на самом контракте — единственное, что делает
USDT физически неподвижным. Заморожённые средства не спасёт никакая репутация
контрагента, и наоборот: адрес без меток может быть уже заблокирован.

Два независимых пути (используем оба, контракт приоритетнее):

1. Вызов контракта — авторитетный источник.
   POST {TRONGRID}/wallet/triggerconstantcontract
   function_selector = "isBlackListed(address)"   ← заглавная L обязательна;
   строчный вариант isBlacklisted — другая функция, у Tether её нет.
   Селектор 0xe47d6060 (посчитан локально, см. docs/research/keccak_selectors.py).
   Ответ: сначала result.result == true, затем constant_result[0] —
   32-байтовое слово; НЕНУЛЕВОЕ означает блокировку. Отсутствие
   constant_result — «не удалось проверить», а не «чисто».

2. Агрегация TronScan — дешёвый путь на хосте, куда мы и так ходим.
   GET {TRONSCAN}/api/security/account/data?address=… → поле is_black_list
   («в блэклисте стейблкоина»).

Провайдер различает ТРИ исхода: заблокирован, не заблокирован, не удалось
проверить. Третий не должен выглядеть как второй — иначе повторяется дефект
«сбой источника неотличим от чистого результата».

ENV:
  TRONGRID_API_URL   — по умолчанию https://api.trongrid.io
  TRONGRID_API_KEY   — опционален, поднимает лимиты (free: ~100k/сутки, 15 QPS)
  USDT_CONTRACT      — контракт USDT-TRC20 (по умолчанию боевой)
  TETHER_BLACKLIST_CHECK=0 — выключить проверку целиком
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from ..models import _base58_decode
from .base import ProviderError

PROVIDER = "Tether blacklist"

TRONGRID_URL = os.getenv("TRONGRID_API_URL", "https://api.trongrid.io").rstrip("/")
TRONGRID_API_KEY = os.getenv("TRONGRID_API_KEY", "").strip()
TRONSCAN_BASE = "https://apilist.tronscanapi.com"
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "")
USDT_CONTRACT = os.getenv("USDT_CONTRACT", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")

FUNCTION_SELECTOR = "isBlackListed(address)"
ENABLED = os.getenv("TETHER_BLACKLIST_CHECK", "1") not in ("0", "false", "False")


def is_enabled() -> bool:
    return ENABLED


def address_to_param(address: str) -> str:
    """base58 TRON-адрес → 32-байтовый ABI-параметр (hex, без префикса 41).

    TRON-адрес внутри — 21 байт: 0x41 + 20 байт. В ABI уходят именно эти 20
    байт, дополненные слева нулями до 32."""
    decoded = _base58_decode(address)
    if len(decoded) != 25 or decoded[0] != 0x41:
        raise ProviderError(f"{PROVIDER}: адрес не похож на TRON ({address})")
    return decoded[1:21].hex().rjust(64, "0")


async def _via_contract(address: str, client: httpx.AsyncClient) -> bool:
    """Чтение isBlackListed у контракта. ProviderError, если ответ непонятен."""
    headers = {"Content-Type": "application/json"}
    if TRONGRID_API_KEY:
        headers["TRON-PRO-API-KEY"] = TRONGRID_API_KEY
    payload = {
        "owner_address": USDT_CONTRACT,
        "contract_address": USDT_CONTRACT,
        "function_selector": FUNCTION_SELECTOR,
        "parameter": address_to_param(address),
        "visible": True,
    }
    try:
        r = await client.post(
            f"{TRONGRID_URL}/wallet/triggerconstantcontract",
            json=payload,
            headers=headers,
            timeout=10.0,
        )
        r.raise_for_status()
        data = r.json() or {}
    except (httpx.HTTPError, ValueError) as e:
        raise ProviderError(f"{PROVIDER}: TronGrid недоступен ({e})") from e

    if not isinstance(data, dict):
        raise ProviderError(f"{PROVIDER}: неожиданный ответ TronGrid")
    result = data.get("result") or {}
    if isinstance(result, dict) and result.get("result") is not True:
        reason = result.get("message") or data.get("Error") or "вызов отклонён"
        raise ProviderError(f"{PROVIDER}: {reason}")
    words = data.get("constant_result")
    if not isinstance(words, list) or not words:
        # Пустой ответ — это «не знаем», а не «не заблокирован».
        raise ProviderError(f"{PROVIDER}: контракт не вернул значение")
    try:
        return int(str(words[0]), 16) != 0
    except ValueError as e:
        raise ProviderError(f"{PROVIDER}: не разобрать значение {words[0]!r}") from e


async def _via_tronscan(address: str, client: httpx.AsyncClient) -> bool:
    """Агрегация TronScan: поле is_black_list. Запасной и более дешёвый путь."""
    headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if TRONSCAN_API_KEY else {}
    try:
        r = await client.get(
            f"{TRONSCAN_BASE}/api/security/account/data",
            params={"address": address},
            headers=headers,
            timeout=10.0,
        )
        r.raise_for_status()
        data = r.json() or {}
    except (httpx.HTTPError, ValueError) as e:
        raise ProviderError(f"{PROVIDER}: TronScan security недоступен ({e})") from e
    if not isinstance(data, dict) or "is_black_list" not in data:
        raise ProviderError(f"{PROVIDER}: TronScan не вернул is_black_list")
    return bool(data["is_black_list"])


async def check(address: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Заблокирован ли адрес эмитентом.

    Возвращает {blacklisted: bool, source: str} либо бросает ProviderError,
    если ни один путь не дал ответа. «Не удалось проверить» обязано отличаться
    от «не заблокирован»."""
    if not ENABLED:
        raise ProviderError(f"{PROVIDER}: проверка выключена (TETHER_BLACKLIST_CHECK=0)")

    errors: list[str] = []
    try:
        return {"blacklisted": await _via_contract(address, client), "source": "contract"}
    except ProviderError as e:
        errors.append(str(e))
    try:
        return {"blacklisted": await _via_tronscan(address, client), "source": "tronscan"}
    except ProviderError as e:
        errors.append(str(e))
    raise ProviderError("; ".join(errors))
