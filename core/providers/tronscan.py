"""TronScan API provider.

Основной эндпоинт — https://apilist.tronscanapi.com/api/account (бесплатный,
работает без ключа и отдаёт те же поля, что нужны агрегатору: теги addressTag/
publicTag/redTag/..., accountType/contractMap для контрактов, totalTransactionCount).

Раньше использовался /api/accountv2, но TronScan закрыл его за платным ключом
(отдаёт HTTP 401 без валидного TRON-PRO-API-KEY), из-за чего пропадали ВСЕ метки
и любой адрес определялся как «unknown». accountv2 оставлен как fallback — если
задан рабочий TRONSCAN_API_KEY, он может дать чуть более полные данные.

По актуальной документации TronScan задокументирован только /api/accountv2, а
/api/account — легаси. Различия в наборе меток между ними не подтверждены; в полях
балансов различаются: accountv2 → withPriceTokens[], account → trc20token_balances[]
(см. core/balance.py).

Ключ TRONSCAN_API_KEY опционален: и без него всё работает, с ним — выше лимиты.

Ошибки: если оба эндпоинта недоступны — ProviderError (агрегатор отметит
provider_status["tronscan"] = "error"), а не пустой словарь.
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from .base import ProviderError

TRONSCAN_BASE = "https://apilist.tronscanapi.com"
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "")


async def _get(
    path: str, address: str, client: httpx.AsyncClient, with_key: bool = True
) -> dict[str, Any]:
    headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if (TRONSCAN_API_KEY and with_key) else {}
    r = await client.get(
        f"{TRONSCAN_BASE}{path}",
        params={"address": address},
        headers=headers,
        timeout=10.0,
    )
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, dict):
        raise ValueError("unexpected response shape")
    return data


async def fetch_account(address: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Данные по адресу из TronScan.

    Основной путь — бесплатный /api/account. Если он упал, а ключ задан,
    пробуем /api/accountv2 (платный) как запасной вариант. Оба недоступны →
    ProviderError.
    """
    errors: list[str] = []
    attempts: list[tuple[str, bool]] = [("/api/account", True)]
    if TRONSCAN_API_KEY:
        # Отозванный или опечатанный ключ даёт 401/403 на КАЖДЫЙ запрос, хотя
        # без ключа /api/account работает. Раньше повтора без ключа не было, и
        # недействительный ключ делал «НЕПОЛНОЙ» каждую проверку. Переводы
        # (flow.py) так и устроены — теперь метки тоже.
        attempts += [("/api/account", False), ("/api/accountv2", True)]
    for path, with_key in attempts:
        try:
            return await _get(path, address, client, with_key)
        except (httpx.HTTPError, ValueError) as e:
            errors.append(f"{path.rsplit('/', 1)[-1]}{'' if with_key else ' без ключа'}: {e}")
    raise ProviderError("TronScan: " + "; ".join(errors))
