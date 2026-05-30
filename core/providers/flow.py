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
    """Последние TRC20-переводы адреса. Возвращает [] при ошибке.

    Эндпоинт публичный (работает без ключа). Валидный ключ повышает лимиты,
    но НЕВАЛИДНЫЙ ключ ломает запрос (`ApiKey not exists`) — поэтому при
    неудаче с ключом делаем ретрай без ключа."""
    # С ключом (если есть), затем без — чтобы пережить отозванный/битый ключ.
    attempts = [True, False] if TRONSCAN_API_KEY else [False]
    for with_key in attempts:
        headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if with_key else {}
        try:
            r = await client.get(
                f"{TRONSCAN_BASE}/api/token_trc20/transfers",
                params={"limit": TRANSFERS_LIMIT, "start": 0, "relatedAddress": address},
                headers=headers,
                timeout=10.0,
            )
            r.raise_for_status()
            data = r.json() or {}
            transfers = data.get("token_transfers")
            if transfers is not None:
                return transfers
            # тело-ошибка (напр. невалидный ключ) — пробуем следующий вариант
        except (httpx.HTTPError, ValueError):
            continue
    return []
