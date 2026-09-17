"""TronScan flow-провайдер: анализ контрагентов по TRC20-переводам.

Берёт последние переводы адреса через публичный эндпоинт
https://apilist.tronscanapi.com/api/token_trc20/transfers — он отдаёт метку
контрагента (`from_address_tag` / `to_address_tag`) прямо в ответе, поэтому
по одному запросу видно, с какими размеченными биржами связан адрес.

По документации TronScan `limit` ≤ 50 на запрос, добор — постранично через `start`
при `start + limit ≤ 10000`. Число страниц задаёт FLOW_PAGES (по умолчанию 1 —
как раньше; больше страниц = глубже история, но дольше проверка).

Ключ не обязателен (эндпоинт публичный), но `TRONSCAN_API_KEY` повышает лимит.

Ошибки: если ни одна попытка не дала ответа — ProviderError, а не пустой список
(агрегатор отметит provider_status["flow"] = "error").
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from .base import ProviderError

TRONSCAN_BASE = "https://apilist.tronscanapi.com"
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "")
TRANSFERS_LIMIT = 50  # максимум TronScan на один запрос
FLOW_PAGES = max(1, int(os.getenv("FLOW_PAGES", "1")))


async def _fetch_page(
    address: str, start: int, client: httpx.AsyncClient
) -> list[dict[str, Any]]:
    """Одна страница переводов. Валидный ключ повышает лимиты, но НЕВАЛИДНЫЙ ломает
    запрос (`ApiKey not exists`) — поэтому при неудаче с ключом ретрай без ключа."""
    attempts = [True, False] if TRONSCAN_API_KEY else [False]
    errors: list[str] = []
    for with_key in attempts:
        headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if with_key else {}
        try:
            r = await client.get(
                f"{TRONSCAN_BASE}/api/token_trc20/transfers",
                params={"limit": TRANSFERS_LIMIT, "start": start, "relatedAddress": address},
                headers=headers,
                timeout=10.0,
            )
            r.raise_for_status()
            data = r.json() or {}
            transfers = data.get("token_transfers") if isinstance(data, dict) else None
            if transfers is not None:
                return transfers
            errors.append(f"key={with_key}: no token_transfers in body")
            # тело-ошибка (напр. невалидный ключ) — пробуем следующий вариант
        except (httpx.HTTPError, ValueError) as e:
            errors.append(f"key={with_key}: {e}")
            continue
    raise ProviderError("TronScan transfers: " + "; ".join(errors))


async def fetch_transfers(address: str, client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Последние TRC20-переводы адреса (до FLOW_PAGES × 50). ProviderError, если
    не удалось получить даже первую страницу; неполный добор — не ошибка."""
    out = await _fetch_page(address, 0, client)
    for page in range(1, FLOW_PAGES):
        if len(out) < page * TRANSFERS_LIMIT:
            break  # история закончилась
        try:
            more = await _fetch_page(address, page * TRANSFERS_LIMIT, client)
        except ProviderError:
            break  # первая страница есть — работаем с тем, что добрали
        if not more:
            break
        out.extend(more)
    return out
