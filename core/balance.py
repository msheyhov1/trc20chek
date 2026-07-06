"""Извлечение баланса кошелька из ответа TronScan /api/account.

Без отдельного запроса — переиспользуем данные, которые уже пришли в
tronscan.fetch_account (там есть TRX-баланс и список токенов с TRC20-балансами).
"""
from __future__ import annotations

from typing import Any

USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def extract_balances(ts_data: dict[str, Any]) -> tuple[float, float]:
    """Возвращает (balance_trx, balance_usdt) из ответа /api/account."""
    if not ts_data:
        return 0.0, 0.0

    # TRX: поле balance в «sun» (1 TRX = 1_000_000 sun)
    try:
        trx = int(ts_data.get("balance") or 0) / 1_000_000
    except (TypeError, ValueError):
        trx = 0.0

    # USDT: ищем контракт USDT в списке токенов
    usdt = 0.0
    tokens = ts_data.get("tokens") or ts_data.get("tokenBalances") or []
    for t in tokens:
        if t.get("tokenId") != USDT_CONTRACT:
            continue
        # amount — уже человекочитаемое значение; иначе считаем из balance/decimals
        try:
            usdt = float(t.get("amount"))
        except (TypeError, ValueError):
            try:
                dec = int(t.get("tokenDecimal", 6))
                usdt = int(t.get("balance") or 0) / (10 ** dec)
            except (TypeError, ValueError):
                usdt = 0.0
        break
    return trx, usdt
