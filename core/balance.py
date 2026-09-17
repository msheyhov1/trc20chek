"""Извлечение баланса кошелька из ответа TronScan.

Без отдельного запроса — переиспользуем данные, которые уже пришли в
tronscan.fetch_account (там есть TRX-баланс и список токенов с TRC20-балансами).

Реальные имена полей (подтверждены документацией TronScan и продакшн-кодом
нескольких независимых клиентов, см. ROADMAP.md §5.4):
  /api/accountv2 → withPriceTokens[]     {tokenId, balance, amount, tokenDecimal, ...}
  /api/account   → trc20token_balances[] {tokenId, contract_address, balance, tokenDecimal?}
Полей `tokens` / `tokenBalances`, которые читались раньше, в ответе нет —
из-за этого баланс USDT всегда был 0. Читаем все известные варианты.
"""
from __future__ import annotations

from typing import Any

USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

# Порядок = предпочтение: документированное поле accountv2 первым.
_TOKEN_LIST_KEYS = (
    "withPriceTokens",
    "trc20token_balances",
    "tokens",
    "tokenBalances",
    "balances",
)
_TOKEN_ID_KEYS = ("tokenId", "token_id", "contract_address", "contractAddress")
_DECIMALS_KEYS = ("tokenDecimal", "token_decimal", "decimals")


def _first(d: dict[str, Any], keys: tuple[str, ...], default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default


def _to_float(x: Any) -> float | None:
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _token_amount(t: dict[str, Any], default_decimals: int = 6) -> float:
    """Человекочитаемая сумма: готовое `amount`/`quantity`, иначе balance / 10**decimals."""
    for k in ("amount", "quantity"):
        v = _to_float(t.get(k))
        if v is not None:
            return v
    raw = _to_float(t.get("balance"))
    if raw is None:
        return 0.0
    try:
        dec = int(_first(t, _DECIMALS_KEYS, default_decimals))
    except (TypeError, ValueError):
        dec = default_decimals
    return raw / (10 ** dec)


def extract_balances(ts_data: dict[str, Any]) -> tuple[float, float]:
    """Возвращает (balance_trx, balance_usdt) из ответа /api/account или /api/accountv2."""
    if not ts_data:
        return 0.0, 0.0

    # TRX: поле balance в «sun» (1 TRX = 1_000_000 sun)
    try:
        trx = int(ts_data.get("balance") or 0) / 1_000_000
    except (TypeError, ValueError):
        trx = 0.0

    usdt = 0.0
    for list_key in _TOKEN_LIST_KEYS:
        tokens = ts_data.get(list_key)
        if not isinstance(tokens, list):
            continue
        for t in tokens:
            if not isinstance(t, dict):
                continue
            if _first(t, _TOKEN_ID_KEYS) != USDT_CONTRACT:
                continue
            usdt = _token_amount(t, 6)
            return trx, usdt
    return trx, usdt
