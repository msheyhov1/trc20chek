"""Главный агрегатор: координирует провайдеров и строит итоговый Verdict."""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from . import cache
from .models import AddressVerdict, EntityType, RiskLevel, is_valid_trc20_address
from .providers import goplus, local, tronscan

# Нормализация биржевых меток
EXCHANGE_KEYWORDS: dict[str, str] = {
    "binance": "Binance",
    "okx": "OKX",
    "okex": "OKX",
    "bybit": "Bybit",
    "huobi": "HTX (Huobi)",
    "htx": "HTX (Huobi)",
    "kucoin": "KuCoin",
    "gate.io": "Gate.io",
    "gateio": "Gate.io",
    "bitget": "Bitget",
    "mexc": "MEXC",
    "kraken": "Kraken",
    "coinbase": "Coinbase",
    "bitfinex": "Bitfinex",
    "poloniex": "Poloniex",
    "crypto.com": "Crypto.com",
    "bitstamp": "Bitstamp",
}

# Серьёзные риск-флаги GoPlus → dangerous
CRITICAL_GOPLUS_FLAGS = {
    "phishing_activities",
    "stealing_attack",
    "cybercrime",
    "blackmail_activities",
    "sanctioned",
    "money_laundering",
    "financial_crime",
}


def _normalize_exchange(tag: str | None) -> str | None:
    if not tag:
        return None
    t = tag.lower()
    for key, name in EXCHANGE_KEYWORDS.items():
        if key in t:
            return name
    return None


def _apply_tronscan(data: dict[str, Any], verdict: AddressVerdict) -> None:
    tags = {
        "publicTag": data.get("publicTag", ""),
        "addressTag": data.get("addressTag", ""),
        "redTag": data.get("redTag", ""),
        "greyTag": data.get("greyTag", ""),
        "blueTag": data.get("blueTag", ""),
        "tag1": data.get("tag1", ""),
        "name": data.get("name", ""),
    }
    tags = {k: v for k, v in tags.items() if v}
    if tags:
        verdict.raw_labels["tronscan"] = tags
        verdict.sources.append("TronScan")

    # 1. Красный тег = скам/опасный
    if data.get("redTag"):
        verdict.entity_type = EntityType.SCAM
        verdict.risk_level = RiskLevel.DANGEROUS
        verdict.entity = data["redTag"]
        verdict.risk_flags.append(f"TronScan red tag: {data['redTag']}")
        return

    # 2. Биржа
    main_tag = data.get("publicTag") or data.get("addressTag", "")
    exch = _normalize_exchange(main_tag)
    if exch:
        verdict.entity = exch
        verdict.entity_type = EntityType.EXCHANGE
        verdict.risk_level = RiskLevel.SAFE
        if "hot" in main_tag.lower():
            verdict.risk_flags.append("Exchange hot wallet")
        elif "cold" in main_tag.lower():
            verdict.risk_flags.append("Exchange cold wallet")
        return

    # 3. Контракт
    # TronScan accountv2: контракт = accountType == 2, а сам адрес присутствует
    # ключом в contractMap со значением true. Поля isContract в ответе нет.
    contract_map = data.get("contractMap") or {}
    if data.get("accountType") == 2 or verdict.address in contract_map:
        verdict.entity_type = EntityType.CONTRACT
        verdict.entity = data.get("name") or data.get("tag1") or "Smart contract"
        verdict.risk_level = RiskLevel.SAFE if data.get("vip") else RiskLevel.CAUTION
        return

    # 4. Серый тег = подозрительно
    if data.get("greyTag"):
        verdict.entity_type = EntityType.LABELED
        verdict.entity = data["greyTag"]
        verdict.risk_level = RiskLevel.CAUTION
        verdict.risk_flags.append(f"TronScan grey tag: {data['greyTag']}")
        return

    # 5. Любая другая метка
    if main_tag:
        verdict.entity = main_tag
        verdict.entity_type = EntityType.LABELED
        if verdict.risk_level == RiskLevel.UNKNOWN:
            verdict.risk_level = RiskLevel.CAUTION


def _apply_goplus(data: dict[str, Any], verdict: AddressVerdict) -> None:
    result = (data or {}).get("result") or {}
    if not result:
        return

    raised = [
        k for k, v in result.items()
        if v == "1" and k not in {"data_source", "contract_address"}
    ]
    verdict.raw_labels["goplus"] = {
        "flags_raised": raised,
        "data_source": result.get("data_source"),
    }
    if not raised:
        return

    src = result.get("data_source") or "GoPlus"
    verdict.sources.append(f"GoPlus ({src})")
    for f in raised:
        verdict.risk_flags.append(f"GoPlus: {f.replace('_', ' ')}")

    if any(f in CRITICAL_GOPLUS_FLAGS for f in raised):
        verdict.risk_level = RiskLevel.DANGEROUS
        if verdict.entity_type == EntityType.UNKNOWN:
            verdict.entity_type = EntityType.SCAM
            verdict.entity = "Malicious address (GoPlus)"
    elif verdict.risk_level == RiskLevel.UNKNOWN:
        verdict.risk_level = RiskLevel.CAUTION


def _apply_local(data: dict[str, str] | None, verdict: AddressVerdict) -> None:
    if not data:
        return
    verdict.raw_labels["local"] = data
    verdict.sources.append("Local DB")
    # Локальные метки имеют наивысший приоритет
    verdict.entity = data.get("entity") or verdict.entity
    if data.get("entity_type"):
        try:
            verdict.entity_type = EntityType(data["entity_type"])
        except ValueError:
            pass
    if data.get("risk_level"):
        try:
            verdict.risk_level = RiskLevel(data["risk_level"])
        except ValueError:
            pass
    if data.get("note"):
        verdict.risk_flags.append(f"Local note: {data['note']}")


async def check_address(address: str, use_cache: bool = True) -> AddressVerdict:
    """Главная точка входа.

    - Валидирует адрес
    - Смотрит кеш
    - Параллельно опрашивает TronScan + GoPlus + локальную БД
    - Сводит в единый Verdict
    - Кеширует результат
    """
    if not is_valid_trc20_address(address):
        return AddressVerdict(
            address=address,
            entity="Invalid TRC20 address",
            entity_type=EntityType.UNKNOWN,
            risk_level=RiskLevel.UNKNOWN,
            risk_flags=["Address failed base58check validation"],
        )

    # Кеш
    if use_cache:
        cached = await cache.get(address)
        if cached:
            v = AddressVerdict(
                address=cached["address"],
                entity=cached.get("entity"),
                entity_type=EntityType(cached.get("entity_type", "unknown")),
                risk_level=RiskLevel(cached.get("risk_level", "unknown")),
                risk_flags=cached.get("risk_flags", []),
                sources=cached.get("sources", []),
                raw_labels=cached.get("raw_labels", {}),
                cached=True,
            )
            return v

    # Параллельный запрос провайдеров
    async with httpx.AsyncClient() as client:
        ts_data, gp_data = await asyncio.gather(
            tronscan.fetch_account(address, client),
            goplus.fetch_address_security(address, client),
        )

    verdict = AddressVerdict(address=address)
    _apply_tronscan(ts_data, verdict)
    _apply_goplus(gp_data, verdict)
    _apply_local(local.lookup(address), verdict)

    # Fallback
    if verdict.entity_type == EntityType.UNKNOWN and not verdict.entity:
        verdict.entity = "No public labels"
        verdict.risk_level = RiskLevel.UNKNOWN

    # Кеш
    if use_cache:
        await cache.put(address, verdict.to_dict())

    return verdict
