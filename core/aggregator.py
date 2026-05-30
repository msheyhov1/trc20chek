"""Главный агрегатор: координирует провайдеров и строит итоговый Verdict."""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

from . import cache
from .models import AddressVerdict, EntityType, RiskLevel, is_valid_trc20_address
from .providers import flow, goplus, local, ofac, tronscan

# Нормализация биржевых меток
EXCHANGE_KEYWORDS: dict[str, str] = {
    "binance": "Binance",
    "okx": "OKX",
    "okex": "OKX",
    "bybit": "Bybit",
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

# Биржи под санкциями. Деньги с них блокируются комплаенсом ("заморозка").
# Источники: UK A7-пакет от 26.05.2026 (HTX/Huobi, EXMO, Bitpapa, Rapira,
# Aifory, Arvix, ABCEX) + OFAC (Garantex/Grinex/Cryptex).
# Ловим по тегам TronScan: и сам хот-кошелёк биржи, и переводы с/на него.
SANCTIONED_EXCHANGES: dict[str, str] = {
    "exmo": "EXMO",
    "rapira": "Rapira",
    "abcex": "ABCEX",
    "bitpapa": "Bitpapa",
    "htx": "HTX (Huobi)",
    "huobi": "HTX (Huobi)",
    "arvix": "Arvix",
    "aifory": "Aifory",
    "garantex": "Garantex",
    "grinex": "Grinex",
    "cryptex": "Cryptex",
}
SANCTIONED_EXCHANGE_NAMES = set(SANCTIONED_EXCHANGES.values())

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


_ALL_EXCHANGES = {**EXCHANGE_KEYWORDS, **SANCTIONED_EXCHANGES}


def _normalize_exchange(tag: str | None) -> str | None:
    if not tag:
        return None
    t = tag.lower()
    for key, name in _ALL_EXCHANGES.items():
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
    """Только собирает риск-флаги GoPlus. Решения о risk_level/entity_type
    принимает _compute_aml (централизованная риск-модель)."""
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


def _apply_flow(transfers: list[dict[str, Any]], verdict: AddressVerdict) -> None:
    """Анализ контрагентов: с какими биржами и как часто взаимодействует адрес.

    Не утверждает «адрес = биржа» — определяет, что это кошелёк, связанный с
    биржей (депозиты/выводы). Обогащает вердикт только если адрес не опознан
    более сильным источником (контракт, прямая метка, скам)."""
    if not transfers:
        return

    counts: dict[str, dict[str, int]] = {}
    addr = verdict.address
    for t in transfers:
        if addr == t.get("from_address"):
            tag = (t.get("to_address_tag") or {}).get("to_address_tag")
            direction = "deposits"  # адрес отправил на контрагента
        elif addr == t.get("to_address"):
            tag = (t.get("from_address_tag") or {}).get("from_address_tag")
            direction = "withdrawals"  # адрес получил от контрагента
        else:
            continue
        exch = _normalize_exchange(tag)
        if not exch:
            continue
        c = counts.setdefault(exch, {"deposits": 0, "withdrawals": 0})
        c[direction] += 1

    if not counts:
        return

    links = sorted(
        (
            {
                "name": name,
                "deposits": v["deposits"],
                "withdrawals": v["withdrawals"],
                "total": v["deposits"] + v["withdrawals"],
                "sanctioned": name in SANCTIONED_EXCHANGE_NAMES,
            }
            for name, v in counts.items()
        ),
        key=lambda x: -x["total"],
    )
    verdict.exchange_links = links
    verdict.raw_labels["flow"] = {"exchange_links": links}
    verdict.sources.append("TronScan flow")

    # Обогащаем, только если сильнее ничего не нашли
    if verdict.entity_type == EntityType.UNKNOWN:
        top = links[0]["name"]
        verdict.entity_type = EntityType.WALLET
        verdict.entity = f"Кошелёк (связан с {top})"


def _amount(t: dict[str, Any]) -> float:
    """Нормализованная сумма перевода (с учётом decimals). 0 при сбое.

    Прим.: суммируем разные токены как сопоставимые — это аппроксимация.
    В TRC20 подавляющая часть оборота — USDT (≈$1), так что для оценки
    ДОЛИ экспозиции этого достаточно."""
    try:
        q = int(t.get("quant") or 0)
        dec = int((t.get("tokenInfo") or {}).get("tokenDecimal", 6))
        return q / (10 ** dec)
    except (TypeError, ValueError):
        return 0.0


def _compute_aml(
    verdict: AddressVerdict,
    transfers: list[dict[str, Any]],
    sanctioned: set[str],
) -> None:
    """Централизованная риск-модель (AML).

    Логика как у профессиональных AML-инструментов:
    - ПРЯМОЕ попадание в OFAC SDN → санкционный, скор 100.
    - КОСВЕННАЯ экспозиция (переводы с/на санкционные адреса) измеряется в %
      объёма, а не «да/нет» — поэтому биржи не клеймятся грязными за то, что
      через них текут любые деньги.
    - Известные сервисы (биржа/контракт) не понижаются в риске за косвенную
      экспозицию (только прямая санкция/скам их роняет)."""
    addr = verdict.address
    direct = addr in sanctioned

    # Сам адрес — хот-кошелёк санкционной биржи? (по тегу TronScan)
    self_sanctioned_exch = (
        verdict.entity_type == EntityType.EXCHANGE
        and verdict.entity in SANCTIONED_EXCHANGE_NAMES
    )

    # 1-хоп экспозиция по объёму контрагентов
    vol = {"sanctions": 0.0, "sanctioned_exchange": 0.0, "exchange": 0.0, "other": 0.0}
    total = 0.0
    sanctioned_cps: set[str] = set()
    risky_exchanges: set[str] = set()
    for t in transfers:
        if addr == t.get("from_address"):
            cp = t.get("to_address")
            tag = (t.get("to_address_tag") or {}).get("to_address_tag")
        elif addr == t.get("to_address"):
            cp = t.get("from_address")
            tag = (t.get("from_address_tag") or {}).get("from_address_tag")
        else:
            continue
        amt = _amount(t)
        total += amt
        exch = _normalize_exchange(tag)
        if cp in sanctioned:
            vol["sanctions"] += amt
            sanctioned_cps.add(cp)
        elif exch and exch in SANCTIONED_EXCHANGE_NAMES:
            vol["sanctioned_exchange"] += amt
            risky_exchanges.add(exch)
        elif exch:
            vol["exchange"] += amt
        else:
            vol["other"] += amt

    def pct(x: float) -> float:
        return round(x / total * 100, 1) if total > 0 else 0.0

    flags_raised = (verdict.raw_labels.get("goplus") or {}).get("flags_raised") or []
    goplus_critical = sorted(f for f in flags_raised if f in CRITICAL_GOPLUS_FLAGS)
    # «Грязный» объём = прямые санкционные адреса + санкционные биржи
    risky_pct = pct(vol["sanctions"] + vol["sanctioned_exchange"])

    verdict.aml = {
        "direct_sanctioned": direct,
        "sanctions_exposure_pct": pct(vol["sanctions"]),
        "sanctioned_exchange_exposure_pct": pct(vol["sanctioned_exchange"]),
        "exchange_exposure_pct": pct(vol["exchange"]),
        "other_exposure_pct": pct(vol["other"]),
        "risky_exposure_pct": risky_pct,
        "transfers_analyzed": len(transfers),
        "sanctioned_counterparties": sorted(sanctioned_cps),
        "sanctioned_exchanges": sorted(risky_exchanges),
        "goplus_critical_flags": goplus_critical,
    }

    # Известный ЛЕГАЛЬНЫЙ сервис (биржа/контракт, НЕ санкционный): косвенная
    # экспозиция через него ОЖИДАЕМА и не делает его грязным.
    known_service = (
        verdict.entity_type in (EntityType.EXCHANGE, EntityType.CONTRACT)
        and not self_sanctioned_exch
    )

    # ---- Скор 0-100 ----
    if direct or self_sanctioned_exch or verdict.entity_type == EntityType.SCAM:
        score = 100.0  # прямой сигнал об адресе — бьёт всё
    elif goplus_critical:
        score = 90.0
    elif known_service:
        score = 10.0 if flags_raised else 0.0
    else:
        score = risky_pct  # экспозиция к санкциям и санкционным биржам — драйвер
        if flags_raised:
            score = max(score, 20.0)
    verdict.risk_score = int(round(min(100.0, score)))

    # ---- Прямое попадание в OFAC ----
    if direct:
        verdict.entity_type = EntityType.SANCTIONED
        if not verdict.entity or verdict.entity == "No public labels":
            verdict.entity = "Санкционный адрес (OFAC SDN)"
        verdict.risk_flags.insert(0, "🚨 Адрес в санкционном списке OFAC SDN")
        if "OFAC SDN" not in verdict.sources:
            verdict.sources.append("OFAC SDN")

    # ---- Сам адрес — кошелёк санкционной биржи ----
    elif self_sanctioned_exch:
        verdict.entity_type = EntityType.SANCTIONED
        verdict.entity = f"{verdict.entity} (санкционная биржа)"
        verdict.risk_flags.insert(0, "🚨 Хот-кошелёк санкционной биржи (UK/OFAC)")

    # ---- GoPlus critical на самом адресе ----
    if goplus_critical and not direct and verdict.entity_type == EntityType.UNKNOWN:
        verdict.entity_type = EntityType.SCAM
        verdict.entity = verdict.entity or "Вредоносный адрес (GoPlus)"

    # ---- Синтез risk_level ----
    direct_danger = (
        direct or self_sanctioned_exch or bool(goplus_critical)
        or verdict.entity_type in (EntityType.SCAM, EntityType.SANCTIONED)
    )
    if direct_danger:
        verdict.risk_level = RiskLevel.DANGEROUS
    elif not known_service:
        if verdict.risk_score >= 70:
            verdict.risk_level = RiskLevel.DANGEROUS
        elif verdict.risk_score >= 20:
            verdict.risk_level = RiskLevel.CAUTION
    # иначе оставляем то, что выставил TronScan (SAFE для биржи и т.п.)

    # ---- Поясняющие флаги экспозиции ----
    if vol["sanctions"] > 0 and not direct:
        verdict.risk_flags.append(
            f"Экспозиция к санкционным адресам: {pct(vol['sanctions'])}% объёма "
            f"({len(sanctioned_cps)} контрагент(ов))"
        )
    if vol["sanctioned_exchange"] > 0 and not self_sanctioned_exch:
        verdict.risk_flags.append(
            f"⚠️ Переводы с санкционными биржами ({', '.join(sorted(risky_exchanges))}): "
            f"{pct(vol['sanctioned_exchange'])}% объёма — деньги могут заморозить"
        )


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
                exchange_links=cached.get("exchange_links", []),
                risk_score=cached.get("risk_score", 0),
                aml=cached.get("aml", {}),
                cached=True,
            )
            return v

    # Параллельный запрос провайдеров
    async with httpx.AsyncClient() as client:
        ts_data, gp_data, flow_data, sanctioned = await asyncio.gather(
            tronscan.fetch_account(address, client),
            goplus.fetch_address_security(address, client),
            flow.fetch_transfers(address, client),
            ofac.fetch_sanctioned_set(client),
        )

    verdict = AddressVerdict(address=address)
    _apply_tronscan(ts_data, verdict)
    _apply_goplus(gp_data, verdict)
    _apply_flow(flow_data, verdict)
    _compute_aml(verdict, flow_data, sanctioned)
    _apply_local(local.lookup(address), verdict)

    # Fallback
    if verdict.entity_type == EntityType.UNKNOWN and not verdict.entity:
        verdict.entity = "No public labels"
        verdict.risk_level = RiskLevel.UNKNOWN

    # Кеш
    if use_cache:
        await cache.put(address, verdict.to_dict())

    return verdict
