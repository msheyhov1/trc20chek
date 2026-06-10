"""Главный агрегатор: координирует провайдеров и строит итоговый Verdict."""
from __future__ import annotations

import asyncio
import os
from collections import Counter
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

# 2-хоп анализ связанных кошельков (косвенная санкционная экспозиция).
# Раскрываем топ-N неизвестных посредников и смотрим ИХ санкционную экспозицию.
HOP2_ENABLED = os.getenv("AML_HOP2", "1") not in ("0", "false", "False", "")
HOP2_LIMIT = int(os.getenv("AML_HOP2_LIMIT", "12"))  # сколько посредников раскрывать
HOP2_WEIGHT = 0.6  # вес косвенной (2-хоп) экспозиции относительно прямой
# Ограничение параллелизма hop2, чтобы не бить в QPS-лимит TronScan-ключа.
HOP2_CONCURRENCY = int(os.getenv("AML_HOP2_CONCURRENCY", "4"))

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

    # Активность адреса — для отличия личного кошелька от нетегированного сервиса
    activity = data.get("totalTransactionCount") or data.get("transactions")
    if isinstance(activity, int):
        verdict.raw_labels["activity_tx"] = activity

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


def _detect_exchange_deposit(
    transfers: list[dict[str, Any]], addr: str
) -> tuple[str, int, float] | None:
    """Депозитный адрес биржи (sweep-паттерн).

    У биржевого депозитника одна и та же сумма ПРИХОДИТ от стороннего адреса и
    почти сразу той же суммой УХОДИT на биржу (587.32 in → 587.32 out на Bybit,
    400 → 400, …). Несколько таких совпадающих пар «приход → вывод на ту же
    биржу» — устойчивый признак, что адрес принадлежит депозитной инфраструктуре
    биржи, а не личному кошельку.

    Возвращает (биржа, число_пар, доля_исходящих_на_биржу_покрытых_парами) или
    None. Совпадение сумм — по центам (sweep переводит ровно полученный USDT,
    комиссия в TRX/energy, не в токене), что исключает ложные срабатывания на
    активных трейдерах со случайно похожими суммами."""
    incoming: list[float] = []           # суммы, пришедшие НЕ с биржи
    out_to_exch: list[tuple[float, str]] = []  # (сумма, биржа) — выводы на биржу
    for t in transfers:
        amt = _amount(t)
        if amt <= 0:
            continue
        if addr == t.get("to_address"):
            from_tag = (t.get("from_address_tag") or {}).get("from_address_tag")
            if _normalize_exchange(from_tag):
                continue  # это вывод С биржи (нам пришло), а не депозит-ин
            incoming.append(amt)
        elif addr == t.get("from_address"):
            to_tag = (t.get("to_address_tag") or {}).get("to_address_tag")
            exch = _normalize_exchange(to_tag)
            if exch:
                out_to_exch.append((amt, exch))

    if len(out_to_exch) < 2 or not incoming:
        return None

    # Мультимножество входящих сумм (центы гасят float-шум). Каждую входящую
    # сумму матчим максимум с одним выводом, чтобы не задвоить пары.
    pool = Counter(round(a, 2) for a in incoming)
    pairs_by_exch: dict[str, int] = {}
    for amt, exch in sorted(out_to_exch, key=lambda x: -x[0]):
        key = round(amt, 2)
        if pool.get(key, 0) > 0:
            pool[key] -= 1
            pairs_by_exch[exch] = pairs_by_exch.get(exch, 0) + 1

    if not pairs_by_exch:
        return None
    exch, pairs = max(pairs_by_exch.items(), key=lambda x: x[1])
    if pairs < 2:  # «несколько» совпадающих пар — иначе это просто перевод
        return None
    coverage = round(pairs / len(out_to_exch), 2)
    return exch, pairs, coverage


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

    # Обогащаем, только если сильнее ничего не нашли.
    if verdict.entity_type != EntityType.UNKNOWN:
        return

    # Депозитный адрес биржи? (sweep: пришла сумма — ровно столько ушло на биржу).
    # Для НЕсанкционных бирж это легальная инфраструктура → помечаем как биржу.
    # Если поток идёт на санкционную биржу — НЕ маскируем риск, отдаём в AML.
    deposit = _detect_exchange_deposit(transfers, addr)
    if deposit and deposit[0] not in SANCTIONED_EXCHANGE_NAMES:
        exch, pairs, coverage = deposit
        verdict.entity_type = EntityType.EXCHANGE
        verdict.entity = f"Депозитный кошелёк {exch}"
        verdict.risk_level = RiskLevel.SAFE
        verdict.raw_labels["flow"]["deposit_pattern"] = {
            "exchange": exch, "matched_pairs": pairs, "coverage": coverage,
        }
        verdict.risk_flags.append(
            f"🏦 Депозитный адрес биржи {exch}: {pairs} совпадающих пар "
            f"«приход → вывод на {exch}» одной суммой (sweep-паттерн), "
            f"принадлежит инфраструктуре биржи, а не личному кошельку"
        )
        return

    # Иначе это ЛИЧНЫЙ кошелёк (у самого адреса нет биржевой метки — иначе он был
    # бы EXCHANGE выше); метку имеет контрагент, поэтому «связан с», а не «принадлежит».
    top = links[0]["name"]
    verdict.entity_type = EntityType.WALLET
    verdict.entity = f"Личный кошелёк (связан с {top})"
    verdict.risk_flags.append(
        "ℹ️ Личный кошелёк, не биржа: на самом адресе нет биржевой метки, "
        "связь определена по контрагентам переводов"
    )
    # Эвристика: огромная активность → возможно нетегированный сервис/биржа
    activity = verdict.raw_labels.get("activity_tx") or 0
    if isinstance(activity, int) and activity > 50_000:
        verdict.entity = f"Возможно сервис/биржа (связан с {top}, нетегирован)"
        verdict.risk_flags.append(
            f"⚠️ Очень высокая активность ({activity:,} транзакций) — "
            "возможно нетегированный сервис, а не личный кошелёк"
        )


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


def _parse_transfers(
    addr: str, transfers: list[dict[str, Any]], sanctioned: set[str]
) -> tuple[float, dict[str, dict[str, Any]]]:
    """Сводит переводы в объёмы по контрагентам.

    Возвращает (total_volume, {cp_address: {volume, exch, sanctioned}}).
    Используется и для 1-хоп категорий, и для выбора посредников 2-го хопа."""
    total = 0.0
    per_cp: dict[str, dict[str, Any]] = {}
    for t in transfers:
        if addr == t.get("from_address"):
            cp = t.get("to_address")
            tag = (t.get("to_address_tag") or {}).get("to_address_tag")
        elif addr == t.get("to_address"):
            cp = t.get("from_address")
            tag = (t.get("from_address_tag") or {}).get("from_address_tag")
        else:
            continue
        if not cp:
            continue
        amt = _amount(t)
        total += amt
        d = per_cp.setdefault(
            cp, {"volume": 0.0, "exch": None, "sanctioned": cp in sanctioned}
        )
        d["volume"] += amt
        if d["exch"] is None:
            d["exch"] = _normalize_exchange(tag)
    return total, per_cp


async def _fetch_hop2(
    per_cp: dict[str, dict[str, Any]],
    total: float,
    sanctioned: set[str],
    client: httpx.AsyncClient,
) -> dict[str, Any] | None:
    """2-й хоп: раскрывает топ-N неизвестных посредников (личных кошельков,
    через которые шли деньги) и считает ИХ собственную санкционную экспозицию.
    Так ловятся деньги, отмытые через промежуточный кошелёк."""
    if total <= 0 or HOP2_LIMIT <= 0:
        return None
    # Раскрываем только неизвестные кошельки (не биржи и не санкц. адреса):
    # именно там прячут отмывание. Биржи-контрагенты бессмысленно раскрывать.
    intermediaries = sorted(
        (
            (cp, d["volume"])
            for cp, d in per_cp.items()
            if not d["sanctioned"] and not d["exch"]
        ),
        key=lambda x: -x[1],
    )[:HOP2_LIMIT]
    if not intermediaries:
        return None

    sem = asyncio.Semaphore(HOP2_CONCURRENCY)

    async def _one(cp: str, vol: float) -> dict[str, Any] | None:
        async with sem:
            sub_transfers = await flow.fetch_transfers(cp, client)
        sub_total, sub_cp = _parse_transfers(cp, sub_transfers, sanctioned)
        if sub_total <= 0:
            return None
        dirty = sum(
            d["volume"]
            for d in sub_cp.values()
            if d["sanctioned"] or (d["exch"] in SANCTIONED_EXCHANGE_NAMES)
        )
        if dirty <= 0:
            return None
        exchs = sorted(
            {d["exch"] for d in sub_cp.values() if d["exch"] in SANCTIONED_EXCHANGE_NAMES}
        )
        return {
            "address": cp,
            "our_share": round(vol / total, 4),
            "their_risk_pct": round(dirty / sub_total * 100, 1),
            "sanctioned_exchanges": exchs,
        }

    results = await asyncio.gather(*[_one(cp, vol) for cp, vol in intermediaries])
    flagged = [r for r in results if r]
    # Косвенная экспозиция = Σ (наша доля через посредника × его «грязность»)
    indirect = sum(r["our_share"] * (r["their_risk_pct"] / 100) for r in flagged)
    return {
        "intermediaries_checked": len(intermediaries),
        "flagged": flagged,
        "indirect_exposure_pct": round(indirect * 100, 1),
    }


def _compute_aml(
    verdict: AddressVerdict,
    transfers: list[dict[str, Any]],
    sanctioned: set[str],
    hop2: dict[str, Any] | None = None,
) -> None:
    """Централизованная риск-модель (AML).

    Логика как у профессиональных AML-инструментов:
    - ПРЯМОЕ попадание в OFAC SDN → санкционный, скор 100.
    - КОСВЕННАЯ экспозиция (переводы с/на санкционные адреса) измеряется в %
      объёма, а не «да/нет» — поэтому биржи не клеймятся грязными за то, что
      через них текут любые деньги.
    - 2-й хоп: деньги, пришедшие через посредника, который сам связан с
      санкциями (с понижающим весом HOP2_WEIGHT).
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
    total, per_cp = _parse_transfers(addr, transfers, sanctioned)
    vol = {"sanctions": 0.0, "sanctioned_exchange": 0.0, "exchange": 0.0, "other": 0.0}
    sanctioned_cps: set[str] = set()
    risky_exchanges: set[str] = set()
    for cp, d in per_cp.items():
        amt = d["volume"]
        if d["sanctioned"]:
            vol["sanctions"] += amt
            sanctioned_cps.add(cp)
        elif d["exch"] in SANCTIONED_EXCHANGE_NAMES:
            vol["sanctioned_exchange"] += amt
            risky_exchanges.add(d["exch"])
        elif d["exch"]:
            vol["exchange"] += amt
        else:
            vol["other"] += amt

    def pct(x: float) -> float:
        return round(x / total * 100, 1) if total > 0 else 0.0

    flags_raised = (verdict.raw_labels.get("goplus") or {}).get("flags_raised") or []
    goplus_critical = sorted(f for f in flags_raised if f in CRITICAL_GOPLUS_FLAGS)
    # «Грязный» объём = прямые санкционные адреса + санкционные биржи
    risky_pct = pct(vol["sanctions"] + vol["sanctioned_exchange"])
    indirect_pct = (hop2 or {}).get("indirect_exposure_pct", 0.0) or 0.0

    verdict.aml = {
        "direct_sanctioned": direct,
        "sanctions_exposure_pct": pct(vol["sanctions"]),
        "sanctioned_exchange_exposure_pct": pct(vol["sanctioned_exchange"]),
        "exchange_exposure_pct": pct(vol["exchange"]),
        "other_exposure_pct": pct(vol["other"]),
        "risky_exposure_pct": risky_pct,
        "indirect_sanctions_pct": indirect_pct,
        "hop2_intermediaries_checked": (hop2 or {}).get("intermediaries_checked", 0),
        "hop2_flagged": (hop2 or {}).get("flagged", []),
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
        # прямая экспозиция + косвенная (2-хоп) с понижающим весом
        score = risky_pct + indirect_pct * HOP2_WEIGHT
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
    if indirect_pct > 0 and not direct_danger:
        n = len((hop2 or {}).get("flagged", []))
        verdict.risk_flags.append(
            f"Косвенная связь с санкциями через {n} посредник(ов): "
            f"~{indirect_pct}% объёма (2-й хоп)"
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

        # 2-й хоп: только для кошельков/неизвестных (биржи/контракты/прямые
        # санкции раскрывать бессмысленно — их контрагенты это «все подряд»).
        hop2 = None
        if (
            HOP2_ENABLED
            and address not in sanctioned
            and verdict.entity_type not in (EntityType.EXCHANGE, EntityType.CONTRACT)
        ):
            total_h, per_cp_h = _parse_transfers(address, flow_data, sanctioned)
            hop2 = await _fetch_hop2(per_cp_h, total_h, sanctioned, client)

    _compute_aml(verdict, flow_data, sanctioned, hop2)
    if hop2 and hop2.get("flagged"):
        verdict.sources.append("TronScan flow (2-hop)")
    _apply_local(local.lookup(address), verdict)

    # Fallback: нет публичной метки. risk_level НЕ трогаем — его уже выставил
    # _compute_aml (у адреса может быть реальный риск от экспозиции/2-хопа).
    if verdict.entity_type == EntityType.UNKNOWN and not verdict.entity:
        verdict.entity = "No public labels"

    # Кеш
    if use_cache:
        await cache.put(address, verdict.to_dict())

    return verdict
