"""Главный агрегатор: координирует провайдеров и строит итоговый Verdict."""
from __future__ import annotations

import asyncio
import os
from collections import Counter
from typing import Any

import httpx

from . import aml_external, balance, cache, cluster
from .models import AddressVerdict, EntityType, RiskLevel, is_valid_trc20_address
from .providers import flow, goplus, local, ofac, tronscan

# Туннель: для этих типов внешний AML-API НЕ запрашивается
# (биржа/депозитник биржи/контракт — инфраструктура; скам/санкции уже помечены).
_AML_SKIP_TYPES = frozenset(
    {EntityType.EXCHANGE, EntityType.CONTRACT, EntityType.SCAM, EntityType.SANCTIONED}
)

# Доля доминирующей биржевой сущности в AML, при которой НЕразмеченный адрес
# считаем биржей/сервисом. Swapster видит off-chain принадлежность, которой нет
# у TronScan/on-chain (напр. транзитный хаб биржи без публичной метки). Тюнится env.
AML_EXCHANGE_ENTITY_THRESHOLD = float(os.getenv("AML_EXCHANGE_ENTITY_THRESHOLD", "0.9"))


def _relabel_from_swapster(verdict: AddressVerdict, is_transit: bool) -> None:
    """Помечаем неопознанный адрес как биржу/сервис ТОЛЬКО если выполнено И то, И другое:
      1) Swapster показал доминирующую биржевую сущность (EXCHANGE*) ≥ порога;
      2) адрес ведёт себя как ТРАНЗИТ (форвардит ~всё полученное, не копит баланс).

    Второе условие отсекает обычного юзера, который «всегда заводит с биржи» и
    держит/тратит средства: у него высокая биржевая экспозиция, но он НЕ транзит.
    Инфраструктура биржи (депозитник/хаб) — именно транзит."""
    if verdict.entity_type not in (EntityType.WALLET, EntityType.UNKNOWN, EntityType.LABELED):
        return
    if not is_transit:
        return
    ext = verdict.external_aml or {}
    if not ext.get("available") or ext.get("pending"):
        return
    entities = ext.get("entities") or []
    if not entities:
        return
    top = max(entities, key=lambda e: e.get("risk_score") or 0)
    share = (top.get("risk_score") or 0) / 100.0
    name = top.get("entity") or ""
    if "EXCHANGE" in name.upper() and share >= AML_EXCHANGE_ENTITY_THRESHOLD:
        verdict.entity_type = EntityType.EXCHANGE
        verdict.entity = f"Биржа/сервис (Swapster: {name} {top.get('risk_score')}%)"
        try:
            verdict.risk_level = RiskLevel(ext.get("risk_level"))
        except ValueError:
            pass
        if "Swapster" not in verdict.sources:
            verdict.sources.append("Swapster")


# Транзит: адрес форвардит ≥ этой доли полученного и не копит существенный баланс.
TRANSIT_FORWARD_RATIO = 0.8


def _is_transit(transfers: list[dict[str, Any]], addr: str, balance_usdt: float) -> bool:
    """Пересылает почти всё полученное и держит ~0 (инфраструктура, не личный кошелёк)."""
    tin = tout = 0.0
    for t in transfers:
        amt = _amount(t)
        if amt <= 0:
            continue
        if t.get("from_address") == addr:
            tout += amt
        elif t.get("to_address") == addr:
            tin += amt
    if tin <= 0:
        return False
    return tout >= TRANSIT_FORWARD_RATIO * tin and balance_usdt < 0.1 * tin

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

# Депозитный/транзитный адрес биржи (funnel-эвристика, см. _detect_exchange_deposit).
# Концентрация оттока на одну биржу и доля пересылаемого — пороги распознавания.
DEPOSIT_CONCENTRATION = 0.9   # ≥90% оттока на одну биржу
DEPOSIT_FORWARD_RATIO = 0.5   # пересылает ≥50% полученного извне
DEPOSIT_BACKFLOW_RATIO = 0.15  # приход С этой биржи ≤15% оттока на неё (газ, не торговля)

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
) -> dict[str, Any] | None:
    """Депозитный / транзитный адрес биржи (funnel-паттерн).

    Узнаётся по поведению, как «deposit address» у Arkham/Chainalysis (без их
    off-chain кластеризации, только on-chain эвристика):
      • адрес ПОЛУЧАЕТ средства от сторонних адресов и пересылает почти весь
        отток на ОДНУ биржу (концентрация оттока ≥ DEPOSIT_CONCENTRATION);
      • сам ОТ этой биржи ничего не получает — иначе это личный торговый
        кошелёк, который и заводит, и выводит (ключевой дискриминатор);
      • транзит: пересылает существенную долю полученного (баланс не копит).

    Суммы НЕ обязаны совпадать 1:1 — депозитник часто АГРЕГИРУЕТ несколько
    приходов в один вывод (4129.33 + 10 + 20 → 4159.33 на Bybit). Поэтому
    смотрим не совпадение сумм, а концентрацию и пересылку по объёму.

    Возвращает dict с деталями или None."""
    out_exch: dict[str, float] = {}   # отток на биржи, по биржам
    out_other = 0.0                   # отток на не-биржи
    in_exch: dict[str, float] = {}    # приток С бирж (выводы), по биржам
    in_other = 0.0                    # приток от не-бирж («депозиты» пользователей)
    in_sources: set[str] = set()
    in_amounts: list[float] = []
    out_pairs: list[tuple[float, str]] = []
    # Якоря кластера: адреса хот/сборных кошельков биржи, куда уходит отток
    anchors: dict[str, dict[str, float]] = {}  # exch -> {hot_wallet_addr: volume}
    for t in transfers:
        amt = _amount(t)
        if amt <= 0:
            continue
        if addr == t.get("from_address"):
            exch = _normalize_exchange((t.get("to_address_tag") or {}).get("to_address_tag"))
            if exch:
                out_exch[exch] = out_exch.get(exch, 0.0) + amt
                out_pairs.append((amt, exch))
                dst = t.get("to_address")
                if dst:
                    anchors.setdefault(exch, {})[dst] = (
                        anchors.setdefault(exch, {}).get(dst, 0.0) + amt
                    )
            else:
                out_other += amt
        elif addr == t.get("to_address"):
            exch = _normalize_exchange((t.get("from_address_tag") or {}).get("from_address_tag"))
            if exch:
                in_exch[exch] = in_exch.get(exch, 0.0) + amt
            else:
                in_other += amt
                in_amounts.append(amt)
                if t.get("from_address"):
                    in_sources.add(t["from_address"])

    if not out_exch:
        return None
    total_out = sum(out_exch.values()) + out_other
    exch = max(out_exch, key=lambda k: out_exch[k])
    out_e = out_exch[exch]
    concentration = out_e / total_out if total_out > 0 else 0.0

    # funnel-критерии депозитника
    is_deposit = (
        concentration >= DEPOSIT_CONCENTRATION   # почти весь отток — на одну биржу
        # от этой биржи приходит мало относительно оттока на неё: газ-пополнения
        # для sweep — норма, а вот сопоставимый обратный поток = личный торговый
        # кошелёк (и заводит, и выводит), это НЕ депозитник.
        and in_exch.get(exch, 0.0) <= DEPOSIT_BACKFLOW_RATIO * out_e
        and in_other > 0                          # есть внешние «депозиты»
        and len(in_amounts) >= 2                  # не одиночный перевод
        and out_e >= DEPOSIT_FORWARD_RATIO * in_other  # пересылает бóльшую часть
    )
    if not is_deposit:
        return None

    # sweep-пары 1:1 по центам — необязательны, но усиливают вывод (для UI)
    pool = Counter(round(a, 2) for a in in_amounts)
    pairs = 0
    for amt, e in out_pairs:
        key = round(amt, 2)
        if e == exch and pool.get(key, 0) > 0:
            pool[key] -= 1
            pairs += 1

    # Якорь кластера — хот/сборный кошелёк биржи, на который уходит больше всего.
    exch_anchors = anchors.get(exch, {})
    hot_wallet = max(exch_anchors, key=lambda a: exch_anchors[a]) if exch_anchors else None

    return {
        "exchange": exch,
        "concentration": round(concentration, 2),
        "forwarded_pct": round(min(out_e / in_other, 9.99) * 100, 1),
        "in_sources": len(in_sources),
        "matched_pairs": pairs,
        "hot_wallet": hot_wallet,
        "sanctioned": exch in SANCTIONED_EXCHANGE_NAMES,
    }


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

    # Депозитный/транзитный адрес биржи? (funnel: получает извне → пересылает
    # почти весь отток на одну биржу, сам от неё ничего не получает).
    # Это адрес инфраструктуры биржи, а не личный кошелёк — помечаем как биржу.
    # Для САНКЦИОННОЙ биржи риск не маскируем: deposit_pattern.sanctioned поднимет
    # его в _compute_aml до SANCTIONED (адрес обслуживает санкционную биржу).
    deposit = _detect_exchange_deposit(transfers, addr)
    if deposit:
        exch = deposit["exchange"]
        verdict.entity_type = EntityType.EXCHANGE
        verdict.entity = f"Депозитный кошелёк {exch}"
        verdict.risk_level = RiskLevel.SAFE  # для санкц. биржи поднимет _compute_aml
        verdict.raw_labels["flow"]["deposit_pattern"] = deposit
        conc = int(round(deposit["concentration"] * 100))
        if deposit["sanctioned"]:
            verdict.risk_flags.append(
                f"🚨 Депозитный адрес САНКЦИОННОЙ биржи {exch}: {conc}% оттока идёт "
                f"на {exch}, средства приходят извне ({deposit['in_sources']} источн.) "
                f"и пересылаются на биржу. Это не личный кошелёк — адрес обслуживает "
                f"санкционную биржу, средства уходят в санкционную инфраструктуру"
            )
        else:
            verdict.risk_flags.append(
                f"🏦 Депозитный/транзитный адрес биржи {exch}: {conc}% оттока идёт "
                f"на {exch}, средства приходят извне ({deposit['in_sources']} источн.) "
                f"и пересылаются на биржу (funnel-паттерн) — инфраструктура биржи, "
                f"а не личный кошелёк"
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

    # Сам адрес обслуживает санкционную биржу: либо его тег = санкц. биржа
    # (хот-кошелёк), либо sweep-паттерн опознал депозитник санкц. биржи.
    deposit_pattern = (verdict.raw_labels.get("flow") or {}).get("deposit_pattern") or {}
    sanctioned_deposit = bool(deposit_pattern.get("sanctioned"))
    self_sanctioned_exch = sanctioned_deposit or (
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
        verdict.risk_flags.insert(
            0,
            "🚨 Депозитный адрес санкционной биржи (UK/OFAC) — средства уходят "
            "в санкционную инфраструктуру, могут быть заморожены"
            if sanctioned_deposit
            else "🚨 Хот-кошелёк санкционной биржи (UK/OFAC)",
        )

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


async def _apply_cluster(verdict: AddressVerdict) -> None:
    """Накопительная кластеризация депозитников бирж.

    Если адрес опознан как депозитный/транзитный адрес биржи (funnel), пишем его
    в локальную БД с якорем (хот-кошелёк биржи) и дополняем вердикт числом уже
    известных родственных депозитников того же якоря/биржи."""
    dp = (verdict.raw_labels.get("flow") or {}).get("deposit_pattern")
    if not dp:
        return
    exch = dp["exchange"]
    hot = dp.get("hot_wallet")
    await cluster.record(verdict.address, exch, hot, bool(dp.get("sanctioned")))
    info = await cluster.cluster_info(exch, hot, exclude=verdict.address)
    if not info:
        return
    verdict.raw_labels["cluster"] = info
    n_anchor = info.get("siblings_on_anchor", 0)
    n_exch = info.get("known_deposits_exchange", 0)
    if n_anchor > 0:
        verdict.risk_flags.append(
            f"🔗 Кластер биржи {exch}: ещё {n_anchor} родственных депозитных "
            f"адрес(ов) пересылают на тот же хот-кошелёк {hot}"
        )
    elif n_exch > 0:
        verdict.risk_flags.append(
            f"🔗 Кластер биржи {exch}: всего {n_exch} известных депозитных "
            f"адрес(ов) этой биржи в локальной базе"
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
                balance_trx=cached.get("balance_trx", 0.0),
                balance_usdt=cached.get("balance_usdt", 0.0),
                external_aml=cached.get("external_aml", {}),
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

    # Кластеризация: опознан депозитник биржи → пишем в накопительную БД и
    # обогащаем вердикт числом родственных депозитников того же якоря/биржи.
    await _apply_cluster(verdict)

    _apply_local(local.lookup(address), verdict)

    # Fallback: нет публичной метки. risk_level НЕ трогаем — его уже выставил
    # _compute_aml (у адреса может быть реальный риск от экспозиции/2-хопа).
    if verdict.entity_type == EntityType.UNKNOWN and not verdict.entity:
        verdict.entity = "No public labels"

    # Баланс кошелька (из уже полученного ответа TronScan)
    verdict.balance_trx, verdict.balance_usdt = balance.extract_balances(ts_data)

    # Туннель: биржа/контракт/скам/санкции → внешний AML не зовём.
    # Обычный кошелёк (WALLET/UNKNOWN/LABELED) → запрашиваем AML через внешний API.
    if verdict.entity_type in _AML_SKIP_TYPES:
        verdict.external_aml = {"skipped": True, "reason": "биржа/сервис — AML не требуется"}
    else:
        verdict.external_aml = await aml_external.check(address)
        # Swapster может опознать биржу/сервис там, где TronScan/on-chain пусто,
        # но только если адрес ещё и ведёт себя как транзит (не личный юзер).
        transit = _is_transit(flow_data, address, verdict.balance_usdt)
        _relabel_from_swapster(verdict, transit)

    # Кеш
    if use_cache:
        await cache.put(address, verdict.to_dict())

    return verdict
