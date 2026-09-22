"""Главный агрегатор: координирует провайдеров и строит итоговый Verdict."""
from __future__ import annotations

import asyncio
import logging
import os
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import httpx

from . import (
    aml_bitok,
    aml_external,
    balance,
    cache,
    cluster,
    history,
    labels,
    services,
)
from .models import AddressVerdict, EntityType, RiskLevel, is_valid_trc20_address
from .providers import flow, goplus, local, ofac, tether, token_security, tronscan
from .providers.base import ProviderError

PROVIDER_TETHER = tether.PROVIDER

log = logging.getLogger(__name__)

# Версия правил скоринга. Меняется, когда меняются пороги или формула — тогда
# старый сохранённый вердикт читается в контексте тогдашних правил, а не текущих.
RULESET_VERSION = "2026.09.2"

# Туннель: для этих типов внешний AML-API НЕ запрашивается — биржа/депозитник
# биржи/контракт — это инфраструктура, её AML-скор ничего не говорит о владельце,
# а запросов к платным KYT в потоке проверок бирж больше всего.
# Скам/санкции туннель НЕ отсекает: там как раз ценно второе мнение сервисов.
_AML_SKIP_TYPES = frozenset({EntityType.EXCHANGE, EntityType.CONTRACT, EntityType.FROZEN})

# Доля доминирующей биржевой сущности в AML, при которой НЕразмеченный адрес
# считаем биржей/сервисом. Swapster видит off-chain принадлежность, которой нет
# у TronScan/on-chain (напр. транзитный хаб биржи без публичной метки). Тюнится env.
AML_EXCHANGE_ENTITY_THRESHOLD = float(os.getenv("AML_EXCHANGE_ENTITY_THRESHOLD", "0.9"))


# Группы риска в общем формате entities (одинаковы у Swapster и Bitok).
_ENTITY_LEVEL_ORDER = {"HIGH_RISK": 3, "MEDIUM_RISK": 2, "LOW_RISK": 1}


def _top_risk_entity(ext: dict[str, Any]) -> str | None:
    """Категория, которой подписывается вердикт внешнего KYT.

    Раньше бралась первая из списка. У Bitok он отсортирован по доле объёма, а
    Swapster отдаёт категории в произвольном порядке — и в подписи «высокий
    риск — 31.7% (…)» оказывалась случайная категория, нередко безобидная,
    вместо той, из-за которой риск и поднялся.

    Берём самую весомую из САМЫХ рисковых: подпись должна объяснять вердикт,
    а не пересказывать крупнейшую строку разбивки."""
    entities = [e for e in (ext.get("entities") or []) if isinstance(e, dict)]
    if not entities:
        return None
    top = max(
        entities,
        key=lambda e: (
            _ENTITY_LEVEL_ORDER.get(str(e.get("level") or ""), 0),
            e.get("risk_score") or 0,
        ),
    )
    return top.get("entity") or None


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


# Категория сущности Bitok → тип адреса в наших терминах.
# Покрывает ВСЕ категории из aml_bitok.ENTITY_CATEGORY_RU: это проверяет
# test_every_bitok_category_has_a_type. Раньше 13 категорий не имели маппинга и
# падали в LABELED («Маркированный») — среди них mixer и enforcement_action,
# которой Bitok размечает блокировку Tether, то есть самый жёсткий сигнал для USDT.
_BITOK_CATEGORY_TYPE = {
    # биржи и платёжные сервисы
    "exchange": EntityType.EXCHANGE,
    "psp": EntityType.EXCHANGE,
    "marketplace": EntityType.PROJECT,
    "nft_marketplace": EntityType.PROJECT,
    "mining_pool": EntityType.PROJECT,
    "mining": EntityType.PROJECT,
    "iaas": EntityType.PROJECT,
    "ico": EntityType.PROJECT,
    # повышенный риск: не скам, но и не «безопасная биржа»
    "high_risk_exchange": EntityType.HIGH_RISK_SERVICE,
    "p2p_exchange": EntityType.HIGH_RISK_SERVICE,
    "atm": EntityType.HIGH_RISK_SERVICE,
    "mixer": EntityType.HIGH_RISK_SERVICE,
    "privacy_protocol": EntityType.HIGH_RISK_SERVICE,
    "gambling": EntityType.HIGH_RISK_SERVICE,
    "online_pharmacy": EntityType.HIGH_RISK_SERVICE,
    "high_risk_jurisdiction": EntityType.HIGH_RISK_SERVICE,
    # контракты
    "token_contract": EntityType.CONTRACT,
    "smart_contract": EntityType.CONTRACT,
    "dex": EntityType.CONTRACT,
    "lending": EntityType.CONTRACT,
    "bridge": EntityType.CONTRACT,
    # заблокированные средства
    "enforcement_action": EntityType.FROZEN,
    "seized_funds": EntityType.FROZEN,
    # санкции
    "sanctions": EntityType.SANCTIONED,
    "terrorist_financing": EntityType.SANCTIONED,
    # криминал
    "scam": EntityType.SCAM,
    "fraud_shop": EntityType.SCAM,
    "darknet_market": EntityType.SCAM,
    "ransomware": EntityType.SCAM,
    "stolen_funds": EntityType.SCAM,
    "illegal_service": EntityType.SCAM,
    "cam": EntityType.SCAM,
    # кошельки и служебное
    "personal_wallet": EntityType.WALLET,
    "custodial_wallet": EntityType.WALLET,
    "unnamed_wallet": EntityType.WALLET,
    "unnamed_service": EntityType.LABELED,
    "dust": EntityType.LABELED,
    "other": EntityType.LABELED,
    "undefined": EntityType.UNKNOWN,
}

# Типы, которые сами по себе означают серьёзный риск независимо от того, что
# сказал внешний сервис в risk_level. Bitok может отдать категорию «sanctions»
# с родным уровнем «low» — но тип и уровень не должны противоречить друг другу.
_TYPE_MIN_RISK: dict[EntityType, tuple[int, RiskLevel]] = {
    EntityType.SANCTIONED: (100, RiskLevel.DANGEROUS),
    EntityType.FROZEN: (100, RiskLevel.DANGEROUS),
    EntityType.SCAM: (100, RiskLevel.DANGEROUS),
    EntityType.HIGH_RISK_SERVICE: (60, RiskLevel.CAUTION),
}

# Метки, которые считаем «пустыми» — их разрешено перезаписать данными Bitok.
_EMPTY_ENTITY_LABELS = {"", "No public labels"}


def _label_from_bitok(verdict: AddressVerdict) -> None:
    """Bitok видит off-chain имя сущности («Tether blacklist», «Binance») там,
    где у TronScan публичной метки нет. Ставим её ТОЛЬКО если своей метки нет —
    on-chain данные и локальная БД приоритетнее."""
    ext = verdict.bitok_aml or {}
    if not ext.get("available") or ext.get("pending"):
        return
    name = (ext.get("entity") or "").strip()
    if not name:
        return
    if verdict.entity_type != EntityType.UNKNOWN:
        return
    if (verdict.entity or "").strip() not in _EMPTY_ENTITY_LABELS:
        return
    category = (ext.get("entity_category") or "").strip().lower()
    category_ru = aml_bitok.category_ru(category)
    verdict.entity = f"{name} · {category_ru}" if category_ru else name
    verdict.entity_type = _BITOK_CATEGORY_TYPE.get(category, EntityType.LABELED)
    if verdict.entity_type is EntityType.SANCTIONED:
        verdict.sanction_source = aml_bitok.PROVIDER
    if aml_bitok.PROVIDER not in verdict.sources:
        verdict.sources.append(aml_bitok.PROVIDER)


# Порядок «строгости» уровней: внешний AML может только поднять риск.
_RISK_ORDER = {
    RiskLevel.UNKNOWN: 0,
    RiskLevel.SAFE: 1,
    RiskLevel.CAUTION: 2,
    RiskLevel.DANGEROUS: 3,
}

# Внешний AML влияет на итоговый risk_level/risk_score. EXTERNAL_AML_AFFECTS_RISK=0
# → сервисы показываются в выводе, но итоговый вердикт не меняют.
EXTERNAL_AML_AFFECTS_RISK = os.getenv("EXTERNAL_AML_AFFECTS_RISK", "1") != "0"


def _apply_external_aml_risk(verdict: AddressVerdict) -> None:
    """Swapster/Bitok сказали «caution/dangerous» → поднимаем итоговый вердикт
    до их уровня и добавляем поясняющий флаг. Понижать вердикт внешним сервисам
    НЕ даём: чистый ответ KYT не отменяет наши on-chain находки, а UNKNOWN
    («меток нет») не превращается в «безопасно» из-за отсутствия у них данных."""
    if not EXTERNAL_AML_AFFECTS_RISK:
        return
    for ext in (verdict.external_aml or {}, verdict.bitok_aml or {}):
        if not ext.get("available") or ext.get("pending"):
            continue
        try:
            level = RiskLevel(ext.get("risk_level"))
        except ValueError:
            continue
        if level not in (RiskLevel.CAUTION, RiskLevel.DANGEROUS):
            continue
        provider = ext.get("provider") or "AML"
        pct = ext.get("risk_score")
        if isinstance(pct, int | float):
            verdict.risk_score = max(verdict.risk_score, int(round(pct)))
        detail = f" — {pct:g}%" if isinstance(pct, int | float) else ""
        top = _top_risk_entity(ext) or ext.get("entity_category_ru")
        reason = f" ({top})" if top else ""
        verdict.risk_flags.append(
            f"{'⛔️' if level is RiskLevel.DANGEROUS else '⚠️'} {provider}: "
            f"{'высокий' if level is RiskLevel.DANGEROUS else 'средний'} риск"
            f"{detail}{reason}"
        )
        if _RISK_ORDER[level] > _RISK_ORDER[verdict.risk_level]:
            verdict.risk_level = level
        if provider not in verdict.sources:
            verdict.sources.append(provider)


# Транзит: адрес форвардит ≥ этой доли полученного и не копит существенный баланс.
TRANSIT_FORWARD_RATIO = float(os.getenv("TRANSIT_FORWARD_RATIO", "0.8"))


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
# Ключ — подстрока тега TronScan (lowercase), значение — каноничное имя.
# Матчинг по вхождению (см. _normalize_exchange), поэтому ключи должны быть
# различимыми (без коротких/общих слов, чтобы не ловить ложные совпадения).
EXCHANGE_KEYWORDS: dict[str, str] = {
    # топ по обороту / USDT-TRC20
    "binance": "Binance",
    "okx": "OKX",
    "okex": "OKX",
    "bybit": "Bybit",
    "kucoin": "KuCoin",
    "gate.io": "Gate.io",
    "gateio": "Gate.io",
    "bitget": "Bitget",
    "mexc": "MEXC",
    "mxc": "MEXC",          # TronScan метит хот-кошельки MEXC как «MXC» (старое имя)
    "kraken": "Kraken",
    "coinbase": "Coinbase",
    "bitfinex": "Bitfinex",
    "poloniex": "Poloniex",
    "crypto.com": "Crypto.com",
    "bitstamp": "Bitstamp",
    # средний эшелон / активны с TRC20
    "bitmart": "BitMart",
    "bitrue": "Bitrue",
    "coinex": "CoinEx",
    "lbank": "LBank",
    "whitebit": "WhiteBIT",
    "phemex": "Phemex",
    "bingx": "BingX",
    "bitmex": "BitMEX",
    "deribit": "Deribit",
    "ascendex": "AscendEX",
    "digifinex": "DigiFinex",
    "pionex": "Pionex",
    "btse": "BTSE",
    "toobit": "Toobit",
    "weex": "WEEX",
    "coinw": "CoinW",
    "bitunix": "Bitunix",
    "deepcoin": "Deepcoin",
    "probit": "ProBit",
    "hitbtc": "HitBTC",
    "latoken": "LATOKEN",
    "bigone": "BigONE",
    "coincheck": "Coincheck",
    "bitflyer": "bitFlyer",
    "gemini": "Gemini",
    "bittrex": "Bittrex",
    "xt.com": "XT.com",
    "cointr": "CoinTR",
    "fameex": "FameEX",
    "biconomy": "Biconomy",
    "hotcoin": "Hotcoin",
    "azbit": "Azbit",
    "nominex": "Nominex",
    # региональные
    "bithumb": "Bithumb",
    "upbit": "Upbit",
    "coinone": "Coinone",
    "korbit": "Korbit",
    "bitkub": "Bitkub",
    "indodax": "Indodax",
    "tokocrypto": "Tokocrypto",
    "wazirx": "WazirX",
    "coindcx": "CoinDCX",
    "bitso": "Bitso",
    "bitpanda": "Bitpanda",
    "bitvavo": "Bitvavo",
    "luno": "Luno",
    # кастодиальные/лендинг (держат USDT, часто метятся как биржи)
    "nexo": "Nexo",
    "cex.io": "CEX.IO",
}

# Биржи под санкциями. Деньги с них блокируются комплаенсом ("заморозка").
# Ловим по тегам TronScan: и сам хот-кошелёк биржи, и переводы с/на него.
#
# ВАЖНО: название не должно одновременно быть в EXCHANGE_KEYWORDS — иначе
# _normalize_exchange отдаст предпочтение обычному словарю (он первый в
# _ALL_EXCHANGES) и санкционная биржа получит вердикт «безопасно».
# Это проверяет test_no_overlap_between_exchange_dicts.
#
# Источники и даты (см. ROADMAP.md §5.3):
#   UK, 26.05.2026 — HTX/Huobi
#   UK A7-пакет    — EXMO, Bitpapa, Rapira, Aifory, Arvix, ABCEX
#   OFAC           — Garantex, Grinex, Cryptex
#   OFAC 02.06.2026 — Nobitex, Wallex, Bitpin, Ramzinex (иранские, оборот в USDT-TRC20)
#   OFAC 22.06.2026 — Bitcoin Xchange (сеть финансирования ISIS)
#   OFAC 07.08.2026 — Shelbit, Aban Tether
#   EU 21-й пакет, 23.07.2026 — WhiteBird, NoOne, Tradex/Brightum, Monease, Exnode
#   EU 20-й пакет, 23.04.2026 — TengriCoin
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
    # OFAC 02.06.2026 — иранские биржи
    "nobitex": "Nobitex",
    "wallex": "Wallex",
    "bitpin": "Bitpin",
    "ramzinex": "Ramzinex",
    # OFAC 07.08.2026
    "shelbit": "Shelbit",
    "aban tether": "Aban Tether",
    "abantether": "Aban Tether",
    # OFAC 22.06.2026
    "bitcoin xchange": "Bitcoin Xchange",
    # EU 21-й пакет, 23.07.2026
    "whitebird": "WhiteBird",
    "noonecrypto": "NoOne",
    "noone": "NoOne",
    "brightum": "Tradex (Brightum)",
    "monease": "Monease",
    "exnode": "Exnode",
    # EU 20-й пакет, 23.04.2026
    "tengricoin": "TengriCoin",
}
SANCTIONED_EXCHANGE_NAMES = set(SANCTIONED_EXCHANGES.values())

# Сервисы с повышенным риском, опознаваемые по тегу TronScan: обменники без KYC,
# P2P-площадки, мгновенные свопы. Для них НЕЛЬЗЯ использовать EXCHANGE: тот
# трактуется как безопасный (правило known_service) и отключает платные KYT
# через туннель, а именно через такие сервисы и выводят средства.
#
# Список по умолчанию пуст намеренно: состав нужно брать из проверяемого
# источника, а не из общих соображений — ошибочно записать легальную биржу в
# высокорисковые хуже, чем не записать никого. Заполняется через env
# HIGH_RISK_EXCHANGES в формате `подстрока_тега:Каноническое имя` через запятую.
def _parse_high_risk_exchanges() -> dict[str, str]:
    raw = os.getenv("HIGH_RISK_EXCHANGES", "").strip()
    out: dict[str, str] = {}
    for chunk in raw.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        key, _, name = chunk.partition(":")
        key = key.strip().lower()
        if key:
            out[key] = name.strip() or key.title()
    return out


HIGH_RISK_EXCHANGES: dict[str, str] = _parse_high_risk_exchanges()
HIGH_RISK_EXCHANGE_NAMES = set(HIGH_RISK_EXCHANGES.values())

# Кастодиальные кошельки внутри мессенджеров. Для TRC20-потоков это такие же
# держатели средств, как биржа: адрес принадлежит СЕРВИСУ, а не пользователю,
# которому он выдан, и дальше этого адреса перевод не проследить.
#
# Отдельный словарь, а не строка в EXCHANGE_KEYWORDS, нужен ради формулировки:
# «Депозитный кошелёк Binance» и «кошелёк телеграм-бота» читаются по-разному,
# и пользователю важно знать, что он имеет дело с кастодиальным сервисом
# с минимальной верификацией.
#
# Ключи — подстроки тега TronScan. Теги здесь не проверены живым запросом
# (эндпоинт TronScan из окружения разработки недоступен), поэтому подобраны
# так, чтобы ложное срабатывание было невозможно: совпадение только с
# самоназванием сервиса. Если такого тега у TronScan нет, правило просто
# никогда не сработает и ничего не испортит. Надёжный путь для этих сервисов —
# разметить их хот-кошелёк по адресу: /label в боте или SERVICE_ADDRESSES
# (см. core/services.py); дальше их депозитники опознает funnel-эвристика.
CUSTODIAL_SERVICES: dict[str, str] = {
    "cryptobot": "CryptoBot (Telegram)",
    "crypto bot": "CryptoBot (Telegram)",
    "cryptopay": "CryptoBot (Telegram)",
    "crypto pay": "CryptoBot (Telegram)",
    "telegram wallet": "Telegram Wallet",
    "wallet.tg": "Telegram Wallet",
    "tg wallet": "Telegram Wallet",
    "@wallet": "Telegram Wallet",
    "xrocket": "xRocket (Telegram)",
}
CUSTODIAL_SERVICE_NAMES = set(CUSTODIAL_SERVICES.values())

# Каноническое имя → какой орган внёс биржу в список. Нужно, чтобы отчёт не
# ссылался на OFAC там, где санкция британская или европейская: уровень риска
# можно перепроверить, а ссылка на конкретный список читается как факт.
# Покрытие проверяет test_every_sanctioned_exchange_has_a_source.
SANCTIONED_EXCHANGE_SOURCE: dict[str, str] = {
    "HTX (Huobi)": "UK · EU",
    "EXMO": "UK · EU",
    "Bitpapa": "UK · EU",
    "Rapira": "UK · EU",
    "Aifory": "UK · EU",
    "Arvix": "UK · EU",
    "ABCEX": "UK · EU",
    "Garantex": "OFAC",
    "Grinex": "OFAC",
    "Cryptex": "OFAC",
    "Nobitex": "OFAC",
    "Wallex": "OFAC",
    "Bitpin": "OFAC",
    "Ramzinex": "OFAC",
    "Shelbit": "OFAC",
    "Aban Tether": "OFAC",
    "Bitcoin Xchange": "OFAC",
    "WhiteBird": "EU",
    "NoOne": "EU",
    "Tradex (Brightum)": "EU",
    "Monease": "EU",
    "Exnode": "EU",
    "TengriCoin": "EU",
}

# 2-хоп анализ связанных кошельков (косвенная санкционная экспозиция).
# Раскрываем топ-N неизвестных посредников и смотрим ИХ санкционную экспозицию.
HOP2_ENABLED = os.getenv("AML_HOP2", "1") not in ("0", "false", "False", "")
HOP2_LIMIT = int(os.getenv("AML_HOP2_LIMIT", "12"))  # сколько посредников раскрывать
HOP2_WEIGHT = float(os.getenv("AML_HOP2_WEIGHT", "0.6"))  # вес косвенной экспозиции
# Ограничение параллелизма hop2, чтобы не бить в QPS-лимит TronScan-ключа.
HOP2_CONCURRENCY = int(os.getenv("AML_HOP2_CONCURRENCY", "4"))
# Глубина истории для посредников 2-го хопа. Отдельно от FLOW_PAGES: у главного
# адреса лишняя страница — один запрос, а здесь адресов до двенадцати.
HOP2_FLOW_PAGES = max(1, int(os.getenv("AML_HOP2_FLOW_PAGES", "1")))

# Депозитный/транзитный адрес биржи (funnel-эвристика, см. _detect_exchange_deposit).
# Концентрация оттока на одну биржу и доля пересылаемого — пороги распознавания.
# Это эвристики: их тюнят на реальных данных, поэтому берём из env, а не
# пересобираем образ ради смены числа.
DEPOSIT_CONCENTRATION = float(os.getenv("DEPOSIT_CONCENTRATION", "0.9"))
DEPOSIT_FORWARD_RATIO = float(os.getenv("DEPOSIT_FORWARD_RATIO", "0.5"))
DEPOSIT_BACKFLOW_RATIO = float(os.getenv("DEPOSIT_BACKFLOW_RATIO", "0.15"))
# Одноразовый депозитный адрес: получил ОДИН перевод и свипнул его на биржу.
# Так работают Binance и Bybit — адрес выдаётся пользователю под один депозит,
# и требование «минимум два прихода» отбрасывало именно их. Свидетельств
# меньше, поэтому пороги жёстче, а вывод помечается как вероятный.
DEPOSIT_SWEEP_CONCENTRATION = float(os.getenv("DEPOSIT_SWEEP_CONCENTRATION", "0.99"))
DEPOSIT_SWEEP_FORWARD_RATIO = float(os.getenv("DEPOSIT_SWEEP_FORWARD_RATIO", "0.9"))
# Порог «очень высокая активность» → возможно нетегированный сервис.
UNTAGGED_SERVICE_TX = int(os.getenv("UNTAGGED_SERVICE_TX", "50000"))

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


_ALL_EXCHANGES = {
    **EXCHANGE_KEYWORDS,
    **SANCTIONED_EXCHANGES,
    **HIGH_RISK_EXCHANGES,
    **CUSTODIAL_SERVICES,
}


def _normalize_exchange(tag: str | None) -> str | None:
    if not tag:
        return None
    t = tag.lower()
    for key, name in _ALL_EXCHANGES.items():
        if key in t:
            return name
    return None


def _counterparty_service(
    tag: str | None, address: str | None, anchors: dict[str, str] | None = None
) -> str | None:
    """Какой сервис стоит за контрагентом перевода.

    Тремя слоями, от надёжного к накопленному:
      1. тег TronScan в самом переводе;
      2. реестр сервисных адресов (env SERVICE_ADDRESSES и ручные метки) —
         так опознаются сервисы, которых TronScan не размечает вовсе;
      3. якоря из накопительного кластера — хот-кошельки, выученные на прошлых
         проверках, когда тег в ответе был.

    Второй и третий слой и есть ответ на вопрос, почему депозитники Bybit и
    Binance оставались «личными кошельками»: без тега на контрагенте
    funnel-эвристика не видела в оттоке биржу и не срабатывала вообще."""
    return (
        _normalize_exchange(tag)
        or services.service_name(address)
        or (anchors or {}).get(address or "")
        or None
    )


# Возраст адреса: моложе этого — «свежий». Не риск сам по себе (адреса создают
# каждый день), но в паре с крупным приходом это другой профиль: у долгоживущего
# кошелька есть история, у вчерашнего её нет и проверять нечего.
NEW_ADDRESS_DAYS = int(os.getenv("NEW_ADDRESS_DAYS", "30"))
# Жалобы пользователей в TronScan — сигнал слабее скам-тега (репорт может быть и
# ошибочным), поэтому не «опасно», а нижняя граница «осторожно».
FEEDBACK_RISK_SCORE = float(os.getenv("FEEDBACK_RISK_SCORE", "30"))


def _apply_account_profile(data: dict[str, Any], verdict: AddressVerdict) -> None:
    """Поля ответа /api/account, которые раньше отбрасывались.

    Всё это уже приходит в том же ответе, что и метки: дополнительных запросов
    не делается, а бюджет проверки (~20 внешних запросов на 90 с) не трогается.

      date_created                    — когда адрес активирован (мс)
      feedbackRisk                    — TronScan получал жалобы на адрес
      transactions_in/transactions_out — чистый получатель или отправитель

    Функция только собирает данные и объясняющие флаги; решение о риске
    принимает _compute_aml (единственный расчёт)."""
    profile: dict[str, Any] = {}

    created = data.get("date_created")
    if isinstance(created, int | float) and created > 0:
        # TronScan отдаёт миллисекунды. Секунды тоже встречаются в зеркалах API,
        # поэтому различаем по порядку величины, а не по вере в документацию.
        seconds = created / 1000 if created > 1e11 else float(created)
        age_days = max(0.0, (datetime.now(UTC).timestamp() - seconds) / 86400)
        profile["created_at"] = datetime.fromtimestamp(seconds, UTC).isoformat(
            timespec="seconds"
        )
        profile["age_days"] = round(age_days, 1)
        if age_days < NEW_ADDRESS_DAYS:
            verdict.risk_flags.append(
                f"🆕 Адрес создан {age_days:.0f} дн. назад — истории, по которой "
                f"его можно оценить, почти нет"
            )

    tx_in = data.get("transactions_in")
    tx_out = data.get("transactions_out")
    if isinstance(tx_in, int):
        profile["tx_in"] = tx_in
    if isinstance(tx_out, int):
        profile["tx_out"] = tx_out
    if isinstance(tx_in, int) and isinstance(tx_out, int) and tx_in >= 5 and tx_out == 0:
        verdict.risk_flags.append(
            f"📥 Только приём: {tx_in} входящих переводов и ни одного исходящего — "
            f"средства с адреса ещё ни разу не уходили"
        )

    if data.get("feedbackRisk"):
        profile["feedback_risk"] = True
        verdict.risk_flags.append(
            "⚠️ TronScan: на адрес поступали жалобы пользователей (feedbackRisk)"
        )

    if profile:
        verdict.raw_labels["profile"] = profile


def _custodial_note(name: str) -> str:
    """Что значит «адрес кастодиального сервиса» для того, кто его проверяет."""
    return (
        f"💬 {name} — кастодиальный сервис: адрес принадлежит сервису, а не "
        f"пользователю, которому он выдан. Дальше этого адреса перевод "
        f"не прослеживается, а верификация личности у таких сервисов минимальна"
    )


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

    # Профиль адреса из того же ответа — ни одного лишнего запроса.
    # Ставится ДО ветвлений: ниже каждая ветка делает return, и для биржи,
    # контракта или скама профиль бы не собрался.
    _apply_account_profile(data, verdict)

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
        if exch in HIGH_RISK_EXCHANGE_NAMES:
            # Обменник без KYC — не «безопасная биржа»: он не получает ни
            # правила known_service, ни туннеля, отключающего платные KYT.
            verdict.entity_type = EntityType.HIGH_RISK_SERVICE
            verdict.risk_flags.append(
                f"⚠️ {exch} — сервис с повышенным риском (обменник без "
                f"верификации): через такие площадки выводят средства"
            )
            return
        verdict.entity_type = EntityType.EXCHANGE
        verdict.risk_level = RiskLevel.SAFE
        if exch in CUSTODIAL_SERVICE_NAMES:
            verdict.risk_flags.append(_custodial_note(exch))
            return
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
    transfers: list[dict[str, Any]], addr: str, anchors: dict[str, str] | None = None
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

    Два исхода различаются уверенностью (`confidence`):
      • `high`   — несколько приходов, классический funnel;
      • `medium` — ОДИН приход и свип почти всей суммы на биржу. Так устроены
        одноразовые депозитные адреса Binance/Bybit, и раньше они не
        опознавались вовсе. Отличить такой адрес от личного кошелька, который
        разово отправил всё на биржу, on-chain нельзя, поэтому вывод помечается
        как вероятный и НЕ включает поддавки для известного сервиса: платные
        KYT для него по-прежнему запрашиваются, а риск считается как обычно.

    `anchors` — выученные ранее хот-кошельки (см. `_counterparty_service`).

    Возвращает dict с деталями или None."""
    out_exch: dict[str, float] = {}   # отток на биржи, по биржам
    out_other = 0.0                   # отток на не-биржи
    in_exch: dict[str, float] = {}    # приток С бирж (выводы), по биржам
    in_other = 0.0                    # приток от не-бирж («депозиты» пользователей)
    in_tx = 0                         # всего входящих переводов (с бирж И извне)
    in_sources: set[str] = set()
    in_amounts: list[float] = []
    out_pairs: list[tuple[float, str]] = []
    # Якоря кластера: адреса хот/сборных кошельков биржи, куда уходит отток
    anchor_volume: dict[str, dict[str, float]] = {}  # exch -> {hot_wallet: volume}
    for t in transfers:
        amt = _amount(t)
        if amt <= 0:
            continue
        if addr == t.get("from_address"):
            dst = t.get("to_address")
            exch = _counterparty_service(
                (t.get("to_address_tag") or {}).get("to_address_tag"), dst, anchors
            )
            if exch:
                out_exch[exch] = out_exch.get(exch, 0.0) + amt
                out_pairs.append((amt, exch))
                if dst:
                    anchor_volume.setdefault(exch, {})[dst] = (
                        anchor_volume.setdefault(exch, {}).get(dst, 0.0) + amt
                    )
            else:
                out_other += amt
        elif addr == t.get("to_address"):
            in_tx += 1
            src = t.get("from_address")
            exch = _counterparty_service(
                (t.get("from_address_tag") or {}).get("from_address_tag"), src, anchors
            )
            if exch:
                in_exch[exch] = in_exch.get(exch, 0.0) + amt
            else:
                in_other += amt
                in_amounts.append(amt)
                if src:
                    in_sources.add(src)

    if not out_exch:
        return None
    total_out = sum(out_exch.values()) + out_other
    exch = max(out_exch, key=lambda k: out_exch[k])
    out_e = out_exch[exch]
    concentration = out_e / total_out if total_out > 0 else 0.0

    # funnel-критерии депозитника. Приход может идти и от «внешних юзеров», и с
    # ДРУГИХ бирж (напр. вывел с Bybit/Binance → форварднул на MEXC) — в обоих
    # случаях адрес funnel'ит на одну биржу.
    total_in = in_other + sum(in_exch.values())
    backflow = in_exch.get(exch, 0.0)
    if total_in <= 0 or concentration < DEPOSIT_CONCENTRATION:
        return None
    # от ЭТОЙ биржи приходит мало относительно оттока на неё: газ-пополнения
    # для sweep — норма, а сопоставимый обратный поток = личный торговый
    # кошелёк (и заводит, и выводит), это НЕ депозитник.
    if backflow > DEPOSIT_BACKFLOW_RATIO * out_e:
        return None

    if in_tx >= 2 and out_e >= DEPOSIT_FORWARD_RATIO * total_in:
        confidence = "high"
    elif (
        in_tx == 1
        and backflow <= 0
        and concentration >= DEPOSIT_SWEEP_CONCENTRATION
        and out_e >= DEPOSIT_SWEEP_FORWARD_RATIO * total_in
    ):
        confidence = "medium"
    else:
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
    exch_anchors = anchor_volume.get(exch, {})
    hot_wallet = max(exch_anchors, key=lambda a: exch_anchors[a]) if exch_anchors else None

    return {
        "exchange": exch,
        "confidence": confidence,
        "concentration": round(concentration, 2),
        "forwarded_pct": round(min(out_e / total_in, 9.99) * 100, 1) if total_in else 0.0,
        "in_sources": len(in_sources),
        "in_transfers": in_tx,
        "matched_pairs": pairs,
        "hot_wallet": hot_wallet,
        "sanctioned": exch in SANCTIONED_EXCHANGE_NAMES,
    }


def _is_probable_deposit(verdict: AddressVerdict) -> bool:
    """Депозитник, опознанный по ОДНОМУ свипу (confidence = medium).

    Вывод вероятный, поэтому поддавков «известного сервиса» он не получает: ни
    обнуления риска, ни туннеля, отключающего платные KYT, ни пропуска 2-го
    хопа. Иначе одна разовая отправка на биржу превращала бы личный кошелёк в
    «безопасную биржу» — ровно та ошибка, из-за которой санкционные биржи
    когда-то выдавали «exchange / safe / 0»."""
    dp = (verdict.raw_labels.get("flow") or {}).get("deposit_pattern") or {}
    return dp.get("confidence") == "medium"


async def _anchor_map(transfers: list[dict[str, Any]], addr: str) -> dict[str, str]:
    """Контрагенты переводов, которых мы уже знаем как хот-кошельки бирж.

    Один локальный SQLite-запрос: внешних вызовов не добавляет и в бюджет
    проверки не вмешивается."""
    cps: set[str] = set()
    for t in transfers:
        if addr == t.get("from_address"):
            cp = t.get("to_address")
        elif addr == t.get("to_address"):
            cp = t.get("from_address")
        else:
            continue
        if cp:
            cps.add(cp)
    if not cps:
        return {}
    return await cluster.anchors_for(cps)


def _apply_flow(
    transfers: list[dict[str, Any]],
    verdict: AddressVerdict,
    anchors: dict[str, str] | None = None,
) -> None:
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
            cp = t.get("to_address")
            direction = "deposits"  # адрес отправил на контрагента
        elif addr == t.get("to_address"):
            tag = (t.get("from_address_tag") or {}).get("from_address_tag")
            cp = t.get("from_address")
            direction = "withdrawals"  # адрес получил от контрагента
        else:
            continue
        exch = _counterparty_service(tag, cp, anchors)
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
    deposit = _detect_exchange_deposit(transfers, addr, anchors)
    if deposit:
        exch = deposit["exchange"]
        probable = deposit.get("confidence") == "medium"
        verdict.entity_type = EntityType.EXCHANGE
        verdict.entity = (
            f"Депозитный кошелёк {exch}" if not probable
            else f"Депозитный кошелёк {exch} (вероятно)"
        )
        verdict.risk_level = RiskLevel.SAFE  # для санкц. биржи поднимет _compute_aml
        verdict.raw_labels["flow"]["deposit_pattern"] = deposit
        conc = int(round(deposit["concentration"] * 100))
        custodial = exch in CUSTODIAL_SERVICE_NAMES
        if deposit["sanctioned"]:
            verdict.risk_flags.append(
                f"🚨 Депозитный адрес САНКЦИОННОЙ биржи {exch}: {conc}% оттока идёт "
                f"на {exch}, средства приходят извне ({deposit['in_sources']} источн.) "
                f"и пересылаются на биржу. Это не личный кошелёк — адрес обслуживает "
                f"санкционную биржу, средства уходят в санкционную инфраструктуру"
            )
        elif probable:
            # Честно про объём свидетельств: один приход и один свип — это
            # ровно то, как выглядит одноразовый депозитник, но точно так же
            # выглядит личный кошелёк, разово отправивший всё на биржу.
            verdict.risk_flags.append(
                f"🏦 Похоже на одноразовый депозитный адрес {exch}: получил один "
                f"перевод и переслал {deposit['forwarded_pct']:.0f}% суммы на {exch}. "
                f"Так выдаются адреса под разовый депозит; личный кошелёк, разово "
                f"отправивший всё на биржу, выглядит так же — вывод вероятный"
            )
        else:
            verdict.risk_flags.append(
                f"🏦 Депозитный/транзитный адрес биржи {exch}: {conc}% оттока идёт "
                f"на {exch}, средства приходят извне ({deposit['in_sources']} источн.) "
                f"и пересылаются на биржу (funnel-паттерн) — инфраструктура биржи, "
                f"а не личный кошелёк"
            )
        if custodial:
            verdict.risk_flags.append(_custodial_note(exch))
        return

    # Иначе это ЛИЧНЫЙ кошелёк (у самого адреса нет биржевой метки — иначе он был
    # бы EXCHANGE выше); метку имеет контрагент, поэтому «связан с», а не «принадлежит».
    top = links[0]["name"]
    verdict.entity_type = EntityType.WALLET
    verdict.entity = f"Личный кошелёк (связан с {top})"
    if top in CUSTODIAL_SERVICE_NAMES:
        verdict.risk_flags.append(_custodial_note(top))
    verdict.risk_flags.append(
        "ℹ️ Личный кошелёк, не биржа: на самом адресе нет биржевой метки, "
        "связь определена по контрагентам переводов"
    )
    # Эвристика: огромная активность → возможно нетегированный сервис/биржа
    activity = verdict.raw_labels.get("activity_tx") or 0
    if isinstance(activity, int) and activity > UNTAGGED_SERVICE_TX:
        verdict.entity = f"Возможно сервис/биржа (связан с {top}, нетегирован)"
        verdict.risk_flags.append(
            f"⚠️ Очень высокая активность ({activity:,} транзакций) — "
            "возможно нетегированный сервис, а не личный кошелёк"
        )


# ---------- Какие токены участвуют в объёмной математике ----------
# Экспозиция считается как ДОЛЯ от общего объёма, поэтому в знаменатель нельзя
# пускать произвольный токен: любой может выпустить свой TRC20 с символом «USDT»
# и огромным quant, прислать себе один перевод и тем самым разбавить санкционную
# экспозицию до нуля. Это не шум, а дешёвый вектор уклонения (ROADMAP §1.1).
#
# Поэтому сверяем КОНТРАКТ (tokenInfo.tokenId), а не символ: символ подделывается
# тривиально, адрес контракта — нет.
_STABLECOINS: dict[str, str] = {
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": "USDT",
    "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8": "USDC",
    "TPYmHEhy5n8TCEfYGqW2rPxsghSfzghPDn": "USDD",
    "TUpMhErZL2fhh4sVNULAbNKLokS4GjC1F4": "TUSD",
    "TMwFHYXLJaRUPeW6421aqXL4ZEzPRFGkGT": "USDJ",
}


def _volume_tokens() -> dict[str, str]:
    """Контракты, участвующие в объёмной математике. Расширяется через env
    AML_VOLUME_TOKENS (`адрес:символ` через запятую)."""
    extra = os.getenv("AML_VOLUME_TOKENS", "").strip()
    if not extra:
        return _STABLECOINS
    out = dict(_STABLECOINS)
    for chunk in extra.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        addr, _, sym = chunk.partition(":")
        addr = addr.strip()
        if is_valid_trc20_address(addr):
            out[addr] = (sym.strip() or "?").upper()
        else:
            log.warning("AML_VOLUME_TOKENS: пропускаю невалидный адрес %r", addr)
    return out


VOLUME_TOKENS = _volume_tokens()

# Символы, под которые мимикрируют скам-токены. Совпадение символа при ЧУЖОМ
# контракте — признак отравления истории / подготовки к дрейну.
_IMPERSONATED_SYMBOLS = {"USDT", "USDC", "USDD", "TUSD", "TETHER", "USD", "TRX"}


def _token_id(t: dict[str, Any]) -> str:
    info = t.get("tokenInfo") or {}
    return str(info.get("tokenId") or t.get("contract_address") or "")


def _raw_amount(t: dict[str, Any]) -> float:
    """Сумма перевода по его собственным decimals, без фильтра по токену."""
    try:
        q = int(t.get("quant") or 0)
        dec = int((t.get("tokenInfo") or {}).get("tokenDecimal", 6))
        return q / (10 ** dec)
    except (TypeError, ValueError):
        return 0.0


def _amount(t: dict[str, Any]) -> float:
    """Нормализованная сумма перевода для объёмной математики. 0, если токен не
    входит в VOLUME_TOKENS — такой перевод не должен влиять на доли экспозиции.

    Прим.: разные стейблкоины суммируются как сопоставимые — это аппроксимация,
    но все они ≈$1, так что для оценки ДОЛИ этого достаточно.

    Обратная совместимость: если в переводе вообще нет tokenId (старые фикстуры,
    неполный ответ), считаем как раньше — иначе молча обнулили бы весь анализ."""
    tid = _token_id(t)
    if tid and tid not in VOLUME_TOKENS:
        return 0.0
    return _raw_amount(t)


# Уровень безопасности токена по TronScan (строкой!): "3" подозрительный,
# "4" небезопасный. "2" = «проходит базовые проверки» и подлинность НЕ доказывает:
# новая подделка может быть ещё не отрепорчена, поэтому решающим остаётся tokenId.
_BAD_TOKEN_LEVELS = {"3", "4"}


def _apply_transfer_signals(
    transfers: list[dict[str, Any]], meta: dict[str, Any], verdict: AddressVerdict
) -> dict[str, Any]:
    """Читает риск-признаки, которые TronScan уже присылает в ответе переводов.

    Эти поля приходят в том же запросе, который агрегатор и так делает, но раньше
    отбрасывались: дополнительных обращений к API не нужно.
      • tokenInfo.tokenLevel / tokenCanShow — оценка самого токена;
      • riskTransaction — TronScan пометил перевод рискованным;
      • normalAddressInfo[адрес].risk — рискованный контрагент;
      • contractInfo — какие контрагенты являются контрактами.
    """
    addr = verdict.address
    risky_tokens: dict[str, str] = {}   # контракт → символ
    hidden_tokens: set[str] = set()
    risky_tx = 0
    risky_cps: set[str] = set()
    contract_cps: set[str] = set()

    info = meta.get("normalAddressInfo") or {}
    contracts = meta.get("contractInfo") or {}

    for t in transfers:
        ti = t.get("tokenInfo") or {}
        tid = str(ti.get("tokenId") or "")
        level = str(ti.get("tokenLevel") or "")
        if tid and level in _BAD_TOKEN_LEVELS:
            risky_tokens[tid] = str(ti.get("tokenAbbr") or tid)
        if tid and str(ti.get("tokenCanShow", "")) == "0":
            hidden_tokens.add(tid)
        if t.get("riskTransaction"):
            risky_tx += 1
        for side in ("from_address", "to_address"):
            cp = t.get(side)
            if not cp or cp == addr:
                continue
            if isinstance(info.get(cp), dict) and info[cp].get("risk"):
                risky_cps.add(cp)
            if cp in contracts:
                contract_cps.add(cp)

    if risky_tokens:
        names = ", ".join(sorted(set(risky_tokens.values()))[:5])
        verdict.risk_flags.append(
            f"⚠️ Переводы токенов, помеченных TronScan как подозрительные или "
            f"небезопасные: {names} ({len(risky_tokens)} шт.)"
        )
    if hidden_tokens:
        verdict.risk_flags.append(
            f"⚠️ {len(hidden_tokens)} токен(ов) скрыты TronScan как непригодные "
            f"к показу — обычно спам или крайний риск"
        )
    if risky_tx:
        verdict.risk_flags.append(
            f"⚠️ TronScan помечает {risky_tx} перевод(ов) этого адреса как рискованные"
        )
    if risky_cps:
        verdict.risk_flags.append(
            f"⚠️ Рискованные контрагенты по оценке TronScan: {len(risky_cps)} адрес(ов)"
        )

    return {
        "risky_tokens": sorted(risky_tokens),
        "hidden_tokens": sorted(hidden_tokens),
        "risky_transactions": risky_tx,
        "risky_counterparties": sorted(risky_cps),
        "contract_counterparties": sorted(contract_cps),
    }


# Отравление истории: сколько символов должно совпасть у адреса-двойника.
# По разборам SlowMist и TRM Labs двойник совпадает по первым 3-4 и последним 4
# символам — именно столько обычно видно в интерфейсе кошелька, когда адрес
# сокращён, и именно поэтому жертва копирует его из истории не глядя.
POISON_PREFIX = int(os.getenv("POISON_PREFIX_CHARS", "4"))
POISON_SUFFIX = int(os.getenv("POISON_SUFFIX_CHARS", "4"))
# Пылевой перевод: столько или меньше — приманка, а не платёж.
POISON_DUST_MAX = float(os.getenv("POISON_DUST_MAX", "1.0"))


def _detect_poisoning(
    transfers: list[dict[str, Any]], verdict: AddressVerdict
) -> list[dict[str, Any]]:
    """Адреса-двойники в истории (address poisoning).

    Атака: жертве присылают перевод с адреса, визуально похожего на настоящего
    контрагента, чтобы она скопировала его из истории и отправила деньги не туда.
    Признаки, которые ищем: совпадение префикса и суффикса при разной середине,
    нулевая или пылевая сумма и единственное появление отправителя.

    Данные уже есть в ответе flow — дополнительных запросов не нужно.
    Это эвристика, а не стандарт, поэтому и в выводе подаётся как предположение.
    """
    addr = verdict.address
    # Сколько раз встречается контрагент и на какой объём — «настоящий» партнёр
    # обычно появляется не один раз и не на пыль.
    seen: dict[str, int] = {}
    volume: dict[str, float] = {}
    for t in transfers:
        for side in ("from_address", "to_address"):
            cp = t.get(side)
            if cp and cp != addr:
                seen[cp] = seen.get(cp, 0) + 1
                volume[cp] = volume.get(cp, 0.0) + _amount(t)

    def key(a: str) -> tuple[str, str]:
        return a[:POISON_PREFIX], a[-POISON_SUFFIX:]

    # Группируем по «внешнему виду» сокращённого адреса.
    groups: dict[tuple[str, str], list[str]] = {}
    for cp in seen:
        groups.setdefault(key(cp), []).append(cp)

    suspects: list[dict[str, Any]] = []
    for look, members in groups.items():
        if len(members) < 2:
            continue
        # Настоящий контрагент — тот, через кого шёл реальный объём.
        real = max(members, key=lambda a: volume.get(a, 0.0))
        for cp in members:
            if cp == real:
                continue
            if volume.get(cp, 0.0) > POISON_DUST_MAX or seen.get(cp, 0) > 1:
                continue  # не пыль и не одиночный — на приманку не похоже
            suspects.append({
                "lookalike": cp,
                "resembles": real,
                "shared": f"{look[0]}…{look[1]}",
                "amount": round(volume.get(cp, 0.0), 6),
            })

    if suspects:
        first = suspects[0]
        verdict.risk_flags.append(
            f"🎭 Похоже на отравление истории: адрес {first['lookalike']} "
            f"начинается и заканчивается так же, как {first['resembles']} "
            f"({first['shared']}), но прислал только пыль. Так подсовывают "
            f"похожий адрес, чтобы его скопировали из истории. "
            f"Всего таких: {len(suspects)}. Сверяйте адрес полностью, не по краям"
        )
    return suspects


def _apply_token_security(data: dict[str, Any] | None, verdict: AddressVerdict) -> None:
    """Безопасность контракта. Раньше контракт получал SAFE/CAUTION и на этом
    анализ заканчивался — туннель исключал его из внешних AML."""
    if not data:
        return
    verdict.raw_labels["token_security"] = data
    flags, serious = token_security.describe(data)
    verdict.risk_flags.extend(flags)
    if serious and verdict.entity_type is EntityType.CONTRACT:
        # Контракт с функцией блокировки или помеченный небезопасным — это не
        # «смарт-контракт, вероятно всё в порядке».
        verdict.entity_type = EntityType.HIGH_RISK_SERVICE
    if "TronScan security" not in verdict.sources:
        verdict.sources.append("TronScan security")


def _apply_tether(result: dict[str, Any] | None, verdict: AddressVerdict) -> None:
    """Блокировка адреса эмитентом USDT.

    Самый жёсткий из возможных сигналов для USDT-TRC20: заблокированные
    средства физически неподвижны, поэтому тип FROZEN и максимальный скор
    независимо от того, насколько чиста остальная история адреса."""
    if not result:
        return
    verdict.raw_labels["tether"] = result
    if not result.get("blacklisted"):
        return
    verdict.entity_type = EntityType.FROZEN
    if not verdict.entity or verdict.entity == "No public labels":
        verdict.entity = "Адрес в блэклисте Tether"
    verdict.risk_flags.insert(
        0,
        "🚫 Адрес заблокирован эмитентом USDT (блэклист Tether): средства на нём "
        "заморожены и не могут быть переведены. Отправлять сюда USDT нельзя — "
        f"деньги будут потеряны (источник: {result.get('source')})",
    )
    if PROVIDER_TETHER not in verdict.sources:
        verdict.sources.append(PROVIDER_TETHER)


def _apply_token_hygiene(
    transfers: list[dict[str, Any]], verdict: AddressVerdict
) -> dict[str, Any]:
    """Смотрит, какие токены реально ходили через адрес.

    Возвращает сводку для `verdict.aml` и добавляет флаги:
      • переводы токена, мимикрирующего под USDT с чужого контракта;
      • доля переводов, исключённых из объёмной математики.
    """
    counted = ignored = 0
    fakes: dict[str, str] = {}   # контракт → заявленный символ
    symbols: set[str] = set()
    for t in transfers:
        tid = _token_id(t)
        info = t.get("tokenInfo") or {}
        sym = str(info.get("tokenAbbr") or "").strip()
        name = str(info.get("tokenName") or "").strip()
        if tid and tid in VOLUME_TOKENS:
            counted += 1
            symbols.add(VOLUME_TOKENS[tid])
            continue
        if tid:
            ignored += 1
            looks_like = sym.upper() in _IMPERSONATED_SYMBOLS or "tether" in name.lower()
            if looks_like:
                fakes[tid] = sym or name
        else:
            counted += 1  # нет tokenId — считаем как раньше (см. _amount)

    if fakes:
        listed = ", ".join(sorted({v for v in fakes.values() if v})) or "USDT"
        verdict.risk_flags.append(
            f"⚠️ Переводы поддельного «{listed}»: символ совпадает, а контракт чужой "
            f"({len(fakes)} шт.). Типичное отравление истории или подготовка к обману "
            f"при копировании адреса. Из расчёта экспозиции такие переводы исключены"
        )
    if ignored and counted and ignored >= counted:
        verdict.risk_flags.append(
            f"ℹ️ Большая часть переводов ({ignored} из {ignored + counted}) — в токенах "
            f"вне списка учёта, экспозиция посчитана по {counted}"
        )
    return {
        "transfers_counted": counted,
        "transfers_ignored": ignored,
        "tokens_counted": sorted(symbols),
        "impersonating_tokens": sorted(fakes),
    }


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
            direction = "out"   # адрес ОТПРАВИЛ контрагенту
        elif addr == t.get("to_address"):
            cp = t.get("from_address")
            tag = (t.get("from_address_tag") or {}).get("from_address_tag")
            direction = "in"    # адрес ПОЛУЧИЛ от контрагента
        else:
            continue
        if not cp:
            continue
        amt = _amount(t)
        total += amt
        d = per_cp.setdefault(
            cp,
            {
                "volume": 0.0,
                # Направление важно для AML: получить средства от санкционного
                # адреса — принять грязные деньги, отправить — финансировать.
                # Раньше и то и другое давало одинаковый вклад в один `volume`.
                "volume_in": 0.0,
                "volume_out": 0.0,
                "exch": None,
                "sanctioned": cp in sanctioned,
            },
        )
        d["volume"] += amt
        d[f"volume_{direction}"] += amt
        if d["exch"] is None:
            d["exch"] = _counterparty_service(tag, cp)
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
            sub_transfers = await flow.fetch_transfers(cp, client, pages=HOP2_FLOW_PAGES)
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


def _pct_str(value: float) -> str:
    """Процент для текста флага: 70 вместо «70.0», но 0.9 остаётся «0.9»."""
    return f"{value:.0f}" if abs(value - round(value)) < 0.05 else f"{value:g}"


def _compute_aml(
    verdict: AddressVerdict,
    transfers: list[dict[str, Any]],
    sanctioned: set[str],
    hop2: dict[str, Any] | None = None,
    tokens: dict[str, Any] | None = None,
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
    # Тот же объём с разбивкой по направлению: «получено от» и «отправлено на».
    flow_dir = {"sanctions_in": 0.0, "sanctions_out": 0.0,
                "sanctioned_exchange_in": 0.0, "sanctioned_exchange_out": 0.0}
    sanctioned_cps: set[str] = set()
    risky_exchanges: set[str] = set()
    for cp, d in per_cp.items():
        amt = d["volume"]
        if d["sanctioned"]:
            vol["sanctions"] += amt
            flow_dir["sanctions_in"] += d.get("volume_in", 0.0)
            flow_dir["sanctions_out"] += d.get("volume_out", 0.0)
            sanctioned_cps.add(cp)
        elif d["exch"] in SANCTIONED_EXCHANGE_NAMES:
            vol["sanctioned_exchange"] += amt
            flow_dir["sanctioned_exchange_in"] += d.get("volume_in", 0.0)
            flow_dir["sanctioned_exchange_out"] += d.get("volume_out", 0.0)
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
        # Направление экспозиции: получить от санкционного адреса и отправить
        # на него — разные события, и в отчёте они должны читаться раздельно.
        "sanctions_received_pct": pct(flow_dir["sanctions_in"]),
        "sanctions_sent_pct": pct(flow_dir["sanctions_out"]),
        "sanctioned_exchange_received_pct": pct(flow_dir["sanctioned_exchange_in"]),
        "sanctioned_exchange_sent_pct": pct(flow_dir["sanctioned_exchange_out"]),
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
        # Гигиена токенов: сколько переводов реально попало в объёмную математику
        # и не мимикрирует ли кто-то под USDT (см. _apply_token_hygiene).
        **(tokens or {}),
    }

    # Известный ЛЕГАЛЬНЫЙ сервис (биржа/контракт, НЕ санкционный): косвенная
    # экспозиция через него ОЖИДАЕМА и не делает его грязным.
    # HIGH_RISK_SERVICE сюда НЕ входит: биржа без KYC, P2P и миксер не получают
    # поддавка «через сервис течёт всё подряд».
    known_service = (
        verdict.entity_type in (EntityType.EXCHANGE, EntityType.CONTRACT)
        and not self_sanctioned_exch
        and not _is_probable_deposit(verdict)
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

    # Жалобы пользователей в TronScan (feedbackRisk) — сигнал о САМОМ адресе,
    # а не о его контрагентах, поэтому он задаёт нижнюю границу. Для опознанного
    # легального сервиса игнорируем: на биржи жалуются постоянно, и репорт там
    # говорит о споре с поддержкой, а не о природе адреса.
    if not known_service and (verdict.raw_labels.get("profile") or {}).get("feedback_risk"):
        score = max(score, FEEDBACK_RISK_SCORE)

    verdict.risk_score = int(round(min(100.0, score)))

    # ---- Прямое попадание в OFAC ----
    if direct:
        verdict.entity_type = EntityType.SANCTIONED
        verdict.sanction_source = "OFAC SDN"
        if not verdict.entity or verdict.entity == "No public labels":
            verdict.entity = "Санкционный адрес (OFAC SDN)"
        verdict.risk_flags.insert(0, "🚨 Адрес в санкционном списке OFAC SDN")
        if "OFAC SDN" not in verdict.sources:
            verdict.sources.append("OFAC SDN")

    # ---- Сам адрес — кошелёк санкционной биржи ----
    elif self_sanctioned_exch:
        exch_name = deposit_pattern.get("exchange") or verdict.entity or ""
        src = SANCTIONED_EXCHANGE_SOURCE.get(exch_name, "UK · EU · OFAC")
        verdict.entity_type = EntityType.SANCTIONED
        verdict.sanction_source = src
        verdict.entity = f"{verdict.entity} (санкционная биржа)"
        verdict.risk_flags.insert(
            0,
            f"🚨 Депозитный адрес санкционной биржи ({src}) — средства уходят "
            f"в санкционную инфраструктуру, могут быть заморожены"
            if sanctioned_deposit
            else f"🚨 Хот-кошелёк санкционной биржи ({src})",
        )

    # ---- GoPlus critical на самом адресе ----
    if goplus_critical and not direct and verdict.entity_type == EntityType.UNKNOWN:
        verdict.entity_type = EntityType.SCAM
        verdict.entity = verdict.entity or "Вредоносный адрес (GoPlus)"

    # ---- Тип сам по себе задаёт нижнюю границу риска ----
    # Метка от внешнего сервиса может прийти с мягким уровнем (Bitok умеет отдать
    # категорию «sanctions» с родным уровнем «low»). Тип и уровень не должны
    # противоречить друг другу: иначе в отчёте одновременно «САНКЦИОННЫЙ» и
    # «НЕТ ДАННЫХ · риск 0/100».
    floor = _TYPE_MIN_RISK.get(verdict.entity_type)
    if floor:
        min_score, min_level = floor
        verdict.risk_score = max(verdict.risk_score, min_score)
        if _RISK_ORDER[min_level] > _RISK_ORDER[verdict.risk_level]:
            verdict.risk_level = min_level

    # ---- Синтез risk_level ----
    direct_danger = (
        direct or self_sanctioned_exch or bool(goplus_critical)
        or verdict.entity_type in (EntityType.SCAM, EntityType.SANCTIONED, EntityType.FROZEN)
    )
    if direct_danger:
        verdict.risk_level = RiskLevel.DANGEROUS
    elif not known_service:
        if verdict.risk_score >= 70:
            verdict.risk_level = RiskLevel.DANGEROUS
        elif verdict.risk_score >= 20:
            verdict.risk_level = RiskLevel.CAUTION
    elif verdict.risk_level is RiskLevel.UNKNOWN:
        # Опознанный легальный сервис без находок — это «безопасно», а не «нет
        # данных». Раньше метка биржи от внешнего AML оставляла уровень UNKNOWN.
        verdict.risk_level = RiskLevel.SAFE

    # ---- Поясняющие флаги экспозиции ----
    if vol["sanctions"] > 0 and not direct:
        # Направление называем явно: «получил от санкционного» и «отправил на
        # санкционный» — это разные обвинения, и читатель отчёта должен видеть,
        # какое из них к адресу относится.
        parts = []
        if flow_dir["sanctions_in"] > 0:
            parts.append(f"получено {_pct_str(pct(flow_dir['sanctions_in']))}%")
        if flow_dir["sanctions_out"] > 0:
            parts.append(f"отправлено {_pct_str(pct(flow_dir['sanctions_out']))}%")
        detail = f" ({', '.join(parts)})" if parts else ""
        verdict.risk_flags.append(
            f"Экспозиция к санкционным адресам: {_pct_str(pct(vol['sanctions']))}% объёма"
            f"{detail}, {len(sanctioned_cps)} контрагент(ов)"
        )
    if vol["sanctioned_exchange"] > 0 and not self_sanctioned_exch:
        verdict.risk_flags.append(
            f"⚠️ Переводы с санкционными биржами ({', '.join(sorted(risky_exchanges))}): "
            f"{_pct_str(pct(vol['sanctioned_exchange']))}% объёма — деньги могут заморозить"
        )
    if indirect_pct > 0 and not direct_danger:
        n = len((hop2 or {}).get("flagged", []))
        verdict.risk_flags.append(
            f"Косвенная связь с санкциями через {n} посредник(ов): "
            f"~{_pct_str(indirect_pct)}% объёма (2-й хоп)"
        )

    # ---- Внешние KYT — последний штрих ОДНОГО расчёта ----
    # Раньше это был отдельный проход уже после _compute_aml, из-за чего метка от
    # Swapster/Bitok меняла тип адреса, а скор оставался посчитанным для прежнего
    # типа. Теперь всё считается один раз и в одном месте.
    _apply_external_aml_risk(verdict)


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
    """Ручные метки — НАИВЫСШИЙ приоритет, поэтому вызывается последней.

    Раньше вызов стоял до внешних AML, и KYT переопределял ручную метку: свой
    доверенный адрес нельзя было пометить безопасным. Оператор, который вручную
    разметил адрес, знает о нём больше, чем платный сервис, поэтому заданный
    локально уровень — окончательный. Когда локальная метка понижает риск, это
    видно в выводе отдельной строкой, а не молча."""
    if not data:
        return
    verdict.raw_labels["local"] = data
    verdict.sources.append("Local DB")
    verdict.entity = data.get("entity") or verdict.entity
    if data.get("entity_type"):
        try:
            verdict.entity_type = EntityType(data["entity_type"])
        except ValueError:
            log.warning("Local label: неизвестный entity_type %r", data["entity_type"])
    if data.get("risk_level"):
        try:
            new_level = RiskLevel(data["risk_level"])
        except ValueError:
            log.warning("Local label: неизвестный risk_level %r", data["risk_level"])
        else:
            lowered = _RISK_ORDER[new_level] < _RISK_ORDER[verdict.risk_level]
            if lowered:
                verdict.risk_flags.append(
                    f"📝 Уровень понижен до «{new_level.value}» ручной локальной меткой "
                    f"(было «{verdict.risk_level.value}», скор {verdict.risk_score})"
                )
            verdict.risk_level = new_level
            if new_level is RiskLevel.SAFE:
                verdict.risk_score = min(verdict.risk_score, 10)
    if data.get("note"):
        verdict.risk_flags.append(f"Local note: {data['note']}")


def _cache_age(checked_at: str | None) -> int | None:
    """Возраст кешированного вердикта в секундах. None, если дата неизвестна
    (вердикт сохранён версией без checked_at)."""
    if not checked_at:
        return None
    try:
        ts = datetime.fromisoformat(checked_at)
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return max(0, int(datetime.now(UTC).timestamp() - ts.timestamp()))


async def _guarded(name: str, coro, default):
    """Вызов провайдера с фиксацией исхода.

    Провайдер, который не смог получить данные, обязан быть ВИДЕН в вердикте:
    иначе «сбой TronScan» и «у адреса нет меток» дают одинаковый вывод, и
    отсутствие данных выглядит как отсутствие риска (ROADMAP §1.3)."""
    try:
        return name, await coro, "ok"
    except ProviderError as e:
        log.warning("Провайдер %s недоступен: %s", name, e)
        return name, default, "error"
    except Exception:  # pragma: no cover — неожиданный сбой не должен ронять проверку
        log.exception("Провайдер %s: неожиданная ошибка", name)
        return name, default, "error"


# Человекочитаемые имена провайдеров для флага о неполной проверке.
_PROVIDER_RU = {
    "tronscan": "TronScan (метки и баланс)",
    "goplus": "GoPlus (риск-флаги)",
    "flow": "TronScan переводы (связи и экспозиция)",
    "ofac": "OFAC SDN (санкционный список)",
    "swapster": "Swapster",
    "bitok": "Bitok",
    "hop2": "2-й хоп",
}


def _aml_status(ext: dict[str, Any]) -> str:
    """Исход внешнего KYT в терминах provider_status.

    «Не настроен» отделяем от «ошибка»: первое — решение оператора, второе —
    сбой, о котором пользователю надо сказать."""
    if not isinstance(ext, dict):
        return "error"
    if ext.get("skipped"):
        return "skipped"
    if ext.get("available"):
        return "pending" if ext.get("pending") else "ok"
    reason = str(ext.get("reason") or "")
    return "not_configured" if "не настроен" in reason else "error"


def _apply_provider_gaps(verdict: AddressVerdict) -> None:
    """Один явный флаг про то, что проверка неполная. Без него пользователь
    не может отличить «чисто» от «не проверили»."""
    failed = [n for n, st in verdict.provider_status.items() if st == "error"]
    if failed:
        names = ", ".join(_PROVIDER_RU.get(n, n) for n in failed)
        verdict.risk_flags.insert(
            0,
            f"❗ Проверка НЕПОЛНАЯ: недоступны источники — {names}. "
            f"Отсутствие находок здесь не означает отсутствие риска",
        )
    if verdict.provider_status.get("ofac") == "bundled":
        verdict.risk_flags.append(
            "ℹ️ Санкционный список взят из вшитого снимка (GitHub недоступен) — "
            "новые санкционные адреса могут отсутствовать"
        )


async def _apply_history(verdict: AddressVerdict, source: str) -> None:
    """Записать проверку в журнал и сравнить с предыдущей.

    Смена уровня риска у того же адреса — самостоятельная находка: адрес, по
    которому вчера было «безопасно», сегодня может быть в блэклисте. Ошибки
    журнала глушатся внутри core.history: он необязательный."""
    prev = await history.previous(verdict.address)
    await history.record(verdict, source)
    if not prev:
        return
    verdict.raw_labels["previous_check"] = prev
    old_level, new_level = prev.get("risk_level"), verdict.risk_level.value
    if old_level == new_level:
        return
    old_score = prev.get("risk_score")
    grew = _RISK_ORDER.get(RiskLevel(old_level) if old_level else RiskLevel.UNKNOWN, 0) < \
        _RISK_ORDER[verdict.risk_level]
    arrow = "⬆️" if grew else "⬇️"
    verdict.risk_flags.append(
        f"{arrow} Вердикт изменился с прошлой проверки: было «{old_level}» "
        f"({old_score}/100), стало «{new_level}» ({verdict.risk_score}/100)"
    )


# Общий бюджет одной проверки. Этапы идут последовательно (flow → hop2 →
# внешние KYT), у каждого свой таймаут, но верхней границы у суммы не было.
# По истечении отдаём то, что успело посчитаться: неполный ответ с честной
# пометкой полезнее, чем бот, который молча держит пользователя минутами.
CHECK_BUDGET_SECONDS = float(os.getenv("CHECK_BUDGET_SECONDS", "90"))

# Дедупликация одновременных проверок одного адреса. Два пользователя,
# нажавшие «проверить» на одном адресе, оплачивали два похода в Swapster и
# Bitok. Второй теперь ждёт результат первого.
_inflight: dict[tuple[str, bool], asyncio.Task] = {}


def inflight_count() -> int:
    """Сколько проверок выполняется прямо сейчас (для /stats)."""
    return len(_inflight)


async def check_address(
    address: str, use_cache: bool = True, source: str = "api"
) -> AddressVerdict:
    """Главная точка входа. Дедуплицирует одновременные проверки одного адреса
    и ограничивает проверку общим бюджетом времени."""
    if not is_valid_trc20_address(address):
        return AddressVerdict(
            address=address,
            entity="Invalid TRC20 address",
            entity_type=EntityType.UNKNOWN,
            risk_level=RiskLevel.UNKNOWN,
            risk_flags=["Address failed base58check validation"],
        )

    key = (address, use_cache)
    running = _inflight.get(key)
    if running is not None and not running.done():
        log.info("Проверка %s уже выполняется — ждём её результат", address)
        # shield: отмена ожидающего не должна ронять проверку, которую ждут другие.
        return await asyncio.shield(running)

    task = asyncio.create_task(_check_address_guarded(address, use_cache, source))
    _inflight[key] = task
    try:
        return await asyncio.shield(task)
    finally:
        if _inflight.get(key) is task:
            del _inflight[key]


async def _check_address_guarded(
    address: str, use_cache: bool, source: str
) -> AddressVerdict:
    """Проверка под общим дедлайном."""
    if CHECK_BUDGET_SECONDS <= 0:
        return await _check_address(address, use_cache, source)
    try:
        async with asyncio.timeout(CHECK_BUDGET_SECONDS):
            return await _check_address(address, use_cache, source)
    except TimeoutError:
        log.warning(
            "Проверка %s не уложилась в бюджет %.0f с — отдаём частичный результат",
            address, CHECK_BUDGET_SECONDS,
        )
        partial = _partial.pop(address, None)
        if partial is None:
            partial = AddressVerdict(address=address, entity="Проверка не завершилась")
        partial.risk_flags.insert(
            0,
            f"⏳ Проверка прервана по таймауту ({CHECK_BUDGET_SECONDS:.0f} с): часть "
            f"источников не успела ответить. Повторите — платные KYT иногда "
            f"считаются дольше обычного",
        )
        for name in ("swapster", "bitok", "hop2"):
            partial.provider_status.setdefault(name, "timeout")
        partial.checked_at = datetime.now(UTC).isoformat(timespec="seconds")
        partial.ruleset_version = RULESET_VERSION
        return partial


# Частично собранные вердикты: если проверка не уложится в бюджет, отдаём то,
# что успели узнать, вместо пустого ответа.
_partial: dict[str, AddressVerdict] = {}


async def _check_address(
    address: str, use_cache: bool, source: str
) -> AddressVerdict:
    """Собственно проверка.

    - Смотрит кеш
    - Параллельно опрашивает TronScan + GoPlus + flow + OFAC + блэклист Tether
    - Сводит в единый Verdict, фиксируя состояние каждого источника
    - Кеширует результат
    """
    # Кеш
    if use_cache:
        cached = await cache.get(address)
        if cached:
            v = AddressVerdict.from_dict(cached)
            v.cached = True
            v.cache_age_seconds = _cache_age(v.checked_at)
            return v

    # Параллельный запрос провайдеров. Сбой одного не отменяет остальные, но
    # фиксируется в provider_status и выводится пользователю.
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(
            _guarded("tronscan", tronscan.fetch_account(address, client), {}),
            _guarded("goplus", goplus.fetch_address_security(address, client), {}),
            _guarded("flow", flow.fetch_transfers(address, client), []),
            _guarded("ofac", ofac.fetch_sanctioned_set(client), set()),
            _guarded("tether", tether.check(address, client), None),
        )
        data = {name: value for name, value, _ in results}
        status = {name: st for name, _, st in results}
        ts_data = data["tronscan"]
        gp_data = data["goplus"]
        flow_data = data["flow"]
        # Метаданные уровня ответа приходят вместе с переводами (flow.TransferPage);
        # обычный список (мок, старый вызов) просто не имеет их.
        flow_meta = getattr(flow_data, "meta", {})
        sanctioned = data["ofac"]
        tether_result = data["tether"]
        if status["ofac"] == "ok":
            # live | cache | bundled — откуда фактически взят список.
            # "none" приходит только когда модуль не ходил в сеть (подменён в тестах).
            src = ofac.last_source()
            status["ofac"] = src if src != "none" else ("ok" if sanctioned else "empty")
        if not tether.is_enabled():
            status["tether"] = "skipped"

        verdict = AddressVerdict(address=address)
        verdict.provider_status = status
        # Держим ссылку: при срабатывании общего дедлайна отдаём собранное,
        # а не пустой вердикт.
        _partial[address] = verdict
        token_summary = _apply_token_hygiene(flow_data, verdict)
        token_summary.update(_apply_transfer_signals(flow_data, flow_meta, verdict))
        token_summary["poisoning_suspects"] = _detect_poisoning(flow_data, verdict)
        _apply_tronscan(ts_data, verdict)
        _apply_goplus(gp_data, verdict)
        # Якоря из накопительного кластера: хот-кошельки, выученные на прошлых
        # проверках. Без них депозитник биржи, у контрагента которого в ответе
        # не оказалось тега, оставался «личным кошельком».
        _apply_flow(flow_data, verdict, await _anchor_map(flow_data, address))
        # Блокировка эмитентом бьёт всё остальное, поэтому применяется до
        # решения о туннеле: для FROZEN платные KYT уже ничего не добавят.
        _apply_tether(tether_result, verdict)

        # Безопасность контракта спрашиваем ТОЛЬКО для контрактов: для кошелька
        # этот эндпоинт бессмысленен, а лишний запрос — лишняя задержка.
        if verdict.entity_type is EntityType.CONTRACT and token_security.is_enabled():
            _, sec_data, sec_status = await _guarded(
                "token_security", token_security.fetch(address, client), None
            )
            verdict.provider_status["token_security"] = sec_status
            _apply_token_security(sec_data, verdict)

        # 2-й хоп: только для кошельков/неизвестных (биржи/контракты/прямые
        # санкции раскрывать бессмысленно — их контрагенты это «все подряд»).
        hop2 = None
        if (
            HOP2_ENABLED
            and address not in sanctioned
            and (
                verdict.entity_type not in (EntityType.EXCHANGE, EntityType.CONTRACT)
                # Для «вероятного» депозитника как раз интересно, кто на него
                # прислал: вывод держится на одном переводе.
                or _is_probable_deposit(verdict)
            )
        ):
            total_h, per_cp_h = _parse_transfers(address, flow_data, sanctioned)
            try:
                hop2 = await _fetch_hop2(per_cp_h, total_h, sanctioned, client)
                verdict.provider_status["hop2"] = "ok"
            except ProviderError as e:
                log.warning("2-й хоп недоступен: %s", e)
                verdict.provider_status["hop2"] = "error"

    if hop2 and hop2.get("flagged"):
        verdict.sources.append("TronScan flow (2-hop)")

    # Кластеризация: опознан депозитник биржи → пишем в накопительную БД и
    # обогащаем вердикт числом родственных депозитников того же якоря/биржи.
    await _apply_cluster(verdict)

    # Баланс кошелька (из уже полученного ответа TronScan). Нужен до внешних AML:
    # по нему определяется транзитность для релейбла Swapster.
    verdict.balance_trx, verdict.balance_usdt = balance.extract_balances(ts_data)

    # ---- Фаза меток: внешние KYT ----
    # Туннель: биржа/контракт → внешние AML не зовём (их скор ничего не говорит о
    # владельце инфраструктуры). Решение принимается по ON-CHAIN типу, до расчёта
    # риска. Скам/санкции туннель НЕ отсекает: там второе мнение ценно.
    if verdict.entity_type in _AML_SKIP_TYPES and not _is_probable_deposit(verdict):
        reason = (
            "средства заблокированы эмитентом — второе мнение ничего не добавит"
            if verdict.entity_type is EntityType.FROZEN
            else "биржа/сервис — внешний AML не требуется"
        )
        verdict.external_aml = {"skipped": True, "reason": reason}
        verdict.bitok_aml = {"skipped": True, "reason": reason}
        verdict.provider_status["swapster"] = "skipped"
        verdict.provider_status["bitok"] = "skipped"
    else:
        verdict.external_aml, verdict.bitok_aml = await asyncio.gather(
            aml_external.check(address), aml_bitok.check(address)
        )
        for key, ext in (("swapster", verdict.external_aml), ("bitok", verdict.bitok_aml)):
            verdict.provider_status[key] = _aml_status(ext)
        # Swapster может опознать биржу/сервис там, где TronScan/on-chain пусто,
        # но только если адрес ещё и ведёт себя как транзит (не личный юзер).
        transit = _is_transit(flow_data, address, verdict.balance_usdt)
        _relabel_from_swapster(verdict, transit)
        # Bitok знает имя сущности off-chain — используем, если меток нет вообще.
        _label_from_bitok(verdict)

    # ---- Фаза расчёта: ОДИН раз, когда все метки собраны ----
    # Порядок важен: раньше риск считался до внешних AML, и их метка меняла тип
    # адреса уже после расчёта. Получались взаимоисключающие строки в отчёте —
    # «Тип: САНКЦИОННЫЙ» рядом с «НЕТ ДАННЫХ · риск 0/100», а переклеймённая в
    # биржу сущность сохраняла «кошельковый» скор.
    _compute_aml(verdict, flow_data, sanctioned, hop2, token_summary)

    # Fallback: нет публичной метки. risk_level НЕ трогаем — его уже выставил
    # _compute_aml (у адреса может быть реальный риск от экспозиции/2-хопа).
    if verdict.entity_type == EntityType.UNKNOWN and not verdict.entity:
        verdict.entity = "No public labels"

    # Ручные метки — последними: у них наивысший приоритет (см. _apply_local).
    # Приоритет источников: БД меток (правится оператором без редеплоя) выше
    # предзаданных в local.py — в БД они и так засеяны при старте.
    _apply_local(labels.lookup(address) or local.lookup(address), verdict)

    # Один явный флаг, если какой-то источник не ответил.
    _apply_provider_gaps(verdict)

    verdict.checked_at = datetime.now(UTC).isoformat(timespec="seconds")
    verdict.ruleset_version = RULESET_VERSION

    # Сравнение с прошлым результатом — то, зачем журнал и нужен: повторная
    # проверка контрагента отвечает на вопрос «изменилось ли что-нибудь».
    await _apply_history(verdict, source)

    # Кеш
    if use_cache:
        await cache.put(address, verdict.to_dict())

    _partial.pop(address, None)
    return verdict
