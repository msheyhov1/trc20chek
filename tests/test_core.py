"""Тесты ядра без внешних запросов — провайдеры подменяются моками."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from core.aggregator import check_address
from core.models import AddressVerdict, EntityType, RiskLevel, is_valid_trc20_address

# ---------- Валидация ----------

def test_valid_address():
    # Реальный USDT-контракт
    assert is_valid_trc20_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") is True


def test_invalid_length():
    assert is_valid_trc20_address("TR7NHqjeKQxGTCi8q8ZY4pL8") is False


def test_invalid_prefix():
    assert is_valid_trc20_address("XR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t") is False


def test_invalid_checksum():
    # Изменили один символ в валидном
    assert is_valid_trc20_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X") is False


def test_invalid_chars():
    assert is_valid_trc20_address("TR7NHqjeKQxGTCi8q8ZY4pL8otSzg!Lj6t") is False


# ---------- Агрегатор: моки провайдеров ----------

VALID_ADDR = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

EMPTY_GP = {"code": 1, "result": {
    "cybercrime": "0", "money_laundering": "0", "financial_crime": "0",
    "phishing_activities": "0", "blacklist_doubt": "0", "stealing_attack": "0",
    "blackmail_activities": "0", "sanctioned": "0", "mixer": "0",
    "honeypot_related_address": "0", "data_source": "GoPlus",
}}


NO_AML = {"available": False, "reason": "не настроен"}


NOT_BLACKLISTED = {"blacklisted": False, "source": "contract"}


@pytest.fixture(autouse=True)
def _no_network_by_default():
    """flow, OFAC, блэклист Tether и внешние AML по умолчанию пустые — тесты не
    ходят в сеть. Конкретный тест переопределяет нужный патч своим внутри `with`."""
    with patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=[])), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())), \
         patch("core.aggregator.tether.check",
               new=AsyncMock(return_value=dict(NOT_BLACKLISTED))), \
         patch("core.aggregator.aml_external.check", new=AsyncMock(return_value=dict(NO_AML))), \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value=dict(NO_AML))):
        yield


@pytest.mark.asyncio
async def test_exchange_detection():
    """Биржевой кошелёк с publicTag='Binance-Hot'"""
    ts_resp = {
        "address": VALID_ADDR,
        "publicTag": "Binance-Hot 2",
        "addressTag": "Binance-Hot 2",
    }
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity == "Binance"
    assert v.entity_type == EntityType.EXCHANGE
    assert v.risk_level == RiskLevel.SAFE
    assert "Exchange hot wallet" in v.risk_flags


@pytest.mark.asyncio
async def test_contract_detection():
    """Контракт USDT"""
    # Реальная структура ответа TronScan accountv2 для контракта:
    # accountType == 2, адрес присутствует ключом в contractMap, имя в name.
    ts_resp = {
        "address": VALID_ADDR,
        "name": "Tether USD",
        "contractMap": {VALID_ADDR: True},
        "accountType": 2,
        "vip": True,
    }
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.CONTRACT
    assert v.risk_level == RiskLevel.SAFE
    assert "Tether" in (v.entity or "")


@pytest.mark.asyncio
async def test_scam_detection_tronscan_red():
    ts_resp = {"address": VALID_ADDR, "redTag": "Phishing/Hacker/Scammer"}
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.SCAM
    assert v.risk_level == RiskLevel.DANGEROUS


@pytest.mark.asyncio
async def test_scam_detection_goplus_flags():
    """GoPlus поднимает phishing — обязан стать DANGEROUS, даже если TronScan чист"""
    gp_resp = {"code": 1, "result": {
        **EMPTY_GP["result"],
        "phishing_activities": "1", "stealing_attack": "1", "blacklist_doubt": "1",
        "data_source": "GoPlus,SlowMist",
    }}
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=gp_resp)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.entity_type == EntityType.SCAM
    assert any("phishing" in f for f in v.risk_flags)


@pytest.mark.asyncio
async def test_unknown_address():
    """Никаких меток ни от кого"""
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value={})):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.UNKNOWN
    assert v.risk_level == RiskLevel.UNKNOWN


@pytest.mark.asyncio
async def test_invalid_address_short_circuit():
    """Невалидный адрес — провайдеров не дёргаем"""
    ts_mock = AsyncMock(return_value={})
    gp_mock = AsyncMock(return_value={})
    with patch("core.aggregator.tronscan.fetch_account", new=ts_mock), \
         patch("core.aggregator.goplus.fetch_address_security", new=gp_mock):
        v = await check_address("BAD", use_cache=False)
    assert "Invalid" in (v.entity or "")
    ts_mock.assert_not_called()
    gp_mock.assert_not_called()


@pytest.mark.asyncio
async def test_flow_exchange_links():
    """Адрес без прямой метки, но по переводам видно связь с биржами."""
    addr = VALID_ADDR
    transfers = [
        {"from_address": addr, "to_address": "Ta",
         "to_address_tag": {"to_address_tag": "Bybit"}},
        {"from_address": addr, "to_address": "Tb",
         "to_address_tag": {"to_address_tag": "Bybit"}},
        {"from_address": "Tc", "to_address": addr,
         "from_address_tag": {"from_address_tag": "Bitget 9"}},
        {"from_address": addr, "to_address": "Td",
         "to_address_tag": {"to_address_tag": ""}},  # контрагент без метки — игнор
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.WALLET
    assert "Bybit" in (v.entity or "")
    assert {e["name"] for e in v.exchange_links} == {"Bybit", "Bitget"}
    bybit = next(e for e in v.exchange_links if e["name"] == "Bybit")
    assert bybit["deposits"] == 2 and bybit["withdrawals"] == 0
    assert "TronScan flow" in v.sources


@pytest.mark.asyncio
async def test_exchange_deposit_wallet_sweep():
    """Депозитник биржи: сумма приходит от стороннего адреса и ровно столько же
    уходит на биржу (sweep). Несколько таких пар → адрес = депозитный кош биржи."""
    addr = VALID_ADDR
    transfers = [
        # пара 1: пришло 587.32 от Tx → ушло 587.32 на Bybit
        _tr("Tx1", addr, 587_320_000),
        _tr(addr, "TBybit", 587_320_000, to_tag="Bybit"),
        # пара 2: 400 → 400 на Bybit
        _tr("Tx2", addr, 400_000_000),
        _tr(addr, "TBybit", 400_000_000, to_tag="Bybit"),
        # пара 3: 307.13 → 307.13 на Bybit
        _tr("Tx3", addr, 307_130_000),
        _tr(addr, "TBybit", 307_130_000, to_tag="Bybit"),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.EXCHANGE
    assert v.entity == "Депозитный кошелёк Bybit"
    assert v.risk_level == RiskLevel.SAFE
    dp = v.raw_labels["flow"]["deposit_pattern"]
    assert dp["exchange"] == "Bybit" and dp["matched_pairs"] == 3
    assert any("Депозитный/транзитный адрес биржи" in f for f in v.risk_flags)


@pytest.mark.asyncio
async def test_exchange_deposit_aggregation():
    """Депозитник АГРЕГИРУЕТ несколько приходов в один вывод на биржу
    (4129.33 + 10 + 20 → 4159.33 на Bybit). Суммы НЕ 1:1, но funnel ловится."""
    addr = VALID_ADDR
    transfers = [
        _tr(addr, "TBybit", 4_159_330_000, to_tag="Bybit"),  # вывел всё на Bybit
        _tr("Tsrc1", addr, 4_129_330_000),                   # приход извне
        _tr("Tsrc2", addr, 10_000_000),
        _tr("Tsrc2", addr, 20_000_000),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.EXCHANGE
    assert v.entity == "Депозитный кошелёк Bybit"
    assert v.risk_level == RiskLevel.SAFE
    dp = v.raw_labels["flow"]["deposit_pattern"]
    assert dp["exchange"] == "Bybit"
    assert dp["matched_pairs"] == 0          # 1:1 совпадений нет — поймали funnel
    assert dp["concentration"] == 1.0


@pytest.mark.asyncio
async def test_sanctioned_exchange_deposit_wallet():
    """Депозитник САНКЦИОННОЙ биржи (sweep на HTX): приход = вывод на HTX.
    Не «личный кошелёк», а SANCTIONED — адрес обслуживает санкционную биржу."""
    addr = VALID_ADDR
    transfers = [
        _tr("Tx1", addr, 500_000_000),
        _tr(addr, "THTX", 500_000_000, to_tag="HTX 1"),
        _tr("Tx2", addr, 300_000_000),
        _tr(addr, "THTX", 300_000_000, to_tag="HTX 1"),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.SANCTIONED
    assert "HTX" in (v.entity or "")
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.risk_score == 100
    assert v.raw_labels["flow"]["deposit_pattern"]["sanctioned"] is True
    assert any("санкционной биржи" in f.lower() for f in v.risk_flags)


@pytest.mark.asyncio
async def test_deposit_clustering_siblings(tmp_path, monkeypatch):
    """Кластеризация: два разных депозитника, пересылающих на ОДИН хот-кошелёк
    биржи, связываются в кластер — второй видит первого как родственный адрес."""
    from core import cluster
    monkeypatch.setattr(cluster, "CLUSTER_PATH", tmp_path / "cluster.db")
    await cluster.init_db()

    addr_a = VALID_ADDR
    addr_b = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"
    hot = "THotBybitCollector00000000000000000"

    def _funnel(addr, a1, a2):
        return [
            _tr(addr, hot, a1 + a2, to_tag="Bybit"),  # вывод на общий хот-кошелёк
            _tr("Tsrc1", addr, a1),
            _tr("Tsrc2", addr, a2),
        ]

    async def _check(addr, transfers):
        with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
             patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
             patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
             patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())):
            return await check_address(addr, use_cache=False)

    va = await _check(addr_a, _funnel(addr_a, 100_000_000, 100_000_000))
    assert va.raw_labels["cluster"]["siblings_on_anchor"] == 0  # пока один

    vb = await _check(addr_b, _funnel(addr_b, 50_000_000, 50_000_000))
    cl = vb.raw_labels["cluster"]
    assert cl["hot_wallet"] == hot
    assert cl["siblings_on_anchor"] == 1            # видит addr_a на том же якоре
    assert addr_a in cl["siblings_sample"]
    assert any("Кластер биржи Bybit" in f for f in vb.risk_flags)


@pytest.mark.asyncio
async def test_two_way_exchange_not_deposit():
    """Личный торговый кошелёк: и заводит на биржу, и ВЫВОДИТ с неё (двусторонний)
    → не депозитник (депозитник от своей биржи ничего не получает)."""
    addr = VALID_ADDR
    transfers = [
        _tr(addr, "TBybit", 500_000_000, to_tag="Bybit"),     # завёл на Bybit
        _tr("TBybit2", addr, 300_000_000, from_tag="Bybit"),  # вывел С Bybit
        _tr("Tfriend", addr, 200_000_000),                    # приход извне
        _tr("Tfriend", addr, 100_000_000),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.WALLET
    assert "deposit_pattern" not in v.raw_labels.get("flow", {})


@pytest.mark.asyncio
async def test_deposit_wallet_with_gas_backflow():
    """Депозитник получает от биржи МЕЛОЧЬ на газ (sweep), но весь отток — на неё.
    Малый обратный поток (≤15% оттока) не должен ломать распознавание депозитника."""
    addr = VALID_ADDR
    transfers = [
        _tr(addr, "TBybitHot", 60_000_000_000, to_tag="Bybit"),   # отток на Bybit
        _tr(addr, "TBybitHot", 42_000_000_000, to_tag="Bybit"),
        _tr("TBybitGas", addr, 2_000_000_000, from_tag="Bybit"),  # газ с Bybit (~2% оттока)
        _tr("Tuser1", addr, 50_000_000_000),                      # внешние депозиты
        _tr("Tuser2", addr, 46_000_000_000),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.EXCHANGE
    assert "Депозитный" in (v.entity or "")
    assert "deposit_pattern" in v.raw_labels.get("flow", {})


@pytest.mark.asyncio
async def test_swapster_relabels_unlabeled_as_exchange():
    """Неразмеченный транзитный адрес (получает с Bybit+Binance, форвардит) →
    on-chain даёт «кошелёк», но Swapster EXCHANGE LICENSED 99.6% → биржа/сервис."""
    addr = VALID_ADDR
    transfers = [
        _tr("TBybit", addr, 57_000_000_000, from_tag="Bybit"),
        _tr("TBinance", addr, 12_000_000_000, from_tag="Binance"),
        _tr(addr, "Tsink", 63_000_000_000),  # форвард на неразмеченный
    ]
    aml = {
        "available": True, "provider": "Swapster", "pending": False,
        "risk_score": 10.6, "risk_level": "safe",
        "entities": [{"entity": "EXCHANGE LICENSED", "level": "LOW_RISK", "risk_score": 99.6}],
    }
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())), \
         patch("core.aggregator.aml_external.check", new=AsyncMock(return_value=aml)):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.EXCHANGE
    assert "Swapster" in (v.entity or "")


def test_normalize_exchange_tags():
    """Теги TronScan (с суффиксами/регистром) → каноничное имя; обычные слова → None."""
    from core.aggregator import _normalize_exchange
    assert _normalize_exchange("MXC 2") == "MEXC"
    assert _normalize_exchange("Bybit Deposit") == "Bybit"
    assert _normalize_exchange("BitMart 1") == "BitMart"
    assert _normalize_exchange("WhiteBIT") == "WhiteBIT"
    assert _normalize_exchange("Coinbase Prime") == "Coinbase"
    assert _normalize_exchange("XT.COM") == "XT.com"
    # анти-ложные срабатывания
    for w in ("Justin Sun", "SunSwap", "Tether Treasury", "Bitcoin", "Contract", ""):
        assert _normalize_exchange(w) is None


@pytest.mark.asyncio
async def test_deposit_to_mexc_funded_from_other_exchanges():
    """Депозитник MEXC, куда средства заводят выводами с Bybit/Binance и форвардят
    на хот-кошелёк MEXC (в TronScan помечен «MXC»). Имя биржи берётся on-chain."""
    addr = VALID_ADDR
    transfers = [
        _tr("TBybit", addr, 57_000_000_000, from_tag="Bybit"),
        _tr("TBinance", addr, 12_000_000_000, from_tag="Binance"),
        _tr(addr, "TMXChot", 40_000_000_000, to_tag="MXC"),
        _tr(addr, "TMXChot2", 29_000_000_000, to_tag="MXC 2"),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.EXCHANGE
    assert "MEXC" in (v.entity or "")


@pytest.mark.asyncio
async def test_swapster_does_not_relabel_personal_holder():
    """Юзер всегда заводит с Bybit и ДЕРЖИТ (не форвардит) → у Swapster высокая
    биржевая экспозиция, но адрес НЕ транзит → остаётся кошельком, НЕ биржей."""
    addr = VALID_ADDR
    transfers = [
        _tr("TBybit", addr, 50_000_000_000, from_tag="Bybit"),
        _tr("TBybit", addr, 30_000_000_000, from_tag="Bybit"),
    ]  # только приход, ничего не пересылает дальше
    aml = {
        "available": True, "provider": "Swapster", "pending": False,
        "risk_score": 8.0, "risk_level": "safe",
        "entities": [{"entity": "EXCHANGE LICENSED", "level": "LOW_RISK", "risk_score": 99.6}],
    }
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())), \
         patch("core.aggregator.aml_external.check", new=AsyncMock(return_value=aml)):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.WALLET
    assert "Биржа" not in (v.entity or "")


@pytest.mark.asyncio
async def test_flow_does_not_override_contract():
    """Если TronScan уже опознал контракт — flow его не понижает до кошелька."""
    ts_resp = {"address": VALID_ADDR, "accountType": 2,
               "contractMap": {VALID_ADDR: True}, "name": "TetherToken"}
    transfers = [{"from_address": "Tx", "to_address": VALID_ADDR,
                  "from_address_tag": {"from_address_tag": "Binance-Hot 4"}}]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.CONTRACT  # тип не перебит
    assert any(e["name"] == "Binance" for e in v.exchange_links)  # но связи зафиксированы


# ---------- AML: санкции и экспозиция ----------

SANCTIONED_ADDR = "TBADaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _tr(frm, to, quant, *, from_tag="", to_tag=""):
    return {
        "from_address": frm, "to_address": to,
        "from_address_tag": {"from_address_tag": from_tag},
        "to_address_tag": {"to_address_tag": to_tag},
        "quant": str(quant), "tokenInfo": {"tokenDecimal": 6},
    }


@pytest.mark.asyncio
async def test_ofac_direct_sanction():
    """Сам адрес в OFAC SDN → санкционный, скор 100, DANGEROUS."""
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value={VALID_ADDR})):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.SANCTIONED
    assert v.risk_score == 100
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.aml["direct_sanctioned"] is True
    assert "OFAC SDN" in v.sources


@pytest.mark.asyncio
async def test_sanction_exposure_scoring():
    """Кошелёк льёт 80% объёма на санкционный адрес → скор 80, DANGEROUS."""
    transfers = [
        _tr(VALID_ADDR, SANCTIONED_ADDR, 800_000_000),               # 800 на санкционный
        _tr("Tgood", VALID_ADDR, 200_000_000, from_tag="Binance-Hot 2"),  # 200 с биржи
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value={SANCTIONED_ADDR})):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.aml["sanctions_exposure_pct"] == 80.0
    assert v.aml["exchange_exposure_pct"] == 20.0
    assert v.risk_score == 80
    assert v.risk_level == RiskLevel.DANGEROUS
    assert SANCTIONED_ADDR in v.aml["sanctioned_counterparties"]


@pytest.mark.asyncio
async def test_exchange_not_branded_by_indirect_exposure():
    """Биржу НЕ клеймим грязной за косвенную экспозицию, но показываем её в AML."""
    ts_resp = {"address": VALID_ADDR, "publicTag": "Binance-Hot 2", "addressTag": "Binance-Hot 2"}
    transfers = [
        _tr(VALID_ADDR, SANCTIONED_ADDR, 900_000_000),  # 90% объёма «грязного»
        _tr(VALID_ADDR, "Tclean", 100_000_000),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value={SANCTIONED_ADDR})):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.EXCHANGE      # осталась биржей
    assert v.risk_level == RiskLevel.SAFE            # НЕ заклеймена грязной
    assert v.risk_score <= 10                        # скор сервиса низкий
    assert v.aml["sanctions_exposure_pct"] == 90.0   # но экспозиция показана честно


@pytest.mark.asyncio
async def test_sanctioned_exchange_self():
    """Сам адрес — хот-кошелёк санкционной биржи (HTX, UK A7) → SANCTIONED."""
    ts_resp = {"address": VALID_ADDR, "publicTag": "HTX 1", "addressTag": "HTX 1"}
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.SANCTIONED
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.risk_score == 100
    assert "HTX" in (v.entity or "")


@pytest.mark.asyncio
async def test_sanctioned_exchange_exposure():
    """Кошелёк получил 70% объёма с санкционной биржи (HTX) → DANGEROUS."""
    transfers = [
        _tr("Thtxhotwallet", VALID_ADDR, 700_000_000, from_tag="HTX 3"),  # 700 c HTX
        _tr(VALID_ADDR, "Tclean", 300_000_000),                            # 300 прочее
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.aml["sanctioned_exchange_exposure_pct"] == 70.0
    assert "HTX (Huobi)" in v.aml["sanctioned_exchanges"]
    assert v.risk_score == 70
    assert v.risk_level == RiskLevel.DANGEROUS


@pytest.mark.asyncio
async def test_hop2_indirect_sanction():
    """2-й хоп: деньги пришли через посредника, который сам шлёт на санкционный
    адрес → косвенная экспозиция поднимает риск (с весом HOP2_WEIGHT=0.6)."""
    mid = "Tmiddleman000000000000000000000000"
    # hop1: проверяемый адрес получил всё от посредника mid (без метки)
    hop1 = [_tr(mid, VALID_ADDR, 1_000_000_000)]
    # hop2: посредник mid слил 100% объёма на санкционный адрес
    hop2 = [_tr(mid, SANCTIONED_ADDR, 1_000_000_000)]
    transfers_by_addr = {VALID_ADDR: hop1, mid: hop2}

    async def fake_transfers(addr, client):
        return transfers_by_addr.get(addr, [])

    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=fake_transfers), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value={SANCTIONED_ADDR})):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.aml["hop2_intermediaries_checked"] == 1
    assert v.aml["indirect_sanctions_pct"] == 100.0
    assert v.risk_score == 60   # 100% косвенно × вес 0.6
    assert v.risk_level == RiskLevel.CAUTION
    assert any("посредник" in f for f in v.risk_flags)


@pytest.mark.asyncio
async def test_personal_wallet_not_exchange():
    """Адрес без своей метки, но шлёт на Bybit → ЛИЧНЫЙ кошелёк, не биржа."""
    transfers = [_tr(VALID_ADDR, "Tbybit", 1_000_000, to_tag="Bybit 9")]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.WALLET          # НЕ exchange
    assert "Личный кошелёк" in (v.entity or "")
    assert any("не биржа" in f for f in v.risk_flags)


@pytest.mark.asyncio
async def test_untagged_high_activity_flagged_as_service():
    """Без метки, но 200k транзакций → возможно нетегированный сервис/биржа."""
    ts_resp = {"address": VALID_ADDR, "totalTransactionCount": 200_000}
    transfers = [_tr(VALID_ADDR, "Tbybit", 1_000_000, to_tag="Bybit 9")]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert "сервис" in (v.entity or "").lower()
    assert any("нетегир" in f for f in v.risk_flags)


# ---------- Внешние AML-сервисы (Swapster + Bitok) ----------

def _bitok(risk_level="none", score=0.0, entity=None, category=None, entities=None):
    """Ответ Bitok в нормализованном виде (как его отдаёт core/aml_bitok.check)."""
    from core.aml_bitok import _LEVEL_MAP, category_ru
    return {
        "available": True, "provider": "Bitok", "pending": False,
        "risk_score": score, "risk_level": _LEVEL_MAP.get(risk_level),
        "level_raw": risk_level, "entity": entity, "entity_category": category,
        "entity_category_ru": category_ru(category), "entities": entities or [],
    }


@pytest.mark.asyncio
async def test_bitok_labels_unlabeled_address():
    """У TronScan меток нет, но Bitok знает сущность → берём её имя и тип.

    `enforcement_action` — это категория, которой Bitok размечает блокировку
    Tether: средства физически неподвижны, поэтому тип FROZEN, а не нейтральный
    «Маркированный», как было раньше."""
    ext = _bitok("severe", 100.0, "Tether blacklist - TQ8a74", "enforcement_action")
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value=ext)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.FROZEN
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.risk_score == 100
    assert "Tether blacklist" in (v.entity or "")
    assert "правоохранительная блокировка" in (v.entity or "")
    assert "Bitok" in v.sources


@pytest.mark.asyncio
async def test_bitok_exchange_category_sets_exchange_type():
    ext = _bitok("none", 0.0, "Binance", "exchange")
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value=ext)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.EXCHANGE
    assert "Binance" in (v.entity or "")


@pytest.mark.asyncio
async def test_bitok_high_risk_escalates_verdict():
    """Чистый по on-chain адрес, но Bitok даёт severe → вердикт поднимается."""
    ext = _bitok("severe", 96.0, entities=[
        {"entity": "даркнет-маркет", "level": "HIGH_RISK", "risk_score": 96.0,
         "proximity": "indirect"}])
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value=ext)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.risk_score == 96
    assert any("Bitok" in f for f in v.risk_flags)


@pytest.mark.asyncio
async def test_external_aml_never_downgrades_verdict():
    """Адрес в OFAC SDN: «чистый» ответ внешнего сервиса не снимает опасность."""
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set",
               new=AsyncMock(return_value={VALID_ADDR})), \
         patch("core.aggregator.aml_bitok.check",
               new=AsyncMock(return_value=_bitok("none", 0.0))):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.SANCTIONED
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.risk_score == 100


@pytest.mark.asyncio
async def test_aml_tunnel_skips_exchange_for_both_providers():
    """Биржевой хот-кошелёк — платные KYT не дёргаем ни один."""
    ts_resp = {"address": VALID_ADDR, "accountType": 0, "publicTag": "Binance-Hot 4"}
    swapster = AsyncMock(return_value=dict(NO_AML))
    bitok = AsyncMock(return_value=dict(NO_AML))
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.aml_external.check", new=swapster), \
         patch("core.aggregator.aml_bitok.check", new=bitok):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.external_aml.get("skipped") is True
    assert v.bitok_aml.get("skipped") is True
    swapster.assert_not_awaited()
    bitok.assert_not_awaited()


# ---------- Гигиена токенов: фильтр объёмной математики по контракту ----------

FAKE_USDT_CONTRACT = "TFakeUSDTcontract00000000000000000"


def _spam(frm, to, quant, symbol="USDT"):
    """Перевод токена-подделки: символ как у USDT, контракт чужой."""
    return {
        "from_address": frm, "to_address": to,
        "from_address_tag": {"from_address_tag": ""},
        "to_address_tag": {"to_address_tag": ""},
        "quant": str(quant),
        "tokenInfo": {
            "tokenDecimal": 6, "tokenId": FAKE_USDT_CONTRACT,
            "tokenAbbr": symbol, "tokenName": "Tether USD",
        },
    }


def _usdt(frm, to, quant, *, from_tag="", to_tag=""):
    """Перевод НАСТОЯЩЕГО USDT (с tokenId реального контракта)."""
    t = _tr(frm, to, quant, from_tag=from_tag, to_tag=to_tag)
    t["tokenInfo"]["tokenId"] = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
    t["tokenInfo"]["tokenAbbr"] = "USDT"
    return t


@pytest.mark.asyncio
async def test_spam_token_cannot_dilute_sanction_exposure():
    """Вектор уклонения: выпустить свой токен с символом USDT и прислать себе
    один перевод на огромную сумму, чтобы санкционная доля упала до нуля.
    Объём считается только по токенам из VOLUME_TOKENS, поэтому не работает."""
    transfers = [
        _usdt(VALID_ADDR, SANCTIONED_ADDR, 900_000_000),   # 900 настоящих USDT
        _usdt("Tgood", VALID_ADDR, 100_000_000),           # 100 настоящих USDT
        _spam("Tspam", VALID_ADDR, 10_000_000_000_000),    # 10 млн поддельных
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set",
               new=AsyncMock(return_value={SANCTIONED_ADDR})):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.aml["sanctions_exposure_pct"] == 90.0   # не размылось
    assert v.risk_score == 90
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.aml["impersonating_tokens"] == [FAKE_USDT_CONTRACT]
    assert any("поддельного" in f for f in v.risk_flags)


@pytest.mark.asyncio
async def test_spam_token_does_not_break_deposit_detection():
    """Тот же спам не должен сбивать funnel-атрибуцию депозитника биржи:
    концентрация оттока считается по тому же объёму."""
    addr = VALID_ADDR
    transfers = [
        _usdt(addr, "TBybitHot", 4_159_330_000, to_tag="Bybit"),
        _usdt("Tsrc1", addr, 4_129_330_000),
        _usdt("Tsrc2", addr, 10_000_000),
        _usdt("Tsrc2", addr, 20_000_000),
        _spam("Tspam", addr, 10_000_000_000_000),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.EXCHANGE
    assert v.entity == "Депозитный кошелёк Bybit"


def test_amount_counts_only_allowlisted_contracts():
    from core.aggregator import _amount
    real = _usdt("Ta", "Tb", 1_000_000)
    assert _amount(real) == 1.0
    assert _amount(_spam("Ta", "Tb", 1_000_000)) == 0.0
    # Перевод без tokenId — считаем как раньше, иначе обнулили бы старые данные
    legacy = _tr("Ta", "Tb", 1_000_000)
    assert _amount(legacy) == 1.0


def test_volume_tokens_extendable_via_env(monkeypatch):
    """Свой токен можно добавить в учёт через env, мусор отбрасывается."""
    from core import aggregator as agg
    monkeypatch.setenv("AML_VOLUME_TOKENS", f"{VALID_ADDR}:MYUSD, @garbage")
    tokens = agg._volume_tokens()
    assert tokens[VALID_ADDR] == "MYUSD"
    assert "@garbage" not in tokens


# ---------- Санкционные биржи: словари и свежесть списка ----------

def test_no_overlap_between_exchange_dicts():
    """Название в обоих словарях = санкционная биржа получит вердикт «безопасно»:
    _normalize_exchange отдаёт предпочтение обычному словарю (он первый)."""
    from core.aggregator import EXCHANGE_KEYWORDS, SANCTIONED_EXCHANGES
    assert not set(EXCHANGE_KEYWORDS) & set(SANCTIONED_EXCHANGES)
    assert not set(EXCHANGE_KEYWORDS.values()) & set(SANCTIONED_EXCHANGES.values())


@pytest.mark.parametrize(
    "tag,expected",
    [
        ("Nobitex 1", "Nobitex"),          # OFAC 02.06.2026
        ("Wallex Hot", "Wallex"),
        ("Bitpin", "Bitpin"),
        ("Ramzinex", "Ramzinex"),
        ("WhiteBird", "WhiteBird"),        # EU 21-й пакет 23.07.2026
        ("Exnode Pay", "Exnode"),
        ("Brightum", "Tradex (Brightum)"),
        ("Shelbit", "Shelbit"),            # OFAC 07.08.2026
        ("AbanTether", "Aban Tether"),
        ("Bitcoin Xchange 2", "Bitcoin Xchange"),
        ("TengriCoin", "TengriCoin"),
    ],
)
def test_newly_sanctioned_exchanges_recognized(tag, expected):
    from core.aggregator import SANCTIONED_EXCHANGE_NAMES, _normalize_exchange
    name = _normalize_exchange(tag)
    assert name == expected
    assert name in SANCTIONED_EXCHANGE_NAMES


@pytest.mark.asyncio
async def test_sanctioned_iranian_exchange_hot_wallet():
    """Хот-кошелёк Nobitex: раньше «биржа / безопасно / KYT пропущен»."""
    ts_resp = {"address": VALID_ADDR, "publicTag": "Nobitex 1"}
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.SANCTIONED
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.risk_score == 100
    assert "Nobitex" in (v.entity or "")
    assert v.sanction_source == "OFAC"      # не «OFAC» по умолчанию, а по факту
    # Туннель считает адрес инфраструктурой биржи и не тратит платный KYT —
    # но это НЕ маскирует риск: вердикт всё равно максимальный.
    assert v.external_aml.get("skipped") is True


@pytest.mark.asyncio
async def test_sanctioned_exchange_source_is_not_always_ofac():
    """UK/EU-санкции не должны подписываться ссылкой на список США."""
    ts_resp = {"address": VALID_ADDR, "publicTag": "HTX 1"}
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts_resp)), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.SANCTIONED
    assert v.sanction_source == "UK · EU"
    assert v.entity_type_ru() == "САНКЦИОННЫЙ (UK · EU)"
    assert not any("OFAC" in f for f in v.risk_flags)


def test_every_sanctioned_exchange_has_a_source():
    from core.aggregator import SANCTIONED_EXCHANGE_NAMES, SANCTIONED_EXCHANGE_SOURCE
    missing = SANCTIONED_EXCHANGE_NAMES - set(SANCTIONED_EXCHANGE_SOURCE)
    assert not missing, f"не указан орган, внёсший биржу в список: {sorted(missing)}"


def test_every_bitok_category_has_a_type():
    """Новая категория Bitok без маппинга молча падала в «Маркированный» —
    так терялись mixer и enforcement_action (блокировка Tether)."""
    from core.aggregator import _BITOK_CATEGORY_TYPE
    from core.aml_bitok import ENTITY_CATEGORY_RU
    missing = set(ENTITY_CATEGORY_RU) - set(_BITOK_CATEGORY_TYPE)
    assert not missing, f"категории Bitok без типа адреса: {sorted(missing)}"


@pytest.mark.asyncio
async def test_bitok_mixer_is_high_risk_service_not_plain_label():
    ext = _bitok("medium", 50.0, "Some mixer", "mixer")
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value=ext)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.HIGH_RISK_SERVICE
    assert v.risk_score >= 60
    assert v.risk_level in (RiskLevel.CAUTION, RiskLevel.DANGEROUS)


@pytest.mark.asyncio
async def test_bitok_sanctions_category_with_soft_level_is_still_dangerous():
    """Bitok умеет отдать категорию «sanctions» с родным уровнем «low».
    Тип и уровень не должны противоречить друг другу в одном отчёте."""
    ext = _bitok("low", 5.0, "OFAC-related wallet", "sanctions")
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value=ext)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.SANCTIONED
    assert v.risk_level == RiskLevel.DANGEROUS      # было UNKNOWN + скор 0
    assert v.risk_score == 100
    assert v.sanction_source == "Bitok"
    assert v.entity_type_ru() == "САНКЦИОННЫЙ (Bitok)"


@pytest.mark.asyncio
async def test_swapster_relabel_gets_service_score_not_wallet_score():
    """Переклеймённая в биржу сущность должна считаться как сервис.
    Раньше тип менялся ПОСЛЕ расчёта, и скор оставался «кошельковым»."""
    addr = VALID_ADDR
    transfers = [
        _usdt("TBybit", addr, 90_000_000, from_tag="Bybit"),
        _usdt(addr, SANCTIONED_ADDR, 10_000_000),
        _usdt(addr, "Tsink", 80_000_000),
    ]
    sw = {
        "available": True, "provider": "Swapster", "pending": False,
        "risk_score": 3.0, "risk_level": "safe",
        "entities": [{"entity": "EXCHANGE LICENSED", "level": "LOW_RISK", "risk_score": 99.0}],
    }
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.ofac.fetch_sanctioned_set",
               new=AsyncMock(return_value={SANCTIONED_ADDR})), \
         patch("core.aggregator.aml_external.check", new=AsyncMock(return_value=sw)):
        v = await check_address(addr, use_cache=False)
    assert v.entity_type == EntityType.EXCHANGE
    assert v.risk_level == RiskLevel.SAFE
    assert v.risk_score <= 10        # правило known_service применилось
    assert v.aml["sanctions_exposure_pct"] > 0   # но экспозиция показана честно


# ---------- Ручные метки: наивысший приоритет ----------

@pytest.mark.asyncio
async def test_local_label_wins_over_external_aml():
    """Свой доверенный адрес можно пометить безопасным: раньше KYT поднимал его
    обратно, потому что _apply_local вызывался ДО внешних AML."""
    from core.providers import local as local_provider

    local_provider.LOCAL_LABELS[VALID_ADDR] = {
        "entity": "Наш горячий кошелёк",
        "entity_type": "labeled",
        "risk_level": "safe",
        "note": "внутренний адрес команды",
    }
    try:
        ext = _bitok("medium", 55.0)
        with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
             patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
             patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value=ext)):
            v = await check_address(VALID_ADDR, use_cache=False)
    finally:
        del local_provider.LOCAL_LABELS[VALID_ADDR]
    assert v.entity == "Наш горячий кошелёк"
    assert v.risk_level == RiskLevel.SAFE      # было caution
    assert v.risk_score <= 10
    assert any("понижен" in f for f in v.risk_flags)   # понижение не молчаливое


# ---------- checked_at / версия правил / возраст кеша ----------

@pytest.mark.asyncio
async def test_verdict_carries_timestamp_and_ruleset(tmp_path, monkeypatch):
    from core import cache
    from core.aggregator import RULESET_VERSION
    monkeypatch.setattr(cache, "CACHE_PATH", tmp_path / "cache.db")
    await cache.init_db()
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)):
        fresh = await check_address(VALID_ADDR, use_cache=True)
        restored = await check_address(VALID_ADDR, use_cache=True)
    assert fresh.checked_at and fresh.checked_at.endswith("+00:00")
    assert fresh.ruleset_version == RULESET_VERSION
    assert fresh.cache_age_seconds is None
    assert restored.cached is True
    assert restored.checked_at == fresh.checked_at      # дата ПРОВЕРКИ, не выдачи
    assert restored.cache_age_seconds is not None and restored.cache_age_seconds >= 0
    assert "checked_at" in fresh.to_dict()


def test_cache_age_handles_missing_and_broken_timestamp():
    from core.aggregator import _cache_age
    assert _cache_age(None) is None
    assert _cache_age("не дата") is None
    assert _cache_age("2020-01-01T00:00:00+00:00") > 0


# ---------- provider_status: сбой источника виден в вердикте ----------

@pytest.mark.asyncio
async def test_provider_failure_is_visible_in_verdict():
    """«GoPlus недоступен» не должно выглядеть как «GoPlus сказал чисто»."""
    from core.providers.base import ProviderError

    async def broken(*a, **kw):
        raise ProviderError("rate limit")

    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=broken), \
         patch("core.aggregator.flow.fetch_transfers", new=broken):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.provider_status["goplus"] == "error"
    assert v.provider_status["flow"] == "error"
    assert v.provider_status["tronscan"] == "ok"
    assert any("НЕПОЛНАЯ" in f for f in v.risk_flags)
    assert v.risk_flags[0].startswith("❗")   # первым, а не в хвосте


@pytest.mark.asyncio
async def test_no_gap_flag_when_all_providers_ok():
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert not any("НЕПОЛНАЯ" in f for f in v.risk_flags)
    assert v.provider_status["goplus"] == "ok"


@pytest.mark.asyncio
async def test_aml_status_distinguishes_not_configured_from_error():
    from core.aggregator import _aml_status
    assert _aml_status({"available": True, "pending": False}) == "ok"
    assert _aml_status({"available": True, "pending": True}) == "pending"
    assert _aml_status({"skipped": True}) == "skipped"
    assert _aml_status({"available": False, "reason": "Bitok не настроен"}) == "not_configured"
    assert _aml_status({"available": False, "reason": "Bitok: HTTP 500"}) == "error"


# ---------- Кеш: round-trip вердикта ----------

@pytest.mark.asyncio
async def test_cache_roundtrip_keeps_every_field(tmp_path, monkeypatch):
    """to_dict() → from_dict() не должен терять поля. Раньше терялся bitok_aml:
    кешированный вердикт отдавал риск 96/dangerous без блока, его объяснявшего."""
    from core import cache
    monkeypatch.setattr(cache, "CACHE_PATH", tmp_path / "cache.db")
    await cache.init_db()

    bitok = {
        "available": True, "provider": "Bitok", "pending": False, "risk_score": 96.0,
        "risk_level": "dangerous", "level_raw": "severe", "entity": "Darknet market",
        "entity_category": "darknet_market", "entity_category_ru": "даркнет-маркет",
        "entities": [],
    }
    patches = {
        "core.aggregator.tronscan.fetch_account": AsyncMock(return_value={}),
        "core.aggregator.goplus.fetch_address_security": AsyncMock(return_value=EMPTY_GP),
        "core.aggregator.aml_bitok.check": AsyncMock(return_value=bitok),
    }
    ctx = [patch(k, new=v) for k, v in patches.items()]
    for c in ctx:
        c.start()
    try:
        fresh = await check_address(VALID_ADDR, use_cache=True)
        restored = await check_address(VALID_ADDR, use_cache=True)
    finally:
        for c in ctx:
            c.stop()

    assert restored.cached is True
    assert restored.bitok_aml == fresh.bitok_aml          # раньше было {}
    assert restored.provider_status == fresh.provider_status
    payload = fresh.to_dict()
    payload.pop("cached")
    again = AddressVerdict.from_dict(payload).to_dict()
    again.pop("cached")
    assert again == payload


def test_from_dict_tolerates_unknown_enum_values():
    """Старый кеш с неизвестным типом не должен ронять восстановление."""
    v = AddressVerdict.from_dict(
        {"address": VALID_ADDR, "entity_type": "quantum_wallet", "risk_level": "extreme"}
    )
    assert v.entity_type == EntityType.UNKNOWN
    assert v.risk_level == RiskLevel.UNKNOWN


def test_to_dict_deduplicates_sources():
    v = AddressVerdict(address=VALID_ADDR, sources=["TronScan", "GoPlus", "TronScan"])
    assert v.to_dict()["sources"] == ["TronScan", "GoPlus"]


# ---------- Балансы: реальные имена полей TronScan ----------

@pytest.mark.parametrize(
    "payload",
    [
        # /api/accountv2 — задокументированное поле
        {"balance": 5_000_000, "withPriceTokens": [
            {"tokenId": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "balance": "1234500000",
             "amount": "1234.5", "tokenDecimal": 6}]},
        # /api/account — легаси, только сырой balance
        {"balance": 5_000_000, "trc20token_balances": [
            {"tokenId": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "balance": "1234500000",
             "tokenDecimal": 6}]},
        # исторический вариант, который читал старый код
        {"balance": 5_000_000, "tokens": [
            {"tokenId": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "amount": "1234.5"}]},
        # snake_case
        {"balance": 5_000_000, "balances": [
            {"token_id": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "balance": "1234500000",
             "token_decimal": 6}]},
    ],
)
def test_extract_balances_known_response_shapes(payload):
    from core.balance import extract_balances
    trx, usdt = extract_balances(payload)
    assert trx == 5.0
    assert abs(usdt - 1234.5) < 0.01


def test_extract_balances_ignores_fake_usdt_contract():
    """Поддельный USDT не должен показываться как баланс USDT."""
    from core.balance import extract_balances
    trx, usdt = extract_balances(
        {"balance": 1_000_000,
         "withPriceTokens": [{"tokenId": FAKE_USDT_CONTRACT, "amount": "999999"}]}
    )
    assert usdt == 0.0


def test_extract_balances_empty_and_garbage():
    from core.balance import extract_balances
    assert extract_balances({}) == (0.0, 0.0)
    assert extract_balances({"balance": "nope", "tokens": "nope"}) == (0.0, 0.0)


# ---------- Блокировка USDT эмитентом (самый жёсткий сигнал для TRC20) ----------

BLACKLISTED = {"blacklisted": True, "source": "contract"}


@pytest.mark.asyncio
async def test_tether_blacklist_overrides_clean_history():
    """Адрес без единой находки, но заблокирован эмитентом: средства неподвижны,
    поэтому вердикт максимальный, а тип — FROZEN, а не «нет меток»."""
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.tether.check", new=AsyncMock(return_value=dict(BLACKLISTED))):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.FROZEN
    assert v.risk_level == RiskLevel.DANGEROUS
    assert v.risk_score == 100
    assert "блэклист" in (v.entity or "").lower()
    assert v.risk_flags[0].startswith("🚫")
    assert any("заморожены" in f for f in v.risk_flags)
    assert "Tether blacklist" in v.sources


@pytest.mark.asyncio
async def test_tether_blacklist_skips_paid_kyt():
    """Второе мнение по заблокированным средствам ничего не добавит — не платим."""
    swapster = AsyncMock(return_value=dict(NO_AML))
    bitok = AsyncMock(return_value=dict(NO_AML))
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.tether.check", new=AsyncMock(return_value=dict(BLACKLISTED))), \
         patch("core.aggregator.aml_external.check", new=swapster), \
         patch("core.aggregator.aml_bitok.check", new=bitok):
        v = await check_address(VALID_ADDR, use_cache=False)
    swapster.assert_not_awaited()
    bitok.assert_not_awaited()
    assert "заблокированы" in v.external_aml.get("reason", "")


@pytest.mark.asyncio
async def test_clean_tether_check_does_not_change_verdict():
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.entity_type == EntityType.UNKNOWN
    assert v.raw_labels["tether"]["blacklisted"] is False
    assert v.provider_status["tether"] == "ok"


@pytest.mark.asyncio
async def test_tether_check_failure_is_reported_not_silent():
    """Недоступность проверки блэклиста не должна выглядеть как «не заблокирован»."""
    from core.providers.base import ProviderError

    async def broken(*a, **kw):
        raise ProviderError("TronGrid недоступен")

    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.tether.check", new=broken):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.provider_status["tether"] == "error"
    assert any("НЕПОЛНАЯ" in f for f in v.risk_flags)
    assert "tether" not in v.raw_labels


# ---------- Признаки, которые TronScan уже присылает в ответе переводов ----------

def _with_token(frm, to, quant, *, level="2", can_show=1, risky=False, token=None):
    t = _tr(frm, to, quant)
    t["tokenInfo"].update({
        "tokenId": token or "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        "tokenAbbr": "USDT",
        "tokenLevel": level,
        "tokenCanShow": can_show,
    })
    if risky:
        t["riskTransaction"] = True
    return t


@pytest.mark.asyncio
async def test_suspicious_token_level_is_flagged():
    """tokenLevel «3»/«4» = подозрительный/небезопасный по оценке TronScan.
    Поле приходило в том же ответе и раньше просто выбрасывалось."""
    transfers = [_with_token("Tx", VALID_ADDR, 1_000_000, level="4", token="TFakeTok" + "0" * 26)]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert any("небезопасные" in f for f in v.risk_flags)
    assert v.aml["risky_tokens"]


@pytest.mark.asyncio
async def test_hidden_token_and_risky_transaction_flags():
    transfers = [
        _with_token("Tx", VALID_ADDR, 1_000_000, can_show=0, token="TSpam" + "0" * 29),
        _with_token("Ty", VALID_ADDR, 2_000_000, risky=True),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert any("скрыты TronScan" in f for f in v.risk_flags)
    assert any("рискованные" in f for f in v.risk_flags)
    assert v.aml["risky_transactions"] == 1


@pytest.mark.asyncio
async def test_risky_counterparty_from_response_meta():
    """normalAddressInfo приходит на уровне ответа — раньше терялся целиком."""
    from core.providers.flow import TransferPage

    page = TransferPage(
        [_with_token("Tbad", VALID_ADDR, 1_000_000)],
        {"normalAddressInfo": {"Tbad": {"risk": True}}, "contractInfo": {}},
    )
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=page)):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert any("Рискованные контрагенты" in f for f in v.risk_flags)
    assert v.aml["risky_counterparties"] == ["Tbad"]


@pytest.mark.asyncio
async def test_plain_list_from_provider_still_works():
    """Мок или старый вызов отдаёт обычный список без .meta — не должно падать."""
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers",
               new=AsyncMock(return_value=[_with_token("Tx", VALID_ADDR, 1_000_000)])):
        v = await check_address(VALID_ADDR, use_cache=False)
    assert v.aml["risky_counterparties"] == []
