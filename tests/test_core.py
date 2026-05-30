"""Тесты ядра без внешних запросов — провайдеры подменяются моками."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from core.aggregator import check_address
from core.models import EntityType, RiskLevel, is_valid_trc20_address


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


@pytest.fixture(autouse=True)
def _no_network_by_default():
    """flow и OFAC по умолчанию пустые — тесты не ходят в сеть.
    Конкретный тест переопределяет нужный патч своим внутри `with`."""
    with patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=[])), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())):
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
