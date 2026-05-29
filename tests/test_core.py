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
def _no_flow_by_default():
    """flow-провайдер по умолчанию возвращает пусто — тесты не ходят в сеть.
    Тесту про flow достаточно переопределить этот патч своим внутри `with`."""
    with patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=[])):
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
