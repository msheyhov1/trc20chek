"""Распознавание депозитных кошельков бирж и кастодиальных сервисов.

Жалоба, из-за которой написан файл: депозитники Bybit и Binance показывались
«личными кошельками». Причин было три, и каждая проверяется ниже:
  1. одноразовый депозитный адрес (один приход → один свип) отбрасывался
     требованием «минимум два входящих»;
  2. контрагент без тега TronScan не опознавался вообще, хотя мы уже выучили
     его якорь на прошлой проверке;
  3. сервис, которого TronScan не размечает (CryptoBot, Telegram Wallet),
     нельзя было задать вручную так, чтобы он работал и как контрагент.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from core import aggregator as agg
from core import cluster, labels, services
from core.models import AddressVerdict, EntityType, RiskLevel

A = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USER = "TUser1111111111111111111111111111"
HOT = "TExchangeHot1111111111111111111111"
# Валидные адреса нужны только там, где их проверяет base58check (SERVICE_ADDRESSES).
HOT_VALID = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"
EMPTY_GP = {"code": 1, "result": {"cybercrime": "0", "data_source": "GoPlus"}}


def _tr(frm, to, quant, *, from_tag="", to_tag=""):
    return {
        "from_address": frm, "to_address": to,
        "from_address_tag": {"from_address_tag": from_tag},
        "to_address_tag": {"to_address_tag": to_tag},
        "quant": str(quant), "tokenInfo": {"tokenDecimal": 6},
    }


# ---------- одноразовый депозитный адрес ----------

def test_single_sweep_is_recognised_as_probable_deposit():
    """Так выдаются адреса под разовый депозит: один приход, один свип."""
    transfers = [
        _tr(USER, A, 5_000_000_000),
        _tr(A, HOT, 5_000_000_000, to_tag="Bybit Hot 3"),
    ]
    d = agg._detect_exchange_deposit(transfers, A)
    assert d is not None
    assert d["exchange"] == "Bybit"
    assert d["confidence"] == "medium"
    assert d["hot_wallet"] == HOT


def test_multi_source_funnel_stays_high_confidence():
    transfers = [
        _tr(USER, A, 1_000_000_000),
        _tr("TUser2", A, 2_000_000_000),
        _tr(A, HOT, 3_000_000_000, to_tag="Binance-Hot 4"),
    ]
    d = agg._detect_exchange_deposit(transfers, A)
    assert d["confidence"] == "high"
    assert d["exchange"] == "Binance"
    assert d["in_transfers"] == 2


def test_single_sweep_needs_almost_everything_forwarded():
    """Получил и отправил на биржу только пятую часть — это не свип."""
    transfers = [
        _tr(USER, A, 5_000_000_000),
        _tr(A, HOT, 1_000_000_000, to_tag="Bybit Hot 3"),
    ]
    assert agg._detect_exchange_deposit(transfers, A) is None


def test_single_sweep_needs_full_concentration():
    """Часть оттока ушла мимо биржи — одного прихода для вывода уже мало."""
    transfers = [
        _tr(USER, A, 10_000_000_000),
        _tr(A, HOT, 9_000_000_000, to_tag="Bybit Hot 3"),
        _tr(A, "Tother", 1_000_000_000),
    ]
    assert agg._detect_exchange_deposit(transfers, A) is None


def test_withdrawal_then_send_back_is_not_a_deposit():
    """Вывел с биржи и отправил обратно — личный торговый кошелёк."""
    transfers = [
        _tr(HOT, A, 5_000_000_000, from_tag="Bybit Hot 3"),
        _tr(A, HOT, 5_000_000_000, to_tag="Bybit Hot 3"),
    ]
    assert agg._detect_exchange_deposit(transfers, A) is None


@pytest.mark.asyncio
async def test_probable_deposit_still_gets_paid_kyt_and_risk():
    """Вывод вероятный, поэтому поддавков «известного сервиса» он не получает:
    туннель не срабатывает, риск считается как для обычного адреса. Иначе одна
    отправка на биржу делала бы личный кошелёк «безопасной биржей»."""
    transfers = [
        _tr(USER, A, 5_000_000_000),
        _tr(A, HOT, 5_000_000_000, to_tag="Bybit Hot 3"),
    ]
    aml = {"available": False, "reason": "не настроен"}
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security",
               new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.aml_external.check",
               new=AsyncMock(return_value=dict(aml))) as sw, \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value=dict(aml))):
        v = await agg.check_address(A, use_cache=False)
    assert v.entity_type is EntityType.EXCHANGE
    assert "(вероятно)" in (v.entity or "")
    assert sw.await_count == 1                        # туннель НЕ сработал
    assert v.provider_status["swapster"] != "skipped"
    assert any("одноразовый депозитный адрес" in f for f in v.risk_flags)


@pytest.mark.asyncio
async def test_high_confidence_deposit_is_tunneled_as_before():
    transfers = [
        _tr(USER, A, 1_000_000_000),
        _tr("TUser2", A, 2_000_000_000),
        _tr(A, HOT, 3_000_000_000, to_tag="Bybit Hot 3"),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security",
               new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.aml_external.check", new=AsyncMock()) as sw:
        v = await agg.check_address(A, use_cache=False)
    assert v.entity == "Депозитный кошелёк Bybit"
    assert sw.await_count == 0                        # туннель сработал
    assert v.risk_score == 0


# ---------- контрагент без тега ----------

def test_untagged_counterparty_is_resolved_by_learned_anchor():
    """Тег контрагента в ответе TronScan есть не всегда. Якорь, выученный на
    прошлой проверке, закрывает именно этот пробел."""
    transfers = [
        _tr(USER, A, 1_000_000_000),
        _tr("TUser2", A, 2_000_000_000),
        _tr(A, HOT, 3_000_000_000),          # тега нет
    ]
    assert agg._detect_exchange_deposit(transfers, A) is None
    d = agg._detect_exchange_deposit(transfers, A, {HOT: "Bybit"})
    assert d["exchange"] == "Bybit"
    assert d["confidence"] == "high"


@pytest.mark.asyncio
async def test_anchor_map_reads_learned_hot_wallets(tmp_path, monkeypatch):
    monkeypatch.setattr(cluster, "CLUSTER_PATH", tmp_path / "cluster.db")
    await cluster.init_db()
    await cluster.record("Tsibling1", "Bybit", HOT)
    await cluster.record("Tsibling2", "Bybit", HOT)
    transfers = [_tr(A, HOT, 1_000_000), _tr("Tsomeone", A, 1_000_000)]
    assert await agg._anchor_map(transfers, A) == {HOT: "Bybit"}


@pytest.mark.asyncio
async def test_anchor_map_is_empty_without_knowledge(tmp_path, monkeypatch):
    monkeypatch.setattr(cluster, "CLUSTER_PATH", tmp_path / "cluster.db")
    await cluster.init_db()
    assert await agg._anchor_map([_tr(A, HOT, 1_000_000)], A) == {}
    assert await agg._anchor_map([], A) == {}


@pytest.mark.asyncio
async def test_anchors_for_survives_broken_db(monkeypatch, tmp_path):
    """Кластеризация необязательна: сломанная БД не должна ронять проверку."""
    monkeypatch.setattr(cluster, "CLUSTER_PATH", tmp_path / "нет" / "cluster.db")
    assert await cluster.anchors_for({HOT}) == {}


# ---------- реестр сервисных адресов ----------

def test_service_address_from_env(monkeypatch):
    monkeypatch.setenv("SERVICE_ADDRESSES", f"{HOT_VALID}:CryptoBot (Telegram)")
    services.reload_env()
    try:
        assert services.service_name(HOT_VALID) == "CryptoBot (Telegram)"
        assert services.service_name(A) is None
    finally:
        monkeypatch.delenv("SERVICE_ADDRESSES")
        services.reload_env()


def test_invalid_service_address_is_dropped(monkeypatch):
    """Опечатка в переменной окружения иначе молча не сработала бы никогда."""
    monkeypatch.setenv("SERVICE_ADDRESSES", "НЕадрес:Имя, TR7bad:Имя2")
    services.reload_env()
    try:
        assert services.count() == 0
    finally:
        monkeypatch.delenv("SERVICE_ADDRESSES")
        services.reload_env()


def test_manual_label_makes_address_a_service(monkeypatch):
    """Разметил хот-кошелёк командой /label — и его депозитники начинают
    опознаваться funnel-эвристикой."""
    monkeypatch.setitem(
        labels._cache, HOT, {"entity": "CryptoBot (Telegram)", "entity_type": "exchange"}
    )
    assert services.service_name(HOT) == "CryptoBot (Telegram)"


def test_scam_label_does_not_make_address_a_service(monkeypatch):
    monkeypatch.setitem(labels._cache, HOT, {"entity": "Дрейнер", "entity_type": "scam"})
    assert services.service_name(HOT) is None


def test_deposit_detected_through_service_registry(monkeypatch):
    monkeypatch.setitem(
        labels._cache, HOT, {"entity": "CryptoBot (Telegram)", "entity_type": "exchange"}
    )
    transfers = [
        _tr(USER, A, 1_000_000_000),
        _tr("TUser2", A, 2_000_000_000),
        _tr(A, HOT, 3_000_000_000),          # тега TronScan нет
    ]
    d = agg._detect_exchange_deposit(transfers, A)
    assert d["exchange"] == "CryptoBot (Telegram)"


# ---------- кастодиальные телеграм-сервисы ----------

@pytest.mark.parametrize(
    "tag,expected",
    [
        ("CryptoBot", "CryptoBot (Telegram)"),
        ("Crypto Bot Hot Wallet", "CryptoBot (Telegram)"),
        ("CryptoPay", "CryptoBot (Telegram)"),
        ("Telegram Wallet", "Telegram Wallet"),
        ("wallet.tg", "Telegram Wallet"),
        ("@wallet", "Telegram Wallet"),
        ("xRocket", "xRocket (Telegram)"),
    ],
)
def test_custodial_tags_are_recognised(tag, expected):
    assert agg._normalize_exchange(tag) == expected


def test_custodial_wallet_gets_an_explanatory_flag():
    v = AddressVerdict(address=A)
    agg._apply_tronscan({"address": A, "publicTag": "CryptoBot"}, v)
    assert v.entity == "CryptoBot (Telegram)"
    assert v.entity_type is EntityType.EXCHANGE
    assert any("кастодиальный сервис" in f for f in v.risk_flags)


def test_custodial_note_added_for_linked_personal_wallet():
    """Пользователь CryptoBot — не сам сервис, но знать, куда ушли деньги,
    ему тоже нужно."""
    v = AddressVerdict(address=A)
    agg._apply_flow([_tr(A, HOT, 1_000_000, to_tag="CryptoBot")], v)
    assert v.entity_type is EntityType.WALLET
    assert "CryptoBot (Telegram)" in (v.entity or "")
    assert any("кастодиальный сервис" in f for f in v.risk_flags)


def test_custodial_names_do_not_collide_with_exchanges():
    """Одно имя в двух словарях — и _normalize_exchange вернёт не тот сервис."""
    dicts = {
        "exchange": agg.EXCHANGE_KEYWORDS,
        "sanctioned": agg.SANCTIONED_EXCHANGES,
        "custodial": agg.CUSTODIAL_SERVICES,
    }
    for a, da in dicts.items():
        for b, db in dicts.items():
            if a < b:
                assert not set(da) & set(db), f"{a} ∩ {b}: ключи"
                assert not set(da.values()) & set(db.values()), f"{a} ∩ {b}: имена"


def test_sanctioned_exchange_still_wins_over_custodial():
    """Порядок словарей в _ALL_EXCHANGES не должен маскировать санкции."""
    assert agg._normalize_exchange("Garantex Hot") == "Garantex"
    assert agg._normalize_exchange("Nobitex 1") == "Nobitex"


# ---------- кластер пополняется и вероятными депозитниками ----------

@pytest.mark.asyncio
async def test_probable_deposit_is_recorded_in_cluster(tmp_path, monkeypatch):
    monkeypatch.setattr(cluster, "CLUSTER_PATH", tmp_path / "cluster.db")
    await cluster.init_db()
    v = AddressVerdict(address=A)
    v.raw_labels["flow"] = {
        "deposit_pattern": {
            "exchange": "Bybit", "hot_wallet": HOT,
            "confidence": "medium", "sanctioned": False,
        }
    }
    await agg._apply_cluster(v)
    assert await cluster.anchors_for({HOT}) == {HOT: "Bybit"}


@pytest.mark.asyncio
async def test_sanctioned_exchange_deposit_is_not_softened_by_confidence():
    """Санкционная биржа бьёт всё: «вероятно» не должно понижать вердикт."""
    transfers = [
        _tr(USER, A, 5_000_000_000),
        _tr(A, HOT, 5_000_000_000, to_tag="Garantex Hot"),
    ]
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security",
               new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.aml_external.check", new=AsyncMock(return_value={})), \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value={})):
        v = await agg.check_address(A, use_cache=False)
    assert v.entity_type is EntityType.SANCTIONED
    assert v.risk_score == 100
    assert v.risk_level is RiskLevel.DANGEROUS
