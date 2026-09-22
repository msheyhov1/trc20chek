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


# ---------- «вероятно» не выдаётся за факт ----------

@pytest.mark.asyncio
async def test_probable_deposit_does_not_claim_safe():
    """«Нет данных» честнее, чем «безопасно», когда вывод держится на одном
    переводе. Уверенный депозитник биржи — другое дело, он безопасен."""
    transfers = [
        _tr(USER, A, 5_000_000_000),
        _tr(A, HOT, 5_000_000_000, to_tag="Bybit Hot 3"),
    ]
    aml = {"available": False, "reason": "не настроен"}
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security",
               new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=transfers)), \
         patch("core.aggregator.aml_external.check", new=AsyncMock(return_value=dict(aml))), \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock(return_value=dict(aml))):
        v = await agg.check_address(A, use_cache=False)
    assert v.risk_level is RiskLevel.UNKNOWN
    assert v.risk_score == 0


def test_high_confidence_deposit_is_marked_safe():
    v = AddressVerdict(address=A)
    agg._apply_flow([
        _tr(USER, A, 1_000_000_000),
        _tr("TUser2", A, 2_000_000_000),
        _tr(A, HOT, 3_000_000_000, to_tag="Bybit Hot 3"),
    ], v)
    assert v.risk_level is RiskLevel.SAFE


# ---------- накопительная база не подменяет измерение догадкой ----------

async def _record(exchange="Bybit", **over):
    args = {"address": "Tx", "hot_wallet": HOT, "confidence": "high"}
    args.update(over)
    await cluster.record(args["address"], exchange, args["hot_wallet"],
                         confidence=args["confidence"])


@pytest.mark.asyncio
async def test_probable_deposits_do_not_inflate_sibling_counter(tmp_path, monkeypatch):
    """Счётчик «ещё N родственных депозитников» — самый сильный аргумент в
    отчёте. Догадки в него попадать не должны, а якорь учится всё равно."""
    monkeypatch.setattr(cluster, "CLUSTER_PATH", tmp_path / "cluster.db")
    await cluster.init_db()
    await _record(address="Tsure1", confidence="high")
    await _record(address="Tmaybe1", confidence="medium")
    await _record(address="Tmaybe2", confidence="medium")

    info = await cluster.cluster_info("Bybit", HOT, exclude=A)
    assert info["siblings_on_anchor"] == 1
    assert info["known_deposits_exchange"] == 1
    # якорь выучен по всем записям: этот факт взят из тега, а не из догадки
    assert await cluster.anchors_for({HOT}) == {HOT: "Bybit"}


@pytest.mark.asyncio
async def test_cluster_db_from_older_version_is_migrated(tmp_path, monkeypatch):
    """Том с базой на Railway переживает редеплой, поэтому колонка confidence
    добавляется к УЖЕ существующей таблице."""
    import aiosqlite
    path = tmp_path / "cluster.db"
    monkeypatch.setattr(cluster, "CLUSTER_PATH", path)
    async with aiosqlite.connect(path) as db:
        await db.execute(
            "CREATE TABLE deposit_cluster (address TEXT PRIMARY KEY, exchange TEXT "
            "NOT NULL, hot_wallet TEXT, sanctioned INTEGER DEFAULT 0, "
            "first_seen REAL, last_seen REAL)"
        )
        await db.execute(
            "INSERT INTO deposit_cluster VALUES ('Told', 'Bybit', ?, 0, 1.0, 1.0)", (HOT,)
        )
        await db.commit()

    await cluster.init_db()          # миграция
    await cluster.init_db()          # повторный старт не должен падать
    await _record(address="Tnew", confidence="high")
    info = await cluster.cluster_info("Bybit", HOT, exclude=A)
    # старая запись получает confidence='high' по DEFAULT и остаётся в счёте
    assert info["siblings_on_anchor"] == 2


# ---------- направления переводов ----------

def test_exchange_links_directions():
    """«Депозиты» — адрес ОТПРАВИЛ на биржу, «выводы» — ПОЛУЧИЛ с неё.
    Перепутать их означает поменять местами «заводил» и «выводил»."""
    v = AddressVerdict(address=A)
    agg._apply_flow([
        _tr("Tbnc", A, 600_000_000, from_tag="Binance-Hot 4"),   # получил с Binance
        _tr(A, "Tbyb", 1_000_000_000, to_tag="Bybit Hot 3"),     # отправил на Bybit
    ], v)
    links = {e["name"]: e for e in v.exchange_links}
    assert (links["Binance"]["deposits"], links["Binance"]["withdrawals"]) == (0, 1)
    assert (links["Bybit"]["deposits"], links["Bybit"]["withdrawals"]) == (1, 0)


def test_sanctions_exposure_direction_split():
    """Получить от санкционного адреса и отправить на него — разные обвинения,
    и в отчёте они идут раздельно (↓получено ↑отправлено)."""
    sanctioned = "TBADaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    transfers = [
        _tr(sanctioned, A, 100_000_000),        # получил 100
        _tr(A, sanctioned, 300_000_000),        # отправил 300
        _tr(A, "Tbyb", 1_600_000_000, to_tag="Bybit Hot 3"),
    ]
    v = AddressVerdict(address=A)
    agg._compute_aml(v, transfers, {sanctioned})
    assert v.aml["sanctions_exposure_pct"] == 20.0      # 400 из 2000
    assert v.aml["sanctions_received_pct"] == 5.0       # 100 из 2000
    assert v.aml["sanctions_sent_pct"] == 15.0          # 300 из 2000
    assert v.aml["exchange_exposure_pct"] == 80.0


def test_counterparty_volume_split_by_direction():
    sanctioned = "TBADaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    total, per_cp = agg._parse_transfers(A, [
        _tr(sanctioned, A, 100_000_000),
        _tr(A, sanctioned, 300_000_000),
    ], {sanctioned})
    d = per_cp[sanctioned]
    assert (d["volume_in"], d["volume_out"], d["volume"]) == (100.0, 300.0, 400.0)
    assert total == 400.0


# ---------- адрес без единой операции ----------

def _untouched_verdict(**over):
    v = AddressVerdict(address=A)
    v.raw_labels["profile"] = {"tx_in": 0, "tx_out": 0}
    status = {"tronscan": "ok", "flow": "ok"}
    status.update(over.pop("status", {}))
    return v, status


def test_untouched_address_is_recognised():
    v, status = _untouched_verdict()
    assert agg._is_untouched(v, [], status) is True


def test_provider_failure_is_not_an_empty_address():
    """«Источник не ответил» не должно превращаться в «адрес пустой» — это
    ровно та подмена, против которой заведён provider_status."""
    for broken in ("tronscan", "flow"):
        v, status = _untouched_verdict()
        status[broken] = "error"
        assert agg._is_untouched(v, [], status) is False


def test_address_with_history_is_not_empty():
    v, status = _untouched_verdict()
    v.raw_labels["profile"] = {"tx_in": 3, "tx_out": 0}
    assert agg._is_untouched(v, [], status) is False


def test_trx_only_activity_is_not_empty():
    """Счётчики TronScan показывают активность, которой нет в TRC20-переводах
    (например, только TRX). Граф есть — значит адрес не пустой."""
    v, status = _untouched_verdict()
    v.raw_labels["profile"] = {"tx_in": 0, "tx_out": 2}
    assert agg._is_untouched(v, [], status) is False


def test_transfers_without_counters_are_not_empty():
    v, status = _untouched_verdict()
    assert agg._is_untouched(v, [_tr(USER, A, 1_000_000)], status) is False


def test_missing_counters_are_not_treated_as_empty():
    """Поля в ответе нет — значит мы не знаем, а не «операций не было»."""
    v = AddressVerdict(address=A)
    assert agg._is_untouched(v, [], {"tronscan": "ok", "flow": "ok"}) is False


def test_labelled_address_is_not_empty():
    v, status = _untouched_verdict()
    v.entity = "Binance"
    v.entity_type = EntityType.EXCHANGE
    assert agg._is_untouched(v, [], status) is False


@pytest.mark.asyncio
async def test_empty_address_does_not_spend_paid_kyt():
    """Платные KYT считают граф транзакций. У адреса без единой операции графа
    нет, и «0% чисто» от них — не находка, а стоимость запроса."""
    ts = {"address": A, "transactions_in": 0, "transactions_out": 0}
    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value=ts)), \
         patch("core.aggregator.goplus.fetch_address_security",
               new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=[])), \
         patch("core.aggregator.aml_external.check", new=AsyncMock()) as sw, \
         patch("core.aggregator.aml_bitok.check", new=AsyncMock()) as bt:
        v = await agg.check_address(A, use_cache=False)
    assert sw.await_count == 0 and bt.await_count == 0
    assert v.provider_status["swapster"] == "skipped"
    assert any("Адрес пустой" in f for f in v.risk_flags)
    assert "нет ни одной операции" in v.external_aml["reason"]


@pytest.mark.asyncio
async def test_unreachable_tronscan_still_asks_paid_kyt():
    """Если TronScan не ответил, адрес не «пустой», а непроверенный —
    отказываться от второго мнения тут как раз нельзя."""
    from core.providers.base import ProviderError
    with patch("core.aggregator.tronscan.fetch_account",
               new=AsyncMock(side_effect=ProviderError("нет связи"))), \
         patch("core.aggregator.goplus.fetch_address_security",
               new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=[])), \
         patch("core.aggregator.aml_external.check",
               new=AsyncMock(return_value={"available": False, "reason": "не настроен"})) as sw, \
         patch("core.aggregator.aml_bitok.check",
               new=AsyncMock(return_value={"available": False, "reason": "не настроен"})):
        v = await agg.check_address(A, use_cache=False)
    assert sw.await_count == 1
    assert not any("Адрес пустой" in f for f in v.risk_flags)
    assert any("НЕПОЛНАЯ" in f for f in v.risk_flags)


def test_cryptopay_is_not_cryptobot():
    """Cryptopay (cryptopay.me) — отдельная компания. Ключ «cryptopay»
    приписывал её тег телеграм-боту CryptoBot."""
    assert agg._normalize_exchange("Cryptopay") is None
    assert agg._normalize_exchange("Crypto Pay Hot") is None


# ---------- теги-подделки под биржу ----------

@pytest.mark.parametrize(
    "tag", ["Fake Binance", "Binance Phishing", "Scam_Bybit", "OKX Impersonator",
            "Fake CryptoBot", "Bybit drainer"],
)
def test_impostor_tag_is_not_the_exchange(tag):
    """Матчинг биржи — по вхождению подстроки, и «Fake Binance» раньше был
    самим Binance: «биржа · безопасно · 0» и отключённые платные KYT."""
    assert agg._normalize_exchange(tag) is None


def test_impostor_tag_on_address_itself_is_scam():
    v = AddressVerdict(address=A)
    agg._apply_tronscan({"address": A, "publicTag": "Fake Binance Support"}, v)
    assert v.entity_type is EntityType.SCAM
    assert v.risk_level is RiskLevel.DANGEROUS
    assert any("выдаёт себя за Binance" in f for f in v.risk_flags)


def test_impostor_counterparty_is_not_an_exchange_link():
    """Контрагент с тегом-подделкой не должен давать «связь с Binance» и
    засчитываться в биржевой объём."""
    v = AddressVerdict(address=A)
    agg._apply_flow([_tr(A, HOT, 1_000_000, to_tag="Fake Binance")], v)
    assert v.exchange_links == []


def test_real_exchange_tags_still_work():
    for tag, name in (("Binance-Hot 4", "Binance"), ("Bybit Hot 3", "Bybit"),
                      ("Garantex", "Garantex"), ("Telegram Wallet", "Telegram Wallet")):
        assert agg._normalize_exchange(tag) == name
