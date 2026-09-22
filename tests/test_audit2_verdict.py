"""Аудит 2: дефекты, при которых вердикт уходил в «безопасную» сторону.

Каждый тест воспроизводит конкретный сценарий, найденный при аудите, — до
исправления он давал «нет данных · 0» или «безопасно» там, где риск известен.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from core import aggregator as agg
from core import labels
from core.models import AddressVerdict, EntityType, RiskLevel
from core.providers.base import ProviderError

A = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
OFAC = "TA3rH2A7iHnm6pKH8gr9cK1EZnShnmZdFg"
USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
GP = {"code": 1, "result": {"cybercrime": "0", "data_source": "GoPlus"}}
NO_AML = {"available": False, "reason": "не настроен"}


def tr(frm, to, usdt, *, from_tag="", to_tag=""):
    return {"from_address": frm, "to_address": to,
            "from_address_tag": {"from_address_tag": from_tag},
            "to_address_tag": {"to_address_tag": to_tag},
            "quant": str(int(usdt * 10**6)),
            "tokenInfo": {"tokenDecimal": 6, "tokenId": USDT}}


def _patches(**over):
    p = {
        "core.aggregator.tronscan.fetch_account": AsyncMock(return_value={}),
        "core.aggregator.goplus.fetch_address_security": AsyncMock(return_value=GP),
        "core.aggregator.flow.fetch_transfers": AsyncMock(return_value=[]),
        "core.aggregator.ofac.fetch_sanctioned_set": AsyncMock(return_value={OFAC}),
        "core.aggregator.tether.check":
            AsyncMock(return_value={"blacklisted": False, "source": "contract"}),
        "core.aggregator.aml_external.check": AsyncMock(return_value=dict(NO_AML)),
        "core.aggregator.aml_bitok.check": AsyncMock(return_value=dict(NO_AML)),
        "core.aggregator.history.record": AsyncMock(),
        "core.aggregator.history.previous": AsyncMock(return_value=None),
    }
    p.update(over)
    return p


async def _check(addr, **over):
    ctx = [patch(k, new=v) for k, v in _patches(**over).items()]
    for c in ctx:
        c.start()
    try:
        return await agg.check_address(addr, use_cache=False)
    finally:
        for c in ctx:
            c.stop()


# ---------- 1. обрыв по дедлайну ----------

async def test_sanctioned_address_survives_budget_timeout(monkeypatch):
    """Санкционный адрес, на котором медленно отвечал Bitok, выходил
    «НЕТ ДАННЫХ · 0/100»: риск считается в самом конце, и при обрыве
    расчёт не выполнялся вовсе."""
    monkeypatch.setattr(agg, "CHECK_BUDGET_SECONDS", 0.2)

    async def hang(addr):
        await asyncio.sleep(5)

    v = await _check(OFAC, **{"core.aggregator.aml_bitok.check": hang})
    assert v.entity_type is EntityType.SANCTIONED
    assert v.risk_level is RiskLevel.DANGEROUS and v.risk_score == 100
    assert any("прервана по таймауту" in f for f in v.risk_flags)
    assert v.provider_status["bitok"] == "timeout"


async def test_finished_kyt_is_kept_when_the_other_one_hangs(monkeypatch):
    """Swapster готов за секунды — его результат не должен пропадать из-за
    медленного Bitok."""
    monkeypatch.setattr(agg, "CHECK_BUDGET_SECONDS", 0.2)
    sw = {"available": True, "provider": "Swapster", "pending": False,
          "risk_score": 80.0, "risk_level": "dangerous", "entities": []}

    async def hang(addr):
        await asyncio.sleep(5)

    v = await _check(A, **{"core.aggregator.aml_external.check": AsyncMock(return_value=sw),
                           "core.aggregator.aml_bitok.check": hang})
    assert v.provider_status["swapster"] == "ok"
    assert v.risk_level is RiskLevel.DANGEROUS and v.risk_score == 80


# ---------- 2. 2-й хоп при частичном сбое ----------

async def test_hop2_keeps_results_when_one_intermediary_fails():
    """Один 429 из двенадцати параллельных запросов выбрасывал весь 2-й хоп —
    вместе с найденным «грязным» посредником."""
    mids = [f"TMid{i:030d}"[:34] for i in range(4)]
    by = {A: [tr(m, A, 100) for m in mids], mids[0]: [tr(mids[0], OFAC, 100)]}

    async def ft(addr, client, pages=None):
        if addr == mids[3]:
            raise ProviderError("429 Too Many Requests")
        return by.get(addr, [tr(addr, "Tclean", 50)])

    v = await _check(A, **{"core.aggregator.flow.fetch_transfers": ft})
    assert v.provider_status["hop2"] == "partial"
    assert v.aml["indirect_sanctions_pct"] == 25.0
    assert v.aml["hop2_failed"] == 1
    assert any("2-й хоп неполный" in f for f in v.risk_flags)


async def test_hop2_all_failed_is_an_error():
    mids = [f"TMid{i:030d}"[:34] for i in range(2)]

    async def ft(addr, client, pages=None):
        if addr == A:
            return [tr(m, A, 100) for m in mids]
        raise ProviderError("down")

    v = await _check(A, **{"core.aggregator.flow.fetch_transfers": ft})
    assert v.provider_status["hop2"] == "error"
    assert any("НЕПОЛНАЯ" in f for f in v.risk_flags)


# ---------- 3. порядок флагов ----------

def test_flags_are_ordered_by_severity():
    v = AddressVerdict(address=A)
    v.risk_flags = [
        "ℹ️ справка", "⚠️ предупреждение", "🆕 свежий", "⛔️ Bitok: высокий риск",
        "Экспозиция к санкционным адресам: 5%", "❗ Проверка НЕПОЛНАЯ",
    ]
    agg._order_flags(v)
    assert v.risk_flags[0].startswith("❗")
    assert v.risk_flags[1].startswith("⛔️")
    assert v.risk_flags[2].startswith("Экспозиция")
    assert v.risk_flags[-1] == "🆕 свежий" or v.risk_flags[-1] == "ℹ️ справка"


def test_bot_never_hides_decisive_flags():
    """Бот показывает восемь флагов — но решающие все, сколько бы их ни было."""
    from bot.main import format_verdict
    v = AddressVerdict(address=A)
    v.risk_flags = [f"⛔️ опасность {i}" for i in range(10)] + ["ℹ️ справка"]
    text = format_verdict(v)
    assert all(f"опасность {i}" in text for i in range(10))
    assert "…и ещё 1" in text


def test_unknown_flag_prefix_gets_middle_rank():
    """Новая находка без эмодзи не должна утонуть ниже справки."""
    assert agg.flag_rank("Что-то новое") == 2
    assert agg.flag_rank("ℹ️ справка") == 3


def test_critical_goplus_flag_is_marked_as_danger():
    v = AddressVerdict(address=A)
    agg._apply_goplus({"result": {"phishing_activities": "1", "mixer": "1"}}, v)
    assert "⛔️ GoPlus: phishing activities" in v.risk_flags
    assert "GoPlus: mixer" in v.risk_flags


# ---------- 5. Swapster не понижает вердикт ----------

SW_EXCHANGE = {"available": True, "provider": "Swapster", "pending": False,
               "risk_score": 5.0, "risk_level": "safe",
               "entities": [{"entity": "EXCHANGE", "level": "LOW_RISK", "risk_score": 95.0}]}
TRANSIT = [tr("Tu1", A, 1000), tr("Tu2", A, 1000), tr(A, "Tx", 1990)]


async def test_swapster_does_not_relabel_grey_tagged_address():
    """Серая метка TronScan + транзит + «EXCHANGE 95%» давали «биржа ·
    безопасно · 0»: внешний сервис понижал вердикт."""
    v = await _check(A, **{
        "core.aggregator.tronscan.fetch_account":
            AsyncMock(return_value={"address": A, "greyTag": "Suspicious activity"}),
        "core.aggregator.flow.fetch_transfers": AsyncMock(return_value=TRANSIT),
        "core.aggregator.aml_external.check": AsyncMock(return_value=SW_EXCHANGE),
    })
    assert v.entity_type is EntityType.LABELED
    assert v.risk_level is RiskLevel.CAUTION


@pytest.mark.parametrize("name,level", [
    ("HIGH RISK EXCHANGE", "LOW_RISK"),
    ("EXCHANGE P2P", "LOW_RISK"),
    ("SANCTIONED EXCHANGE", "LOW_RISK"),
    ("EXCHANGE", "HIGH_RISK"),
])
async def test_swapster_risky_exchange_category_is_not_a_safe_exchange(name, level):
    sw = dict(SW_EXCHANGE, entities=[{"entity": name, "level": level, "risk_score": 95.0}])
    v = await _check(A, **{
        "core.aggregator.flow.fetch_transfers": AsyncMock(return_value=TRANSIT),
        "core.aggregator.aml_external.check": AsyncMock(return_value=sw),
    })
    assert v.entity_type is not EntityType.EXCHANGE


async def test_swapster_does_not_relabel_address_with_own_risk_signals():
    v = await _check(A, **{
        "core.aggregator.goplus.fetch_address_security":
            AsyncMock(return_value={"code": 1, "result": {"mixer": "1"}}),
        "core.aggregator.flow.fetch_transfers": AsyncMock(return_value=TRANSIT),
        "core.aggregator.aml_external.check": AsyncMock(return_value=SW_EXCHANGE),
    })
    assert v.entity_type is not EntityType.EXCHANGE


# ---------- 6. жёсткие факты и ручные метки ----------

async def test_safe_label_does_not_whitewash_ofac(monkeypatch):
    """Метка «safe» давала адресу из OFAC «безопасно · 10», а ставить метки
    может любой пользователь из белого списка."""
    monkeypatch.setitem(labels._cache, OFAC,
                        {"entity": "наш партнёр", "entity_type": "labeled", "risk_level": "safe"})
    v = await _check(OFAC)
    assert v.entity_type is EntityType.SANCTIONED
    assert v.risk_level is RiskLevel.DANGEROUS and v.risk_score == 100
    assert any("«наш партнёр» не применена" in f for f in v.risk_flags)


async def test_safe_label_does_not_whitewash_tether_blacklist(monkeypatch):
    monkeypatch.setitem(labels._cache, A,
                        {"entity": "свой", "entity_type": "labeled", "risk_level": "safe"})
    v = await _check(A, **{"core.aggregator.tether.check":
                           AsyncMock(return_value={"blacklisted": True, "source": "contract"})})
    assert v.entity_type is EntityType.FROZEN
    assert v.risk_level is RiskLevel.DANGEROUS


async def test_label_can_still_override_an_opinion(monkeypatch):
    """Мнение платного KYT метка переопределить может — это не факт."""
    monkeypatch.setitem(labels._cache, A,
                        {"entity": "наш кошелёк", "entity_type": "labeled", "risk_level": "safe"})
    bitok = {"available": True, "provider": "Bitok", "pending": False,
             "risk_score": 55.0, "risk_level": "caution", "entities": []}
    v = await _check(A, **{"core.aggregator.aml_bitok.check": AsyncMock(return_value=bitok)})
    assert v.risk_level is RiskLevel.SAFE
    assert v.entity == "наш кошелёк"


async def test_deposit_into_ofac_address_labelled_as_exchange_is_sanctioned(monkeypatch):
    """Адрес, пересылающий всё на OFAC-адрес с меткой «биржа», получал
    «депозитный кошелёк · безопасно · 0» при 50 % санкционного объёма."""
    monkeypatch.setitem(labels._cache, OFAC, {"entity": "SomeExchange", "entity_type": "exchange"})
    funnel = [tr("Tu1", A, 1000), tr("Tu2", A, 1000), tr(A, OFAC, 2000)]
    v = await _check(A, **{"core.aggregator.flow.fetch_transfers": AsyncMock(return_value=funnel)})
    assert v.entity_type is EntityType.SANCTIONED
    assert v.sanction_source == "OFAC SDN"
    assert v.risk_score == 100
    assert any("адрес из санкционного списка OFAC" in f for f in v.risk_flags)


# ---------- GoPlus: поля-счётчики ----------

def test_goplus_count_fields_are_raised():
    """Адрес с ОДНИМ вредоносным контрактом помечался, а с тремя — нет:
    срабатывало только значение «1»."""
    v = AddressVerdict(address=A)
    agg._apply_goplus({"result": {"number_of_malicious_contracts_created": "3"}}, v)
    assert v.risk_flags == ["GoPlus: number of malicious contracts created (3)"]
    zero = AddressVerdict(address=A)
    agg._apply_goplus({"result": {"number_of_malicious_contracts_created": "0"}}, zero)
    assert zero.risk_flags == []


# ---------- кеш не хранит неполные вердикты ----------

async def test_degraded_verdict_is_not_cached(monkeypatch):
    put = AsyncMock()
    monkeypatch.setattr(agg.cache, "get", AsyncMock(return_value=None))
    monkeypatch.setattr(agg.cache, "put", put)
    ctx = [patch(k, new=v) for k, v in _patches(**{
        "core.aggregator.tronscan.fetch_account":
            AsyncMock(side_effect=ProviderError("down")),
    }).items()]
    for c in ctx:
        c.start()
    try:
        v = await agg.check_address(A, use_cache=True)
    finally:
        for c in ctx:
            c.stop()
    assert v.is_degraded()
    put.assert_not_awaited()


async def test_degraded_check_does_not_claim_verdict_change(monkeypatch):
    """«Вердикт изменился» при неполной проверке читается как смена риска,
    хотя это сбой источника."""
    prev = {"risk_level": "dangerous", "risk_score": 100}
    v = await _check(A, **{
        "core.aggregator.history.previous": AsyncMock(return_value=prev),
        "core.aggregator.tronscan.fetch_account":
            AsyncMock(side_effect=ProviderError("down")),
    })
    assert not any("Вердикт изменился" in f for f in v.risk_flags)
