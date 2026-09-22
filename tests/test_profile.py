"""Профиль адреса из ответа TronScan: возраст, жалобы, приход/расход.

Все эти поля приходят в том же ответе `/api/account`, что и метки, и раньше
отбрасывались. Дополнительных запросов не делается — бюджет проверки не трогаем.
"""
from __future__ import annotations

import time

from core import aggregator as agg
from core.models import AddressVerdict, EntityType, RiskLevel

A = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def _apply(**fields):
    v = AddressVerdict(address=A)
    agg._apply_tronscan({"address": A, **fields}, v)
    return v


def _ms_days_ago(days: float) -> int:
    return int((time.time() - days * 86400) * 1000)


# ---------- возраст ----------

def test_age_is_computed_from_date_created():
    v = _apply(date_created=_ms_days_ago(400))
    p = v.raw_labels["profile"]
    assert 399 <= p["age_days"] <= 401
    assert p["created_at"].startswith("20")


def test_fresh_address_is_flagged():
    v = _apply(date_created=_ms_days_ago(3))
    assert any("создан 3 дн. назад" in f for f in v.risk_flags)


def test_old_address_is_not_flagged():
    v = _apply(date_created=_ms_days_ago(900))
    assert not any("создан" in f for f in v.risk_flags)


def test_seconds_timestamp_is_understood():
    """Зеркала API отдают секунды. Различаем по порядку величины, иначе
    возраст адреса получался бы в тысячах лет."""
    v = _apply(date_created=int(time.time() - 10 * 86400))
    assert 9 <= v.raw_labels["profile"]["age_days"] <= 11


def test_missing_or_broken_date_is_ignored():
    assert "profile" not in _apply().raw_labels
    assert "age_days" not in _apply(date_created="вчера").raw_labels.get("profile", {})
    assert "age_days" not in _apply(date_created=0).raw_labels.get("profile", {})


# ---------- профиль не теряется на ветках ----------

def test_profile_is_collected_for_exchange_too():
    """У _apply_tronscan каждая ветка делает return. Если собирать профиль
    после ветвлений, для биржи, контракта и скама его бы не было."""
    v = _apply(publicTag="Binance-Hot 4", date_created=_ms_days_ago(500))
    assert v.entity_type is EntityType.EXCHANGE
    assert v.raw_labels["profile"]["age_days"] > 100


def test_profile_is_collected_for_red_tag():
    v = _apply(redTag="Fake Phishing", date_created=_ms_days_ago(2))
    assert v.entity_type is EntityType.SCAM
    assert v.raw_labels["profile"]["age_days"] < 5


# ---------- приход/расход ----------

def _apply_with_flow(seen_out, **fields):
    """Профиль вместе с направлениями, разобранными по TRC20-переводам."""
    v = AddressVerdict(address=A)
    v.raw_labels["trc20_seen"] = {"in": 5, "out": seen_out}
    agg._apply_tronscan({"address": A, **fields}, v)
    return v


def test_receive_only_address_is_flagged():
    v = _apply_with_flow(0, transactions_in=42, transactions_out=0)
    assert v.raw_labels["profile"] == {"tx_in": 42, "tx_out": 0}
    assert any("Только приём" in f for f in v.risk_flags)


def test_receive_only_needs_agreement_with_transfer_history():
    """Счётчики TronScan считают ТРАНЗАКЦИИ, и попадают ли в них TRC20 —
    по документации не видно (in+out там не сходится с transactions). Если
    в разобранной истории исходящие переводы есть, утверждать «средства ни
    разу не уходили» нельзя, даже когда счётчик показывает ноль."""
    v = _apply_with_flow(3, transactions_in=42, transactions_out=0)
    assert not any("Только приём" in f for f in v.risk_flags)


def test_receive_only_is_silent_without_transfer_data():
    """Переводы не загрузились — второго источника нет, вывод не делаем."""
    v = _apply(transactions_in=42, transactions_out=0)
    assert v.raw_labels["profile"] == {"tx_in": 42, "tx_out": 0}
    assert not any("Только приём" in f for f in v.risk_flags)


def test_receive_only_needs_enough_transfers():
    """Одна входящая транзакция и ноль исходящих — это просто новый адрес."""
    v = _apply_with_flow(0, transactions_in=1, transactions_out=0)
    assert not any("Только приём" in f for f in v.risk_flags)


def test_normal_address_is_not_flagged():
    v = _apply_with_flow(4, transactions_in=42, transactions_out=17)
    assert not any("Только приём" in f for f in v.risk_flags)


def test_seen_directions_counts_both_ways():
    transfers = [
        {"from_address": "Tx", "to_address": A},
        {"from_address": "Ty", "to_address": A},
        {"from_address": A, "to_address": "Tz"},
        {"from_address": "Tq", "to_address": "Tw"},   # чужой перевод в выдаче
    ]
    assert agg._seen_directions(transfers, A) == {"in": 2, "out": 1}
    assert agg._seen_directions([], A) == {"in": 0, "out": 0}


# ---------- жалобы пользователей ----------

def test_feedback_risk_is_flagged():
    v = _apply(feedbackRisk=True)
    assert v.raw_labels["profile"]["feedback_risk"] is True
    assert any("жалобы пользователей" in f for f in v.risk_flags)


def test_feedback_risk_raises_score_for_unknown_wallet():
    v = _apply(feedbackRisk=True)
    agg._compute_aml(v, [], set())
    assert v.risk_score >= agg.FEEDBACK_RISK_SCORE
    assert v.risk_level is RiskLevel.CAUTION


def test_feedback_risk_does_not_touch_exchanges():
    """На биржи жалуются постоянно: репорт там про спор с поддержкой, а не про
    природу адреса. Иначе Binance получал бы «осторожно»."""
    v = _apply(publicTag="Binance-Hot 4", feedbackRisk=True)
    agg._compute_aml(v, [], set())
    assert v.entity_type is EntityType.EXCHANGE
    assert v.risk_score == 0
    assert v.risk_level is RiskLevel.SAFE


def test_feedback_risk_never_lowers_an_existing_score():
    v = _apply(greyTag="Подозрительный", feedbackRisk=True)
    agg._compute_aml(v, [], set())
    before = v.risk_score
    assert before >= agg.FEEDBACK_RISK_SCORE


# ---------- рендер ----------

def test_bot_renders_profile_line():
    from bot.main import _profile_line
    v = AddressVerdict(address=A)
    v.raw_labels["profile"] = {"age_days": 12.4, "tx_in": 1234, "tx_out": 2}
    line = _profile_line(v)
    assert "возраст 12 дн." in line
    assert "транзакций ↓1 234 ↑2" in line


def test_bot_profile_line_empty_without_data():
    from bot.main import _profile_line
    assert _profile_line(AddressVerdict(address=A)) == ""


def test_bot_renders_years_for_old_address():
    from bot.main import _profile_line
    v = AddressVerdict(address=A)
    v.raw_labels["profile"] = {"age_days": 1095}
    assert "3.0 г." in _profile_line(v)
