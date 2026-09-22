"""Тесты рендера вердикта в боте.

format_verdict — это весь пользовательский вывод бота, и до этого он не был
покрыт ни одним тестом (33% покрытия модуля). Здесь проверяется главное:
экранирование внешних меток, устойчивость к новым типам и лимит длины.
"""
from __future__ import annotations

import bot.main as bm
from core.models import AddressVerdict, EntityType, RiskLevel

ADDR = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def _v(**kw) -> AddressVerdict:
    v = AddressVerdict(address=ADDR)
    for k, val in kw.items():
        setattr(v, k, val)
    return v


def test_renders_every_entity_type():
    """Новый тип в перечислении раньше ронял рендер по KeyError."""
    for et in EntityType:
        text = bm.format_verdict(_v(entity_type=et, entity="X"))
        assert "Тип:" in text


def test_renders_every_risk_level():
    for rl in RiskLevel:
        text = bm.format_verdict(_v(risk_level=rl))
        assert bm.RISK_EMOJI[rl] in text


def test_sanction_source_is_shown_not_hardcoded_ofac():
    text = bm.format_verdict(
        _v(entity_type=EntityType.SANCTIONED, sanction_source="UK · EU", entity="HTX")
    )
    assert "САНКЦИОННЫЙ (UK · EU)" in text
    assert "OFAC" not in text


def test_html_in_external_label_is_escaped():
    """Метки приходят из внешних API. Неэкранированный тег сломал бы разбор
    HTML в Telegram или подменил разметку сообщения."""
    text = bm.format_verdict(_v(entity='<b>hack</b> & "co" <script>'))
    assert "<b>hack</b>" not in text
    assert "&lt;b&gt;hack&lt;/b&gt;" in text
    assert "&lt;script&gt;" in text
    assert "&amp;" in text


def test_html_in_flags_and_links_is_escaped():
    text = bm.format_verdict(
        _v(
            risk_flags=["<img src=x>"],
            exchange_links=[{"name": "<i>Bybit</i>", "deposits": 1, "withdrawals": 0}],
        )
    )
    assert "<img" not in text
    assert "<i>Bybit</i>" not in text


def test_frozen_type_reads_as_blocked_funds():
    text = bm.format_verdict(
        _v(entity_type=EntityType.FROZEN, entity="Tether blacklist",
           risk_level=RiskLevel.DANGEROUS, risk_score=100)
    )
    assert "СРЕДСТВА ЗАБЛОКИРОВАНЫ" in text


def test_high_risk_service_type_is_not_plain_exchange():
    text = bm.format_verdict(_v(entity_type=EntityType.HIGH_RISK_SERVICE, entity="Mixer"))
    assert "Высокорисковый сервис" in text
    assert "Тип: Биржа" not in text


def test_checked_at_and_cache_age_are_shown():
    text = bm.format_verdict(
        _v(checked_at="2026-09-17T22:19:00+00:00", cached=True, cache_age_seconds=7200)
    )
    assert "17.09.2026 22:19 UTC" in text
    assert "из кеша, 2 ч назад" in text


def test_fmt_when_and_age_edge_cases():
    assert bm._fmt_when(None) == "—"
    assert bm._fmt_when("не дата") == "не дата"
    assert bm._fmt_age(None) == ""
    assert bm._fmt_age(30) == ", только что"
    assert bm._fmt_age(600) == ", 10 мин назад"
    assert bm._fmt_age(180_000) == ", 2 дн назад"


def test_provider_gap_flag_is_visible_at_top():
    text = bm.format_verdict(
        _v(risk_flags=["❗ Проверка НЕПОЛНАЯ: недоступны источники — GoPlus"])
    )
    assert "НЕПОЛНАЯ" in text


def test_long_verdict_is_truncated_within_telegram_limit():
    v = _v(risk_flags=[f"Флаг {i}: " + "длинное описание " * 20 for i in range(40)])
    text = bm.format_verdict(v)
    # format_verdict сам не режет — режет _check_and_render, здесь проверяем,
    # что показывается ограниченное число флагов и есть пометка об остатке
    assert "…и ещё" in text
    assert len(text) < bm.TG_MESSAGE_LIMIT


def test_score_bar_bounds():
    assert bm._score_bar(0) == "▱" * 10
    assert bm._score_bar(100) == "▰" * 10
    assert bm._score_bar(50).count("▰") == 5
    assert len(bm._score_bar(-5)) == 10
    assert len(bm._score_bar(999)) == 10


def test_aml_providers_block_renders_both():
    v = _v(
        external_aml={"available": True, "provider": "Swapster", "pending": False,
                      "risk_score": 12.0, "risk_level": "safe", "entities": []},
        bitok_aml={"available": True, "provider": "Bitok", "pending": False,
                   "risk_score": 80.0, "risk_level": "dangerous", "level_raw": "high",
                   "entity": "Darknet", "entity_category_ru": "даркнет-маркет",
                   "entities": []},
    )
    text = bm.format_verdict(v)
    assert "1) Swapster" in text and "2) Bitok" in text
    assert "даркнет-маркет" in text


def test_aml_skipped_shows_the_actual_reason():
    """Причин у туннеля несколько — биржа, блокировка эмитентом, пустой адрес.
    Раньше для всех печаталась строка про биржу, и на пустом адресе это
    выглядело ошибкой вердикта."""
    v = _v(
        external_aml={"skipped": True, "reason": "биржа/сервис — внешний AML не требуется"},
        bitok_aml={"skipped": True, "reason": "биржа/сервис — внешний AML не требуется"},
    )
    assert "биржа/сервис — внешний AML не требуется" in bm.format_verdict(v)

    empty = _v(
        external_aml={"skipped": True, "reason": "на адресе нет ни одной операции"},
        bitok_aml={"skipped": True, "reason": "на адресе нет ни одной операции"},
    )
    assert "нет ни одной операции" in bm.format_verdict(empty)


def test_aml_skipped_without_reason_falls_back():
    v = _v(external_aml={"skipped": True}, bitok_aml={"skipped": True})
    assert "проверка не требуется" in bm.format_verdict(v)


def test_exposure_block_omitted_without_transfers():
    assert bm._exposure_line({}) == []
    assert bm._exposure_line({"transfers_analyzed": 0}) == []
    lines = bm._exposure_line({"transfers_analyzed": 50, "sanctions_exposure_pct": 12.5})
    assert any("санкции 12.5%" in ln for ln in lines)
