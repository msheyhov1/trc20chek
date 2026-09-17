"""Тесты обработчиков бота: команды и разбор входящего текста."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import bot.main as bm

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
OTHER = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"


def _message(text: str, user_id: int = 111):
    m = MagicMock()
    m.text = text
    m.from_user = MagicMock(id=user_id)
    m.answer = AsyncMock(return_value=MagicMock(edit_text=AsyncMock()))
    return m


async def test_help_lists_sources_and_commands():
    m = _message("/help")
    await bm.cmd_help(m)
    text = m.answer.await_args.args[0]
    for expected in ("OFAC", "Tether", "Swapster", "Bitok", "/id", "/status"):
        assert expected in text


async def test_id_command_returns_own_telegram_id():
    """Раньше свой ID можно было узнать только получив отказ от бота,
    то есть не будучи в белом списке."""
    m = _message("/id", user_id=424242)
    await bm.cmd_id(m)
    assert "424242" in m.answer.await_args.args[0]


async def test_status_command_shows_configuration():
    m = _message("/status")
    await bm.cmd_status(m)
    text = m.answer.await_args.args[0]
    assert "Конфигурация сервера" in text
    assert "Swapster" in text and "Bitok" in text
    assert "белом списке" in text


async def test_start_mentions_accepted_formats():
    m = _message("/start")
    await bm.cmd_start(m)
    text = m.answer.await_args.args[0]
    assert "TronScan" in text and "41" in text


@pytest.mark.parametrize("text", [f"{USDT},", f"({USDT})", f"tronscan.org/#/address/{USDT}"])
async def test_on_text_accepts_wrapped_address(text):
    m = _message(text)
    with patch.object(bm, "_check_one", new=AsyncMock()) as one:
        await bm.on_text(m)
    one.assert_awaited_once()
    assert one.await_args.args[1] == USDT


async def test_on_text_reports_checksum_typo_differently():
    m = _message("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X")
    with patch.object(bm, "_check_one", new=AsyncMock()) as one:
        await bm.on_text(m)
    one.assert_not_awaited()
    assert "контрольная сумма" in m.answer.await_args.args[0]


async def test_on_text_reports_no_address_found():
    m = _message("привет, посоветуй что-нибудь")
    with patch.object(bm, "_check_one", new=AsyncMock()) as one:
        await bm.on_text(m)
    one.assert_not_awaited()
    assert "Не нашёл" in m.answer.await_args.args[0]


async def test_on_text_announces_count_for_multiple_addresses():
    """Проверки идут последовательно и по десятки секунд — человек должен
    заранее знать, сколько их."""
    m = _message(f"{USDT}\n{OTHER}")
    with patch.object(bm, "_check_one", new=AsyncMock()) as one:
        await bm.on_text(m)
    assert one.await_count == 2
    assert "Нашёл адресов: 2" in m.answer.await_args_list[0].args[0]
    assert one.await_args_list[0].args[2] == " (1 из 2)"
    assert one.await_args_list[1].args[2] == " (2 из 2)"


async def test_on_text_respects_address_limit(monkeypatch):
    monkeypatch.setattr(bm, "MAX_ADDRESSES_PER_MESSAGE", 1)
    m = _message(f"{USDT} {OTHER}")
    with patch.object(bm, "_check_one", new=AsyncMock()) as one:
        await bm.on_text(m)
    assert one.await_count == 1


async def test_check_one_edits_progress_message_with_verdict():
    m = _message(USDT)
    progress = MagicMock(edit_text=AsyncMock())
    m.answer = AsyncMock(return_value=progress)
    with patch.object(bm, "_check_and_render", new=AsyncMock(return_value="ВЕРДИКТ")):
        await bm._check_one(m, USDT)
    assert "Проверяю адрес" in m.answer.await_args.args[0]
    progress.edit_text.assert_awaited_once()
    assert progress.edit_text.await_args.args[0] == "ВЕРДИКТ"


async def test_check_one_reports_failure_in_place():
    m = _message(USDT)
    progress = MagicMock(edit_text=AsyncMock())
    m.answer = AsyncMock(return_value=progress)
    with patch.object(bm, "_check_and_render", new=AsyncMock(side_effect=RuntimeError("упало"))):
        await bm._check_one(m, USDT)
    assert "Не удалось проверить" in progress.edit_text.await_args.args[0]


def test_fit_message_truncates_and_warns():
    long = "строка\n" * 2000
    out = bm._fit_message(long)
    assert len(out) <= bm.TG_MESSAGE_LIMIT
    assert "обрезан" in out


def test_fit_message_keeps_short_text_intact():
    assert bm._fit_message("коротко") == "коротко"
