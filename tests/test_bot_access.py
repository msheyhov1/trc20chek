"""Тесты гейта доступа к боту по Telegram ID."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from aiogram.types import Message

import bot.main as bm


def test_parse_ids():
    assert bm._parse_ids("123, 456 789") == {123, 456, 789}
    assert bm._parse_ids("") == set()
    assert bm._parse_ids("12, x, 34") == {12, 34}  # мусор пропускается


def test_is_allowed_open(monkeypatch):
    """Пустой список → доступ открыт всем (чтобы не залочиться до настройки)."""
    monkeypatch.setattr(bm, "ALLOWED_TG_IDS", set())
    assert bm._is_allowed(999) is True
    assert bm._is_allowed(None) is True


def test_is_allowed_restricted(monkeypatch):
    monkeypatch.setattr(bm, "ALLOWED_TG_IDS", {111})
    assert bm._is_allowed(111) is True
    assert bm._is_allowed(222) is False
    assert bm._is_allowed(None) is False


async def test_middleware_blocks_stranger(monkeypatch):
    monkeypatch.setattr(bm, "ALLOWED_TG_IDS", {111})
    mw = bm.AccessMiddleware()
    handler = AsyncMock()
    event = MagicMock(spec=Message)
    event.answer = AsyncMock()
    data = {"event_from_user": MagicMock(id=222)}

    await mw(handler, event, data)

    handler.assert_not_called()           # обработчик не вызван
    event.answer.assert_awaited()         # отказ отправлен


async def test_middleware_allows_member(monkeypatch):
    monkeypatch.setattr(bm, "ALLOWED_TG_IDS", {111})
    mw = bm.AccessMiddleware()
    handler = AsyncMock()
    event = MagicMock(spec=Message)
    event.answer = AsyncMock()
    data = {"event_from_user": MagicMock(id=111)}

    await mw(handler, event, data)

    handler.assert_awaited_once()         # пропущен к обработчику
    event.answer.assert_not_called()
