"""Тесты гейта доступа к боту по Telegram ID."""
from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

from aiogram.types import CallbackQuery, Message

import bot.main as bm


def test_parse_ids():
    assert bm._parse_ids("123, 456 789") == {123, 456, 789}
    assert bm._parse_ids("") == set()
    assert bm._parse_ids("12, x, 34") == {12, 34}  # мусор пропускается


def test_parse_ids_operator_typos():
    """Кавычки от raw-редактора Railway, «;» вместо запятой — частые ошибки."""
    assert bm._parse_ids('"123"') == {123}
    assert bm._parse_ids("'123', '456'") == {123, 456}
    assert bm._parse_ids("111;222") == {111, 222}
    assert bm._parse_ids("@username") == set()          # не id
    assert bm._parse_ids("-1001234567890") == set()     # id канала, не пользователя
    assert bm._parse_ids("0") == set()


def test_access_middleware_registered_on_dispatcher():
    """Гейт должен висеть на РЕАЛЬНОМ dp: тесты самого класса этого не ловят —
    удали строку регистрации, и они останутся зелёными."""
    for observer in ("message", "callback_query"):
        names = [type(m).__name__ for m in getattr(bm.dp, observer).middleware]
        assert "AccessMiddleware" in names, observer


def test_every_observer_with_handlers_is_gated():
    """Появится новый тип апдейта (inline_query и т.п.) без гейта — тест упадёт."""
    for name, observer in bm.dp.observers.items():
        if name == "update" or not getattr(observer, "handlers", None):
            continue
        names = [type(m).__name__ for m in observer.middleware]
        assert "AccessMiddleware" in names, f"обработчики {name} не закрыты гейтом"


def test_is_allowed_empty_denies_everyone(monkeypatch):
    """Fail-closed: пустой список → бот закрыт для ВСЕХ, а не открыт."""
    monkeypatch.setattr(bm, "ALLOWED_TG_IDS", set())
    assert bm._is_allowed(999) is False
    assert bm._is_allowed(None) is False


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


async def test_middleware_blocks_with_empty_whitelist(monkeypatch):
    """Не задан ALLOWED_TG_IDS → к обработчику не пускаем никого."""
    monkeypatch.setattr(bm, "ALLOWED_TG_IDS", set())
    mw = bm.AccessMiddleware()
    handler = AsyncMock()
    event = MagicMock(spec=Message)
    event.answer = AsyncMock()

    await mw(handler, event, {"event_from_user": MagicMock(id=111)})

    handler.assert_not_called()
    event.answer.assert_awaited()


async def test_middleware_blocks_stranger_callback(monkeypatch):
    """Инлайн-кнопка («Перепроверить») гейтится так же, как сообщение,
    и колбэк закрывается алертом — иначе у чужого крутится спиннер."""
    monkeypatch.setattr(bm, "ALLOWED_TG_IDS", {111})
    mw = bm.AccessMiddleware()
    handler = AsyncMock()
    event = MagicMock(spec=CallbackQuery)
    event.answer = AsyncMock()

    await mw(handler, event, {"event_from_user": MagicMock(id=222)})

    handler.assert_not_called()
    event.answer.assert_awaited_once()
    assert event.answer.await_args.kwargs.get("show_alert") is True


async def test_middleware_blocks_event_without_user(monkeypatch):
    """Апдейт без пользователя (анонимный админ канала) — тоже мимо."""
    monkeypatch.setattr(bm, "ALLOWED_TG_IDS", {111})
    mw = bm.AccessMiddleware()
    handler = AsyncMock()
    event = MagicMock(spec=Message)
    event.answer = AsyncMock()

    await mw(handler, event, {"event_from_user": None})

    handler.assert_not_called()


def test_log_access_mode_warns_when_empty(monkeypatch, caplog):
    """Пустой белый список виден в логах старта как ошибка, а не как норма."""
    monkeypatch.setattr(bm, "ALLOWED_TG_IDS", set())
    with caplog.at_level(logging.ERROR):
        bm.log_access_mode(logging.getLogger("test-access"))
    assert "НИКОГО" in caplog.text
