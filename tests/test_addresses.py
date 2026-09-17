"""Тесты извлечения адресов из живого текста (core/addresses.py).

Прежний парсер бота был split() + startswith("T") + len == 34 и не распознавал
адрес с любой пунктуацией вокруг, в кавычках Telegram и в ссылке на TronScan —
то есть ровно те формы, в которых адрес обычно и присылают.
"""
from __future__ import annotations

import pytest

from core.addresses import extract_addresses, hex_to_base58, looks_like_address_attempt

USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
OTHER = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"
USDT_HEX = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"


@pytest.mark.parametrize(
    "text",
    [
        USDT,
        f"проверь {USDT}",
        f"{USDT},",
        f"адрес: {USDT}.",
        f"({USDT})",
        f"[{USDT}]",
        f"`{USDT}`",
        f'"{USDT}"',
        f"{USDT}\n",
        f"https://tronscan.org/#/address/{USDT}",
        f"https://tronscan.org/#/address/{USDT}/transfers",
        f"это мой кошелёк {USDT} — проверь пожалуйста",
    ],
)
def test_extracts_address_in_real_world_wrapping(text):
    assert extract_addresses(text) == [USDT]


def test_extracts_hex_format():
    """Некоторые кошельки и API отдают адрес как 41…"""
    assert extract_addresses(USDT_HEX) == [USDT]
    assert extract_addresses(f"owner_address: {USDT_HEX}") == [USDT]


def test_preserves_order_and_drops_duplicates():
    assert extract_addresses(f"{USDT} {OTHER} {USDT}") == [USDT, OTHER]


def test_limit_applies():
    assert extract_addresses(f"{USDT} {OTHER}", limit=1) == [USDT]


def test_rejects_invalid_checksum():
    assert extract_addresses("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X") == []


def test_rejects_plain_text():
    assert extract_addresses("привет как дела") == []
    assert extract_addresses("") == []
    assert extract_addresses(None) == []


def test_does_not_match_inside_longer_base58_run():
    """Адрес внутри длинной base58-строки — скорее всего не адрес."""
    assert extract_addresses(USDT + "abcdef") == []
    assert extract_addresses("zzz" + USDT) == []


def test_hex_to_base58_roundtrip():
    assert hex_to_base58(USDT_HEX) == USDT
    assert hex_to_base58("0x" + USDT_HEX) == USDT
    assert hex_to_base58(USDT_HEX.upper()) == USDT


def test_hex_to_base58_rejects_garbage():
    assert hex_to_base58("deadbeef") is None
    assert hex_to_base58("42" + "a" * 40) is None     # неверный префикс
    assert hex_to_base58("41" + "z" * 40) is None     # не hex


def test_looks_like_attempt_distinguishes_typo_from_chatter():
    """Опечатка в адресе и обычный текст требуют разных ответов пользователю."""
    assert looks_like_address_attempt("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X") is True
    assert looks_like_address_attempt("TR7NHqjeKQxGTCi8q8ZY4pL8") is True   # обрезан
    assert looks_like_address_attempt("привет") is False
    assert looks_like_address_attempt(USDT) is False   # валидный — не «попытка»
