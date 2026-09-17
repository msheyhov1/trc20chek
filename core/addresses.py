"""Извлечение TRON-адресов из произвольного текста.

Прежний парсер бота был `text.split()` + `startswith("T")` + `len == 34`,
поэтому не распознавал ничего, кроме адреса, отделённого пробелами: запятая,
точка, скобки, обратные кавычки Telegram и ссылка на TronScan ломали разбор.
А ссылка и пересланное сообщение — самый частый способ передать адрес.

Здесь: поиск по base58-алфавиту с границами, распознавание hex-формата `41…`
(его отдают некоторые кошельки и API) и сохранение порядка без дублей.
"""
from __future__ import annotations

import hashlib
import re

from .models import is_valid_trc20_address

# base58 без 0, O, I, l — поэтому набор символов уже отсекает часть мусора.
_BASE58 = "[1-9A-HJ-NP-Za-km-z]"
# Границы — не сам base58-символ: так адрес находится в «(T…)», «T…,», «`T…`»
# и в конце URL, но не внутри более длинной строки того же алфавита.
_B58_RE = re.compile(rf"(?<!{_BASE58})(T{_BASE58}{{33}})(?!{_BASE58})")
# Hex-представление: 0x41 + 20 байт. Регистр любой.
_HEX_RE = re.compile(r"(?<![0-9A-Fa-fx])(41[0-9A-Fa-f]{40})(?![0-9A-Fa-f])")

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def hex_to_base58(hex_addr: str) -> str | None:
    """`41a614f8…` → `TR7NHqje…`. None, если строка не похожа на TRON-hex."""
    raw = hex_addr.lower().removeprefix("0x")
    if len(raw) != 42 or not raw.startswith("41"):
        return None
    try:
        payload = bytes.fromhex(raw)
    except ValueError:
        return None
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    num = int.from_bytes(payload + checksum, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58_ALPHABET[rem] + out
    # Ведущие нулевые байты кодируются как «1» (здесь их не бывает, но пусть будет).
    for byte in payload + checksum:
        if byte:
            break
        out = "1" + out
    return out


def extract_addresses(text: str, limit: int | None = None) -> list[str]:
    """Валидные TRC20-адреса из текста, в порядке появления и без дублей.

    Принимает адреса с пунктуацией вокруг, внутри ссылок (`tronscan.org/#/address/T…`)
    и в hex-формате `41…` — последний конвертируется в base58.
    """
    found: list[str] = []
    seen: set[str] = set()

    def _add(addr: str) -> None:
        if addr and addr not in seen and is_valid_trc20_address(addr):
            seen.add(addr)
            found.append(addr)

    for m in _B58_RE.finditer(text or ""):
        _add(m.group(1))
    for m in _HEX_RE.finditer(text or ""):
        converted = hex_to_base58(m.group(1))
        if converted:
            _add(converted)

    return found[:limit] if limit else found


def looks_like_address_attempt(text: str) -> bool:
    """Похоже, что человек прислал адрес, но с ошибкой (опечатка, обрезан).

    Нужно, чтобы отличить «прислал не то» от «прислал адрес с битой
    контрольной суммой» и дать разный ответ."""
    for m in re.finditer(rf"T{_BASE58}{{20,40}}", text or ""):
        if not is_valid_trc20_address(m.group(0)):
            return True
    return False
