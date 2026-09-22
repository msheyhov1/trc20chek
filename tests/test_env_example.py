"""Каждая переменная окружения, которую читает код, описана в .env.example.

CLAUDE.md называет .env.example полным списком с пояснениями. В PR #2 скрипт,
дописывавший файл, заменял по якорю без проверки, якорь не совпал — и четыре
новые переменные (SERVICE_ADDRESSES, OFAC_ASSETS, NEW_ADDRESS_DAYS,
FEEDBACK_RISK_SCORE) так и не попали в файл. Оператор о них просто не узнал бы.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _vars_read_by_code() -> set[str]:
    found: set[str] = set()
    for folder in ("core", "api", "bot"):
        for path in (ROOT / folder).rglob("*.py"):
            found |= set(re.findall(r'os\.getenv\(\s*"([A-Z0-9_]+)"', path.read_text("utf-8")))
    return found


def _vars_documented() -> set[str]:
    text = (ROOT / ".env.example").read_text("utf-8")
    return set(re.findall(r"^([A-Z0-9_]+)=", text, flags=re.MULTILINE))


def test_every_env_var_is_documented():
    missing = sorted(_vars_read_by_code() - _vars_documented())
    assert not missing, f"не описаны в .env.example: {missing}"
