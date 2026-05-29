"""Локальный провайдер кастомных меток.

Можно вручную добавлять адреса, которые вы хотите помечать сами
(внутренние кошельки команды, известные вам скамеры и т.д.).
"""
from __future__ import annotations

# Формат: address -> {entity, entity_type, risk_level, note}
LOCAL_LABELS: dict[str, dict[str, str]] = {
    # Примеры — замените на свои
    # "TXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX": {
    #     "entity": "Our hot wallet",
    #     "entity_type": "labeled",
    #     "risk_level": "safe",
    #     "note": "Internal team wallet"
    # },
}


def lookup(address: str) -> dict[str, str] | None:
    return LOCAL_LABELS.get(address)
