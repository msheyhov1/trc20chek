"""Реестр сервисных адресов: кто стоит за адресом, когда тега TronScan нет.

Теги TronScan покрывают далеко не всё. Депозитные адреса бирж не размечены
вовсе (это задокументировано), а телеграм-кошельки вроде CryptoBot и Telegram
Wallet встречаются на TRON и без публичного тега.

Адрес, который мы знаем, должен опознаваться в ДВУХ ролях:
  • как сам проверяемый адрес — «это кошелёк такого-то сервиса»;
  • как контрагент в переводах — иначе funnel-эвристика не увидит сервис в
    оттоке, и его депозитник останется «личным кошельком».
Вторая роль важнее: именно из-за неё депозитники и не опознавались.

Слои, в порядке приоритета:
  1. env `SERVICE_ADDRESSES` — `адрес:Имя` через запятую, правится без редеплоя;
  2. ручные метки оператора (`core.labels`, команда /label в боте) с типом
     «биржа» или «сервис повышенного риска» — они уже лежат в памяти, поэтому
     чтение синхронное и бесплатное.

Встроенного списка адресов здесь нет намеренно: адрес хот-кошелька нельзя взять
по памяти, его нужно сверить с источником. Неверно приписанный Binance адрес
хуже, чем неопознанный, — это тот же класс ошибки, что `isContract` и `tokens`
(см. CLAUDE.md, «Что НЕ делать»). Поэтому список наполняет оператор: одной
командой /label или переменной окружения.

Достаточно разметить ОДИН хот-кошелёк сервиса: дальше funnel-эвристика и
накопительный кластер сами опознают его депозитные адреса.
"""
from __future__ import annotations

import os

from . import labels
from .models import EntityType, is_valid_trc20_address

# Типы ручных меток, которые означают «за адресом стоит сервис». Метка «скам»
# или «санкционный» сюда НЕ входит: такой адрес нельзя считать биржей в оттоке.
_SERVICE_TYPES = {EntityType.EXCHANGE.value, EntityType.HIGH_RISK_SERVICE.value}


def _parse_env() -> dict[str, str]:
    """SERVICE_ADDRESSES=`адрес:Имя` через запятую. Адрес валидируется: опечатка
    в переменной окружения иначе молча не сработала бы никогда."""
    out: dict[str, str] = {}
    raw = os.getenv("SERVICE_ADDRESSES", "").strip()
    for chunk in raw.replace(";", ",").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        addr, _, name = chunk.partition(":")
        addr, name = addr.strip(), name.strip()
        if addr and name and is_valid_trc20_address(addr):
            out[addr] = name
    return out


ENV_SERVICES: dict[str, str] = _parse_env()


def reload_env() -> None:
    """Перечитать переменную окружения (нужно тестам и при смене конфигурации)."""
    global ENV_SERVICES
    ENV_SERVICES = _parse_env()


def service_name(address: str | None) -> str | None:
    """Имя сервиса по адресу или None. Дешёвая синхронная операция: два поиска
    по словарю в памяти, поэтому её можно звать на каждый перевод."""
    if not address:
        return None
    name = ENV_SERVICES.get(address)
    if name:
        return name
    label = labels.lookup(address) or {}
    if label.get("entity_type") in _SERVICE_TYPES:
        return label.get("entity") or None
    return None


def count() -> int:
    return len(ENV_SERVICES)
