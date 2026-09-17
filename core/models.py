"""Модели данных и валидация TRC20-адресов."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"
    UNKNOWN = "unknown"


class EntityType(str, Enum):
    EXCHANGE = "exchange"
    CONTRACT = "contract"
    PROJECT = "project"
    SCAM = "scam"
    SANCTIONED = "sanctioned"  # адрес в официальном санкционном списке (OFAC SDN)
    LABELED = "labeled"
    WALLET = "wallet"  # личный кошелёк, опознан по связям с биржами (flow-анализ)
    UNKNOWN = "unknown"


def _enum_or(enum_cls, value: Any, default):
    """Безопасное восстановление enum из строки: незнакомое значение → default."""
    try:
        return enum_cls(value)
    except (ValueError, TypeError):
        return default


@dataclass
class AddressVerdict:
    address: str
    entity: str | None = None
    entity_type: EntityType = EntityType.UNKNOWN
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_flags: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    raw_labels: dict[str, Any] = field(default_factory=dict)
    # Связи с биржами по анализу переводов (flow): [{name, deposits, withdrawals, total}]
    exchange_links: list[dict[str, Any]] = field(default_factory=list)
    # AML: числовой скор 0-100 + разбивка экспозиции по контрагентам (внутренняя, on-chain)
    risk_score: int = 0
    aml: dict[str, Any] = field(default_factory=dict)
    # Баланс кошелька (из TronScan /api/account)
    balance_trx: float = 0.0
    balance_usdt: float = 0.0
    # Результаты внешних AML-API (туннель: заполняются только для НЕ-биржевых кошельков).
    # external_aml — Swapster, bitok_aml — Bitok KYT. Формат у обоих одинаковый.
    external_aml: dict[str, Any] = field(default_factory=dict)
    bitok_aml: dict[str, Any] = field(default_factory=dict)
    # Состояние каждого провайдера в ЭТОЙ проверке: ok | error | skipped |
    # not_configured | pending | fallback. «Провайдер недоступен» обязан быть виден
    # в вердикте — иначе отсутствие данных выглядит как отсутствие риска.
    provider_status: dict[str, str] = field(default_factory=dict)
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "entity": self.entity,
            "entity_type": self.entity_type.value,
            "risk_level": self.risk_level.value,
            "risk_score": self.risk_score,
            "aml": self.aml,
            "balance_trx": self.balance_trx,
            "balance_usdt": self.balance_usdt,
            "external_aml": self.external_aml,
            "bitok_aml": self.bitok_aml,
            "provider_status": self.provider_status,
            "risk_flags": self.risk_flags,
            "sources": list(dict.fromkeys(self.sources)),
            "raw_labels": self.raw_labels,
            "exchange_links": self.exchange_links,
            "cached": self.cached,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AddressVerdict:
        """Обратная операция к to_dict(). Единственное место восстановления вердикта
        (кеш, история): новое поле добавляется сюда один раз, а не в каждом вызове."""
        return cls(
            address=d.get("address", ""),
            entity=d.get("entity"),
            entity_type=_enum_or(EntityType, d.get("entity_type"), EntityType.UNKNOWN),
            risk_level=_enum_or(RiskLevel, d.get("risk_level"), RiskLevel.UNKNOWN),
            risk_flags=list(d.get("risk_flags") or []),
            sources=list(d.get("sources") or []),
            raw_labels=dict(d.get("raw_labels") or {}),
            exchange_links=list(d.get("exchange_links") or []),
            risk_score=int(d.get("risk_score") or 0),
            aml=dict(d.get("aml") or {}),
            balance_trx=float(d.get("balance_trx") or 0.0),
            balance_usdt=float(d.get("balance_usdt") or 0.0),
            external_aml=dict(d.get("external_aml") or {}),
            bitok_aml=dict(d.get("bitok_aml") or {}),
            provider_status=dict(d.get("provider_status") or {}),
            cached=bool(d.get("cached", False)),
        )


# ---------- Валидация TRC20 ----------
# TRC20-адрес = base58-encoded address начинающийся с 'T', длина 34 символа.
# Внутренне — это 25 байт: 0x41 (TRON mainnet prefix) + 20 байт hash + 4 байта checksum.

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_decode(s: str) -> bytes:
    num = 0
    for char in s:
        if char not in _BASE58_ALPHABET:
            raise ValueError(f"invalid base58 char: {char}")
        num = num * 58 + _BASE58_ALPHABET.index(char)
    # Leading '1's в base58 → leading zero bytes
    n_pad = len(s) - len(s.lstrip("1"))
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * n_pad + body


def is_valid_trc20_address(address: str) -> bool:
    """Проверка формата TRC20 (TRON) адреса: длина, префикс, base58check."""
    if not isinstance(address, str) or len(address) != 34 or not address.startswith("T"):
        return False
    try:
        import hashlib

        decoded = _base58_decode(address)
        if len(decoded) != 25 or decoded[0] != 0x41:
            return False
        payload, checksum = decoded[:-4], decoded[-4:]
        digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return digest == checksum
    except Exception:
        return False
