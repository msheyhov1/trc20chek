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
    # Результат внешнего AML-API (туннель: заполняется только для НЕ-биржевых кошельков)
    external_aml: dict[str, Any] = field(default_factory=dict)
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
            "risk_flags": self.risk_flags,
            "sources": self.sources,
            "raw_labels": self.raw_labels,
            "exchange_links": self.exchange_links,
            "cached": self.cached,
        }


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
