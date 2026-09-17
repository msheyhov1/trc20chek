"""Безопасность контракта/токена по TronScan Security Service.

Зачем: контракт у нас определялся по accountType/contractMap, получал SAFE при
наличии `vip` и CAUTION иначе — и на этом всё, туннель исключал контракты из
внешних AML. Между тем «можно ли взаимодействовать с этим контрактом» — частый
вопрос, а скам-контракты (дрейнеры, фейковые стейкинги, токены с функцией
блокировки) распространены не меньше скам-кошельков.

Эндпоинт (официальная документация TronScan, Security Service API):
  GET /api/security/token/data?address=<контракт>
  → {is_vip, black_list_type, increase_total_supply, token_level, has_url,
     swap_token, sun_liquidity, open_source, is_proxy}

`token_level` — строка: "0" неизвестно, "1" нейтрально, "2" ок, "3"
подозрительно, "4" небезопасно. Уровень "2" НЕ доказывает добросовестность:
новый скам-токен может быть просто ещё не отрепорчен.

Бесплатность эндпоинта без ключа официально не подтверждена, поэтому провайдер
необязательный и его сбой не должен влиять на вердикт иначе, чем через
provider_status.
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from .base import ProviderError

TRONSCAN_BASE = "https://apilist.tronscanapi.com"
TRONSCAN_API_KEY = os.getenv("TRONSCAN_API_KEY", "")
ENABLED = os.getenv("TOKEN_SECURITY_CHECK", "1") not in ("0", "false", "False")

# token_level → человекочитаемое описание.
LEVEL_RU = {
    "0": "уровень не определён",
    "1": "нейтральный",
    "2": "проходит базовые проверки",
    "3": "подозрительный",
    "4": "небезопасный",
}
BAD_LEVELS = {"3", "4"}


def is_enabled() -> bool:
    return ENABLED


async def fetch(address: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Данные о безопасности контракта. ProviderError при сбое."""
    if not ENABLED:
        raise ProviderError("Token security: проверка выключена (TOKEN_SECURITY_CHECK=0)")
    headers = {"TRON-PRO-API-KEY": TRONSCAN_API_KEY} if TRONSCAN_API_KEY else {}
    try:
        r = await client.get(
            f"{TRONSCAN_BASE}/api/security/token/data",
            params={"address": address},
            headers=headers,
            timeout=10.0,
        )
        r.raise_for_status()
        data = r.json() or {}
    except (httpx.HTTPError, ValueError) as e:
        raise ProviderError(f"Token security: {e}") from e
    if not isinstance(data, dict):
        raise ProviderError("Token security: неожиданный ответ")
    return data


def describe(data: dict[str, Any]) -> tuple[list[str], bool]:
    """Ответ → (список флагов на русском, есть ли серьёзная проблема).

    Серьёзной считаем только то, что прямо угрожает пользователю: небезопасный
    уровень токена или наличие функции блокировки средств. Закрытый исходник и
    proxy — это повод для внимания, но не приговор: так устроены и легальные
    контракты, включая сам USDT."""
    flags: list[str] = []
    serious = False

    level = str(data.get("token_level") or "")
    if level in BAD_LEVELS:
        serious = True
        flags.append(f"⛔️ TronScan: токен помечен как {LEVEL_RU[level]} (уровень {level})")
    elif level in LEVEL_RU and level != "2":
        flags.append(f"ℹ️ TronScan: {LEVEL_RU[level]}")

    if str(data.get("black_list_type") or "0") == "1":
        serious = True
        flags.append(
            "⛔️ У контракта есть функция блокировки адресов — эмитент может "
            "заморозить средства на любом кошельке"
        )
    if data.get("has_url"):
        serious = True
        flags.append(
            "⛔️ В имени или символе токена зашита ссылка — классическая приманка "
            "airdrop-фишинга"
        )
    if data.get("increase_total_supply"):
        flags.append("⚠️ Эмитент может увеличивать общее предложение токена")
    if data.get("is_proxy"):
        flags.append("⚠️ Контракт является proxy — логику можно подменить после деплоя")
    if data.get("open_source") is False:
        flags.append("⚠️ Исходный код контракта не опубликован")
    if data.get("is_vip"):
        flags.append("✅ Токен из VIP-списка TronScan (известный эмитент)")
    return flags, serious
