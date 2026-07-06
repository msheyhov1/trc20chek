"""Внешний AML-провайдер (туннельная логика).

Вызывается ТОЛЬКО для НЕ-биржевых кошельков: если адрес — биржа, депозитник
биржи, контракт или уже помечен как скам/санкции, AML через внешний API не
запрашивается (это лишний расход и не имеет смысла для инфраструктуры бирж).

Сейчас это ЗАГЛУШКА. Подключи свой AML API прямо здесь — заполни тело
`check()` реальным HTTP-запросом. Ожидаемый формат возврата (пример):

    {
        "available": True,
        "provider": "AMLBot",         # имя сервиса
        "risk_level": "safe",         # safe | caution | dangerous (по желанию)
        "risk_score": 12,             # 0-100 (по желанию)
        "details": {...},             # любые доп. поля от провайдера
    }

Если ключ не задан — возвращаем `available: False`, и в выводе показывается
«AML: внешний API не настроен».
"""
from __future__ import annotations

import os
from typing import Any

import httpx

AML_API_KEY = os.getenv("AML_API_KEY", "")
AML_API_URL = os.getenv("AML_API_URL", "")


async def check(address: str, client: httpx.AsyncClient) -> dict[str, Any]:
    """Проверка адреса во внешнем AML-сервисе. Заглушка — заполни под свой API."""
    if not AML_API_KEY or not AML_API_URL:
        return {"available": False, "reason": "AML API не настроен (AML_API_KEY / AML_API_URL)"}

    # TODO: заменить на реальный вызов твоего AML API. Пример каркаса:
    #
    # try:
    #     r = await client.get(
    #         AML_API_URL,
    #         params={"address": address},
    #         headers={"Authorization": f"Bearer {AML_API_KEY}"},
    #         timeout=15.0,
    #     )
    #     r.raise_for_status()
    #     data = r.json()
    #     return {
    #         "available": True,
    #         "provider": "МОЙ_AML",
    #         "risk_level": ...,      # смапить из data
    #         "risk_score": ...,      # смапить из data
    #         "details": data,
    #     }
    # except (httpx.HTTPError, ValueError) as e:
    #     return {"available": False, "reason": f"AML API error: {e}"}

    return {"available": False, "reason": "AML API ещё не подключён (заполни core/aml_external.py)"}
