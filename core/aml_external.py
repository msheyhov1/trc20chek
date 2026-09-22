"""Внешний AML-провайдер — Swapster (USDT / TRC20).

Туннель: вызывается ТОЛЬКО для НЕ-биржевых кошельков (см. aggregator).
Биржи/депозитники/контракты AML не проверяются — экономим лимит Swapster.

Флоу двухступенчатый (как в проде fix-bot):
  1) PUT  /aml  {"payCurrency": "USDT"}                                  -> reqId
  2) POST /aml  {"reqId", "checkCurrency", "checkNetwork", "address"}    -> результат
Auth: Authorization: Bearer <SWAPSTER_API_TOKEN>.

ENV:
  SWAPSTER_API_TOKEN        — токен API (без него AML «не настроен»)
  SWAPSTER_API_BASE_URL     — по умолчанию https://api.swapster.fi
                              (тест-контур: https://test-api.swapster.fi)
  SWAPSTER_PROXY_URL        — опц. прокси со статичным IP под whitelist Swapster
                              (http://user:pass@host:port или socks5://host:port)
  SWAPSTER_PAY_CURRENCY     — USDT
  SWAPSTER_CHECK_CURRENCY   — USDT
  SWAPSTER_CHECK_NETWORK    — TRC20
  SWAPSTER_TIMEOUT_SECONDS  — 30

Возврат check() — dict под формат вывода бота/веба:
  {available, provider, pending, risk_score(0-100|None), risk_level, entities, reason}
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

import httpx

PROVIDER = "Swapster"


def _cfg() -> dict[str, Any]:
    return {
        "token": os.getenv("SWAPSTER_API_TOKEN", "").strip(),
        "base_url": os.getenv("SWAPSTER_API_BASE_URL", "https://api.swapster.fi").rstrip("/"),
        "proxy": os.getenv("SWAPSTER_PROXY_URL", "").strip(),
        "pay_currency": os.getenv("SWAPSTER_PAY_CURRENCY", "USDT"),
        "check_currency": os.getenv("SWAPSTER_CHECK_CURRENCY", "USDT"),
        "check_network": os.getenv("SWAPSTER_CHECK_NETWORK", "TRC20"),
        "timeout": float(os.getenv("SWAPSTER_TIMEOUT_SECONDS", "30")),
    }


def is_configured() -> bool:
    return bool(os.getenv("SWAPSTER_API_TOKEN", "").strip())


def _score_to_percent(score: Any) -> float | None:
    """riskScore приходит как доля 0..1 или проценты 0..100 — нормализуем в 0..100."""
    if score is None:
        return None
    try:
        v = float(score)
    except (TypeError, ValueError):
        return None
    return round(v * 100, 2) if 0 <= v <= 1 else round(v, 2)


def _level_from_pct(pct: float | None) -> str | None:
    if pct is None:
        return None
    if pct < 25:
        return "safe"
    if pct < 75:
        return "caution"
    return "dangerous"


async def _request(client: httpx.AsyncClient, method: str, path: str, cfg: dict, **kw) -> dict:
    """Запрос к Swapster с однократным retry на 429. Бросает httpx.HTTPError на прочих ошибках."""
    url = f"{cfg['base_url']}{path}"
    for attempt in range(2):
        r = await client.request(method, url, **kw)
        if r.status_code == 429 and attempt == 0:
            try:
                delay = min(float(r.headers.get("Retry-After", "1")), 10.0)
            except ValueError:
                delay = 1.0
            await asyncio.sleep(delay)
            continue
        r.raise_for_status()
        try:
            return r.json() or {}
        except ValueError:
            return {}
    raise httpx.HTTPError("Swapster: превышен лимит запросов")


async def check(address: str) -> dict[str, Any]:
    """AML-проверка адреса через Swapster. Всегда возвращает dict, не бросает."""
    cfg = _cfg()
    if not cfg["token"]:
        return {"available": False, "provider": PROVIDER,
                "reason": "Swapster не настроен (SWAPSTER_API_TOKEN пуст)"}

    headers = {
        "Authorization": f"Bearer {cfg['token']}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    # На ОДИН запрос — меньшая доля бюджета, чтобы два запроса с retry успели
    # уложиться в общий дедлайн (см. asyncio.timeout ниже).
    per_request = max(5.0, min(cfg["timeout"], 15.0))
    client_kw: dict[str, Any] = {"timeout": per_request, "headers": headers}
    if cfg["proxy"]:
        client_kw["proxy"] = cfg["proxy"]

    # SWAPSTER_TIMEOUT_SECONDS — НАСТЕННЫЙ бюджет всей проверки. Раньше значение
    # ограничивало один запрос, а флоу делает два (PUT + POST), каждый с retry на
    # 429 и паузой до 10 с: худший случай выходил за две минуты без верхней границы.
    try:
        async with asyncio.timeout(cfg["timeout"]):
            async with httpx.AsyncClient(**client_kw) as client:
                prepared = await _request(
                    client, "PUT", "/aml", cfg, json={"payCurrency": cfg["pay_currency"]}
                )
                req_id = prepared.get("reqId")
                if not req_id:
                    return {"available": False, "provider": PROVIDER,
                            "reason": "Swapster: API не вернул reqId"}

                data = await _request(
                    client, "POST", "/aml", cfg,
                    json={
                        "reqId": req_id,
                        "checkCurrency": cfg["check_currency"],
                        "checkNetwork": cfg["check_network"],
                        "address": address,
                    },
                )
    except TimeoutError:
        return {"available": False, "provider": PROVIDER,
                "reason": f"Swapster: превышен бюджет проверки ({cfg['timeout']:g} с)"}
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        reason = {
            400: "неверный запрос/адрес",
            401: "неверный API-токен",
            403: "доступ запрещён (IP не в whitelist?)",
            429: "превышен лимит запросов",
            503: "сервис временно недоступен",
        }.get(code, f"HTTP {code}")
        return {"available": False, "provider": PROVIDER, "reason": f"Swapster: {reason}"}
    except (httpx.HTTPError, ValueError) as e:
        return {"available": False, "provider": PROVIDER,
                "reason": f"Swapster: ошибка соединения ({e})"}

    pending = bool(data.get("pending"))
    pct = None if pending else _score_to_percent(data.get("riskScore"))
    entities = [
        {
            "entity": (e.get("entity") or "UNKNOWN").replace("_", " "),
            "level": e.get("level"),
            "risk_score": _score_to_percent(e.get("riskScore")),
        }
        for e in (data.get("entities") or [])
        if isinstance(e, dict)
    ]
    # Тот же контракт, что у Bitok: сначала самая весомая категория. Swapster
    # отдаёт их в произвольном порядке, а бот и веб рисуют оба провайдера одним
    # кодом и разбивку показывают как есть.
    entities.sort(key=lambda e: e.get("risk_score") or 0, reverse=True)
    return {
        "available": True,
        "provider": PROVIDER,
        "pending": pending,
        "risk_score": pct,  # проценты с десятыми (0..100) или None
        "risk_level": _level_from_pct(pct),
        "entities": entities,
        "details": data,
    }
