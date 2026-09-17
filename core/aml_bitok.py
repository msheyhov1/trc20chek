"""Внешний AML-провайдер — Bitok KYT (USDT / TRC20).

Второй AML-источник рядом со Swapster (`core/aml_external.py`). Вызывается тем же
туннелем: ТОЛЬКО для НЕ-биржевых кошельков (биржи/депозитники/контракты не проверяем —
экономим лимит KYT).

Контракт API (docs.bitok.org, проверено вживую против https://kyt-api.bitok2.org):
  1) POST /v1/manual-checks/check-address/  {"network": "TRX", "address": ...}
     -> {"id": ..., "check_status": "checking"}
  2) GET  /v1/manual-checks/{id}/            поллинг до check_status == "checked"
     -> {"risk_level": "none|low|medium|high|severe|undefined", "risk_score": 0..1}
  3) GET  /v1/manual-checks/{id}/address-exposure/   (best-effort)
     -> {"entity_name": "Binance", "entity_category": "exchange", ...}
  4) GET  /v1/manual-checks/{id}/risks/              (best-effort)
     -> [{"risk_type", "entity_category", "risk_level", "value_share", "proximity"}, ...]

Авторизация — HMAC-SHA256 (docs.bitok.org/guide/authorization): заголовки
API-KEY-ID / API-TIMESTAMP (мс) / API-SIGNATURE, где подпись =
base64(HMAC(secret, "METHOD\\nENDPOINT\\nTIMESTAMP[\\nCOMPACT_JSON]")).
Тело шлём ровно той compact-JSON строкой, что подписали.

ENV:
  BITOK_API_KEY_ID       — идентификатор ключа (без него провайдер «не настроен»)
  BITOK_API_SECRET       — секрет для подписи
  BITOK_API_BASE_URL     — по умолчанию https://kyt-api.bitok2.org (контур РФ)
  BITOK_NETWORK          — TRX
  BITOK_TIMEOUT_SECONDS  — общий таймаут проверки, по умолчанию 45

Возврат check() — dict в том же нормализованном формате, что и Swapster
(его рендерят бот и веб одним кодом):
  {available, provider, pending, risk_score(0-100|None), risk_level, level_raw,
   entity, entity_category, entity_category_ru, entities, reason, details}
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any

import httpx

PROVIDER = "Bitok"

# Лёгкие адреса готовы за ~0.3 сек, тяжёлый граф считается 12+ сек — поллим.
POLL_DELAY = 2.0

# Родная шкала Bitok → общая шкала проекта (RiskLevel).
_LEVEL_MAP = {
    "none": "safe",
    "low": "safe",
    "medium": "caution",
    "high": "dangerous",
    "severe": "dangerous",
}

# Родная шкала Bitok → группировка, в которой бот/веб рисуют строки рисков.
_LEVEL_GROUP = {
    "none": "LOW_RISK",
    "low": "LOW_RISK",
    "medium": "MEDIUM_RISK",
    "high": "HIGH_RISK",
    "severe": "HIGH_RISK",
}

# Категории сущностей Bitok → русские названия (docs.bitok.org/guide/entity-categories).
# Fallback для незнакомой категории — сама строка с подчёркиваниями через пробел.
ENTITY_CATEGORY_RU = {
    # высокий риск
    "cam": "CSAM (материалы насилия над детьми)",
    "darknet_market": "даркнет-маркет",
    "fraud_shop": "фрод-шоп (краденые данные)",
    "illegal_service": "нелегальный сервис",
    "scam": "скам / мошенничество",
    "stolen_funds": "похищенные средства",
    "ransomware": "шифровальщик (ransomware)",
    "terrorist_financing": "финансирование терроризма",
    "high_risk_jurisdiction": "санкционная юрисдикция",
    "sanctions": "санкционный список",
    "online_pharmacy": "нелегальная аптека",
    "gambling": "гемблинг",
    "high_risk_exchange": "высокорисковая биржа (без KYC)",
    # средний риск
    "mixer": "миксер",
    "privacy_protocol": "privacy-протокол",
    "p2p_exchange": "P2P-обменник",
    "dex": "DEX",
    "lending": "лендинг-протокол",
    "bridge": "кросс-чейн мост",
    "ico": "ICO",
    "enforcement_action": "правоохранительная блокировка",
    # низкий риск
    "exchange": "биржа",
    "psp": "платёжный провайдер",
    "marketplace": "маркетплейс",
    "mining": "майнинг",
    "mining_pool": "майнинг-пул",
    "iaas": "инфраструктурный сервис",
    "personal_wallet": "личный кошелёк",
    "custodial_wallet": "кастодиальный кошелёк",
    "token_contract": "контракт токена",
    "smart_contract": "смарт-контракт",
    "nft_marketplace": "NFT-маркетплейс",
    "atm": "крипто-банкомат",
    # системные
    "seized_funds": "изъятые средства",
    "dust": "пыль (dust)",
    "unnamed_wallet": "неопознанный кошелёк",
    "unnamed_service": "неопознанный сервис",
    "other": "прочее",
    "undefined": "не определено",
}


def category_ru(category: str | None) -> str:
    """Человекочитаемое имя категории: из словаря, иначе — сама категория без подчёркиваний."""
    raw = (category or "").strip()
    if not raw:
        return ""
    return ENTITY_CATEGORY_RU.get(raw.lower(), raw.replace("_", " "))


def _cfg() -> dict[str, Any]:
    return {
        "key_id": os.getenv("BITOK_API_KEY_ID", "").strip(),
        "secret": os.getenv("BITOK_API_SECRET", "").strip(),
        "base_url": os.getenv("BITOK_API_BASE_URL", "https://kyt-api.bitok2.org").rstrip("/"),
        "network": os.getenv("BITOK_NETWORK", "TRX").strip() or "TRX",
        "timeout": float(os.getenv("BITOK_TIMEOUT_SECONDS", "45")),
    }


def is_configured() -> bool:
    return bool(os.getenv("BITOK_API_KEY_ID", "").strip() and os.getenv("BITOK_API_SECRET", "").strip())


def _score_to_percent(score: Any) -> float | None:
    """risk_score приходит долей 0..1 (или уже процентами) — нормализуем в 0..100."""
    if score is None:
        return None
    try:
        v = float(score)
    except (TypeError, ValueError):
        return None
    return round(v * 100, 2) if 0 <= v <= 1 else round(v, 2)


def sign(secret: str, method: str, endpoint: str, timestamp: str, body: str | None = None) -> str:
    """API-SIGNATURE: base64(HMAC-SHA256(secret, METHOD\\nENDPOINT\\nTS[\\nBODY]))."""
    str_to_sign = f"{method}\n{endpoint}\n{timestamp}"
    if body:
        str_to_sign += "\n" + body
    digest = hmac.new(secret.encode(), str_to_sign.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


def _headers(cfg: dict, method: str, endpoint: str, body: str | None) -> dict[str, str]:
    # Таймстамп в мс, свой на каждый запрос (сервер проверяет свежесть подписи).
    ts = str(int(time.time() * 1000))
    return {
        "API-KEY-ID": cfg["key_id"],
        "API-TIMESTAMP": ts,
        "API-SIGNATURE": sign(cfg["secret"], method, endpoint, ts, body),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


class _BitokHTTPError(Exception):
    """Ошибка API с текстом, пригодным для показа пользователю."""


async def _request(client: httpx.AsyncClient, cfg: dict, method: str,
                   endpoint: str, payload: dict | None = None) -> Any:
    """Один подписанный запрос. Тело шлём ровно той строкой, что подписали."""
    body = json.dumps(payload, separators=(",", ":")) if payload is not None else None
    r = await client.request(
        method, cfg["base_url"] + endpoint,
        content=body, headers=_headers(cfg, method, endpoint, body),
    )
    try:
        data = r.json()
    except ValueError:
        data = {"detail": r.text[:200]}

    if 200 <= r.status_code < 300:
        return data

    detail = ""
    if isinstance(data, dict):
        detail = str(data.get("detail") or data.get("message") or data)[:200]
    else:
        detail = str(data)[:200]
    msg = {
        400: f"неверный запрос: {detail}",
        401: "неверный API-ключ или подпись",
        403: f"доступ запрещён: {detail}",
        404: "эндпоинт не найден",
        429: "превышен лимит запросов",
    }.get(r.status_code, f"HTTP {r.status_code}: {detail}")
    raise _BitokHTTPError(msg)


async def check(address: str) -> dict[str, Any]:
    """AML-проверка адреса через Bitok KYT. Всегда возвращает dict, не бросает."""
    cfg = _cfg()
    if not cfg["key_id"] or not cfg["secret"]:
        return {"available": False, "provider": PROVIDER,
                "reason": "Bitok не настроен (BITOK_API_KEY_ID / BITOK_API_SECRET пусты)"}

    # BITOK_TIMEOUT_SECONDS — НАСТЕННЫЙ бюджет всей проверки, как и обещает
    # .env.example. Раньше значение уходило только в таймаут httpx и умножалось на
    # число попыток поллинга: на дефолтах худший случай был ~940 с, и бот всё это
    # время держал пользователя. Теперь считаем дедлайн от одной точки старта, а
    # на отдельный запрос даём меньшую долю бюджета.
    deadline = time.monotonic() + cfg["timeout"]
    request_timeout = max(5.0, min(cfg["timeout"], 15.0))

    def _left() -> float:
        return deadline - time.monotonic()

    try:
        async with httpx.AsyncClient(timeout=request_timeout) as client:
            check_data = await _request(
                client, cfg, "POST", "/v1/manual-checks/check-address/",
                {"network": cfg["network"], "address": address},
            )
            check_id = check_data.get("id")
            if not check_id:
                return {"available": False, "provider": PROVIDER,
                        "reason": "Bitok: API не вернул id проверки"}

            while check_data.get("check_status") == "checking":
                # Нужен запас на сам запрос статуса, иначе выйдем за бюджет.
                if _left() <= POLL_DELAY + 1.0:
                    break
                await asyncio.sleep(POLL_DELAY)
                check_data = await _request(client, cfg, "GET", f"/v1/manual-checks/{check_id}/")

            status = check_data.get("check_status")
            if status == "error":
                return {"available": False, "provider": PROVIDER,
                        "reason": "Bitok: проверка завершилась ошибкой на стороне сервиса"}
            if status != "checked":
                return {"available": True, "provider": PROVIDER, "pending": True,
                        "risk_score": None, "risk_level": None, "entities": [],
                        "details": check_data}

            # Сущность и детальные риски — best-effort: их сбой не ломает результат.
            # Если бюджет исчерпан, отдаём риск без них: скор важнее имени.
            entity = entity_category = None
            risks: list[dict[str, Any]] = []
            if _left() <= 1.0:
                return _result(check_data, None, None, [])
            try:
                exposure = await _request(
                    client, cfg, "GET", f"/v1/manual-checks/{check_id}/address-exposure/")
                if isinstance(exposure, dict):
                    entity = exposure.get("entity_name")
                    entity_category = exposure.get("entity_category")
            except (_BitokHTTPError, httpx.HTTPError, ValueError):
                pass
            try:
                risks_data = await _request(
                    client, cfg, "GET", f"/v1/manual-checks/{check_id}/risks/")
                if isinstance(risks_data, list):
                    risks = [r for r in risks_data if isinstance(r, dict)]
            except (_BitokHTTPError, httpx.HTTPError, ValueError):
                pass
    except _BitokHTTPError as e:
        return {"available": False, "provider": PROVIDER, "reason": f"Bitok: {e}"}
    except (httpx.HTTPError, ValueError) as e:
        return {"available": False, "provider": PROVIDER,
                "reason": f"Bitok: ошибка соединения ({e})"}

    return _result(check_data, entity, entity_category, risks)


def _result(
    check_data: dict[str, Any],
    entity: str | None,
    entity_category: str | None,
    risks: list[dict[str, Any]],
) -> dict[str, Any]:
    level_raw = (check_data.get("risk_level") or "undefined").lower()
    return {
        "available": True,
        "provider": PROVIDER,
        "pending": False,
        "risk_score": _score_to_percent(check_data.get("risk_score")),
        "risk_level": _LEVEL_MAP.get(level_raw),
        "level_raw": level_raw,
        "entity": entity,
        "entity_category": entity_category,
        "entity_category_ru": category_ru(entity_category),
        "entities": _normalize_risks(risks),
        "details": check_data,
    }


def _normalize_risks(risks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Риски Bitok → общий формат entities (как у Swapster), чтобы бот/веб
    рисовали оба провайдера одним кодом. value_share — доля объёма, а не риск."""
    out: list[dict[str, Any]] = []
    for r in risks:
        raw_cat = str(r.get("entity_category") or r.get("risk_type") or "?")
        level_raw = str(r.get("risk_level") or "").lower()
        out.append({
            "entity": category_ru(raw_cat),
            "level": _LEVEL_GROUP.get(level_raw, "LOW_RISK"),
            "level_raw": level_raw,
            "risk_score": _score_to_percent(r.get("value_share")),
            "proximity": r.get("proximity"),
        })
    out.sort(key=lambda e: e.get("risk_score") or 0, reverse=True)
    return out
