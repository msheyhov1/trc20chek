"""Тесты пароля на веб-сайт (HTTP Basic Auth)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

import api.main as am


def _creds(user: str, pw: str):
    c = MagicMock()
    c.username, c.password = user, pw
    return c


def test_web_auth_disabled(monkeypatch):
    """WEB_PASSWORD пуст → сайт открыт, креды не нужны."""
    monkeypatch.setattr(am, "WEB_PASSWORD", "")
    assert am.require_web_auth(None) is None
    assert am.require_web_auth(_creds("x", "y")) is None


def test_web_auth_correct(monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "s3cret")
    monkeypatch.setattr(am, "WEB_USER", "admin")
    assert am.require_web_auth(_creds("admin", "s3cret")) is None


def test_web_auth_missing_credentials(monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "s3cret")
    with pytest.raises(HTTPException) as exc:
        am.require_web_auth(None)
    assert exc.value.status_code == 401
    assert exc.value.headers.get("WWW-Authenticate", "").startswith("Basic")


def test_web_auth_wrong_password(monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "s3cret")
    monkeypatch.setattr(am, "WEB_USER", "admin")
    with pytest.raises(HTTPException):
        am.require_web_auth(_creds("admin", "nope"))


def test_web_auth_wrong_user(monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "s3cret")
    monkeypatch.setattr(am, "WEB_USER", "admin")
    with pytest.raises(HTTPException):
        am.require_web_auth(_creds("hacker", "s3cret"))


# ---------- Дефолт доступа: без пароля и ключа /check закрыт ----------

def test_is_protected_requires_explicit_choice(monkeypatch):
    """У бота гейт fail-closed. Веб должен быть симметричен: «открыт всем»
    только по явному WEB_PUBLIC=1, а не по умолчанию."""
    monkeypatch.setattr(am, "WEB_PASSWORD", "")
    monkeypatch.setattr(am, "API_KEY", "")
    monkeypatch.setattr(am, "WEB_PUBLIC", False)
    assert am.is_protected() is False

    monkeypatch.setattr(am, "WEB_PASSWORD", "pw")
    assert am.is_protected() is True
    monkeypatch.setattr(am, "WEB_PASSWORD", "")
    monkeypatch.setattr(am, "API_KEY", "k")
    assert am.is_protected() is True
    monkeypatch.setattr(am, "API_KEY", "")
    monkeypatch.setattr(am, "WEB_PUBLIC", True)
    assert am.is_protected() is True


def _request(headers: dict | None = None, ip: str = "1.2.3.4"):
    r = MagicMock()
    r.headers = headers or {}
    r.client = MagicMock()
    r.client.host = ip
    return r


def test_authorize_blocks_when_nothing_configured(monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "")
    monkeypatch.setattr(am, "API_KEY", "")
    monkeypatch.setattr(am, "WEB_PUBLIC", False)
    with pytest.raises(HTTPException) as exc:
        am._authorize(_request(), None)
    assert exc.value.status_code == 503


def test_authorize_accepts_api_key_from_header(monkeypatch):
    """Ключ в query попадает в логи и историю браузера — заголовок предпочтительнее,
    но оба должны работать."""
    monkeypatch.setattr(am, "API_KEY", "s3cret")
    assert am._authorize(_request({"x-api-key": "s3cret"}), None) is None
    assert am._authorize(_request(), "s3cret") is None
    with pytest.raises(HTTPException) as exc:
        am._authorize(_request({"x-api-key": "wrong"}), None)
    assert exc.value.status_code == 401
    with pytest.raises(HTTPException):
        am._authorize(_request(), None)


def test_authorize_rate_limits_public_access(monkeypatch):
    from api.ratelimit import RateLimiter
    monkeypatch.setattr(am, "API_KEY", "")
    monkeypatch.setattr(am, "WEB_PASSWORD", "")
    monkeypatch.setattr(am, "WEB_PUBLIC", True)
    monkeypatch.setattr(am, "limiter", RateLimiter(per_ip=2, window_seconds=3600, daily_total=0))

    am._authorize(_request(ip="9.9.9.9"), None)
    am._authorize(_request(ip="9.9.9.9"), None)
    with pytest.raises(HTTPException) as exc:
        am._authorize(_request(ip="9.9.9.9"), None)
    assert exc.value.status_code == 429
    # другой IP не задет
    assert am._authorize(_request(ip="8.8.8.8"), None) is None


def test_authorize_skips_rate_limit_for_api_key_clients(monkeypatch):
    from api.ratelimit import RateLimiter
    monkeypatch.setattr(am, "API_KEY", "k")
    monkeypatch.setattr(am, "limiter", RateLimiter(per_ip=1, window_seconds=3600, daily_total=1))
    for _ in range(5):
        am._authorize(_request({"x-api-key": "k"}), None)


def test_client_ip_prefers_forwarded_header():
    assert am.client_ip(_request({"x-forwarded-for": "5.6.7.8, 10.0.0.1"})) == "5.6.7.8"
    assert am.client_ip(_request(ip="4.4.4.4")) == "4.4.4.4"


def test_openapi_schema_is_not_public():
    """При заданном WEB_PASSWORD /docs выдавал устройство API всем желающим."""
    paths = [getattr(r, "path", "") for r in am.app.routes]
    assert "/docs" not in paths
    assert "/openapi.json" not in paths
    assert "/redoc" not in paths


# ---------- Старт без volume не должен ронять сервис ----------

async def test_init_storage_survives_failure(caplog):
    """Кеш и кластеризация объявлены необязательными, поэтому сбой init_db
    обязан деградировать, а не уводить контейнер в restart-loop."""
    async def broken():
        raise OSError("unable to open database file")

    am.storage_status["cache"] = "unknown"
    await am._init_storage("cache", broken)
    assert am.storage_status["cache"] == "unavailable"


async def test_init_storage_marks_ok():
    async def fine():
        return None

    await am._init_storage("cluster", fine)
    assert am.storage_status["cluster"] == "ok"


async def test_health_reports_storage_and_providers():
    body = await am.health()
    assert body["status"] == "ok"
    assert set(body["storage"]) == {"cache", "cluster", "history", "labels"}
    assert set(body["providers"]) == {"tronscan_key", "goplus_key", "swapster", "bitok"}
    assert "daily_limit" in body["rate_limit"]
    assert "web_protected" in body
