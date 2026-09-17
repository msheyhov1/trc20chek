"""Тесты HTTP-эндпоинтов через TestClient.

Раньше проверялась только функция require_web_auth в отрыве от роутов: тесты
оставались зелёными, даже если гейт снять с эндпоинта. Здесь ходим по реальным
URL приложения.
"""
from __future__ import annotations

import base64
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import api.main as am
from core.models import AddressVerdict, EntityType, RiskLevel

VALID = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


@pytest.fixture
def client(monkeypatch, tmp_path):
    """Клиент без запуска lifespan: бот и SQLite в этих тестах не нужны."""
    from api.ratelimit import RateLimiter
    monkeypatch.setattr(am, "limiter", RateLimiter(per_ip=0, window_seconds=3600, daily_total=0))
    monkeypatch.setattr(am, "WEB_PASSWORD", "")
    monkeypatch.setattr(am, "API_KEY", "")
    monkeypatch.setattr(am, "WEB_PUBLIC", True)
    return TestClient(am.app)


def _verdict() -> AddressVerdict:
    v = AddressVerdict(address=VALID)
    v.entity = "Binance"
    v.entity_type = EntityType.EXCHANGE
    v.risk_level = RiskLevel.SAFE
    v.checked_at = "2026-09-17T22:19:00+00:00"
    return v


def test_health_is_open_and_reports_state(client):
    """Railway healthcheck не должен зависеть ни от пароля, ни от бота."""
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert "storage" in body and "providers" in body and "rate_limit" in body


def test_check_returns_verdict(client):
    with patch("api.main.check_address", new=AsyncMock(return_value=_verdict())) as m:
        r = client.get(f"/check/{VALID}")
    assert r.status_code == 200
    body = r.json()
    assert body["address"] == VALID
    assert body["entity_type_ru"] == "Биржа"
    assert body["risk_level_ru"] == "БЕЗОПАСНО"
    assert body["checked_at"] == "2026-09-17T22:19:00+00:00"
    # по умолчанию свежая проверка, кеш только по явному ?cache=true
    assert m.await_args.kwargs["use_cache"] is False


def test_check_cache_opt_in(client):
    with patch("api.main.check_address", new=AsyncMock(return_value=_verdict())) as m:
        client.get(f"/check/{VALID}?cache=true")
    assert m.await_args.kwargs["use_cache"] is True


def test_check_rejects_invalid_address(client):
    r = client.get("/check/INVALID")
    assert r.status_code == 400
    assert "Invalid TRC20" in r.json()["detail"]


def test_check_rejects_bad_checksum(client):
    r = client.get("/check/TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6X")
    assert r.status_code == 400


def test_check_closed_without_any_protection(client, monkeypatch):
    """Асимметрия с ботом устранена: без пароля, ключа и WEB_PUBLIC — 503."""
    monkeypatch.setattr(am, "WEB_PUBLIC", False)
    r = client.get(f"/check/{VALID}")
    assert r.status_code == 503
    assert "WEB_PUBLIC" in r.json()["detail"]


def test_check_requires_api_key_when_set(client, monkeypatch):
    monkeypatch.setattr(am, "API_KEY", "s3cret")
    assert client.get(f"/check/{VALID}").status_code == 401
    with patch("api.main.check_address", new=AsyncMock(return_value=_verdict())):
        assert client.get(f"/check/{VALID}", headers={"X-API-Key": "s3cret"}).status_code == 200
        assert client.get(f"/check/{VALID}?api_key=s3cret").status_code == 200
    assert client.get(f"/check/{VALID}?api_key=wrong").status_code == 401


def test_check_requires_basic_auth_when_password_set(client, monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "pw")
    monkeypatch.setattr(am, "WEB_USER", "admin")
    r = client.get(f"/check/{VALID}")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate", "").startswith("Basic")

    token = base64.b64encode(b"admin:pw").decode()
    with patch("api.main.check_address", new=AsyncMock(return_value=_verdict())):
        ok = client.get(f"/check/{VALID}", headers={"Authorization": f"Basic {token}"})
    assert ok.status_code == 200


def test_index_is_behind_the_same_gate(client, monkeypatch):
    assert client.get("/").status_code == 200
    monkeypatch.setattr(am, "WEB_PASSWORD", "pw")
    assert client.get("/").status_code == 401


def test_rate_limit_returns_429(client, monkeypatch):
    from api.ratelimit import RateLimiter
    monkeypatch.setattr(am, "limiter", RateLimiter(per_ip=1, window_seconds=3600, daily_total=0))
    with patch("api.main.check_address", new=AsyncMock(return_value=_verdict())):
        assert client.get(f"/check/{VALID}").status_code == 200
        r = client.get(f"/check/{VALID}")
    assert r.status_code == 429
    assert "Слишком много" in r.json()["detail"]


def test_api_schema_endpoints_are_not_exposed(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404, path


def test_static_files_are_served(client):
    r = client.get("/static/app.js")
    assert r.status_code == 200
    assert "entity_type_ru" in r.text      # веб использует подписи из API
