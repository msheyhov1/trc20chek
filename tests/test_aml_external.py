"""Тесты интеграции Swapster (core/aml_external) — без реальных сетевых вызовов."""
import pytest

from core import aml_external as ax


def test_score_to_percent_fraction_and_percent():
    assert ax._score_to_percent(0.5) == 50.0      # доля 0..1
    assert ax._score_to_percent(1) == 100.0
    assert ax._score_to_percent(63) == 63.0       # уже проценты
    assert ax._score_to_percent(None) is None
    assert ax._score_to_percent("x") is None


def test_level_from_pct_thresholds():
    assert ax._level_from_pct(0) == "safe"
    assert ax._level_from_pct(24.9) == "safe"
    assert ax._level_from_pct(25) == "caution"
    assert ax._level_from_pct(74.9) == "caution"
    assert ax._level_from_pct(75) == "dangerous"
    assert ax._level_from_pct(None) is None


@pytest.mark.asyncio
async def test_check_not_configured(monkeypatch):
    monkeypatch.delenv("SWAPSTER_API_TOKEN", raising=False)
    res = await ax.check("T" + "x" * 33)
    assert res["available"] is False
    assert "не настроен" in res["reason"]


@pytest.mark.asyncio
async def test_check_maps_response(monkeypatch):
    """PUT возвращает reqId, POST — riskScore+entities; проверяем маппинг."""
    monkeypatch.setenv("SWAPSTER_API_TOKEN", "test-token")

    class FakeResp:
        def __init__(self, payload):
            self._p = payload
            self.status_code = 200
            self.headers = {}

        def raise_for_status(self):
            pass

        def json(self):
            return self._p

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def request(self, method, url, **kw):
            if method == "PUT":
                return FakeResp({"reqId": "req-123"})
            return FakeResp({
                "pending": False,
                "riskScore": 0.8,
                "entities": [
                    {"entity": "DARK_MARKET", "level": "HIGH_RISK", "riskScore": 0.9},
                    {"entity": "WALLET", "level": "LOW_RISK", "riskScore": 0.1},
                ],
            })

    monkeypatch.setattr(ax.httpx, "AsyncClient", FakeClient)

    res = await ax.check("T" + "y" * 33)
    assert res["available"] is True
    assert res["provider"] == "Swapster"
    assert res["pending"] is False
    assert res["risk_score"] == 80
    assert res["risk_level"] == "dangerous"
    assert res["entities"][0]["entity"] == "DARK MARKET"
    assert res["entities"][0]["risk_score"] == 90.0
