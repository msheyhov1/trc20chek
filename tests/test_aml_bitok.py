"""Тесты интеграции Bitok KYT (core/aml_bitok) — без реальных сетевых вызовов."""
import pytest

from core import aml_bitok as bk


# ---------- подпись ----------

def test_sign_with_body_known_vector():
    """Фиксированный вектор: подпись = base64(HMAC(secret, METHOD\\nEP\\nTS\\nBODY))."""
    sig = bk.sign(
        "secret", "POST", "/v1/manual-checks/check-address/", "1713449845309",
        '{"network":"TRX","address":"T1"}',
    )
    assert sig == "chIVyDVHhWFEpjgBQ7vJRkKRLQS8HB15W3qVS83+z7Q="


def test_sign_without_body_known_vector():
    """GET без тела — подписываются только METHOD/endpoint/timestamp."""
    assert bk.sign("secret", "GET", "/v1/manual-checks/42/", "1713449845309") == \
        "ruDQnT7jwsC3LoHUQGPTiAlQzTDK1QXobL7lMG1SDZw="


def test_headers_contain_auth_triplet(monkeypatch):
    monkeypatch.setenv("BITOK_API_KEY_ID", "key-1")
    monkeypatch.setenv("BITOK_API_SECRET", "secret")
    headers = bk._headers(bk._cfg(), "GET", "/v1/manual-checks/42/", None)
    assert headers["API-KEY-ID"] == "key-1"
    assert headers["API-TIMESTAMP"].isdigit() and len(headers["API-TIMESTAMP"]) == 13  # мс
    assert headers["API-SIGNATURE"]


# ---------- чистые хелперы ----------

def test_score_to_percent():
    assert bk._score_to_percent(0.42) == 42.0   # доля 0..1
    assert bk._score_to_percent(1) == 100.0
    assert bk._score_to_percent(63) == 63.0     # уже проценты
    assert bk._score_to_percent(None) is None
    assert bk._score_to_percent("x") is None


def test_category_ru_known_and_fallback():
    assert bk.category_ru("enforcement_action") == "правоохранительная блокировка"
    assert bk.category_ru("darknet_market") == "даркнет-маркет"
    assert bk.category_ru("brand_new_category") == "brand new category"
    assert bk.category_ru(None) == ""


def test_normalize_risks_maps_levels_and_sorts():
    out = bk._normalize_risks([
        {"entity_category": "exchange", "risk_level": "low", "value_share": 0.2,
         "proximity": "indirect"},
        {"entity_category": "darknet_market", "risk_level": "severe", "value_share": 0.7,
         "proximity": "direct"},
        {"risk_type": "mixer_use", "risk_level": "medium", "value_share": 0.5},
    ])
    assert [e["entity"] for e in out] == ["даркнет-маркет", "mixer use", "биржа"]
    assert [e["level"] for e in out] == ["HIGH_RISK", "MEDIUM_RISK", "LOW_RISK"]
    assert out[0]["risk_score"] == 70.0
    assert out[0]["proximity"] == "direct"


# ---------- сетевой слой (fake httpx) ----------

class FakeResp:
    def __init__(self, payload, status_code=200):
        self._p = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        return self._p


class FakeClient:
    """Подменяет httpx.AsyncClient: отдаёт заранее заданные ответы по (метод, путь)."""

    routes: dict = {}
    calls: list = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, **kw):
        path = url.split(".org", 1)[-1]
        FakeClient.calls.append((method, path))
        resp = FakeClient.routes[(method, path)]
        return resp() if callable(resp) else resp


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("BITOK_API_KEY_ID", "key-1")
    monkeypatch.setenv("BITOK_API_SECRET", "secret")
    monkeypatch.setattr(bk, "POLL_DELAY", 0)  # без реальных пауз в тестах
    monkeypatch.setattr(bk.httpx, "AsyncClient", FakeClient)
    FakeClient.calls = []
    yield


@pytest.mark.asyncio
async def test_check_not_configured(monkeypatch):
    monkeypatch.delenv("BITOK_API_KEY_ID", raising=False)
    monkeypatch.delenv("BITOK_API_SECRET", raising=False)
    res = await bk.check("T" + "x" * 33)
    assert res["available"] is False
    assert res["provider"] == "Bitok"
    assert "не настроен" in res["reason"]


@pytest.mark.asyncio
async def test_check_polls_until_checked_and_maps(configured):
    """POST заводит проверку (checking), GET поллится до checked, затем
    подтягиваются сущность и риски."""
    states = iter([
        FakeResp({"id": "abc", "check_status": "checking"}),
        FakeResp({"id": "abc", "check_status": "checked",
                  "risk_level": "severe", "risk_score": 1.0}),
    ])
    FakeClient.routes = {
        ("POST", "/v1/manual-checks/check-address/"):
            FakeResp({"id": "abc", "check_status": "checking"}),
        ("GET", "/v1/manual-checks/abc/"): lambda: next(states),
        ("GET", "/v1/manual-checks/abc/address-exposure/"):
            FakeResp({"entity_name": "Tether blacklist - TQ8a74",
                      "entity_category": "enforcement_action"}),
        ("GET", "/v1/manual-checks/abc/risks/"):
            FakeResp([{"entity_category": "enforcement_action", "risk_level": "severe",
                       "value_share": 1.0, "proximity": "direct"}]),
    }

    res = await bk.check("T" + "y" * 33)

    assert res["available"] is True and res["pending"] is False
    assert res["provider"] == "Bitok"
    assert res["risk_score"] == 100.0
    assert res["risk_level"] == "dangerous"       # severe → общая шкала проекта
    assert res["level_raw"] == "severe"
    assert res["entity"] == "Tether blacklist - TQ8a74"
    assert res["entity_category_ru"] == "правоохранительная блокировка"
    assert res["entities"][0]["level"] == "HIGH_RISK"
    # поллинг реально сходил за статусом второй раз
    assert FakeClient.calls.count(("GET", "/v1/manual-checks/abc/")) == 2


@pytest.mark.asyncio
async def test_check_clean_address(configured):
    FakeClient.routes = {
        ("POST", "/v1/manual-checks/check-address/"):
            FakeResp({"id": "ok", "check_status": "checked",
                      "risk_level": "none", "risk_score": 0.0}),
        ("GET", "/v1/manual-checks/ok/address-exposure/"): FakeResp({}),
        ("GET", "/v1/manual-checks/ok/risks/"): FakeResp([]),
    }
    res = await bk.check("T" + "z" * 33)
    assert res["risk_level"] == "safe" and res["risk_score"] == 0.0
    assert res["entity"] is None and res["entities"] == []


@pytest.mark.asyncio
async def test_exposure_failure_does_not_break_result(configured):
    """Сбой best-effort эндпоинтов не роняет проверку — риск всё равно вернётся."""
    FakeClient.routes = {
        ("POST", "/v1/manual-checks/check-address/"):
            FakeResp({"id": "ok", "check_status": "checked",
                      "risk_level": "medium", "risk_score": 0.5}),
        ("GET", "/v1/manual-checks/ok/address-exposure/"): FakeResp({"detail": "nope"}, 500),
        ("GET", "/v1/manual-checks/ok/risks/"): FakeResp({"detail": "nope"}, 500),
    }
    res = await bk.check("T" + "z" * 33)
    assert res["available"] is True
    assert res["risk_level"] == "caution" and res["risk_score"] == 50.0
    assert res["entity"] is None


@pytest.mark.asyncio
async def test_check_unauthorized(configured):
    FakeClient.routes = {
        ("POST", "/v1/manual-checks/check-address/"):
            FakeResp({"detail": "bad signature"}, 401),
    }
    res = await bk.check("T" + "z" * 33)
    assert res["available"] is False
    assert "ключ" in res["reason"]


@pytest.mark.asyncio
async def test_check_service_error_status(configured):
    FakeClient.routes = {
        ("POST", "/v1/manual-checks/check-address/"):
            FakeResp({"id": "err", "check_status": "error"}),
    }
    res = await bk.check("T" + "z" * 33)
    assert res["available"] is False
    assert "ошибкой" in res["reason"]
