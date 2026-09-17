"""Тесты провайдера блокировки USDT эмитентом (core/providers/tether.py)."""
from __future__ import annotations

import httpx
import pytest

from core.providers import tether
from core.providers.base import ProviderError

ADDR = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
ZERO = "0" * 64
ONE = "0" * 63 + "1"


class FakeResponse:
    def __init__(self, payload=None, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = ""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=None)

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeClient:
    def __init__(self, post=None, get=None):
        self._post = list(post or [])
        self._get = list(get or [])
        self.posts: list[dict] = []
        self.gets: list[dict] = []

    async def post(self, url, **kw):
        self.posts.append({"url": url, **kw})
        item = self._post.pop(0) if self._post else FakeResponse(status_code=500)
        if isinstance(item, Exception):
            raise item
        return item

    async def get(self, url, **kw):
        self.gets.append({"url": url, **kw})
        item = self._get.pop(0) if self._get else FakeResponse(status_code=500)
        if isinstance(item, Exception):
            raise item
        return item


# ---------- кодирование параметра ----------

def test_address_to_param_matches_abi_encoding():
    """20 байт адреса без префикса 41, дополненные слева до 32 байт."""
    p = tether.address_to_param(ADDR)
    assert len(p) == 64
    assert p.startswith("0" * 24)
    assert p.endswith("a614f803b6fd780986a42c78ec9c7f77e6ded13c")


def test_address_to_param_rejects_non_tron():
    with pytest.raises(ProviderError):
        tether.address_to_param("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")


def test_function_selector_case_matters():
    """isBlackListed (заглавная L) — у Tether есть; isBlacklisted — другая функция."""
    assert tether.FUNCTION_SELECTOR == "isBlackListed(address)"


# ---------- вызов контракта ----------

@pytest.mark.asyncio
async def test_contract_reports_blacklisted():
    client = FakeClient(post=[FakeResponse({"result": {"result": True}, "constant_result": [ONE]})])
    res = await tether.check(ADDR, client)
    assert res == {"blacklisted": True, "source": "contract"}
    body = client.posts[0]["json"]
    assert body["function_selector"] == "isBlackListed(address)"
    assert body["contract_address"] == tether.USDT_CONTRACT
    assert body["visible"] is True


@pytest.mark.asyncio
async def test_contract_reports_clean():
    client = FakeClient(post=[FakeResponse({"result": {"result": True}, "constant_result": [ZERO]})])
    res = await tether.check(ADDR, client)
    assert res["blacklisted"] is False


@pytest.mark.asyncio
async def test_empty_constant_result_is_unknown_not_clean():
    """Пустой ответ контракта — «не удалось проверить», а не «не заблокирован».
    Иначе сбой источника снова выглядел бы как отсутствие риска."""
    client = FakeClient(
        post=[FakeResponse({"result": {"result": True}})],
        get=[httpx.ConnectError("down")],
    )
    with pytest.raises(ProviderError) as exc:
        await tether.check(ADDR, client)
    assert "не вернул значение" in str(exc.value)


@pytest.mark.asyncio
async def test_rejected_call_is_an_error():
    client = FakeClient(
        post=[FakeResponse({"result": {"result": False, "message": "CONTRACT_VALIDATE_ERROR"}})],
        get=[httpx.ConnectError("down")],
    )
    with pytest.raises(ProviderError) as exc:
        await tether.check(ADDR, client)
    assert "CONTRACT_VALIDATE_ERROR" in str(exc.value)


@pytest.mark.asyncio
async def test_api_key_is_sent_when_configured(monkeypatch):
    monkeypatch.setattr(tether, "TRONGRID_API_KEY", "key-1")
    client = FakeClient(post=[FakeResponse({"result": {"result": True}, "constant_result": [ZERO]})])
    await tether.check(ADDR, client)
    assert client.posts[0]["headers"]["TRON-PRO-API-KEY"] == "key-1"


# ---------- запасной путь через TronScan ----------

@pytest.mark.asyncio
async def test_falls_back_to_tronscan_security_endpoint():
    client = FakeClient(
        post=[httpx.ConnectError("trongrid down")],
        get=[FakeResponse({"is_black_list": True})],
    )
    res = await tether.check(ADDR, client)
    assert res == {"blacklisted": True, "source": "tronscan"}
    assert "/api/security/account/data" in client.gets[0]["url"]


@pytest.mark.asyncio
async def test_raises_when_both_paths_fail():
    client = FakeClient(
        post=[httpx.ConnectError("trongrid down")],
        get=[FakeResponse({"something_else": 1})],
    )
    with pytest.raises(ProviderError) as exc:
        await tether.check(ADDR, client)
    assert "TronGrid" in str(exc.value)
    assert "is_black_list" in str(exc.value)


@pytest.mark.asyncio
async def test_disabled_by_env(monkeypatch):
    monkeypatch.setattr(tether, "ENABLED", False)
    with pytest.raises(ProviderError) as exc:
        await tether.check(ADDR, FakeClient())
    assert "выключена" in str(exc.value)
