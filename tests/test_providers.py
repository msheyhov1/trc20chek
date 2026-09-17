"""Тесты HTTP-слоя провайдеров.

До этого слой был почти не покрыт (33-41% по модулям), а именно в нём живёт
главное соглашение: провайдер, который не смог получить данные, обязан бросить
ProviderError, а не вернуть пустой результат. Иначе сбой источника неотличим от
«ничего не найдено», и отсутствие данных выглядит как отсутствие риска.
"""
from __future__ import annotations

import httpx
import pytest

from core.providers import flow, goplus, ofac, tronscan
from core.providers.base import ProviderError


class FakeResponse:
    def __init__(self, payload=None, status_code=200, text=""):
        self._payload = payload
        self.status_code = status_code
        self.text = text or ""

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}", request=None, response=None
            )

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeClient:
    """Клиент, отдающий заранее заданную последовательность ответов."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    async def get(self, url, **kw):
        self.calls.append({"url": url, **kw})
        item = self._responses.pop(0) if self._responses else FakeResponse(status_code=500)
        if isinstance(item, Exception):
            raise item
        return item


# ---------- TronScan ----------

@pytest.mark.asyncio
async def test_tronscan_returns_account_data():
    client = FakeClient([FakeResponse({"address": "T1", "publicTag": "Binance-Hot 4"})])
    data = await tronscan.fetch_account("T1", client)
    assert data["publicTag"] == "Binance-Hot 4"
    assert "/api/account" in client.calls[0]["url"]


@pytest.mark.asyncio
async def test_tronscan_raises_when_endpoint_fails_without_key(monkeypatch):
    monkeypatch.setattr(tronscan, "TRONSCAN_API_KEY", "")
    client = FakeClient([httpx.ConnectError("boom")])
    with pytest.raises(ProviderError) as exc:
        await tronscan.fetch_account("T1", client)
    assert "TronScan" in str(exc.value)


@pytest.mark.asyncio
async def test_tronscan_falls_back_to_accountv2_with_key(monkeypatch):
    monkeypatch.setattr(tronscan, "TRONSCAN_API_KEY", "key")
    client = FakeClient([
        FakeResponse(status_code=404),                 # /api/account недоступен
        FakeResponse({"address": "T1", "accountType": 2}),  # /api/accountv2 ответил
    ])
    data = await tronscan.fetch_account("T1", client)
    assert data["accountType"] == 2
    assert "/api/accountv2" in client.calls[1]["url"]


@pytest.mark.asyncio
async def test_tronscan_rejects_non_dict_body():
    client = FakeClient([FakeResponse([1, 2, 3]), FakeResponse([1, 2, 3])])
    with pytest.raises(ProviderError):
        await tronscan.fetch_account("T1", client)


# ---------- GoPlus ----------

@pytest.mark.asyncio
async def test_goplus_ok():
    client = FakeClient([FakeResponse({"code": 1, "result": {"cybercrime": "1"}})])
    data = await goplus.fetch_address_security("T1", client)
    assert data["result"]["cybercrime"] == "1"


@pytest.mark.asyncio
async def test_goplus_rate_limit_is_an_error_not_clean_result():
    """code != 1 — это «не проверили», а не «флагов нет»."""
    client = FakeClient([FakeResponse({"code": 4029, "message": "rate limit"})])
    with pytest.raises(ProviderError) as exc:
        await goplus.fetch_address_security("T1", client)
    assert "4029" in str(exc.value)


@pytest.mark.asyncio
async def test_goplus_network_error():
    client = FakeClient([httpx.ReadTimeout("slow")])
    with pytest.raises(ProviderError):
        await goplus.fetch_address_security("T1", client)


# ---------- flow ----------

@pytest.mark.asyncio
async def test_flow_returns_transfers_single_page(monkeypatch):
    monkeypatch.setattr(flow, "TRONSCAN_API_KEY", "")
    monkeypatch.setattr(flow, "FLOW_PAGES", 1)
    client = FakeClient([FakeResponse({"token_transfers": [{"quant": "1"}]})])
    out = await flow.fetch_transfers("T1", client)
    assert len(out) == 1
    assert client.calls[0]["params"]["start"] == 0
    assert client.calls[0]["params"]["limit"] == flow.TRANSFERS_LIMIT


@pytest.mark.asyncio
async def test_flow_retries_without_broken_key(monkeypatch):
    """Невалидный ключ ломает публичный эндпоинт — ретрай без ключа обязателен."""
    monkeypatch.setattr(flow, "TRONSCAN_API_KEY", "revoked")
    monkeypatch.setattr(flow, "FLOW_PAGES", 1)
    client = FakeClient([
        FakeResponse({"error": "ApiKey not exists"}),      # с ключом — тело-ошибка
        FakeResponse({"token_transfers": [{"quant": "5"}]}),  # без ключа — ок
    ])
    out = await flow.fetch_transfers("T1", client)
    assert len(out) == 1
    assert client.calls[0]["headers"].get("TRON-PRO-API-KEY") == "revoked"
    assert client.calls[1]["headers"] == {}


@pytest.mark.asyncio
async def test_flow_raises_when_all_attempts_fail(monkeypatch):
    monkeypatch.setattr(flow, "TRONSCAN_API_KEY", "")
    client = FakeClient([httpx.ConnectError("down")])
    with pytest.raises(ProviderError):
        await flow.fetch_transfers("T1", client)


@pytest.mark.asyncio
async def test_flow_pagination_appends_pages(monkeypatch):
    monkeypatch.setattr(flow, "TRONSCAN_API_KEY", "")
    monkeypatch.setattr(flow, "FLOW_PAGES", 3)
    full = [{"quant": str(i)} for i in range(flow.TRANSFERS_LIMIT)]
    client = FakeClient([
        FakeResponse({"token_transfers": full}),
        FakeResponse({"token_transfers": [{"quant": "x"}]}),   # короткая страница — конец
    ])
    out = await flow.fetch_transfers("T1", client)
    assert len(out) == flow.TRANSFERS_LIMIT + 1
    assert client.calls[1]["params"]["start"] == flow.TRANSFERS_LIMIT


@pytest.mark.asyncio
async def test_flow_keeps_first_page_when_later_page_fails(monkeypatch):
    """Неполный добор — не ошибка: работаем с тем, что получили."""
    monkeypatch.setattr(flow, "TRONSCAN_API_KEY", "")
    monkeypatch.setattr(flow, "FLOW_PAGES", 2)
    full = [{"quant": str(i)} for i in range(flow.TRANSFERS_LIMIT)]
    client = FakeClient([
        FakeResponse({"token_transfers": full}),
        httpx.ConnectError("down"),
    ])
    out = await flow.fetch_transfers("T1", client)
    assert len(out) == flow.TRANSFERS_LIMIT


# ---------- OFAC ----------

@pytest.fixture(autouse=True)
def _reset_ofac_cache():
    ofac._cache.update({"set": None, "ts": 0.0, "source": "none"})
    yield
    ofac._cache.update({"set": None, "ts": 0.0, "source": "none"})


@pytest.mark.asyncio
async def test_ofac_live_list():
    client = FakeClient([FakeResponse(text="TAddr1\nTAddr2\n\n# комментарий\n")])
    addrs = await ofac.fetch_sanctioned_set(client)
    assert addrs == {"TAddr1", "TAddr2"}
    assert ofac.last_source() == "live"


@pytest.mark.asyncio
async def test_ofac_uses_memory_cache_on_failure():
    ok = FakeClient([FakeResponse(text="TAddr1\n")])
    await ofac.fetch_sanctioned_set(ok)
    ofac._cache["ts"] = 0.0          # протухло — пойдёт в сеть и упадёт
    broken = FakeClient([httpx.ConnectError("no github")])
    addrs = await ofac.fetch_sanctioned_set(broken)
    assert addrs == {"TAddr1"}
    assert ofac.last_source() == "cache"


@pytest.mark.asyncio
async def test_ofac_falls_back_to_bundled_snapshot():
    """GitHub недоступен на холодном старте — проверка санкций не должна
    молча выключаться: берём вшитый снимок."""
    client = FakeClient([httpx.ConnectError("no github")])
    addrs = await ofac.fetch_sanctioned_set(client)
    assert len(addrs) > 200
    assert ofac.last_source() == "bundled"


@pytest.mark.asyncio
async def test_ofac_raises_only_when_nothing_available(monkeypatch, tmp_path):
    monkeypatch.setattr(ofac, "BUNDLED_PATH", tmp_path / "missing.txt")
    client = FakeClient([httpx.ConnectError("no github")])
    with pytest.raises(ProviderError):
        await ofac.fetch_sanctioned_set(client)
    assert ofac.last_source() == "none"


def test_bundled_snapshot_is_shipped_inside_package():
    """Файл должен лежать в core/, иначе не попадёт в Docker-образ:
    Dockerfile копирует только core/api/bot/web."""
    assert ofac.BUNDLED_PATH.exists()
    assert "core" in ofac.BUNDLED_PATH.parts
    assert len(ofac._bundled()) > 200
