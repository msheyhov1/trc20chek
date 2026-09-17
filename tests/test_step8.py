"""Тесты бюджета проверки, дедупликации, мониторинга и пакетной проверки."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from core import watchlist
from core.models import AddressVerdict, EntityType, RiskLevel

A = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
B = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"
EMPTY_GP = {"code": 1, "result": {"cybercrime": "0", "data_source": "GoPlus"}}
NO_AML = {"available": False, "reason": "не настроен"}


def _base_patches(**over):
    p = {
        "core.aggregator.tronscan.fetch_account": AsyncMock(return_value={}),
        "core.aggregator.goplus.fetch_address_security": AsyncMock(return_value=EMPTY_GP),
        "core.aggregator.flow.fetch_transfers": AsyncMock(return_value=[]),
        "core.aggregator.ofac.fetch_sanctioned_set": AsyncMock(return_value=set()),
        "core.aggregator.tether.check":
            AsyncMock(return_value={"blacklisted": False, "source": "contract"}),
        "core.aggregator.aml_external.check": AsyncMock(return_value=dict(NO_AML)),
        "core.aggregator.aml_bitok.check": AsyncMock(return_value=dict(NO_AML)),
        "core.aggregator.history.record": AsyncMock(),
        "core.aggregator.history.previous": AsyncMock(return_value=None),
    }
    p.update(over)
    return p


# ---------- дедупликация одновременных проверок ----------

async def test_concurrent_checks_of_same_address_run_once():
    """Два пользователя нажали «проверить» на одном адресе: раньше это были
    два похода в Swapster и Bitok, то есть двойная оплата."""
    from core.aggregator import check_address

    calls = {"n": 0}

    async def slow_bitok(addr):
        calls["n"] += 1
        await asyncio.sleep(0.05)
        return dict(NO_AML)

    ctx = [patch(k, new=v) for k, v in
           _base_patches(**{"core.aggregator.aml_bitok.check": slow_bitok}).items()]
    for c in ctx:
        c.start()
    try:
        a, b = await asyncio.gather(
            check_address(A, use_cache=False), check_address(A, use_cache=False)
        )
    finally:
        for c in ctx:
            c.stop()
    assert calls["n"] == 1                 # платный KYT вызван один раз
    assert a.address == b.address == A


async def test_different_addresses_are_not_deduplicated():
    from core.aggregator import check_address

    calls = {"n": 0}

    async def counting(addr):
        calls["n"] += 1
        return dict(NO_AML)

    ctx = [patch(k, new=v) for k, v in
           _base_patches(**{"core.aggregator.aml_bitok.check": counting}).items()]
    for c in ctx:
        c.start()
    try:
        await asyncio.gather(
            check_address(A, use_cache=False), check_address(B, use_cache=False)
        )
    finally:
        for c in ctx:
            c.stop()
    assert calls["n"] == 2


async def test_inflight_registry_is_cleaned_up():
    from core.aggregator import check_address, inflight_count

    ctx = [patch(k, new=v) for k, v in _base_patches().items()]
    for c in ctx:
        c.start()
    try:
        await check_address(A, use_cache=False)
    finally:
        for c in ctx:
            c.stop()
    assert inflight_count() == 0


# ---------- общий бюджет проверки ----------

async def test_budget_returns_partial_verdict_with_warning(monkeypatch):
    """По истечении бюджета отдаём то, что успели, с честной пометкой —
    это полезнее, чем бот, который молча держит пользователя минутами."""
    from core import aggregator as agg

    monkeypatch.setattr(agg, "CHECK_BUDGET_SECONDS", 0.2)

    async def hanging_bitok(addr):
        await asyncio.sleep(5)
        return dict(NO_AML)

    # Серая метка, а НЕ биржевая: биржа попадает в туннель, и платные KYT
    # вообще не вызываются — тогда и подвиснуть было бы нечему.
    ts = {"address": A, "greyTag": "Подозрительный адрес"}
    ctx = [patch(k, new=v) for k, v in _base_patches(**{
        "core.aggregator.aml_bitok.check": hanging_bitok,
        "core.aggregator.tronscan.fetch_account": AsyncMock(return_value=ts),
    }).items()]
    for c in ctx:
        c.start()
    try:
        v = await agg.check_address(A, use_cache=False)
    finally:
        for c in ctx:
            c.stop()
    assert any("прервана по таймауту" in f for f in v.risk_flags)
    assert v.checked_at is not None
    # то, что успели узнать до таймаута, сохранилось
    assert v.entity == "Подозрительный адрес"
    assert v.provider_status["bitok"] == "timeout"


async def test_budget_disabled_by_zero(monkeypatch):
    from core import aggregator as agg

    monkeypatch.setattr(agg, "CHECK_BUDGET_SECONDS", 0)
    ctx = [patch(k, new=v) for k, v in _base_patches().items()]
    for c in ctx:
        c.start()
    try:
        v = await agg.check_address(A, use_cache=False)
    finally:
        for c in ctx:
            c.stop()
    assert not any("таймауту" in f for f in v.risk_flags)


# ---------- мониторинг ----------

@pytest.fixture
def wl(tmp_path, monkeypatch):
    monkeypatch.setattr(watchlist, "WATCHLIST_PATH", tmp_path / "watch.db")
    monkeypatch.setattr(watchlist, "ENABLED", True)
    return watchlist


def _verdict(level=RiskLevel.DANGEROUS, score=90):
    v = AddressVerdict(address=A)
    v.risk_level = level
    v.risk_score = score
    v.entity = "Что-то плохое"
    v.entity_type = EntityType.SCAM
    return v


async def test_add_list_remove(wl):
    await wl.init_db()
    ok, note = await wl.add(A, 555)
    assert ok and "наблюдением" in note
    items = await wl.list_for(555)
    assert [i["address"] for i in items] == [A]
    assert await wl.remove(A, 555) is True
    assert await wl.list_for(555) == []


async def test_per_user_limit(wl, monkeypatch):
    """Каждая перепроверка платная, поэтому лимит на пользователя обязателен."""
    await wl.init_db()
    monkeypatch.setattr(wl, "MAX_PER_USER", 1)
    assert (await wl.add(A, 1))[0] is True
    ok, note = await wl.add(B, 1)
    assert ok is False and "лимит" in note


async def test_due_respects_interval(wl, monkeypatch):
    await wl.init_db()
    await wl.add(A, 1)
    monkeypatch.setattr(wl, "INTERVAL_SECONDS", 3600)
    assert len(await wl.due()) == 1          # last_check = 0 → пора
    await wl.mark_checked(A, 1, "safe", 5)
    assert await wl.due() == []              # только что проверяли


async def test_tick_notifies_only_on_change(wl):
    await wl.init_db()
    await wl.add(A, 777)
    sent: list[tuple[int, str]] = []

    async def notify(chat_id, text):
        sent.append((chat_id, text))

    # первый проход: прошлого уровня нет — молчим, только запоминаем
    await wl.tick(AsyncMock(return_value=_verdict(RiskLevel.SAFE, 0)), notify)
    assert sent == []

    # тот же уровень — по-прежнему молчим: рассылка «всё как было» это спам
    await wl.mark_checked(A, 777, "safe", 0)
    wl.INTERVAL_SECONDS = 0
    await wl.tick(AsyncMock(return_value=_verdict(RiskLevel.SAFE, 0)), notify)
    assert sent == []

    # уровень изменился — уведомляем
    await wl.tick(AsyncMock(return_value=_verdict(RiskLevel.DANGEROUS, 90)), notify)
    assert len(sent) == 1
    chat_id, text = sent[0]
    assert chat_id == 777
    assert "Риск вырос" in text
    assert "safe" in text and "dangerous" in text


async def test_tick_survives_failing_check(wl):
    await wl.init_db()
    await wl.add(A, 1)
    wl.INTERVAL_SECONDS = 0
    notify = AsyncMock()
    await wl.tick(AsyncMock(side_effect=RuntimeError("провайдер упал")), notify)
    notify.assert_not_awaited()          # не уведомляем и не падаем


async def test_run_loop_stops_on_event(wl, monkeypatch):
    await wl.init_db()
    monkeypatch.setattr(wl, "TICK_SECONDS", 1)
    stop = asyncio.Event()
    task = asyncio.create_task(wl.run_loop(AsyncMock(), AsyncMock(), stop))
    await asyncio.sleep(0.05)
    stop.set()
    await asyncio.wait_for(task, timeout=3)


async def test_disabled_watchlist_is_inert(monkeypatch):
    monkeypatch.setattr(watchlist, "ENABLED", False)
    ok, note = await watchlist.add(A, 1)
    assert ok is False and "выключен" in note
    assert await watchlist.list_for(1) == []
    assert await watchlist.due() == []
    assert (await watchlist.stats())["enabled"] is False


async def test_stats_shape(wl):
    await wl.init_db()
    await wl.add(A, 1)
    await wl.add(A, 2)
    st = await wl.stats()
    assert st["subscriptions"] == 2
    assert st["addresses"] == 1
    assert st["users"] == 2


def test_change_text_direction():
    up = watchlist._change_text(_verdict(RiskLevel.DANGEROUS, 90), "safe", 0)
    down = watchlist._change_text(_verdict(RiskLevel.SAFE, 0), "dangerous", 90)
    assert "Риск вырос" in up
    assert "Риск снизился" in down


# ---------- пакетная проверка через API ----------

@pytest.fixture
def client(monkeypatch):
    import api.main as am
    from api.ratelimit import RateLimiter
    monkeypatch.setattr(am, "limiter", RateLimiter(per_ip=0, window_seconds=3600, daily_total=0))
    monkeypatch.setattr(am, "WEB_PASSWORD", "")
    monkeypatch.setattr(am, "API_KEY", "")
    monkeypatch.setattr(am, "WEB_PUBLIC", True)
    from fastapi.testclient import TestClient
    return TestClient(am.app)


def test_batch_checks_all_addresses(client):
    v = AddressVerdict(address=A)
    v.risk_level = RiskLevel.SAFE
    with patch("api.main.check_address", new=AsyncMock(return_value=v)) as m:
        r = client.post("/check/batch", json={"addresses": [A, B]})
    assert r.status_code == 200
    assert len(r.json()["results"]) == 2
    assert m.await_count == 2


def test_batch_reports_invalid_address_per_item(client):
    v = AddressVerdict(address=A)
    with patch("api.main.check_address", new=AsyncMock(return_value=v)):
        r = client.post("/check/batch", json={"addresses": [A, "BAD"]})
    results = r.json()["results"]
    assert results[1]["error"] == "Invalid TRC20 address format"


def test_batch_rejects_oversized_request(client, monkeypatch):
    import api.main as am
    monkeypatch.setattr(am, "BATCH_MAX", 2)
    r = client.post("/check/batch", json={"addresses": [A, B, A]})
    assert r.status_code == 400
    assert "не больше 2" in r.json()["detail"]


def test_batch_consumes_rate_limit_per_address(client, monkeypatch):
    """Иначе батч обходил бы суточную квоту одним запросом."""
    import api.main as am
    from api.ratelimit import RateLimiter
    monkeypatch.setattr(am, "limiter", RateLimiter(per_ip=2, window_seconds=3600, daily_total=0))
    v = AddressVerdict(address=A)
    with patch("api.main.check_address", new=AsyncMock(return_value=v)):
        r = client.post("/check/batch", json={"addresses": [A, B, A]})
    assert r.status_code == 429


def test_stats_includes_watchlist_and_inflight(client):
    r = client.get("/stats")
    assert r.status_code == 200
    body = r.json()
    assert "watchlist" in body
    assert "in_flight" in body
