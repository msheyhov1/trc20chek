"""Тесты журнала проверок и ручных меток (core/history.py, core/labels.py)."""
from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import pytest

from core import history, labels
from core.models import AddressVerdict, EntityType, RiskLevel

A = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
B = "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"
EMPTY_GP = {"code": 1, "result": {"cybercrime": "0", "data_source": "GoPlus"}}


def _verdict(addr=A, level=RiskLevel.SAFE, score=0, entity="X"):
    v = AddressVerdict(address=addr)
    v.risk_level = level
    v.risk_score = score
    v.entity = entity
    v.entity_type = EntityType.WALLET
    return v


@pytest.fixture
def hist(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "HISTORY_PATH", tmp_path / "history.db")
    monkeypatch.setattr(history, "ENABLED", True)
    return history


@pytest.fixture
def lbl(tmp_path, monkeypatch):
    monkeypatch.setattr(labels, "LABELS_PATH", tmp_path / "labels.db")
    return labels


# ---------- журнал ----------

async def test_records_and_reads_back(hist):
    await hist.init_db()
    await hist.record(_verdict(score=42), source="bot")
    items = await hist.recent()
    assert len(items) == 1
    assert items[0]["address"] == A
    assert items[0]["risk_score"] == 42
    assert items[0]["source"] == "bot"


async def test_previous_returns_older_entry(hist):
    await hist.init_db()
    await hist.record(_verdict(level=RiskLevel.SAFE, score=10))
    await hist.record(_verdict(level=RiskLevel.DANGEROUS, score=90))
    prev = await hist.previous(A)
    # previous() отдаёт последнюю запись; в проверке она берётся ДО записи новой
    assert prev["risk_score"] == 90


async def test_recent_filters_by_address(hist):
    await hist.init_db()
    await hist.record(_verdict(addr=A))
    await hist.record(_verdict(addr=B))
    assert len(await hist.recent(address=A)) == 1
    assert len(await hist.recent()) == 2


async def test_stats_counts_by_level(hist):
    await hist.init_db()
    await hist.record(_verdict(level=RiskLevel.DANGEROUS, score=90))
    await hist.record(_verdict(addr=B, level=RiskLevel.SAFE))
    st = await hist.stats()
    assert st["enabled"] is True
    assert st["total"] == 2
    assert st["unique_addresses"] == 2
    assert st["last_24h"] == 2
    assert st["by_risk_level"]["dangerous"] == 1


async def test_prune_respects_max_rows(hist, monkeypatch):
    await hist.init_db()
    monkeypatch.setattr(hist, "MAX_ROWS", 2)
    monkeypatch.setattr(hist, "RETENTION_DAYS", 0)
    for _ in range(5):
        await hist.record(_verdict())
    assert await hist.prune() == 3
    assert len(await hist.recent(limit=100)) == 2


async def test_prune_respects_retention(hist, monkeypatch):
    await hist.init_db()
    monkeypatch.setattr(hist, "RETENTION_DAYS", 1)
    monkeypatch.setattr(hist, "MAX_ROWS", 0)
    await hist.record(_verdict())
    import aiosqlite
    async with aiosqlite.connect(hist.HISTORY_PATH) as db:
        await db.execute("UPDATE checks SET checked_at = ?", (time.time() - 10 * 86400,))
        await db.commit()
    assert await hist.prune() == 1
    assert await hist.recent() == []


async def test_history_failure_never_breaks_a_check(monkeypatch, tmp_path):
    """Журнал необязательный: недоступный диск не должен ронять проверку."""
    monkeypatch.setattr(history, "HISTORY_PATH", tmp_path / "nope" / "h.db")
    monkeypatch.setattr(history, "ENABLED", True)
    await history.record(_verdict())          # не бросает
    assert await history.recent() == []
    assert await history.previous(A) is None


async def test_disabled_history_is_inert(monkeypatch):
    monkeypatch.setattr(history, "ENABLED", False)
    await history.init_db()
    await history.record(_verdict())
    assert await history.recent() == []
    assert (await history.stats())["enabled"] is False
    assert await history.prune() == 0


# ---------- сравнение с прошлым результатом в вердикте ----------

async def test_verdict_reports_risk_change(hist):
    """Смена уровня у того же адреса — самостоятельная находка: вчера «чисто»,
    сегодня блэклист."""
    from core.aggregator import check_address
    await hist.init_db()
    await hist.record(_verdict(level=RiskLevel.SAFE, score=5))

    with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
         patch("core.aggregator.goplus.fetch_address_security", new=AsyncMock(return_value=EMPTY_GP)), \
         patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=[])), \
         patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value={A})), \
         patch("core.aggregator.tether.check",
               new=AsyncMock(return_value={"blacklisted": False, "source": "contract"})), \
         patch("core.aggregator.aml_external.check",
               new=AsyncMock(return_value={"available": False, "reason": "не настроен"})), \
         patch("core.aggregator.aml_bitok.check",
               new=AsyncMock(return_value={"available": False, "reason": "не настроен"})):
        v = await check_address(A, use_cache=False)

    assert v.raw_labels["previous_check"]["risk_level"] == "safe"
    assert any("Вердикт изменился" in f and "⬆️" in f for f in v.risk_flags)


# ---------- метки ----------

async def test_put_get_delete(lbl):
    await lbl.init_db()
    await lbl.put(A, entity="Наш кошелёк", entity_type="labeled", risk_level="safe", author="42")
    assert lbl.lookup(A) == {"entity": "Наш кошелёк", "entity_type": "labeled", "risk_level": "safe"}
    assert lbl.count() == 1
    assert await lbl.delete(A) is True
    assert lbl.lookup(A) is None
    assert await lbl.delete(A) is False


async def test_invalid_enum_values_are_dropped_with_warning(lbl, caplog):
    await lbl.init_db()
    await lbl.put(A, entity="X", entity_type="кто-то", risk_level="очень плохо")
    stored = lbl.lookup(A)
    assert "entity_type" not in stored
    assert "risk_level" not in stored
    assert "неизвестный" in caplog.text


async def test_seed_from_local_py_does_not_overwrite_operator_edits(lbl):
    seed = {A: {"entity": "Из кода", "entity_type": "labeled", "risk_level": "safe"}}
    await lbl.init_db(seed)
    assert lbl.lookup(A)["entity"] == "Из кода"
    await lbl.put(A, entity="Правка оператора", risk_level="dangerous")
    await lbl.init_db(seed)          # повторный старт сервиса
    assert lbl.lookup(A)["entity"] == "Правка оператора"


async def test_all_labels_lists_author(lbl):
    await lbl.init_db()
    await lbl.put(A, entity="X", author="777")
    items = await lbl.all_labels()
    assert items[0]["author"] == "777"


async def test_db_label_takes_priority_over_local_py(lbl):
    """Метка из БД должна побеждать предзаданную в коде: её правит оператор."""
    from core.aggregator import check_address
    from core.providers import local as local_provider

    await lbl.init_db()
    await lbl.put(A, entity="Из базы", entity_type="labeled", risk_level="safe")
    local_provider.LOCAL_LABELS[A] = {"entity": "Из кода", "risk_level": "dangerous"}
    try:
        with patch("core.aggregator.tronscan.fetch_account", new=AsyncMock(return_value={})), \
             patch("core.aggregator.goplus.fetch_address_security",
                   new=AsyncMock(return_value=EMPTY_GP)), \
             patch("core.aggregator.flow.fetch_transfers", new=AsyncMock(return_value=[])), \
             patch("core.aggregator.ofac.fetch_sanctioned_set", new=AsyncMock(return_value=set())), \
             patch("core.aggregator.tether.check",
                   new=AsyncMock(return_value={"blacklisted": False, "source": "contract"})), \
             patch("core.aggregator.history.record", new=AsyncMock()), \
             patch("core.aggregator.history.previous", new=AsyncMock(return_value=None)), \
             patch("core.aggregator.aml_external.check",
                   new=AsyncMock(return_value={"available": False, "reason": "не настроен"})), \
             patch("core.aggregator.aml_bitok.check",
                   new=AsyncMock(return_value={"available": False, "reason": "не настроен"})):
            v = await check_address(A, use_cache=False)
    finally:
        del local_provider.LOCAL_LABELS[A]
        await lbl.delete(A)
    assert v.entity == "Из базы"
    assert v.risk_level == RiskLevel.SAFE
