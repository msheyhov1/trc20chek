"""Тесты лимитов на публичные проверки (api/ratelimit.py)."""
from __future__ import annotations

import time

from api.ratelimit import RateLimiter


def test_per_ip_limit_and_independence():
    rl = RateLimiter(per_ip=2, window_seconds=3600, daily_total=0)
    for _ in range(2):
        ok, _ = rl.check("a")
        assert ok
        rl.record("a")
    ok, reason = rl.check("a")
    assert not ok and "одного адреса" in reason
    ok, _ = rl.check("b")
    assert ok          # лимит на IP, не глобальный


def test_daily_limit_applies_across_ips():
    rl = RateLimiter(per_ip=0, window_seconds=3600, daily_total=3)
    for i in range(3):
        ok, _ = rl.check(f"ip{i}")
        assert ok
        rl.record(f"ip{i}")
    ok, reason = rl.check("ip-new")
    assert not ok and "Суточный лимит" in reason


def test_rejected_request_does_not_consume_quota():
    """Отказ не должен считаться попыткой — иначе лимит никогда не отпустит."""
    rl = RateLimiter(per_ip=1, window_seconds=3600, daily_total=0)
    rl.check("a")
    rl.record("a")
    before = rl.stats()["daily_used"]
    for _ in range(5):
        assert rl.check("a")[0] is False
    assert rl.stats()["daily_used"] == before


def test_window_expiry_releases_limit():
    rl = RateLimiter(per_ip=1, window_seconds=1, daily_total=0)
    rl.record("a")
    assert rl.check("a")[0] is False
    time.sleep(1.1)
    assert rl.check("a")[0] is True


def test_zero_limits_mean_unlimited():
    rl = RateLimiter(per_ip=0, window_seconds=3600, daily_total=0)
    for _ in range(50):
        assert rl.check("a")[0] is True
        rl.record("a")


def test_prune_releases_memory_for_idle_ips():
    """Словарь по IP не должен расти вечно."""
    rl = RateLimiter(per_ip=5, window_seconds=1, daily_total=0)
    for i in range(20):
        rl.record(f"ip{i}")
    assert rl.stats()["active_ips"] == 20
    time.sleep(1.1)
    assert rl.stats()["active_ips"] == 0


def test_stats_shape():
    rl = RateLimiter(per_ip=7, window_seconds=600, daily_total=9)
    s = rl.stats()
    assert s["per_ip_limit"] == 7
    assert s["window_seconds"] == 600
    assert s["daily_limit"] == 9
    assert s["daily_used"] == 0
