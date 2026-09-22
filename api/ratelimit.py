"""Лимиты на публичные проверки.

Зачем: каждая проверка адреса тратит платные лимиты двух KYT-сервисов. У бота
доступ fail-closed (пустой белый список не пускает никого), а веб до этого был
fail-open — при пустом WEB_PASSWORD эндпоинт /check отдавался всему интернету,
и любой мог сжечь квоту. Лимиты делают дефолты симметричными.

Две независимые границы:
  • на один IP за окно (RATE_LIMIT_PER_IP / RATE_LIMIT_WINDOW_SECONDS);
  • суточная на весь сервис (RATE_LIMIT_DAILY) — потолок расходов.

Состояние в памяти процесса: API и бот живут в одном контейнере, внешнего
хранилища для этого не нужно. При рестарте счётчики сбрасываются — для защиты
от случайного слива квоты этого достаточно, это не средство против DDoS.
"""
from __future__ import annotations

import os
import time
from collections import deque


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


PER_IP = _int_env("RATE_LIMIT_PER_IP", 20)
WINDOW_SECONDS = _int_env("RATE_LIMIT_WINDOW_SECONDS", 3600)
DAILY_TOTAL = _int_env("RATE_LIMIT_DAILY", 500)


class RateLimiter:
    """Скользящее окно на IP + суточный потолок на весь сервис."""

    def __init__(
        self,
        per_ip: int | None = None,
        window_seconds: int | None = None,
        daily_total: int | None = None,
    ) -> None:
        self.per_ip = PER_IP if per_ip is None else per_ip
        self.window = WINDOW_SECONDS if window_seconds is None else window_seconds
        self.daily_total = DAILY_TOTAL if daily_total is None else daily_total
        self._hits: dict[str, deque[float]] = {}
        self._day: deque[float] = deque()

    def _prune(self, now: float) -> None:
        while self._day and now - self._day[0] > 86400:
            self._day.popleft()
        # Освобождаем память по неактивным IP, иначе словарь растёт вечно.
        for ip, hits in list(self._hits.items()):
            while hits and now - hits[0] > self.window:
                hits.popleft()
            if not hits:
                del self._hits[ip]

    def check(self, ip: str, n: int = 1) -> tuple[bool, str]:
        """(разрешено, причина отказа) для N проверок разом. Отказ НЕ
        увеличивает счётчики.

        N нужен пакетной проверке: раньше пакет списывал квоту по одному адресу
        и падал на середине — квота уходила, а проверок не было ни одной."""
        now = time.time()
        self._prune(now)
        if self.daily_total > 0 and len(self._day) + n > self.daily_total:
            left = max(0, self.daily_total - len(self._day))
            return False, (
                f"Суточный лимит проверок исчерпан ({self.daily_total}, осталось "
                f"{left}). Лимит защищает платные квоты AML-сервисов."
            )
        hits = self._hits.get(ip) or deque()
        if self.per_ip > 0 and len(hits) + n > self.per_ip:
            if n > self.per_ip:
                return False, (
                    f"За раз можно проверить не больше {self.per_ip} адресов "
                    f"с одного IP (лимит на {self.window // 60} мин)."
                )
            retry_in = int(self.window - (now - hits[0])) + 1 if hits else self.window
            return False, (
                f"Слишком много проверок с одного адреса ({self.per_ip} за "
                f"{self.window // 60} мин). Попробуйте через {retry_in} с."
            )
        return True, ""

    def record(self, ip: str) -> None:
        """Зачесть успешно принятый запрос."""
        now = time.time()
        self._hits.setdefault(ip, deque()).append(now)
        self._day.append(now)

    def stats(self) -> dict[str, int]:
        self._prune(time.time())
        return {
            "per_ip_limit": self.per_ip,
            "window_seconds": self.window,
            "daily_limit": self.daily_total,
            "daily_used": len(self._day),
            "active_ips": len(self._hits),
        }
