"""Общая настройка тестов.

Главное здесь — запрет реальных сетевых запросов.

Зачем: тест `test_contract_detection` не подменял `token_security.fetch`, и в
CI проверка контракта уходила на живой TronScan. Локально сеть была закрыта
политикой окружения, поэтому провайдер падал, ветка не выполнялась и тест был
зелёным; в CI сеть есть — и настоящий ответ по контракту USDT переклассифицировал
его в высокорисковый сервис. Тест, который проходит или падает в зависимости от
доступности интернета, бесполезен, а разницу между окружениями искать долго.

Теперь любой реальный HTTP-запрос из теста роняет его с понятным сообщением.
Подменяется именно ТРАНСПОРТ httpx, который открывает сокеты, а не `send`:
`TestClient` из FastAPI тоже построен на httpx, но ходит в приложение
в процессе через ASGITransport, и блокировать его нельзя. Тесты, которым нужен
«ответ сервера», подставляют свой клиент или мок функции провайдера.
"""
from __future__ import annotations

import httpx
import pytest


class NetworkAccessInTest(RuntimeError):
    """Тест попытался выйти в сеть."""


@pytest.fixture(autouse=True)
def _no_real_network(request, monkeypatch):
    """Блокирует реальные запросы. Снять: маркер @pytest.mark.allow_network."""
    if request.node.get_closest_marker("allow_network"):
        return

    def _blocked(*args, **kwargs):
        raise NetworkAccessInTest(
            "Тест попытался выполнить реальный HTTP-запрос. Подмените функцию "
            "провайдера (например core.aggregator.token_security.fetch) или "
            "передайте фейковый клиент. Иначе результат теста будет зависеть от "
            "доступности интернета: именно так дефект прошёл локально и упал в CI."
        )

    # Только реальный транспорт: ASGITransport (TestClient) не затрагивается.
    monkeypatch.setattr(
        httpx.AsyncHTTPTransport, "handle_async_request", _blocked, raising=False
    )
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _blocked, raising=False)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "allow_network: тесту разрешены реальные сетевые запросы"
    )


@pytest.fixture(autouse=True)
def _fresh_kyt_cache():
    """Кеш KYT живёт в памяти процесса: без очистки результат одного теста
    достался бы следующему, проверяющему тот же адрес с другим ответом."""
    from core import aggregator
    aggregator._kyt_cache.clear()
    yield
    aggregator._kyt_cache.clear()
