"""Тесты пароля на веб-сайт (HTTP Basic Auth)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

import api.main as am


def _creds(user: str, pw: str):
    c = MagicMock()
    c.username, c.password = user, pw
    return c


def test_web_auth_disabled(monkeypatch):
    """WEB_PASSWORD пуст → сайт открыт, креды не нужны."""
    monkeypatch.setattr(am, "WEB_PASSWORD", "")
    assert am.require_web_auth(None) is None
    assert am.require_web_auth(_creds("x", "y")) is None


def test_web_auth_correct(monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "s3cret")
    monkeypatch.setattr(am, "WEB_USER", "admin")
    assert am.require_web_auth(_creds("admin", "s3cret")) is None


def test_web_auth_missing_credentials(monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "s3cret")
    with pytest.raises(HTTPException) as exc:
        am.require_web_auth(None)
    assert exc.value.status_code == 401
    assert exc.value.headers.get("WWW-Authenticate", "").startswith("Basic")


def test_web_auth_wrong_password(monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "s3cret")
    monkeypatch.setattr(am, "WEB_USER", "admin")
    with pytest.raises(HTTPException):
        am.require_web_auth(_creds("admin", "nope"))


def test_web_auth_wrong_user(monkeypatch):
    monkeypatch.setattr(am, "WEB_PASSWORD", "s3cret")
    monkeypatch.setattr(am, "WEB_USER", "admin")
    with pytest.raises(HTTPException):
        am.require_web_auth(_creds("hacker", "s3cret"))
