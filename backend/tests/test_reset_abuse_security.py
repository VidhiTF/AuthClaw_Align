"""Regression coverage for reset abuse and connector authorization boundaries."""
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
import redis
from fastapi import HTTPException

from app.api.v1.endpoints import auth, onboarding


def request(ip="192.0.2.1"):
    return SimpleNamespace(client=SimpleNamespace(host=ip), headers={},
                           state=SimpleNamespace(user_id=uuid4(), tenant_id=uuid4()))


def test_reset_limits_before_lookup_and_delivery(monkeypatch):
    database = MagicMock()
    database.return_value.execute.return_value.all.return_value = []
    monkeypatch.setattr(auth, "OwnerSessionLocal", database)
    counts = {}
    def increment(_client, key, seconds):
        counts[key] = counts.get(key, 0) + 1
        return counts[key], seconds * 1000
    monkeypatch.setattr(onboarding, "_get_redis", lambda: object())
    monkeypatch.setattr(onboarding, "atomic_increment", increment)
    payload = auth.PasswordResetRequest(email="Person@example.com")
    for _ in range(5):
        auth.request_password_reset(payload, request())
    with pytest.raises(HTTPException) as caught:
        auth.request_password_reset(payload, request("192.0.2.2"))
    assert caught.value.status_code == 429
    assert database.call_count == 5


def test_reset_fails_closed_without_rate_store(monkeypatch):
    database = MagicMock()
    database.return_value.execute.return_value.all.return_value = []
    monkeypatch.setattr(auth, "OwnerSessionLocal", database)
    monkeypatch.setattr(onboarding, "_get_redis", MagicMock(side_effect=redis.ConnectionError()))
    with pytest.raises(HTTPException) as caught:
        auth.request_password_reset(auth.PasswordResetRequest(email="a@example.com"), request())
    assert caught.value.status_code == 503
    database.assert_not_called()


def test_reset_ip_limit_spans_accounts_and_ignores_forwarded_header(monkeypatch):
    database = MagicMock()
    database.return_value.execute.return_value.all.return_value = []
    monkeypatch.setattr(auth, "OwnerSessionLocal", database)
    counts = {}
    def increment(_client, key, seconds):
        counts[key] = counts.get(key, 0) + 1
        return counts[key], seconds * 1000
    monkeypatch.setattr(onboarding, "_get_redis", lambda: object())
    monkeypatch.setattr(onboarding, "atomic_increment", increment)
    for number in range(20):
        auth.request_password_reset(auth.PasswordResetRequest(email=f"p{number}@example.com"), request())
    attempt = request()
    attempt.headers["x-forwarded-for"] = "192.0.2.99"
    with pytest.raises(HTTPException) as caught:
        auth.request_password_reset(auth.PasswordResetRequest(email="other@example.com"), attempt)
    assert caught.value.status_code == 429
    assert database.call_count == 20
