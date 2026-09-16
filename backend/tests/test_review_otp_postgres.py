"""Run only against an explicitly supplied disposable REVIEW_DATABASE_URL."""
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import Column, MetaData, Table, create_engine, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from app.db.models import TrustCenterShare
from app.services import trust_center


@pytest.fixture
def sessions(monkeypatch):
    url = os.getenv("REVIEW_DATABASE_URL")
    if not url:
        pytest.skip("Dedicated review PostgreSQL not configured")
    assert make_url(url).database.endswith("_test")
    monkeypatch.setenv("AUTHCLAW_SESSION_KEY_VERSION", "v1")
    monkeypatch.setenv("SESSION_SECRET_V1", "review-only-session-key-32-characters")
    engine = create_engine(url)
    schema = "review_" + uuid4().hex
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    isolated = engine.execution_options(schema_translate_map={None: schema})
    metadata = MetaData()
    for name in ("tenants", "users"):
        Table(name, metadata, Column("id", UUID(as_uuid=True), primary_key=True))
    TrustCenterShare.__table__.to_metadata(metadata)
    metadata.create_all(isolated)
    try:
        yield sessionmaker(bind=isolated)
    finally:
        with engine.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        engine.dispose()


@pytest.mark.parametrize("code,successes,attempts", [("123456", 1, None), ("000000", 0, 5)])
def test_concurrent_otp_attempts_and_consumption(sessions, code, successes, attempts):
    tenant_id, share_id = uuid4(), uuid4()
    with sessions() as db:
        schema = db.bind.get_execution_options()["schema_translate_map"][None]
        db.execute(text(f'INSERT INTO "{schema}".tenants (id) VALUES (:id)'), {"id": tenant_id})
        share = TrustCenterShare(id=share_id, tenant_id=tenant_id, label="Review", auditor_email="auditor@example.com", token_hash=uuid4().hex, token_prefix="review", frameworks=["SOC2"], permissions=[], status="active", expires_at=trust_center.now_utc() + timedelta(days=1))
        share.metadata_json = {"auditor_otp_hash": trust_center._auditor_otp_hash(share, "123456"), "auditor_otp_expires_at": (trust_center.now_utc() + timedelta(minutes=5)).isoformat(), "auditor_otp_attempts": 0}
        db.add(share)
        db.commit()
    barrier = Barrier(8)
    def verify(_):
        with sessions() as db:
            share = db.get(TrustCenterShare, share_id)
            barrier.wait(timeout=10)  # Every transaction holds the same stale pre-check state.
            try:
                return trust_center.verify_auditor_otp(db, share, "review-share", code)
            except ValueError as error:
                return str(error)
    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(verify, range(8)))
    assert sum(isinstance(result, dict) for result in results) == successes
    with sessions() as db:
        metadata = db.get(TrustCenterShare, share_id).metadata_json
        assert metadata.get("auditor_otp_attempts") == attempts
        if successes:
            assert "auditor_otp_hash" not in metadata
        else:
            assert results.count("Too many invalid verification attempts") == 3
