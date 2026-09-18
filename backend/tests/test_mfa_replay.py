"""MFA success consumes a credential in the caller's database transaction."""

from uuid import uuid4

import pyotp
import pytest
from sqlalchemy import JSON, create_engine, update
from sqlalchemy.orm import Session

from app.core import auth
from app.db.models import User


@pytest.fixture
def mfa_user(monkeypatch):
    # SQLite exercises ORM refresh/commit semantics; PostgreSQL tests prove locking/RLS.
    for name in ("mfa_backup_codes", "mfa_pending_backup_codes"):
        column = User.__table__.c[name]
        monkeypatch.setattr(column, "type", column.type.with_variant(JSON(), "sqlite"))
    monkeypatch.setenv("AUTHCLAW_SECRET_PROVIDER", "env")
    monkeypatch.setenv("ENVELOPE_KEY", "test-mfa-encryption-key-32-bytes!!")
    monkeypatch.setenv("API_KEY_HASH_SECRET", "test-mfa-backup-key")
    engine = create_engine("sqlite://")
    User.__table__.create(engine)
    with Session(engine, autoflush=False) as db:
        secret = pyotp.random_base32()
        user = User(
            id=uuid4(), tenant_id=uuid4(), email="mfa@example.test", role="admin",
            is_active=True, mfa_enabled=True, mfa_secret=secret,
            mfa_backup_codes=["backup01"],
        )
        db.add(user)
        db.commit()
        yield db, user, secret
    engine.dispose()


def test_successful_totp_cannot_be_reused_after_commit(mfa_user):
    db, user, secret = mfa_user
    code = pyotp.TOTP(secret).now()
    assert auth.verify_mfa_code(user, code) is True
    db.commit()
    assert auth.verify_mfa_code(user, code) is False


def test_consumed_backup_code_survives_authoritative_refresh(mfa_user):
    db, user, _secret = mfa_user
    assert auth.verify_mfa_code(user, "BACKUP01") is True
    db.refresh(user)
    db.commit()
    assert auth.verify_mfa_code(user, "backup01") is False


def test_duplicate_backup_entries_are_consumed_together(mfa_user):
    db, user, _secret = mfa_user
    user.mfa_backup_codes = ["backup01", "backup01"]
    db.commit()
    assert auth.verify_mfa_code(user, "backup01") is True
    db.commit()
    assert auth.verify_mfa_code(user, "backup01") is False


@pytest.fixture
def clock(monkeypatch):
    now = [1_800_000_000]
    monkeypatch.setattr(auth.time, "time", lambda: now[0])
    return now


@pytest.mark.parametrize("offset,accepted", [(-2, False), (-1, True), (0, True), (1, True), (2, False)])
def test_only_current_and_adjacent_steps_are_accepted(mfa_user, clock, offset, accepted):
    db, user, secret = mfa_user
    code = pyotp.TOTP(secret).at(clock[0] + offset * 30)
    assert auth.verify_mfa_code(user, code) is accepted
    db.refresh(user)
    assert user.mfa_last_totp_step == (clock[0] // 30 + offset if accepted else None)


def test_monotonic_consumption_rejects_old_and_allows_next_step(mfa_user, clock):
    db, user, secret = mfa_user
    totp = pyotp.TOTP(secret)
    assert auth.verify_mfa_code(user, totp.at(clock[0])) is True
    db.commit()
    assert auth.verify_mfa_code(user, totp.at(clock[0] - 30)) is False
    clock[0] += 30
    assert auth.verify_mfa_code(user, totp.at(clock[0])) is True
    # A later authorization refresh cannot discard the consumed step.
    db.query(User).populate_existing().filter(User.id == user.id).one()
    assert auth.verify_mfa_code(user, totp.at(clock[0])) is False


def test_future_window_step_prevents_older_step_reuse(mfa_user, clock):
    db, user, secret = mfa_user
    totp = pyotp.TOTP(secret)
    assert auth.verify_mfa_code(user, totp.at(clock[0] + 30)) is True
    db.commit()
    assert auth.verify_mfa_code(user, totp.at(clock[0])) is False


@pytest.mark.parametrize("factor", ["totp", "backup"])
def test_rolled_back_action_can_retry_unconsumed_factor(mfa_user, factor):
    db, user, secret = mfa_user
    code = pyotp.TOTP(secret).now() if factor == "totp" else "backup01"
    assert auth.verify_mfa_code(user, code) is True
    db.rollback()
    assert auth.verify_mfa_code(user, code) is True
    db.commit()
    assert auth.verify_mfa_code(user, code) is False


@pytest.mark.parametrize("revocation", [{"is_active": False}, {"mfa_enabled": False}, {"mfa_secret": None}])
def test_database_revocation_overrides_cached_identity(mfa_user, revocation):
    db, user, secret = mfa_user
    db.execute(update(User).where(User.id == user.id).values(**revocation).execution_options(synchronize_session=False))
    assert auth.verify_mfa_code(user, pyotp.TOTP(secret).now()) is False
    assert auth.verify_mfa_code(user, "backup01") is False
    db.refresh(user)
    assert user.mfa_last_totp_step is None
    assert user.mfa_backup_codes == ["backup01"]


def test_verification_refreshes_credentials_without_flushing_local_changes(mfa_user):
    db, user, secret = mfa_user
    attacker_secret = pyotp.random_base32()
    user.mfa_secret = attacker_secret
    assert auth.verify_mfa_code(user, pyotp.TOTP(attacker_secret).now()) is False
    assert user.mfa_secret == secret
    assert auth.verify_mfa_code(user, pyotp.TOTP(secret).now()) is True


def test_detached_transient_and_changed_tenant_identities_fail_closed(mfa_user):
    db, user, secret = mfa_user
    code = pyotp.TOTP(secret).now()
    assert auth.verify_mfa_code(User(mfa_secret=secret, mfa_enabled=True), code) is False
    user.tenant_id = uuid4()
    assert auth.verify_mfa_code(user, code) is False
    db.refresh(user)
    db.expunge(user)
    assert auth.verify_mfa_code(user, code) is False
    assert auth.verify_mfa_code(object(), code) is False


def test_same_credential_rotation_preserves_replay_state(mfa_user, clock):
    db, user, secret = mfa_user
    code = pyotp.TOTP(secret).at(clock[0])
    assert auth.verify_mfa_code(user, code) is True
    consumed_step = user.mfa_last_totp_step
    auth.set_mfa_credentials(user, secret.lower(), ["replacement01"])
    db.commit()
    assert user.mfa_last_totp_step == consumed_step
    assert auth.verify_mfa_code(user, code) is False
    assert auth.verify_mfa_code(user, "backup01") is False
    assert auth.verify_mfa_code(user, "replacement01") is True


def test_new_credential_resets_replay_state(mfa_user, clock):
    db, user, secret = mfa_user
    assert auth.verify_mfa_code(user, pyotp.TOTP(secret).at(clock[0])) is True
    replacement = pyotp.random_base32()
    auth.set_mfa_credentials(user, replacement, ["replacement01"])
    db.commit()
    assert user.mfa_last_totp_step is None
    assert auth.verify_mfa_code(user, pyotp.TOTP(secret).at(clock[0])) is False
    assert auth.verify_mfa_code(user, pyotp.TOTP(replacement).at(clock[0])) is True
