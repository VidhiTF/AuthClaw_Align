"""ORM timestamp defaults must produce aware UTC values."""

from datetime import timedelta
from inspect import unwrap

from sqlalchemy import DateTime, create_engine
from sqlalchemy.orm import Session

from app.db import models  # noqa: F401 - register models with Base metadata
from app.db.base import Base


def test_timestamp_defaults_and_updates_are_aware_utc():
    checked = 0
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if not isinstance(column.type, DateTime) or not column.type.timezone:
                continue
            for kind in ("default", "onupdate"):
                generated = getattr(column, kind)
                if generated is None or not generated.is_callable:
                    continue
                checked += 1
                value = unwrap(generated.arg)()
                assert value.utcoffset() == timedelta(0), f"{table.name}.{column.name} {kind}"
    assert checked >= 67


def test_orm_insert_and_update_generate_aware_utc_timestamps():
    engine = create_engine("sqlite://")
    try:
        models.Tenant.__table__.create(engine)
        with Session(engine) as db:
            tenant = models.Tenant(name="T12")
            db.add(tenant)
            db.flush()
            assert tenant.created_at.utcoffset() == timedelta(0)
            assert tenant.updated_at.utcoffset() == timedelta(0)
            inserted_updated_at = tenant.updated_at

            tenant.status = "suspended"
            db.flush()
            assert tenant.updated_at is not inserted_updated_at
            assert tenant.updated_at.utcoffset() == timedelta(0)
    finally:
        engine.dispose()
