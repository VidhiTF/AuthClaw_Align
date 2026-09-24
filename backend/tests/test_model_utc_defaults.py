"""ORM timestamp defaults must produce aware UTC values."""

from datetime import timedelta

from sqlalchemy import DateTime

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
                value = generated.arg(None)
                assert value.utcoffset() == timedelta(0), f"{table.name}.{column.name} {kind}"
    assert checked >= 67
