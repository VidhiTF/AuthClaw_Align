import os

from sqlalchemy.engine import make_url


def destructive_test_urls() -> tuple[str, str]:
    owner_url = os.getenv("TEST_OWNER_DATABASE_URL", "")
    app_url = os.getenv("TEST_DATABASE_URL", "")
    for name, value in (
        ("TEST_OWNER_DATABASE_URL", owner_url),
        ("TEST_DATABASE_URL", app_url),
        ("OWNER_DATABASE_URL", os.getenv("OWNER_DATABASE_URL", "")),
        ("DATABASE_URL", os.getenv("DATABASE_URL", "")),
    ):
        database = make_url(value).database if value else ""
        if not database or not database.endswith("_test"):
            raise RuntimeError(f"{name} must explicitly target a database ending in _test")
    return owner_url, app_url
