from types import SimpleNamespace

from app.core.auth import get_tenant_db
from app.db.session import apply_tenant_context


class _Connection:
    def __init__(self):
        self.params = None

    def execute(self, _statement, params):
        self.params = params


def test_tenant_context_is_reapplied_after_commit_starts_a_transaction():
    db = SimpleNamespace(info={})
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="tenant-123"))
    dependency = get_tenant_db(request, db)

    assert next(dependency) is db
    connection = _Connection()
    apply_tenant_context(db, None, connection)
    assert connection.params == {"tenant_id": "tenant-123"}

    try:
        next(dependency)
    except StopIteration:
        pass
    assert "tenant_id" not in db.info
