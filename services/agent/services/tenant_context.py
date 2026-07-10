from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional


_tenant_id: ContextVar[Optional[str]] = ContextVar("authclaw_tenant_id", default=None)
_request_id: ContextVar[Optional[str]] = ContextVar("authclaw_request_id", default=None)
_tenant_required: ContextVar[bool] = ContextVar("authclaw_tenant_required", default=False)
_auth_lookup: ContextVar[bool] = ContextVar("authclaw_auth_lookup", default=False)


def get_current_tenant_id() -> Optional[str]:
    return _tenant_id.get()


def get_current_request_id() -> Optional[str]:
    return _request_id.get()


def is_tenant_context_required() -> bool:
    return _tenant_required.get()


def is_auth_lookup_context() -> bool:
    return _auth_lookup.get()


@contextmanager
def tenant_context(
    tenant_id: Optional[object],
    request_id: Optional[str] = None,
    required: bool = False,
) -> Iterator[None]:
    tenant_token = _tenant_id.set(str(tenant_id) if tenant_id is not None else None)
    request_token = _request_id.set(str(request_id) if request_id else None)
    required_token = _tenant_required.set(bool(required))
    try:
        yield
    finally:
        _tenant_required.reset(required_token)
        _request_id.reset(request_token)
        _tenant_id.reset(tenant_token)


@contextmanager
def auth_lookup_context() -> Iterator[None]:
    token = _auth_lookup.set(True)
    try:
        yield
    finally:
        _auth_lookup.reset(token)
