import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Mapping, Optional

from services.role_contract import normalize_role


MAX_CLOCK_SKEW_SECONDS = 60


@dataclass(frozen=True)
class ControlPlanePrincipal:
    tenant_id: str
    user_id: str
    role: str


def signature_payload(timestamp: str, method: str, path: str, tenant_id: str, user_id: str, role: str) -> str:
    return "\n".join((timestamp, method.upper(), path, tenant_id, user_id, role.lower()))


def sign_control_plane_request(
    secret: str,
    timestamp: str,
    method: str,
    path: str,
    tenant_id: str,
    user_id: str,
    role: str,
) -> str:
    payload = signature_payload(timestamp, method, path, tenant_id, user_id, role)
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_control_plane_request(
    headers: Mapping[str, str],
    method: str,
    path: str,
    secret: str,
    now: Optional[int] = None,
) -> Optional[ControlPlanePrincipal]:
    if not secret:
        return None

    timestamp = headers.get("x-authclaw-timestamp", "")
    tenant_id = headers.get("x-authclaw-tenant-id", "")
    user_id = headers.get("x-authclaw-user-id", "")
    role = headers.get("x-authclaw-role", "")
    signature = headers.get("x-authclaw-signature", "")
    if not all((timestamp, tenant_id, user_id, role, signature)):
        return None

    try:
        request_time = int(timestamp)
    except ValueError:
        return None
    if abs((now if now is not None else int(time.time())) - request_time) > MAX_CLOCK_SKEW_SECONDS:
        return None

    expected = sign_control_plane_request(secret, timestamp, method, path, tenant_id, user_id, role)
    if not hmac.compare_digest(signature, expected):
        return None
    canonical_role = normalize_role(role)
    if not canonical_role:
        return None
    return ControlPlanePrincipal(tenant_id=tenant_id, user_id=user_id, role=canonical_role)
