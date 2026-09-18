"""Console-to-agent HMAC v2; see docs/ENT-018-protocol.md."""

import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import quote, unquote_plus

from services.role_contract import normalize_role

MAX_CLOCK_SKEW_SECONDS = 60
MAX_MFA_ASSERTION_AGE_SECONDS = 60
NONCE_TTL_SECONDS = 2 * MAX_CLOCK_SKEW_SECONDS + 1
MAX_BODY_BYTES = 1024 * 1024
BASE_HEADER_FIELDS = (
    "version",
    "timestamp",
    "nonce",
    "service",
    "audience",
    "key-id",
    "tenant-id",
    "user-id",
    "role",
    "signature",
)
MFA_HEADER_FIELDS = (
    "mfa-verified-at",
    "mfa-operation",
    "mfa-body-sha256",
    "mfa-assertion-id",
)
HEADER_FIELDS = BASE_HEADER_FIELDS + MFA_HEADER_FIELDS
# Wait out signatures accepted before Redis restart/promotion. The deployment
# must use noeviction so a stable node never evicts a consumed nonce early.
NONCE_SCRIPT = """
local run = string.match(redis.call('INFO', 'server'), 'run_id:([^%s]+)')
local generation = string.match(redis.call('INFO', 'replication'), 'master_replid:([^%s]+)')
local clock = tonumber(redis.call('TIME')[1])
if math.abs(clock - tonumber(ARGV[2])) > tonumber(ARGV[3]) then return 0 end
local gate = 'authclaw:service:v2:startup:' .. run .. ':' .. generation
redis.call('SET', gate, clock, 'NX')
if clock - tonumber(redis.call('GET', gate)) <= tonumber(ARGV[1]) then return -1 end
if redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1]) then return 1 end
return 0
"""


@dataclass(frozen=True)
class ControlPlanePrincipal:
    tenant_id: str
    user_id: str
    role: str
    mfa_verified_at: int | None = None
    mfa_operation: str | None = None
    mfa_body_sha256: str | None = None
    mfa_assertion_id: str | None = None


def canonical_query(query: str) -> str:
    if not query:
        return ""
    if re.search(r"%(?![0-9a-fA-F]{2})", query):
        raise ValueError("Invalid query escape")
    pairs = []
    for part in query.split("&"):
        if not part:
            raise ValueError("Empty query pair")
        name, _, value = part.partition("=")
        pairs.append(
            tuple(quote(unquote_plus(v, errors="strict"), safe="-._~") for v in (name, value))
        )
    return "&".join(f"{name}={value}" for name, value in sorted(pairs, key=lambda p: p[0]))


def signature_payload(headers, method, path, query, body) -> bytes:
    version = headers.get("x-authclaw-version", "")
    fields = [f"authclaw:service-request:v{version}"] + [
        headers.get(f"x-authclaw-{name}", "")
        for name in ("timestamp", "nonce", "service", "audience", "key-id")
    ]
    fields += [
        method,
        path,
        canonical_query(query),
        hashlib.sha256(body).hexdigest(),
        headers.get("content-type", ""),
    ]
    fields += [headers.get(f"x-authclaw-{name}", "") for name in ("tenant-id", "user-id", "role")]
    if version == "3":
        fields += [headers.get(f"x-authclaw-{name}", "") for name in MFA_HEADER_FIELDS]
    if any(not isinstance(v, str) or any(ord(c) < 32 or ord(c) == 127 for c in v) for v in fields):
        raise ValueError("Invalid signed field")
    return "\n".join(fields).encode("utf-8")


def sign_control_plane_request(secret, headers, method, path, query="", body=b""):
    return hmac.new(
        secret.encode(), signature_payload(headers, method, path, query, body), hashlib.sha256
    ).hexdigest()


def endpoint_allowed(endpoints, method: str, path: str, version: str) -> bool:
    if f"{method} {path}" in endpoints:
        return True
    if version != "3" or method != "POST":
        return False
    return (
        "POST /approve/*" in endpoints
        and re.fullmatch(r"/approve/[A-Za-z0-9._:-]+", path) is not None
    ) or (
        "POST /execute/*" in endpoints
        and re.fullmatch(r"/execute/[A-Za-z0-9._:-]+", path) is not None
    )


def verify_control_plane_request(
    headers, method, path, keyring, consume_nonce, *, query="", body=b"", now=None
):
    now = time.time() if now is None else now
    try:
        values = {name: headers.get(f"x-authclaw-{name}", "") for name in HEADER_FIELDS}
        if not all(values[name] for name in BASE_HEADER_FIELDS) or values["version"] not in {"2", "3"}:
            return None
        has_mfa_fields = any(values[name] for name in MFA_HEADER_FIELDS)
        if (values["version"] == "2" and has_mfa_fields) or (
            values["version"] == "3" and not all(values[name] for name in MFA_HEADER_FIELDS)
        ):
            return None
        if not re.fullmatch(r"[0-9]{10}", values["timestamp"]) or not re.fullmatch(
            r"[0-9a-f]{32}", values["nonce"]
        ):
            return None
        if abs(now - int(values["timestamp"])) > MAX_CLOCK_SKEW_SECONDS:
            return None
        key = keyring["keys"][values["key-id"]]
        if (
            values["service"] != key["service"]
            or values["audience"] != "agent"
            or key["audience"] != "agent"
            or not isinstance(key["endpoints"], list)
            or not endpoint_allowed(key["endpoints"], method, path, values["version"])
            or len(key["secret"].encode()) < 32
            or len(body) > MAX_BODY_BYTES
            or not re.fullmatch(r"[0-9a-f]{64}", values["signature"])
        ):
            return None
        if values["version"] == "3" and (
            not re.fullmatch(r"[0-9]{10}", values["mfa-verified-at"])
            or abs(now - int(values["mfa-verified-at"])) > MAX_MFA_ASSERTION_AGE_SECONDS
            or values["mfa-operation"] != f"{method} {path}"
            or values["mfa-body-sha256"] != hashlib.sha256(body).hexdigest()
            or not re.fullmatch(r"[0-9a-f]{32}", values["mfa-assertion-id"])
        ):
            return None
        expected = sign_control_plane_request(key["secret"], headers, method, path, query, body)
        role = normalize_role(values["role"])
        if not role or not hmac.compare_digest(values["signature"], expected):
            return None
    except (KeyError, TypeError, ValueError, AttributeError):
        return None
    nonce_key = hashlib.sha256(
        json.dumps([values["service"], "agent", values["nonce"]]).encode()
    ).hexdigest()
    if not consume_nonce(nonce_key, int(values["timestamp"])):
        return None
    return ControlPlanePrincipal(
        values["tenant-id"],
        values["user-id"],
        role,
        int(values["mfa-verified-at"]) if values["version"] == "3" else None,
        values["mfa-operation"] or None,
        values["mfa-body-sha256"] or None,
        values["mfa-assertion-id"] or None,
    )


@lru_cache(maxsize=1)
def _replay_store(url):
    import redis

    if not url or (
        os.getenv("AUTHCLAW_ENV", "production") not in {"local", "development", "test"}
        and not url.startswith("rediss://")
    ):
        raise ValueError("Secure replay storage required")
    return redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2)


def _consume_nonce(store, nonce, timestamp):
    result = store.eval(
        NONCE_SCRIPT,
        1,
        f"authclaw:service:v2:{nonce}",
        NONCE_TTL_SECONDS,
        timestamp,
        MAX_CLOCK_SKEW_SECONDS,
    )
    if result == -1:
        raise RuntimeError("Replay store recovery window")
    return result == 1


def _consume_mfa_assertion(store, assertion_id: str) -> bool:
    return bool(store.set(
        f"authclaw:mfa-assertion:v1:{assertion_id}", "1", nx=True,
        ex=NONCE_TTL_SECONDS,
    ))


async def authenticate_control_plane(request):
    from fastapi import HTTPException
    from starlette.concurrency import run_in_threadpool

    if not any(f"x-authclaw-{name}" in request.headers for name in HEADER_FIELDS):
        return None
    invalid = HTTPException(401, "Invalid control-plane signature.")
    present_fields = (
        HEADER_FIELDS if request.headers.get("x-authclaw-version") == "3" else BASE_HEADER_FIELDS
    )
    if any(len(request.headers.getlist(f"x-authclaw-{name}")) != 1 for name in present_fields):
        raise invalid
    if len(request.headers.getlist("content-type")) > 1:
        raise invalid
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise HTTPException(413, "Signed request body too large")
        chunks.append(chunk)
    # Starlette middleware forwards its cached body to the downstream app.
    request._body = b"".join(chunks)
    try:
        keyring = json.loads(os.environ["AUTHCLAW_INTERNAL_SERVICE_SECRET"])
        store = _replay_store(os.getenv("REDIS_URL", ""))
        principal = await run_in_threadpool(
            verify_control_plane_request,
            request.headers,
            request.method,
            request.scope["raw_path"].decode("ascii"),
            keyring,
            lambda nonce, timestamp: _consume_nonce(store, nonce, timestamp),
            query=request.scope["query_string"].decode("ascii"),
            body=request._body,
        )
    except UnicodeError:
        raise invalid from None
    except Exception:
        raise HTTPException(503, "Service authentication unavailable") from None
    if not principal:
        raise invalid
    if principal.mfa_assertion_id and not await run_in_threadpool(
        _consume_mfa_assertion, store, principal.mfa_assertion_id
    ):
        raise invalid
    return principal
