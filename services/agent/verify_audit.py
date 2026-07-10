import hashlib
import json
import contextvars
import base64
import hmac
import logging
import os
import queue
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from sqlalchemy import text
from database import engine
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

GENESIS_HASH = "0" * 64
_agent_event_request_id = contextvars.ContextVar("agent_event_request_id", default=None)
_agent_event_sequence = contextvars.ContextVar("agent_event_sequence", default=0)
logger = logging.getLogger("authclaw.audit")
_clickhouse_queue = None
_clickhouse_worker_started = False
_export_private_key = None


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _load_export_private_key():
    global _export_private_key
    if _export_private_key is not None:
        return _export_private_key

    pem = os.getenv("AUTHCLAW_EXPORT_SIGNING_PRIVATE_KEY_PEM")
    key_file = os.getenv("AUTHCLAW_EXPORT_SIGNING_PRIVATE_KEY_FILE")
    password = os.getenv("AUTHCLAW_EXPORT_SIGNING_PRIVATE_KEY_PASSWORD")
    if key_file and not pem:
        with open(key_file, "rb") as handle:
            pem = handle.read().decode("utf-8")

    if pem:
        key_bytes = pem.replace("\\n", "\n").encode("utf-8")
        _export_private_key = serialization.load_pem_private_key(
            key_bytes,
            password=password.encode("utf-8") if password else None,
        )
    else:
        _export_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _export_private_key


def _export_public_key_pem() -> str:
    key = _load_export_private_key().public_key()
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _export_signing_key_id() -> str:
    digest = hashlib.sha256(_export_public_key_pem().encode("utf-8")).hexdigest()
    return f"authclaw-export-{digest[:16]}"


def get_audit_hash_chain_root(tenant_id: int = None) -> str:
    with engine.connect() as conn:
        row = conn.execute(
            text("""
                SELECT integrity_hash
                FROM audit_logs
                WHERE integrity_hash IS NOT NULL
                  AND (:tenant_id IS NULL OR tenant_id = :tenant_id)
                ORDER BY id DESC
                LIMIT 1
            """),
            {"tenant_id": tenant_id},
        ).fetchone()
    return row[0] if row and row[0] else GENESIS_HASH


def create_signed_export_package(
    payload: dict,
    tenant_id: int = None,
    export_type: str = "audit",
    framework_scope: str = "all",
    timeframe: dict = None,
) -> dict:
    payload_bytes = _canonical_json_bytes(payload)
    payload_hash = hashlib.sha256(payload_bytes).hexdigest()
    generated_at = datetime.now(timezone.utc).isoformat()
    audit_verification = verify_audit_chain(tenant_id=tenant_id)
    manifest = {
        "version": "authclaw.signed-export.v1",
        "tenant": str(tenant_id or ""),
        "timeframe": timeframe or {"from": None, "to": generated_at},
        "hash_chain_root": get_audit_hash_chain_root(tenant_id=tenant_id),
        "records_checked": audit_verification.get("records_checked", 0),
        "framework_scope": framework_scope or "all",
        "export_type": export_type,
        "payload_sha256": f"sha256-{payload_hash}",
        "signing_key_id": _export_signing_key_id(),
        "signing_algorithm": "RSASSA-PSS-SHA256",
        "generated_at": generated_at,
        "public_key_pem": _export_public_key_pem(),
    }
    signature = _load_export_private_key().sign(
        _canonical_json_bytes(manifest),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    manifest["signature"] = _b64url(signature)
    return {"manifest": manifest, "payload": payload, "payload_b64": _b64url(payload_bytes)}


def verify_signed_export_package(payload: dict = None, payload_b64: str = None, manifest: dict = None) -> dict:
    if not manifest or "signature" not in manifest:
        return {"valid": False, "reason": "missing signature manifest"}
    if payload is None and not payload_b64:
        return {"valid": False, "reason": "missing payload"}
    try:
        payload_bytes = _b64url_decode(payload_b64) if payload_b64 else _canonical_json_bytes(payload)
        expected_hash = manifest.get("payload_sha256")
        actual_hash = f"sha256-{hashlib.sha256(payload_bytes).hexdigest()}"
        if expected_hash != actual_hash:
            return {"valid": False, "reason": "payload hash mismatch", "expected": expected_hash, "actual": actual_hash}

        signature = _b64url_decode(manifest["signature"])
        unsigned_manifest = dict(manifest)
        unsigned_manifest.pop("signature", None)
        public_key_pem = unsigned_manifest.get("public_key_pem")
        if not public_key_pem:
            return {"valid": False, "reason": "missing public key"}
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        public_key.verify(
            signature,
            _canonical_json_bytes(unsigned_manifest),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return {
            "valid": True,
            "reason": "signature verified",
            "payload_sha256": actual_hash,
            "signing_key_id": unsigned_manifest.get("signing_key_id"),
            "hash_chain_root": unsigned_manifest.get("hash_chain_root"),
            "framework_scope": unsigned_manifest.get("framework_scope"),
            "export_type": unsigned_manifest.get("export_type"),
        }
    except (InvalidSignature, ValueError, TypeError) as exc:
        return {"valid": False, "reason": f"signature verification failed: {exc.__class__.__name__}"}


def _env_truthy(name: str, default: bool = True) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "on"}


def clickhouse_pipeline_enabled() -> bool:
    return _env_truthy("AUTHCLAW_CLICKHOUSE_ENABLED", True)


def _clickhouse_http_url(query: str) -> str:
    base_url = os.getenv("CLICKHOUSE_HTTP_URL", "http://127.0.0.1:8123").rstrip("/")
    params = {
        "query": query,
        "date_time_input_format": "best_effort",
        "input_format_skip_unknown_fields": "1",
    }
    return f"{base_url}/?{urllib.parse.urlencode(params)}"


def _ensure_clickhouse_worker() -> None:
    global _clickhouse_queue, _clickhouse_worker_started
    if not clickhouse_pipeline_enabled() or _clickhouse_worker_started:
        return
    _clickhouse_queue = queue.Queue(maxsize=int(os.getenv("AUTHCLAW_CLICKHOUSE_QUEUE_SIZE", "1000")))
    worker = threading.Thread(target=_clickhouse_worker, name="authclaw-clickhouse-audit-mirror", daemon=True)
    worker.start()
    _clickhouse_worker_started = True


def _clickhouse_worker() -> None:
    while True:
        event = _clickhouse_queue.get()
        try:
            _write_clickhouse_event(event)
        except Exception as exc:
            logger.debug("ClickHouse audit mirror skipped event: %s", exc)
        finally:
            _clickhouse_queue.task_done()


def _write_clickhouse_event(event: dict) -> None:
    database = os.getenv("CLICKHOUSE_DATABASE", "authclaw")
    table = os.getenv("CLICKHOUSE_AUDIT_TABLE", "audit_events")
    query = f"INSERT INTO {database}.{table} FORMAT JSONEachRow"
    payload = json.dumps(event, default=str).encode("utf-8") + b"\n"
    request = urllib.request.Request(
        _clickhouse_http_url(query),
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    timeout = float(os.getenv("CLICKHOUSE_TIMEOUT_SECONDS", "1.5"))
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(f"ClickHouse returned {response.status}")


def mirror_audit_event_to_clickhouse(event: dict) -> None:
    """
    Durable audit/event pipeline entrypoint. Events are recorded before delivery,
    then published to Kafka REST/MSK and ClickHouse when configured. Delivery
    failures are retained for retry/dead-letter visibility and never prevent the
    source PostgreSQL audit chain from being written.
    """
    try:
        from services.event_pipeline import EventPipeline

        EventPipeline().record_and_deliver(event, stream="audit")
    except Exception as exc:
        logger.debug("Audit event pipeline delivery skipped: %s", exc)
        return


def sign_export_payload(payload: bytes, tenant_id: int = None, export_type: str = "audit") -> dict:
    """
    Produces tamper-evident export headers using a tenant-scoped HMAC key. This
    is additive to the existing CSV/PDF bytes and avoids changing export bodies.
    """
    secret = (
        os.getenv(f"AUTHCLAW_TENANT_{tenant_id}_EXPORT_SIGNING_KEY") if tenant_id is not None else None
    ) or os.getenv("AUTHCLAW_EXPORT_SIGNING_KEY") or os.getenv("AUTHCLAW_ENCRYPTION_KEY") or os.getenv("JWT_SECRET") or "authclaw-local-export-signing-key"
    body_hash = hashlib.sha256(payload or b"").hexdigest()
    signature = hmac.new(
        secret.encode("utf-8"),
        f"{tenant_id}:{export_type}:{body_hash}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-AuthClaw-Export-Hash": f"sha256={body_hash}",
        "X-AuthClaw-Export-Signature": f"sha256={signature}",
        "X-AuthClaw-Export-Tenant": str(tenant_id or ""),
    }


def set_agent_event_context(request_id: str):
    request_token = _agent_event_request_id.set(request_id)
    sequence_token = _agent_event_sequence.set(0)
    return request_token, sequence_token


def clear_agent_event_context(token) -> None:
    if not token:
        return
    request_token, sequence_token = token
    _agent_event_sequence.reset(sequence_token)
    _agent_event_request_id.reset(request_token)

def calculate_record_hash(record: dict, previous_hash: str) -> str:
    """
    Deterministically computes the SHA-256 integrity hash for a single audit log record.
    Hashed fields: record_id, user_query, response, allowed, created_at, risk_level, approval_status, previous_hash
    """
    # format created_at to a standardized string representation
    created_at = record["created_at"]
    if hasattr(created_at, "isoformat"):
        created_at_str = created_at.isoformat()
    else:
        created_at_str = str(created_at)

    hash_data = {
        "record_id": int(record["record_id"]),
        "user_query": record["user_query"] or "",
        "response": record["response"] or "",
        "allowed": bool(record["allowed"]),
        "created_at": created_at_str,
        "risk_level": record["risk_level"] or "",
        "approval_status": record["approval_status"] or "",
        "previous_hash": previous_hash
    }
    
    serialized = json.dumps(hash_data, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def verify_audit_chain(tenant_id: int = None) -> dict:
    """
    Performs full integrity check on the audit log cryptographic chain:
    - Recalculates hashes.
    - Verifies previous_hash linkage.
    - Detects modified records.
    - Detects deleted records and missing ID gaps.
    - Detects broken chain continuity.
    """
    with engine.connect() as conn:
        params = {}
        tenant_filter = ""
        if tenant_id is not None:
            tenant_filter = "WHERE tenant_id = :tenant_id"
            params["tenant_id"] = tenant_id
        res = conn.execute(
            text(f"""
            SELECT id, user_query, response, allowed, created_at, risk_level, approval_status, integrity_hash, previous_hash
            FROM audit_logs
            {tenant_filter}
            ORDER BY id ASC
            """),  # nosec B608
            params
        )
        rows = res.fetchall()

    if not rows:
        return {
            "valid": True,
            "records_checked": 0,
            "chain_started_at": None
        }

    # Identify the start of the cryptographic chain (the first record with a non-null hash)
    start_index = -1
    for i, r in enumerate(rows):
        if r[7] is not None:  # integrity_hash is not None
            start_index = i
            break

    if start_index == -1:
        # No chained records exist yet (all are legacy)
        return {
            "valid": True,
            "records_checked": 0,
            "chain_started_at": None
        }

    records_checked = 0
    chain_started_at = rows[start_index][4]
    if hasattr(chain_started_at, "isoformat"):
        chain_started_at_str = chain_started_at.isoformat()
    else:
        chain_started_at_str = str(chain_started_at)

    prev_id = None
    prev_hash = None

    for i in range(start_index, len(rows)):
        r = rows[i]
        rec_id = r[0]
        query = r[1]
        response = r[2]
        allowed = r[3]
        created_at = r[4]
        risk_level = r[5]
        approval_status = r[6]
        integrity_hash = r[7]
        previous_hash = r[8]

        # Verify hash columns are present once the chain starts
        if integrity_hash is None or previous_hash is None:
            return {
                "valid": False,
                "records_checked": records_checked,
                "failed_record_id": rec_id,
                "reason": "missing hash metadata in active chain"
            }

        # 1. Detect ID gaps (deleted records)
        if tenant_id is None and prev_id is not None:
            if rec_id != prev_id + 1:
                return {
                    "valid": False,
                    "records_checked": records_checked,
                    "failed_record_id": rec_id,
                    "reason": f"missing record detected between {prev_id} and {rec_id}"
                }

        # 2. Verify previous_hash linkage
        expected_prev = GENESIS_HASH if prev_hash is None else prev_hash
        if previous_hash != expected_prev:
            return {
                "valid": False,
                "records_checked": records_checked,
                "failed_record_id": rec_id,
                "reason": "broken link"
            }

        # 3. Recalculate hash to verify against tampering (modification)
        record_dict = {
            "record_id": rec_id,
            "user_query": query,
            "response": response,
            "allowed": allowed,
            "created_at": created_at,
            "risk_level": risk_level,
            "approval_status": approval_status
        }
        computed_hash = calculate_record_hash(record_dict, previous_hash)
        if integrity_hash != computed_hash:
            return {
                "valid": False,
                "records_checked": records_checked,
                "failed_record_id": rec_id,
                "reason": "hash mismatch"
            }

        prev_id = rec_id
        prev_hash = integrity_hash
        records_checked += 1

    return {
        "valid": True,
        "records_checked": records_checked,
        "chain_started_at": chain_started_at_str
    }

def record_gateway_request(
    risk_level: str,
    allowed: bool,
    status: str,
    request_id: str = None,
    tenant_id: str = "Default Tenant",
    route_id: str = None,
    provider: str = "OpenAI",
    model: str = "gpt-4o",
    latency: int = 150,
    tokens_in: int = 0,
    tokens_out: int = 0,
    decision: str = None,
    duration_ms: int = None
):
    """
    Centrally and persistently records every incoming gateway request to PostgreSQL.
    """
    from database import engine
    from datetime import datetime
    import uuid
    try:
        if not request_id:
            request_id = f"req-{uuid.uuid4()}"
        with engine.connect() as conn:
            conn.execute(
                text("""
                INSERT INTO gateway_requests (
                    timestamp, created_at, risk_level, allowed, status, request_id, 
                    tenant_id, route_id, provider, model, latency, 
                    tokens_in, tokens_out, decision, duration_ms
                )
                VALUES (
                    :timestamp, :created_at, :risk_level, :allowed, :status, :request_id, 
                    :tenant_id, :route_id, :provider, :model, :latency, 
                    :tokens_in, :tokens_out, :decision, :duration_ms
                )
                """),
                {
                    "timestamp": datetime.now(),
                    "created_at": datetime.now(),
                    "risk_level": risk_level,
                    "allowed": allowed,
                    "status": status,
                    "request_id": request_id,
                    "tenant_id": tenant_id,
                    "route_id": route_id or "1",
                    "provider": provider,
                    "model": model,
                    "latency": latency,
                    "tokens_in": tokens_in or int(len(risk_level) * 15),
                    "tokens_out": tokens_out or int(len(status) * 25),
                    "decision": decision,
                    "duration_ms": duration_ms if duration_ms is not None else latency
                }
            )
            conn.commit()

            mirror_audit_event_to_clickhouse({
                "event_type": "gateway_request",
                "request_id": request_id,
                "tenant_id": tenant_id,
                "route_id": route_id or "1",
                "provider": provider,
                "model": model,
                "risk_level": risk_level,
                "allowed": allowed,
                "status": status,
                "decision": decision,
                "duration_ms": duration_ms if duration_ms is not None else latency,
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "created_at": datetime.now().isoformat(),
            })
    except Exception as e:
        print(f"Error logging gateway request metrics: {e}", flush=True)

def create_audit_block(
    query: str,
    response: str,
    allowed: bool,
    risk_level: str,
    approval_status: str,
    session_id: str = "N/A",
    approval_id: str = None,
    approver: str = None,
    original_request: str = None,
    approval_timestamp: datetime = None,
    execution_timestamp: datetime = None,
    execution_status: str = None,
    policy_name: str = None,
    policy_type: str = None,
    matched_pattern: str = None,
    redacted_value: str = None,
    username: str = None,
    tenant_id: int = None
) -> int:
    """
    Creates a new cryptographic audit block in PostgreSQL database and recalculates hashes.
    """
    from database import engine
    from startup.audit import log_audit_event
    from datetime import datetime
    
    with engine.connect() as conn:
        res = conn.execute(
            text("""
            INSERT INTO audit_logs
            (
                user_query,
                response,
                allowed,
                risk_level,
                approval_status,
                created_at,
                approval_id,
                approver,
                original_request,
                approval_timestamp,
                execution_timestamp,
                execution_status,
                policy_name,
                policy_type,
                matched_pattern,
                redacted_value,
                username,
                tenant_id
            )
            VALUES
            (
                :query,
                :response,
                :allowed,
                :risk_level,
                :approval_status,
                :created_at,
                :approval_id,
                :approver,
                :original_request,
                :approval_timestamp,
                :execution_timestamp,
                :execution_status,
                :policy_name,
                :policy_type,
                :matched_pattern,
                :redacted_value,
                :username,
                :tenant_id
            )
            RETURNING id, created_at
            """),
            {
                "query": query,
                "response": response,
                "allowed": allowed,
                "risk_level": risk_level,
                "approval_status": approval_status,
                "created_at": datetime.now(),
                "approval_id": approval_id,
                "approver": approver,
                "original_request": original_request or query,
                "approval_timestamp": approval_timestamp,
                "execution_timestamp": execution_timestamp,
                "execution_status": execution_status,
                "policy_name": policy_name,
                "policy_type": policy_type,
                "matched_pattern": matched_pattern,
                "redacted_value": redacted_value,
                "username": username,
                "tenant_id": tenant_id
            }
        )
        row = res.fetchone()
        inserted_id = row[0]
        db_created_at = row[1]
        conn.commit()

        # Retrieve the integrity_hash of the latest record before the newly inserted one
        prev_res = conn.execute(
            text("""
            SELECT integrity_hash
            FROM audit_logs
            WHERE id < :inserted_id
              AND integrity_hash IS NOT NULL
              AND (
                (:tenant_id IS NULL AND tenant_id IS NULL)
                OR tenant_id = :tenant_id
              )
            ORDER BY id DESC
            LIMIT 1
            """),
            {"inserted_id": inserted_id, "tenant_id": tenant_id}
        ).fetchone()
        previous_hash = prev_res[0] if prev_res else GENESIS_HASH

        # Calculate current record hash
        record_dict = {
            "record_id": inserted_id,
            "user_query": query,
            "response": response,
            "allowed": allowed,
            "created_at": db_created_at,
            "risk_level": risk_level,
            "approval_status": approval_status,
        }
        current_hash = calculate_record_hash(record_dict, previous_hash)

        # Update the record with calculated hashes
        conn.execute(
            text("""
            UPDATE audit_logs
            SET integrity_hash = :integrity_hash, previous_hash = :previous_hash
            WHERE id = :id
            """),
            {
                "integrity_hash": current_hash,
                "previous_hash": previous_hash,
                "id": inserted_id
            }
        )
        conn.commit()

        # Log audit chain created event
        log_audit_event(
            event="audit_chain_created",
            correlation_id=session_id,
            extra={
                "record_id": inserted_id,
                "integrity_hash": current_hash,
                "previous_hash": previous_hash
            }
        )
        mirror_audit_event_to_clickhouse({
            "event_type": "audit_block",
            "record_id": inserted_id,
            "tenant_id": tenant_id,
            "session_id": session_id,
            "approval_id": approval_id,
            "username": username,
            "risk_level": risk_level,
            "allowed": allowed,
            "approval_status": approval_status,
            "policy_name": policy_name,
            "policy_type": policy_type,
            "matched_pattern": matched_pattern,
            "integrity_hash": current_hash,
            "previous_hash": previous_hash,
            "created_at": db_created_at.isoformat() if hasattr(db_created_at, "isoformat") else str(db_created_at),
        })
        return inserted_id

def log_agent_event(
    tenant_id: int,
    session_id: str,
    agent_name: str,
    event_type: str,
    details: str,
    request_id: str = None,
    sequence: int = None
):
    """
    Logs an agent execution event dynamically to the database.
    """
    from database import engine
    from sqlalchemy import text
    try:
        effective_request_id = request_id or _agent_event_request_id.get()
        effective_sequence = sequence
        if effective_sequence is None and effective_request_id:
            current_sequence = _agent_event_sequence.get()
            effective_sequence = current_sequence + 1
            _agent_event_sequence.set(effective_sequence)

        with engine.connect() as conn:
            conn.execute(
                text("""
                INSERT INTO agent_events (tenant_id, session_id, request_id, sequence, agent_name, event_type, details)
                VALUES (:tid, :sid, :rid, :seq, :agent, :type, :details)
                """),
                {
                    "tid": tenant_id,
                    "sid": session_id,
                    "rid": effective_request_id,
                    "seq": effective_sequence,
                    "agent": agent_name,
                    "type": event_type,
                    "details": details
                }
            )
            conn.commit()
    except Exception as e:
        import logging
        logger = logging.getLogger("authclaw.agent_events")
        logger.error(f"Failed to log agent event: {e}", exc_info=True)
