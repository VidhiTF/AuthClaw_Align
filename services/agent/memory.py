import json
import contextvars
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict
from database import engine
from sqlalchemy import text
from services.tenant_context import get_current_tenant_id

_worker_scope = contextvars.ContextVar("authclaw_worker_scope", default=None)
MAX_WORKER_SCOPE_TTL_SECONDS = 30 * 60


@dataclass(frozen=True)
class RuntimeWorkerScope:
    provider: str
    subject: str
    token_ref: str
    expires_at: datetime
    claims: Dict[str, str] = field(default_factory=dict)

    def active(self) -> bool:
        return datetime.now(timezone.utc) < self.expires_at


def create_worker_scope(provider: str, subject: str, token_ref: str, ttl_seconds: int = MAX_WORKER_SCOPE_TTL_SECONDS, claims: Dict[str, str] = None) -> RuntimeWorkerScope:
    """
    Creates a bounded runtime scope for cloud/SCM worker actions. Tokens are
    referenced by name rather than stored in chat memory.
    """
    ttl = min(max(1, int(ttl_seconds or MAX_WORKER_SCOPE_TTL_SECONDS)), MAX_WORKER_SCOPE_TTL_SECONDS)
    return RuntimeWorkerScope(
        provider=provider,
        subject=subject,
        token_ref=token_ref,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl),
        claims=claims or {},
    )


def set_worker_scope(scope: RuntimeWorkerScope):
    if not scope.active():
        raise ValueError("Worker scope is expired.")
    return _worker_scope.set(scope)


def clear_worker_scope(token) -> None:
    if token:
        _worker_scope.reset(token)


def current_worker_scope() -> RuntimeWorkerScope:
    scope = _worker_scope.get()
    if scope and scope.active():
        return scope
    return None


def require_worker_scope(provider: str = None) -> RuntimeWorkerScope:
    scope = current_worker_scope()
    if not scope:
        raise PermissionError("Worker action requires an active scoped runtime token.")
    if provider and scope.provider != provider:
        raise PermissionError(f"Worker scope provider mismatch: expected {provider}.")
    return scope


PROVIDER_UNAVAILABLE_COPY = (
    "The configured model provider is currently unavailable. AuthClaw completed "
    "the security, policy, and audit checks, but the upstream model call could "
    "not be completed. Check the Providers page, API credentials, and outbound "
    "network access, then try again."
)


def sanitize_provider_message(content):
    text_content = str(content or "")
    provider_error_markers = (
        "[Offline Fallback]",
        "Provider unavailable:",
        "HTTPSConnectionPool",
        "generativelanguage.googleapis.com",
        "Max retries exceeded",
        "Failed to establish a new connection",
        "key=",
    )
    if any(marker in text_content for marker in provider_error_markers):
        return PROVIDER_UNAVAILABLE_COPY
    return content


def sanitize_trace(trace):
    if not isinstance(trace, list):
        return trace
    sanitized = []
    for item in trace:
        if isinstance(item, dict):
            clean_item = dict(item)
            if "details" in clean_item:
                clean_item["details"] = sanitize_provider_message(clean_item["details"])
            sanitized.append(clean_item)
        else:
            sanitized.append(item)
    return sanitized


def ensure_session_exists(session_id: str, tenant_id=None):
    """
    Ensures that a chat session exists in the database.
    """
    try:
        with engine.connect() as conn:
            res = conn.execute(
                text("SELECT id FROM chat_sessions WHERE session_id = :session_id"),
                {"session_id": session_id}
            ).fetchone()
            if not res:
                if tenant_id is not None:
                    conn.execute(
                        text(
                            """
                            INSERT INTO chat_sessions (session_id, title, user_id, tenant_id)
                            VALUES (:session_id, 'New Chat', 'admin_user', :tenant_id)
                            """
                        ),
                        {"session_id": session_id, "tenant_id": int(tenant_id)}
                    )
                else:
                    conn.execute(
                        text("INSERT INTO chat_sessions (session_id, title, user_id) VALUES (:session_id, 'New Chat', 'admin_user')"),
                        {"session_id": session_id}
                    )
                conn.commit()
    except Exception as e:
        import logging
        logger = logging.getLogger("authclaw.memory")
        logger.error(f"Database error in ensure_session_exists: {e}", exc_info=True)


def add_message(session_id, role, content, trace=None):
    try:
        tenant_id = get_current_tenant_id()
        ensure_session_exists(session_id, tenant_id=tenant_id)
        with engine.connect() as conn:
            if tenant_id is not None:
                conn.execute(
                    text(
                        """
                        INSERT INTO chat_messages (session_id, role, content, trace, tenant_id)
                        VALUES (:session_id, :role, :content, :trace, :tenant_id)
                        """
                    ),
                    {
                        "session_id": session_id,
                        "role": role,
                        "content": content,
                        "trace": trace,
                        "tenant_id": int(tenant_id),
                    }
                )
            else:
                conn.execute(
                    text("INSERT INTO chat_messages (session_id, role, content, trace) VALUES (:session_id, :role, :content, :trace)"),
                    {"session_id": session_id, "role": role, "content": content, "trace": trace}
                )
            conn.execute(
                text("UPDATE chat_sessions SET updated_at = NOW() WHERE session_id = :session_id"),
                {"session_id": session_id}
            )
            conn.commit()
    except Exception as e:
        import logging
        logger = logging.getLogger("authclaw.memory")
        logger.error(f"Database error in add_message: {e}", exc_info=True)


def get_history(session_id):
    try:
        with engine.connect() as conn:
            res = conn.execute(
                text("SELECT role, content, trace FROM chat_messages WHERE session_id = :session_id ORDER BY id ASC"),
                {"session_id": session_id}
            )
            history = []
            for row in res:
                role = row[0]
                content = row[1]
                trace = row[2]
                
                # Reconstruct extra keys from JSON strings for blocked/system messages if stored as JSON
                msg = {"role": role}
                if role in ("blocked", "system"):
                    try:
                        parsed = json.loads(content)
                        if isinstance(parsed, dict):
                            msg.update(parsed)
                        else:
                            msg["content"] = content
                    except Exception:
                        msg["content"] = content
                else:
                    msg["content"] = sanitize_provider_message(content)
                    
                if trace:
                    try:
                        msg["trace"] = sanitize_trace(json.loads(trace))
                    except Exception:
                        msg["trace"] = sanitize_provider_message(trace)
                    
                history.append(msg)
            return history
    except Exception as e:
        import logging
        logger = logging.getLogger("authclaw.memory")
        logger.error(f"Database error in get_history: {e}", exc_info=True)
        return []
