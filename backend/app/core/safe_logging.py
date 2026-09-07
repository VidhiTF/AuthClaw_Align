"""Centralized structured logging and payload redaction for the backend."""

from __future__ import annotations

import contextvars
import json
import logging
import os
import re
from datetime import datetime, timezone

_request_id = contextvars.ContextVar("backend_log_request_id", default="")
_trace_id = contextvars.ContextVar("backend_log_trace_id", default="")
_operation = contextvars.ContextVar("backend_log_operation", default="")

_CORRELATION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_TRACEPARENT = re.compile(r"^[\da-f]{2}-([\da-f]{32})-[\da-f]{16}-[\da-f]{2}$", re.IGNORECASE)
_SENSITIVE_FIELD = re.compile(
    r"(?i)([\"']?(?:authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"token|secret|password|credential|prompt|messages?|document|content|request[_-]?body|response[_-]?body)[\"']?)"
    r"\s*[:=]\s*(?:bearer\s+)?(?:\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|[^\s,;]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_BASIC_AUTH_URL = re.compile(r"(?i)\b(https?://)[^/@\s:]+(?::[^/@\s]*)?@")
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_LONG_NUMBER = re.compile(r"(?<!\d)(?:\d[ -]?){12,19}(?!\d)")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.DOTALL)


def safe_correlation_id(value: str | None) -> str:
    candidate = (value or "").strip()
    return candidate if _CORRELATION_ID.fullmatch(candidate) else ""


def trace_id_from_headers(traceparent: str | None, fallback: str | None = None) -> str:
    match = _TRACEPARENT.fullmatch((traceparent or "").strip())
    return match.group(1).lower() if match else safe_correlation_id(fallback)


def redact_log_message(message: object) -> str:
    value = str(message).replace("\r", " ").replace("\n", " ")
    value = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", value)
    value = _SENSITIVE_FIELD.sub(lambda match: f"{match.group(1)}=[REDACTED]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _JWT.sub("[REDACTED_JWT]", value)
    value = _BASIC_AUTH_URL.sub(r"\1[REDACTED]@", value)
    value = _AWS_KEY.sub("[REDACTED_AWS_KEY]", value)
    value = _EMAIL.sub("[REDACTED_EMAIL]", value)
    value = _SSN.sub("[REDACTED_SSN]", value)
    value = _LONG_NUMBER.sub("[REDACTED_NUMBER]", value)
    return _IPV4.sub("[REDACTED_IP]", value)[:4096]


def _safe_record_message(record: logging.LogRecord) -> str:
    args = record.args
    if isinstance(args, tuple):
        args = tuple(f"error_type={type(arg).__name__}" if isinstance(arg, BaseException) else arg for arg in args)
    elif isinstance(args, dict):
        args = {key: (f"error_type={type(value).__name__}" if isinstance(value, BaseException) else value) for key, value in args.items()}
    try:
        message = str(record.msg) % args if args else str(record.msg)
    except (TypeError, ValueError):
        message = str(record.msg)
    if record.exc_info and record.exc_info[1]:
        raw_exception = str(record.exc_info[1])
        if raw_exception:
            message = message.replace(raw_exception, f"error_type={type(record.exc_info[1]).__name__}")
    return redact_log_message(message)


def bind_request_context(request_id: str, trace_id: str, operation: str):
    return (
        _request_id.set(safe_correlation_id(request_id)),
        _trace_id.set(safe_correlation_id(trace_id)),
        _operation.set(redact_log_message(operation)[:256]),
    )


def reset_request_context(tokens) -> None:
    _request_id.reset(tokens[0])
    _trace_id.reset(tokens[1])
    _operation.reset(tokens[2])


class SafeJSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "environment": os.getenv("AUTHCLAW_ENV", "local").strip().lower(),
            "service": os.getenv("AUTHCLAW_SERVICE", "backend").strip() or "backend",
            "release": os.getenv("AUTHCLAW_RELEASE", "unknown").strip()[:200],
            "request_id": safe_correlation_id(getattr(record, "request_id", "")) or _request_id.get(),
            "trace_id": safe_correlation_id(getattr(record, "trace_id", "")) or _trace_id.get(),
            "operation": redact_log_message(getattr(record, "operation", "") or _operation.get())[:256],
            "status": getattr(record, "status", ""),
            "latency_ms": getattr(record, "latency_ms", ""),
            "error_category": type(record.exc_info[1]).__name__ if record.exc_info and record.exc_info[1] else "",
            "message": _safe_record_message(record),
        }
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


def configure_safe_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(SafeJSONFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        target = logging.getLogger(name)
        target.handlers = [handler]
        target.propagate = False
