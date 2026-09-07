import json
import logging

from app.core.safe_logging import (
    SafeJSONFormatter,
    bind_request_context,
    redact_log_message,
    reset_request_context,
    safe_correlation_id,
    trace_id_from_headers,
)


def test_safe_formatter_keeps_operational_context_and_redacts_payloads(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "staging")
    monkeypatch.setenv("AUTHCLAW_RELEASE", "sha256:release")
    tokens = bind_request_context("req-safe", "trace-safe", "POST /v1/chat")
    try:
        record = logging.LogRecord(
            "backend.provider", logging.ERROR, __file__, 1,
            'provider failed authorization=Bearer abc "prompt":"patient@example.com" password=hunter2 host=10.1.2.3',
            (), None,
        )
        record.status = 502
        record.latency_ms = 14.5
        payload = json.loads(SafeJSONFormatter().format(record))
    finally:
        reset_request_context(tokens)

    assert payload["environment"] == "staging"
    assert payload["service"] == "backend"
    assert payload["release"] == "sha256:release"
    assert payload["request_id"] == "req-safe"
    assert payload["trace_id"] == "trace-safe"
    assert payload["operation"] == "POST /v1/chat"
    assert payload["status"] == 502
    for forbidden in ("abc", "patient@example.com", "hunter2", "10.1.2.3"):
        assert forbidden not in payload["message"]


def test_redactor_covers_tokens_credentials_and_common_pii():
    raw = (
        "eyJhbGciOiJIUzI1NiJ9.payload.signature AKIA1234567890ABCDEF "
        "https://admin:password@example.invalid 123-45-6789 4111 1111 1111 1111"
    )
    redacted = redact_log_message(raw)
    assert "eyJ" not in redacted
    assert "AKIA1234567890ABCDEF" not in redacted
    assert "admin:password" not in redacted
    assert "123-45-6789" not in redacted
    assert "4111 1111 1111 1111" not in redacted


def test_correlation_values_are_strictly_validated():
    assert safe_correlation_id("req-123") == "req-123"
    assert safe_correlation_id("bad\nheader") == ""
    assert trace_id_from_headers("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01") == "4bf92f3577b34da6a3ce929d0e0e4736"


def test_exception_arguments_emit_only_error_category():
    record = logging.LogRecord(
        "backend.db", logging.ERROR, __file__, 1,
        "database failed: %s", (RuntimeError("postgresql://admin:secret@db/patient"),), None,
    )
    payload = json.loads(SafeJSONFormatter().format(record))
    assert "admin" not in payload["message"]
    assert "secret" not in payload["message"]
    assert "patient" not in payload["message"]
    assert "error_type=RuntimeError" in payload["message"]
