import json
import logging
from io import StringIO

from startup.safe_logging import SafeJSONFormatter, SafeJSONStream, bind_request_context, reset_request_context


def test_agent_formatter_redacts_provider_and_document_data(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_ENV", "production")
    monkeypatch.setenv("AUTHCLAW_RELEASE", "sha256:agent")
    tokens = bind_request_context("req-agent", "trace-agent", "POST /v1/chat/completions")
    try:
        record = logging.LogRecord(
            "agent.provider", logging.WARNING, __file__, 1,
            'request failed api_key=sk-live-secret document="diagnosis for patient@example.com" cookie=session-secret',
            (), None,
        )
        payload = json.loads(SafeJSONFormatter().format(record))
    finally:
        reset_request_context(tokens)

    assert payload["service"] == "agent"
    assert payload["request_id"] == "req-agent"
    assert payload["trace_id"] == "trace-agent"
    assert payload["operation"] == "POST /v1/chat/completions"
    for forbidden in ("sk-live-secret", "diagnosis", "patient@example.com", "session-secret"):
        assert forbidden not in payload["message"]


def test_legacy_print_stream_is_structured_and_redacted():
    output = StringIO()
    stream = SafeJSONStream(output)
    stream.write('provider diagnostic token=top-secret prompt="private medical content"\n')
    payload = json.loads(output.getvalue())
    assert payload["service"] == "agent"
    assert payload["operation"] == ""
    assert "top-secret" not in payload["message"]
    assert "private medical content" not in payload["message"]
