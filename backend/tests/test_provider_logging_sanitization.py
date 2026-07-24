from pathlib import Path


def test_gateway_chat_failure_logs_status_without_response_body():
    source = (
        Path(__file__).parents[1] / "app" / "api" / "v1" / "endpoints" / "chat.py"
    ).read_text(encoding="utf-8")

    assert 'logger.error("Gateway request failed: status=%s", res.status_code)' in source
    assert 'logger.error("Gateway request failed: %s", res.text)' not in source
