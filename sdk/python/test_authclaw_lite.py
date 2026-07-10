from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from authclaw_lite import AuthClaw, AuthClawError  # noqa: E402


class _MockGateway(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        raw_body = self.rfile.read(length)
        self.server.seen = {  # type: ignore[attr-defined]
            "path": self.path,
            "authorization": self.headers.get("authorization"),
            "provider": self.headers.get("x-provider"),
            "request_id": self.headers.get("x-request-id"),
            "body": json.loads(raw_body.decode("utf-8")),
        }
        response = {
            "id": "chatcmpl-test",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }
        body = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AuthClawLiteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockGateway)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_chat_completions_create_forwards_to_gateway(self) -> None:
        client = AuthClaw(api_key="acl_test", gateway_url=f"http://127.0.0.1:{self.server.server_port}")

        response = client.chat_completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "hello"}],
            provider="openai",
            request_id="req-123",
            max_tokens=16,
        )

        self.assertEqual(response["choices"][0]["message"]["content"], "ok")
        self.assertEqual(self.server.seen["path"], "/v1/chat/completions")  # type: ignore[attr-defined]
        self.assertEqual(self.server.seen["authorization"], "Bearer acl_test")  # type: ignore[attr-defined]
        self.assertEqual(self.server.seen["provider"], "openai")  # type: ignore[attr-defined]
        self.assertEqual(self.server.seen["request_id"], "req-123")  # type: ignore[attr-defined]
        self.assertEqual(self.server.seen["body"]["max_tokens"], 16)  # type: ignore[attr-defined]

    def test_missing_key_fails_before_network(self) -> None:
        os.environ.pop("AUTHCLAW_API_KEY", None)
        os.environ.pop("AUTHCLAW_GATEWAY_KEY", None)
        with self.assertRaises(AuthClawError):
            AuthClaw(api_key="", gateway_url=f"http://127.0.0.1:{self.server.server_port}")


if __name__ == "__main__":
    unittest.main()
