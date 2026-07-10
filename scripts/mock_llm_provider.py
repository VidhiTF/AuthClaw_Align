#!/usr/bin/env python3
"""Tiny deterministic LLM provider used by CI integration and benchmark gates."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class MockProviderHandler(BaseHTTPRequestHandler):
    server_version = "AuthClawMockProvider/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def do_GET(self) -> None:
        if self.path == "/health":
            self._json(200, {"status": "healthy", "service": "mock-llm-provider"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0") or "0")
        raw_body = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            body = {}

        if "streamGenerateContent" in self.path or body.get("stream") is True:
            self._sse()
            return
        if "generateContent" in self.path or "/models/" in self.path:
            self._json(
                200,
                {
                    "candidates": [
                        {
                            "content": {
                                "parts": [{"text": "Mock Gemini response from AuthClaw CI."}],
                                "role": "model",
                            },
                            "finishReason": "STOP",
                        }
                    ]
                },
            )
            return
        if "/v1/messages" in self.path:
            self._json(
                200,
                {
                    "id": "msg_mock",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Mock Anthropic response from AuthClaw CI."}],
                    "model": body.get("model", "mock"),
                    "stop_reason": "end_turn",
                },
            )
            return
        if "/v2/chat" in self.path:
            self._json(
                200,
                {
                    "id": "chatcmpl-mock",
                    "message": {"role": "assistant", "content": [{"type": "text", "text": "Mock Cohere response."}]},
                    "finish_reason": "COMPLETE",
                },
            )
            return
        self._json(
            200,
            {
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Mock OpenAI response."}, "finish_reason": "stop"}],
            },
        )

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _sse(self) -> None:
        chunks = [
            {"candidates": [{"content": {"parts": [{"text": "Mock stream "}], "role": "model"}}]},
            {"candidates": [{"content": {"parts": [{"text": "response."}], "role": "model"}, "finishReason": "STOP"}]},
        ]
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.end_headers()
        for chunk in chunks:
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
        self.wfile.write(b"data: [DONE]\n\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19090)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), MockProviderHandler)
    print(f"Mock LLM provider listening on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
