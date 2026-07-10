"""Install-free Python helper for sending traffic through AuthClaw Lite."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class AuthClawError(RuntimeError):
    """Raised when the gateway returns an error or an invalid client request is made."""

    def __init__(self, message: str, *, status_code: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class AuthClaw:
    """Tiny AuthClaw Lite gateway client.

    Copy this file into a project or import it from `sdk/python`.
    """

    def __init__(self, api_key: str | None = None, gateway_url: str | None = None, timeout: float = 30) -> None:
        self.api_key = api_key or os.getenv("AUTHCLAW_API_KEY") or os.getenv("AUTHCLAW_GATEWAY_KEY") or ""
        self.gateway_url = (gateway_url or os.getenv("AUTHCLAW_GATEWAY_URL") or "http://localhost:8080").rstrip("/")
        self.timeout = timeout
        if not self.api_key:
            raise AuthClawError("AuthClaw API key required. Pass api_key or set AUTHCLAW_API_KEY.")
        self.chat_completions = _ChatCompletions(self)

    def request(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        provider: str | None = None,
        request_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        if not path.startswith("/"):
            raise AuthClawError("Gateway path must start with '/'.")

        request_headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if provider:
            request_headers["X-Provider"] = provider
        if request_id:
            request_headers["X-Request-ID"] = request_id
        if headers:
            request_headers.update(headers)

        req = urllib.request.Request(
            self.gateway_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers=request_headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                return _decode_response(response.read())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise AuthClawError(f"Gateway returned HTTP {exc.code}.", status_code=exc.code, body=body) from exc
        except urllib.error.URLError as exc:
            raise AuthClawError(f"Gateway request failed: {exc.reason}") from exc


class _ChatCompletions:
    def __init__(self, client: AuthClaw) -> None:
        self._client = client

    def create(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        provider: str = "openai",
        request_id: str | None = None,
        **kwargs: Any,
    ) -> Any:
        payload: dict[str, Any] = {"model": model, "messages": messages}
        payload.update(kwargs)
        return self._client.request(
            "/v1/chat/completions",
            payload,
            provider=provider,
            request_id=request_id,
        )


def _decode_response(body: bytes) -> Any:
    if not body:
        return None
    text = body.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text

