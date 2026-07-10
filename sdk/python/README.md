# AuthClaw Lite Python SDK

Install-free helper for routing Python traffic through the AuthClaw Lite gateway.

```python
from authclaw_lite import AuthClaw

client = AuthClaw(
    api_key="<AUTHCLAW_GATEWAY_KEY>",
    gateway_url="http://localhost:8080",
)

response = client.chat_completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "user", "content": "My email is jane@example.com. Summarize this safely."}
    ],
    provider="openai",
    request_id="demo-001",
)
print(response)
```

For non-OpenAI-compatible routes, use the generic request helper:

```python
response = client.request(
    path="/v1/models/gemini-2.5-flash-lite:generateContent",
    provider="gemini",
    payload={"contents": [{"parts": [{"text": "My phone is 555-123-9911."}]}]},
)
```

Run the SDK test from the repository root:

```bash
python -m unittest discover -s sdk/python -p "test_*.py"
```
