# AuthClaw agent service

This service is derived from Vidhi Sharma's AuthClaw repository and contains the LangGraph
agent, regulatory RAG, document processing, provider routing, risk, redaction and HITL
logic requested for consolidation.

It intentionally keeps its original internal module layout because the source uses
service-root imports (`from nodes...`, `from services...`). Run commands from this folder:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8001
```

In the consolidated deployment the service is internal. The control plane remains the
authority for identity, tenants and access decisions.
