import json
import logging
from datetime import datetime, timezone
from state import AuthState
from services.security_agent import SecurityAgent
from verify_audit import log_agent_event

logger = logging.getLogger("authclaw.risk")


import time
import concurrent.futures

def risk_node(state: AuthState):
    print("[Risk Start]", flush=True)
    start_time = time.perf_counter()

    query = state.get("message", "")
    tenant_id = state.get("tenant_id", 1)
    session_id = state.get("session_id", "default")
    
    # Enforce 5s hard timeout on risk calculation
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(SecurityAgent().classify_risk, query)
        risk_level = future.result(timeout=5.0)
    except concurrent.futures.TimeoutError as te:
        print("[Risk End] Timeout occurred", flush=True)
        raise TimeoutError("Risk Analysis timed out after 5 seconds") from te
    finally:
        executor.shutdown(wait=False)

    security_findings = state.get("security_findings") or []
    finding_actions = {str(finding.get("action", "")).lower() for finding in security_findings}
    if "block" in finding_actions or "require_approval" in finding_actions:
        risk_level = "HIGH"
    elif security_findings and risk_level == "LOW":
        risk_level = "MEDIUM"

    state["risk_level"] = risk_level

    log_agent_event(
        tenant_id=tenant_id,
        session_id=session_id,
        agent_name="Security Agent",
        event_type="RISK_CLASSIFIED",
        details=f"Request classified as {risk_level} risk."
    )
    log_agent_event(
        tenant_id=tenant_id,
        session_id=session_id,
        agent_name="Risk Agent",
        event_type="RISK_CLASSIFIED",
        details=f"Request classified as {risk_level} risk."
    )

    # Structured JSON log for risk classification
    log_data = {
        "event": "risk_classification",
        "query": query[:100],
        "risk_level": risk_level,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    logger.info(json.dumps(log_data))
    print(json.dumps(log_data), flush=True)

    duration = time.perf_counter() - start_time
    print(f"[Risk End] Duration: {duration:.4f}s", flush=True)
    return state
