import time

from services.audit_agent import AuditAgent


def audit_node(state):
    print("[Audit Start] (Audit Agent)", flush=True)
    start_time = time.perf_counter()

    state = AuditAgent().record(state)

    duration = time.perf_counter() - start_time
    print(f"[Audit End] Duration: {duration:.4f}s", flush=True)
    return state
