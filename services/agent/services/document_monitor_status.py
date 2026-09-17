"""Process-local document monitor status; safe for liveness metric scrapes."""
import threading


_lock = threading.Lock()
_state = {
    "enabled": False,
    "status": "disabled",
    "tenant_configured": False,
    "failures_total": 0,
    "last_error_type": None,
    "last_success_timestamp": None,
}


def update_monitor_status(**changes):
    with _lock:
        _state.update(changes)


def monitor_status() -> dict:
    with _lock:
        return dict(_state)


def monitor_metrics_snapshot() -> dict:
    state = monitor_status()
    return {
        "enabled": int(state["enabled"]),
        "healthy": int(state["status"] == "healthy"),
        "failures_total": state["failures_total"],
        "last_success_timestamp_seconds": state["last_success_timestamp"] or 0,
    }
