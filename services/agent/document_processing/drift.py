"""Compatibility boundary for retired aggregate compliance snapshots."""


def get_current_framework_scores(tenant_id=None) -> dict:
    """No tenantless compliance score can be derived from agent diagnostics.

    Tenant-scoped callers can use ComplianceEvidenceEngine for explicitly
    unassessed diagnostics. This legacy report adapter lacks a trusted tenant
    and cannot select an arbitrary tenant or invent a success on failure.
    """
    return {}


def record_compliance_snapshot(tenant_id=None) -> None:
    """Retain historical data, but stop unversioned aggregate writes and alerts.

    Existing document/monitoring callers may continue invoking this hook. Only
    the canonical backend owns authoritative, version-aware score snapshots.
    """
    return None
