from approval_store import pending_approvals
from graph import graph


def resume_approved_request(approval_id: str):

    approval = pending_approvals.get(approval_id)

    if not approval:
        return {
            "error": "Approval not found"
        }

    if approval["status"] != "APPROVED":
        return {
            "error": "Request not approved yet"
        }

    result = graph.invoke(
        {
            "message": approval["query"],
            "approval_status": "APPROVED"
        }
    )

    return result