"""
Compliance agent chat persistence endpoints
Provides stateful chat history and persistence, scoped per tenant.
"""

import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional, Any
from uuid import UUID

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_scopes
from app.db.models import ChatMessage, ChatSession, ComplianceWorkflow
from app.orchestrator.runner import ComplianceWorkflowRunner, _create_approval_in_db, emit_audit_event
from app.rag import service as rag_service
from app.services.notifications import create_notification

logger = logging.getLogger("api.chat")
router = APIRouter()


class SessionCreateRequest(BaseModel):
    title: str = Field(default="New Chat")


class MessageCreateRequest(BaseModel):
    message: str


class SessionResponse(BaseModel):
    id: UUID
    tenant_id: UUID
    title: str
    created_at: datetime

    class Config:
        from_attributes = True


class MessageResponse(BaseModel):
    id: UUID
    sender: str
    text: str
    results: Optional[Any] = None
    timestamp: datetime

    class Config:
        from_attributes = True


def classify_intent(message: str) -> str:
    msg = message.lower().strip()
    if (
        "run gdpr scan" in msg or
        "run hipaa scan" in msg or
        "run soc2 scan" in msg or
        "run soc 2 scan" in msg or
        "check compliance posture" in msg or
        "compliance posture" in msg or
        (any(msg.startswith(prefix) for prefix in ["run ", "start ", "execute ", "check ", "trigger ", "launch "]) and
         any(fw in msg for fw in ["gdpr", "hipaa", "soc2", "soc 2"]))
    ):
        return "SCAN_REQUEST"

    if (
        "apply remediation" in msg or
        "execute fixes" in msg or
        "deploy policy" in msg or
        "infrastructure modifications" in msg or
        "infrastructure modification" in msg or
        "fix findings" in msg or
        any(msg.startswith(prefix) for prefix in ["remediate", "fix", "apply"])
    ):
        return "EXECUTION_REQUEST"

    return "READ_ONLY"


@router.get("/sessions", response_model=list[SessionResponse])
def list_sessions(
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """List all chat sessions for the active tenant."""
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    sessions = db.query(ChatSession).filter(
        ChatSession.tenant_id == tenant_id
    ).order_by(ChatSession.created_at.desc()).all()
    return sessions


@router.post("/sessions", response_model=SessionResponse, status_code=201)
def create_session(
    request: Request,
    body: SessionCreateRequest,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["write"]),
):
    """Create a new chat session for the active tenant."""
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    session = ChatSession(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        title=body.title
    )
    db.add(session)
    db.flush()
    db.refresh(session)
    db.commit()
    return session


@router.get("/sessions/{session_id}/history", response_model=list[MessageResponse])
def get_session_history(
    session_id: UUID,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["read"]),
):
    """Retrieve chronological message list for a session."""
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    session = db.query(ChatSession).filter(
        ChatSession.id == session_id,
        ChatSession.tenant_id == tenant_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found")

    messages = db.query(ChatMessage).filter(
        ChatMessage.session_id == session_id
    ).order_by(ChatMessage.timestamp.asc()).all()
    return messages


@router.post("/sessions/{session_id}/message")
def post_message(
    session_id: UUID,
    body: MessageCreateRequest,
    request: Request,
    db: Session = Depends(get_tenant_db),
    _auth=require_scopes(["write"]),
):
    """Post a user message, process it and return the response."""
    tenant_id = uuid.UUID(str(request.state.tenant_id))
    session = db.query(ChatSession).filter(
        ChatSession.id == session_id,
        ChatSession.tenant_id == tenant_id
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found")

    message_text = body.message
    if not message_text or not message_text.strip():
        raise HTTPException(status_code=400, detail="Message is required")

    # Save user message to database
    user_msg = ChatMessage(
        id=uuid.uuid4(),
        session_id=session_id,
        sender="user",
        text=message_text,
        timestamp=datetime.utcnow()
    )
    db.add(user_msg)
    db.commit()

    # Rename session if it's the first message!
    msg_count = db.query(ChatMessage).filter(ChatMessage.session_id == session_id).count()
    if msg_count == 1:
        session.title = message_text[:50] + ("..." if len(message_text) > 50 else "")
        db.commit()

    intent = classify_intent(message_text)

    response_text = ""
    results_payload = None

    if intent == "SCAN_REQUEST":
        # Extract framework
        msg_lower = message_text.lower()
        framework = "GDPR"
        if "hipaa" in msg_lower:
            framework = "HIPAA"
        elif "soc" in msg_lower:
            framework = "SOC2"

        try:
            runner = ComplianceWorkflowRunner(db)
            scan_res = runner.start(
                tenant_id=str(tenant_id),
                framework=framework,
                request_id=None,
            )
            response_text = (
                f"Initiating {framework} compliance scan. EPHEMERAL WORKER started.\n\n"
                f"[System] Workflow launched successfully! Scan completed immediately without immediate approval. "
                f"ID: {scan_res['workflow_id']}. State: {scan_res['current_state']}."
            )
            results_payload = scan_res
        except Exception as exc:
            logger.error("Failed to trigger scan from chat: %s", exc)
            response_text = f"Failed to execute scan request: {str(exc)}"

    elif intent == "EXECUTION_REQUEST":
        # Find UUID in user message
        uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I)
        match = uuid_pattern.search(message_text)

        if not match:
            response_text = (
                "To apply remediation, please select a completed scan from the ledger on the left and click "
                "'Apply Remediation', or specify the scan UUID in your message (e.g. 'Apply remediation for scan 12345678-abcd-...')."
            )
        else:
            workflow_id = match.group(0)
            wf = db.query(ComplianceWorkflow).filter(
                ComplianceWorkflow.workflow_id == workflow_id,
                ComplianceWorkflow.tenant_id == tenant_id
            ).first()
            if not wf:
                response_text = f"Compliance workflow {workflow_id} not found."
            elif wf.execution_status != "COMPLETED":
                response_text = f"Workflow {workflow_id} is not in COMPLETED state (current state: {wf.execution_status})."
            elif not wf.remediation_plan:
                response_text = f"No remediation plan is available for workflow {workflow_id}."
            else:
                try:
                    approval_id = _create_approval_in_db(db, str(tenant_id), workflow_id, wf.remediation_plan)

                    wf.execution_status = "PAUSED"
                    wf.current_state = "AWAITING_APPROVAL"
                    wf.approval_status = "PENDING"
                    wf.approval_id = uuid.UUID(approval_id)

                    from sqlalchemy.orm.attributes import flag_modified
                    state_data = wf.state_data or {}
                    state_data.update({
                        "current_state": "AWAITING_APPROVAL",
                        "execution_status": "PAUSED",
                        "remediation_state": "NOT_STARTED",
                        "remediation_actions": [],
                        "rollback_result": {},
                        "approval_status": "PENDING",
                        "approval_id": approval_id,
                    })
                    wf.state_data = state_data
                    flag_modified(wf, "state_data")
                    wf.updated_at = datetime.utcnow()

                    db.commit()
                    create_notification(
                        db,
                        tenant_id=tenant_id,
                        type="approval_requested",
                        severity="warning",
                        title="Approval requested",
                        body=f"Workflow {workflow_id} is waiting for remediation approval.",
                        link="/agent",
                    )

                    emit_audit_event(
                        workflow_id, str(tenant_id), wf.request_id or "",
                        "COMPLETE→AWAITING_APPROVAL", "create_approval", "pending"
                    )

                    runner = ComplianceWorkflowRunner(db)
                    wf_status = runner.get_status(workflow_id, str(tenant_id))

                    response_text = (
                        f"Remediation workflow initiated for scan {workflow_id}. "
                        f"A pending approval has been generated and requires your MFA confirmation to execute remediation."
                    )
                    results_payload = wf_status
                except Exception as exc:
                    logger.error("Failed to trigger remediation from chat: %s", exc)
                    response_text = f"Failed to execute remediation: {str(exc)}"

    else:  # READ_ONLY: Query Gemini via reverse proxy (current message only)
        gateway_url = os.getenv("GATEWAY_URL", "http://localhost:8080")
        # Use the Authorization header forwarded from the frontend (raw API key Bearer token)
        # Fallback to a configured gateway key if the header is unavailable
        auth_header = request.headers.get("Authorization") or f"Bearer {os.getenv('GATEWAY_API_KEY', '')}"
        rag_result = rag_service.answer_question(db, message_text)

        # Send ONLY the current user message — not the full history.
        # Gemini's stateless API doesn't benefit from history here and it
        # inflates prompt_count / billing unnecessarily.
        contents = [
            {
                "role": "user",
                "parts": [{"text": rag_result["prompt"]}]
            }
        ]

        if not rag_result["grounded"]:
            response_text = rag_result["answer"]
        else:
            try:
                res = requests.post(
                    f"{gateway_url}/v1/models/gemini-2.5-flash-lite:generateContent",
                    headers={
                        "Authorization": auth_header,
                        "Content-Type": "application/json"
                    },
                    json={"contents": contents},
                    timeout=30
                )
                if not res.ok:
                    logger.error("Gateway request failed: %s", res.text)
                    response_text = rag_result["answer"]
                else:
                    data = res.json()
                    model_answer = data.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    response_text = model_answer or rag_result["answer"]
                    citation_ids = [item["id"] for item in rag_result["citations"]]
                    if citation_ids and not any(f"[{citation_id}]" in response_text for citation_id in citation_ids):
                        response_text = f"{response_text.rstrip()}\n\nGrounding citations: " + ", ".join(f"[{item}]" for item in citation_ids[:3])
            except Exception as exc:
                logger.error("Failed to query Gemini: %s", exc)
                response_text = rag_result["answer"]

        results_payload = {
            "type": "rag_answer",
            "question": message_text,
            "corpus_version": rag_result["corpus_version"],
            "corpus_checksum": rag_result["corpus_checksum"],
            "grounded": rag_result["grounded"],
            "citations": rag_result["citations"],
            "retrieved_chunks": rag_result["retrieved_chunks"],
        }

    # Save agent response
    agent_msg = ChatMessage(
        id=uuid.uuid4(),
        session_id=session_id,
        sender="agent",
        text=response_text,
        results=results_payload,
        timestamp=datetime.utcnow()
    )
    db.add(agent_msg)
    db.commit()

    return {
        "text": response_text,
        "results": results_payload,
        "session_title": session.title
    }
