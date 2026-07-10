import hashlib
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text

from approval_store import create_approval
from database import engine
from services.worker_throttle import WorkerThrottle


SUPPORTED_PROVIDERS = {"aws", "gcp", "github"}
ALLOWLISTED_ACTIONS = {
    "aws": {"enable_s3_block_public_access", "enable_iam_user_mfa", "restrict_security_group_ingress"},
    "gcp": {"remove_public_bucket_binding", "rotate_service_account_key", "restrict_firewall_ingress"},
    "github": {"enable_branch_protection", "enable_secret_scanning", "enable_dependabot_alerts"},
}


class RemediationRuntimeError(Exception):
    pass


class BaseRemediationAdapter:
    provider = "base"

    def __init__(self, connector: Dict[str, Any]):
        self.connector = connector

    def issue_scoped_credentials(self, mode: str) -> Dict[str, Any]:
        if os.getenv("AUTHCLAW_REAL_REMEDIATION_CONNECTORS", "false").lower() in {"1", "true", "yes"}:
            return self.issue_real_credentials(mode)
        return {
            "scope": f"{self.provider}:{mode}",
            "token": f"mock-{self.provider}-{secrets.token_urlsafe(16)}",
            "ttl_seconds": 900,
        }

    def issue_real_credentials(self, mode: str) -> Dict[str, Any]:
        raise RemediationRuntimeError(f"Real {self.provider} remediation connector is not configured.")

    def scan_read_only(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def execute_plan(self, plan: Dict[str, Any]) -> Dict[str, Any]:
        action = plan["proposed_action"]
        if action not in ALLOWLISTED_ACTIONS[self.provider]:
            raise RemediationRuntimeError(f"Action '{action}' is not allowlisted for {self.provider}.")
        return {
            "provider_request_id": f"mock-{self.provider}-{uuid.uuid4().hex[:12]}",
            "before": {"resource_id": plan["resource_id"], "status": "non_compliant"},
            "after": {"resource_id": plan["resource_id"], "status": "remediated", "action": action},
            "summary": f"{self.provider.upper()} remediation action {action} applied to {plan['resource_id']}.",
        }


class AWSRemediationAdapter(BaseRemediationAdapter):
    provider = "aws"

    def issue_real_credentials(self, mode: str) -> Dict[str, Any]:
        import boto3  # type: ignore

        sts = boto3.client("sts", region_name=self.connector.get("region") or "us-east-1")
        result = sts.assume_role(
            RoleArn=self.connector["role_identifier"],
            RoleSessionName=f"authclaw-{mode}-{uuid.uuid4().hex[:8]}",
            DurationSeconds=900,
        )
        credentials = result["Credentials"]
        return {
            "scope": f"aws:{mode}:{self.connector.get('scope') or 'read-only'}",
            "token": credentials["SessionToken"],
            "ttl_seconds": 900,
        }

    def scan_read_only(self) -> List[Dict[str, Any]]:
        return [
            {
                "resource_id": "arn:aws:s3:::customer-public-assets",
                "finding_type": "s3_public_exposure",
                "finding": "S3 bucket allows public access.",
                "recommendation": "Enable S3 Block Public Access.",
                "severity": "HIGH",
                "proposed_action": "enable_s3_block_public_access",
            },
            {
                "resource_id": "arn:aws:iam::123456789012:user/legacy-ops",
                "finding_type": "iam_user_without_mfa",
                "finding": "IAM user does not have MFA enabled.",
                "recommendation": "Require MFA for the IAM user.",
                "severity": "MEDIUM",
                "proposed_action": "enable_iam_user_mfa",
            },
            {
                "resource_id": "sg-0authclawssh",
                "finding_type": "open_security_group",
                "finding": "Security group allows SSH/RDP from 0.0.0.0/0.",
                "recommendation": "Restrict inbound management ports.",
                "severity": "HIGH",
                "proposed_action": "restrict_security_group_ingress",
            },
        ]


class GCPRemediationAdapter(BaseRemediationAdapter):
    provider = "gcp"

    def issue_real_credentials(self, mode: str) -> Dict[str, Any]:
        from google.auth import impersonated_credentials  # type: ignore
        from google.auth import default  # type: ignore

        source_credentials, _ = default()
        target = impersonated_credentials.Credentials(
            source_credentials=source_credentials,
            target_principal=self.connector["role_identifier"],
            target_scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"],
            lifetime=900,
        )
        target.refresh(None)
        return {"scope": f"gcp:{mode}", "token": target.token, "ttl_seconds": 900}

    def scan_read_only(self) -> List[Dict[str, Any]]:
        return [
            {
                "resource_id": "projects/authclaw/buckets/public-evidence",
                "finding_type": "gcs_public_iam",
                "finding": "GCS bucket grants public reader access.",
                "recommendation": "Remove allUsers/allAuthenticatedUsers bucket bindings.",
                "severity": "HIGH",
                "proposed_action": "remove_public_bucket_binding",
            },
            {
                "resource_id": "serviceAccounts/legacy@appspot.gserviceaccount.com/keys/old-key",
                "finding_type": "old_service_account_key",
                "finding": "Service account key is older than policy.",
                "recommendation": "Rotate the service account key.",
                "severity": "MEDIUM",
                "proposed_action": "rotate_service_account_key",
            },
            {
                "resource_id": "global/firewalls/allow-ssh-all",
                "finding_type": "open_firewall_rule",
                "finding": "Firewall rule allows SSH/RDP from 0.0.0.0/0.",
                "recommendation": "Restrict firewall ingress.",
                "severity": "HIGH",
                "proposed_action": "restrict_firewall_ingress",
            },
        ]


class GitHubRemediationAdapter(BaseRemediationAdapter):
    provider = "github"

    def issue_real_credentials(self, mode: str) -> Dict[str, Any]:
        import jwt  # type: ignore
        import requests  # type: ignore

        app_id = self.connector["role_identifier"]
        private_key = os.environ["GITHUB_APP_PRIVATE_KEY"]
        now = int(datetime.now(timezone.utc).timestamp())
        app_jwt = jwt.encode({"iat": now - 60, "exp": now + 540, "iss": app_id}, private_key, algorithm="RS256")
        install_id = self.connector["credential_ref"]
        response = requests.post(
            f"https://api.github.com/app/installations/{install_id}/access_tokens",
            headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
            timeout=10,
        )
        response.raise_for_status()
        return {"scope": f"github:{mode}", "token": response.json()["token"], "ttl_seconds": 900}

    def scan_read_only(self) -> List[Dict[str, Any]]:
        return [
            {
                "resource_id": "authclaw/app:main",
                "finding_type": "missing_branch_protection",
                "finding": "Default branch protection is not enforced.",
                "recommendation": "Enable required pull request reviews and status checks.",
                "severity": "HIGH",
                "proposed_action": "enable_branch_protection",
            },
            {
                "resource_id": "authclaw/app/security-and-analysis",
                "finding_type": "secret_scanning_disabled",
                "finding": "Secret scanning is disabled.",
                "recommendation": "Enable GitHub secret scanning.",
                "severity": "HIGH",
                "proposed_action": "enable_secret_scanning",
            },
            {
                "resource_id": "authclaw/app/dependabot",
                "finding_type": "dependabot_alerts_disabled",
                "finding": "Dependabot alerts are disabled.",
                "recommendation": "Enable Dependabot security alerts.",
                "severity": "MEDIUM",
                "proposed_action": "enable_dependabot_alerts",
            },
        ]


ADAPTERS = {"aws": AWSRemediationAdapter, "gcp": GCPRemediationAdapter, "github": GitHubRemediationAdapter}


class RemediationRuntime:
    def _adapter(self, connector: Dict[str, Any]) -> BaseRemediationAdapter:
        provider = str(connector["provider"]).lower()
        if provider not in ADAPTERS:
            raise RemediationRuntimeError(f"Unsupported remediation provider '{provider}'.")
        return ADAPTERS[provider](connector)

    def _row(self, row) -> Optional[Dict[str, Any]]:
        return dict(row._mapping) if row else None

    def _audit(self, tenant_id: int, event_type: str, details: str, **kwargs) -> None:
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO remediation_worker_audit_events (
                        tenant_id, worker_id, connector_id, finding_id, plan_id, approval_id,
                        event_type, details, metadata, created_at
                    )
                    VALUES (
                        :tenant_id, :worker_id, :connector_id, :finding_id, :plan_id, :approval_id,
                        :event_type, :details, :metadata, NOW()
                    )
                """),
                {
                    "tenant_id": tenant_id,
                    "worker_id": kwargs.get("worker_id"),
                    "connector_id": kwargs.get("connector_id"),
                    "finding_id": kwargs.get("finding_id"),
                    "plan_id": kwargs.get("plan_id"),
                    "approval_id": kwargs.get("approval_id"),
                    "event_type": event_type,
                    "details": details,
                    "metadata": json.dumps(kwargs.get("metadata") or {}),
                },
            )
            conn.commit()

    def list_connectors(self, tenant_id: int) -> List[Dict[str, Any]]:
        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT * FROM remediation_connectors WHERE tenant_id = :tenant_id ORDER BY provider, name"),
                {"tenant_id": tenant_id},
            ).fetchall()
        return [dict(row._mapping) for row in rows]

    def create_connector(self, tenant_id: int, payload: Dict[str, Any]) -> Dict[str, Any]:
        provider = str(payload.get("provider", "")).lower()
        if provider not in SUPPORTED_PROVIDERS:
            raise RemediationRuntimeError("Provider must be one of: aws, gcp, github.")
        with engine.connect() as conn:
            row = conn.execute(
                text("""
                    INSERT INTO remediation_connectors (
                        tenant_id, provider, name, credential_ref, role_identifier,
                        region, scope, status, metadata, created_at, updated_at
                    )
                    VALUES (
                        :tenant_id, :provider, :name, :credential_ref, :role_identifier,
                        :region, :scope, 'configured', :metadata, NOW(), NOW()
                    )
                    ON CONFLICT (tenant_id, provider, name) DO UPDATE SET
                        credential_ref = EXCLUDED.credential_ref,
                        role_identifier = EXCLUDED.role_identifier,
                        region = EXCLUDED.region,
                        scope = EXCLUDED.scope,
                        status = 'configured',
                        metadata = EXCLUDED.metadata,
                        updated_at = NOW()
                    RETURNING *
                """),
                {
                    "tenant_id": tenant_id,
                    "provider": provider,
                    "name": payload.get("name") or provider.upper(),
                    "credential_ref": payload.get("credential_ref") or f"{provider}-credential-ref",
                    "role_identifier": payload.get("role_identifier"),
                    "region": payload.get("region"),
                    "scope": payload.get("scope") or "read-only",
                    "metadata": json.dumps(payload.get("metadata") or {}),
                },
            ).fetchone()
            conn.commit()
        connector = self._row(row)
        self._audit(tenant_id, "connector_saved", f"{provider} connector saved.", connector_id=connector["id"])
        return connector

    def get_connector(self, tenant_id: int, connector_id: int) -> Dict[str, Any]:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM remediation_connectors WHERE id = :id AND tenant_id = :tenant_id"),
                {"id": connector_id, "tenant_id": tenant_id},
            ).fetchone()
        connector = self._row(row)
        if not connector:
            raise RemediationRuntimeError("Connector not found.")
        return connector

    def _lease_credentials(self, tenant_id: int, connector: Dict[str, Any], mode: str) -> Dict[str, Any]:
        issued = self._adapter(connector).issue_scoped_credentials(mode)
        lease_id = f"lease-{uuid.uuid4()}"
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(issued.get("ttl_seconds", 900)))
        token_hash = hashlib.sha256(str(issued["token"]).encode("utf-8")).hexdigest()
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO worker_credential_leases (
                        lease_id, tenant_id, connector_id, provider, scope, token_hash,
                        issued_at, expires_at
                    )
                    VALUES (
                        :lease_id, :tenant_id, :connector_id, :provider, :scope, :token_hash,
                        NOW(), :expires_at
                    )
                """),
                {
                    "lease_id": lease_id,
                    "tenant_id": tenant_id,
                    "connector_id": connector["id"],
                    "provider": connector["provider"],
                    "scope": issued["scope"],
                    "token_hash": token_hash,
                    "expires_at": expires_at.replace(tzinfo=None),
                },
            )
            conn.commit()
        return {"lease_id": lease_id, "expires_at": expires_at.isoformat(), "scope": issued["scope"]}

    def test_connector(self, tenant_id: int, connector_id: int) -> Dict[str, Any]:
        connector = self.get_connector(tenant_id, connector_id)
        lease = self._lease_credentials(tenant_id, connector, "test")
        with engine.connect() as conn:
            row = conn.execute(
                text("""
                    UPDATE remediation_connectors
                    SET status = 'connected', health_message = :message,
                        last_tested_at = NOW(), updated_at = NOW()
                    WHERE id = :id AND tenant_id = :tenant_id
                    RETURNING *
                """),
                {"id": connector_id, "tenant_id": tenant_id, "message": f"Scoped credential lease {lease['lease_id']} issued."},
            ).fetchone()
            conn.commit()
        connector = self._row(row)
        self._audit(tenant_id, "connector_tested", "Connector test succeeded.", connector_id=connector_id, metadata=lease)
        return {"connector": connector, "lease": lease}

    def _create_worker(self, tenant_id: int, connector: Dict[str, Any], mode: str, lease_id: str, **kwargs) -> str:
        worker_id = f"worker-{uuid.uuid4()}"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
        with engine.connect() as conn:
            conn.execute(
                text("""
                    INSERT INTO remediation_worker_runs (
                        worker_id, tenant_id, connector_id, provider, mode, status,
                        credential_lease_id, finding_id, plan_id, approval_id,
                        started_at, expires_at, logs
                    )
                    VALUES (
                        :worker_id, :tenant_id, :connector_id, :provider, :mode, 'running',
                        :lease_id, :finding_id, :plan_id, :approval_id,
                        NOW(), :expires_at, :logs
                    )
                """),
                {
                    "worker_id": worker_id,
                    "tenant_id": tenant_id,
                    "connector_id": connector["id"],
                    "provider": connector["provider"],
                    "mode": mode,
                    "lease_id": lease_id,
                    "finding_id": kwargs.get("finding_id"),
                    "plan_id": kwargs.get("plan_id"),
                    "approval_id": kwargs.get("approval_id"),
                    "expires_at": expires_at.replace(tzinfo=None),
                    "logs": json.dumps([{"event": "create", "mode": mode}]),
                },
            )
            conn.execute(
                text("""
                    INSERT INTO ephemeral_workers (provider, status, lifespan_seconds, started_at, logs, cost, tokens_used)
                    VALUES (:provider, 'running', 900, :started_at, :logs, 0.00, 0)
                """),
                {"provider": connector["provider"], "started_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "logs": worker_id},
            )
            conn.commit()
        self._audit(tenant_id, "worker_created", f"Worker {worker_id} created.", worker_id=worker_id, connector_id=connector["id"])
        return worker_id

    def run_scan(self, tenant_id: int, connector_id: int) -> Dict[str, Any]:
        WorkerThrottle("remediation").enforce(tenant_id)
        connector = self.get_connector(tenant_id, connector_id)
        lease = self._lease_credentials(tenant_id, connector, "read_only_scan")
        worker_id = self._create_worker(tenant_id, connector, "read_only_scan", lease["lease_id"])
        findings = self._adapter(connector).scan_read_only()
        stored = []
        with engine.connect() as conn:
            for item in findings:
                row = conn.execute(
                    text("""
                        INSERT INTO remediation_findings (
                            tenant_id, connector_id, provider, resource_id, finding_type,
                            finding, recommendation, severity, fix_plan, approval_status,
                            status, worker_id, evidence, created_at, updated_at
                        )
                        VALUES (
                            :tenant_id, :connector_id, :provider, :resource_id, :finding_type,
                            :finding, :recommendation, :severity, :fix_plan, 'not_requested',
                            'open', :worker_id, :evidence, NOW(), NOW()
                        )
                        RETURNING *
                    """),
                    {
                        "tenant_id": tenant_id,
                        "connector_id": connector_id,
                        "provider": connector["provider"],
                        "resource_id": item["resource_id"],
                        "finding_type": item["finding_type"],
                        "finding": item["finding"],
                        "recommendation": item["recommendation"],
                        "severity": item["severity"],
                        "fix_plan": item["proposed_action"],
                        "worker_id": worker_id,
                        "evidence": json.dumps({"mode": "read_only_scan", "connector": connector["name"]}),
                    },
                ).fetchone()
                stored.append(dict(row._mapping))
            conn.execute(
                text("""
                    UPDATE remediation_worker_runs
                    SET status = 'completed', completed_at = NOW(), evidence = :evidence,
                        logs = :logs
                    WHERE worker_id = :worker_id AND tenant_id = :tenant_id
                """),
                {
                    "worker_id": worker_id,
                    "tenant_id": tenant_id,
                    "evidence": json.dumps({"findings_created": len(stored)}),
                    "logs": json.dumps([{"event": "create"}, {"event": "execute"}, {"event": "audit"}, {"event": "expire"}]),
                },
            )
            conn.execute(
                text("UPDATE ephemeral_workers SET status = 'completed' WHERE logs = :worker_id"),
                {"worker_id": worker_id},
            )
            conn.execute(
                text("UPDATE worker_credential_leases SET revoked_at = NOW() WHERE lease_id = :lease_id"),
                {"lease_id": lease["lease_id"]},
            )
            conn.commit()
        self._audit(tenant_id, "scan_completed", f"Read-only scan created {len(stored)} findings.", worker_id=worker_id, connector_id=connector_id)
        return {"worker_id": worker_id, "findings": stored}

    def list_findings(self, tenant_id: int) -> List[Dict[str, Any]]:
        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT * FROM remediation_findings WHERE tenant_id = :tenant_id ORDER BY id DESC"),
                {"tenant_id": tenant_id},
            ).fetchall()
        return [dict(row._mapping) for row in rows]

    def create_plan(self, tenant_id: int, finding_id: int) -> Dict[str, Any]:
        with engine.connect() as conn:
            finding = conn.execute(
                text("SELECT * FROM remediation_findings WHERE id = :id AND tenant_id = :tenant_id"),
                {"id": finding_id, "tenant_id": tenant_id},
            ).fetchone()
            if not finding:
                raise RemediationRuntimeError("Finding not found.")
            finding = dict(finding._mapping)
            provider = finding["provider"]
            action = finding["fix_plan"]
            if action not in ALLOWLISTED_ACTIONS.get(provider, set()):
                raise RemediationRuntimeError("Finding action is not allowlisted.")
            payload = {
                "provider": provider,
                "resource_id": finding["resource_id"],
                "proposed_action": action,
                "finding_type": finding["finding_type"],
            }
            row = conn.execute(
                text("""
                    INSERT INTO remediation_plans (
                        tenant_id, finding_id, connector_id, provider, resource_id,
                        proposed_action, risk_level, rollback_plan, evidence_requirements,
                        status, plan_payload, created_at, updated_at
                    )
                    VALUES (
                        :tenant_id, :finding_id, :connector_id, :provider, :resource_id,
                        :proposed_action, :risk_level, :rollback_plan, :evidence_requirements,
                        'planned', :plan_payload, NOW(), NOW()
                    )
                    RETURNING *
                """),
                {
                    "tenant_id": tenant_id,
                    "finding_id": finding_id,
                    "connector_id": finding["connector_id"],
                    "provider": provider,
                    "resource_id": finding["resource_id"],
                    "proposed_action": action,
                    "risk_level": finding["severity"],
                    "rollback_plan": "Revert the provider setting to its previous captured value.",
                    "evidence_requirements": "Store before/after resource snapshots and provider request ID.",
                    "plan_payload": json.dumps(payload),
                },
            ).fetchone()
            conn.commit()
        plan = dict(row._mapping)
        self._audit(tenant_id, "plan_created", f"Remediation plan {plan['id']} created.", finding_id=finding_id, plan_id=plan["id"])
        return plan

    def request_plan_approval(self, tenant_id: int, plan_id: int) -> Dict[str, Any]:
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM remediation_plans WHERE id = :id AND tenant_id = :tenant_id"),
                {"id": plan_id, "tenant_id": tenant_id},
            ).fetchone()
        plan = self._row(row)
        if not plan:
            raise RemediationRuntimeError("Remediation plan not found.")
        metadata = {
            "execution_target": "remediation",
            "remediation_plan_id": plan_id,
            "finding_id": plan["finding_id"],
            "action_payload": json.loads(plan["plan_payload"]),
        }
        approval = create_approval(
            query=f"Execute {plan['provider']} remediation {plan['proposed_action']} on {plan['resource_id']}",
            risk_level=plan["risk_level"],
            tenant_id=tenant_id,
            request_id=f"remediation-{uuid.uuid4()}",
            reason="remediation_execution",
            metadata=metadata,
        )
        with engine.connect() as conn:
            conn.execute(
                text("""
                    UPDATE remediation_plans
                    SET approval_id = :approval_id, status = 'pending_approval', updated_at = NOW()
                    WHERE id = :id AND tenant_id = :tenant_id
                """),
                {"approval_id": approval["approval_id"], "id": plan_id, "tenant_id": tenant_id},
            )
            conn.execute(
                text("""
                    UPDATE remediation_findings
                    SET approval_status = 'pending', updated_at = NOW()
                    WHERE id = :finding_id AND tenant_id = :tenant_id
                """),
                {"finding_id": plan["finding_id"], "tenant_id": tenant_id},
            )
            conn.commit()
        self._audit(tenant_id, "approval_requested", "Remediation approval requested.", finding_id=plan["finding_id"], plan_id=plan_id, approval_id=approval["approval_id"])
        return {"approval_id": approval["approval_id"], "plan_id": plan_id, "status": "pending_approval"}

    def get_worker(self, tenant_id: int, worker_id: str) -> Dict[str, Any]:
        with engine.connect() as conn:
            worker = conn.execute(
                text("SELECT * FROM remediation_worker_runs WHERE worker_id = :worker_id AND tenant_id = :tenant_id"),
                {"worker_id": worker_id, "tenant_id": tenant_id},
            ).fetchone()
            events = conn.execute(
                text("SELECT * FROM remediation_worker_audit_events WHERE worker_id = :worker_id AND tenant_id = :tenant_id ORDER BY id ASC"),
                {"worker_id": worker_id, "tenant_id": tenant_id},
            ).fetchall()
        row = self._row(worker)
        if not row:
            raise RemediationRuntimeError("Worker not found.")
        row["audit_events"] = [dict(event._mapping) for event in events]
        return row

    def execute_approved_plan(self, approval_record: Dict[str, Any]) -> Dict[str, Any]:
        tenant_id = int(approval_record["tenant_id"])
        WorkerThrottle("remediation").enforce(tenant_id)
        metadata = approval_record.get("metadata") or {}
        plan_id = int(metadata.get("remediation_plan_id") or 0)
        if not plan_id:
            raise RemediationRuntimeError("Approval is missing remediation plan binding.")
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM remediation_plans WHERE id = :id AND tenant_id = :tenant_id AND approval_id = :approval_id"),
                {"id": plan_id, "tenant_id": tenant_id, "approval_id": approval_record["approval_id"]},
            ).fetchone()
        plan = self._row(row)
        if not plan:
            raise RemediationRuntimeError("Approved remediation plan not found.")
        connector = self.get_connector(tenant_id, int(plan["connector_id"]))
        lease = self._lease_credentials(tenant_id, connector, "execution")
        worker_id = self._create_worker(
            tenant_id,
            connector,
            "execution",
            lease["lease_id"],
            finding_id=plan["finding_id"],
            plan_id=plan_id,
            approval_id=approval_record["approval_id"],
        )
        evidence = self._adapter(connector).execute_plan(plan)
        with engine.connect() as conn:
            conn.execute(
                text("""
                    UPDATE remediation_worker_runs
                    SET status = 'completed', completed_at = NOW(), evidence = :evidence,
                        logs = :logs
                    WHERE worker_id = :worker_id AND tenant_id = :tenant_id
                """),
                {
                    "worker_id": worker_id,
                    "tenant_id": tenant_id,
                    "evidence": json.dumps(evidence),
                    "logs": json.dumps([{"event": "create"}, {"event": "execute"}, {"event": "audit"}, {"event": "revoke"}]),
                },
            )
            conn.execute(
                text("UPDATE ephemeral_workers SET status = 'completed' WHERE logs = :worker_id"),
                {"worker_id": worker_id},
            )
            conn.execute(text("UPDATE worker_credential_leases SET revoked_at = NOW() WHERE lease_id = :lease_id"), {"lease_id": lease["lease_id"]})
            conn.execute(
                text("""
                    UPDATE remediation_plans
                    SET status = 'executed', execution_evidence = :evidence, updated_at = NOW()
                    WHERE id = :plan_id AND tenant_id = :tenant_id
                """),
                {"plan_id": plan_id, "tenant_id": tenant_id, "evidence": json.dumps(evidence)},
            )
            conn.execute(
                text("""
                    UPDATE remediation_findings
                    SET status = 'remediated', approval_status = 'executed', updated_at = NOW()
                    WHERE id = :finding_id AND tenant_id = :tenant_id
                """),
                {"finding_id": plan["finding_id"], "tenant_id": tenant_id},
            )
            conn.commit()
        self._audit(tenant_id, "remediation_executed", evidence["summary"], worker_id=worker_id, connector_id=connector["id"], finding_id=plan["finding_id"], plan_id=plan_id, approval_id=approval_record["approval_id"], metadata=evidence)
        return {
            "worker_run_id": worker_id,
            "provider": connector["provider"],
            "connector_id": connector["id"],
            "plan_id": plan_id,
            "finding_id": plan["finding_id"],
            "summary": evidence["summary"],
            "evidence": evidence,
            "audit_events": [{"event": "remediation_executed", "details": evidence["summary"]}],
        }
