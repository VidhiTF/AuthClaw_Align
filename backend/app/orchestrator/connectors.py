import hashlib
import io
import json
import logging
import os
import re
import base64
from typing import Optional

from app.orchestrator.remediation_state import MutationPhase, new_mutation_state, upgrade_mutation_state

logger = logging.getLogger("orchestrator.scanner")


SENSITIVE_PATTERNS = [
    ("EMAIL_ADDRESS", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "[REDACTED_EMAIL]"),
    ("US_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CARD]"),
    ("PHONE_NUMBER", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED_PHONE]"),
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _checksum_sha256(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _precondition_failed(exc: Exception) -> bool:
    response = getattr(exc, "response", {}) or {}
    error = response.get("Error", {}) if isinstance(response, dict) else {}
    return str(error.get("Code", "")) in {"PreconditionFailed", "412"} or "precondition" in str(exc).lower()


class RemediationConflictError(RuntimeError):
    """The target no longer matches the prepared remediation operation."""


def redact_sensitive_text(text: str) -> tuple[str, dict]:
    counts = {}
    redacted = text
    for entity, pattern, replacement in SENSITIVE_PATTERNS:
        redacted, count = pattern.subn(replacement, redacted)
        if count:
            counts[entity] = count
    return redacted, {"entity_counts": counts, "total": sum(counts.values())}


def verification_summary(text: str) -> dict:
    return redact_sensitive_text(text)[1]

class DocumentScanner:
    """Fetches document contents from S3 and extracts raw text for analysis."""

    def __init__(self):
        self.aws_enabled = os.getenv("AWS_ENABLED", "false").lower() == "true"
        self.region = os.getenv("AWS_REGION", "us-east-1")
        self.bucket = os.getenv("AWS_S3_BUCKET", "")
        self.s3_client = None

        if self.aws_enabled and self.bucket and os.getenv("AWS_ACCESS_KEY_ID"):
            try:
                import boto3
                self.s3_client = boto3.client(
                    "s3",
                    region_name=self.region,
                    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                )
            except Exception as exc:
                logger.error("Failed to initialize S3 client: %s", exc)

    def list_documents(self, tenant_id: str) -> list[dict]:
        """Lists documents in S3 under the tenant's prefix."""
        if not self.s3_client:
            return []
        
        prefix = f"tenant-{tenant_id}/"
        docs = []
        try:
            paginator = self.s3_client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                for obj in page.get("Contents", []):
                    if obj["Key"].endswith("/"):
                        continue
                    docs.append({
                        "object_key": obj["Key"],
                        "file_name": obj["Key"].split("/")[-1] if "/" in obj["Key"] else obj["Key"],
                        "size": obj.get("Size", 0)
                    })
        except Exception as e:
            logger.error("Failed to list documents for tenant %s: %s", tenant_id, e)
        return docs

    def fetch_and_extract_text(self, object_key: str, file_name: str, content_type: Optional[str] = None) -> str:
        """Fetches an object from S3 and extracts its text based on file extension or content type."""
        if not self.s3_client:
            raise RuntimeError("S3 client not initialized. Ensure AWS_ENABLED=true and credentials are set.")

        logger.info("Fetching document %s from S3 bucket %s", object_key, self.bucket)
        response = self.s3_client.get_object(Bucket=self.bucket, Key=object_key)
        try:
            body = response["Body"].read()
        finally:
            response["Body"].close()

        ext = file_name.split(".")[-1].lower() if "." in file_name else ""
        
        # 1. Plain text extraction
        if ext in ["txt", "csv", "md"] or (content_type and "text/" in content_type):
            try:
                return body.decode("utf-8")
            except UnicodeDecodeError:
                return body.decode("latin-1", errors="replace")

        # 2. JSON extraction
        if ext == "json" or (content_type and "application/json" in content_type):
            try:
                data = json.loads(body.decode("utf-8"))
                # Dump it back to a formatted string or just return the raw string
                return json.dumps(data, indent=2)
            except Exception as e:
                logger.warning("Failed to parse JSON %s: %s", file_name, e)
                return body.decode("utf-8", errors="replace")

        # 3. PDF extraction
        if ext == "pdf" or (content_type and "application/pdf" in content_type):
            try:
                import pypdf
                reader = pypdf.PdfReader(io.BytesIO(body))
                text_parts = []
                for page in reader.pages:
                    text_parts.append(page.extract_text())
                return "\n".join(text_parts)
            except Exception as e:
                logger.warning("Failed to extract PDF text from %s: %s", file_name, e)
                return ""

        # Fallback for unknown types — try to decode as utf-8
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            logger.warning("Unsupported binary format for %s", file_name)
            return ""

    def build_remediation_plan(self, object_key: str, evidence: str) -> dict:
        """Bind a finding to a concrete S3 target and executable CLI plan."""
        bucket = self.bucket or "<configure AWS_S3_BUCKET>"
        return {
            "connector": "aws_s3",
            "target": {
                "provider": "aws",
                "type": "s3_object",
                "bucket": bucket,
                "object_key": object_key,
                "uri": f"s3://{bucket}/{object_key}",
            },
            "destructive": True,
            "diff": {
                "kind": "cli",
                "summary": f"Redact detected sensitive entities in {object_key}",
                "commands": [
                    f"aws s3 cp s3://{bucket}/{object_key} ./before.txt",
                    "# AuthClaw redacts detected sensitive values locally",
                    f"aws s3 cp ./after.txt s3://{bucket}/{object_key}",
                ],
                "preview": [
                    f"- sensitive data in {object_key}: {evidence}",
                    f"+ sensitive data in {object_key}: redacted placeholders",
                ],
                "terraform": [],
            },
        }

    def _read_text_object(self, object_key: str) -> tuple[bytes, str, dict]:
        if not self.s3_client:
            raise RuntimeError("AWS S3 remediation requires AWS_ENABLED=true, AWS_S3_BUCKET, and AWS credentials")

        obj = self.s3_client.get_object(Bucket=self.bucket, Key=object_key)
        body = obj["Body"].read()
        metadata = {
            "content_type": obj.get("ContentType") or "text/plain",
            "version_id": obj.get("VersionId"),
            "etag": obj.get("ETag", "").strip('"'),
            "etag_header": obj.get("ETag", ""),
            "metadata": obj.get("Metadata") or {},
        }
        try:
            return body, body.decode("utf-8"), metadata
        except UnicodeDecodeError:
            return body, body.decode("latin-1"), metadata

    def _validated_target(self, plan_item: dict) -> tuple[dict, str]:
        target = plan_item.get("target") or {}
        object_key = target.get("object_key") or plan_item.get("finding_control", "")
        if target.get("type") != "s3_object":
            raise RuntimeError(f"Unsupported remediation target: {target.get('type') or 'unknown'}")
        if not target.get("bucket") or target["bucket"] != self.bucket:
            raise RuntimeError("Configured S3 bucket does not match the approved target bucket")
        return target, object_key

    def _immutable_backup(self, mutation_state: dict, body: bytes, content_type: str) -> None:
        backup = mutation_state["backup"]
        metadata = {
            "authclaw-role": "rollback-source",
            "operation-id": mutation_state["operation_id"],
        }
        try:
            result = self.s3_client.put_object(
                Bucket=self.bucket,
                Key=backup["key"],
                Body=body,
                ContentType=content_type,
                Metadata=metadata,
                IfNoneMatch="*",
                ChecksumSHA256=_checksum_sha256(body),
            )
            backup["etag"] = result.get("ETag", "").strip('"')
            backup["version_id"] = result.get("VersionId")
            return
        except Exception as exc:
            if not _precondition_failed(exc):
                raise

        existing_bytes, _, existing_metadata = self._read_text_object(backup["key"])
        if (
            _sha256(existing_bytes) != backup["sha256"]
            or existing_metadata["metadata"].get("operation-id") != mutation_state["operation_id"]
        ):
            raise RemediationConflictError("Existing rollback backup does not match the prepared operation")
        backup["etag"] = existing_metadata.get("etag")
        backup["version_id"] = existing_metadata.get("version_id")

    def prepare_remediation(
        self,
        workflow_id: str,
        action_id: str,
        plan_item: dict,
        existing_state: Optional[dict] = None,
    ) -> dict:
        """Create an immutable backup and return state that must be persisted before apply."""
        target, object_key = self._validated_target(plan_item)
        state = upgrade_mutation_state(
            workflow_id,
            action_id,
            {"status": "RUNNING", "mutation_state": existing_state} if existing_state else {"status": "PENDING"},
        )
        if existing_state:
            if state["phase"] in {MutationPhase.APPLIED.value, MutationPhase.PREPARED.value, MutationPhase.APPLYING.value}:
                return self.reconcile_remediation(state)
            if state["phase"] != MutationPhase.PENDING.value:
                return state

        before_bytes, before_text, metadata = self._read_text_object(object_key)
        after_text, redaction = redact_sensitive_text(before_text)
        after_bytes = after_text.encode("utf-8")
        if before_bytes == after_bytes:
            raise RuntimeError("No redactable sensitive values were found during apply")

        backup_key = f".authclaw-rollback/{workflow_id}/{action_id}/{object_key.lstrip('/')}"
        state.update({
            "phase": MutationPhase.PREPARED.value,
            "target": {
                "bucket": self.bucket,
                "key": object_key,
                "content_type": metadata["content_type"],
            },
            "original": {
                "sha256": _sha256(before_bytes),
                "etag": metadata.get("etag"),
                "etag_header": metadata.get("etag_header") or metadata.get("etag"),
                "version_id": metadata.get("version_id"),
                "verification": verification_summary(before_text),
            },
            "intended": {
                "sha256": _sha256(after_bytes),
                "verification": verification_summary(after_text),
                "redaction": redaction,
            },
            "backup": {
                "bucket": self.bucket,
                "key": backup_key,
                "sha256": _sha256(before_bytes),
            },
            "mutation": None,
            "conflict": None,
        })
        self._immutable_backup(state, before_bytes, metadata["content_type"])
        return state

    def reconcile_remediation(self, mutation_state: dict) -> dict:
        """Resolve an in-flight operation from the current target contents."""
        target = mutation_state.get("target") or {}
        if not target.get("key"):
            mutation_state["phase"] = MutationPhase.UNKNOWN.value
            mutation_state["conflict"] = "missing_target_state"
            return mutation_state

        current_bytes, _, metadata = self._read_text_object(target["key"])
        current_sha = _sha256(current_bytes)
        if current_sha == (mutation_state.get("original") or {}).get("sha256"):
            mutation_state["phase"] = MutationPhase.PREPARED.value
            mutation_state["conflict"] = None
            return mutation_state
        if (
            current_sha == (mutation_state.get("intended") or {}).get("sha256")
            and metadata["metadata"].get("operation-id") == mutation_state.get("operation_id")
        ):
            mutation_state["phase"] = MutationPhase.APPLIED.value
            mutation_state["mutation"] = {
                "sha256": current_sha,
                "etag": metadata.get("etag"),
                "etag_header": metadata.get("etag_header") or metadata.get("etag"),
                "version_id": metadata.get("version_id"),
                "reconciled": True,
            }
            mutation_state["conflict"] = None
            return mutation_state

        mutation_state["phase"] = MutationPhase.CONFLICTED.value
        mutation_state["conflict"] = "target_changed_outside_prepared_operation"
        return mutation_state

    def _result_from_state(self, mutation_state: dict, target: dict, plan_item: dict) -> dict:
        redaction = (mutation_state.get("intended") or {}).get("redaction") or {"total": 0}
        mutation = mutation_state.get("mutation") or {}
        return {
            "connector": "aws_s3",
            "control": mutation_state["target"]["key"],
            "target": target,
            "status": "success",
            "details": f"Redacted {redaction.get('total', 0)} sensitive value(s) in s3://{self.bucket}/{mutation_state['target']['key']}",
            "mutation_id": mutation.get("version_id") or mutation.get("etag"),
            "before_verification": mutation_state["original"]["verification"],
            "after_verification": mutation_state["intended"]["verification"],
            "before_sha256": mutation_state["original"]["sha256"],
            "after_sha256": mutation_state["intended"]["sha256"],
            "cli_diff": plan_item.get("diff", {}),
            "mutation_state": mutation_state,
            "rollback_ref": self.rollback_ref_from_state(mutation_state),
        }

    def rollback_ref_from_state(self, mutation_state: dict) -> dict:
        mutation = mutation_state.get("mutation") or {}
        return {
            "state_version": mutation_state["state_version"],
            "operation_id": mutation_state["operation_id"],
            "bucket": self.bucket,
            "backup_key": mutation_state["backup"]["key"],
            "target_key": mutation_state["target"]["key"],
            "content_type": mutation_state["target"]["content_type"],
            "original_sha256": mutation_state["original"]["sha256"],
            "intended_sha256": mutation_state["intended"]["sha256"],
            "before_version_id": mutation_state["original"].get("version_id"),
            "after_version_id": mutation.get("version_id"),
            "mutation_etag": mutation.get("etag"),
            "mutation_etag_header": mutation.get("etag_header") or mutation.get("etag"),
        }

    def apply_prepared_remediation(self, mutation_state: dict, plan_item: dict) -> dict:
        """Conditionally apply a prepared mutation, reconciling ambiguous errors."""
        target, object_key = self._validated_target(plan_item)
        mutation_state = self.reconcile_remediation(mutation_state)
        if mutation_state["phase"] == MutationPhase.APPLIED.value:
            return self._result_from_state(mutation_state, target, plan_item)
        if mutation_state["phase"] != MutationPhase.PREPARED.value:
            raise RemediationConflictError(mutation_state.get("conflict") or "Prepared remediation is not applicable")

        backup_bytes, backup_text, backup_metadata = self._read_text_object(mutation_state["backup"]["key"])
        if _sha256(backup_bytes) != mutation_state["backup"]["sha256"]:
            raise RemediationConflictError("Rollback backup checksum does not match prepared state")
        after_text, _ = redact_sensitive_text(backup_text)
        after_bytes = after_text.encode("utf-8")
        if _sha256(after_bytes) != mutation_state["intended"]["sha256"]:
            raise RemediationConflictError("Prepared redaction output is not reproducible")

        mutation_state["phase"] = MutationPhase.APPLYING.value
        try:
            put_result = self.s3_client.put_object(
                Bucket=self.bucket,
                Key=object_key,
                Body=after_bytes,
                ContentType=mutation_state["target"]["content_type"],
                Metadata={
                    "authclaw-remediated": "true",
                    "operation-id": mutation_state["operation_id"],
                },
                IfMatch=mutation_state["original"].get("etag_header") or mutation_state["original"].get("etag"),
                ChecksumSHA256=_checksum_sha256(after_bytes),
            )
            mutation_state["mutation"] = {
                "sha256": mutation_state["intended"]["sha256"],
                "etag": put_result.get("ETag", "").strip('"'),
                "etag_header": put_result.get("ETag", ""),
                "version_id": put_result.get("VersionId"),
                "reconciled": False,
            }
        except Exception as exc:
            reconciled = self.reconcile_remediation(mutation_state)
            if reconciled["phase"] == MutationPhase.APPLIED.value:
                return self._result_from_state(reconciled, target, plan_item)
            if _precondition_failed(exc) or reconciled["phase"] == MutationPhase.CONFLICTED.value:
                raise RemediationConflictError(reconciled.get("conflict") or "Target changed before remediation") from exc
            raise RuntimeError("S3 mutation outcome is unresolved; retry will reconcile prepared state") from exc

        verified_bytes, verified_text, verified_metadata = self._read_text_object(object_key)
        verified_sha = _sha256(verified_bytes)
        if (
            verified_sha != mutation_state["intended"]["sha256"]
            or verification_summary(verified_text)["total"] != 0
            or verified_metadata["metadata"].get("operation-id") != mutation_state["operation_id"]
        ):
            mutation_state["phase"] = MutationPhase.CONFLICTED.value
            mutation_state["conflict"] = "post_mutation_verification_mismatch"
            raise RemediationConflictError("Post-mutation verification did not match the prepared operation")

        mutation_state["phase"] = MutationPhase.APPLIED.value
        mutation_state["mutation"] = {
            "sha256": verified_sha,
            "etag": verified_metadata.get("etag") or put_result.get("ETag", "").strip('"'),
            "etag_header": verified_metadata.get("etag_header") or put_result.get("ETag", ""),
            "version_id": verified_metadata.get("version_id") or put_result.get("VersionId"),
            "reconciled": False,
        }
        return self._result_from_state(mutation_state, target, plan_item)

    def execute_remediation(self, workflow_id: str, action_id: str, plan_item: dict) -> dict:
        """Compatibility wrapper for callers that do not persist intermediate state."""
        prepared = self.prepare_remediation(workflow_id, action_id, plan_item)
        return self.apply_prepared_remediation(prepared, plan_item)

    def rollback_remediation(self, rollback_plan: dict) -> dict:
        """Restore the original S3 object from the rollback copy."""
        if not self.s3_client:
            raise RuntimeError("AWS S3 rollback requires AWS_ENABLED=true, AWS_S3_BUCKET, and AWS credentials")

        rollback_ref = rollback_plan.get("rollback_ref") or {}
        if not rollback_ref.get("bucket") or rollback_ref["bucket"] != self.bucket:
            raise RuntimeError("Configured S3 bucket does not match the rollback bucket")
        backup_key = rollback_ref.get("backup_key")
        target_key = rollback_ref.get("target_key")
        if not backup_key or not target_key:
            raise RuntimeError("Rollback reference is missing backup_key or target_key")

        backup_obj = self.s3_client.get_object(Bucket=self.bucket, Key=backup_key)
        body = backup_obj["Body"].read()
        if rollback_ref.get("original_sha256") and _sha256(body) != rollback_ref["original_sha256"]:
            raise RemediationConflictError("Rollback backup checksum does not match the recorded original")

        current_metadata = None
        try:
            current_bytes, _, current_metadata = self._read_text_object(target_key)
        except Exception:
            if not (rollback_ref.get("mutation_etag_header") or rollback_ref.get("mutation_etag")):
                raise
        else:
            if rollback_ref.get("original_sha256") and _sha256(current_bytes) == rollback_ref["original_sha256"]:
                return {
                    "connector": "aws_s3",
                    "control": target_key,
                    "status": "rolled_back",
                    "details": f"S3 target {target_key} already contains the recorded original",
                    "mutation_id": current_metadata.get("version_id") or current_metadata.get("etag"),
                }
            expected_etag = rollback_ref.get("mutation_etag")
            same_mutation = (
                expected_etag
                and current_metadata.get("etag") == expected_etag
                and current_metadata["metadata"].get("operation-id") == rollback_ref.get("operation_id")
            )
            if rollback_ref.get("intended_sha256") and _sha256(current_bytes) != rollback_ref["intended_sha256"] and not same_mutation:
                raise RemediationConflictError("S3 target changed after remediation; automatic rollback refused")

        put_args = {
            "Bucket": self.bucket,
            "Key": target_key,
            "Body": body,
            "ContentType": rollback_ref.get("content_type") or backup_obj.get("ContentType") or "text/plain",
            "Metadata": {"authclaw-rollback": "true", "operation-id": rollback_ref.get("operation_id", "")},
        }
        if rollback_ref.get("mutation_etag_header") or rollback_ref.get("mutation_etag"):
            put_args["IfMatch"] = rollback_ref.get("mutation_etag_header") or rollback_ref.get("mutation_etag")
        result = self.s3_client.put_object(**put_args)
        restored_bytes, _, _ = self._read_text_object(target_key)
        if rollback_ref.get("original_sha256") and _sha256(restored_bytes) != rollback_ref["original_sha256"]:
            raise RemediationConflictError("Rollback result does not match the recorded original")
        return {
            "connector": "aws_s3",
            "control": target_key,
            "status": "rolled_back",
            "details": f"Restored s3://{self.bucket}/{target_key} from rollback copy",
            "mutation_id": result.get("VersionId") or result.get("ETag", "").strip('"'),
        }

    def simulate_remediation(self, object_key: str, action: str) -> dict:
        """Legacy compatibility for older tests; real workflows use execute_remediation."""
        logger.info("Legacy simulated remediation action '%s' on %s", action, object_key)
        return {
            "connector": "S3Document",
            "control": object_key,
            "status": "success",
            "details": f"Simulated remediation: {action} on {object_key}",
        }
