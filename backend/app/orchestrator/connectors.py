import hashlib
import io
import json
import logging
import os
import re
from typing import Optional

logger = logging.getLogger("orchestrator.scanner")


SENSITIVE_PATTERNS = [
    ("EMAIL_ADDRESS", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "[REDACTED_EMAIL]"),
    ("US_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[REDACTED_CARD]"),
    ("PHONE_NUMBER", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED_PHONE]"),
]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
        body = response["Body"].read()

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
        }
        try:
            return body, body.decode("utf-8"), metadata
        except UnicodeDecodeError:
            return body, body.decode("latin-1"), metadata

    def execute_remediation(self, workflow_id: str, action_id: str, plan_item: dict) -> dict:
        """Apply an approved S3 redaction mutation and return before/after proof."""
        target = plan_item.get("target") or {}
        object_key = target.get("object_key") or plan_item.get("finding_control", "")
        if target.get("type") != "s3_object":
            raise RuntimeError(f"Unsupported remediation target: {target.get('type') or 'unknown'}")

        before_bytes, before_text, metadata = self._read_text_object(object_key)
        after_text, redaction = redact_sensitive_text(before_text)
        after_bytes = after_text.encode("utf-8")
        if before_bytes == after_bytes:
            raise RuntimeError("No redactable sensitive values were found during apply")

        backup_key = f".authclaw-rollback/{workflow_id}/{action_id}/{object_key.lstrip('/')}"
        self.s3_client.put_object(
            Bucket=self.bucket,
            Key=backup_key,
            Body=before_bytes,
            ContentType=metadata["content_type"],
            Metadata={"authclaw-role": "rollback-source", "workflow-id": workflow_id, "action-id": action_id},
        )
        put_result = self.s3_client.put_object(
            Bucket=self.bucket,
            Key=object_key,
            Body=after_bytes,
            ContentType=metadata["content_type"],
            Metadata={"authclaw-remediated": "true", "workflow-id": workflow_id, "action-id": action_id},
        )

        verified_bytes, verified_text, after_metadata = self._read_text_object(object_key)
        before_verification = verification_summary(before_text)
        after_verification = verification_summary(verified_text)
        verified = _sha256(verified_bytes) == _sha256(after_bytes) and after_verification["total"] == 0

        return {
            "connector": "aws_s3",
            "control": object_key,
            "target": target,
            "status": "success" if verified else "failed",
            "details": f"Redacted {redaction['total']} sensitive value(s) in s3://{self.bucket}/{object_key}",
            "mutation_id": put_result.get("VersionId") or put_result.get("ETag", "").strip('"'),
            "before_verification": before_verification,
            "after_verification": after_verification,
            "before_sha256": _sha256(before_bytes),
            "after_sha256": _sha256(verified_bytes),
            "cli_diff": plan_item.get("diff", {}),
            "rollback_ref": {
                "bucket": self.bucket,
                "backup_key": backup_key,
                "target_key": object_key,
                "content_type": metadata["content_type"],
                "before_version_id": metadata.get("version_id"),
                "after_version_id": after_metadata.get("version_id"),
            },
        }

    def rollback_remediation(self, rollback_plan: dict) -> dict:
        """Restore the original S3 object from the rollback copy."""
        if not self.s3_client:
            raise RuntimeError("AWS S3 rollback requires AWS_ENABLED=true, AWS_S3_BUCKET, and AWS credentials")

        rollback_ref = rollback_plan.get("rollback_ref") or {}
        backup_key = rollback_ref.get("backup_key")
        target_key = rollback_ref.get("target_key")
        if not backup_key or not target_key:
            raise RuntimeError("Rollback reference is missing backup_key or target_key")

        backup_obj = self.s3_client.get_object(Bucket=self.bucket, Key=backup_key)
        body = backup_obj["Body"].read()
        result = self.s3_client.put_object(
            Bucket=self.bucket,
            Key=target_key,
            Body=body,
            ContentType=rollback_ref.get("content_type") or backup_obj.get("ContentType") or "text/plain",
            Metadata={"authclaw-rollback": "true"},
        )
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
