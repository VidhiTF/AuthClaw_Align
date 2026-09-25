"""
AWS Connector Framework
GET  /v1/aws/status          — test S3 and Bedrock connectivity (no automatic calls on startup)
POST /v1/aws/s3/sync         — discover S3 objects under tenant prefix, sync metadata to Postgres
GET  /v1/aws/s3/documents    — list synced document metadata from Postgres
GET  /v1/aws/usage           — return current Bedrock daily usage counters

IMPORTANT: All AWS interactions are gated behind the AWS_ENABLED env flag.
No AWS API calls are made on import, startup, or health checks.
Credentials come exclusively from .env.local / env vars.
"""

import logging
import os
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_db, require_permission, require_scopes
from app.db.models import AWSUsageLimits, AWSS3Document
from app.services import ephemeral_workers

logger = logging.getLogger("api.aws")
router = APIRouter()


def _require_aws_enabled() -> None:
    """Raise 503 if AWS_ENABLED is not explicitly set to 'true'."""
    if os.getenv("AWS_ENABLED", "false").lower() != "true":
        raise HTTPException(
            status_code=503,
            detail=(
                "AWS integration is disabled. "
                "Set AWS_ENABLED=true in .env.local to enable Phase 14 features."
            ),
        )


class AWSStatusResponse(BaseModel):
    aws_enabled: bool
    bedrock_enabled: bool
    s3_status: str          # "connected" | "not_configured" | "error:<msg>"
    bedrock_status: str     # "connected" | "not_configured" | "error:<msg>" | "disabled"
    region: Optional[str]
    bucket: Optional[str]


class S3SyncResponse(BaseModel):
    synced: int
    skipped: int
    total_in_bucket: int
    bucket: str
    prefix: str
    worker_token_id: Optional[UUID] = None
    worker_run_id: Optional[UUID] = None


class S3DocumentResponse(BaseModel):
    id: UUID
    bucket_name: str
    object_key: str
    file_name: str
    file_size_bytes: Optional[int]
    content_type: Optional[str]
    last_modified: Optional[datetime]
    synced_at: datetime

    class Config:
        from_attributes = True


class AWSUsageResponse(BaseModel):
    tenant_id: str
    daily_requests: int
    max_daily_requests: int
    daily_tokens: int
    max_daily_tokens: int
    daily_cost_estimate: float
    max_daily_cost_usd: float
    last_reset: datetime
    requests_remaining: int
    tokens_remaining: int


@router.get("/status", response_model=AWSStatusResponse, dependencies=[require_scopes(["read"])])
def get_aws_status(request: Request) -> AWSStatusResponse:
    """
    Test AWS connectivity (S3 and optionally Bedrock).

    This endpoint only makes lightweight AWS API calls (S3 HeadBucket, 
    Bedrock ListFoundationModels) when AWS_ENABLED=true AND credentials are
    present. It NEVER makes calls during startup or health checks.
    """
    aws_enabled = os.getenv("AWS_ENABLED", "false").lower() == "true"
    bedrock_enabled = os.getenv("BEDROCK_ENABLED", "false").lower() == "true"
    region = os.getenv("AWS_REGION", "")
    bucket = os.getenv("AWS_S3_BUCKET", "")

    if not aws_enabled:
        return AWSStatusResponse(
            aws_enabled=False,
            bedrock_enabled=False,
            s3_status="not_configured",
            bedrock_status="disabled",
            region=None,
            bucket=None,
        )

    s3_status = "not_configured"
    if bucket and os.getenv("AWS_ACCESS_KEY_ID"):
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError

            s3 = boto3.client(
                "s3",
                region_name=region or "us-east-1",
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            )
            s3.head_bucket(Bucket=bucket)
            s3_status = "connected"
        except Exception as exc:
            s3_status = f"error:{str(exc)[:120]}"
            logger.warning("S3 status check failed: %s", exc)

    bedrock_status = "disabled"
    if bedrock_enabled and os.getenv("AWS_ACCESS_KEY_ID"):
        try:
            import boto3
            br = boto3.client(
                "bedrock",
                region_name=region or "us-east-1",
                aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            )
            br.list_foundation_models(byOutputModality="TEXT")
            bedrock_status = "connected"
        except Exception as exc:
            bedrock_status = f"error:{str(exc)[:120]}"
            logger.warning("Bedrock status check failed: %s", exc)

    return AWSStatusResponse(
        aws_enabled=True,
        bedrock_enabled=bedrock_enabled,
        s3_status=s3_status,
        bedrock_status=bedrock_status,
        region=region or None,
        bucket=bucket or None,
    )


@router.post(
    "/s3/sync",
    response_model=S3SyncResponse,
    dependencies=[require_permission("tenant.connectors.manage"), require_scopes(["write"])],
)
def sync_s3_documents(
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> S3SyncResponse:
    """
    Discover S3 objects under the tenant's prefix and sync metadata to Postgres.

    Prefix: tenant-{tenant_id}/ within the configured bucket.
    Only file metadata is stored (name, size, content_type, last_modified, etag).
    File content is NEVER fetched or stored.

    ⚠️ BILLING NOTE: This calls s3:ListBucket — free tier includes 20k GETs/month.
    """
    _require_aws_enabled()

    bucket = os.getenv("AWS_S3_BUCKET", "")
    region = os.getenv("AWS_REGION", "us-east-1")
    if not bucket:
        raise HTTPException(status_code=400, detail="AWS_S3_BUCKET is not configured.")

    tenant_id = str(request.state.tenant_id)
    prefix = f"tenant-{tenant_id}/"
    request_id = request.headers.get("x-request-id", "")

    worker_token = ephemeral_workers.issue_worker_token(
        db,
        tenant_id=request.state.tenant_id,
        connector="aws",
        action_id="s3.sync",
        purpose="scan",
        scopes=["aws:s3:read"],
        issued_by=getattr(request.state, "user_id", None),
        ttl_seconds=ephemeral_workers.DEFAULT_TTL_SECONDS,
        metadata={"bucket": bucket, "prefix": prefix, "source": "aws.s3.sync"},
        request_id=request_id,
    )
    worker_auth = ephemeral_workers.authorize_worker_action(
        db,
        tenant_id=request.state.tenant_id,
        raw_token=worker_token.raw_token,
        connector="aws",
        action="s3.sync",
        request_id=request_id,
        metadata={"bucket": bucket, "prefix": prefix},
    )
    if not worker_auth.allowed:
        raise HTTPException(status_code=403, detail=worker_auth.reason)

    try:
        import boto3
        s3 = boto3.client(
            "s3",
            region_name=region,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        )

        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

        total_in_bucket = 0
        synced = 0
        skipped = 0

        for page in pages:
            for obj in page.get("Contents", []):
                total_in_bucket += 1
                key: str = obj["Key"]
                # Skip "directory" placeholder objects (key ends with /)
                if key.endswith("/"):
                    skipped += 1
                    continue

                file_name = key.split("/")[-1] if "/" in key else key
                etag = obj.get("ETag", "").strip('"')
                last_modified = obj.get("LastModified")
                size = obj.get("Size")
                content_type = None
                try:
                    head = s3.head_object(Bucket=bucket, Key=key)
                    content_type = head.get("ContentType")
                except Exception:
                    pass  # Non-fatal — content type is optional metadata

                # Upsert into aws_s3_documents
                existing = db.query(AWSS3Document).filter(
                    AWSS3Document.tenant_id == request.state.tenant_id,
                    AWSS3Document.bucket_name == bucket,
                    AWSS3Document.object_key == key,
                ).first()

                if existing:
                    if existing.etag != etag:
                        # Object was modified — update metadata
                        existing.file_size_bytes = size
                        existing.content_type = content_type
                        existing.last_modified = last_modified
                        existing.etag = etag
                        existing.synced_at = datetime.now(timezone.utc)
                        synced += 1
                    else:
                        skipped += 1
                else:
                    doc = AWSS3Document(
                        tenant_id=request.state.tenant_id,
                        bucket_name=bucket,
                        object_key=key,
                        file_name=file_name,
                        file_size_bytes=size,
                        content_type=content_type,
                        last_modified=last_modified,
                        etag=etag,
                    )
                    db.add(doc)
                    synced += 1

        db.commit()
        logger.info(
            "[AWS-S3] Sync complete for tenant=%s: synced=%d skipped=%d total=%d",
            tenant_id, synced, skipped, total_in_bucket,
        )
        return S3SyncResponse(
            synced=synced,
            skipped=skipped,
            total_in_bucket=total_in_bucket,
            bucket=bucket,
            prefix=prefix,
            worker_token_id=worker_token.token.id,
            worker_run_id=worker_auth.run.id,
        )

    except HTTPException:
        raise
    except Exception as exc:
        db.rollback()
        logger.error("[AWS-S3] Sync failed for tenant=%s: %s", tenant_id, exc)
        raise HTTPException(status_code=502, detail=f"S3 sync failed: {str(exc)}")


@router.get(
    "/s3/documents",
    response_model=List[S3DocumentResponse],
    dependencies=[require_permission("tenant.connectors.read"), require_scopes(["read"])],
)
def list_s3_documents(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_tenant_db),
) -> List[S3DocumentResponse]:
    """
    Return synced S3 document metadata from Postgres.
    No AWS API call is made — this reads only from local Postgres.
    """
    # Note: AWS_ENABLED not required here — read from local DB is always safe
    docs = (
        db.query(AWSS3Document)
        .order_by(AWSS3Document.synced_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return docs


@router.get(
    "/usage",
    response_model=AWSUsageResponse,
    dependencies=[require_scopes(["read"])],
)
def get_aws_usage(
    request: Request,
    db: Session = Depends(get_tenant_db),
) -> AWSUsageResponse:
    """
    Return current Bedrock daily usage counters and limits for this tenant.
    No AWS API call — reads from local Postgres only.
    """
    usage = db.query(AWSUsageLimits).filter(
        AWSUsageLimits.tenant_id == request.state.tenant_id
    ).first()

    if not usage:
        # Return defaults if no usage record exists yet
        return AWSUsageResponse(
            tenant_id=str(request.state.tenant_id),
            daily_requests=0,
            max_daily_requests=int(os.getenv("BEDROCK_MAX_REQUESTS_PER_DAY", "100")),
            daily_tokens=0,
            max_daily_tokens=int(os.getenv("BEDROCK_MAX_TOKENS_PER_DAY", "50000")),
            daily_cost_estimate=0.0,
            max_daily_cost_usd=float(os.getenv("BEDROCK_MAX_COST_ESTIMATE_USD", "1.0")),
            last_reset=datetime.now(timezone.utc),
            requests_remaining=int(os.getenv("BEDROCK_MAX_REQUESTS_PER_DAY", "100")),
            tokens_remaining=int(os.getenv("BEDROCK_MAX_TOKENS_PER_DAY", "50000")),
        )

    return AWSUsageResponse(
        tenant_id=str(usage.tenant_id),
        daily_requests=usage.daily_requests,
        max_daily_requests=usage.max_daily_requests,
        daily_tokens=usage.daily_tokens,
        max_daily_tokens=usage.max_daily_tokens,
        daily_cost_estimate=usage.daily_cost_estimate,
        max_daily_cost_usd=usage.max_daily_cost_usd,
        last_reset=usage.last_reset,
        requests_remaining=max(0, usage.max_daily_requests - usage.daily_requests),
        tokens_remaining=max(0, usage.max_daily_tokens - usage.daily_tokens),
    )
