"""Cloud and SCM connector credential storage plus provider actions."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import jwt
import requests
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_secret, encrypt_secret
from app.db.models import CloudConnector
from app.services import ephemeral_workers


PROVIDERS: dict[str, dict[str, Any]] = {
    "aws": {
        "display_name": "AWS",
        "auth_type": "access_key",
        "fields": ["access_key_id", "secret_access_key", "region"],
        "optional_fields": ["session_token", "bucket"],
        "actions": ["inventory", "iam-scan", "remediate"],
    },
    "github": {
        "display_name": "GitHub",
        "auth_type": "token",
        "fields": ["token"],
        "optional_fields": ["owner", "repo"],
        "actions": ["inventory", "security-alerts", "pr-remediation"],
    },
    "gcp": {
        "display_name": "Google Cloud",
        "auth_type": "service_account",
        "fields": ["service_account_json"],
        "optional_fields": ["project_id"],
        "actions": ["inventory", "iam-scan", "remediate"],
    },
}
SECRET_METADATA_PARTS = ("secret", "token", "password", "private_key", "service_account", "credential")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def provider_catalog() -> list[dict[str, Any]]:
    github_oauth = os.getenv("GITHUB_OAUTH_CLIENT_ID", "")
    gcp_oauth = os.getenv("GCP_OAUTH_CLIENT_ID", "")
    return [
        {
            "provider": provider,
            "display_name": spec["display_name"],
            "auth_type": spec["auth_type"],
            "fields": spec["fields"],
            "optional_fields": spec["optional_fields"],
            "actions": spec["actions"],
            "oauth_url": (
                f"https://github.com/login/oauth/authorize?client_id={github_oauth}&scope=repo security_events"
                if provider == "github" and github_oauth
                else (
                    f"https://accounts.google.com/o/oauth2/v2/auth?client_id={gcp_oauth}&response_type=code&scope=https://www.googleapis.com/auth/cloud-platform"
                    if provider == "gcp" and gcp_oauth
                    else None
                )
            ),
        }
        for provider, spec in PROVIDERS.items()
    ]


def _sanitize_metadata(provider: str, credentials: dict[str, Any], metadata: dict[str, Any] | None) -> dict[str, Any]:
    metadata = dict(metadata or {})
    if provider == "aws":
        metadata["region"] = credentials.get("region") or metadata.get("region") or "us-east-1"
        if credentials.get("bucket"):
            metadata["bucket"] = credentials["bucket"]
        metadata["account_hint"] = (credentials.get("access_key_id") or "")[:8]
    if provider == "github":
        if credentials.get("owner"):
            metadata["owner"] = credentials["owner"]
        if credentials.get("repo"):
            metadata["repo"] = credentials["repo"]
    if provider == "gcp":
        service_account = _service_account(credentials)
        metadata["project_id"] = credentials.get("project_id") or service_account.get("project_id")
        metadata["client_email"] = service_account.get("client_email")
    return _public_metadata(metadata)


def _public_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    return {
        key: value
        for key, value in dict(metadata or {}).items()
        if value not in (None, "") and not any(part in key.lower() for part in SECRET_METADATA_PARTS)
    }


def _service_account(credentials: dict[str, Any]) -> dict[str, Any]:
    value = credentials.get("service_account_json")
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        return json.loads(value)
    return {}


def validate_credentials(provider: str, credentials: dict[str, Any]) -> None:
    spec = PROVIDERS.get(provider)
    if not spec:
        raise ValueError(f"Unsupported cloud provider: {provider}")
    missing = [field for field in spec["fields"] if not credentials.get(field)]
    if missing:
        raise ValueError(f"Missing {provider} credential fields: {', '.join(missing)}")
    if provider == "gcp":
        service_account = _service_account(credentials)
        for field in ("client_email", "private_key"):
            if not service_account.get(field):
                raise ValueError(f"GCP service_account_json missing {field}")


def serialize_connector(connector: CloudConnector) -> dict[str, Any]:
    return {
        "id": str(connector.id),
        "provider": connector.provider,
        "display_name": connector.display_name,
        "auth_type": connector.auth_type,
        "status": connector.status,
        "last_verified_at": connector.last_verified_at.isoformat() if connector.last_verified_at else None,
        "last_error": connector.last_error,
        "created_at": connector.created_at.isoformat() if connector.created_at else None,
        "updated_at": connector.updated_at.isoformat() if connector.updated_at else None,
        "metadata": _public_metadata(connector.metadata_json),
    }


def create_connector(
    db: Session,
    *,
    tenant_id: Any,
    user_id: Any,
    provider: str,
    display_name: str,
    credentials: dict[str, Any],
    metadata: dict[str, Any] | None = None,
) -> CloudConnector:
    provider = provider.lower().strip()
    validate_credentials(provider, credentials)
    connector = CloudConnector(
        tenant_id=tenant_id,
        provider=provider,
        display_name=display_name.strip() or PROVIDERS[provider]["display_name"],
        auth_type=PROVIDERS[provider]["auth_type"],
        encrypted_secret=encrypt_secret(json.dumps(credentials)),
        status="pending",
        created_by=user_id,
        metadata_json=_sanitize_metadata(provider, credentials, metadata),
    )
    db.add(connector)
    db.flush()
    verify_connector(db, connector, commit=False)
    db.commit()
    db.refresh(connector)
    return connector


def revoke_connector(db: Session, connector: CloudConnector, actor_id: Any) -> None:
    connector.status = "revoked"
    connector.revoked_at = now_utc()
    connector.revoked_by = actor_id
    connector.updated_at = now_utc()
    db.commit()


def _credentials(connector: CloudConnector) -> dict[str, Any]:
    return json.loads(decrypt_secret(connector.encrypted_secret))


def verify_connector(db: Session, connector: CloudConnector, *, commit: bool = True) -> dict[str, Any]:
    try:
        result = _verify(connector.provider, _credentials(connector), connector.metadata_json or {})
        connector.status = "connected"
        connector.last_error = None
        connector.last_verified_at = now_utc()
        connector.metadata_json = {**(connector.metadata_json or {}), **result.get("metadata", {})}
    except Exception:
        connector.status = "error"
        connector.last_error = "Verification failed. Check connector configuration and try again."
        result = {"ok": False, "error": connector.last_error}
    connector.updated_at = now_utc()
    if commit:
        db.commit()
        db.refresh(connector)
    return {"ok": connector.status == "connected", **result}


def run_action(db: Session, connector: CloudConnector, action: str, payload: dict[str, Any], actor_id: Any, request_id: str = "") -> dict[str, Any]:
    if connector.status == "revoked":
        raise ValueError("Connector is revoked")
    action = action.strip().lower()
    if action not in PROVIDERS[connector.provider]["actions"]:
        raise ValueError(f"Unsupported {connector.provider} action: {action}")
    credentials = _credentials(connector)
    result = _run_provider_action(connector.provider, action, credentials, connector.metadata_json or {}, payload)
    ephemeral_workers.emit_worker_audit_event(
        db,
        tenant_id=connector.tenant_id,
        action=f"cloud.{connector.provider}.{action}",
        reason=f"Ran {connector.provider} connector action {action}",
        request_id=request_id,
        actor_id=actor_id,
        connector=connector.provider,
        trace=[f"cloud_connector_id={connector.id}", f"status={result.get('status', 'ok')}"],
    )
    connector.updated_at = now_utc()
    db.commit()
    return result


def _verify(provider: str, credentials: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    if provider == "aws":
        sts = _aws_client(credentials, "sts")
        identity = sts.get_caller_identity()
        return {"ok": True, "metadata": {"account_id": identity.get("Account"), "arn": identity.get("Arn")}}
    if provider == "github":
        user = _github_request(credentials, "GET", "https://api.github.com/user")
        return {"ok": True, "metadata": {"login": user.get("login"), "github_id": user.get("id")}}
    if provider == "gcp":
        token = _gcp_access_token(credentials)
        project_id = credentials.get("project_id") or _service_account(credentials).get("project_id") or metadata.get("project_id")
        response = requests.get(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        response.raise_for_status()
        project = response.json()
        return {"ok": True, "metadata": {"project_id": project_id, "project_number": project.get("projectNumber")}}
    raise ValueError(f"Unsupported cloud provider: {provider}")


def _run_provider_action(provider: str, action: str, credentials: dict[str, Any], metadata: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    if provider == "aws":
        return _aws_action(action, credentials, metadata, payload)
    if provider == "github":
        return _github_action(action, credentials, metadata, payload)
    if provider == "gcp":
        return _gcp_action(action, credentials, metadata, payload)
    raise ValueError(f"Unsupported cloud provider: {provider}")


def _aws_client(credentials: dict[str, Any], service: str):
    import boto3

    return boto3.client(
        service,
        region_name=credentials.get("region") or "us-east-1",
        aws_access_key_id=credentials["access_key_id"],
        aws_secret_access_key=credentials["secret_access_key"],
        aws_session_token=credentials.get("session_token") or None,
    )


def _aws_action(action: str, credentials: dict[str, Any], metadata: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    if action == "inventory":
        s3 = _aws_client(credentials, "s3")
        buckets = s3.list_buckets().get("Buckets", [])
        return {"status": "ok", "items": [{"type": "s3_bucket", "name": item["Name"], "created_at": str(item.get("CreationDate", ""))} for item in buckets]}
    if action == "iam-scan":
        iam = _aws_client(credentials, "iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        users = iam.list_users(MaxItems=50).get("Users", [])
        findings = []
        if summary.get("AccountMFAEnabled", 0) == 0:
            findings.append({"severity": "high", "title": "AWS account MFA is not enabled"})
        return {"status": "ok", "summary": summary, "users": [user["UserName"] for user in users], "findings": findings}
    if action == "remediate":
        bucket = payload.get("bucket") or metadata.get("bucket")
        if not bucket:
            raise ValueError("bucket is required for AWS remediation")
        s3 = _aws_client(credentials, "s3")
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        return {"status": "ok", "mutation": "s3.put_public_access_block", "bucket": bucket}
    raise ValueError(f"Unsupported AWS action: {action}")


def _github_request(credentials: dict[str, Any], method: str, url: str, **kwargs):
    headers = {
        "Authorization": f"Bearer {credentials['token']}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    response = requests.request(method, url, headers=headers, timeout=20, **kwargs)
    response.raise_for_status()
    if response.status_code == 204:
        return {}
    return response.json()


def _github_repo(metadata: dict[str, Any], payload: dict[str, Any]) -> tuple[str, str]:
    owner = payload.get("owner") or metadata.get("owner")
    repo = payload.get("repo") or metadata.get("repo")
    if not owner or not repo:
        raise ValueError("GitHub owner and repo are required")
    return owner, repo


def _github_action(action: str, credentials: dict[str, Any], metadata: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    if action == "inventory":
        if metadata.get("owner") and metadata.get("repo"):
            owner, repo = _github_repo(metadata, payload)
            repo_data = _github_request(credentials, "GET", f"https://api.github.com/repos/{owner}/{repo}")
            return {"status": "ok", "items": [{"type": "repo", "full_name": repo_data["full_name"], "private": repo_data["private"], "default_branch": repo_data["default_branch"]}]}
        repos = _github_request(credentials, "GET", "https://api.github.com/user/repos?per_page=50&sort=updated")
        return {"status": "ok", "items": [{"type": "repo", "full_name": repo["full_name"], "private": repo["private"], "default_branch": repo["default_branch"]} for repo in repos]}
    if action == "security-alerts":
        owner, repo = _github_repo(metadata, payload)
        endpoints = {
            "code_scanning": f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts?per_page=50",
            "dependabot": f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts?per_page=50",
            "secret_scanning": f"https://api.github.com/repos/{owner}/{repo}/secret-scanning/alerts?per_page=50",
        }
        alerts = {}
        for key, url in endpoints.items():
            try:
                alerts[key] = _github_request(credentials, "GET", url)
            except requests.HTTPError as exc:
                alerts[key] = {"error": str(exc)}
        return {"status": "ok", "alerts": alerts}
    if action == "pr-remediation":
        owner, repo = _github_repo(metadata, payload)
        title = payload.get("title") or "AuthClaw remediation"
        body = payload.get("body") or "Automated AuthClaw remediation proposal."
        branch = payload.get("branch") or f"authclaw/remediation-{uuid.uuid4().hex[:8]}"
        repo_data = _github_request(credentials, "GET", f"https://api.github.com/repos/{owner}/{repo}")
        base = payload.get("base") or repo_data["default_branch"]
        ref = _github_request(credentials, "GET", f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{base}")
        sha = ref["object"]["sha"]
        _github_request(credentials, "POST", f"https://api.github.com/repos/{owner}/{repo}/git/refs", json={"ref": f"refs/heads/{branch}", "sha": sha})
        path = payload.get("path") or f".authclaw/remediations/{uuid.uuid4().hex}.md"
        _github_request(
            credentials,
            "PUT",
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            json={
                "message": title,
                "content": __import__("base64").b64encode(body.encode("utf-8")).decode("ascii"),
                "branch": branch,
            },
        )
        pr = _github_request(credentials, "POST", f"https://api.github.com/repos/{owner}/{repo}/pulls", json={"title": title, "head": branch, "base": base, "body": body})
        return {"status": "ok", "pull_request": {"number": pr.get("number"), "url": pr.get("html_url"), "branch": branch}}
    raise ValueError(f"Unsupported GitHub action: {action}")


def _gcp_access_token(credentials: dict[str, Any]) -> str:
    service_account = _service_account(credentials)
    now = int(datetime.now(timezone.utc).timestamp())
    claims = {
        "iss": service_account["client_email"],
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    }
    assertion = jwt.encode(claims, service_account["private_key"], algorithm="RS256")
    response = requests.post(
        "https://oauth2.googleapis.com/token",
        data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion},
        timeout=20,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def _gcp_project(credentials: dict[str, Any], metadata: dict[str, Any], payload: dict[str, Any]) -> str:
    project_id = payload.get("project_id") or credentials.get("project_id") or metadata.get("project_id") or _service_account(credentials).get("project_id")
    if not project_id:
        raise ValueError("GCP project_id is required")
    return project_id


def _gcp_action(action: str, credentials: dict[str, Any], metadata: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    token = _gcp_access_token(credentials)
    project_id = _gcp_project(credentials, metadata, payload)
    headers = {"Authorization": f"Bearer {token}"}
    if action == "inventory":
        response = requests.get(
            f"https://cloudasset.googleapis.com/v1/projects/{project_id}/assets",
            headers=headers,
            params={"contentType": "RESOURCE", "pageSize": 100},
            timeout=25,
        )
        response.raise_for_status()
        assets = response.json().get("assets", [])
        return {"status": "ok", "items": [{"type": item.get("assetType"), "name": item.get("name")} for item in assets]}
    if action == "iam-scan":
        response = requests.post(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy",
            headers={**headers, "Content-Type": "application/json"},
            json={},
            timeout=20,
        )
        response.raise_for_status()
        policy = response.json()
        risky = [
            binding for binding in policy.get("bindings", [])
            if any(member in ("allUsers", "allAuthenticatedUsers") for member in binding.get("members", []))
        ]
        return {"status": "ok", "policy": policy, "findings": [{"severity": "high", "title": "Public IAM binding", "binding": item} for item in risky]}
    if action == "remediate":
        bucket = payload.get("bucket")
        if not bucket:
            raise ValueError("bucket is required for GCP remediation")
        response = requests.patch(
            f"https://storage.googleapis.com/storage/v1/b/{bucket}",
            headers={**headers, "Content-Type": "application/json"},
            params={"projection": "full"},
            json={"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}},
            timeout=20,
        )
        response.raise_for_status()
        return {"status": "ok", "mutation": "storage.bucket.uniform_access", "bucket": bucket}
    raise ValueError(f"Unsupported GCP action: {action}")
