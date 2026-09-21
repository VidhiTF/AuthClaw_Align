import os
import json
import logging
import re
import base64
import time
from typing import Dict, List, Any

logger = logging.getLogger("authclaw.document_processing.connectors")

_AWS_ROLE_ARN_PATTERN = re.compile(r"^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]+$")
_UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_google_access_token_cache = {"token": None, "expires_at": 0}
_ms_graph_token_cache = {"token": None, "expires_at": 0}


class ConnectorValidationError(RuntimeError):
    """Raised when a real connector cannot safely perform an operation."""


def _require_connector(source: str) -> None:
    if not validate_connector_config(source).get("valid"):
        raise ConnectorValidationError(f"{source} connector configuration is invalid.")


def _complete_listing(response, key: str) -> list:
    if response.status_code != 200:
        raise RuntimeError(f"Connector listing returned HTTP {response.status_code}.")
    payload = response.json()
    if any(payload.get(field) for field in ("nextPageToken", "@odata.nextLink", "has_more", "incompleteSearch")):
        raise RuntimeError("Connector inventory is incomplete; reconciliation is unsafe.")
    if not isinstance(payload[key], list):
        raise RuntimeError("Connector inventory is not a list.")
    if any(not isinstance(item, dict) or not isinstance(item.get("name"), str) or not item["name"].strip() or
           (not isinstance(item.get("id"), str) or not item["id"].strip()
            if key != "entries" else item.get(".tag") not in {"file", "folder", "deleted"}) or
           (key == "value" and not any(isinstance(item.get(facet), dict) for facet in ("file", "folder")))
           for item in payload[key]):
        raise RuntimeError("Connector inventory contains malformed entries.")
    return payload[key]


def is_real_connectors_enabled() -> bool:
    return os.getenv("ENABLE_REAL_CONNECTORS", "false").lower() == "true"


def _strict_connector_validation() -> bool:
    return os.getenv("AUTHCLAW_CONNECTOR_STRICT_VALIDATION", "false").lower() == "true"


def _connector_validation_failed(source: str, message: str) -> Dict[str, Any]:
    result = {"source": source, "valid": False, "message": message}
    if _strict_connector_validation():
        raise ConnectorValidationError(message)
    logger.warning("%s connector validation failed: %s", source, message)
    return result


def _valid_connector(source: str, message: str, **details: Any) -> Dict[str, Any]:
    return {"source": source, "valid": True, "message": message, **details}


def _load_service_account_json() -> Dict[str, Any]:
    raw_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
    if raw_json:
        return json.loads(raw_json)

    path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return {}


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _aws_session():
    import boto3

    role_arn = os.getenv("AUTHCLAW_AWS_ROLE_ARN") or os.getenv("AWS_ROLE_ARN")
    if not role_arn:
        return boto3.session.Session()

    session_name = os.getenv("AUTHCLAW_AWS_ROLE_SESSION_NAME", "authclaw-document-connector")
    sts = boto3.client("sts")
    external_id = os.getenv("AUTHCLAW_AWS_EXTERNAL_ID", "").strip()
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name, **({"ExternalId": external_id} if external_id else {}))
    credentials = assumed["Credentials"]
    return boto3.session.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def _google_service_account_access_token() -> str:
    now = int(time.time())
    cached_token = _google_access_token_cache.get("token")
    if cached_token and _google_access_token_cache.get("expires_at", 0) > now + 60:
        return cached_token

    service_account = _load_service_account_json()
    if not service_account:
        return None

    import requests
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    header = {"alg": "RS256", "typ": "JWT"}
    claims = {
        "iss": service_account["client_email"],
        "scope": os.getenv("GOOGLE_DRIVE_SCOPES", "https://www.googleapis.com/auth/drive.readonly"),
        "aud": "https://oauth2.googleapis.com/token",
        "iat": now,
        "exp": now + 3600,
    }
    signing_input = ".".join([
        _base64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _base64url(json.dumps(claims, separators=(",", ":")).encode("utf-8")),
    ]).encode("ascii")
    private_key = serialization.load_pem_private_key(service_account["private_key"].encode("utf-8"), password=None)
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    assertion = signing_input.decode("ascii") + "." + _base64url(signature)

    response = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        },
        timeout=15,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload["access_token"]
    _google_access_token_cache["token"] = token
    _google_access_token_cache["expires_at"] = now + int(payload.get("expires_in", 3600))
    return token


def _google_drive_headers() -> Dict[str, str]:
    token = _google_service_account_access_token()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _ms_graph_access_token() -> str:
    token = os.getenv("MICROSOFT_GRAPH_TOKEN")
    if token:
        return token

    now = int(time.time())
    cached_token = _ms_graph_token_cache.get("token")
    if cached_token and _ms_graph_token_cache.get("expires_at", 0) > now + 60:
        return cached_token

    import requests

    tenant_id = os.getenv("MS_GRAPH_TENANT_ID")
    response = requests.post(
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        data={
            "client_id": os.getenv("MS_GRAPH_CLIENT_ID"),
            "client_secret": os.getenv("MS_GRAPH_CLIENT_SECRET"),
            "scope": os.getenv("MS_GRAPH_SCOPES", "https://graph.microsoft.com/.default"),
            "grant_type": "client_credentials",
        },
        timeout=15,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload["access_token"]
    _ms_graph_token_cache["token"] = token
    _ms_graph_token_cache["expires_at"] = now + int(payload.get("expires_in", 3600))
    return token


def validate_aws_connector_config() -> Dict[str, Any]:
    """
    Validates AWS connector configuration before production S3 scans run.
    Supports IAM role auth, explicit access keys, or the default boto3 provider chain.
    """
    if not is_real_connectors_enabled():
        return _valid_connector("aws", "Real connectors are disabled; mock mode is active.", mode="mock")

    role_arn = os.getenv("AUTHCLAW_AWS_ROLE_ARN") or os.getenv("AWS_ROLE_ARN")
    if role_arn and not _AWS_ROLE_ARN_PATTERN.match(role_arn):
        return _connector_validation_failed("aws", "AWS role ARN is malformed.")

    has_static_keys = bool(os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"))
    if role_arn:
        return _valid_connector("aws", "AWS IAM role configuration is present.", mode="iam_role", role_arn=role_arn)
    if has_static_keys:
        return _valid_connector("aws", "AWS access key configuration is present.", mode="access_key")

    try:
        import boto3
        session = boto3.session.Session()
        credentials = session.get_credentials()
        if credentials:
            return _valid_connector("aws", "AWS default credential chain resolved credentials.", mode="default_chain")
    except ImportError:
        return _connector_validation_failed("aws", "boto3 is not installed.")
    except Exception as exc:
        return _connector_validation_failed("aws", f"AWS credential provider chain failed: {exc}")

    return _connector_validation_failed(
        "aws",
        "Set AUTHCLAW_AWS_ROLE_ARN/AWS_ROLE_ARN or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.",
    )


def validate_gcp_connector_config() -> Dict[str, Any]:
    """
    Validates Google Drive connector configuration.
    Service-account JSON is preferred; GOOGLE_API_KEY remains supported for legacy reads.
    """
    if not is_real_connectors_enabled():
        return _valid_connector("gcp", "Real connectors are disabled; mock mode is active.", mode="mock")

    service_account = {}
    try:
        service_account = _load_service_account_json()
    except Exception as exc:
        return _connector_validation_failed("gcp", f"Google service account JSON could not be parsed: {exc}")

    if service_account:
        missing = [field for field in ("project_id", "client_email", "private_key") if not service_account.get(field)]
        if missing:
            return _connector_validation_failed("gcp", f"Google service account JSON is missing: {', '.join(missing)}.")
        if "@" not in service_account.get("client_email", ""):
            return _connector_validation_failed("gcp", "Google service account client_email is invalid.")
        return _valid_connector(
            "gcp",
            "Google service account configuration is present.",
            mode="service_account",
            project_id=service_account.get("project_id"),
            client_email=service_account.get("client_email"),
        )

    if os.getenv("GOOGLE_API_KEY"):
        return _valid_connector("gcp", "Google API key configuration is present.", mode="api_key_legacy")

    return _connector_validation_failed(
        "gcp",
        "Set GOOGLE_SERVICE_ACCOUNT_JSON, GOOGLE_APPLICATION_CREDENTIALS, or GOOGLE_API_KEY.",
    )


def validate_ms_graph_connector_config() -> Dict[str, Any]:
    """
    Validates OneDrive/SharePoint Microsoft Graph connector configuration.
    Supports a bearer token or application credentials.
    """
    if not is_real_connectors_enabled():
        return _valid_connector("microsoft_graph", "Real connectors are disabled; mock mode is active.", mode="mock")

    token = os.getenv("MICROSOFT_GRAPH_TOKEN")
    if token:
        if len(token.strip()) < 20:
            return _connector_validation_failed("microsoft_graph", "MICROSOFT_GRAPH_TOKEN is too short.")
        return _valid_connector("microsoft_graph", "Microsoft Graph bearer token is present.", mode="bearer_token")

    tenant_id = os.getenv("MS_GRAPH_TENANT_ID")
    client_id = os.getenv("MS_GRAPH_CLIENT_ID")
    client_secret = os.getenv("MS_GRAPH_CLIENT_SECRET")
    missing = [
        name
        for name, value in {
            "MS_GRAPH_TENANT_ID": tenant_id,
            "MS_GRAPH_CLIENT_ID": client_id,
            "MS_GRAPH_CLIENT_SECRET": client_secret,
        }.items()
        if not value
    ]
    if missing:
        return _connector_validation_failed("microsoft_graph", f"Missing Microsoft Graph config: {', '.join(missing)}.")
    if not (_UUID_PATTERN.match(tenant_id) or tenant_id.lower() in {"common", "organizations", "consumers"}):
        return _connector_validation_failed("microsoft_graph", "MS_GRAPH_TENANT_ID must be a tenant UUID or supported alias.")
    if not _UUID_PATTERN.match(client_id):
        return _connector_validation_failed("microsoft_graph", "MS_GRAPH_CLIENT_ID must be a UUID.")
    if len(client_secret.strip()) < 8:
        return _connector_validation_failed("microsoft_graph", "MS_GRAPH_CLIENT_SECRET is too short.")
    return _valid_connector("microsoft_graph", "Microsoft Graph application credentials are present.", mode="client_credentials")


def validate_connector_config(source: str) -> Dict[str, Any]:
    normalized = source.lower()
    if normalized == "s3":
        return validate_aws_connector_config()
    if normalized == "gdrive":
        return validate_gcp_connector_config()
    if normalized in {"onedrive", "sharepoint"}:
        return validate_ms_graph_connector_config()
    if normalized == "dropbox":
        token = os.getenv("DROPBOX_ACCESS_TOKEN")
        if not is_real_connectors_enabled():
            return _valid_connector("dropbox", "Real connectors are disabled; mock mode is active.", mode="mock")
        if token and len(token.strip()) >= 20:
            return _valid_connector("dropbox", "Dropbox access token is present.", mode="bearer_token")
        return _connector_validation_failed("dropbox", "DROPBOX_ACCESS_TOKEN is missing or too short.")
    return _connector_validation_failed(source, f"Unknown connector source: {source}.")


def connector_validation_report() -> Dict[str, Dict[str, Any]]:
    return {
        "s3": validate_connector_config("s3"),
        "gdrive": validate_connector_config("gdrive"),
        "onedrive": validate_connector_config("onedrive"),
        "sharepoint": validate_connector_config("sharepoint"),
        "dropbox": validate_connector_config("dropbox"),
    }


def discover_s3_buckets() -> List[str]:
    """
    Lists available S3 buckets via boto3.
    Mock inventories are returned only when real connectors are disabled.
    """
    if is_real_connectors_enabled():
        _require_connector("s3")
        response = _aws_session().client("s3").list_buckets()
        if response.get("ContinuationToken") or response.get("NextToken"):
            raise RuntimeError("S3 bucket inventory is incomplete.")
        if not isinstance(response["Buckets"], list):
            raise RuntimeError("S3 bucket inventory is not a list.")
        return [b["Name"] for b in response["Buckets"]]
    return ["company-compliance-docs", "security-policies", "vendor-documents", "audit-evidence"]

def fetch_s3_document(bucket_name: str, object_key: str) -> bytes:
    """
    Fetches a document from an AWS S3 bucket.
    Returns mock content only when ENABLE_REAL_CONNECTORS is false.
    """
    if is_real_connectors_enabled():
        _require_connector("s3")
        response = _aws_session().client("s3").get_object(Bucket=bucket_name, Key=object_key)
        return response["Body"].read()

    # S3 mock fallback
    dummy_aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    dummy_aws_secret = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    dummy_db_password = "pass" + "word123"
    mock_content = (
        f"AWS S3 Cloud Compliance Evidence Record.\n"
        f"AWS Access Key Exposed: {dummy_aws_key}\n"
        f"AWS Secret Key Exposed: {dummy_aws_secret}\n"
        f"Database Link: postgresql://postgres:{dummy_db_password}@prod-db.internal:5432/production\n"
        "Standard encryption: SSL 2.0 (outdated).\n"
        "Author: cloud_admin\n"
        "Created: 2026-05-01T10:00:00Z"
    )
    return mock_content.encode("utf-8")

def fetch_gdrive_document(file_id: str) -> bytes:
    """
    Fetches a document from Google Drive.
    """
    if is_real_connectors_enabled():
        _require_connector("gdrive")
        import requests
        api_key = os.getenv("GOOGLE_API_KEY")
        if api_key:
            url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media&key={api_key}"
            res = requests.get(url, timeout=15)
        else:
            url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media"
            res = requests.get(url, headers=_google_drive_headers(), timeout=15)
        if res.status_code == 200:
            return res.content
        raise RuntimeError(f"Google Drive fetch returned HTTP {res.status_code}.")

    # GDrive mock fallback
    mock_content = (
        "Google Drive Corporate Access Policy document.\n"
        "Shared Drive permissions: Anyone with the link can edit (Public Link Share).\n"
        "External users consent: No consent form is required for storing customer details.\n"
        "Customer records: john.doe@gmail.com, 555-901-3829, SSN: 000-12-3456.\n"
        "Author: gdrive_compliance_officer\n"
        "Modified: 2026-06-12T15:30:00Z"
    )
    return mock_content.encode("utf-8")

def fetch_onedrive_document(item_id: str) -> bytes:
    """
    Fetches a document from Microsoft OneDrive.
    """
    if is_real_connectors_enabled():
        _require_connector("onedrive")
        import requests
        token = _ms_graph_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"https://graph.microsoft.com/v1.0/me/drive/items/{item_id}/content"
        res = requests.get(url, headers=headers, timeout=15)
        if res.status_code == 200:
            return res.content
        raise RuntimeError(f"OneDrive fetch returned HTTP {res.status_code}.")

    # OneDrive mock fallback
    dummy_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    mock_content = (
        "OneDrive Shared Financial Log.\n"
        "Financial Transaction Info:\n"
        "Credit Card VISA: 4111-1111-1111-1111\n"
        "Bank Account Routing: 021000021\n"
        f"API Token: {dummy_jwt}\n"
        "Author: onedrive_accounting\n"
        "Created: 2026-04-10T12:00:00Z"
    )
    return mock_content.encode("utf-8")

def fetch_sharepoint_document(site_id: str, item_id: str) -> bytes:
    """
    Fetches a document from SharePoint Online.
    """
    if is_real_connectors_enabled():
        _require_connector("sharepoint")
        import requests
        token = _ms_graph_access_token()
        headers = {"Authorization": f"Bearer {token}"}
        url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/items/{item_id}/content"
        res = requests.get(url, headers=headers, timeout=15)
        if res.status_code == 200:
            return res.content
        raise RuntimeError(f"SharePoint fetch returned HTTP {res.status_code}.")

    # SharePoint mock fallback
    mock_content = (
        "SharePoint Patient Record Registry.\n"
        "Internal ePHI:\n"
        "Patient medical record number: MR-847392\n"
        "Patient Identifier: Name: Bob Smith, Phone: 555-892-0923\n"
        "Patient Diagnosis: Chronic Hypertension\n"
        "Author: sharepoint_clinical_admin\n"
        "Created: 2026-05-18T09:15:00Z"
    )
    return mock_content.encode("utf-8")

def fetch_dropbox_document(file_path: str) -> bytes:
    """
    Fetches a document from Dropbox.
    """
    if is_real_connectors_enabled():
        _require_connector("dropbox")
        import requests
        token = os.getenv("DROPBOX_ACCESS_TOKEN")
        headers = {
            "Authorization": f"Bearer {token}",
            "Dropbox-API-Arg": json.dumps({"path": file_path})
        }
        url = "https://content.dropboxapi.com/2/files/download"
        res = requests.post(url, headers=headers, timeout=15)
        if res.status_code == 200:
            return res.content
        raise RuntimeError(f"Dropbox fetch returned HTTP {res.status_code}.")

    # Dropbox mock fallback
    dummy_openai_key = "sk-prod-" + "1234567890abcdef1234567890abcdef"
    dummy_dropbox_token = "sl.B" + "12345EXAMPLE_TOKEN"
    mock_content = (
        "Dropbox Backup Configuration Script.\n"
        f"Dropbox Access Token Exposed: {dummy_dropbox_token}\n"
        f"OpenAI API Key Leak: {dummy_openai_key}\n"
        "Author: backup_script_admin\n"
        "Created: 2026-06-05T20:10:00Z"
    )
    return mock_content.encode("utf-8")

def list_cloud_source_files(source: str) -> List[Dict[str, Any]]:
    """
    Returns a list of files from the cloud source.
    Lists complete real inventories or raises; disabled connectors use mock data.
    """
    if is_real_connectors_enabled():
        _require_connector(source)
        if source == "s3":
            s3 = _aws_session().client("s3")
            buckets = discover_s3_buckets()
            file_list = []
            for b in buckets:
                resp = s3.list_objects_v2(Bucket=b)
                if resp.get("IsTruncated"):
                    raise RuntimeError("S3 object inventory is incomplete.")
                objects = resp.get("Contents", [])
                if not isinstance(objects, list) or type(resp.get("KeyCount")) is not int or resp["KeyCount"] != len(objects):
                    raise RuntimeError("S3 object inventory is malformed.")
                for obj in objects:
                    key = obj["Key"]
                    if key.lower().endswith((".pdf", ".docx", ".txt", ".md", ".csv", ".xlsx")):
                        file_list.append({
                            "id": f"{b}/{key}",
                            "name": os.path.basename(key) or key,
                            "size_bytes": obj["Size"],
                            "location": f"s3://{b}/{key}"
                        })
            return file_list

        elif source == "gdrive":
            import requests
            api_key = os.getenv("GOOGLE_API_KEY")
            folder_id = os.getenv("GOOGLE_DRIVE_FOLDER_ID")
            query = "mimeType != 'application/vnd.google-apps.folder'"
            if folder_id:
                query = f"'{folder_id}' in parents and {query}"
            if api_key:
                url = f"https://www.googleapis.com/drive/v3/files?q={query}&key={api_key}&fields=nextPageToken,incompleteSearch,files(id,name,size)"
                res = requests.get(url, timeout=15)
            else:
                url = "https://www.googleapis.com/drive/v3/files"
                res = requests.get(url, headers=_google_drive_headers(), params={"q": query, "fields": "nextPageToken,incompleteSearch,files(id,name,size)"}, timeout=15)
            if res.status_code == 200:
                files = _complete_listing(res, "files")
                return [{
                    "id": f["id"],
                    "name": f["name"],
                    "size_bytes": int(f["size"]) if f.get("size") is not None else None,
                    "location": f"Google Drive / {f['name']}"
                } for f in files]

        elif source == "onedrive":
            import requests
            token = _ms_graph_access_token()
            folder_id = os.getenv("ONEDRIVE_FOLDER_ID", "root")
            headers = {"Authorization": f"Bearer {token}"}
            url = f"https://graph.microsoft.com/v1.0/me/drive/items/{folder_id}/children"
            res = requests.get(url, headers=headers, timeout=15)
            if res.status_code == 200:
                items = _complete_listing(res, "value")
                return [{
                    "id": item["id"],
                    "name": item["name"],
                    "size_bytes": item.get("size"),
                    "location": f"OneDrive / {item['name']}"
                } for item in items if "file" in item]

        elif source == "sharepoint":
            import requests
            token = _ms_graph_access_token()
            site_id = os.getenv("SHAREPOINT_SITE_ID")
            folder_id = os.getenv("SHAREPOINT_FOLDER_ID", "root")
            if site_id:
                headers = {"Authorization": f"Bearer {token}"}
                url = f"https://graph.microsoft.com/v1.0/sites/{site_id}/drive/items/{folder_id}/children"
                res = requests.get(url, headers=headers, timeout=15)
                if res.status_code == 200:
                    items = _complete_listing(res, "value")
                    return [{
                        "id": f"{site_id}/{item['id']}",
                        "name": item["name"],
                        "size_bytes": item.get("size"),
                        "location": f"SharePoint / {item['name']}"
                    } for item in items if "file" in item]

        elif source == "dropbox":
            import requests
            token = os.getenv("DROPBOX_ACCESS_TOKEN")
            folder_path = os.getenv("DROPBOX_FOLDER_PATH", "")
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            url = "https://api.dropboxapi.com/2/files/list_folder"
            res = requests.post(url, headers=headers, json={"path": folder_path}, timeout=15)
            if res.status_code == 200:
                entries = _complete_listing(res, "entries")
                return [{
                    "id": entry["path_lower"],
                    "name": entry["name"],
                    "size_bytes": entry.get("size"),
                    "location": f"Dropbox{entry['path_display']}"
                } for entry in entries if entry.get(".tag") == "file"]

        raise RuntimeError(f"Real {source} inventory could not be collected.")

    # Mock Fallback lists
    if source == "s3":
        return [
            {"id": "bucket-evidence/Compliance_Policy.pdf", "name": "Compliance_Policy.pdf", "size_bytes": 10240, "location": "s3://bucket-evidence/Compliance_Policy.pdf"},
            {"id": "bucket-evidence/leaked_secrets.txt", "name": "leaked_secrets.txt", "size_bytes": 5210, "location": "s3://bucket-evidence/leaked_secrets.txt"}
        ]
    elif source == "gdrive":
        return [
            {"id": "gdrive_doc_id_101", "name": "Corporate_Privacy_Policy.docx", "size_bytes": 20480, "location": "Google Drive / Policies"},
            {"id": "gdrive_doc_id_102", "name": "unauthorized_ssn_list.csv", "size_bytes": 1205, "location": "Google Drive / Public Shared"}
        ]
    elif source == "onedrive":
        return [
            {"id": "onedrive_item_201", "name": "Financial_Transactions_Q1.xlsx", "size_bytes": 48200, "location": "OneDrive / Accounting / Q1"},
            {"id": "onedrive_item_202", "name": "secret_api_tokens.md", "size_bytes": 950, "location": "OneDrive / Backups"}
        ]
    elif source == "sharepoint":
        return [
            {"id": "sp_site_id_1/sp_item_301", "name": "Patient_Medical_Registry.pdf", "size_bytes": 150240, "location": "SharePoint / Patient Portal"}
        ]
    elif source == "dropbox":
        return [
            {"id": "/backups/dropbox_auth.json", "name": "dropbox_auth.json", "size_bytes": 412, "location": "Dropbox / Backups / Authentication"}
        ]
    return []

def scan_s3_bucket_security(bucket_name: str) -> List[Dict[str, Any]]:
    """
    Scans S3 bucket properties for configuration security and compliance issues.
    Checks: Block Public Access, SSE Default Encryption, Versioning, Access Logging, Public Policy.
    """
    findings = []
    if is_real_connectors_enabled():
        _require_connector("s3")
        from botocore.exceptions import ClientError
        s3 = _aws_session().client("s3")

        # 1. Block Public Access Check
        try:
            pab = s3.get_public_access_block(Bucket=bucket_name)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            is_public_blocked = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False)
            ])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchPublicAccessBlockConfiguration":
                raise
            is_public_blocked = False

        if not is_public_blocked:
            findings.append({
                "finding_type": "Regulatory",
                "matched_pattern": "S3_PUBLIC_ACCESS_ENABLED",
                "matched_text": f"S3 Bucket '{bucket_name}' has public access enabled or block public access is not fully configured.",
                "risk_level": "CRITICAL",
                "recommendation": "[SOC2/ISO27001] Enable Block Public Access at the bucket level to prevent unauthorized data exposure.",
                "impact": "Exposed critical infrastructure or customer records to the public internet.",
                "priority": "P1"
            })

        # 2. Encryption Check
        try:
            enc = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            has_encryption = len(rules) > 0
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ServerSideEncryptionConfigurationNotFoundError":
                raise
            has_encryption = False

        if not has_encryption:
            findings.append({
                "finding_type": "Regulatory",
                "matched_pattern": "S3_ENCRYPTION_DISABLED",
                "matched_text": f"S3 Bucket '{bucket_name}' does not have default server-side encryption enabled.",
                "risk_level": "HIGH",
                "recommendation": "[SOC2/HIPAA] Enable default AES-256 server-side encryption (SSE-S3 or SSE-KMS) for the bucket.",
                "impact": "Data is stored on physical media in plaintext, violating data privacy compliance mandates.",
                "priority": "P1"
            })

        # 3. Versioning Check
        ver = s3.get_bucket_versioning(Bucket=bucket_name)
        status = ver.get("Status", "Disabled")
        has_versioning = status == "Enabled"

        if not has_versioning:
            findings.append({
                "finding_type": "Regulatory",
                "matched_pattern": "S3_VERSIONING_DISABLED",
                "matched_text": f"S3 Bucket '{bucket_name}' versioning is disabled.",
                "risk_level": "MEDIUM",
                "recommendation": "[ISO27001] Enable S3 bucket versioning to allow recovery from accidental deletion or modification.",
                "impact": "Inability to retrieve historical record states or recover from data override incidents.",
                "priority": "P2"
            })

        # 4. Access Logging Check
        log = s3.get_bucket_logging(Bucket=bucket_name)
        has_logging = "LoggingEnabled" in log

        if not has_logging:
            findings.append({
                "finding_type": "Regulatory",
                "matched_pattern": "S3_LOGGING_DISABLED",
                "matched_text": f"S3 Bucket '{bucket_name}' access logging is disabled.",
                "risk_level": "MEDIUM",
                "recommendation": "[SOC2/HIPAA] Enable server access logging to audit data access and operations.",
                "impact": "Auditors cannot verify access trails to individual objects, decreasing compliance trust.",
                "priority": "P2"
            })

        # 5. Public Policy Status Check
        try:
            policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
            is_public_policy = policy_status.get("PolicyStatus", {}).get("IsPublic", False)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
                raise
            is_public_policy = False

        if is_public_policy:
            findings.append({
                "finding_type": "Regulatory",
                "matched_pattern": "S3_PUBLIC_POLICY_EXPOSED",
                "matched_text": f"S3 Bucket '{bucket_name}' has an overly permissive public bucket policy.",
                "risk_level": "CRITICAL",
                "recommendation": "[SOC2/ISO27001] Remove wildcard (*) principal access rules from the bucket policy.",
                "impact": "Allows external third parties to download and view all objects inside the bucket.",
                "priority": "P1"
            })

        return findings

    # Mock findings are limited to explicit mock mode.
    if not findings:
        findings = [
            {
                "finding_type": "Regulatory",
                "matched_pattern": "S3_ENCRYPTION_DISABLED",
                "matched_text": f"S3 Bucket '{bucket_name}' does not have default server-side encryption enabled.",
                "risk_level": "HIGH",
                "recommendation": "[SOC2/HIPAA] Enable default AES-256 server-side encryption (SSE-S3 or SSE-KMS) for the bucket.",
                "impact": "Data is stored on physical media in plaintext, violating data privacy compliance mandates.",
                "priority": "P1"
            },
            {
                "finding_type": "Regulatory",
                "matched_pattern": "S3_VERSIONING_DISABLED",
                "matched_text": f"S3 Bucket '{bucket_name}' versioning is disabled.",
                "risk_level": "MEDIUM",
                "recommendation": "[ISO27001] Enable S3 bucket versioning to allow recovery from accidental deletion or modification.",
                "impact": "Inability to retrieve historical record states or recover from data override incidents.",
                "priority": "P2"
            }
        ]
    return findings
