import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet


class SecretManagerError(RuntimeError):
    pass


class SecretValidationError(SecretManagerError):
    pass


@dataclass(repr=False)
class StoredSecret:
    name: str
    backend: str
    version_id: Optional[str] = None
    value: str = field(default="", repr=False)


@dataclass(frozen=True)
class SecretHealth:
    backend: str
    healthy: bool
    message: str


SENSITIVE_ENV_NAMES = {
    "JWT_SECRET",
    "AUTHCLAW_JWT_SECRET",
    "AUTHCLAW_ENCRYPTION_KEY",
    "AUTHCLAW_REDACTION_SALT",
    "SMTP_PASSWORD",
    "SENDGRID_API_KEY",
    "DATABASE_URL",
    "GOOGLE_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "COHERE_API_KEY",
    "AZURE_OPENAI_API_KEY",
}

_LOCAL_SECRET_CACHE: Dict[str, str] = {}


def normalize_provider(provider: str) -> str:
    normalized = (provider or "").lower().replace(" ", "_")
    if normalized in {"google_gemini", "gemini"}:
        return "gemini"
    if normalized in {"azure", "azure_openai", "azure-openai"}:
        return "azure_openai"
    if normalized in {"anthropic", "claude"}:
        return "anthropic"
    if normalized in {"cohere", "co"}:
        return "cohere"
    return normalized


def secret_name_for_provider(tenant_id: int, provider: str) -> str:
    return f"authclaw/tenants/{tenant_id}/providers/{normalize_provider(provider)}"


def credential_fingerprint(payload: Dict[str, Any]) -> str:
    api_key = str(payload.get("api_key") or "")
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16] if api_key else ""


def credential_prefix(payload: Dict[str, Any]) -> str:
    api_key = str(payload.get("api_key") or "")
    if not api_key:
        return ""
    return f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) > 12 else f"{api_key[:3]}..."


def _truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_production() -> bool:
    return os.getenv("AUTHCLAW_ENV", "development").lower() in {"production", "prod"}


def select_secret_backend(requested: Optional[str] = None) -> str:
    explicit = (requested or os.getenv("AUTHCLAW_SECRET_BACKEND") or "").strip().lower()
    if explicit in {"local_env", "local"} and _truthy(os.getenv("AWS_SECRETS_MANAGER_ENABLED")):
        return "aws_secrets_manager"
    if explicit and explicit not in {"auto", "automatic"}:
        return explicit
    auto_requested = explicit in {"auto", "automatic"}
    if os.getenv("VAULT_ADDR") and os.getenv("VAULT_TOKEN"):
        return "hashicorp_vault"
    if _truthy(os.getenv("AWS_SECRETS_MANAGER_ENABLED")) or (
        auto_requested and (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"))
    ):
        return "aws_secrets_manager"
    return "local_env"


def _safe_error(name: str, detail: str) -> SecretManagerError:
    return SecretManagerError(f"Secret '{name}' {detail}.")


class SecretManager:
    """
    Central secret access point for AuthClaw.

    Business logic must use this service instead of direct sensitive env access.
    Local development uses local_env with generated or user-provided process
    secrets. Production must use a managed backend.
    """

    def __init__(self, backend: Optional[str] = None):
        self.backend = select_secret_backend(backend)
        self.region_name = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")

    def selection_policy(self) -> Dict[str, Any]:
        return {
            "requested_backend": (os.getenv("AUTHCLAW_SECRET_BACKEND") or "auto").strip().lower(),
            "selected_backend": self.backend,
            "fallback_hierarchy": ["hashicorp_vault", "aws_secrets_manager", "local_env"],
            "production_allows_local": not _is_production(),
            "rotation_supported": self.backend in {"local_env", "local", "aws_secrets_manager", "hashicorp_vault", "vault"},
        }

    def get_secret(self, name: str) -> Optional[str]:
        if self.backend in {"local_env", "local"}:
            return os.getenv(name) or _LOCAL_SECRET_CACHE.get(name)
        if self.backend == "aws_secrets_manager":
            return self._get_aws_secret(name)
        if self.backend in {"hashicorp_vault", "vault"}:
            return self._get_vault_secret(name)
        if self.backend == "azure_key_vault":
            return self._get_azure_secret(name)
        if self.backend == "google_secret_manager":
            return self._get_google_secret(name)
        raise SecretManagerError(f"Unsupported secret backend '{self.backend}'.")

    def get_required_secret(self, name: str, *, min_length: int = 1) -> str:
        value = self.get_secret(name)
        if not value or len(value) < min_length:
            raise _safe_error(name, f"is missing or shorter than {min_length} characters")
        return value

    def put_secret(self, name: str, value: str) -> StoredSecret:
        if not value:
            raise _safe_error(name, "cannot be stored with an empty value")
        if self.backend in {"local_env", "local"}:
            _LOCAL_SECRET_CACHE[name] = value
            os.environ[name] = value
            return StoredSecret(name=name, backend=self.backend, version_id=self._version(value), value=value)
        if self.backend == "aws_secrets_manager":
            version_id = self._put_aws_secret(name, value)
            return StoredSecret(name=name, backend=self.backend, version_id=version_id, value=value)
        if self.backend in {"hashicorp_vault", "vault"}:
            version_id = self._put_vault_secret(name, value)
            return StoredSecret(name=name, backend="hashicorp_vault", version_id=version_id, value=value)
        if self.backend == "azure_key_vault":
            version_id = self._put_azure_secret(name, value)
            return StoredSecret(name=name, backend=self.backend, version_id=version_id, value=value)
        if self.backend == "google_secret_manager":
            version_id = self._put_google_secret(name, value)
            return StoredSecret(name=name, backend=self.backend, version_id=version_id, value=value)
        raise SecretManagerError(f"Unsupported secret backend '{self.backend}'.")

    def rotate_secret(self, name: str, value: str, *, actor: str = "system") -> StoredSecret:
        stored = self.put_secret(name, value)
        self.audit_secret_event("secret_rotated", name, actor=actor, version_id=stored.version_id)
        return stored

    def delete_secret(self, name: str) -> None:
        if self.backend in {"local_env", "local"}:
            _LOCAL_SECRET_CACHE.pop(name, None)
            os.environ.pop(name, None)
            return
        if self.backend == "aws_secrets_manager":
            self._delete_aws_secret(name)
            return
        raise SecretManagerError(f"Secret deletion is not implemented for backend '{self.backend}'.")

    def encryption_key(self) -> str:
        key = self.get_required_secret("AUTHCLAW_ENCRYPTION_KEY", min_length=32)
        try:
            Fernet(key.encode("utf-8"))
        except Exception as exc:
            raise SecretValidationError("AUTHCLAW_ENCRYPTION_KEY is not a valid Fernet key.") from exc
        return key

    def redaction_salt(self) -> str:
        return self.get_required_secret("AUTHCLAW_REDACTION_SALT", min_length=32)

    def fingerprint(self, value: str, *, purpose: str = "generic") -> str:
        salt = self.redaction_salt()
        return hmac.new(salt.encode("utf-8"), f"{purpose}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()[:20]

    def encrypt_for_database(self, value: str) -> str:
        envelope = self._encrypt_with_envelope(value)
        if envelope:
            return envelope
        key = base64.urlsafe_b64decode(self.encryption_key().encode("utf-8"))
        nonce = os.urandom(12)
        ciphertext = AESGCM(key).encrypt(nonce, value.encode("utf-8"), None)
        return "v2:aes256gcm:" + base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt_from_database(self, encrypted_value: str) -> str:
        if encrypted_value.startswith("v3:envelope:"):
            return self._decrypt_with_envelope(encrypted_value)
        if encrypted_value.startswith("v2:aes256gcm:"):
            payload = base64.urlsafe_b64decode(encrypted_value.split(":", 2)[2].encode("utf-8"))
            nonce, ciphertext = payload[:12], payload[12:]
            key = base64.urlsafe_b64decode(self.encryption_key().encode("utf-8"))
            return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
        return Fernet(self.encryption_key().encode("utf-8")).decrypt(encrypted_value.encode("utf-8")).decode("utf-8")

    def store_provider_payload(self, tenant_id: int, provider: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        normalized_provider = normalize_provider(provider)
        secret_name = secret_name_for_provider(tenant_id, normalized_provider)
        secret_value = json.dumps(payload)
        stored = self.put_secret(secret_name, secret_value)
        database_payload = json.dumps(
            {
                "provider": normalized_provider,
                "secret_ref": stored.name,
                "secret_backend": stored.backend,
                "secret_version": stored.version_id,
            }
        )
        encrypted_payload = self.encrypt_for_database(database_payload)
        now = datetime.now(timezone.utc).isoformat()
        self.audit_secret_event("provider_secret_stored", secret_name, actor="tenant_admin", version_id=stored.version_id)
        return {
            "provider": normalized_provider,
            "secret_ref": stored.name,
            "secret_backend": stored.backend,
            "secret_version": stored.version_id,
            "encrypted_payload": encrypted_payload,
            "key_fingerprint": credential_fingerprint(payload),
            "key_prefix": credential_prefix(payload),
            "rotated_at": now,
        }

    def resolve_provider_payload(self, credential_row: Dict[str, Any]) -> Dict[str, Any]:
        secret_ref = credential_row.get("secret_ref")
        if secret_ref:
            secret_value = self.get_secret(secret_ref)
            if secret_value:
                return json.loads(secret_value)

        encrypted_payload = credential_row.get("encrypted_payload")
        if not encrypted_payload:
            raise SecretManagerError("Provider credential payload is missing.")
        payload = json.loads(self.decrypt_from_database(encrypted_payload))
        if isinstance(payload, dict) and payload.get("secret_ref") and not payload.get("api_key"):
            secret_value = self.get_secret(payload["secret_ref"])
            if secret_value:
                return json.loads(secret_value)
            raise SecretManagerError("Provider credential secret reference is unavailable.")
        return payload

    def get_json_secret(self, name: str) -> Optional[dict]:
        value = self.get_secret(name)
        if not value:
            return None
        try:
            return json.loads(value)
        except json.JSONDecodeError as exc:
            raise SecretManagerError(f"Secret '{name}' is not valid JSON.") from exc

    def health_check(self) -> SecretHealth:
        try:
            if self.backend in {"local_env", "local"}:
                self.get_required_secret("JWT_SECRET", min_length=32)
                self.encryption_key()
                self.redaction_salt()
            elif self.backend == "aws_secrets_manager":
                self._client()
            elif self.backend in {"hashicorp_vault", "vault"}:
                self._vault_request("GET", "sys/health", expect_json=False)
            elif self.backend == "azure_key_vault":
                self._azure_client()
            elif self.backend == "google_secret_manager":
                self._google_client()
            else:
                raise SecretManagerError(f"Unsupported secret backend '{self.backend}'.")
            return SecretHealth(backend=self.backend, healthy=True, message="secret manager healthy")
        except Exception as exc:
            return SecretHealth(backend=self.backend, healthy=False, message=str(exc))

    def validate_startup(self, *, production: Optional[bool] = None) -> None:
        production = _is_production() if production is None else production
        errors = []
        health = self.health_check()
        if not health.healthy:
            errors.append(health.message)
        if production and self.backend in {"local_env", "local"}:
            errors.append("production requires AUTHCLAW_SECRET_BACKEND to be aws_secrets_manager, hashicorp_vault, azure_key_vault, or google_secret_manager")
        if errors:
            raise SecretValidationError("; ".join(errors))

    def audit_secret_event(self, event_type: str, secret_name: str, *, actor: str = "system", version_id: Optional[str] = None) -> None:
        safe_name = hashlib.sha256(secret_name.encode("utf-8")).hexdigest()[:16]
        try:
            from verify_audit import create_audit_block

            create_audit_block(
                query=f"Secret event: {event_type}",
                response=f"secret_ref={safe_name}; backend={self.backend}; version={version_id or 'n/a'}",
                allowed=True,
                risk_level="LOW",
                approval_status="completed",
                session_id="secret-manager",
                username=actor,
                tenant_id=1,
            )
        except Exception:
            # Audit must never expose secret values or block provider credential save in local dev.
            return

    def _version(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    def _envelope_provider(self) -> str:
        return (os.getenv("AUTHCLAW_ENVELOPE_PROVIDER") or os.getenv("AUTHCLAW_KMS_PROVIDER") or "").strip().lower()

    def _encrypt_with_envelope(self, value: str) -> Optional[str]:
        provider = self._envelope_provider()
        if provider in {"", "local", "local_env", "disabled", "none"}:
            return None
        try:
            data_key, encrypted_data_key, key_id = self._generate_envelope_data_key(provider)
            nonce = os.urandom(12)
            ciphertext = AESGCM(data_key).encrypt(nonce, value.encode("utf-8"), None)
            payload = {
                "provider": provider,
                "key_id": key_id,
                "encrypted_data_key": base64.urlsafe_b64encode(encrypted_data_key).decode("utf-8"),
                "ciphertext": base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8"),
                "alg": "AES-256-GCM",
            }
            return "v3:envelope:" + base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        except Exception:
            if _is_production() and os.getenv("AUTHCLAW_REQUIRE_REMOTE_KMS", "").lower() in {"1", "true", "yes", "on"}:
                raise
            return None

    def _decrypt_with_envelope(self, encrypted_value: str) -> str:
        encoded = encrypted_value.split(":", 2)[2]
        payload = json.loads(base64.urlsafe_b64decode(encoded.encode("utf-8")).decode("utf-8"))
        provider = str(payload.get("provider") or self._envelope_provider()).lower()
        encrypted_data_key = base64.urlsafe_b64decode(payload["encrypted_data_key"].encode("utf-8"))
        data_key = self._decrypt_envelope_data_key(provider, encrypted_data_key, payload.get("key_id"))
        ciphertext_payload = base64.urlsafe_b64decode(payload["ciphertext"].encode("utf-8"))
        nonce, ciphertext = ciphertext_payload[:12], ciphertext_payload[12:]
        return AESGCM(data_key).decrypt(nonce, ciphertext, None).decode("utf-8")

    def _generate_envelope_data_key(self, provider: str):
        if provider in {"aws", "aws_kms", "kms"}:
            return self._aws_kms_generate_data_key()
        if provider in {"vault", "hashicorp_vault"}:
            return self._vault_generate_data_key()
        raise SecretManagerError(f"Unsupported envelope provider '{provider}'.")

    def _decrypt_envelope_data_key(self, provider: str, encrypted_data_key: bytes, key_id: Optional[str]) -> bytes:
        if provider in {"aws", "aws_kms", "kms"}:
            return self._aws_kms_decrypt_data_key(encrypted_data_key)
        if provider in {"vault", "hashicorp_vault"}:
            return self._vault_decrypt_data_key(encrypted_data_key, key_id)
        raise SecretManagerError(f"Unsupported envelope provider '{provider}'.")

    def _kms_client(self):
        try:
            import boto3
        except ImportError as exc:
            raise SecretManagerError("boto3 is required when AWS KMS envelope encryption is enabled.") from exc
        if not self.region_name:
            raise SecretManagerError("AWS_REGION or AWS_DEFAULT_REGION is required for AWS KMS.")
        return boto3.client("kms", region_name=self.region_name)

    def _aws_kms_key_id(self) -> str:
        key_id = os.getenv("AUTHCLAW_AWS_KMS_KEY_ID") or os.getenv("AWS_KMS_KEY_ID")
        if not key_id:
            raise SecretManagerError("AUTHCLAW_AWS_KMS_KEY_ID or AWS_KMS_KEY_ID is required for AWS KMS envelope encryption.")
        return key_id

    def _aws_kms_generate_data_key(self):
        key_id = self._aws_kms_key_id()
        response = self._kms_client().generate_data_key(KeyId=key_id, KeySpec="AES_256")
        return response["Plaintext"], response["CiphertextBlob"], key_id

    def _aws_kms_decrypt_data_key(self, encrypted_data_key: bytes) -> bytes:
        response = self._kms_client().decrypt(CiphertextBlob=encrypted_data_key)
        return response["Plaintext"]

    def _vault_transit_key(self) -> str:
        return os.getenv("VAULT_TRANSIT_KEY", "authclaw-tenant-key")

    def _vault_generate_data_key(self):
        key_name = self._vault_transit_key()
        response = self._vault_request(
            "POST",
            f"transit/datakey/plaintext/{key_name}",
            payload={"bits": 256},
        )
        data = (response or {}).get("data") or {}
        plaintext = base64.b64decode(data["plaintext"])
        ciphertext = data["ciphertext"].encode("utf-8")
        return plaintext, ciphertext, key_name

    def _vault_decrypt_data_key(self, encrypted_data_key: bytes, key_id: Optional[str]) -> bytes:
        key_name = key_id or self._vault_transit_key()
        response = self._vault_request(
            "POST",
            f"transit/decrypt/{key_name}",
            payload={"ciphertext": encrypted_data_key.decode("utf-8")},
        )
        data = (response or {}).get("data") or {}
        return base64.b64decode(data["plaintext"])

    def _client(self):
        try:
            import boto3
        except ImportError as exc:
            raise SecretManagerError("boto3 is required when AWS Secrets Manager is enabled.") from exc
        if not self.region_name:
            raise SecretManagerError("AWS_REGION or AWS_DEFAULT_REGION is required for AWS Secrets Manager.")
        return boto3.client("secretsmanager", region_name=self.region_name)

    def _get_aws_secret(self, name: str) -> Optional[str]:
        client = self._client()
        try:
            response = client.get_secret_value(SecretId=name)
        except Exception as exc:
            raise _safe_error(name, f"could not be read from AWS Secrets Manager: {type(exc).__name__}") from exc
        return response.get("SecretString")

    def _put_aws_secret(self, name: str, value: str) -> Optional[str]:
        client = self._client()
        try:
            try:
                response = client.put_secret_value(SecretId=name, SecretString=value)
            except client.exceptions.ResourceNotFoundException:
                response = client.create_secret(Name=name, SecretString=value)
            return response.get("VersionId")
        except Exception as exc:
            raise _safe_error(name, f"could not be stored in AWS Secrets Manager: {type(exc).__name__}") from exc

    def _delete_aws_secret(self, name: str) -> None:
        client = self._client()
        try:
            client.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
        except client.exceptions.ResourceNotFoundException:
            return
        except Exception as exc:
            raise _safe_error(name, f"could not be deleted from AWS Secrets Manager: {type(exc).__name__}") from exc

    def _vault_request(self, method: str, path: str, *, payload: Optional[dict] = None, expect_json: bool = True) -> Any:
        try:
            import requests
        except ImportError as exc:
            raise SecretManagerError("requests is required for HashiCorp Vault secret backend.") from exc
        address = os.getenv("VAULT_ADDR")
        token = os.getenv("VAULT_TOKEN")
        if not address or not token:
            raise SecretManagerError("VAULT_ADDR and VAULT_TOKEN are required for HashiCorp Vault.")
        base_url = address.rstrip("/")
        if base_url.endswith("/v1"):
            base_url = base_url[:-3].rstrip("/")
        response = requests.request(
            method,
            f"{base_url}/v1/{path.lstrip('/')}",
            headers={"X-Vault-Token": token},
            json=payload,
            timeout=10,
        )
        if response.status_code >= 400:
            raise SecretManagerError(f"Vault request failed with status {response.status_code}.")
        return response.json() if expect_json and response.text else None

    def _vault_path(self, name: str) -> str:
        mount = os.getenv("VAULT_KV_MOUNT", "secret")
        return f"{mount}/data/{name}"

    def _get_vault_secret(self, name: str) -> Optional[str]:
        data = self._vault_request("GET", self._vault_path(name))
        return ((data or {}).get("data") or {}).get("data", {}).get("value")

    def _put_vault_secret(self, name: str, value: str) -> str:
        self._vault_request("POST", self._vault_path(name), payload={"data": {"value": value}})
        return self._version(value)

    def _azure_client(self):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:
            raise SecretManagerError("azure-identity and azure-keyvault-secrets are required for Azure Key Vault.") from exc
        vault_url = os.getenv("AZURE_KEY_VAULT_URL")
        if not vault_url:
            raise SecretManagerError("AZURE_KEY_VAULT_URL is required for Azure Key Vault.")
        return SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())

    def _get_azure_secret(self, name: str) -> Optional[str]:
        return self._azure_client().get_secret(name).value

    def _put_azure_secret(self, name: str, value: str) -> str:
        return self._azure_client().set_secret(name, value).properties.version or self._version(value)

    def _google_client(self):
        try:
            from google.cloud import secretmanager
        except ImportError as exc:
            raise SecretManagerError("google-cloud-secret-manager is required for Google Secret Manager.") from exc
        project = os.getenv("GOOGLE_CLOUD_PROJECT")
        if not project:
            raise SecretManagerError("GOOGLE_CLOUD_PROJECT is required for Google Secret Manager.")
        return secretmanager.SecretManagerServiceClient(), project

    def _google_secret_resource(self, name: str) -> str:
        _, project = self._google_client()
        return f"projects/{project}/secrets/{name.replace('/', '--')}"

    def _get_google_secret(self, name: str) -> Optional[str]:
        client, _ = self._google_client()
        response = client.access_secret_version(request={"name": f"{self._google_secret_resource(name)}/versions/latest"})
        return response.payload.data.decode("utf-8")

    def _put_google_secret(self, name: str, value: str) -> str:
        client, _ = self._google_client()
        parent = "/".join(self._google_secret_resource(name).split("/")[:2])
        secret_id = name.replace("/", "--")
        try:
            client.create_secret(request={"parent": parent, "secret_id": secret_id, "secret": {"replication": {"automatic": {}}}})
        except Exception:
            pass
        version = client.add_secret_version(request={"parent": self._google_secret_resource(name), "payload": {"data": value.encode("utf-8")}})
        return version.name.rsplit("/", 1)[-1]


def generate_fernet_key() -> str:
    return Fernet.generate_key().decode("utf-8")


def generate_urlsafe_secret(num_bytes: int = 48) -> str:
    return base64.urlsafe_b64encode(os.urandom(num_bytes)).decode("utf-8")


def bootstrap_local_process_secrets() -> None:
    if _is_production():
        return
    os.environ.setdefault("AUTHCLAW_SECRET_BACKEND", "local_env")
    if not os.getenv("JWT_SECRET") and not os.getenv("AUTHCLAW_JWT_SECRET"):
        os.environ["JWT_SECRET"] = generate_urlsafe_secret()
    if not os.getenv("AUTHCLAW_ENCRYPTION_KEY"):
        os.environ["AUTHCLAW_ENCRYPTION_KEY"] = generate_fernet_key()
    if not os.getenv("AUTHCLAW_REDACTION_SALT"):
        os.environ["AUTHCLAW_REDACTION_SALT"] = generate_urlsafe_secret()
