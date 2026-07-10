import os
import json
import logging
import re
import yaml
from database import DATABASE_URL
from services.secret_manager import SecretManager, SecretValidationError, bootstrap_local_process_secrets

logger = logging.getLogger("authclaw.startup.validation")

POLICY_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


def _normalize_policy_list(data: dict, key: str) -> list:
    if key not in data:
        raise ValueError(f"Missing required policy key: '{key}'")
    if not isinstance(data[key], list):
        raise ValueError(f"Policy key '{key}' must be a list of strings.")
    normalized = []
    seen = set()
    for i, val in enumerate(data[key]):
        if not isinstance(val, str):
            raise ValueError(f"Item at index {i} in '{key}' must be a string.")
        item = val.strip().lower()
        if not item:
            raise ValueError(f"Item at index {i} in '{key}' must not be empty.")
        if item not in seen:
            normalized.append(item)
            seen.add(item)
    return normalized


def _validate_policy_entity_name(value: str, field: str) -> str:
    normalized = value.strip().lower()
    if not POLICY_NAME_PATTERN.match(normalized):
        raise ValueError(f"{field} '{value}' must use lowercase letters, numbers, '.', '_' or '-'.")
    return normalized

def load_and_validate_policy(filepath: str) -> dict:
    """
    Parses and validates the policies YAML file.
    Validates structure, types, allowed values, and version metadata.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Policy file not found at: {filepath}")
        
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML format in policy file: {str(e)}")
        
    if not isinstance(data, dict):
        raise ValueError("Policy file root must be a YAML mapping/dictionary.")
        
    # Check version metadata
    if "version" not in data:
        raise ValueError("Missing policy version metadata ('version' key).")
    version = data["version"]
    if not isinstance(version, (str, int, float)) or not str(version).strip():
        raise ValueError("Policy 'version' must be a non-empty string or number.")

    blocked_keywords = _normalize_policy_list(data, "blocked_keywords")
    high_risk_keywords = _normalize_policy_list(data, "high_risk_keywords")
    medium_risk_keywords = _normalize_policy_list(data, "medium_risk_keywords")

    if "redaction" not in data:
        raise ValueError("Missing required policy key: 'redaction'")
    if not isinstance(data["redaction"], dict):
        raise ValueError("Policy key 'redaction' must be a dictionary.")
        
    allowed_redaction_actions = {"mask", "hash", "synthetic", "redact", "tokenize"}
    redaction_rules = {}
    for key, action in data["redaction"].items():
        if not isinstance(key, str) or not isinstance(action, str):
            raise ValueError("Redaction keys and values must be strings.")
        entity = _validate_policy_entity_name(key, "redaction field")
        action_lower = action.strip().lower()
        if action_lower not in allowed_redaction_actions:
            raise ValueError(f"Invalid redaction action '{action}' for field '{key}'. Must be one of: {allowed_redaction_actions}")
        redaction_rules[entity] = action_lower

    # Validate approval section (optional; defaults applied if absent)
    approval_raw = data.get("approval", {})
    if not isinstance(approval_raw, dict):
        raise ValueError("Policy key 'approval' must be a dictionary.")
    require_mfa = approval_raw.get("require_mfa", True)
    if not isinstance(require_mfa, bool):
        raise ValueError("approval.require_mfa must be a boolean (true or false).")
    default_mfa_code = str(approval_raw.get("default_mfa_code", "123456")).strip()
    if not default_mfa_code:
        raise ValueError("approval.default_mfa_code must be a non-empty string.")
    expiry_minutes = approval_raw.get("expiry_minutes", 30)
    if not isinstance(expiry_minutes, (int, float)) or expiry_minutes <= 0:
        raise ValueError("approval.expiry_minutes must be a positive number.")
    execution_expiry_minutes = approval_raw.get("execution_expiry_minutes", 10)
    if not isinstance(execution_expiry_minutes, (int, float)) or execution_expiry_minutes <= 0:
        raise ValueError("approval.execution_expiry_minutes must be a positive number.")

    sensitive_data_raw = data.get("sensitive_data", {})
    if not isinstance(sensitive_data_raw, dict):
        raise ValueError("Policy key 'sensitive_data' must be a dictionary.")
    allowed_sensitive_actions = {"allow", "redact", "block", "require_approval", "mask", "hash", "tokenize"}
    default_sensitive_action = str(sensitive_data_raw.get("default_action", "redact")).lower()
    if default_sensitive_action not in allowed_sensitive_actions:
        raise ValueError(
            f"Invalid sensitive_data.default_action '{default_sensitive_action}'. "
            f"Must be one of: {allowed_sensitive_actions}"
        )
    approval_confidence_threshold = sensitive_data_raw.get("approval_confidence_threshold", 1.01)
    if not isinstance(approval_confidence_threshold, (int, float)):
        raise ValueError("sensitive_data.approval_confidence_threshold must be numeric.")
    sensitive_actions_raw = sensitive_data_raw.get("actions", {})
    if not isinstance(sensitive_actions_raw, dict):
        raise ValueError("sensitive_data.actions must be a dictionary.")
    sensitive_actions = {}
    for key, action in sensitive_actions_raw.items():
        if not isinstance(key, str) or not isinstance(action, str):
            raise ValueError("sensitive_data.actions keys and values must be strings.")
        entity = _validate_policy_entity_name(key, "sensitive_data action entity")
        action_lower = action.lower()
        if action_lower not in allowed_sensitive_actions:
            raise ValueError(
                f"Invalid sensitive_data action '{action}' for entity '{key}'. "
                f"Must be one of: {allowed_sensitive_actions}"
            )
        sensitive_actions[entity] = action_lower

    opa_raw = data.get("opa", {})
    if not isinstance(opa_raw, dict):
        raise ValueError("Policy key 'opa' must be a dictionary.")
    opa_package = str(opa_raw.get("package", "authclaw.policy")).strip()
    if not re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$", opa_package):
        raise ValueError("opa.package must be a dotted lowercase Rego package name.")
    bundle_version = str(opa_raw.get("bundle_version", version)).strip()
    if not bundle_version:
        raise ValueError("opa.bundle_version must be non-empty when provided.")
    fail_closed = opa_raw.get("fail_closed", True)
    if not isinstance(fail_closed, bool):
        raise ValueError("opa.fail_closed must be a boolean.")

    # Normalize keys/actions to lowercase
    normalized = {
        "version": str(version),
        "blocked_keywords": blocked_keywords,
        "high_risk_keywords": high_risk_keywords,
        "medium_risk_keywords": medium_risk_keywords,
        "redaction": redaction_rules,
        "approval": {
            "require_mfa": require_mfa,
            "default_mfa_code": default_mfa_code,
            "expiry_minutes": int(expiry_minutes),
            "execution_expiry_minutes": int(execution_expiry_minutes),
        },
        "sensitive_data": {
            "default_action": default_sensitive_action,
            "approval_confidence_threshold": float(approval_confidence_threshold),
            "actions": sensitive_actions,
        },
        "opa": {
            "package": opa_package,
            "bundle_version": bundle_version,
            "fail_closed": fail_closed,
        },
    }
    return normalized


def validate_environment():
    """
    Validates required environment variables for the application:
    - GOOGLE_API_KEY
    - MODEL_PROVIDER
    - MODEL_NAME
    - DATABASE_URL
    And loads/validates YAML policies.
    """
    errors = []
    
    production = os.getenv("AUTHCLAW_ENV", "development").lower() in {"production", "prod"}
    bootstrap_local_process_secrets()

    # 1. Validate local provider fallback key.
    # Development can run in degraded/offline-provider mode so the UI, auth,
    # policies, API keys, and audit flows remain testable without provider quota.
    model_provider = os.getenv("MODEL_PROVIDER", "gemini").lower().replace(" ", "_")
    provider_key_env = {
        "gemini": "GOOGLE_API_KEY",
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "cohere": "COHERE_API_KEY",
        "azure_openai": "AZURE_OPENAI_API_KEY",
        "azure": "AZURE_OPENAI_API_KEY",
    }.get(model_provider, "GOOGLE_API_KEY")
    provider_api_key = os.getenv(provider_key_env)
    if not provider_api_key and production:
        errors.append(f"{provider_key_env} is not set or empty.")
    elif not provider_api_key:
        logger.warning("%s is not configured. Local runtime will use provider fallback behavior.", provider_key_env)
        
    # 2. Validate MODEL_PROVIDER
    supported_providers = ["gemini", "openai", "anthropic", "cohere", "azure_openai"]
    if model_provider not in supported_providers and model_provider != "azure":
        errors.append(f"MODEL_PROVIDER '{model_provider}' is not supported. Supported: {supported_providers}")
        
    # 3. Validate MODEL_NAME
    model_name = os.getenv("MODEL_NAME", "gemini-2.5-flash-lite")
    if not model_name:
        errors.append("MODEL_NAME cannot be empty.")
        
    # 4. Validate DATABASE_URL
    if not DATABASE_URL:
        errors.append("DATABASE_URL is not set or empty.")
    elif not DATABASE_URL.startswith(("postgresql://", "postgresql+psycopg2://")):
        errors.append("DATABASE_URL must be a PostgreSQL connection string starting with 'postgresql://'.")

    # 5. Load and Validate YAML Policies
    try:
        from policy import load_policy
        load_policy()
    except Exception as e:
        errors.append(f"Failed to load policy file: {str(e)}")

    if production:
        errors.extend(validate_production_environment())

    try:
        SecretManager().validate_startup(production=production)
    except SecretValidationError as exc:
        errors.append(f"Secret manager validation failed: {exc}")

    if errors:
        failure_log = {
            "event": "environment_validation",
            "status": "failed",
            "message": "Environment validation failed.",
            "details": {
                "errors": errors
            }
        }
        logger.error(json.dumps(failure_log))
        print(json.dumps(failure_log), flush=True)
        raise ValueError(f"Environment validation failed: {'; '.join(errors)}")

    # Structured JSON logging for success
    success_log = {
        "event": "environment_validation",
        "status": "success",
        "message": "Environment validation completed successfully.",
        "details": {
            "model_provider": model_provider,
            "model_name": model_name,
            "database_url_configured": True,
            "production_mode": production
        }
    }
    logger.info(json.dumps(success_log))
    print(json.dumps(success_log), flush=True)


def validate_production_environment() -> list:
    errors = []

    manager = SecretManager()
    if manager.backend in {"local_env", "local"}:
        errors.append("Production requires a managed secret backend, not local_env.")

    allowed_origins = [origin.strip() for origin in os.getenv("AUTHCLAW_ALLOWED_ORIGINS", "").split(",") if origin.strip()]
    if not allowed_origins:
        errors.append("Production requires AUTHCLAW_ALLOWED_ORIGINS.")
    for origin in allowed_origins:
        lowered = origin.lower()
        if origin == "*" or "localhost" in lowered or "127.0.0.1" in lowered:
            errors.append(f"Production CORS origin is not allowed: {origin}")

    if not os.getenv("SMTP_HOST") or not os.getenv("SMTP_FROM"):
        errors.append("Production onboarding requires SMTP_HOST and SMTP_FROM for email verification.")

    rate_limit = os.getenv("AUTHCLAW_RATE_LIMIT_PER_MINUTE")
    try:
        if not rate_limit or int(rate_limit) <= 0:
            errors.append("Production requires AUTHCLAW_RATE_LIMIT_PER_MINUTE as a positive integer.")
    except ValueError:
        errors.append("AUTHCLAW_RATE_LIMIT_PER_MINUTE must be an integer.")

    if os.getenv("AUTHCLAW_USE_COOKIES", "false").lower() in {"1", "true", "yes"}:
        if os.getenv("AUTHCLAW_COOKIE_SECURE", "false").lower() not in {"1", "true", "yes"}:
            errors.append("Production cookie mode requires AUTHCLAW_COOKIE_SECURE=true.")
        if os.getenv("AUTHCLAW_COOKIE_SAMESITE", "strict").lower() not in {"strict", "lax", "none"}:
            errors.append("AUTHCLAW_COOKIE_SAMESITE must be strict, lax, or none.")

    if os.getenv("AWS_SECRETS_MANAGER_ENABLED", "false").lower() in {"1", "true", "yes"}:
        if not (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")):
            errors.append("AWS_REGION or AWS_DEFAULT_REGION is required when AWS Secrets Manager is enabled.")

    if os.getenv("AUTHCLAW_OPA_ENABLED", "true").lower() in {"0", "false", "no", "off"}:
        errors.append("Production requires AUTHCLAW_OPA_ENABLED=true because OPA is the enforcement path.")
    if not os.getenv("AUTHCLAW_OPA_POLICY_URL"):
        errors.append("Production requires AUTHCLAW_OPA_POLICY_URL.")

    document_storage = os.getenv("AUTHCLAW_DOCUMENT_STORAGE_BACKEND", "local").lower()
    if document_storage not in {"local", "s3"}:
        errors.append("AUTHCLAW_DOCUMENT_STORAGE_BACKEND must be either local or s3.")
    if document_storage == "s3":
        if not os.getenv("AUTHCLAW_DOCUMENT_S3_BUCKET"):
            errors.append("AUTHCLAW_DOCUMENT_S3_BUCKET is required when AUTHCLAW_DOCUMENT_STORAGE_BACKEND=s3.")
        if not (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")):
            errors.append("AWS_REGION or AWS_DEFAULT_REGION is required when document storage uses S3.")

    return errors
