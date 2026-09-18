"""Configuration settings for AuthClaw Backend"""
import json
import os
from typing import List
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings


COMPLIANCE_OWNER_ROLES = {
    "platform_security": "Platform security",
    "agent_engineering": "Agent engineering",
    "governance": "Governance",
    "release_governance": "Release governance",
}


class Settings(BaseSettings):
    """Application settings from environment variables"""
    
    # API
    API_TITLE: str = "AuthClaw API"
    API_VERSION: str = "0.1.0"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "postgresql://authclaw:authclaw@localhost:5432/authclaw"

    @field_validator("DATABASE_URL")
    @classmethod
    def select_installed_postgres_driver(cls, value: str) -> str:
        return value.replace("postgresql://", "postgresql+psycopg://", 1) if value.startswith("postgresql://") else value
    
    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:8000",
    ]
    
    # Security
    JWT_SECRET: str = "dev-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    API_KEY_HASH_SECRET: str = ""
    PRIVACY_NOTICE_VERSION: str = Field(default="2026-07-20", min_length=1, max_length=50)
    INTERNAL_LAUNCH_OWNER_EMAIL: str = ""

    # Evidence may qualify only in an explicitly selected deployment scope.
    COMPLIANCE_ENVIRONMENT: str = "unconfigured"
    COMPLIANCE_OWNER_MAP_JSON: str = "{}"

    @field_validator("COMPLIANCE_OWNER_MAP_JSON")
    @classmethod
    def validate_compliance_owners(cls, value: str) -> str:
        try:
            if len(value) > 4096:
                raise ValueError
            owners = json.loads(value)
            if not isinstance(owners, dict) or set(owners) - COMPLIANCE_OWNER_ROLES.keys():
                raise ValueError
            for names in owners.values():
                if not isinstance(names, list) or not 1 <= len(names) <= 8:
                    raise ValueError
                if any(not isinstance(name, str) or not name.strip() or len(name) > 100
                       or any(ord(char) < 32 or ord(char) == 127 for char in name) for name in names):
                    raise ValueError
            return json.dumps({role: [name.strip() for name in names] for role, names in owners.items()}, sort_keys=True)
        except (ValueError, TypeError):
            raise ValueError("Invalid compliance owner configuration") from None

    @model_validator(mode="after")
    def validate_compliance_environment(self):
        if self.COMPLIANCE_ENVIRONMENT not in {"unconfigured", "local", "ci", "staging", "production"}:
            raise ValueError("Invalid compliance assessment environment")
        runtime = os.getenv("AUTHCLAW_ENV", "local").strip().lower()
        expected = {"prod": "production", "stage": "staging", "shared-test": "ci",
                    "test": "local", "testing": "local"}.get(runtime, runtime)
        if self.COMPLIANCE_ENVIRONMENT != "unconfigured" and self.COMPLIANCE_ENVIRONMENT != expected:
            raise ValueError("Compliance assessment environment must match the deployment environment")
        return self

    def compliance_owners(self, role_ids: list[str], *, public: bool = False) -> list[str]:
        owners = {} if public else json.loads(self.COMPLIANCE_OWNER_MAP_JSON)
        return list(dict.fromkeys(name for role in role_ids
                                  for name in owners.get(role, [COMPLIANCE_OWNER_ROLES.get(role, "Unassigned")])))
    
    # Session
    SESSION_SECRET: str = "dev-secret-change-in-production"
    
    # Encryption
    ENVELOPE_KEY: str = "your-256-bit-hex-encoded-key-here"
    KMS_KEY_ID: str = "local-dev-key-id"
    AUTHCLAW_SECRET_PROVIDER: str = "env"
    AUTHCLAW_SECRET_KEY_VERSION: str = "v1"
    VAULT_ADDR: str = ""
    VAULT_SECRET_KEY_PATH: str = ""
    VAULT_SECRET_KEY_FIELD: str = "key"
    AWS_KMS_ENCRYPTED_DATA_KEY: str = ""
    
    class Config:
        env_file = ("../.env.local", ".env.local")
        case_sensitive = True
        extra = "ignore"
        hide_input_in_errors = True


settings = Settings()
