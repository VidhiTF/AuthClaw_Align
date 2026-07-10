"""Configuration settings for AuthClaw Backend"""
from typing import List
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings from environment variables"""
    
    # API
    API_TITLE: str = "AuthClaw API"
    API_VERSION: str = "0.1.0"
    DEBUG: bool = True
    
    # Database
    DATABASE_URL: str = "postgresql://authclaw:authclaw@localhost:5432/authclaw"
    
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


settings = Settings()
