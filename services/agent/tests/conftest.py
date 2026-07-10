import os
import uuid
import hashlib
import base64
import pytest
from sqlalchemy import create_engine, text

# 1. Generate API key and set environment variables first!
test_api_key = f"test-key-{uuid.uuid4().hex[:12]}"
os.environ["AUTHCLAW_TEST_API_KEY"] = test_api_key
os.environ["DATABASE_URL"] = "postgresql://postgres:vidhi@localhost:5432/authclaw_test"
os.environ["GOOGLE_API_KEY"] = "dummy"

# 2. Re-create the database authclaw_test
postgres_url = "postgresql://postgres:vidhi@localhost:5432/postgres"
postgres_engine = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
with postgres_engine.connect() as conn:
    conn.execute(text("DROP DATABASE IF EXISTS authclaw_test"))
    conn.execute(text("CREATE DATABASE authclaw_test"))

# 3. Run database migrations to populate tables
from database.migrations import run_startup_migrations
run_startup_migrations()

# 4. Create a dynamic test tenant and dynamic API key
from main import hash_password
tenant_name = f"test-tenant-{uuid.uuid4().hex[:12]}"
tenant_domain = f"{tenant_name}.com"
tenant_email = f"admin@{tenant_domain}"
tenant_password = "TestPassword123"
password_hash = hash_password(tenant_password)

email_token = str(uuid.uuid4())
domain_token = f"authclaw-domain-verification={uuid.uuid4().hex[:16]}"
totp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')

from database import engine
with engine.connect() as conn:
    res = conn.execute(
        text("""
        INSERT INTO tenants (name, domain, email, password_hash, email_verified, email_verification_token, domain_verified, domain_verification_token, totp_secret)
        VALUES (:name, :domain, :email, :password, true, :et, true, :dt, :totp)
        RETURNING id
        """),
        {
            "name": tenant_name,
            "domain": tenant_domain,
            "email": tenant_email,
            "password": password_hash,
            "et": email_token,
            "dt": domain_token,
            "totp": totp_secret
        }
    )
    tenant_id = res.fetchone()[0]
    conn.commit()

# Hash the generated key and save it to the DB
key_hash = hashlib.sha256(test_api_key.encode('utf-8')).hexdigest()
with engine.connect() as conn:
    conn.execute(
        text("INSERT INTO tenant_api_keys (tenant_id, name, key_hash) VALUES (:tid, 'Test Key', :hash)"),
        {"tid": tenant_id, "hash": key_hash}
    )
    conn.execute(
        text("""
        INSERT INTO policies (name, type, rules, enabled, tenant_id)
        VALUES 
        ('GDPR Policy', 'GDPR', '{"blocked_keywords": ["passport", "ssn", "social security number"], "pii_redaction": true}', true, :tid),
        ('SOC2 Policy', 'SOC2', '{"blocked_keywords": ["credit card", "bank routing", "pin number"], "pii_redaction": true}', true, :tid),
        ('HIPAA Policy', 'HIPAA', '{"blocked_keywords": ["medical record", "health history", "diagnoses", "diagnosis"], "pii_redaction": true}', true, :tid)
        """),
        {"tid": tenant_id}
    )
    conn.commit()


# Monkey patch dns.resolver
import dns.resolver

class DummyTxtRecord:
    def __init__(self, token):
        self.strings = [token.encode('utf-8')]

original_resolve = dns.resolver.Resolver.resolve
def mock_resolve(self, qname, rdtype='A', *args, **kwargs):
    if rdtype == 'TXT':
        from database import engine
        from sqlalchemy import text
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT domain_verification_token FROM tenants WHERE domain = :d"),
                {"d": str(qname)}
            ).fetchone()
            if row:
                return [DummyTxtRecord(row[0])]
    try:
        return original_resolve(self, qname, rdtype, *args, **kwargs)
    except Exception:
        raise dns.resolver.NXDOMAIN(qnames=[qname])

dns.resolver.Resolver.resolve = mock_resolve


@pytest.fixture(autouse=True)
def isolate_runtime_test_flags(monkeypatch):
    # Local manual runs may export this for usability. Tests should start from
    # production-like MFA behavior unless an individual test opts into bypass.
    monkeypatch.delenv("DISABLE_MFA_FOR_TESTING", raising=False)


class GatewayTestProvider:
    model_name = "pytest-gateway-model"
    api_url = "pytest://gateway-provider"

    def generate(self, prompt: str, **kwargs) -> str:
        if "P987654321" in prompt or "[REDACTED]" in prompt:
            return "The requested sensitive value is [REDACTED]."
        return "Gateway test provider response."


@pytest.fixture(autouse=True)
def use_deterministic_gateway_provider(monkeypatch, request):
    if request.node.fspath.basename in {"test_provider_router.py", "test_phase9_secrets_management.py"}:
        return

    from services.provider_router import ProviderSelection, ProviderRouter

    def select_test_provider(self):
        return ProviderSelection(
            route_id="pytest-route",
            provider_name="pytest",
            model="pytest-gateway-model",
            endpoint="pytest://gateway-provider",
            provider=GatewayTestProvider(),
            source="pytest_fixture",
        )

    monkeypatch.setattr(ProviderRouter, "select", select_test_provider)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    yield
    # Dispose of engines to prevent connection pool block during drop database
    from database import engine
    engine.dispose()
    
    # Drop database
    postgres_url = "postgresql://postgres:vidhi@localhost:5432/postgres"
    postgres_engine = create_engine(postgres_url, isolation_level="AUTOCOMMIT")
    with postgres_engine.connect() as conn:
        conn.execute(text("DROP DATABASE IF EXISTS authclaw_test"))
