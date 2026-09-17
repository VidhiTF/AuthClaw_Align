"""Exercise the actual agent file service without its destructive legacy conftest."""

import asyncio
import ast
from contextlib import nullcontext
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse
from sqlalchemy import create_engine, text

spec = importlib.util.spec_from_file_location(
    "agent_evidence_access",
    Path(__file__).resolve().parents[2] / "services/agent/services/evidence_access.py",
)
access = importlib.util.module_from_spec(spec)
spec.loader.exec_module(access)


@pytest.fixture
def vault(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "evidence/tenant-1/report.txt"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"tenant one evidence")
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE compliance_evidence (id INTEGER, tenant_id INTEGER, file_path TEXT, hash TEXT, metadata TEXT)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO compliance_evidence VALUES (7, 1, :path, :hash, :metadata)"
            ),
            {
                "path": "/evidence/tenant-1/report.txt",
                "hash": "sha256-" + hashlib.sha256(path.read_bytes()).hexdigest(),
                "metadata": json.dumps(
                    {"retention_class": "retain", "allow_download": True}
                ),
            },
        )
        yield conn, path
    engine.dispose()


@pytest.mark.parametrize(
    "tenant, identifier",
    [(2, "7"), (1, "report.txt"), (1, "../report.txt"), (1, "7 OR 1=1"), (1, "999")],
)
def test_guessed_ids_filenames_and_traversal_are_denied(vault, tenant, identifier):
    conn, _ = vault
    with pytest.raises(HTTPException) as error:
        access.download_file(conn, tenant, identifier)
    assert error.value.status_code == 404


def test_authorized_download_is_a_verified_private_snapshot(vault):
    conn, path = vault
    response = access.download_file(conn, 1, "7")
    path.write_bytes(b"changed after authorization")

    async def consume():
        return b"".join([part async for part in response.body_iterator])

    assert asyncio.run(consume()) == b"tenant one evidence"
    assert response.headers["cache-control"] == "private, no-store"
    assert (
        response.headers["content-disposition"]
        == "attachment; filename*=UTF-8''report.txt"
    )


@pytest.mark.parametrize(
    "key",
    [
        "/evidence/../private",
        "/evidence/tenant-2/report.txt",
        "/evidence/tenant-1/../tenant-2/report.txt",
    ],
)
def test_database_path_cannot_escape_tenant_directory(vault, key):
    conn, _ = vault
    conn.execute(text("UPDATE compliance_evidence SET file_path=:key"), {"key": key})
    with pytest.raises(HTTPException) as error:
        access.download_file(conn, 1, "7")
    assert error.value.status_code == 404


def test_tampered_or_legacy_evidence_fails_closed(vault):
    conn, path = vault
    path.write_bytes(b"tampered")
    with pytest.raises(HTTPException) as error:
        access.download_file(conn, 1, "7")
    assert error.value.status_code == 409
    conn.execute(text("UPDATE compliance_evidence SET metadata=NULL"))
    with pytest.raises(HTTPException) as error:
        access.download_file(conn, 1, "7")
    assert error.value.status_code == 404


@pytest.mark.parametrize(
    "path,method,purpose",
    [
        ("/evidence", "GET", "view"),
        ("/evidence/download/7", "GET", "download"),
        ("/evidence/export/csv", "GET", "export"),
        ("/evidence/7", "DELETE", "delete"),
        ("/compliance/evidence/export/csv", "GET", "export"),
        ("/reports/auditor/csv", "GET", "export"),
    ],
)
def test_actual_agent_middleware_audits_and_fails_closed(
    monkeypatch, path, method, purpose
):
    # Compile the actual middleware, avoiding main's unrelated model/network
    # initializers and the legacy agent conftest's DROP DATABASE side effect.
    source = Path(__file__).resolve().parents[2] / "services/agent/main.py"
    node = next(
        n
        for n in ast.parse(source.read_text(encoding="utf-8")).body
        if getattr(n, "name", "") == "tenant_database_context_middleware"
    )
    node.decorator_list = []
    async def unsigned(request):
        return None

    namespace = {
        "authenticate_control_plane": unsigned,
        "Request": Request,
        "JSONResponse": JSONResponse,
        "HTTPException": HTTPException,
        "_is_public_or_auth_path": lambda p: False,
        "_rbac_enforcement_enabled": lambda: False,
        "_tenant_id_from_request_headers": lambda r: 1,
        "tenant_context": lambda *a, **k: nullcontext(),
        "optional_user_from_request": lambda r: {"sub": "actor-1"},
    }
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    monkeypatch.setitem(sys.modules, "services.evidence_access", access)
    records = []
    monkeypatch.setitem(
        sys.modules,
        "verify_audit",
        SimpleNamespace(create_audit_block=lambda **k: records.append(k) or 1),
    )
    request = Request(
        {
            "type": "http",
            "path": path,
            "method": method,
            "headers": [(b"x-request-id", b"test")],
        }
    )
    delivered = []

    async def endpoint(request):
        delivered.append(True)
        return JSONResponse({"ok": True})

    middleware = namespace["tenant_database_context_middleware"]
    assert asyncio.run(middleware(request, endpoint)).status_code == 200
    assert records[0]["username"] == "actor-1"
    assert records[0]["tenant_id"] == 1
    assert records[0]["query"] == f"evidence:{purpose} {path}"
    delivered.clear()

    def unavailable(**kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setitem(
        sys.modules, "verify_audit", SimpleNamespace(create_audit_block=unavailable)
    )
    assert asyncio.run(middleware(request, endpoint)).status_code == 503
    assert not delivered


def test_control_export_filename_cannot_include_user_input(monkeypatch):
    source = Path(__file__).resolve().parents[2] / "services/agent/main.py"
    node = next(
        n
        for n in ast.parse(source.read_text(encoding="utf-8")).body
        if getattr(n, "name", "") == "export_control_evidence_csv"
    )
    node.decorator_list = []
    namespace = {
        "Optional": __import__("typing").Optional,
        "Header": lambda v: v,
        "Response": JSONResponse,
        "resolve_tenant": lambda *a: 1,
    }
    monkeypatch.setitem(
        sys.modules,
        "services.compliance_evidence_engine",
        SimpleNamespace(
            ComplianceEvidenceEngine=lambda: SimpleNamespace(
                evidence_csv=lambda *a, **k: "data"
            )
        ),
    )
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    response = namespace["export_control_evidence_csv"](
        framework="bad\r\nX-Injected: yes"
    )
    assert (
        response.headers["content-disposition"]
        == "attachment; filename=control_evidence.csv"
    )
