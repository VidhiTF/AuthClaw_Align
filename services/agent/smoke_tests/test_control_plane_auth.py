"""Protocol, tamper, rotation, ASGI body and real Redis replay regressions."""

import ast
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, Mock, patch
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from services import control_plane_auth as auth
from services.tenant_context import tenant_context
from approval_store import ApprovalPersistenceError
from services.quota_service import QuotaExceeded, QuotaUnavailable

SECRET = "test-only-32-byte-signing-secret!!"
KEY = {
    "secret": SECRET,
    "service": "console",
    "audience": "agent",
    "endpoints": ["POST /chat", "GET /chat"],
}
RING = {"active_key_id": "v1", "keys": {"v1": KEY}}


def signed(**changes):
    headers = {
        "x-authclaw-version": "2",
        "x-authclaw-timestamp": "2000000000",
        "x-authclaw-nonce": "a" * 32,
        "x-authclaw-service": "console",
        "x-authclaw-audience": "agent",
        "x-authclaw-key-id": "v1",
        "x-authclaw-tenant-id": "tenant",
        "x-authclaw-user-id": "user",
        "x-authclaw-role": "owner",
        "content-type": "application/json",
    }
    headers.update(changes)
    headers["x-authclaw-signature"] = auth.sign_control_plane_request(
        SECRET, headers, "POST", "/chat", "q=a+b", b'{"a":1}'
    )
    return headers


def signed_mfa(path="/approve/approval-17", body=b"{}", **changes):
    now = changes.pop("now", 2000000000)
    headers = {
        "x-authclaw-version": "3",
        "x-authclaw-timestamp": str(now),
        "x-authclaw-nonce": "b" * 32,
        "x-authclaw-service": "console",
        "x-authclaw-audience": "agent",
        "x-authclaw-key-id": "v1",
        "x-authclaw-tenant-id": "tenant",
        "x-authclaw-user-id": "control-plane-user-17",
        "x-authclaw-role": "owner",
        "x-authclaw-mfa-verified-at": str(now),
        "x-authclaw-mfa-operation": f"POST {path}",
        "x-authclaw-mfa-body-sha256": __import__("hashlib").sha256(body).hexdigest(),
        "x-authclaw-mfa-assertion-id": "c" * 32,
        "content-type": "application/json",
    }
    headers.update(changes)
    headers["x-authclaw-signature"] = auth.sign_control_plane_request(
        SECRET, headers, "POST", path, body=body
    )
    return headers


class ControlPlaneAuthSmokeTests(unittest.TestCase):
    def test_replay_storage_requires_tls_by_default(self):
        auth._replay_store.cache_clear()
        with patch.dict(os.environ, {}, clear=True):
            for url in ("", "redis://localhost:6379"):
                with self.assertRaises(ValueError):
                    auth._replay_store(url)
            store = auth._replay_store("rediss://localhost:6379")
            store.close()
        auth._replay_store.cache_clear()

    def verify(self, headers=None, **kwargs):
        args = dict(
            method="POST",
            path="/chat",
            keyring=RING,
            consume_nonce=lambda *_: True,
            query="q=a+b",
            body=b'{"a":1}',
            now=2000000000,
        )
        args.update(kwargs)
        return auth.verify_control_plane_request(headers or signed(), **args)

    def test_tampering_and_policy_are_rejected(self):
        for name, value in {
            "body": b'{"a":2}',
            "query": "q=a+c",
            "path": "/other",
            "method": "GET",
        }.items():
            with self.subTest(name=name):
                self.assertIsNone(self.verify(**{name: value}))

    def test_v3_fresh_mfa_assertion_is_actor_action_and_body_bound(self):
        path = "/approve/approval-17"
        body = b'{"comment":"approved"}'
        keyring = {"keys": {"v1": {**KEY, "endpoints": ["POST /approve/*"]}}}
        headers = signed_mfa(path=path, body=body)
        principal = auth.verify_control_plane_request(
            headers,
            "POST",
            path,
            keyring,
            lambda *_: True,
            body=body,
            now=2000000000,
        )
        self.assertEqual(principal.user_id, "control-plane-user-17")
        self.assertEqual(principal.mfa_operation, f"POST {path}")
        self.assertEqual(principal.mfa_assertion_id, "c" * 32)

        for name, value in (
            ("x-authclaw-mfa-operation", "POST /approve/other"),
            ("x-authclaw-mfa-body-sha256", "0" * 64),
            ("x-authclaw-mfa-verified-at", "1999999900"),
            ("x-authclaw-mfa-assertion-id", "d" * 32),
        ):
            with self.subTest(name=name):
                tampered = {**headers, name: value}
                self.assertIsNone(auth.verify_control_plane_request(
                    tampered, "POST", path, keyring, lambda *_: True,
                    body=body, now=2000000000,
                ))

        unsigned_mfa = signed(**{
            "x-authclaw-mfa-verified-at": "2000000000",
            "x-authclaw-mfa-operation": f"POST {path}",
            "x-authclaw-mfa-body-sha256": __import__("hashlib").sha256(body).hexdigest(),
            "x-authclaw-mfa-assertion-id": "e" * 32,
        })
        self.assertIsNone(auth.verify_control_plane_request(
            unsigned_mfa, "POST", path, keyring, lambda *_: True,
            body=body, now=2000000000,
        ))

    def test_mfa_assertion_is_single_use_at_middleware_boundary(self):
        store = Mock()
        store.set.side_effect = [True, False]
        self.assertTrue(auth._consume_mfa_assertion(store, "a" * 32))
        self.assertFalse(auth._consume_mfa_assertion(store, "a" * 32))
        store.set.assert_called_with(
            "authclaw:mfa-assertion:v1:" + "a" * 32,
            "1", nx=True, ex=auth.NONCE_TTL_SECONDS,
        )
        for name, value in {
            "tenant-id": "other",
            "user-id": "other",
            "role": "admin",
            "service": "other",
            "audience": "other",
            "key-id": "v2",
            "version": "1",
            "nonce": "b" * 32,
            "timestamp": "2000000001",
        }.items():
            with self.subTest(header=name):
                headers = signed()
                headers["x-authclaw-" + name] = value
                self.assertIsNone(self.verify(headers))
        headers = signed()
        headers["content-type"] = "text/plain"
        self.assertIsNone(self.verify(headers))
        for key in (dict(KEY, endpoints=[]), dict(KEY, service="other"), dict(KEY, secret="short")):
            self.assertIsNone(self.verify(keyring={"keys": {"v1": key}}))

    def test_query_and_role_canonicalization(self):
        self.assertEqual(auth.canonical_query("b=2&a=x+y&a=%C3%A9"), "a=x%20y&a=%C3%A9&b=2")
        self.assertEqual(auth.canonical_query("a"), "a=")
        for query in ("%FF=a", "a=%", "a=1&&b=2"):
            with self.assertRaises(ValueError):
                auth.canonical_query(query)
        self.assertIsNotNone(self.verify(query="q=a%20b"))
        self.assertEqual(self.verify(signed(**{"x-authclaw-role": "Super Admin"})).role, "tenant_administrator")
        self.assertIsNone(self.verify(signed(**{"x-authclaw-role": "root"})))
        with self.assertRaises(ValueError):
            signed(**{"x-authclaw-user-id": "user\nforged"})

    def test_replay_full_window_and_rotation(self):
        consumed = {}
        clock = 1999999940

        def consume(nonce, timestamp):
            self.assertEqual(timestamp, 2000000000)
            if consumed.get(nonce, 0) > clock:
                return False
            consumed[nonce] = clock + auth.NONCE_TTL_SECONDS
            return True

        self.assertIsNotNone(self.verify(consume_nonce=consume, now=clock))
        for clock in (1999999941, 2000000000, 2000000060):
            self.assertIsNone(self.verify(consume_nonce=consume, now=clock))
        for clock in (1999999939, 2000000061):
            self.assertIsNone(self.verify(now=clock))
        new_key = dict(KEY, secret="new-" + SECRET)
        overlap = {"keys": {"v1": KEY, "v2": new_key}}
        for active, secret in (("v1", SECRET), ("v2", new_key["secret"]), ("v1", SECRET)):
            headers = signed(**{"x-authclaw-key-id": active})
            headers["x-authclaw-signature"] = auth.sign_control_plane_request(
                secret, headers, "POST", "/chat", "q=a+b", b'{"a":1}'
            )
            self.assertIsNotNone(self.verify(headers, keyring=overlap))
        self.assertIsNone(self.verify(keyring={"keys": {"v2": new_key}}))
        self.assertIsNone(self.verify(keyring=SECRET))  # No legacy raw-key fallback.
        headers = signed(**{"x-authclaw-key-id": "v2"})
        headers["x-authclaw-signature"] = auth.sign_control_plane_request(
            new_key["secret"], headers, "POST", "/chat", "q=a+b", b'{"a":1}'
        )
        clock = 2000000000
        self.assertIsNone(
            self.verify(headers, keyring=overlap, consume_nonce=consume, now=2000000000)
        )

    @unittest.skipUnless(
        shutil.which("node"), "Node is required for cross-language interoperability"
    )
    def test_real_typescript_signer_interoperates(self):
        root = Path(__file__).resolve().parents[3]
        script = """
import {controlPlaneHeaders} from './src/lib/control-plane-auth.ts';
const cases=[['q=a+b','{"a":1}'],['b=%2F&a=%C3%A9&a=x%20y','unicode: é 😀'],['empty&z=%21%27%28%29%2A',''],['','line\\nbody']];
const ring=JSON.parse(process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET);
console.log(JSON.stringify(['v1','v2','v1'].flatMap(active=>{
ring.active_key_id=active; process.env.AUTHCLAW_INTERNAL_SERVICE_SECRET=JSON.stringify(ring);
return cases.map(([query,body])=>({query,body,headers:Object.fromEntries(Object.entries(
controlPlaneHeaders(new URL('https://agent.invalid/chat'+(query?'?'+query:'')), 'POST', body, 'application/json',
{tenantId:'tenant',userId:'user',role:'owner'})).map(([k,v])=>[k.toLowerCase(),v]))}));})));
"""
        overlap = {**RING, "keys": {"v1": KEY, "v2": dict(KEY, secret="new-" + SECRET)}}
        result = subprocess.run(
            ["node", "--experimental-strip-types", "--input-type=module", "-e", script],
            cwd=root / "console",
            env={**os.environ, "AUTHCLAW_INTERNAL_SERVICE_SECRET": json.dumps(overlap)},
            encoding="utf-8",
            capture_output=True,
            check=True,
        )
        for case in json.loads(result.stdout):
            headers = {**case["headers"], "content-type": "application/json"}
            self.assertIsNotNone(
                self.verify(
                    headers,
                    keyring=overlap,
                    query=case["query"],
                    body=case["body"].encode(),
                    now=time.time(),
                )
            )

    def test_middleware_preserves_body_and_verifies_once(self):
        app = FastAPI()
        consumed = set()

        def consume(store, nonce, timestamp):
            if nonce in consumed:
                return False
            consumed.add(nonce)
            return True

        @app.middleware("http")
        async def boundary(request, call_next):
            try:
                request.state.principal = await auth.authenticate_control_plane(request)
            except HTTPException as error:
                return JSONResponse({"detail": error.detail}, status_code=error.status_code)
            return await call_next(request)

        @app.post("/chat")
        async def echo(request: Request):
            return {
                "body": (await request.body()).decode(),
                "actor": request.state.principal.user_id,
            }

        headers = signed(**{"x-authclaw-timestamp": str(int(time.time()))})
        with patch.dict(
            os.environ, {"AUTHCLAW_INTERNAL_SERVICE_SECRET": json.dumps(RING)}
        ), patch.object(auth, "_replay_store"), patch.object(
            auth, "_consume_nonce", side_effect=consume
        ), TestClient(
            app
        ) as client:
            response = client.post("/chat?q=a+b", content=b'{"a":1}', headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["body"], '{"a":1}')
            self.assertEqual(
                client.post("/chat?q=a+b", content=b'{"a":1}', headers=headers).status_code, 401
            )
            self.assertEqual(
                client.post(
                    "/chat?q=a+b",
                    content=b'{"a":1}',
                    headers=list(headers.items()) + [("x-authclaw-nonce", "b" * 32)],
                ).status_code,
                401,
            )
            self.assertEqual(
                client.post("/chat", headers={"x-authclaw-version": "2"}).status_code, 401
            )
            self.assertEqual(
                client.post(
                    "/chat", content=b"x" * (auth.MAX_BODY_BYTES + 1), headers=headers
                ).status_code,
                413,
            )
            self.assertEqual(
                client.post(
                    "/chat?q=a+b",
                    content=b'{"a":1}',
                    headers=list(headers.items()) + [("content-type", "text/plain")],
                ).status_code,
                401,
            )
            with patch.object(auth, "_consume_nonce", side_effect=RuntimeError("outage")):
                self.assertEqual(
                    client.post("/chat?q=a+b", content=b'{"a":1}', headers=headers).status_code, 503
                )

    def test_real_middleware_order_authenticates_before_rbac(self):
        app = FastAPI()
        names = {
            "optional_user_from_request",
            "_tenant_id_from_request_headers",
            "tenant_database_context_middleware",
            "production_rbac_enforcement_middleware",
            "AgentExecutionRequest",
        }
        tree = ast.parse((Path(__file__).resolve().parents[1] / "main.py").read_text())

        def tenant_lookup(request):
            import asyncio

            with self.assertRaises(RuntimeError):
                asyncio.get_running_loop()  # Blocking DB lookup must run off the event loop.
            return actual_lookup(request)

        namespace = {
            "app": app,
            "Request": Request,
            "Optional": Optional,
            "BaseModel": BaseModel,
            "Field": Field,
            "text": lambda sql: sql,
            "HTTPException": HTTPException,
            "JSONResponse": JSONResponse,
            "uuid": uuid,
            "tenant_context": tenant_context,
            "authenticate_control_plane": auth.authenticate_control_plane,
            "_tenant_id_from_request_headers": tenant_lookup,
            "_is_public_or_auth_path": lambda _: False,
            "_rbac_enforcement_enabled": lambda: True,
            "_tenant_tier_limit": lambda _: 100,
            "admit": lambda *args, **kwargs: None,
            "QuotaExceeded": QuotaExceeded,
            "QuotaUnavailable": QuotaUnavailable,
            "decode_jwt": lambda _: None,
            "reconcile_due_approval_executions": Mock(return_value=0),
            "ApprovalPersistenceError": ApprovalPersistenceError,
            "run_in_threadpool": run_in_threadpool,
            "datetime": datetime,
            "timezone": timezone,
        }
        # Preserve source declaration/decorator order, not a hand-built substitute stack.
        exec(
            compile(
                ast.Module(
                    body=[n for n in tree.body if getattr(n, "name", "") in names], type_ignores=[]
                ),
                "main.py",
                "exec",
            ),
            namespace,
        )
        actual_lookup = namespace["_tenant_id_from_request_headers"]
        namespace["_tenant_id_from_request_headers"] = tenant_lookup
        tenant_rows = {"disabled": "disabled"}
        engine = MagicMock()

        def upsert(sql, params):
            tenant_rows[params["control_plane_id"]] = "active"
            return Mock(scalar_one=lambda: 42)

        engine.begin.return_value.__enter__.return_value.execute.side_effect = upsert

        @app.post("/chat")
        async def echo(request: Request):
            return {
                "actor": namespace["optional_user_from_request"](request)["sub"],
                "body": (await request.body()).decode(),
            }

        @app.post("/api/v1/agent/executions")
        async def execute(request: Request):
            from services.execution_auth import authorize_agent_operation

            try:
                authorize_agent_operation(
                    namespace["optional_user_from_request"](request),
                    namespace["AgentExecutionRequest"]
                    .model_validate_json(await request.body())
                    .operation.strip()
                    .lower(),
                    42,
                )
            except PermissionError as exc:
                raise HTTPException(status_code=403, detail=str(exc)) from exc
            return {"ok": True}

        with patch.dict(sys.modules, {"database": Mock(engine=engine)}), patch.dict(
            os.environ, {"AUTHCLAW_INTERNAL_SERVICE_SECRET": json.dumps(RING)}
        ), patch.object(auth, "_replay_store"), patch.object(
            auth, "_consume_nonce", return_value=True
        ) as consume, TestClient(
            app, raise_server_exceptions=False
        ) as client:
            headers = signed(**{"x-authclaw-timestamp": str(int(time.time()))})
            response = client.post("/chat?q=a+b", content=b'{"a":1}', headers=headers)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json(), {"actor": "user", "body": '{"a":1}'})
            self.assertEqual(tenant_rows, {"disabled": "disabled", "tenant": "active"})
            self.assertEqual(consume.call_count, 1)
            headers["x-authclaw-role"] = "admin"
            self.assertEqual(
                client.post("/chat?q=a+b", content=b'{"a":1}', headers=headers).status_code, 401
            )
            self.assertEqual(consume.call_count, 1)
            self.assertEqual(client.post("/chat").status_code, 401)
            headers = signed(**{"x-authclaw-timestamp": str(int(time.time()))})
            for error, status in (
                (QuotaExceeded("tenant"), 429),
                (QuotaUnavailable("offline"), 503),
            ):
                namespace["admit"] = Mock(side_effect=error)
                self.assertEqual(
                    client.post("/chat?q=a+b", content=b'{"a":1}', headers=headers).status_code,
                    status,
                )
            namespace["admit"] = lambda *args, **kwargs: None
            forbidden = dict(
                KEY, endpoints=["POST /policies/test", "POST /api/v1/agent/executions"]
            )
            with patch.dict(
                os.environ,
                {"AUTHCLAW_INTERNAL_SERVICE_SECRET": json.dumps({"keys": {"v1": forbidden}})},
            ):
                for tenant in ("unknown", "disabled"):
                    for role in ("viewer",):
                        headers.update({"x-authclaw-tenant-id": tenant, "x-authclaw-role": role})
                        for path, body in (
                            ("/policies/test", b""),
                            ("/api/v1/agent/executions", b'{"operation":"rag"}'),
                            ("/api/v1/agent/executions", b'{"operation":" REMEDIATION_PLAN "}'),
                        ):
                            headers["x-authclaw-signature"] = auth.sign_control_plane_request(
                                SECRET, headers, "POST", path, body=body
                            )
                            before, calls = dict(tenant_rows), engine.begin.call_count
                            self.assertEqual(
                                client.post(path, content=body, headers=headers).status_code, 403
                            )
                            self.assertEqual(tenant_rows, before)
                            self.assertEqual(engine.begin.call_count, calls)
                for body, status in (
                    (b'{"operation":"unknown"}', 422),
                    (b'{"operation":null}', 422),
                    (b"{", 422),
                    (b"{}", 200),
                    (b'{"operation":" CHAT "}', 200),
                ):
                    headers["x-authclaw-signature"] = auth.sign_control_plane_request(
                        SECRET, headers, "POST", path, body=body
                    )
                    calls = engine.begin.call_count
                    self.assertEqual(
                        client.post(path, content=body, headers=headers).status_code, status
                    )
                    self.assertEqual(engine.begin.call_count, calls + (status == 200))

    @unittest.skipUnless(os.getenv("ENT018_REDIS_URL"), "Dedicated Redis integration URL required")
    def test_real_redis_atomic_replay_and_recovery(self):
        import redis

        store = redis.Redis.from_url(os.environ["ENT018_REDIS_URL"])
        # Only the explicitly disposable test Redis is used; no production cache mutation.
        self.assertIn("localhost", os.environ["ENT018_REDIS_URL"])
        self.assertEqual(store.config_get("maxmemory-policy")["maxmemory-policy"], "noeviction")
        run_id = store.info("server")["run_id"]
        generation = store.info("replication")["master_replid"]
        gate = f"authclaw:service:v2:startup:{run_id}:{generation}"
        store.delete(gate)
        timestamp = int(store.time()[0])
        with self.assertRaises(RuntimeError):
            auth._consume_nonce(store, "test", timestamp)
        store.set(gate, int(store.time()[0]) - 122)
        nonce = os.urandom(16).hex()
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(
                pool.map(lambda _: auth._consume_nonce(store, nonce, timestamp), range(16))
            )
        self.assertEqual(sum(results), 1)
        self.assertGreaterEqual(
            store.ttl("authclaw:service:v2:" + nonce), 120 - math.ceil(time.monotonic() - started)
        )
        self.assertFalse(auth._consume_nonce(store, nonce, timestamp))
        # An agent with a skewed wall clock cannot extend Redis's acceptance window.
        future = int(store.time()[0]) + 65
        headers = signed(
            **{"x-authclaw-timestamp": str(future), "x-authclaw-nonce": os.urandom(16).hex()}
        )
        self.assertIsNone(
            self.verify(
                headers, now=future, consume_nonce=lambda *args: auth._consume_nonce(store, *args)
            )
        )
        # Promotion must fence even a process whose old startup gate was ready.
        store.execute_command("REPLICAOF", "127.0.0.1", "1")
        store.execute_command("REPLICAOF", "NO", "ONE")
        self.assertEqual(store.info("server")["run_id"], run_id)
        self.assertNotEqual(store.info("replication")["master_replid"], generation)
        self.assertTrue(store.exists(gate))
        with self.assertRaises(RuntimeError):
            auth._consume_nonce(store, os.urandom(16).hex(), timestamp)


if __name__ == "__main__":
    unittest.main()
