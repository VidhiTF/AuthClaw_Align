"""Reproducible three-process core/provider-stub load proof; not an HTTP benchmark."""
import concurrent.futures
import json
import os
import sys
import time
import uuid
import multiprocessing
import socket
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def configure(url, dimension):
    from services import quota_service as quota
    os.environ.update({
        "AUTHCLAW_ENV": "test", "REDIS_URL": url,
        "AUTHCLAW_RATE_LIMIT_ENABLED": "true", "AUTHCLAW_ALLOW_MEMORY_RATE_LIMIT": "false",
        **{name: "10000" for name in quota.LIMITS.values()},
        quota.LIMITS[dimension]: "17",
    })


def replica(work):
    from services import quota_service as quota
    url, tenant, dimension, requests = work
    configure(url, dimension)
    results = {"ingress_admissions": 0, "rejections": 0, "unavailable": 0,
               "provider_invocations": 0, "latencies_ms": []}
    def deterministic_provider_stub():
        results["provider_invocations"] += 1
        return "fixed-provider-response"
    for _ in range(requests):
        started = time.perf_counter()
        try:
            quota.admit(tenant, "verified-user", "verified-key")
            results["ingress_admissions"] += 1
            quota.admit(tenant, provider_model="deterministic/stub")
            assert deterministic_provider_stub() == "fixed-provider-response"
        except quota.QuotaExceeded:
            results["rejections"] += 1
        except quota.QuotaUnavailable:
            results["unavailable"] += 1
        results["latencies_ms"].append((time.perf_counter() - started) * 1000)
    return results


def run(url):
    from services import quota_service as quota
    report = {"replicas": 3, "requests_per_replica": 100, "provider": "deterministic Python callable", "stages": {}}
    for dimension in quota.LIMITS:
        tenant = "load-" + uuid.uuid4().hex
        with concurrent.futures.ProcessPoolExecutor(max_workers=3) as pool:
            replicas = list(pool.map(replica, [(url, tenant, dimension, 100)] * 3))
        combined = {key: sum(item[key] for item in replicas) for key in replicas[0] if key != "latencies_ms"}
        latencies = sorted(value for item in replicas for value in item["latencies_ms"])
        combined.update(offered=300, limit=17, p50_ms=round(latencies[149], 3), p95_ms=round(latencies[284], 3), max_ms=round(latencies[-1], 3))
        assert combined["provider_invocations"] == 17, combined
        assert combined["rejections"] == 283, combined
        assert combined["unavailable"] == 0, combined
        report["stages"][dimension] = combined
    outage_tenant = "outage-" + uuid.uuid4().hex
    # A refused local socket is real dependency failure, without disrupting other tests.
    outage = replica(("redis://127.0.0.1:1/0", outage_tenant, "tenant", 10))
    assert outage["unavailable"] == 10 and outage["provider_invocations"] == 0, outage
    recovery = replica((url, outage_tenant, "tenant", 10))
    assert recovery["provider_invocations"] == 10 and recovery["unavailable"] == 0, recovery
    report["outage"] = {key: value for key, value in outage.items() if key != "latencies_ms"}
    report["recovery"] = {key: value for key, value in recovery.items() if key != "latencies_ms"}
    return report


def http_replica(url, dimension, tenant, ready):
    import uvicorn
    from fastapi import FastAPI
    from services import quota_service as quota
    from services.tenant_context import get_current_tenant_id
    from test_quota_http_boundary import boundary_namespace
    configure(url, dimension)
    try:
        quota.check_available()
    except quota.QuotaUnavailable:
        pass  # The outage fixture deliberately serves protected 503 responses.
    ns = boundary_namespace()
    ns["record_unavailable"] = quota.record_unavailable
    ns["resolve_tenant"] = lambda **credentials: tenant
    ns["_tenant_tier_limit"] = lambda tenant_id: 10000
    app = FastAPI()
    app.middleware("http")(ns["tenant_database_context_middleware"])
    app.add_exception_handler(quota.QuotaExceeded, ns["quota_exceeded_response"])
    app.add_exception_handler(quota.QuotaUnavailable, ns["quota_unavailable_response"])
    counts = {"downstream": 0, "provider": 0}
    @app.post("/provider")
    async def provider():
        counts["downstream"] += 1
        quota.admit(get_current_tenant_id(), provider_model="deterministic/stub")
        counts["provider"] += 1
        return {"response": "fixed-provider-response"}
    @app.get("/health")
    async def health():
        return dict(counts)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    for _ in range(1000):
        if server.started:
            break
        time.sleep(0.01)
    if not server.started:
        raise RuntimeError("HTTP fixture failed to start")
    ready.put((os.getpid(), listener.getsockname()[1]))
    thread.join(120)


def http_stage(url, dimension, offered=300, tenant=None):
    import httpx
    tenant = tenant or "http-load-" + uuid.uuid4().hex
    ready = multiprocessing.Queue()
    processes = [multiprocessing.Process(target=http_replica, args=(url, dimension, tenant, ready)) for _ in range(3)]
    try:
        for process in processes:
            process.start()
        replicas = [ready.get(timeout=30) for _ in processes]
        ports = [port for _, port in replicas]
        with httpx.Client(timeout=10) as client:
            def request(index):
                start = time.perf_counter()
                response = client.post(f"http://127.0.0.1:{ports[index % 3]}/provider", headers={"X-API-Key": "verified-fixture-key"})
                return response.status_code, (time.perf_counter() - start) * 1000
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                responses = list(pool.map(request, range(offered)))
            counts = [client.get(f"http://127.0.0.1:{port}/health").json() for port in ports]
        latencies = sorted(latency for _, latency in responses)
        return {"replica_pids": [pid for pid, _ in replicas], "offered": offered,
                "http_statuses": {str(status): sum(code == status for code, _ in responses) for status in {code for code, _ in responses}},
                "downstream_invocations": sum(count["downstream"] for count in counts),
                "provider_invocations": sum(count["provider"] for count in counts),
                "p50_ms": round(latencies[len(latencies) // 2], 3),
                "p95_ms": round(latencies[int(len(latencies) * .95) - 1], 3),
                "max_ms": round(latencies[-1], 3)}
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()


def run_http(url):
    from services import quota_service as quota
    report = {"fixture": "actual extracted main middleware, verified-auth and plan seams, deterministic provider callable", "stages": {}}
    for dimension in quota.LIMITS:
        stage = http_stage(url, dimension)
        assert set(stage["http_statuses"]) <= {"200", "429", "503"}, stage
        assert 0 < stage["http_statuses"].get("200", 0) <= 17, stage
        assert stage["http_statuses"].get("429", 0) > 0, stage
        assert stage["provider_invocations"] == stage["http_statuses"]["200"], stage
        if dimension != "expensive_model":
            assert stage["provider_invocations"] <= stage["downstream_invocations"] <= 17, stage
        report["stages"][dimension] = stage
    tenant = "http-outage-" + uuid.uuid4().hex
    outage = http_stage("redis://127.0.0.1:1/0", "tenant", 30, tenant)
    assert outage["http_statuses"] == {"503": 30} and outage["downstream_invocations"] == 0, outage
    recovery = http_stage(url, "tenant", 30, tenant)
    assert recovery["http_statuses"] == {"200": 17, "429": 13} and recovery["provider_invocations"] == 17, recovery
    report.update(outage=outage, recovery=recovery)
    return report


if __name__ == "__main__":
    runner = run_http if "--http" in sys.argv else run
    print(json.dumps(runner(os.environ["QUOTA_TEST_REDIS_URL"]), indent=2))
