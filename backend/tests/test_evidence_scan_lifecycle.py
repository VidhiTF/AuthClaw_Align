"""Real HTTP pooling, bounded concurrency, failure isolation and timing evidence."""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
import requests

from app.orchestrator import connectors, graph


@pytest.fixture
def analyzer(monkeypatch):
    stats = SimpleNamespace(active=0, peak=0, ports=set(), requests=[], lock=threading.Lock())

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            with stats.lock:
                stats.active += 1
                stats.peak = max(stats.peak, stats.active)
                stats.ports.add(self.client_address[1])
                stats.requests.append((payload, self.headers.get("Cookie")))
            time.sleep(0.05)
            text = payload["text"]
            body = b"invalid-json" if text == "invalid" else json.dumps(
                [] if text == "clean" else [{"entity_type": "EMAIL_ADDRESS"}]
            ).encode()
            with stats.lock:
                stats.active -= 1
            self.send_response(503 if text == "unavailable" else 200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie", "scan=private")
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    monkeypatch.setenv("PRESIDIO_URL", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    try:
        yield stats
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def prepare(monkeypatch, texts):
    docs = [{"object_key": f"tenant-a/{i}", "file_name": str(i)} for i in range(len(texts))]
    monkeypatch.setattr(connectors.DocumentScanner, "list_documents", lambda self, tenant: docs)
    monkeypatch.setattr(connectors.DocumentScanner, "fetch_and_extract_text", lambda self, key, name: texts[int(name)])
    monkeypatch.setenv("AWS_ENABLED", "false")
    return docs


def test_real_http_parallel_pool_benchmark(monkeypatch, analyzer):
    docs = prepare(monkeypatch, ["sensitive"] * 12)
    caller = threading.get_ident()
    stored = []

    def store(*args):
        assert threading.get_ident() == caller
        stored.append(args[4])

    state = dict(tenant_id="a", workflow_id="wf", framework="SOC2", _store_evidence=store)
    times, results = {}, {}
    for workers in (1, 4):
        monkeypatch.setenv("EVIDENCE_SCAN_WORKERS", str(workers))
        analyzer.peak = 0
        analyzer.ports.clear()
        stored.clear()
        start = time.perf_counter()
        results[workers] = graph.gather_evidence(state)["findings"]
        times[workers] = time.perf_counter() - start
        assert analyzer.peak == workers
        assert len(analyzer.ports) == workers  # Twelve requests reuse 1 or 4 TCP connections.
        assert stored == [doc["object_key"] for doc in docs]
    assert results[1] == results[4]
    assert all(cookie is None for _, cookie in analyzer.requests)
    assert times[4] < times[1] * 0.8
    print(f"12 documents, 50ms analyzer delay: serial={times[1]:.3f}s parallel={times[4]:.3f}s speedup={times[1]/times[4]:.2f}x")


def test_failure_isolation_and_sessions_closed(monkeypatch, analyzer):
    prepare(monkeypatch, ["sensitive", "unavailable", "invalid", "", "clean", "sensitive"])
    closed = []
    original = requests.Session.close

    def close(session):
        closed.append(session)
        original(session)

    monkeypatch.setattr(requests.Session, "close", close)
    monkeypatch.setenv("EVIDENCE_SCAN_WORKERS", "2")
    result = graph.gather_evidence(dict(tenant_id="a", workflow_id="wf", framework="SOC2"))
    assert [item["control"] for item in result["findings"]] == ["tenant-a/0", "tenant-a/4", "tenant-a/5"]
    assert [item["status"] for item in result["findings"]] == ["non_compliant", "compliant", "non_compliant"]
    assert len(closed) == 2


def test_timeout_keeps_later_documents_and_closes_sessions(monkeypatch):
    prepare(monkeypatch, ["sensitive"] * 4)
    calls = []
    closed = []
    original_close = requests.Session.close

    def close(session):
        closed.append(session)
        original_close(session)

    def post(session, url, **kwargs):
        assert kwargs["timeout"] == 10
        calls.append(url)
        raise requests.Timeout("unavailable")

    monkeypatch.setattr(requests.Session, "post", post)
    monkeypatch.setattr(requests.Session, "close", close)
    monkeypatch.setenv("EVIDENCE_SCAN_WORKERS", "2")
    result = graph.gather_evidence(dict(tenant_id="a", workflow_id="wf", framework="SOC2"))
    assert result["findings"] == []
    assert len(calls) == 4
    assert len(closed) == 2


@pytest.mark.parametrize("workers", ["0", "17", "invalid"])
def test_invalid_worker_limit_is_rejected(monkeypatch, workers):
    monkeypatch.setenv("EVIDENCE_SCAN_WORKERS", workers)
    with pytest.raises(ValueError):
        graph.gather_evidence(dict(tenant_id="a", workflow_id="wf", framework="SOC2"))


def test_s3_body_closes_on_read_failure(monkeypatch):
    monkeypatch.setenv("AWS_ENABLED", "false")
    scanner = connectors.DocumentScanner()
    closed = []

    class Body:
        def read(self):
            raise OSError("read interrupted")

        def close(self):
            closed.append(True)

    scanner.s3_client = SimpleNamespace(get_object=lambda **kwargs: {"Body": Body()})
    with pytest.raises(OSError):
        scanner.fetch_and_extract_text("tenant-a/file", "file.txt")
    assert closed == [True]


def test_simultaneous_workflows_keep_tenant_results_separate(monkeypatch, analyzer):
    prepare(monkeypatch, ["sensitive"] * 3)
    monkeypatch.setattr(connectors.DocumentScanner, "list_documents", lambda self, tenant: [
        {"object_key": f"tenant-{tenant}/{i}", "file_name": str(i)} for i in range(3)
    ])
    monkeypatch.setenv("EVIDENCE_SCAN_WORKERS", "2")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(graph.gather_evidence, [
            dict(tenant_id=tenant, workflow_id=tenant, framework="SOC2") for tenant in ("a", "b")
        ]))
    for tenant, result in zip(("a", "b"), results):
        assert [item["control"] for item in result["findings"]] == [f"tenant-{tenant}/{i}" for i in range(3)]


def test_early_iterator_close_bounds_work_and_closes_sessions(monkeypatch):
    calls, closed = [], []
    original_close = requests.Session.close

    def close(session):
        closed.append(session)
        original_close(session)

    monkeypatch.setattr(requests.Session, "close", close)
    scanner = SimpleNamespace(fetch_and_extract_text=lambda key, name: calls.append(key) or "")
    docs = [{"object_key": str(i), "file_name": str(i)} for i in range(100)]
    scans = graph._scan_documents(scanner, docs, "http://unused", 2)
    assert next(scans) == (docs[0], None)
    scans.close()
    assert len(calls) <= 2
    assert len(closed) == 2


def test_listing_failure_closes_scanner_client(monkeypatch):
    closed = []
    scanner = SimpleNamespace(s3_client=SimpleNamespace(close=lambda: closed.append(True)))

    def fail(tenant):
        raise OSError("listing failed")

    scanner.list_documents = fail
    monkeypatch.setattr(connectors, "DocumentScanner", lambda: scanner)
    result = graph.gather_evidence(dict(tenant_id="a", workflow_id="wf", framework="SOC2"))
    assert result["findings"] == []
    assert closed == [True]
