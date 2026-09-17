"""Run unchanged quota rules through Prometheus/Alertmanager to a local receiver."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def serve(work):
    counters = {"rejected": 0.0, "decisions": 0.0, "updated": time.monotonic()}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            phase = (work / "phase").read_text().strip()
            with lock:
                now = time.monotonic()
                elapsed = now - counters["updated"]
                counters["decisions"] += elapsed * 10
                counters["rejected"] += elapsed * (5 if phase == "failure" else 0)
                counters["updated"] = now
                body = (
                    f"authclaw_quota_available {int(phase != 'failure')}\n"
                    f"authclaw_quota_rejected_total {counters['rejected']}\n"
                    f"authclaw_quota_decisions_total {counters['decisions']}\n"
                ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            event = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            with lock, (work / "notifications.jsonl").open("a") as output:
                output.write(json.dumps({"received_at": time.time(), "payload": event}) + "\n")
            self.send_response(200)
            self.end_headers()

    ThreadingHTTPServer(("0.0.0.0", 8091), Handler).serve_forever()


def rehearse(work):
    root = Path(__file__).resolve().parents[1]
    work.mkdir(parents=True, exist_ok=True)
    suffix = str(int(time.time()))
    network = "quota-alert-" + suffix
    exporter, manager, prometheus = [network + item for item in ("-receiver", "-manager", "-prometheus")]
    containers = []
    network_created = False

    def docker(*args):
        result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=240)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout.strip()

    (work / "phase").write_text("failure")
    (work / "notifications.jsonl").write_text("")
    (work / "alertmanager.yml").write_text(f"""route:
  receiver: approved-local-quota-test
  group_by: [alertname]
  group_wait: 1s
  group_interval: 5s
  repeat_interval: 1h
receivers:
  - name: approved-local-quota-test
    webhook_configs:
      - url: http://{exporter}:8091/alerts
        send_resolved: true
""")
    (work / "prometheus.yml").write_text(f"""global:
  scrape_interval: 30s
  scrape_timeout: 25s
  evaluation_interval: 2s
rule_files:
  - /rules/quota-alerts.yml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['{manager}:9093']
scrape_configs:
  - job_name: quota-rehearsal
    static_configs:
      - targets: ['{exporter}:8091']
""")
    rule_mount = f"{root / 'infra' / 'observability'}:/rules:ro"
    try:
        rule_result = docker("run", "--rm", "--entrypoint", "/bin/promtool", "-v", rule_mount,
                             "prom/prometheus:v3.5.1", "test", "rules", "/rules/quota-alerts.test.yml")
        (work / "promtool.txt").write_text(rule_result)
        print(rule_result, flush=True)
        docker("network", "create", "--internal", network)
        network_created = True
        docker("run", "-d", "--name", exporter, "--network", network,
               "-v", f"{root / 'scripts' / 'quota_alert_rehearsal.py'}:/rehearsal.py:ro",
               "-v", f"{work}:/evidence", "python:3.12-alpine", "python", "/rehearsal.py", "--serve", "--work", "/evidence")
        containers.append(exporter)
        docker("run", "-d", "--name", manager, "--network", network,
               "-v", f"{work / 'alertmanager.yml'}:/etc/alertmanager/alertmanager.yml:ro",
               "prom/alertmanager:v0.28.1", "--config.file=/etc/alertmanager/alertmanager.yml", "--cluster.listen-address=")
        containers.append(manager)
        docker("run", "-d", "--name", prometheus, "--network", network,
               "-v", f"{work / 'prometheus.yml'}:/etc/prometheus/prometheus.yml:ro", "-v", rule_mount,
               "prom/prometheus:v3.5.1", "--config.file=/etc/prometheus/prometheus.yml")
        containers.append(prometheus)
        print("Prometheus, Alertmanager and local receiver started; awaiting production alert durations", flush=True)
        expected = {"QuotaLimiterUnavailable", "QuotaSustainedRejections"}
        observed = {"firing": set(), "resolved": set()}
        deadline = time.monotonic() + 900
        recovered = False
        recovered_at = float("inf")
        while time.monotonic() < deadline:
            for line in (work / "notifications.jsonl").read_text().splitlines():
                record = json.loads(line)
                event = record["payload"]
                if event["receiver"] != "approved-local-quota-test":
                    raise AssertionError("Unexpected notification receiver")
                for alert in event["alerts"]:
                    if alert["status"] == "resolved" and record["received_at"] < recovered_at:
                        continue
                    observed[alert["status"]].add(alert["labels"]["alertname"])
            if expected <= observed["firing"] and not recovered:
                print("Both alerts delivered as firing; restoring healthy metrics", flush=True)
                recovered_at = time.time()
                (work / "phase").write_text("healthy")
                recovered = True
            if expected <= observed["resolved"]:
                break
            time.sleep(2)
        if not all(expected <= observed[status] for status in observed):
            raise AssertionError(f"Missing alert transitions: {observed}")
        summary = {"result": "passed", "production_rules_unchanged": True,
                   "recovered_at": recovered_at,
                   "rules_sha256": hashlib.sha256((root / "infra/observability/quota-alerts.yml").read_bytes()).hexdigest(),
                   "receiver": "approved-local-quota-test", "transitions": {key: sorted(value) for key, value in observed.items()}}
        (work / "summary.json").write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary), flush=True)
    finally:
        for container in reversed(containers):
            (work / (container + ".log")).write_text(docker("logs", container))
            docker("rm", "-f", container)
        if network_created:
            docker("network", "rm", network)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    (serve if args.serve else rehearse)(args.work.resolve())
