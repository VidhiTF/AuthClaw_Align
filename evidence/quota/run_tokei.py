"""Run inside python:3.14.3-slim with /work read-only and /evidence writable."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

URL = "https://github.com/XAMPPRocky/tokei/releases/download/v12.1.2/tokei-x86_64-unknown-linux-gnu.tar.gz"
SHA256 = "c8c5c4ab9e1ff47e745de70f4af3214078657399fa7a0da0b5f209d780e49978"
blob = urllib.request.urlopen(URL, timeout=60).read()
assert hashlib.sha256(blob).hexdigest() == SHA256
with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
    archive.extractall("/tmp/tokei", filter="data")
command = ["/tmp/tokei/tokei", "--files", "backend/app", "gateway", "audit_consumer", "console/src",
           "services/agent/main.py", "services/agent/services/quota_service.py",
           "services/agent/document_processing/monitoring.py", "--output", "json"]
report = subprocess.check_output(command)
Path("/evidence/tokei.json").write_bytes(report)
check = subprocess.run(["python", "scripts/check_line_budget.py"], input=report, capture_output=True)
data = json.loads(report)
selected = {"gateway/quota_admission.go", "gateway/main.go", "services/agent/main.py",
            "services/agent/services/quota_service.py", "services/agent/document_processing/monitoring.py"}
counts = {row["name"]: row["stats"]["code"] for language, summary in data.items()
          if language != "Total" for row in summary.get("reports", []) if row["name"] in selected}
result = (f"Archive: {URL}\nSHA256 verified: {SHA256}\nCommand: {' '.join(command)}\n"
          f"Checker: python scripts/check_line_budget.py < /evidence/tokei.json\n"
          f"Exit code: {check.returncode}\n{check.stdout.decode()}{check.stderr.decode()}"
          f"Selected code counts: {json.dumps(counts, sort_keys=True)}\n")
Path("/evidence/tokei-result.txt").write_text(result)
print(result)
raise SystemExit(check.returncode)
