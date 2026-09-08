"""Disposable backend-image HTTPS client -> production TLS proxy -> real OPA."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
TLS = ROOT / "infra/terraform/modules/regional_stack"
BACKEND = os.getenv("TLS_TEST_BACKEND_IMAGE", "authclaw-security-backend:local")
OPA = os.getenv("TLS_TEST_OPA_IMAGE", "authclaw-security-opa:local")


def docker(*arguments, env=None, required=True):
    result = subprocess.run(["docker", *arguments], env=env, capture_output=True, text=True, timeout=120)
    if required and result.returncode:
        raise RuntimeError(result.stderr[-2000:])
    return result


class ContainerTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.name = "authclaw-tls-" + uuid.uuid4().hex[:12]
        cls.proxy, cls.opa = cls.name + "-proxy", cls.name + "-opa"
        cls.addClassCleanup(docker, "network", "rm", cls.name, required=False)
        cls.addClassCleanup(docker, "rm", "-f", cls.opa, required=False)
        cls.addClassCleanup(docker, "rm", "-f", cls.proxy, required=False)
        cls.temp = tempfile.TemporaryDirectory(prefix="authclaw-tls-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.repo_mount = f"type=bind,source={ROOT},target=/repo,readonly"
        fixtures = docker("run", "--rm", "--network", "none", "--mount", cls.repo_mount,
                          "--entrypoint", "python", BACKEND, "/repo/scripts/test_internal_tls.py", "--fixtures")
        cls.fixtures = json.loads(fixtures.stdout)
        ca = Path(cls.temp.name) / "ca.pem"
        ca.write_text(cls.fixtures["ca"], encoding="ascii")
        cls.ca_mount = f"type=bind,source={ca},target=/ca.pem,readonly"
        # Reuse the exact configured proxy image instead of maintaining a second pin.
        import re
        cls.image = re.search(r'proxy_image\s*=\s*optional\(string, "([^"]+)"', (TLS / "internal_tls.tf").read_text())[1]
        docker("network", "create", "--internal", cls.name)
        docker("run", "-d", "--name", cls.opa, "--network", cls.name,
               "--network-alias", "opa.test", "--network-alias", "wrong.test", OPA)

    def replace_proxy(self, version):
        docker("rm", "-f", self.proxy, required=False)
        env = {**os.environ, **self.fixtures[version],
               "TLS_CONFIG": (TLS / "tls-nginx.conf.tftpl").read_text().replace("${port}", "8181")}
        docker("run", "-d", "--name", self.proxy, "--network", "container:" + self.opa,
               "--user", "101", "-e", "TLS_CERT_PEM", "-e", "TLS_KEY_PEM", "-e", "TLS_CONFIG",
               "--entrypoint", "sh", self.image, "-ec", (TLS / "tls-entrypoint.sh").read_text(), env=env)
        # A TLS handshake with min_days=0 is the readiness gate, not a fixed sleep.
        for _ in range(20):
            result = self.client(min_days=0)
            if result.returncode == 0:
                return
            time.sleep(.2)
        self.fail("TLS proxy/OPA readiness failed")

    def client(self, host="opa.test", trusted=True, min_days=30):
        code = (
            "import sys,json; sys.path.insert(0,'/repo/scripts'); "
            "from check_internal_tls import check; import httpx; "
            "result=check(sys.argv[1],min_days=int(sys.argv[2])); "
            "response=httpx.get('https://'+sys.argv[1]+':8443/health',timeout=5); "
            "response.raise_for_status(); "
            "decision=httpx.post('https://'+sys.argv[1]+':8443/v1/data/authclaw',"
            "json={'input':{'rate_limit_exceeded':True}},timeout=5); "
            "decision.raise_for_status(); assert decision.json()['result']['allow'] is False; "
            "print(json.dumps(result))"
        )
        return docker("run", "--rm", "--network", self.name, "--mount", self.repo_mount,
                      "--mount", self.ca_mount, "-e", "SSL_CERT_FILE=/ca.pem" if trusted else "SSL_CERT_FILE=",
                      "--entrypoint", "python", BACKEND, "-c", code, host, str(min_days), required=False)

    def test_certificate_replacement_rollback_and_rejection(self):
        self.replace_proxy("old")
        old = json.loads(self.client().stdout)["sha256"]
        wrong_host = self.client(host="wrong.test")
        self.assertNotEqual(wrong_host.returncode, 0)
        self.assertIn("hostname mismatch", wrong_host.stderr.lower())
        untrusted = self.client(trusted=False)
        self.assertNotEqual(untrusted.returncode, 0)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", untrusted.stderr)
        self.replace_proxy("renewed")
        self.assertNotEqual(json.loads(self.client().stdout)["sha256"], old)
        self.replace_proxy("old")
        self.assertEqual(json.loads(self.client().stdout)["sha256"], old)
        self.replace_proxy("soon")
        expiring = self.client()
        self.assertNotEqual(expiring.returncode, 0)
        self.assertIn("renewal threshold reached", expiring.stderr)


if __name__ == "__main__":
    unittest.main()
