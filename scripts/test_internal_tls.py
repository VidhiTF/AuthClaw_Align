"""Real local NGINX and STARTTLS checks. Only ephemeral synthetic certificates."""
import http.server
import os
from pathlib import Path
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
TLS = ROOT / "infra/terraform/modules/regional_stack"


def certificate(common_name, signer=None, expired=False, valid_days=90):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(signer[0].subject if signer else subject).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(days=2))
               .not_valid_after(now + timedelta(days=-1 if expired else valid_days))
               .add_extension(x509.BasicConstraints(ca=signer is None, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((signer[1] if signer else key).public_key()), critical=False)
               .add_extension(x509.KeyUsage(True, False, True, False, False, signer is None, signer is None, False, False), critical=True)
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False))
    return builder.sign(signer[1] if signer else key, hashes.SHA256()), key


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"synthetic-upstream")

    def log_message(self, *args):
        pass


class Certificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.ca = certificate("synthetic-ca")
        cls.leaf = certificate("localhost", cls.ca)
        cls.ca_path = Path(cls.temp.name) / "ca.pem"
        cls.ca_path.write_bytes(cls.ca[0].public_bytes(serialization.Encoding.PEM))
        cls.upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=cls.upstream.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()
        cls.upstream.server_close()
        cls.temp.cleanup()

class TLSChecks(Certificates):
    def test_expiry_gate_accepts_healthy_certificate(self):
        from check_internal_tls import check
        self.start_proxy()
        self.assertGreater(check("localhost", ca_file=self.ca_path)["remaining_days"], 30)

    def test_expiry_gate_rejects_renewal_window(self):
        from check_internal_tls import check
        self.start_proxy(certificate("localhost", self.ca, valid_days=1))
        with self.assertRaisesRegex(ValueError, "renewal threshold"):
            check("localhost", ca_file=self.ca_path)

    def start_proxy(self, leaf=None):
        cert, key = leaf or self.leaf
        env = {**os.environ,
               "TLS_CERT_PEM": cert.public_bytes(serialization.Encoding.PEM).decode(),
               "TLS_KEY_PEM": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
               "TLS_CONFIG": (TLS / "tls-nginx.conf.tftpl").read_text().replace("${port}", str(self.upstream.server_port))}
        process = subprocess.Popen(["sh", "-ec", (TLS / "tls-entrypoint.sh").read_text()], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (process.terminate(), process.wait(timeout=5)))
        for _ in range(50):
            if process.poll() is not None:
                self.fail("NGINX exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", 8443), timeout=.1):
                    return
            except OSError:
                time.sleep(.1)
        self.fail("NGINX did not become ready")

    def request(self, hostname="localhost", context=None):
        context = context or ssl.create_default_context(cafile=str(self.ca_path))
        return urllib.request.urlopen(f"https://{hostname}:8443/health", context=context, timeout=3)

    def test_trusted_tls_reaches_upstream(self):
        self.start_proxy()
        with self.request() as response:
            self.assertEqual(response.read(), b"synthetic-upstream")

    def test_wrong_hostname_is_rejected(self):
        self.start_proxy()
        with self.assertRaises(urllib.error.URLError):
            self.request("127.0.0.1")

    def test_untrusted_ca_is_rejected(self):
        self.start_proxy()
        with self.assertRaises(urllib.error.URLError):
            self.request(context=ssl.create_default_context())

    def test_expired_certificate_is_rejected(self):
        self.start_proxy(certificate("localhost", self.ca, expired=True))
        with self.assertRaises(urllib.error.URLError):
            self.request()

    def test_plaintext_cannot_reach_upstream(self):
        self.start_proxy()
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen("http://localhost:8443/health", timeout=3)
        self.assertEqual(error.exception.code, 400)
        error.exception.close()


class SMTPHandler(socketserver.StreamRequestHandler):
    def finish(self):
        super().finish()
        self.connection.close()

    def handle(self):
        def reply(value):
            self.wfile.write(value + b"\r\n")
            self.wfile.flush()
        reply(b"220 local-test")
        while line := self.rfile.readline():
            command = line.split()[0].upper()
            if command in {b"EHLO", b"HELO"}:
                reply(b"250-local-test\r\n250 STARTTLS")
            elif command == b"STARTTLS":
                reply(b"220 Ready")
                try:
                    self.connection = self.server.context.wrap_socket(self.connection, server_side=True)
                except ssl.SSLError:
                    return
                self.rfile = self.connection.makefile("rb")
                self.wfile = self.connection.makefile("wb")
            elif command == b"DATA":
                reply(b"354 Continue")
                body = []
                while (line := self.rfile.readline()) not in {b".\r\n", b""}:
                    body.append(line)
                self.server.messages.append(b"".join(body))
                reply(b"250 Accepted")
            elif command == b"QUIT":
                reply(b"221 Bye")
                return
            else:
                reply(b"250 OK")


class SMTPChecks(Certificates):
    def test_production_aliases_never_write_local_outbox(self):
        import sys
        sys.path.insert(0, str(ROOT / "backend"))
        from app.services.email_service import EmailDeliveryError, send_email, send_otp_email
        for environment in ("prod", "production"):
            with patch.dict(os.environ, {"AUTHCLAW_ENV": environment, "SMTP_HOST": ""}):
                with self.assertRaises(EmailDeliveryError):
                    send_email("requester@example.invalid", "Invite", "synthetic")
                with self.assertRaises(EmailDeliveryError):
                    send_otp_email("requester@example.invalid", "123456", "synthetic")

    # Reuse synthetic certificate setup without repeating TLS tests.
    def test_email_delivery_and_invalid_ca(self):
        import sys
        sys.path.insert(0, str(ROOT / "backend"))
        from app.services.email_service import EmailDeliveryError, send_otp_email
        cert, key = self.leaf
        cert_path, key_path = Path(self.temp.name) / "server.pem", Path(self.temp.name) / "server.key"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        with socketserver.TCPServer(("127.0.0.1", 0), SMTPHandler) as server:
            server.context, server.messages = context, []
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                with patch.dict(os.environ, {"AUTHCLAW_ENV": "production", "SMTP_HOST": "localhost",
                    "SMTP_PORT": str(server.server_address[1]), "SMTP_TLS": "true",
                    "SMTP_USER": "", "SSL_CERT_FILE": str(self.ca_path)}):
                    result = send_otp_email("requester@example.invalid", "123456", "synthetic", action_url="https://example.invalid/invite")
                    self.assertEqual(result.method, "smtp")
                    self.assertIn(b"123456", server.messages[0])
                    self.assertIn(b"https://example.invalid/invite", server.messages[0])
                    with patch.dict(os.environ, {"SSL_CERT_FILE": "/nonexistent"}):
                        with self.assertRaises(EmailDeliveryError):
                            send_otp_email("requester@example.invalid", "654321", "synthetic")
                    self.assertEqual(len(server.messages), 1)
                    with patch.dict(os.environ, {"SMTP_TLS": "false"}):
                        with self.assertRaises(EmailDeliveryError):
                            send_otp_email("requester@example.invalid", "654321", "synthetic")
            finally:
                server.shutdown()


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--fixtures"]:
        import json
        ca = certificate("synthetic-ca", valid_days=365)
        result = {"ca": ca[0].public_bytes(serialization.Encoding.PEM).decode()}
        for name, days in (("old", 60), ("renewed", 90), ("soon", 1)):
            cert, key = certificate("opa.test", ca, valid_days=days)
            result[name] = {
                "TLS_CERT_PEM": cert.public_bytes(serialization.Encoding.PEM).decode(),
                "TLS_KEY_PEM": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
            }
        print(json.dumps(result))
    else:
        unittest.main()
