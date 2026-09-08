"""Read-only leaf-certificate expiry gate; run from a network that reaches the service."""
import argparse
import hashlib
import json
import socket
import ssl
import time


def check(host, port=8443, *, ca_file=None, min_days=30):
    if min_days < 0:
        raise ValueError("Minimum remaining lifetime cannot be negative")
    context = ssl.create_default_context(cafile=ca_file)
    with socket.create_connection((host, port), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname=host) as peer:
            certificate = peer.getpeercert()
            remaining = ssl.cert_time_to_seconds(certificate["notAfter"]) - time.time()
            if remaining < min_days * 86400:
                raise ValueError("Certificate renewal threshold reached")
            return {
                "host": host, "port": port, "remaining_days": int(remaining / 86400),
                "sha256": hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest(),
            }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ca-file")
    parser.add_argument("--min-days", type=int, default=30)
    args = parser.parse_args()
    try:
        result = check(args.host, args.port, ca_file=args.ca_file, min_days=args.min_days)
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "FAIL", "reason": type(error).__name__}))
        return 1
    print(json.dumps({"status": "PASS", **result}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
