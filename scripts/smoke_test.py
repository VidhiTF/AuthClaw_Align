import socket
import urllib.request
import urllib.error
import sys
import os
import time


def retry_count():
    return max(1, int(os.getenv("AUTHCLAW_SMOKE_RETRIES", "1")))


def retry_delay_seconds():
    return max(0.1, float(os.getenv("AUTHCLAW_SMOKE_RETRY_DELAY_SECONDS", "2")))


def retry(check, *args):
    attempts = retry_count()
    for attempt in range(1, attempts + 1):
        if check(*args):
            return True
        if attempt < attempts:
            time.sleep(retry_delay_seconds())
    return False


def check_port_once(host, port, service_name):
    print(f"Checking port {port} ({service_name})... ", end="")
    try:
        with socket.create_connection((host, port), timeout=3):
            print("OPEN")
            return True
    except (socket.timeout, ConnectionRefusedError):
        print("CLOSED [FAIL]")
        return False


def check_http_endpoint_once(url, expected_status=200):
    print(f"Checking HTTP endpoint {url}... ", end="")
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            status = response.getcode()
            if status == expected_status:
                print(f"OK ({status})")
                return True
            else:
                print(f"FAIL (Expected {expected_status}, got {status}) [FAIL]")
                return False
    except urllib.error.HTTPError as e:
        if e.code == expected_status:
            print(f"OK ({e.code})")
            return True
        else:
            print(f"FAIL (HTTP Error {e.code}) [FAIL]")
            return False
    except Exception as e:
        print(f"ERROR ({str(e)}) [FAIL]")
        return False


def parse_ports():
    raw = os.getenv("AUTHCLAW_SMOKE_PORTS", "")
    if not raw.strip():
        return [
            ("localhost", 8000, "FastAPI Backend"),
            ("localhost", 8080, "Go Gateway"),
            ("localhost", 3001, "Next.js Console"),
            ("localhost", 8123, "ClickHouse"),
            ("localhost", 6379, "Redis"),
        ]
    ports = []
    for item in raw.split(","):
        if not item.strip():
            continue
        port_part, _, name = item.partition(":")
        ports.append(("localhost", int(port_part.strip()), name.strip() or f"Port {port_part.strip()}"))
    return ports


def parse_endpoints():
    raw = os.getenv("AUTHCLAW_SMOKE_ENDPOINTS", "")
    if not raw.strip():
        return [
            ("http://localhost:8000/health", 200),
            ("http://localhost:3001/login", 200),
        ]
    endpoints = []
    for item in raw.split(","):
        if not item.strip():
            continue
        url, _, status = item.partition("=")
        endpoints.append((url.strip(), int(status.strip() or "200")))
    return endpoints


def main():
    print("==================================================")
    print("AuthClaw Phase 13 System Smoke Test")
    print("==================================================")
    
    all_passed = True
    for host, port, name in parse_ports():
        if not retry(check_port_once, host, port, name):
            all_passed = False
            
    print("\nValidating HTTP Service Health...")

    for url, expected_status in parse_endpoints():
        if not retry(check_http_endpoint_once, url, expected_status):
            all_passed = False

    print("==================================================")
    if all_passed:
        print("SMOKE TEST PASSED: All core services are healthy! [OK]")
        sys.exit(0)
    else:
        print("SMOKE TEST FAILED: Some services or endpoints are unhealthy! [FAIL]")
        sys.exit(1)

if __name__ == "__main__":
    main()
