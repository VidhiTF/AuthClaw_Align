#!/usr/bin/env python3
"""Fail-closed validation for P0-07 staging/production ingress evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


DOMAINS = {
    "staging": {
        "marketing": "dev.authclaw.ai",
        "console": "dev.authclaw.ai",
        "api": "api.dev.authclaw.ai",
        "gateway": "gateway.dev.authclaw.ai",
    },
    "production": {
        "marketing": "authclaw.ai",
        "www": "www.authclaw.ai",
        "console": "app.authclaw.ai",
        "api": "api.authclaw.ai",
        "gateway": "gateway.authclaw.ai",
    },
}
PLACEHOLDER = re.compile(r"(?i)(todo|tbd|placeholder|example|replace[-_ ]?me|unknown|pending)")
SHA = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _text(value: object, field: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), f"{field} must be a non-empty string")
    result = value.strip()
    _require(not PLACEHOLDER.search(result), f"{field} contains a placeholder")
    return result


def _timestamp(value: object, field: str) -> datetime:
    text = _text(value, field).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise EvidenceError(f"{field} must be ISO-8601") from exc
    _require(parsed.tzinfo is not None, f"{field} must include a timezone")
    _require(parsed <= datetime.now(timezone.utc), f"{field} cannot be in the future")
    return parsed


def _https_host(value: object, expected_host: str, field: str) -> None:
    parsed = urlparse(_text(value, field))
    _require(parsed.scheme == "https", f"{field} must use https")
    _require(parsed.hostname == expected_host, f"{field} must use {expected_host}")
    _require(parsed.port in (None, 443), f"{field} must not expose an alternate port")


def validate(data: dict) -> None:
    _require(data.get("schema_version") == 1, "schema_version must be 1")
    environment = data.get("environment")
    _require(environment in DOMAINS, "environment must be staging or production")
    domains = DOMAINS[environment]
    _timestamp(data.get("tested_at"), "tested_at")
    commit = _text(data.get("terraform_commit"), "terraform_commit")
    _require(bool(SHA.fullmatch(commit)), "terraform_commit must be a full lowercase Git SHA")
    _text(data.get("release_id"), "release_id")

    dns = data.get("dns")
    _require(isinstance(dns, list) and len(dns) == len(set(domains.values())), "dns must cover every approved hostname exactly once")
    _require({item.get("hostname") for item in dns} == set(domains.values()), "dns contains a missing or alternate hostname")
    for index, item in enumerate(dns):
        _require(item.get("record_type") in ("A", "AAAA"), f"dns[{index}].record_type must be A or AAAA")
        _require(item.get("target_type") == "cloudfront", f"dns[{index}] must target CloudFront")
        _text(item.get("distribution_id"), f"dns[{index}].distribution_id")

    certificates = data.get("certificates", {})
    viewer = certificates.get("viewer", {})
    _require(viewer.get("status") == "ISSUED", "viewer certificate must be ISSUED")
    _require(viewer.get("region") == "us-east-1", "viewer certificate must be in us-east-1")
    _require(set(viewer.get("hostnames", [])) == set(domains.values()), "viewer certificate must cover every approved hostname")
    _text(viewer.get("arn"), "certificates.viewer.arn")
    origins = certificates.get("origins")
    _require(isinstance(origins, list) and origins, "at least one regional origin certificate is required")
    for index, origin in enumerate(origins):
        _require(origin.get("status") == "ISSUED", f"certificates.origins[{index}] must be ISSUED")
        _text(origin.get("arn"), f"certificates.origins[{index}].arn")
        _require(set(origin.get("hostnames", [])) >= {domains["console"], domains["api"], domains["gateway"]}, f"certificates.origins[{index}] must cover console, API, and gateway hosts")

    probes = data.get("probes")
    required_probes = {"http_redirect", "console_health", "api_health", "gateway_health"}
    _require(isinstance(probes, list), "probes must be a list")
    _require(required_probes <= {probe.get("name") for probe in probes}, "required redirect and health probes are missing")
    for index, probe in enumerate(probes):
        expected_host = probe.get("expected_host")
        _require(expected_host in set(domains.values()), f"probes[{index}].expected_host is not approved")
        _https_host(probe.get("final_url"), expected_host, f"probes[{index}].final_url")
        _require(probe.get("status") in (200, 204), f"probes[{index}] must finish successfully")
        _text(probe.get("cloudfront_request_id"), f"probes[{index}].cloudfront_request_id")
        _timestamp(probe.get("observed_at"), f"probes[{index}].observed_at")

    denials = data.get("direct_origin_denials")
    _require(isinstance(denials, list) and {item.get("service") for item in denials} == {"console", "backend", "gateway"}, "direct-origin evidence must cover console, backend, and gateway")
    for index, denial in enumerate(denials):
        _require(denial.get("alb_internal") is True, f"direct_origin_denials[{index}] ALB must be internal")
        _require(denial.get("public_cidrs") == [], f"direct_origin_denials[{index}] must have no public ingress CIDRs")
        _require(denial.get("allowed_prefix_list") == "com.amazonaws.global.cloudfront.origin-facing", f"direct_origin_denials[{index}] must use the CloudFront prefix list")
        _require(denial.get("direct_result") in ("dns_unreachable", "timeout", "denied"), f"direct_origin_denials[{index}] must prove denial")

    cors = data.get("cors", {})
    console_origin = f"https://{domains['console']}"
    _require(cors.get("allowed_origin") == console_origin, "CORS must allow exactly the environment console origin")
    _require(cors.get("allowed_response_header") == console_origin, "allowed CORS proof is missing")
    _require(cors.get("disallowed_response_header") in (None, ""), "an alternate environment origin was allowed")

    cookie = data.get("cookie", {})
    _require(cookie.get("secure") is True and cookie.get("http_only") is True, "session cookie must be Secure and HttpOnly")
    _require(cookie.get("same_site") == "Lax" and cookie.get("path") == "/", "session cookie must be SameSite=Lax and Path=/")
    _require(cookie.get("domain") in (None, ""), "session cookie must be host-only")
    expected_cookie = "authclaw_session_stg" if environment == "staging" else "authclaw_session_prod"
    _require(cookie.get("name") == expected_cookie, f"session cookie must be named {expected_cookie}")

    oidc = data.get("oidc", {})
    expected_callback = f"https://{domains['console']}/api/auth/oidc/callback"
    _require(oidc.get("callback_uri") == expected_callback, "OIDC callback URI is not exact")
    _require(oidc.get("wildcard_registered") is False, "wildcard OIDC callbacks are prohibited")
    _require(oidc.get("cross_environment_callback_status") in (400, 401, 403), "cross-environment callback was not rejected")

    auth = data.get("tenant_auth", {})
    _require(auth.get("same_tenant_status") == 200, "same-tenant authentication proof failed")
    _require(auth.get("cross_tenant_status") in (401, 403, 404), "cross-tenant authentication must be denied")
    _text(auth.get("audit_event_id"), "tenant_auth.audit_event_id")

    waf = data.get("waf", {})
    _require(set(waf.get("managed_rule_groups", [])) >= {"AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet"}, "required WAF managed groups are missing")
    _require(waf.get("rate_limit_status") == 403, "WAF rate-limit denial is missing")
    _text(waf.get("blocked_request_id"), "waf.blocked_request_id")

    logs = data.get("logs", {})
    _require(isinstance(logs.get("retention_days"), int) and logs["retention_days"] >= 30, "access-log retention must be at least 30 days")
    _require(set(logs.get("waf_redacted_fields", [])) >= {"authorization", "cookie", "query_string"}, "WAF logs must redact authorization, cookie, and query string")
    _require(set(logs.get("alb_services", [])) == {"console", "backend", "gateway"}, "ALB access logs must cover all public-origin services")
    _text(logs.get("waf_log_group"), "logs.waf_log_group")
    _text(logs.get("alb_log_bucket"), "logs.alb_log_bucket")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()
    try:
        payload = json.loads(args.evidence.read_text(encoding="utf-8"))
        _require(isinstance(payload, dict), "evidence root must be an object")
        validate(payload)
    except (OSError, json.JSONDecodeError, EvidenceError) as exc:
        print(f"P0-07 evidence rejected: {exc}", file=sys.stderr)
        return 1
    print(f"P0-07 evidence accepted: {args.evidence}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
