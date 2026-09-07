import copy
import unittest
from datetime import datetime, timezone

from scripts.verify_p007_edge_evidence import EvidenceError, validate


def valid_evidence(environment="staging"):
    production = environment == "production"
    domains = (
        ["authclaw.ai", "www.authclaw.ai", "app.authclaw.ai", "api.authclaw.ai", "gateway.authclaw.ai"]
        if production
        else ["dev.authclaw.ai", "api.dev.authclaw.ai", "gateway.dev.authclaw.ai"]
    )
    console = "app.authclaw.ai" if production else "dev.authclaw.ai"
    now = datetime.now(timezone.utc).isoformat()
    return {
        "schema_version": 1,
        "environment": environment,
        "tested_at": now,
        "terraform_commit": "a" * 40,
        "release_id": "release-2026-09-03.1",
        "dns": [{"hostname": host, "record_type": "A", "target_type": "cloudfront", "distribution_id": f"E{index}ABC"} for index, host in enumerate(domains)],
        "certificates": {"viewer": {"status": "ISSUED", "region": "us-east-1", "hostnames": domains, "arn": "arn:aws:acm:us-east-1:123456789012:certificate/abc"}, "origins": [{"status": "ISSUED", "arn": "arn:aws:acm:us-east-1:123456789012:certificate/def", "hostnames": [console, "api.authclaw.ai" if production else "api.dev.authclaw.ai", "gateway.authclaw.ai" if production else "gateway.dev.authclaw.ai"]}]},
        "probes": [
            {"name": name, "expected_host": host, "final_url": f"https://{host}{path}", "status": 200, "cloudfront_request_id": f"req-{name}", "observed_at": now}
            for name, host, path in [
                ("http_redirect", console, "/login"),
                ("console_health", console, "/"),
                ("api_health", "api.authclaw.ai" if production else "api.dev.authclaw.ai", "/health"),
                ("gateway_health", "gateway.authclaw.ai" if production else "gateway.dev.authclaw.ai", "/health"),
            ]
        ],
        "direct_origin_denials": [{"service": service, "alb_internal": True, "public_cidrs": [], "allowed_prefix_list": "com.amazonaws.global.cloudfront.origin-facing", "direct_result": "dns_unreachable"} for service in ("console", "backend", "gateway")],
        "cors": {"allowed_origin": f"https://{console}", "allowed_response_header": f"https://{console}", "disallowed_response_header": None},
        "cookie": {"name": "authclaw_session_prod" if production else "authclaw_session_stg", "secure": True, "http_only": True, "same_site": "Lax", "path": "/", "domain": None},
        "oidc": {"callback_uri": f"https://{console}/api/auth/oidc/callback", "wildcard_registered": False, "cross_environment_callback_status": 403},
        "tenant_auth": {"same_tenant_status": 200, "cross_tenant_status": 403, "audit_event_id": "audit-123"},
        "waf": {"managed_rule_groups": ["AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet"], "rate_limit_status": 403, "blocked_request_id": "waf-123"},
        "logs": {"retention_days": 90, "waf_redacted_fields": ["authorization", "cookie", "query_string"], "alb_services": ["console", "backend", "gateway"], "waf_log_group": "aws-waf-logs-authclaw", "alb_log_bucket": "authclaw-alb-logs"},
    }


class P007EvidenceTests(unittest.TestCase):
    def test_accepts_staging(self):
        validate(valid_evidence())

    def test_accepts_production(self):
        validate(valid_evidence("production"))

    def test_rejects_direct_public_origin(self):
        evidence = valid_evidence()
        evidence["direct_origin_denials"][0]["public_cidrs"] = ["0.0.0.0/0"]
        with self.assertRaises(EvidenceError):
            validate(evidence)

    def test_rejects_cross_environment_cors_and_cookie_domain(self):
        evidence = valid_evidence()
        evidence["cors"]["allowed_origin"] = "https://app.authclaw.ai"
        evidence["cookie"]["domain"] = ".authclaw.ai"
        with self.assertRaises(EvidenceError):
            validate(evidence)

    def test_rejects_missing_log_redaction(self):
        evidence = valid_evidence()
        evidence["logs"]["waf_redacted_fields"] = ["authorization"]
        with self.assertRaises(EvidenceError):
            validate(evidence)

    def test_rejects_placeholder_and_alternate_port(self):
        evidence = valid_evidence()
        evidence["release_id"] = "TBD"
        evidence["probes"][0]["final_url"] = "https://dev.authclaw.ai:8443/login"
        with self.assertRaises(EvidenceError):
            validate(evidence)


if __name__ == "__main__":
    unittest.main()
