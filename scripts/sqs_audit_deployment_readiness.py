#!/usr/bin/env python3
"""Read-only SQS FIFO audit transport deployment-readiness evidence collector."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PASS = "PASS"
FAIL = "FAIL"
PENDING = "LIVE-EVIDENCE-PENDING"
ACCOUNT_RE = re.compile(r"\b\d{12}\b")
ARN_RE = re.compile(r"arn:aws[a-z-]*:[^:\s]+:[^:\s]*:\d{12}:[^\s,\"']+")


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        value = ARN_RE.sub("arn:aws:REDACTED", value)
        return ACCOUNT_RE.sub("ACCOUNT_REDACTED", value)
    return value


def now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def aws_json(args: list[str], *, live: bool) -> tuple[Any | None, str]:
    if not live:
        return None, "live AWS collection not requested"
    try:
        output = subprocess.check_output(["aws", *args, "--output", "json"], text=True, stderr=subprocess.STDOUT, timeout=30)
        return json.loads(output or "{}"), ""
    except FileNotFoundError:
        return None, "aws CLI not installed"
    except subprocess.CalledProcessError as exc:
        return None, redact(exc.output.strip())
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def terraform_outputs(path: str) -> dict[str, Any]:
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def output_value(outputs: dict[str, Any], region_key: str, *keys: str) -> Any:
    value = outputs.get(region_key, {}).get("value", outputs.get(region_key, {}))
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def check(name: str, status: str, evidence: str, raw: Any = None) -> dict[str, Any]:
    return {"name": name, "status": status, "evidence": evidence, "raw": redact(raw)}


def queue_checks(queue: dict[str, str] | None, dlq: dict[str, str] | None, expected: dict[str, Any]) -> list[dict[str, Any]]:
    if not queue:
        return [check("audit queue attributes", PENDING, "queue attributes were not collected")]
    redrive = json.loads(queue.get("RedrivePolicy", "{}") or "{}")
    policy = json.loads(queue.get("Policy", "{}") or "{}")
    dlq_policy = json.loads((dlq or {}).get("Policy", "{}") or "{}")
    tls_deny = any((item.get("Effect") == "Deny" and item.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") == "false") for item in policy.get("Statement", []))
    dlq_tls_deny = any((item.get("Effect") == "Deny" and item.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") == "false") for item in dlq_policy.get("Statement", []))
    checks = [
        check("audit queue is FIFO", PASS if queue.get("FifoQueue") == "true" else FAIL, "FifoQueue=true expected", queue),
        check("audit queue explicit deduplication", PASS if queue.get("ContentBasedDeduplication") == "false" else FAIL, "ContentBasedDeduplication=false expected", queue),
        check("audit queue encrypted", PASS if queue.get("KmsMasterKeyId") else FAIL, "KmsMasterKeyId must be set", queue.get("KmsMasterKeyId")),
        check("audit queue TLS-only policy", PASS if tls_deny else FAIL, "Deny aws:SecureTransport=false expected", policy),
        check("audit queue retention", PASS if int(queue.get("MessageRetentionPeriod", 0)) == expected["retention"] else FAIL, f"expected {expected['retention']}", queue.get("MessageRetentionPeriod")),
        check("audit visibility timeout", PASS if int(queue.get("VisibilityTimeout", 0)) == expected["visibility"] else FAIL, f"expected {expected['visibility']}", queue.get("VisibilityTimeout")),
        check("audit maxReceiveCount", PASS if int(redrive.get("maxReceiveCount", 0)) == expected["max_receive_count"] else FAIL, f"expected {expected['max_receive_count']}", redrive),
    ]
    if dlq:
        allow = json.loads(dlq.get("RedriveAllowPolicy", "{}") or "{}")
        checks.extend(
            [
                check("DLQ is FIFO", PASS if dlq.get("FifoQueue") == "true" else FAIL, "FifoQueue=true expected", dlq),
                check("DLQ encrypted", PASS if dlq.get("KmsMasterKeyId") else FAIL, "KmsMasterKeyId must be set", dlq.get("KmsMasterKeyId")),
                check("DLQ TLS-only policy", PASS if dlq_tls_deny else FAIL, "Deny aws:SecureTransport=false expected", dlq_policy),
                check("DLQ retention", PASS if int(dlq.get("MessageRetentionPeriod", 0)) == expected["dlq_retention"] else FAIL, f"expected {expected['dlq_retention']}", dlq.get("MessageRetentionPeriod")),
                check("DLQ redrive allow policy", PASS if allow.get("redrivePermission") == "byQueue" and allow.get("sourceQueueArns") else FAIL, "must restrict source queue", allow),
            ]
        )
    else:
        checks.append(check("DLQ attributes", PENDING, "DLQ attributes were not collected"))
    return checks


def alarm_checks(alarms: list[dict[str, Any]], expected_names: list[str]) -> list[dict[str, Any]]:
    if not expected_names:
        return [check("SQS alarms", PENDING, "Terraform alarm names unavailable")]
    by_name = {alarm.get("AlarmName"): alarm for alarm in alarms}
    checks = []
    for name in expected_names:
        alarm = by_name.get(name)
        checks.append(check(f"alarm {name}", PASS if alarm and alarm.get("ActionsEnabled") is True else FAIL, "alarm exists and actions are enabled", alarm))
    return checks


def iam_checks(role_arns: dict[str, str], consumer_role: str, *, live: bool) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    producer_actions = ["sqs:ReceiveMessage", "sqs:DeleteMessage"]
    for service, arn in role_arns.items():
        raw, reason = aws_json(["iam", "simulate-principal-policy", "--policy-source-arn", arn, "--action-names", *producer_actions], live=live)
        denied = raw and all(item.get("EvalDecision") != "allowed" for item in raw.get("EvaluationResults", []))
        checks.append(check(f"{service} producer cannot receive/delete", PASS if denied else (PENDING if raw is None else FAIL), reason or "receive/delete must not be allowed", raw))
    raw, reason = aws_json(["iam", "simulate-principal-policy", "--policy-source-arn", consumer_role, "--action-names", "sqs:SendMessage"], live=live) if consumer_role else (None, "consumer role unavailable")
    denied = raw and all(item.get("EvalDecision") != "allowed" for item in raw.get("EvaluationResults", []))
    checks.append(check("consumer cannot send", PASS if denied else (PENDING if raw is None else FAIL), reason or "send must not be allowed", raw))
    return checks


def ecs_checks(cluster: str, services: dict[str, str], queue_url: str, role_arns: dict[str, str], consumer_role: str, *, live: bool, region: str) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    if not cluster or not services:
        return [check("ECS services/task definitions", PENDING, "cluster or service names unavailable", services)]
    for service_key, service_name in services.items():
        raw, reason = aws_json(["ecs", "describe-services", "--cluster", cluster, "--services", service_name, "--region", region], live=live)
        service = (raw or {}).get("services", [{}])[0]
        task_def_arn = service.get("taskDefinition")
        task_raw, task_reason = aws_json(["ecs", "describe-task-definition", "--task-definition", task_def_arn, "--region", region], live=live and bool(task_def_arn))
        task = (task_raw or {}).get("taskDefinition") or {}
        env = {item.get("name"): item.get("value") for container in task.get("containerDefinitions", []) for item in container.get("environment", [])}
        secrets = [item.get("name") for container in task.get("containerDefinitions", []) for item in container.get("secrets", [])]
        expected_role = consumer_role if service_key == "audit_consumer" else role_arns.get(service_key)
        static_creds = any(name in env or name in secrets for name in ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"])
        checks.append(check(f"ECS {service_key} task role", PASS if expected_role and task.get("taskRoleArn") == expected_role else (PENDING if not task else FAIL), task_reason or reason or "taskRoleArn must match Terraform audit SQS role", task.get("taskRoleArn")))
        if service_key in {"backend", "gateway", "agent", "audit_consumer"}:
            checks.append(check(f"ECS {service_key} transport env", PASS if env.get("AUDIT_STREAM_TRANSPORT") in {"kafka", "sqs_fifo"} else (PENDING if not task else FAIL), "AUDIT_STREAM_TRANSPORT must be present and valid", env))
        if service_key in {"backend", "gateway", "agent"}:
            checks.append(check(f"ECS {service_key} queue URL env", PASS if env.get("AUDIT_STREAM_TRANSPORT") == "kafka" or env.get("SQS_AUDIT_QUEUE_URL") == queue_url else (PENDING if not task else FAIL), "SQS_AUDIT_QUEUE_URL required only in SQS mode", env))
        checks.append(check(f"ECS {service_key} no static AWS credentials", PASS if task and not static_creds else (PENDING if not task else FAIL), "task definition must not expose static AWS credential env/secrets", {"environment": env, "secrets": secrets}))
    return checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="Run read-only AWS CLI queries.")
    parser.add_argument("--run-canary", action="store_true", help="Reserved for explicit post-deployment canary evidence; never cuts over traffic.")
    parser.add_argument("--terraform-output-json", default="")
    parser.add_argument("--region-key", default="primary")
    parser.add_argument("--region", default="")
    parser.add_argument("--queue-url", default="")
    parser.add_argument("--dlq-url", default="")
    parser.add_argument("--ecs-cluster", default="")
    parser.add_argument("--output-json", default="infra/security/sqs-audit-deployment-readiness.pending.json")
    parser.add_argument("--output-md", default="infra/security/SQS_AUDIT_CUTOVER_READINESS.md")
    parser.add_argument("--expected-retention", type=int, default=1209600)
    parser.add_argument("--expected-dlq-retention", type=int, default=1209600)
    parser.add_argument("--expected-visibility", type=int, default=60)
    parser.add_argument("--expected-max-receive-count", type=int, default=5)
    args = parser.parse_args()

    outputs = terraform_outputs(args.terraform_output_json)
    audit_sqs = output_value(outputs, args.region_key, "audit_sqs") or {}
    network = output_value(outputs, args.region_key, "network_path") or {}
    services = output_value(outputs, args.region_key, "ecs_service_names") or {}
    region = args.region or output_value(outputs, args.region_key, "region") or ""
    queue_url = args.queue_url or audit_sqs.get("queue_url") or ""
    dlq_url = args.dlq_url or audit_sqs.get("dlq_url") or ""
    cluster = args.ecs_cluster or output_value(outputs, args.region_key, "ecs_cluster_name") or ""

    queue, queue_reason = aws_json(["sqs", "get-queue-attributes", "--queue-url", queue_url, "--attribute-names", "All", "--region", region], live=args.live and bool(queue_url and region))
    dlq, dlq_reason = aws_json(["sqs", "get-queue-attributes", "--queue-url", dlq_url, "--attribute-names", "All", "--region", region], live=args.live and bool(dlq_url and region))
    alarm_names = audit_sqs.get("alarm_names") or []
    alarms, alarm_reason = aws_json(["cloudwatch", "describe-alarms", "--alarm-names", *alarm_names, "--region", region], live=args.live and bool(alarm_names and region))
    endpoint_ids = (network.get("interface_endpoint_ids") or {})
    sqs_endpoint_id = endpoint_ids.get("sqs")
    endpoint, endpoint_reason = aws_json(["ec2", "describe-vpc-endpoints", "--vpc-endpoint-ids", sqs_endpoint_id, "--region", region], live=args.live and bool(sqs_endpoint_id and region))

    checks = []
    checks.extend(queue_checks((queue or {}).get("Attributes"), (dlq or {}).get("Attributes"), {
        "retention": args.expected_retention,
        "dlq_retention": args.expected_dlq_retention,
        "visibility": args.expected_visibility,
        "max_receive_count": args.expected_max_receive_count,
    }))
    checks.extend(alarm_checks((alarms or {}).get("MetricAlarms", []), alarm_names))
    checks.extend(iam_checks(audit_sqs.get("producer_role_arns") or {}, audit_sqs.get("consumer_role_arn") or "", live=args.live))
    checks.append(check("SQS VPC endpoint", PASS if endpoint and (endpoint.get("VpcEndpoints") or [{}])[0].get("PrivateDnsEnabled") else (PENDING if not endpoint else FAIL), endpoint_reason or "private DNS endpoint expected", endpoint))
    checks.extend(ecs_checks(cluster, services, queue_url, audit_sqs.get("producer_role_arns") or {}, audit_sqs.get("consumer_role_arn") or "", live=args.live, region=region))
    checks.append(check("Kafka rollback/default remains configured", PENDING, "confirm audit_stream_transport remains kafka until approved cutover"))
    checks.append(check("commit/image digest match", PENDING, "compare deployed task definition images with intended release digest"))
    checks.append(check("canary audit chain", PENDING if not args.run_canary else PENDING, "record canary IDs, tenant sequence and final chain after explicit deployment canary"))

    payload = {
        "mode": "LIVE-EVIDENCE-PENDING" if not args.live else "READ-ONLY-LIVE-COLLECTION",
        "collected_at": now(),
        "region": region or PENDING,
        "inputs": redact({"queue_url": queue_url, "dlq_url": dlq_url, "cluster": cluster, "sqs_endpoint_id": sqs_endpoint_id}),
        "commands": [
            "terraform output -json > terraform-output.json",
            "python scripts/sqs_audit_deployment_readiness.py --terraform-output-json terraform-output.json --live",
            "aws sqs get-queue-attributes --attribute-names All",
            "aws cloudwatch describe-alarms --alarm-names <audit_sqs.alarm_names>",
            "aws iam simulate-principal-policy for producer/consumer task roles",
            "aws ec2 describe-vpc-endpoints --vpc-endpoint-ids <network_path.interface_endpoint_ids.sqs>",
            "aws ecs describe-services and describe-task-definition for backend/gateway/agent/audit_consumer",
        ],
        "checks": checks,
        "collection_errors": redact({
            "queue": queue_reason,
            "dlq": dlq_reason,
            "alarms": alarm_reason,
            "endpoint": endpoint_reason,
        }),
        "safety": {
            "read_only_by_default": True,
            "run_canary_requested": args.run_canary,
            "never_consumes_or_deletes_ordinary_queue_messages": True,
            "never_performs_cutover": True,
        },
    }

    Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output_json).write_text(json.dumps(redact(payload), indent=2, sort_keys=True), encoding="utf-8")
    md = [
        "# SQS FIFO audit deployment readiness",
        "",
        f"Mode: `{payload['mode']}`",
        "",
        "This collector is read-only by default and never performs cutover.",
        "",
        "| Check | Status | Evidence |",
        "|---|---|---|",
    ]
    md.extend(f"| {item['name']} | {item['status']} | {item['evidence']} |" for item in checks)
    md.extend(["", "## Commands", "", *[f"- `{command}`" for command in payload["commands"]], ""])
    Path(args.output_md).write_text("\n".join(md), encoding="utf-8")
    print(json.dumps(redact(payload), indent=2, sort_keys=True))
    return 1 if any(item["status"] == FAIL for item in checks) else 0


if __name__ == "__main__":
    sys.exit(main())
