#!/usr/bin/env python3
import json
import sys

mode = sys.argv[1]
plan = json.load(open(sys.argv[2], encoding="utf-8"))
addresses = {item["address"] for item in plan.get("resource_changes", [])}

sqs = {addr for addr in addresses if "aws_sqs_queue.audit" in addr or "audit_sqs" in addr or 'aws_vpc_endpoint.interface["sqs"]' in addr}
required = [
    "aws_sqs_queue.audit",
    "aws_sqs_queue.audit_dlq",
    "aws_iam_role.audit_sqs_consumer",
    "aws_cloudwatch_metric_alarm.audit_sqs",
    'aws_vpc_endpoint.interface["sqs"]',
]

if mode == "kafka" and sqs:
    raise SystemExit(f"kafka plan must not include SQS audit resources: {sorted(sqs)}")
if mode == "sqs_fifo":
    missing = [name for name in required if not any(name in addr for addr in addresses)]
    if missing:
        raise SystemExit(f"sqs_fifo plan missing required resources: {missing}")
    agent_roles = [addr for addr in addresses if "aws_iam_role.audit_sqs_producer" in addr and '["agent"]' in addr]
    if agent_roles:
        raise SystemExit(f"agent must not receive canonical SQS producer role: {agent_roles}")
