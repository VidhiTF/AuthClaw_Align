#!/usr/bin/env python3
import json
import sys


SQS_REQUIRED_RESOURCES = [
    "aws_sqs_queue.audit",
    "aws_sqs_queue.audit_dlq",
    'aws_iam_role.application_task["audit_consumer"]',
    "aws_iam_role_policy.audit_sqs_consumer",
    'aws_iam_role_policy.audit_sqs_producer["backend"]',
    'aws_iam_role_policy.audit_sqs_producer["gateway"]',
    "aws_cloudwatch_metric_alarm.audit_sqs",
    'aws_vpc_endpoint.interface["sqs"]',
]


def validate_plan(mode: str, plan: dict) -> None:
    addresses = {item["address"] for item in plan.get("resource_changes", [])}
    if any('aws_vpc_endpoint.gateway["dynamodb"]' in addr for addr in addresses):
        raise SystemExit("plan must not create a DynamoDB endpoint without a confirmed runtime dependency")

    sqs = {
        addr
        for addr in addresses
        if "aws_sqs_queue.audit" in addr
        or "audit_sqs" in addr
        or 'aws_vpc_endpoint.interface["sqs"]' in addr
    }
    if mode == "kafka" and sqs:
        raise SystemExit(f"kafka plan must not include SQS audit resources: {sorted(sqs)}")
    if mode == "sqs_fifo":
        missing = [name for name in SQS_REQUIRED_RESOURCES if not any(name in addr for addr in addresses)]
        if missing:
            raise SystemExit(f"sqs_fifo plan missing required resources: {missing}")
        agent_policies = [
            addr
            for addr in addresses
            if "aws_iam_role_policy.audit_sqs_producer" in addr and '["agent"]' in addr
        ]
        if agent_policies:
            raise SystemExit(f"agent must not receive canonical SQS producer policy: {agent_policies}")


def main() -> None:
    mode = sys.argv[1]
    with open(sys.argv[2], encoding="utf-8") as plan_file:
        validate_plan(mode, json.load(plan_file))


if __name__ == "__main__":
    main()
