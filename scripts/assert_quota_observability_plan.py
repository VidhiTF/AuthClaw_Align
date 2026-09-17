"""Fail CI unless the Terraform plan wires quota metrics through alert delivery."""
import json
import sys
from pathlib import Path


def main(path: str) -> int:
    plan = json.loads(Path(path).read_text(encoding="utf-8"))
    primary = plan["configuration"]["root_module"]["module_calls"]["primary"]["module"]
    resources = {resource["address"]: resource for resource in primary["resources"]}
    required = {
        "aws_prometheus_workspace.quota": "aws_prometheus_workspace",
        "aws_prometheus_rule_group_namespace.quota": "aws_prometheus_rule_group_namespace",
        "aws_prometheus_alert_manager_definition.quota": "aws_prometheus_alert_manager_definition",
        "aws_iam_role.quota_alertmanager": "aws_iam_role",
        "aws_secretsmanager_secret.quota_metrics": "aws_secretsmanager_secret",
        "aws_ecs_task_definition.quota_collector": "aws_ecs_task_definition",
        "aws_ecs_service.quota_collector": "aws_ecs_service",
        "aws_iam_role_policy.quota_collector": "aws_iam_role_policy",
        "aws_iam_role_policy.quota_collector_execution": "aws_iam_role_policy",
        "aws_iam_role_policy.quota_alertmanager": "aws_iam_role_policy",
    }
    errors = [f"missing {address}" for address, kind in required.items()
              if address not in resources or resources[address]["type"] != kind]

    def references(address: str, expression: str) -> set:
        return set(resources.get(address, {}).get("expressions", {}).get(expression, {}).get("references", []))

    if "path.module" not in references("aws_prometheus_rule_group_namespace.quota", "data"):
        errors.append("quota rules are not loaded from the checked-in rule file")
    task_refs = references("aws_ecs_task_definition.quota_collector", "container_definitions")
    if "local.quota_collector_config" not in task_refs:
        errors.append("collector task does not use the quota scrape/remote-write configuration")
    if "aws_secretsmanager_secret.quota_metrics.arn" not in task_refs:
        errors.append("collector task does not inject the dedicated metrics credential")
    alert_refs = references("aws_prometheus_alert_manager_definition.quota", "definition")
    if not {"var.quota_alert_sns_topic_arns", "aws_iam_role.quota_alertmanager[0].arn"} <= alert_refs:
        errors.append("Alertmanager does not route through the approved SNS role and topics")
    trust_refs = references("aws_iam_role.quota_alertmanager", "assume_role_policy")
    if "aws_prometheus_workspace.quota[0].arn" not in trust_refs:
        errors.append("Alertmanager role trust is not bound to the exact quota workspace")
    remote_refs = references("aws_iam_role_policy.quota_collector", "policy")
    if "aws_prometheus_workspace.quota[0].arn" not in remote_refs:
        errors.append("collector remote-write IAM policy is not scoped to the quota workspace")
    execution_refs = references("aws_iam_role_policy.quota_collector_execution", "policy")
    if not {"aws_secretsmanager_secret.quota_metrics.arn", "aws_kms_key.main.arn"} <= execution_refs:
        errors.append("collector execution policy cannot read only the KMS-protected metrics secret")

    changes = {change["address"]: change for change in plan.get("resource_changes", [])}
    alert_policy = changes.get("module.primary.aws_iam_role_policy.quota_alertmanager[0]", {}).get("change", {}).get("after", {}).get("policy", "")
    if "arn:aws:sns:" not in alert_policy or "sns:Publish" not in alert_policy:
        errors.append("planned Alertmanager role has no concrete SNS publish receiver")
    # The collector definition is unknown in a real plan because it embeds
    # resource ARNs. Verify its plan references above and its concrete scrape
    # contract here; Terraform validate covers the surrounding HCL structure.
    source = (Path(__file__).resolve().parents[1] / "infra" / "terraform" /
              "modules" / "regional_stack" / "quota_observability.tf").read_text(encoding="utf-8")
    if ("metrics_path    = \"/internal/metrics/quota\"" not in source or
            'credentials = "$${env:AUTHCLAW_QUOTA_METRICS_SECRET}"' not in source or
            '{ name = "AUTHCLAW_QUOTA_METRICS_SECRET", valueFrom = aws_secretsmanager_secret.quota_metrics.arn }' not in source):
        errors.append("collector scrape is not authenticated against the internal quota metrics route")

    if errors:
        print("Quota observability plan invalid: " + "; ".join(errors), file=sys.stderr)
        return 1
    print("Quota observability plan includes scrape, remote write, rules, Alertmanager, and SNS routing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
