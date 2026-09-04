"""Validate planned IAM documents without writing Terraform plans or secret values."""
import argparse
import json
import subprocess
import sys


def policy_documents(module):
    for resource in module.get("resources", []):
        if resource["type"] in {"aws_iam_role", "aws_iam_role_policy", "aws_kms_key_policy", "aws_sqs_queue_policy"}:
            field = "assume_role_policy" if resource["type"] == "aws_iam_role" else "policy"
            value = resource.get("values", {}).get(field)
            if not value:
                raise ValueError(f"Unresolved policy: {resource['address']}")
            yield resource["address"], resource["type"], json.loads(value)
    for child in module.get("child_modules", []):
        yield from policy_documents(child)


def review(plan, analyzer=None):
    evidence = []
    for address, kind, policy in policy_documents(plan["planned_values"]["root_module"]):
        if policy.get("Version") != "2012-10-17" or not policy.get("Statement"):
            raise ValueError(f"Invalid policy: {address}")
        for statement in policy["Statement"]:
            if statement.get("Effect") == "Allow" and kind == "aws_iam_role_policy":
                actions = statement.get("Action", [])
                actions = [actions] if isinstance(actions, str) else actions
                resources = statement.get("Resource", [])
                resources = [resources] if isinstance(resources, str) else resources
                if any("*" in action for action in actions):
                    raise ValueError(f"Wildcard runtime/execution action: {address}")
                if "*" in resources and actions != ["ecr:GetAuthorizationToken"]:
                    raise ValueError(f"Unscoped runtime/execution resource: {address}")
        findings = analyzer(kind, policy) if analyzer else []
        evidence.append({"address": address, "findings": findings})
    if not evidence:
        raise ValueError("No IAM policies found; refusing empty evidence")
    return evidence


def access_analyzer(kind, policy):
    args = ["aws", "accessanalyzer", "validate-policy", "--policy-document",
            json.dumps(policy), "--policy-type",
            "IDENTITY_POLICY" if kind == "aws_iam_role_policy" else "RESOURCE_POLICY",
            "--output", "json"]
    if kind == "aws_iam_role":
        args += ["--validate-policy-resource-type", "AWS::IAM::AssumeRolePolicyDocument"]
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise ValueError("Access Analyzer failed; review runner permissions/connectivity")
    return [{"type": f["findingType"], "code": f["issueCode"]}
            for f in json.loads(result.stdout)["findings"]]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--access-analyzer", action="store_true")
    args = parser.parse_args()
    try:
        evidence = review(json.load(sys.stdin), access_analyzer if args.access_analyzer else None)
        print(json.dumps({"access_analyzer": args.access_analyzer, "policies": evidence}))
        sys.exit(any(f["type"] in {"ERROR", "SECURITY_WARNING"}
                     for item in evidence for f in item["findings"]))
    except (ValueError, KeyError) as exc:
        # Never echo input or provider responses: a plan can contain historical secrets.
        print("IAM evidence validation failed", file=sys.stderr)
        sys.exit(1)
