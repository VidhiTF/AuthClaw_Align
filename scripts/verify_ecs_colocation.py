#!/usr/bin/env python3
"""Verify captured ECS task definitions for the step-7 policy co-location release."""
import argparse
import hashlib
import json
import re
from pathlib import Path


EXPECTED = {"gateway": ("opa", "presidio")}
DIGEST = re.compile(r"[^\s]+@sha256:[0-9a-f]{64}$")


def load(path):
    raw = path.read_bytes()
    value = json.loads(raw)
    return value.get("taskDefinition", value), hashlib.sha256(raw).hexdigest()


def verify(tasks, service_arns, architecture="X86_64", launch_type="FARGATE"):
    architectures = architecture if isinstance(architecture, dict) else {
        service: architecture for service in EXPECTED
    }
    errors, evidence = [], {"tasks": {}, "standalone_policy_services": []}
    for service, (task, checksum) in tasks.items():
        expected_architecture = architectures.get(service, "X86_64")
        containers = {item["name"]: item for item in task.get("containerDefinitions", [])}
        primary, sidecars = containers.get(service, {}), EXPECTED[service]
        evidence["tasks"][service] = {
            "task_definition": task.get("taskDefinitionArn"), "sha256": checksum,
            "task_role": task.get("taskRoleArn"), "images": {name: item.get("image") for name, item in containers.items()},
        }
        if task.get("networkMode") != "awsvpc": errors.append(f"{service}: networkMode must be awsvpc")
        if launch_type not in task.get("requiresCompatibilities", []): errors.append(f"{service}: launch type must include {launch_type}")
        if task.get("runtimePlatform", {}).get("cpuArchitecture") != expected_architecture: errors.append(f"{service}: architecture must be {expected_architecture}")
        if task.get("taskRoleArn"): errors.append(f"{service}: colocated policy task must not receive a task role")
        for name, item in containers.items():
            if not DIGEST.fullmatch(item.get("image", "")): errors.append(f"{service}/{name}: image is not an immutable digest")
        dependencies = {(item.get("containerName"), item.get("condition")) for item in primary.get("dependsOn", [])}
        env = {item.get("name"): item.get("value") for item in primary.get("environment", [])}
        for sidecar in sidecars:
            item = containers.get(sidecar, {})
            command = " ".join(item.get("command", []))
            port = "8181" if sidecar == "opa" else "3000"
            if not item: errors.append(f"{service}: missing {sidecar} sidecar"); continue
            if (sidecar, "HEALTHY") not in dependencies: errors.append(f"{service}: must wait for healthy {sidecar}")
            if item.get("essential") is not True or not item.get("healthCheck"): errors.append(f"{service}/{sidecar}: must be essential and healthy")
            if item.get("portMappings"): errors.append(f"{service}/{sidecar}: must not expose a task port")
            if f"127.0.0.1:{port}" not in command: errors.append(f"{service}/{sidecar}: must bind to loopback")
            caps = item.get("linuxParameters", {}).get("capabilities", {}).get("drop", [])
            if item.get("readonlyRootFilesystem") is not True or item.get("privileged") is not False or "ALL" not in caps:
                errors.append(f"{service}/{sidecar}: container hardening is incomplete")
        expected_urls = {"OPA_URL": "http://127.0.0.1:8181", "PRESIDIO_URL": "http://127.0.0.1:3000"}
        if any(env.get(name) != value for name, value in expected_urls.items()): errors.append(f"{service}: task-local policy URL mismatch")
    for arn in service_arns:
        name = arn.rsplit("/", 1)[-1]
        if re.search(r"(?:^|[-_])(opa|presidio)$", name): evidence["standalone_policy_services"].append(arn)
    standalone_names = {re.split(r"[-_]", arn.rsplit("/", 1)[-1])[-1] for arn in evidence["standalone_policy_services"]}
    if standalone_names != {"opa", "presidio"}: errors.append("independent OPA and Presidio services are required for privileged callers")
    evidence.update(status="FAIL" if errors else "PASS", errors=errors,
                    architectures={service: architectures.get(service, "X86_64") for service in EXPECTED},
                    launch_type=launch_type)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for service in EXPECTED: parser.add_argument(f"--{service}", required=True, type=Path)
    parser.add_argument("--services", required=True, type=Path, help="ecs list-services JSON")
    parser.add_argument("--architecture", choices=("X86_64", "ARM64"), default="X86_64")
    parser.add_argument("--architecture-map", default="{}",
                        help="JSON service-to-architecture map; unspecified services use --architecture")
    parser.add_argument("--launch-type", choices=("FARGATE", "EC2"), default="FARGATE")
    args = parser.parse_args()
    tasks = {name: load(getattr(args, name)) for name in EXPECTED}
    services = json.loads(args.services.read_text(encoding="utf-8")).get("serviceArns", [])
    architecture_map = json.loads(args.architecture_map)
    if not isinstance(architecture_map, dict) or any(
        value not in {"X86_64", "ARM64"} for value in architecture_map.values()
    ):
        parser.error("--architecture-map values must be X86_64 or ARM64")
    architectures = {service: architecture_map.get(service, args.architecture) for service in EXPECTED}
    result = verify(tasks, services, architectures, args.launch_type)
    print(json.dumps(result, indent=2, sort_keys=True))
    return result["status"] != "PASS"


if __name__ == "__main__":
    raise SystemExit(main())
