"""Fail-closed ECR release inventory, verification, protection, and lifecycle preview."""

import argparse
import datetime as dt
import json
import re
import subprocess
import time
from pathlib import Path

try:
    from scripts.container_vulnerability_policy import active_exceptions
except ModuleNotFoundError:
    from container_vulnerability_policy import active_exceptions


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PROTECTED_PREFIXES = ("release-", "rollback-")
INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)


def run_json(command: list[str]) -> dict:
    output = subprocess.check_output(command + ["--output", "json"], text=True)
    return json.loads(output)


def aws(*args: str) -> dict:
    return run_json(["aws", *args])


def parse_image(reference: str) -> tuple[str, str, str]:
    match = re.fullmatch(r"([^/]+)/(.+)@(sha256:[0-9a-f]{64})", reference)
    if not match:
        raise ValueError(f"image is not an immutable registry digest: {reference}")
    return match.group(1), match.group(2), match.group(3)


def load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path: str, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def task_images(task_definition: str) -> list[dict]:
    task = aws("ecs", "describe-task-definition", "--task-definition", task_definition)["taskDefinition"]
    return [{"container": item["name"], "image": item["image"]} for item in task["containerDefinitions"]]


def inventory(clusters: list[str]) -> dict:
    records = []
    for cluster in clusters:
        services = aws("ecs", "list-services", "--cluster", cluster).get("serviceArns", [])
        for offset in range(0, len(services), 10):
            described = aws("ecs", "describe-services", "--cluster", cluster, "--services", *services[offset:offset + 10])
            if described.get("failures"):
                raise RuntimeError(f"failed to describe ECS services: {described['failures']}")
            for service in described["services"]:
                records.append({
                    "cluster": cluster,
                    "service": service["serviceName"],
                    "task_definition": service["taskDefinition"],
                    "images": task_images(service["taskDefinition"]),
                })
    return {"captured_at": dt.datetime.now(dt.timezone.utc).isoformat(), "services": records}


def image_manifest(repository: str, digest: str) -> tuple[str, str]:
    response = aws(
        "ecr", "batch-get-image", "--repository-name", repository,
        "--image-ids", f"imageDigest={digest}",
    )
    if response.get("failures") or len(response.get("images", [])) != 1:
        raise RuntimeError(f"manifest unavailable for {repository}@{digest}: {response.get('failures')}")
    image = response["images"][0]
    manifest = image["imageManifest"]
    media_type = image.get("imageManifestMediaType") or json.loads(manifest).get("mediaType")
    return manifest, media_type


def put_protection(repository: str, digest: str, tag: str) -> bool:
    existing = aws(
        "ecr", "batch-get-image", "--repository-name", repository,
        "--image-ids", f"imageTag={tag}",
    )
    images = existing.get("images", [])
    if images:
        if images[0]["imageId"]["imageDigest"] != digest:
            raise RuntimeError(f"protected tag {repository}:{tag} already points to another digest")
        return False
    manifest, media_type = image_manifest(repository, digest)
    aws(
        "ecr", "put-image", "--repository-name", repository, "--image-tag", tag,
        "--image-manifest", manifest, "--image-manifest-media-type", media_type,
    )
    return True


def delete_tag(repository: str, tag: str) -> None:
    response = aws("ecr", "batch-delete-image", "--repository-name", repository, "--image-ids", f"imageTag={tag}")
    if response.get("failures"):
        raise RuntimeError(f"failed to remove {repository}:{tag}: {response['failures']}")


def protected_entries(tfvars: dict, deployed: dict, release_id: str) -> list[dict]:
    entries = []
    controlled_repositories = {parse_image(reference)[:2] for reference in tfvars["container_images"].values()}
    for service, reference in tfvars["container_images"].items():
        _, repository, digest = parse_image(reference)
        entries.append({"service": service, "repository": repository, "digest": digest, "tag": f"release-{release_id}", "kind": "release"})
    for record in deployed.get("services", []):
        for image in record.get("images", []):
            try:
                registry, repository, digest = parse_image(image["image"])
            except ValueError:
                raise ValueError(f"deployed image is mutable: {image['image']}")
            if (registry, repository) not in controlled_repositories:
                continue
            service = re.sub(r"[^a-z0-9_.-]", "-", record["service"].lower())
            entries.append({"service": record["service"], "repository": repository, "digest": digest, "tag": f"rollback-{release_id}-{service}-{digest[7:19]}", "kind": "rollback"})
    return list({(item["repository"], item["digest"], item["tag"]): item for item in entries}.values())


def expand_platform_entries(entries: list[dict]) -> list[dict]:
    expanded = list(entries)
    for item in entries:
        manifest, media_type = image_manifest(item["repository"], item["digest"])
        if media_type in INDEX_TYPES:
            for platform, digest in child_digests(manifest).items():
                child = dict(item)
                child.update({"digest": digest, "tag": f"{item['tag']}-{platform}", "platform": f"linux/{platform}"})
                expanded.append(child)
    return list({(item["repository"], item["digest"], item["tag"]): item for item in expanded}.values())


def protect(args) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", args.release_id):
        raise ValueError("release_id contains unsupported tag characters")
    today = dt.datetime.now(dt.timezone.utc).date()
    for name, value in (("rollback_until", args.rollback_until), ("database_compatible_until", args.database_compatible_until)):
        if dt.date.fromisoformat(value) < today:
            raise ValueError(f"{name} must not be in the past")
    deployed = load(args.inventory)
    for path in args.additional_inventory:
        deployed.setdefault("services", []).extend(load(path).get("services", []))
    entries = expand_platform_entries(protected_entries(load(args.tfvars), deployed, args.release_id))
    created = []
    try:
        for item in entries:
            if put_protection(item["repository"], item["digest"], item["tag"]):
                created.append(item)
        for repository in {item["repository"] for item in entries if item["kind"] == "release"}:
            delete_tag(repository, f"candidate-{args.release_id}")
    except Exception:
        for item in reversed(created):
            subprocess.run([
                "aws", "ecr", "batch-delete-image", "--repository-name", item["repository"],
                "--image-ids", f"imageTag={item['tag']}",
            ], check=False, capture_output=True)
        raise
    write(args.output, {
        "schema_version": 1,
        "release_id": args.release_id,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "rollback_protected_until": args.rollback_until,
        "database_compatible_until": args.database_compatible_until,
        "items": entries,
        "status": "PROTECTED",
    })


def child_digests(manifest: str) -> dict[str, str]:
    payload = json.loads(manifest)
    result = {}
    for descriptor in payload.get("manifests", []):
        platform = descriptor.get("platform", {})
        if platform.get("os") == "linux" and platform.get("architecture") in {"amd64", "arm64"}:
            result[platform["architecture"]] = descriptor["digest"]
    return result


def verify(args) -> None:
    tfvars = load(args.tfvars)
    policy = load(args.vulnerability_policy)
    results = []
    for service, reference in tfvars["container_images"].items():
        registry, repository, digest = parse_image(reference)
        repository_info = aws("ecr", "describe-repositories", "--repository-names", repository)["repositories"][0]
        if repository_info["imageTagMutability"] != "IMMUTABLE" or not repository_info["imageScanningConfiguration"]["scanOnPush"]:
            raise RuntimeError(f"{repository} must be immutable with scan-on-push")
        manifest, media_type = image_manifest(repository, digest)
        if media_type not in INDEX_TYPES:
            raise RuntimeError(f"{reference} is not a multi-platform image index")
        children = child_digests(manifest)
        if set(children) != {"amd64", "arm64"}:
            raise RuntimeError(f"{reference} must contain exactly linux/amd64 and linux/arm64")
        architecture = tfvars.get("service_cpu_architectures", {}).get(service, "X86_64")
        expected = {"X86_64": "amd64", "ARM64": "arm64"}.get(architecture)
        if expected not in children:
            raise RuntimeError(f"{service} does not contain configured architecture {architecture}")
        scans = {}
        allowed = set(active_exceptions(policy, service.replace("_", "-"), dt.datetime.now(dt.timezone.utc).date()))
        for platform, child in children.items():
            deadline = time.monotonic() + args.scan_wait
            while True:
                scan = aws("ecr", "describe-image-scan-findings", "--repository-name", repository, "--image-id", f"imageDigest={child}")
                status = scan.get("imageScanStatus", {}).get("status")
                if status == "COMPLETE":
                    break
                if status in {"FAILED", "UNSUPPORTED_IMAGE", "SCAN_ELIGIBILITY_EXPIRED", "FINDINGS_UNAVAILABLE"} or time.monotonic() >= deadline:
                    raise RuntimeError(f"scan unavailable for {repository}@{child}: {status}")
                time.sleep(5)
            findings = scan.get("imageScanFindings", {}).get("findings", [])
            blocking = [item["name"] for item in findings if item.get("severity") in policy["fail_severities"] and item["name"] not in allowed]
            if blocking:
                raise RuntimeError(f"blocking vulnerabilities in {repository}@{child}: {blocking}")
            scans[platform] = {"digest": child, "status": status, "blocking_findings": blocking, "active_exceptions": sorted(allowed)}
        subprocess.run([
            "cosign", "verify", "--certificate-identity", args.identity,
            "--certificate-oidc-issuer", args.issuer, f"{registry}/{repository}@{digest}",
        ], check=True, capture_output=True, text=True)
        results.append({"service": service, "image": reference, "architecture": architecture, "scans": scans, "signature": "VERIFIED"})
    write(args.output, {"verified_at": dt.datetime.now(dt.timezone.utc).isoformat(), "images": results, "status": "PASS"})


def preview(args) -> None:
    repositories = load(args.repositories)
    inventory_payload = load(args.inventory)
    protected_digests = {
        parse_image(image["image"])[2]
        for service in inventory_payload.get("services", []) for image in service.get("images", [])
    }
    policy = json.dumps(load(args.policy), separators=(",", ":"))
    evidence = []
    for repository_url in repositories.values():
        repository = repository_url.split("/", 1)[1]
        aws("ecr", "start-lifecycle-policy-preview", "--repository-name", repository, "--lifecycle-policy-text", policy)
        deadline = time.monotonic() + args.wait
        while True:
            result = aws("ecr", "get-lifecycle-policy-preview", "--repository-name", repository, "--max-results", "1000")
            status = result.get("status")
            if status == "COMPLETE":
                break
            if status == "FAILED" or time.monotonic() >= deadline:
                raise RuntimeError(f"lifecycle preview failed for {repository}: {status}")
            time.sleep(5)
        for item in result.get("previewResults", []):
            tags = item.get("imageTags") or []
            if item.get("action", {}).get("type") == "EXPIRE" and (
                item["imageDigest"] in protected_digests or any(tag.startswith(PROTECTED_PREFIXES) for tag in tags)
            ):
                raise RuntimeError(f"lifecycle policy would expire protected image {repository}@{item['imageDigest']}")
        evidence.append({"repository": repository, "status": status, "summary": result.get("summary", {})})
    write(args.output, {"previewed_at": dt.datetime.now(dt.timezone.utc).isoformat(), "repositories": evidence, "status": "PASS"})


def unprotect(args) -> None:
    record = load(args.record)
    now = dt.datetime.fromisoformat(args.now).date() if args.now else dt.datetime.now(dt.timezone.utc).date()
    windows = [dt.date.fromisoformat(record[key]) for key in ("rollback_protected_until", "database_compatible_until")]
    if any(now < value for value in windows):
        raise RuntimeError("rollback and database compatibility windows have not both closed")
    deployed = load(args.current_inventory)
    active = {parse_image(image["image"])[2] for service in deployed.get("services", []) for image in service.get("images", [])}
    for item in record["items"]:
        if item["digest"] in active:
            raise RuntimeError(f"refusing to unprotect deployed digest {item['digest']}")
    for item in record["items"]:
        delete_tag(item["repository"], item["tag"])


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    command = commands.add_parser("inventory")
    command.add_argument("--cluster", action="append", required=True)
    command.add_argument("--output", required=True)
    command.set_defaults(action=lambda args: write(args.output, inventory(args.cluster)))
    command = commands.add_parser("protect")
    command.add_argument("--tfvars", required=True); command.add_argument("--inventory", required=True)
    command.add_argument("--additional-inventory", action="append", default=[])
    command.add_argument("--release-id", required=True); command.add_argument("--rollback-until", required=True)
    command.add_argument("--database-compatible-until", required=True); command.add_argument("--output", required=True)
    command.set_defaults(action=protect)
    command = commands.add_parser("verify")
    command.add_argument("--tfvars", required=True); command.add_argument("--identity", required=True)
    command.add_argument("--issuer", default="https://token.actions.githubusercontent.com")
    command.add_argument("--vulnerability-policy", default="infra/security/container-vulnerability-policy.json")
    command.add_argument("--scan-wait", type=int, default=600); command.add_argument("--output", required=True)
    command.set_defaults(action=verify)
    command = commands.add_parser("preview")
    command.add_argument("--repositories", required=True); command.add_argument("--policy", required=True)
    command.add_argument("--inventory", required=True); command.add_argument("--wait", type=int, default=300)
    command.add_argument("--output", required=True); command.set_defaults(action=preview)
    command = commands.add_parser("unprotect")
    command.add_argument("--record", required=True); command.add_argument("--current-inventory", required=True)
    command.add_argument("--now"); command.set_defaults(action=unprotect)
    return root


if __name__ == "__main__":
    arguments = parser().parse_args()
    arguments.action(arguments)
