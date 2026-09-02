#!/usr/bin/env python3
"""Generate reproducible ARM64/AMD64 manifest evidence for AuthClaw runtime images."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "AWS_DEPLOYMENT_READINESS_TASK_LIST.md"


SERVICE_DOCKERFILES = {
    "backend": "backend/Dockerfile.demo",
    "agent": "services/agent/Dockerfile",
    "gateway": "gateway/Dockerfile.demo",
    "console": "console/Dockerfile",
    "audit_consumer": "audit_consumer/Dockerfile",
    "opa": "infra/opa/Dockerfile",
    "presidio": "infra/presidio/Dockerfile",
}

COMPOSE_FILES = [
    "docker-compose.yml",
    "docker-compose.full.yml",
    "docker-compose.audit-e2e.yml",
    "docker-compose.demo.yml.disabled",
]

TERRAFORM_FILES = [
    "infra/terraform/main.tf",
    "infra/terraform/modules/regional_stack/main.tf",
    "infra/terraform/variables.tf",
    "infra/terraform/registry.tf",
]

CI_WORKFLOWS = [
    ".github/workflows/ci.yml",
    ".github/workflows/deploy-controlled-beta.yml",
]

FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=[^\s]+\s+)?(?P<image>[^\\s]+)", re.IGNORECASE)
IMAGE_RE = re.compile(r"(?i)^\s*image:\s*(?P<image>\S+)")
TF_IMAGE_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*\"(?P<value>[^\"]+)\"")
PLATFORM_RE = re.compile(r"platforms?:\s*([\"']?[\w/,-\s]+[\"']?)")


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=False, capture_output=True, text=True)


def parse_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def manifest_from_imagetools(image: str) -> Dict[str, object]:
    cmd = ["docker", "buildx", "imagetools", "inspect", image, "--format", "json"]
    proc = run_cmd(cmd)
    if proc.returncode != 0:
        return {"status": "error", "stderr": (proc.stderr or proc.stdout).strip()}
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"status": "error", "stderr": f"Invalid JSON from imagetools: {exc}"}
    return {"status": "ok", "payload": payload}


def extract_dockerfile_images(path: Path) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    content = parse_file(path)
    for idx, line in enumerate(content.splitlines(), start=1):
        m = FROM_RE.search(line)
        if m:
            items.append({"image": m.group("image"), "line": str(idx), "source": f"{path.as_posix()}:{idx}"})
    return items


def extract_compose_images(path: Path) -> List[str]:
    images: List[str] = []
    for line in parse_file(path).splitlines():
        m = IMAGE_RE.search(line)
        if m:
            images.append(m.group("image"))
    return images


def extract_terraform_images(path: Path) -> List[Dict[str, str]]:
    out = []
    for line in parse_file(path).splitlines():
        m = TF_IMAGE_RE.search(line)
        if m:
            out.append({"image": m.group("value"), "line": ""})
    return out


def extract_ci_platforms(path: Path) -> List[str]:
    text = parse_file(path)
    matches = PLATFORM_RE.findall(text)
    platforms = set()
    for match in matches:
        value = match.strip().strip("\"'")
        for part in re.split(r"[\s,\[\]]+", value):
            token = part.strip()
            if token and "linux/" in token:
                platforms.add(token)
    return sorted(platforms)


def registry_domain(image: str) -> str:
    if "@" in image:
        img = image.split("@", 1)[0]
    else:
        img = image
    return img.split("/", 1)[0] if "/" in img else "library"

def is_pinned(image: str) -> bool:
    return "@sha256:" in image


def normalize_digest_info(payload: Dict[str, object], include_single: bool = False) -> Dict[str, object]:
    if payload.get("status") != "ok":
        return {
            "manifest_list_digest": None,
            "amd64": {"supported": False, "digest": None},
            "arm64": {"supported": False, "digest": None},
            "raw_error": payload.get("stderr"),
        }

    data = payload["payload"]
    manifests = data.get("manifests", [])
    if not isinstance(manifests, list):
        manifests = []

    def find(platform: str) -> Dict[str, object]:
        for manifest in manifests:
            plat = manifest.get("platform", {})
            if f"{plat.get('os')}/{plat.get('architecture')}" == platform:
                return {"supported": True, "digest": manifest.get("digest")}
        return {"supported": False, "digest": None}

    digest = data.get("digest") if isinstance(data.get("digest"), str) else None
    return {
        "manifest_list_digest": digest,
        "amd64": find("linux/amd64"),
        "arm64": find("linux/arm64"),
        "raw_error": None,
    }


def make_record(service: str, dockerfile: str, image: str, category: str, ci_platforms: List[str], source: str = "") -> Dict[str, object]:
    source_img = registry_domain(image)
    manifest_raw = manifest_from_imagetools(image)
    digest_info = normalize_digest_info(manifest_raw)
    amd64_info = digest_info["amd64"]  # type: ignore[index]
    arm64_info = digest_info["arm64"]  # type: ignore[index]

    status = "PASS"
    rollback = False
    unsupported = []
    if digest_info["raw_error"]:  # type: ignore[index]
        status = "LIVE-EVIDENCE-PENDING"
        unsupported.append("unverifiable-manifest")
    else:
        if not is_pinned(image):
            status = "FAIL"
            unsupported.append("digest-pin-missing")
        if not amd64_info["supported"]:  # type: ignore[index]
            status = "FAIL"
            rollback = True
            unsupported.append("linux/amd64-not-present")
        if not arm64_info["supported"]:  # type: ignore[index]
            status = "FAIL"
            rollback = True
            unsupported.append("linux/arm64-not-present")

    if any(p in ci_platforms for p in ["linux/amd64", "linux/arm64"]):
        if not {"linux/amd64", "linux/arm64"}.issubset(set(ci_platforms)):
            unsupported.append("ci-platform-gap")
            if status == "PASS":
                status = "FAIL"

    return {
        "service": service,
        "dockerfile": dockerfile,
        "image": image,
        "category": category,
        "source_file": source,
        "external_image_source": source_img,
        "reference_digest_pinned": is_pinned(image),
        "manifest_list_digest": digest_info["manifest_list_digest"],  # type: ignore[index]
        "linux_amd64_supported": amd64_info["supported"],  # type: ignore[index]
        "linux_amd64_digest": amd64_info["digest"],  # type: ignore[index]
        "linux_arm64_supported": arm64_info["supported"],  # type: ignore[index]
        "linux_arm64_digest": arm64_info["digest"],  # type: ignore[index]
        "unsupported_or_unverifiable": unsupported,
        "current_ci_build_platforms": ci_platforms,
        "requires_multiarch_rollback": rollback,
        "status": status,
    }


def dedupe_records(records: Iterable[Dict[str, object]]) -> List[Dict[str, object]]:
    seen = set()
    out = []
    for rec in records:
        key = (rec["service"], rec["image"], rec["category"], rec["source_file"])
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-json", default=str(ROOT / "evidence" / "p0_04_manifest_inventory.json"))
    parser.add_argument("--output-md", default=str(ROOT / "evidence" / "p0_04_manifest_inventory.md"))
    args = parser.parse_args()

    ci_platforms = []
    for wf in CI_WORKFLOWS:
        path = ROOT / wf
        if path.exists():
            ci_platforms.extend(extract_ci_platforms(path))
    ci_platforms = sorted(set(ci_platforms))
    if not ci_platforms:
        ci_platforms = ["linux/amd64"]

    records: List[Dict[str, object]] = []

    # Dockerfile base/build/runtime images (service-specific evidence).
    for service, dockerfile in SERVICE_DOCKERFILES.items():
        df = ROOT / dockerfile
        if not df.exists():
            continue
        for entry in extract_dockerfile_images(df):
            records.append(
                make_record(
                    service=service,
                    dockerfile=dockerfile,
                    image=entry["image"],
                    category="dockerfile_base_or_build",
                    ci_platforms=ci_platforms,
                    source=entry["source"],
                )
            )

    # Compose runtime dependencies.
    for compose_file in COMPOSE_FILES:
        path = ROOT / compose_file
        if not path.exists():
            continue
        for image in extract_compose_images(path):
            records.append(
                make_record(
                    service="compose",
                    dockerfile=compose_file,
                    image=image,
                    category="compose_runtime_dependency",
                    ci_platforms=ci_platforms,
                    source=f"{compose_file}",
                )
            )

    # Terraform image strings where possible.
    for tf_file in TERRAFORM_FILES:
        path = ROOT / tf_file
        if not path.exists():
            continue
        for entry in extract_terraform_images(path):
            img = entry["image"]
            if not img.startswith(("\"","$")) and ":" in img and "/" in img or img.startswith(("ghcr.io","public.ecr.aws","ecr","docker.io")):
                continue
            for service in SERVICE_DOCKERFILES:
                records.append(
                    make_record(
                        service=service,
                        dockerfile=tf_file.replace("\\", "/"),
                        image=img,
                        category="terraform_declared_image",
                        ci_platforms=ci_platforms,
                        source=f"{tf_file}:{entry['line']}" if entry["line"] else tf_file,
                    )
                )
                break

    records = dedupe_records(records)

    runtime_services = [r for r in records if r["service"] in SERVICE_DOCKERFILES]
    runtime_with_fail = sorted({r["service"] for r in runtime_services if r["status"] == "FAIL"})
    runtime_with_pending = sorted({r["service"] for r in runtime_services if r["status"] == "LIVE-EVIDENCE-PENDING"})
    unsupported = sorted(
        {r["image"] for r in records if r["unsupported_or_unverifiable"]}
    )
    digest_gaps = sorted({r["image"] for r in records if "digest-pin-missing" in r["unsupported_or_unverifiable"]})  # type: ignore
    amd64_or_64 = sorted(
        {
            r["image"]
            for r in records
            if not (r["linux_amd64_supported"] and (r["linux_arm64_supported"] is not False))  # type: ignore[index]
        }
    )
    blockers = [
        r["image"] for r in records
        if r["status"] in {"FAIL", "LIVE-EVIDENCE-PENDING"}
    ]

    payload = {
        "source_repo": str(ROOT),
        "script": __file__,
        "python_wheel_audit_reference": str(DOCS),
        "current_ci_build_platforms": ci_platforms,
        "runtime_services": list(SERVICE_DOCKERFILES),
        "total_records": len(records),
        "status_counts": {
            "PASS": sum(1 for r in records if r["status"] == "PASS"),
            "FAIL": sum(1 for r in records if r["status"] == "FAIL"),
            "LIVE-EVIDENCE-PENDING": sum(1 for r in records if r["status"] == "LIVE-EVIDENCE-PENDING"),
        },
        "digest_pinning_gaps": digest_gaps,
        "images_requiring_rollback": runtime_with_fail,
        "ci_platform_gaps": [r["image"] for r in records if "ci-platform-gap" in r["unsupported_or_unverifiable"]],  # type: ignore
        "records": records,
        "blockers": sorted(set(blockers)),
        "unsupported_or_unverifiable_images": unsupported,
        "arm64_missing_or_unsupported_services": runtime_with_fail + runtime_with_pending,
    }

    # Ensure output dir exists.
    json_path = Path(args.output_json)
    md_path = Path(args.output_md)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(json.dumps(payload, indent=2))

    md_lines = [
        "# P0-04 Image Manifest Evidence",
        "",
        f"- Source: `{payload['source_repo']}`",
        f"- Python wheel audit reference: `{payload['python_wheel_audit_reference']}`",
        f"- Current CI build platforms: `{', '.join(ci_platforms)}`",
        "",
        "## Status summary",
        f"- PASS: {payload['status_counts']['PASS']}",
        f"- FAIL: {payload['status_counts']['FAIL']}",
        f"- LIVE-EVIDENCE-PENDING: {payload['status_counts']['LIVE-EVIDENCE-PENDING']}",
        "",
        "## Production runtime image inventory",
        "|service|category|source|image|pinned|amd64|arm64|status|rollback|",
        "|---|---|---|---|---|---|---|---|---|",
    ]

    for rec in sorted(records, key=lambda r: (str(r["service"]), str(r["category"]), str(r["image"]))):
        md_lines.append(
            "|{service}|{category}|{source}|{image}|{pinned}|{amd}|{arm}|{status}|{rollback}|".format(
                service=rec["service"],
                category=rec["category"],
                source=rec["source_file"],
                image=rec["image"],
                pinned="yes" if rec["reference_digest_pinned"] else "no",
                amd="yes" if rec["linux_amd64_supported"] else "no",
                arm="yes" if rec["linux_arm64_supported"] else "no",
                status=rec["status"],
                rollback="yes" if rec["requires_multiarch_rollback"] else "no",
            )
        )

    md_lines.extend(
        [
            "",
            "## Blockers",
            "",
        ]
    )
    for blocker in payload["blockers"]:
        md_lines.append(f"- {blocker}")

    md_lines.extend(
        [
            "",
            "## Failures requiring rollout/baseline work",
            f"- images missing digest pin: {', '.join(payload['digest_pinning_gaps']) or 'none'}",
            f"- services requiring ARM64 remediation/rollback: {', '.join(payload['images_requiring_rollback']) or 'none'}",
            "",
            "## Next Task 2 follow-up",
            "- Replace or rebuild images that lack ARM64 support.",
            "- Add digest pinned, multi-arch manifest publishing in CI (`platforms: linux/amd64,linux/arm64`) and promote signed manifests per service.",
            "- Re-run this manifest check script and attach artifacts to release evidence.",
        ]
    )

    md_path.write_text("\n".join(md_lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
