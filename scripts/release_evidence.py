"""P0-16/18 release ledger: generate pending evidence; reject incomplete promotion."""
import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path


STEPS = {
    1: "decisions configuration_inventory",
    2: "supply_chain ecr_protection",
    3: "aws_foundation identity state network edge secrets observability",
    4: "immutable_staging",
    5: "transport_abstraction",
    6: "transport_cutover transport_reconciliation",
    7: "colocation",
    8: "arm64_startup arm64_health fargate_canary",
    9: "database_migration pool_isolation rls_isolation backup restore database_rollback",
    10: "adr2_compute",
    11: ("full_ci terraform_format terraform_validate terraform_security terraform_plan "
         "arm64_startup arm64_health database_migration pool_isolation rls_isolation backup restore database_rollback "
         "authentication authorization cors cookies oauth tenant_isolation fail_closed "
         "audit_append outbox transport dlq clickhouse export replay chain_verification "
         "task_failure az_failure queue_failure redis_failover database_failover regional_failover "
         "direct_origin_denial internal_ports iam_least_privilege secret_rotation log_redaction "
         "ecr_protection rollback_drill"),
    12: "production_promotion production_health",
}
OPTIONAL = {"adr2_compute", "az_failure", "queue_failure", "redis_failover", "database_failover", "regional_failover"}
TASK_DEFINITION = re.compile(
    r"arn:(?:aws|aws-us-gov|aws-cn):ecs:[a-z0-9-]+:\d{12}:task-definition/[A-Za-z0-9_-]+:\d+"
)


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed > dt.datetime.now(dt.timezone.utc):
        raise ValueError("evidence time must be timezone-aware and not in the future")
    return parsed


def artifact(root, record):
    path = (root / record["path"]).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("artifact must be a file inside the evidence package")
    if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
        raise ValueError(f"artifact checksum mismatch: {record['path']}")


def artifact_reference(root, value):
    path = (value if value.is_absolute() else root / value).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError("artifact must be a file inside the evidence package")
    return {"path": path.relative_to(root.resolve()).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def images(values):
    if not isinstance(values, dict) or not values or not all(
        re.fullmatch(r"[^/\s]+/[^\s]+@sha256:[0-9a-f]{64}", value)
        for value in values.values()
    ):
        raise ValueError("all images must be immutable registry digests")


def task_definitions(current, target):
    if (not isinstance(current, dict) or not isinstance(target, dict) or not current or
            set(current) != set(target) or
            not all(isinstance(name, str) and name.strip() and
                    isinstance(arn, str) and TASK_DEFINITION.fullmatch(arn)
                    for values in (current, target) for name, arn in values.items())):
        raise ValueError("current and target task-definition revisions must be complete matching ARN maps")


def validate(payload, root, through=11):
    """Validate the ledger and raw evidence, never convert operator assertions to AWS proof."""
    if payload["schema_version"] != 1 or through not in STEPS:
        raise ValueError("unsupported schema or step")
    release = payload["release"]
    images(release["images"])
    images(release["previous_images"])
    if not re.fullmatch(r"[0-9a-f]{40}", release["commit"]):
        raise ValueError("release commit must be a full Git SHA")
    artifact(root, release["configuration"])
    if through == 12:
        task_definitions(release["current_task_definitions"], release["target_task_definitions"])
    for field in ("change_window", "communication_channel", "release_approver", "database_approver", "rollback_owner"):
        if not isinstance(release[field], str) or not release[field].strip():
            raise ValueError(f"missing {field}")
    if release["migration_mode"] != "expand" or release["previous_digest_compatible"] is not True:
        raise ValueError("contract/irreversible migration cannot share an application rollback window")
    today = dt.datetime.now(dt.timezone.utc).date()
    if dt.date.fromisoformat(release["database_compatible_until"]) < dt.date.fromisoformat(release["rollback_until"]) or dt.date.fromisoformat(release["rollback_until"]) < today:
        raise ValueError("database compatibility must cover the open rollback window")
    if [s["step"] for s in payload["steps"]] != list(STEPS):
        raise ValueError("ledger must contain each ordered step exactly once")
    last_time = None
    disruptive_releases = set()
    for step in payload["steps"][:through]:
        number = step["step"]
        if not step["release_id"].strip() or not step["approver"].strip():
            raise ValueError(f"step {number}: missing release ID or approver")
        if number in {6, 7, 8, 9, 10}:
            if step["release_id"] in disruptive_releases:
                raise ValueError("transport, placement, ARM64, database and compute require separate releases")
            disruptive_releases.add(step["release_id"])
        artifact(root, step["rollback_point"])
        required = set(STEPS[number].split())
        if set(step["checks"]) != required:
            raise ValueError(f"step {number}: missing or unexpected checks")
        times = []
        for name, check in step["checks"].items():
            if check["status"] != "PASS" and not (
                name in OPTIONAL and check["status"] == "NOT_APPLICABLE" and check.get("reason", "").strip()
            ):
                raise ValueError(f"{name}: missing passing evidence")
            if not check["approver"].strip() or not check["environment"].strip():
                raise ValueError(f"{name}: missing approver or environment")
            if not re.fullmatch(r"[0-9a-f]{40}", check["commit"]):
                raise ValueError(f"{name}: invalid commit")
            images(check["images"])
            artifact(root, check["configuration"])
            artifact(root, check["raw"])
            times.append(timestamp(check["time"]))
            if number >= 11:
                if check["commit"] != release["commit"] or check["images"] != release["images"] or check["configuration"]["sha256"] != release["configuration"]["sha256"]:
                    raise ValueError(f"{name}: evidence does not match the release")
                expected_environment = "production" if number == 12 else "staging"
                if check["environment"] != expected_environment:
                    raise ValueError(f"{name}: expected {expected_environment}")
            if name == "rollback_drill":
                seconds = check["duration_seconds"]
                if type(seconds) not in (int, float) or not 0 < seconds <= 300:
                    raise ValueError("rollback drill must finish within 300 seconds")
                if check["redeployed_images"] != release["previous_images"] or check["retained_artifacts"] is not True:
                    raise ValueError("rollback must use the real retained previous digests")
                if set(check["verified"]) != {"health", "authentication", "gateway", "audit_publication", "clickhouse_consistency"} or not all(value is True for value in check["verified"].values()):
                    raise ValueError("rollback functional checks incomplete")
        if last_time and min(times) < last_time:
            raise ValueError("steps must finish in sequence")
        last_time = max(times)


def template():
    ref = {"path": "", "sha256": ""}
    payload = {"schema_version": 1, "release": {
        **dict.fromkeys(("commit", "change_window", "communication_channel", "release_approver", "database_approver", "rollback_owner", "database_compatible_until", "rollback_until"), ""),
        "images": {}, "previous_images": {}, "configuration": ref,
        "current_task_definitions": {}, "target_task_definitions": {},
        "migration_mode": "expand", "previous_digest_compatible": False,
    }, "steps": [{"step": n, "release_id": "", "approver": "", "rollback_point": ref,
                  "checks": {name: {"status": "PENDING", "environment": "production" if n == 12 else "staging",
                                    "commit": "", "images": {}, "configuration": ref, "time": "", "approver": "", "raw": ref}
                             for name in names.split()}} for n, names in STEPS.items()]}
    payload["steps"][10]["checks"]["rollback_drill"].update(
        duration_seconds=0, retained_artifacts=False, redeployed_images={},
        verified=dict.fromkeys(("health", "authentication", "gateway", "audit_publication", "clickhouse_consistency"), False))
    return payload


def record(payload, root, *, step_number, check_name, raw, rollback_point,
           release_id, approver, environment, recorded_at, status, reason,
           replace, duration_seconds, retained_artifacts, verified_all):
    """Attach operator-supplied raw evidence without manufacturing proof."""
    release = payload["release"]
    if not re.fullmatch(r"[0-9a-f]{40}", release["commit"]):
        raise ValueError("populate the full release commit before recording evidence")
    images(release["images"])
    artifact(root, release["configuration"])
    step = next((item for item in payload["steps"] if item["step"] == step_number), None)
    if step is None or check_name not in step["checks"]:
        raise ValueError("check does not belong to the selected step")
    check = step["checks"][check_name]
    if check["status"] != "PENDING" and not replace:
        raise ValueError("check already recorded; use --replace to supersede it")
    if step["release_id"] and step["release_id"] != release_id:
        raise ValueError("release ID conflicts with another check in this step")
    if status == "NOT_APPLICABLE" and (check_name not in OPTIONAL or not reason.strip()):
        raise ValueError("NOT_APPLICABLE requires an eligible check and a reason")
    if status == "PASS" and reason:
        raise ValueError("--reason is only valid with NOT_APPLICABLE")
    if check_name == "rollback_drill":
        if (type(duration_seconds) not in (int, float) or
                not 0 < duration_seconds <= 300 or
                not retained_artifacts or not verified_all):
            raise ValueError("rollback drill requires duration <=300s, retained artifacts and all functional verifications")
        images(release["previous_images"])
    timestamp(recorded_at)
    raw_ref = artifact_reference(root, raw)
    if rollback_point:
        step["rollback_point"] = artifact_reference(root, rollback_point)
    else:
        artifact(root, step["rollback_point"])
    step.update(release_id=release_id, approver=approver)
    check.update(status=status, environment=environment or check["environment"],
                 commit=release["commit"], images=release["images"],
                 configuration=release["configuration"], time=recorded_at,
                 approver=approver, raw=raw_ref)
    check.pop("reason", None)
    if status == "NOT_APPLICABLE":
        check["reason"] = reason.strip()
    if check_name == "rollback_drill":
        check.update(duration_seconds=duration_seconds, retained_artifacts=True,
                     redeployed_images=release["previous_images"],
                     verified=dict.fromkeys(
                         ("health", "authentication", "gateway", "audit_publication", "clickhouse_consistency"), True))
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "record", "check"))
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--through", type=int, default=11, choices=STEPS)
    parser.add_argument("--step", type=int, choices=STEPS)
    parser.add_argument("--name")
    parser.add_argument("--raw", type=Path)
    parser.add_argument("--rollback-point", type=Path)
    parser.add_argument("--release-id")
    parser.add_argument("--approver")
    parser.add_argument("--environment")
    parser.add_argument("--time", default=None)
    parser.add_argument("--status", choices=("PASS", "NOT_APPLICABLE"), default="PASS")
    parser.add_argument("--reason", default="")
    parser.add_argument("--replace", action="store_true")
    parser.add_argument("--duration-seconds", type=float)
    parser.add_argument("--retained-artifacts", action="store_true")
    parser.add_argument("--verified-all", action="store_true")
    args = parser.parse_args()
    if args.command == "init":
        with args.ledger.open("x", encoding="utf-8") as stream:
            json.dump(template(), stream, indent=2)
            stream.write("\n")
        return 0
    if args.command == "record":
        if not all((args.step, args.name, args.raw, args.release_id, args.approver)):
            parser.error("record requires --step, --name, --raw, --release-id and --approver")
        try:
            payload = json.loads(args.ledger.read_text(encoding="utf-8"))
            recorded_at = args.time or dt.datetime.now(dt.timezone.utc).isoformat()
            record(payload, args.ledger.parent, step_number=args.step,
                   check_name=args.name, raw=args.raw,
                   rollback_point=args.rollback_point, release_id=args.release_id,
                   approver=args.approver, environment=args.environment,
                   recorded_at=recorded_at, status=args.status, reason=args.reason,
                   replace=args.replace, duration_seconds=args.duration_seconds,
                   retained_artifacts=args.retained_artifacts,
                   verified_all=args.verified_all)
            temporary = args.ledger.with_suffix(args.ledger.suffix + ".tmp")
            temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            temporary.replace(args.ledger)
        except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
            print(f"BLOCKED: {exc}")
            return 1
        print(f"PASS: recorded step {args.step} {args.name}")
        return 0
    try:
        validate(json.loads(args.ledger.read_text(encoding="utf-8")), args.ledger.parent, args.through)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print(f"BLOCKED: {exc}")
        return 1
    print(f"PASS: release evidence through step {args.through}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
