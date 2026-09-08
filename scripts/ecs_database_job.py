"""Run an existing immutable ECS database task; fail closed before service rollout."""
import argparse
import json
from pathlib import Path

try:
    from scripts.ecr_release_control import aws, parse_image
except ModuleNotFoundError:
    from ecr_release_control import aws, parse_image


def run_job(gate, job, output):
    definition = gate["task_definitions"][job]
    task = aws("ecs", "describe-task-definition", "--task-definition", definition)["taskDefinition"]
    if not task["containerDefinitions"]:
        raise ValueError("database task has no containers")
    for container in task["containerDefinitions"]:
        parse_image(container["image"])
    launch = gate["launch_model"]
    command = ["ecs", "run-task", "--cluster", gate["cluster"], "--task-definition", task["taskDefinitionArn"]]
    if launch["mode"] == "FARGATE":
        if "FARGATE" not in task.get("requiresCompatibilities", []):
            raise ValueError("database task is not Fargate compatible")
        command += ["--launch-type", "FARGATE"]
    elif launch["mode"] == "EC2_GRAVITON" and launch.get("capacity_provider_name"):
        if "EC2" not in task.get("requiresCompatibilities", []):
            raise ValueError("database task is not EC2 compatible")
        command += ["--capacity-provider-strategy", json.dumps([{
            "capacityProvider": launch["capacity_provider_name"], "weight": 1, "base": 0,
        }])]
    else:
        raise ValueError("unsupported or incomplete database task launch model")
    command += ["--network-configuration", json.dumps(gate["network_configuration"])]
    started = aws(*command)
    Path(output).write_text(json.dumps(started, indent=2) + "\n", encoding="utf-8")
    if started.get("failures") or len(started.get("tasks", [])) != 1:
        raise RuntimeError("database task failed to start; service rollout blocked")
    arn = started["tasks"][0]["taskArn"]
    # AWS wait emits no JSON, unlike the read/write API wrapper.
    import subprocess
    subprocess.run(["aws", "ecs", "wait", "tasks-stopped", "--cluster", gate["cluster"], "--tasks", arn], check=True)
    result = aws("ecs", "describe-tasks", "--cluster", gate["cluster"], "--tasks", arn)
    Path(output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    tasks = result.get("tasks", [])
    if result.get("failures") or len(tasks) != 1:
        raise RuntimeError("database task result unavailable; service rollout blocked")
    finished = tasks[0]
    containers = finished.get("containers", [])
    if (finished.get("taskDefinitionArn") != task["taskDefinitionArn"] or finished.get("lastStatus") != "STOPPED"
            or {c["name"] for c in containers} != {c["name"] for c in task["containerDefinitions"]}
            or not containers or any(type(c.get("exitCode")) is not int or c["exitCode"] != 0 for c in containers)):
        raise RuntimeError("database task did not complete successfully; service rollout blocked")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gate", type=Path)
    parser.add_argument("job")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    run_job(json.loads(args.gate.read_text(encoding="utf-8")), args.job, args.output)
