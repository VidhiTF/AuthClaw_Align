import copy
import unittest

from scripts.verify_ecs_colocation import EXPECTED, verify


def task(service):
    containers = [{
        "name": service, "image": f"registry/{service}@sha256:" + "a" * 64,
        "environment": [], "dependsOn": [{"containerName": name, "condition": "HEALTHY"} for name in EXPECTED[service]],
    }]
    urls = {"gateway": [("OPA_URL", "http://127.0.0.1:8181"), ("PRESIDIO_URL", "http://127.0.0.1:3000")]}
    containers[0]["environment"] = [{"name": key, "value": value} for key, value in urls[service]]
    for name in EXPECTED[service]:
        port = "8181" if name == "opa" else "3000"
        containers.append({"name": name, "image": f"registry/{name}@sha256:" + "b" * 64,
                           "command": [f"--addr=127.0.0.1:{port}"], "essential": True,
                           "healthCheck": {"command": ["CMD", "/healthcheck"]}, "portMappings": [],
                           "readonlyRootFilesystem": True, "privileged": False,
                           "linuxParameters": {"capabilities": {"drop": ["ALL"]}}})
    return {"taskDefinitionArn": f"arn:task/{service}:7", "networkMode": "awsvpc",
            "requiresCompatibilities": ["FARGATE"], "runtimePlatform": {"cpuArchitecture": "X86_64"},
            "containerDefinitions": containers}


class ColocationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tasks = {name: (task(name), name * 8) for name in EXPECTED}

    def test_accepts_hardened_task_local_sidecars(self):
        self.assertEqual(verify(self.tasks, ["arn:service/app-opa", "arn:service/app-presidio"])["status"], "PASS")

    def test_accepts_mixed_architecture_canary(self):
        self.tasks["gateway"][0]["runtimePlatform"]["cpuArchitecture"] = "ARM64"
        result = verify(self.tasks, ["arn:service/app-opa", "arn:service/app-presidio"], {"gateway": "ARM64"})
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["architectures"]["gateway"], "ARM64")

    def test_rejects_each_release_boundary_violation(self):
        changes = [
            lambda p: p["gateway"][0].update(networkMode="bridge"),
            lambda p: p["gateway"][0]["containerDefinitions"][1].update(portMappings=[{"containerPort": 8181}]),
            lambda p: p["gateway"][0]["containerDefinitions"][1].update(image="registry/opa:latest"),
            lambda p: p["gateway"][0]["containerDefinitions"][0].update(dependsOn=[]),
            lambda p: p["gateway"][0].update(taskRoleArn="arn:role/gateway"),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                payload = copy.deepcopy(self.tasks); change(payload)
                self.assertEqual(verify(payload, ["arn:service/app-opa", "arn:service/app-presidio"])["status"], "FAIL")
        self.assertEqual(verify(self.tasks, ["arn:service/app-opa"])["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
