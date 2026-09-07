import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import ecr_release_control as control


DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class ECRReleaseControlTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_parse_image_rejects_mutable_reference(self):
        self.assertEqual(control.parse_image(f"registry.example/team/api@{DIGEST_A}"), ("registry.example", "team/api", DIGEST_A))
        with self.assertRaisesRegex(ValueError, "not an immutable"):
            control.parse_image("registry.example/team/api:latest")

    def test_protection_set_contains_candidate_and_deployed_rollback(self):
        tfvars = {"container_images": {"backend": f"registry.example/team/backend@{DIGEST_A}"}}
        deployed = {"services": [{"service": "prod/backend", "images": [
            {"image": f"registry.example/team/backend@{DIGEST_B}"},
            {"image": f"external.example/proxy@{DIGEST_A}"},
        ]}]}
        entries = control.protected_entries(tfvars, deployed, "release1")
        self.assertEqual({item["kind"] for item in entries}, {"release", "rollback"})
        self.assertEqual({item["repository"] for item in entries}, {"team/backend"})
        self.assertTrue(all(item["tag"].startswith(control.PROTECTED_PREFIXES) for item in entries))

    def test_deeper_rollback_digests_receive_unique_tags(self):
        tfvars = {"container_images": {"backend": f"registry.example/team/backend@{DIGEST_A}"}}
        deployed = {"services": [{"service": "prod/backend", "images": [
            {"image": f"registry.example/team/backend@{DIGEST_A}"},
            {"image": f"registry.example/team/backend@{DIGEST_B}"},
        ]}]}
        rollback = [item for item in control.protected_entries(tfvars, deployed, "release1") if item["kind"] == "rollback"]
        self.assertEqual(len({item["tag"] for item in rollback}), 2)

    def test_child_digests_selects_only_supported_linux_platforms(self):
        manifest = json.dumps({"manifests": [
            {"digest": DIGEST_A, "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": DIGEST_B, "platform": {"os": "linux", "architecture": "arm64"}},
            {"digest": "sha256:" + "c" * 64, "platform": {"os": "unknown", "architecture": "unknown"}},
        ]})
        self.assertEqual(control.child_digests(manifest), {"amd64": DIGEST_A, "arm64": DIGEST_B})

    @patch("scripts.ecr_release_control.image_manifest")
    def test_protection_expands_multi_platform_children(self, manifest):
        manifest.return_value = (json.dumps({"manifests": [
            {"digest": DIGEST_A, "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": DIGEST_B, "platform": {"os": "linux", "architecture": "arm64"}},
        ]}), control.INDEX_TYPES[0])
        entries = control.expand_platform_entries([{"repository": "team/api", "digest": "sha256:" + "c" * 64, "tag": "release-one", "kind": "release"}])
        self.assertEqual({item["tag"] for item in entries}, {"release-one", "release-one-amd64", "release-one-arm64"})

    def test_unprotect_waits_for_both_windows_and_rejects_active_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory, "record.json")
            current = Path(directory, "current.json")
            record.write_text(json.dumps({
                "rollback_protected_until": "2026-09-10", "database_compatible_until": "2026-09-12",
                "items": [{"repository": "team/api", "digest": DIGEST_A, "tag": "release-one"}],
            }), encoding="utf-8")
            current.write_text('{"services": []}', encoding="utf-8")
            args = type("Args", (), {"record": str(record), "current_inventory": str(current), "now": "2026-09-11"})()
            with self.assertRaisesRegex(RuntimeError, "windows"):
                control.unprotect(args)
            args.now = "2026-09-13"
            current.write_text(json.dumps({"services": [{"images": [{"image": f"registry.example/team/api@{DIGEST_A}"}]}]}), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "deployed digest"):
                control.unprotect(args)

    def test_protect_rejects_expired_windows_before_aws_calls(self):
        args = type("Args", (), {
            "release_id": "release1", "rollback_until": "2020-01-01",
            "database_compatible_until": "2020-01-01",
        })()
        with self.assertRaisesRegex(ValueError, "must not be in the past"):
            control.protect(args)

    @patch("scripts.ecr_release_control.aws")
    def test_delete_tag_rejects_ecr_failures(self, aws):
        aws.return_value = {"failures": [{"failureReason": "missing"}]}
        with self.assertRaisesRegex(RuntimeError, "failed to remove"):
            control.delete_tag("team/api", "candidate-one")
    def test_lifecycle_rules_cannot_select_protected_tags(self):
        policy = json.loads(Path(self.ROOT, "infra/ecr-lifecycle-policy.json").read_text(encoding="utf-8"))
        selections = [rule["selection"] for rule in policy["rules"]]
        self.assertFalse(any(item["tagStatus"] == "any" for item in selections))
        prefixes = {prefix for item in selections for prefix in item.get("tagPrefixList", [])}
        self.assertTrue(prefixes.isdisjoint({"release-", "rollback-"}))
        self.assertTrue(any(item["tagStatus"] == "untagged" for item in selections))

    def test_deployment_workflow_enforces_release_controls(self):
        deploy = Path(self.ROOT, ".github/workflows/deploy-controlled-beta.yml").read_text(encoding="utf-8")
        for required in ("ecr_release_control.py verify", "ecr_release_control.py protect", "ecr_release_control.py preview", "candidate-$SOURCE_SHA", "source_manifest"):
            self.assertIn(required, deploy)
        self.assertIn('delete_tag(repository, f"candidate-{args.release_id}")', Path(self.ROOT, "scripts/ecr_release_control.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
