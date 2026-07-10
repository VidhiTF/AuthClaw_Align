import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import no_credential_proof


ROOT = Path(__file__).resolve().parents[1]
GOOD = json.loads((ROOT / "infra/security/no_credential_proof.local.json").read_text(encoding="utf-8"))


class NoCredentialProofTests(unittest.TestCase):
    def test_accepts_local_proof_manifest(self) -> None:
        self.assertEqual(no_credential_proof.validate(copy.deepcopy(GOOD), ROOT), [])

    def test_rejects_missing_required_proof(self) -> None:
        payload = copy.deepcopy(GOOD)
        del payload["local_proofs"]["tenant_isolation_proof"]

        result = no_credential_proof.validate(payload, ROOT)

        self.assertIn("local_proofs missing proofs: tenant_isolation_proof", result)

    def test_rejects_bad_red_team_threshold(self) -> None:
        payload = copy.deepcopy(GOOD)
        payload["red_team_thresholds"]["failed_critical"] = 1

        result = no_credential_proof.validate(payload, ROOT)

        self.assertIn("red_team_thresholds.failed_critical must be 0", result)


if __name__ == "__main__":
    unittest.main()
