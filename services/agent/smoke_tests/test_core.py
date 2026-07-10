import os
import sys
import unittest
from pathlib import Path


SERVICE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE_ROOT))
os.chdir(SERVICE_ROOT)


class AgentCoreSmokeTests(unittest.TestCase):
    def test_risk_classification_is_ordered(self):
        import risk

        risk.get_policy = lambda: {
            "high_risk_keywords": ["delete all users", "production firewall"],
            "medium_risk_keywords": ["rotate"],
        }

        low = risk.calculate_risk("Show the public compliance summary")
        high = risk.calculate_risk("Delete all users and rotate the production firewall")
        ranks = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        self.assertGreaterEqual(ranks[str(high).upper()], ranks[str(low).upper()])

    def test_document_chunker_preserves_content(self):
        from document_processing.chunker import split_text_into_chunks

        text = "AuthClaw protects regulated data. " * 30
        chunks = split_text_into_chunks(text, chunk_size=120, overlap=20)
        self.assertGreater(len(chunks), 1)
        self.assertIn("AuthClaw", chunks[0])


if __name__ == "__main__":
    unittest.main()
