import unittest
from unittest.mock import MagicMock, mock_open, patch

from services.audit_agent import AuditAgent
from verify_audit import GENESIS_HASH


class AuditAgentGenesisTests(unittest.TestCase):
    @patch("services.audit_agent.log_agent_event")
    @patch("services.audit_agent.create_audit_block", return_value=1)
    @patch("services.audit_agent.open", new_callable=mock_open)
    @patch("services.audit_agent.os.makedirs")
    def test_first_audit_record_uses_genesis_hash(
        self,
        _makedirs,
        _open,
        _create_audit_block,
        log_agent_event,
    ):
        connection = MagicMock()
        connection.execute.return_value.fetchone.return_value = ("a" * 64, None)
        connection_context = MagicMock()
        connection_context.__enter__.return_value = connection
        connection_context.__exit__.return_value = False

        state = {
            "message": "Explain GDPR retention",
            "response": "Retention guidance",
            "tenant_id": 42,
            "session_id": "session-1",
        }

        with patch("services.audit_agent.engine.connect", return_value=connection_context):
            result = AuditAgent().record(state)

        self.assertEqual(result["audit_record_id"], 1)
        hash_event = next(
            call
            for call in log_agent_event.call_args_list
            if call.kwargs["event_type"] == "LEDGER_HASH_GENERATED"
        )
        self.assertIn(f"Previous: {GENESIS_HASH[:16]}...", hash_event.kwargs["details"])


if __name__ == "__main__":
    unittest.main()
