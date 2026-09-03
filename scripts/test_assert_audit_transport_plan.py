import unittest

from scripts.assert_audit_transport_plan import SQS_REQUIRED_RESOURCES, validate_plan


def plan_with(*addresses: str) -> dict:
    return {"resource_changes": [{"address": f"module.primary.{address}"} for address in addresses]}


class AuditTransportPlanTests(unittest.TestCase):
    def test_sqs_accepts_separated_application_roles_and_policies(self) -> None:
        validate_plan("sqs_fifo", plan_with(*SQS_REQUIRED_RESOURCES))

    def test_sqs_rejects_legacy_role_without_new_consumer_policy(self) -> None:
        addresses = [
            address
            for address in SQS_REQUIRED_RESOURCES
            if "application_task" not in address and "audit_sqs_consumer" not in address
        ]
        addresses.append("aws_iam_role.audit_sqs_consumer[0]")
        with self.assertRaisesRegex(SystemExit, "application_task"):
            validate_plan("sqs_fifo", plan_with(*addresses))

    def test_kafka_rejects_conditional_sqs_resources(self) -> None:
        with self.assertRaisesRegex(SystemExit, "kafka plan must not include"):
            validate_plan("kafka", plan_with("aws_sqs_queue.audit[0]"))

    def test_agent_cannot_receive_sqs_producer_policy(self) -> None:
        addresses = [*SQS_REQUIRED_RESOURCES, 'aws_iam_role_policy.audit_sqs_producer["agent"]']
        with self.assertRaisesRegex(SystemExit, "agent must not receive"):
            validate_plan("sqs_fifo", plan_with(*addresses))

    def test_dynamodb_endpoint_remains_forbidden(self) -> None:
        with self.assertRaisesRegex(SystemExit, "DynamoDB"):
            validate_plan("kafka", plan_with('aws_vpc_endpoint.gateway["dynamodb"]'))


if __name__ == "__main__":
    unittest.main()
