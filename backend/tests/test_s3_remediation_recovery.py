import copy
from unittest.mock import patch

import pytest

from app.orchestrator.connectors import (
    DocumentScanner,
    RemediationConflictError,
)
from app.orchestrator.graph import execute_remediation
from app.orchestrator.remediation_state import MutationPhase
from tests.test_remediation_connector import FakeS3


def _scanner(s3=None):
    scanner = DocumentScanner()
    scanner.bucket = "authclaw-test"
    scanner.s3_client = s3 or FakeS3()
    return scanner


def _plan(scanner):
    return scanner.build_remediation_plan("tenant-a/doc.txt", "EMAIL_ADDRESS")


class RaiseAfterTargetWriteS3(FakeS3):
    def __init__(self):
        super().__init__()
        self.raise_after_write = True

    def put_object(self, **kwargs):
        result = super().put_object(**kwargs)
        if self.raise_after_write and (kwargs.get("Metadata") or {}).get("authclaw-remediated"):
            self.raise_after_write = False
            raise OSError("client lost response after write")
        return result


class CrashAfterTargetWriteS3(FakeS3):
    def __init__(self):
        super().__init__()
        self.crash_after_write = True

    def put_object(self, **kwargs):
        result = super().put_object(**kwargs)
        if self.crash_after_write and (kwargs.get("Metadata") or {}).get("authclaw-remediated"):
            self.crash_after_write = False
            raise SystemExit("simulated process termination")
        return result


def test_successful_write_followed_by_client_error_reconciles_as_success():
    scanner = _scanner(RaiseAfterTargetWriteS3())
    result = scanner.execute_remediation("workflow-1", "action-1", _plan(scanner))

    assert result["status"] == "success"
    assert result["mutation_state"]["phase"] == MutationPhase.APPLIED.value
    assert result["mutation_state"]["mutation"]["reconciled"] is True


def test_crash_after_write_resumes_from_persisted_applying_state():
    scanner = _scanner(CrashAfterTargetWriteS3())
    plan = _plan(scanner)
    prepared = scanner.prepare_remediation("workflow-1", "action-1", plan)
    prepared["phase"] = MutationPhase.APPLYING.value

    with pytest.raises(SystemExit, match="process termination"):
        scanner.apply_prepared_remediation(prepared, plan)

    resumed = scanner.prepare_remediation("workflow-1", "action-1", plan, prepared)
    result = scanner.apply_prepared_remediation(resumed, plan)
    assert result["status"] == "success"
    assert result["mutation_state"]["mutation"]["reconciled"] is True


def test_reusing_prepared_state_never_overwrites_immutable_backup():
    scanner = _scanner()
    plan = _plan(scanner)
    prepared = scanner.prepare_remediation("workflow-1", "action-1", plan)
    backup_key = prepared["backup"]["key"]
    backup_version = scanner.s3_client.objects[backup_key]["VersionId"]

    resumed = scanner.prepare_remediation("workflow-1", "action-1", plan, prepared)
    assert resumed["phase"] == MutationPhase.PREPARED.value
    assert scanner.s3_client.objects[backup_key]["VersionId"] == backup_version


def test_external_edit_before_apply_is_a_conflict_without_overwrite():
    scanner = _scanner()
    plan = _plan(scanner)
    prepared = scanner.prepare_remediation("workflow-1", "action-1", plan)
    scanner.s3_client.put_object(
        Bucket=scanner.bucket,
        Key="tenant-a/doc.txt",
        Body=b"external edit",
        Metadata={"editor": "external"},
    )

    with pytest.raises(RemediationConflictError):
        scanner.apply_prepared_remediation(prepared, plan)
    assert scanner.s3_client.objects["tenant-a/doc.txt"]["Body"] == b"external edit"


def test_external_edit_before_rollback_is_never_overwritten():
    scanner = _scanner()
    plan = _plan(scanner)
    result = scanner.execute_remediation("workflow-1", "action-1", plan)
    scanner.s3_client.put_object(
        Bucket=scanner.bucket,
        Key="tenant-a/doc.txt",
        Body=b"new owner content",
        Metadata={"editor": "external"},
    )

    with pytest.raises(RemediationConflictError):
        scanner.rollback_remediation({"rollback_ref": result["rollback_ref"]})
    assert scanner.s3_client.objects["tenant-a/doc.txt"]["Body"] == b"new owner content"


def test_graph_persists_prepared_and_applying_state_before_target_write():
    scanner = _scanner()
    snapshots = []
    plan = _plan(scanner)
    state = {
        "workflow_id": "workflow-1",
        "tenant_id": "tenant-a",
        "remediation_plan": [{"finding_control": "tenant-a/doc.txt", **plan}],
        "_persist_state": lambda value: snapshots.append(copy.deepcopy(value)),
    }

    with patch("app.orchestrator.connectors.DocumentScanner", return_value=scanner):
        result = execute_remediation(state)

    phases = [
        snapshot["remediation_actions"][0]["mutation_state"]["phase"]
        for snapshot in snapshots
        if (snapshot.get("remediation_actions") or [{}])[0].get("mutation_state")
    ]
    assert phases[:2] == [MutationPhase.PREPARED.value, MutationPhase.APPLYING.value]
    assert result["remediation_actions"][0]["status"] == "SUCCEEDED"
