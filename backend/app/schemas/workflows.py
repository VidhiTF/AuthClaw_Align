"""Read-only workflow payload contracts, including sparse recovery snapshots.

These models never normalize the executable plan or persisted mutation state.
Missing nested fields stay missing; explicitly supplied nulls stay null.
"""

from pydantic import BaseModel, ConfigDict, Field, model_serializer


class WorkflowPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    @model_serializer(mode="wrap")
    def serialize_present_fields(self, handler):
        # Keep the model's schema: a generic return annotation would replace its
        # concrete serialization schema with an unrestricted object in OpenAPI.
        return {key: value for key, value in handler(self).items() if key in self.model_fields_set}


class WorkflowFinding(WorkflowPayload):
    control: str | None = None
    description: str | None = None
    status: str | None = None
    evidence: str | None = None
    entity_count: int | None = None


class RemediationTarget(WorkflowPayload):
    provider: str | None = None
    type: str | None = None
    bucket: str | None = None
    object_key: str | None = None
    uri: str | None = None


class RemediationDiff(WorkflowPayload):
    kind: str | None = None
    summary: str | None = None
    commands: list[str] | None = None
    preview: list[str] | None = None
    terraform: list[str] | None = Field(
        None,
        max_length=0,
        description="Reserved empty list; no Terraform payload format is currently produced.",
    )


class ProposedChange(WorkflowPayload):
    summary: str | None = None
    target: RemediationTarget | None = None
    steps: list[str] | None = None
    preview: list[str] | None = None


class RemediationRisk(WorkflowPayload):
    level: str | None = None
    destructive: bool | None = None
    impact: str | None = None


class RollbackDescription(WorkflowPayload):
    strategy: str | None = None
    trigger: str | None = None
    evidence: str | None = None


class WorkflowRemediationPlan(WorkflowPayload):
    finding_control: str | None = None
    action: str | None = None
    priority: str | None = None
    estimated_effort: str | None = None
    connector: str | None = None
    target: RemediationTarget | None = None
    destructive: bool | None = None
    diff: RemediationDiff | None = None
    steps: list[str] | None = None
    proposed_change: ProposedChange | None = None
    risk: RemediationRisk | None = None
    rollback: RollbackDescription | None = None


class VerificationSummary(WorkflowPayload):
    entity_counts: dict[str, int] | None = None
    total: int | None = None
    # Historical S3 verification-read failures persisted an error-only summary.
    error: str | None = None


class MutationTarget(WorkflowPayload):
    bucket: str | None = None
    key: str | None = None
    content_type: str | None = None


class ObjectVersion(WorkflowPayload):
    sha256: str | None = None
    etag: str | None = None
    etag_header: str | None = None
    version_id: str | None = None


class OriginalObject(ObjectVersion):
    verification: VerificationSummary | None = None


class IntendedObject(WorkflowPayload):
    sha256: str | None = None
    verification: VerificationSummary | None = None
    redaction: VerificationSummary | None = None


class BackupObject(ObjectVersion):
    bucket: str | None = None
    key: str | None = None


class AppliedMutation(ObjectVersion):
    reconciled: bool | None = None


class MutationState(WorkflowPayload):
    state_version: int | None = None
    operation_id: str | None = None
    phase: str | None = None
    target: MutationTarget | None = None
    original: OriginalObject | None = None
    intended: IntendedObject | None = None
    backup: BackupObject | None = None
    mutation: AppliedMutation | None = None
    conflict: str | None = None


class RollbackReference(WorkflowPayload):
    state_version: int | None = None
    operation_id: str | None = None
    bucket: str | None = None
    backup_key: str | None = None
    target_key: str | None = None
    content_type: str | None = None
    original_sha256: str | None = None
    intended_sha256: str | None = None
    before_version_id: str | None = None
    after_version_id: str | None = None
    mutation_etag: str | None = None
    mutation_etag_header: str | None = None


class ActionRollbackPlan(WorkflowPayload):
    mode: str | None = None
    control: str | None = None
    action: str | None = None
    rollback_ref: RollbackReference | None = None


class ConnectorResult(WorkflowPayload):
    connector: str | None = None
    control: str | None = None
    status: str | None = None
    details: str | None = None
    mutation_id: str | None = None


class RemediationResult(ConnectorResult):
    target: RemediationTarget | None = None
    before_verification: VerificationSummary | None = None
    after_verification: VerificationSummary | None = None
    before_sha256: str | None = None
    after_sha256: str | None = None
    cli_diff: RemediationDiff | None = None
    mutation_state: MutationState | None = None
    rollback_ref: RollbackReference | None = None


class WorkflowRemediationAction(WorkflowPayload):
    id: str | None = None
    index: int | None = None
    finding_control: str | None = None
    action: str | None = None
    connector: str | None = None
    target: RemediationTarget | None = None
    diff: RemediationDiff | None = None
    destructive: bool | None = None
    priority: str | None = None
    status: str | None = None
    attempts: int | None = None
    last_error: str | None = None
    started_at: str | None = None
    updated_at: str | None = None
    completed_at: str | None = None
    result: RemediationResult | None = None
    rollback_plan: ActionRollbackPlan | None = None
    rollback_result: ConnectorResult | None = None
    mutation_state: MutationState | None = None


class WorkflowExecutionResult(WorkflowPayload):
    remediation_state: str | None = None
    actions_executed: int | None = None
    actions_successful: int | None = None
    actions_failed: int | None = None
    rollback_required: bool | None = None
    details: list[RemediationResult] | None = None
    actions: list[WorkflowRemediationAction] | None = None


class WorkflowRollbackResult(WorkflowPayload):
    rollback_attempted: int | None = None
    rollback_successful: int | None = None
    rollback_failed: int | None = None
    details: list[ConnectorResult] | None = None
