# ADR-0011: Audit transport selection

- Status: Proposed
- Date: 2026-09-01
- Decision owner: Architecture and Security
- Evidence: Task 1 Kafka baseline kit and Task 2 audit-stream inventory

## Context

AuthClaw must decide whether its audit stream should remain on Kafka or move to an
AWS-managed transport. This ADR records an evidence-based provisional direction; it
does not authorize a production cutover or any transport or infrastructure change.

The committed Task 1 kit can collect throughput, event sizes, tenant distribution,
topic and consumer-group state, lag, retention, replay signals, delivery failures,
DLQ volume, cost, and operational overhead. No representative deployed run is
committed. Therefore no production value is asserted by this ADR.

The Task 2 repository inventory found:

- three producer paths: gateway, backend outbox, and agent service;
- one explicit consumer group, `authclaw-audit-consumer`;
- `tenant_id` message keys and explicit `tenant_sequence` validation, supporting
  per-tenant rather than global ordering;
- replay-capable mechanics through the PostgreSQL outbox, consumer
  `auto_offset_reset=earliest`, same-offset seek/retry, and manual DLQ handling;
- no code evidence that production operations depend on retained-stream replay;
- declared retention of 7 days for `gateway.traffic`, 30 days for `audit.events`,
  and 90 days for `audit.deadletter`, which is configuration rather than a validated
  business requirement; and
- an agent topic-name mismatch: `authclaw-audit-events` and
  `authclaw-dead-letter-events` versus `audit.events` and `audit.deadletter` in the
  other paths.

The source inventory is
[kafka-audit-stream-inventory.json](./kafka-audit-stream-inventory.json), and the
review summary is
[KAFKA_AUDIT_STREAM_ADR_INPUT.md](./KAFKA_AUDIT_STREAM_ADR_INPUT.md).

## Evidence status

| Evidence | Current result |
| --- | --- |
| Producers, consumers, group, keys, retry and replay code paths | Repository evidence complete |
| Per-tenant ordering assumption | Supported by keying and sequence-check code |
| Global ordering requirement | Not found in code; deployed dependency is `LIVE-EVIDENCE-PENDING` |
| Representative peak/average events per second | `LIVE-EVIDENCE-PENDING` |
| Average/maximum event size and tenant distribution | `LIVE-EVIDENCE-PENDING` |
| Runtime partitions, replication, retention overrides and active groups | `LIVE-EVIDENCE-PENDING` |
| Producer failures, consumer throughput/lag and retry/DLQ volume | `LIVE-EVIDENCE-PENDING` |
| Actual offset reset, seek, replay and DLQ-redrive usage | `LIVE-EVIDENCE-PENDING` |
| Required business/compliance retention and recovery window | `LIVE-EVIDENCE-PENDING` |
| Infrastructure cost and operational overhead | `LIVE-EVIDENCE-PENDING` |

## Options

| Criterion | Kafka | Kinesis Data Streams | SQS FIFO |
| --- | --- | --- | --- |
| Per-tenant ordering | Partition by `tenant_id` | Partition key by `tenant_id`; order within a shard | `MessageGroupId=tenant_id`; order within each group |
| Independent consumers | Native consumer groups | Independent applications/cursors | One competing-consumer queue; another independent consumer requires another queue/fan-out design |
| Replay | Retained offsets and group reset | Retained records and independent cursors | Redelivery while queued and DLQ redrive; not retained-stream replay after successful deletion |
| Retention role | Configurable retained log | Purpose-built retained stream | Bounded queue retention for unconsumed messages |
| DLQ | Application-managed topic and reprocessor | Application-managed queue/stream and checkpoint policy | Native redrive to a FIFO DLQ, with explicit handling because moving a failed message can break exact sequence |
| Deduplication | Application `audit_record_id` required | Application `audit_record_id` required | `MessageDeduplicationId` can use `audit_record_id`, but durable application deduplication remains required |
| Operational model | Highest broker, partition and group responsibility | Managed stream with capacity, shard/key distribution and cursor concerns | Managed queue with the smallest operating surface for the current single-consumer topology |
| Current evidence fit | More capability than presently proven necessary | Required if retained replay is proven | Best provisional fit for one group and per-tenant ordering |

AWS documents that FIFO ordering is scoped by message group and uses explicit
deduplication IDs. AWS also documents that Kinesis stores records for a configurable
retention period, while an SQS FIFO DLQ can affect exact ordering. These semantics
must be verified again during implementation against the target account and region:

- [SQS FIFO delivery logic](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues-understanding-logic.html)
- [SQS message grouping and deduplication](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/best-practices-message-deduplication.html)
- [Kinesis retention](https://docs.aws.amazon.com/streams/latest/dev/kinesis-extended-retention.html)
- [SQS dead-letter queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html)

## Decision

SQS FIFO is the provisional target for a transport-neutral audit-stream abstraction.
Each tenant maps to a FIFO message group using `tenant_id`. This direction is based on
the current evidence of per-tenant ordering, one consumer group, and no proven
production use of retained-stream replay.

This decision permits design and implementation of transport-neutral interfaces only.
It does not permit production provisioning, data migration, producer cutover, consumer
cutover, or Kafka decommissioning.

Kinesis Data Streams is the required alternative if representative live evidence
confirms that consumers or operators need retained-stream replay after successful
processing, independent cursors, or a recovery window that cannot be met by the queue,
outbox, immutable audit store, and DLQ model.

Kafka is retained only if deployed evidence proves a Kafka-specific requirement, such
as multiple independent consumer groups, partition behavior not reproducible with
tenant message groups or Kinesis partition keys, or operational replay semantics that
Kinesis cannot satisfy.

All production conclusions in the preceding two paragraphs are
`LIVE-EVIDENCE-PENDING` until the decision gates below pass.

## Required invariants

### Ordering

- Ordering remains per tenant; no global ordering is introduced.
- `tenant_id` remains the stable ordering key and must map to the transport's ordering
  primitive.
- `tenant_sequence` validation remains transport-independent.
- A poison event must not silently allow later events for the same tenant to violate
  sequence. Quarantine, retry, and redrive behavior must define how that tenant is
  blocked or safely resumed.

### Audit-record deduplication

- Every event retains a stable, globally unique `audit_record_id` across local
  persistence, retries, DLQ movement, redrive, replay, and transport changes.
- Consumers enforce durable idempotency on `audit_record_id` before applying side
  effects. Transport acknowledgements or FIFO deduplication are not the system of
  record for deduplication.
- For SQS FIFO, `MessageDeduplicationId` should be derived from `audit_record_id`, while
  the persistent consumer deduplication check remains authoritative.

### Prior-hash chain

- The existing prior-hash-chain invariant is unchanged.
- Transport adapters must carry the canonical event bytes and existing hash fields;
  they must not regenerate an event ID, previous hash, sequence, timestamp, or payload
  after the audit record is committed locally.
- Consumer verification and reconciliation must detect missing, duplicate, reordered,
  or altered tenant records before acknowledging successful durable processing.

### Retention and replay

- Required business, compliance, incident-recovery, and consumer recovery periods are
  `LIVE-EVIDENCE-PENDING`.
- Kafka topic settings are not accepted as proof of those requirements.
- SQS FIFO remains viable only if replay needs are met by local durable history,
  immutable audit storage, unconsumed-message retention, and controlled DLQ redrive.
- If consumers need arbitrary rereads of successfully processed records from the
  transport, the target changes to Kinesis unless Kafka-specific gates are met.

### Retry, DLQ and local fallback

- A transport-specific FIFO DLQ must preserve `audit_record_id`, tenant ordering key,
  tenant sequence, original enqueue metadata, retry count, failure classification, and
  prior-hash-chain fields.
- DLQ redrive must be tenant-aware, idempotent, audited, rate-limited, observable, and
  tested for ordering effects.
- The existing durable local outbox/fallback remains mandatory. A transport outage must
  not drop or rewrite an audit record.
- Recovery drains the local backlog in tenant sequence, using the original
  `audit_record_id` and hash-chain data. Backlog age, capacity, publish failures, and
  exhaustion must alert before local storage is unsafe.

## Migration plan

1. Define transport-neutral producer, consumer, acknowledgement, retry, checkpoint,
   and DLQ interfaces without changing the active Kafka path.
2. Make canonical audit serialization, `audit_record_id`, tenant sequence, and hash
   verification independent of transport envelopes.
3. Resolve the agent topic-name mismatch and prove which deployed topic receives its
   events. This is `LIVE-EVIDENCE-PENDING` and blocks production migration.
4. Run the Task 1 kit for an approved representative window and attach timestamped,
   environment-scoped, security-reviewed evidence.
5. Exercise the candidate adapter in a non-authoritative shadow environment; reconcile
   counts, IDs, tenant sequences, hash chains, retries, and DLQ outcomes against Kafka.
6. Select SQS FIFO, Kinesis, or retained Kafka by applying the production gates below.
7. Canary tenants only after rollback has been rehearsed and all integrity checks pass.
8. Decommission Kafka only after the agreed rollback window and retention obligations
   expire and the decision owner approves the evidence.

## Rollback

- Kafka remains the authoritative transport until a separate production decision and
  cutover approval.
- During any canary, stop candidate publication/consumption, route affected tenants
  back to Kafka, and drain from the durable local outbox using original IDs and hashes.
- Do not replay both transports into authoritative consumers without the durable
  `audit_record_id` deduplication gate.
- Reconcile every canary tenant's sequence and prior-hash chain before declaring
  rollback complete.
- Candidate queues, streams, DLQs, and evidence are retained until incident review and
  retention requirements permit deletion.

## Production decision gates

Production selection and cutover remain blocked until all gates have evidence:

- Representative Task 1 measurements are complete, timestamped, environment-labelled,
  reproducible, and security-reviewed.
- Peak throughput, event size, tenant skew, backlog recovery, and candidate quotas pass
  load and failure testing with agreed headroom.
- Ordering is confirmed as per-tenant, or any broader ordering dependency is documented.
- Required retention and actual replay usage are approved by every consumer owner,
  Security, Compliance, and Operations.
- Active consumer groups and Kafka-specific offset, partition, or replay dependencies
  are proven or ruled out.
- `audit_record_id` deduplication, tenant sequence, prior-hash-chain verification, local
  fallback, DLQ redrive, and full reconciliation pass fault-injection tests.
- The agent topic-name mismatch is resolved in code ownership and deployed evidence.
- Cost and operational-overhead comparison includes steady state, incidents, replay,
  support, observability, and migration overlap.
- Migration and rollback runbooks are rehearsed with measurable recovery objectives.
- Architecture and Security explicitly approve the final target and production cutover.

## Conditions that change the provisional decision

- Choose Kinesis if `LIVE-EVIDENCE-PENDING` proves retained-stream replay,
  independent cursors, or post-processing rereads are required.
- Retain Kafka if `LIVE-EVIDENCE-PENDING` proves Kafka-specific consumer-group,
  partitioning, or replay semantics that Kinesis cannot meet at acceptable risk.
- Keep SQS FIFO if live evidence confirms one logical consumer group, per-tenant
  ordering, no retained-stream replay dependency, sufficient queue/outbox retention,
  and acceptable throughput, DLQ, cost, and recovery behavior.

## Consequences

- Work may begin on a transport-neutral abstraction while Kafka remains unchanged.
- SQS FIFO is the planning default, reducing unnecessary stream-specific design in the
  absence of replay evidence.
- The final transport can change without weakening audit identity, ordering, hash-chain,
  fallback, retry, or reconciliation requirements.
- Production cutover remains blocked by live evidence rather than inferred from code or
  configured Kafka retention.
