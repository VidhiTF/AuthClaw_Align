package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lib/pq"
)

// AuditEvent represents the schema of traffic events logged by the gateway.
type AuditEvent struct {
	ID                 string    `json:"id"`
	RequestID          string    `json:"request_id"`
	Timestamp          time.Time `json:"timestamp"`
	TenantID           string    `json:"tenant_id"`
	PolicyID           string    `json:"policy_id"`
	Action             string    `json:"action"`
	DecisionReason     string    `json:"reason"`
	Provider           string    `json:"provider"`
	Model              string    `json:"model"`
	PromptCount        int       `json:"prompt_count"`
	RequestSize        int       `json:"request_size"`
	ResponseStatus     int       `json:"response_status"`
	DurationMs         int64     `json:"duration_ms"`
	FrameworksAffected []string  `json:"frameworks_affected,omitempty"`
	ExecutionTrace     []string  `json:"execution_trace,omitempty"`
	IdempotencyKey     string    `json:"idempotency_key,omitempty"`
	TenantSequence     int64     `json:"tenant_sequence,omitempty"`
	ChainVersion       int       `json:"chain_version,omitempty"`
	CanonicalPayload   string    `json:"canonical_payload,omitempty"`
	PriorHash          string    `json:"prior_hash,omitempty"`
	IntegrityHash      string    `json:"integrity_hash,omitempty"`
}

var (
	auditPostgresFailures      atomic.Uint64
	auditOutboxWrites          atomic.Uint64
	auditOutboxFailures        atomic.Uint64
	auditFailClosedFailures    atomic.Uint64
	auditIdempotencyCollisions atomic.Uint64
	auditOutboxBacklog         atomic.Uint64
	auditOutboxOldestAge       atomic.Uint64
	auditFailOpenLosses        atomic.Uint64
	auditPostResponseFailures  atomic.Uint64
	auditOutboxMu              sync.Mutex
)

var auditEventEmitter = EmitAuditEvent

type auditOutboxEnvelope struct {
	FailedAt    time.Time   `json:"failed_at"`
	ErrorReason string      `json:"error_reason"`
	Event       *AuditEvent `json:"event"`
}

type auditPersistenceError struct {
	cause             error
	recoveryAvailable bool
}

func (e *auditPersistenceError) Error() string { return e.cause.Error() }
func (e *auditPersistenceError) Unwrap() error { return e.cause }

func auditFailClosedEnabled() bool {
	return envBool("AUDIT_FAIL_CLOSED", isProductionEnv())
}

func auditOutboxPath() string {
	if path := strings.TrimSpace(os.Getenv("AUDIT_OUTBOX_PATH")); path != "" {
		return path
	}
	return filepath.Join(os.TempDir(), "authclaw", "audit-outbox.ndjson")
}

func writeAuditOutbox(event *AuditEvent, reason error) error {
	return writeAuditOutboxBatch([]*AuditEvent{event}, reason)
}

func writeAuditOutboxBatch(events []*AuditEvent, reason error) error {
	payload := make([]byte, 0, len(events)*512)
	failedAt := time.Now().UTC()
	for _, event := range events {
		if event == nil {
			return fmt.Errorf("audit event is nil")
		}
		line, err := json.Marshal(auditOutboxEnvelope{FailedAt: failedAt, ErrorReason: reason.Error(), Event: event})
		if err != nil {
			return err
		}
		payload = append(payload, line...)
		payload = append(payload, '\n')
	}
	path := auditOutboxPath()
	auditOutboxMu.Lock()
	defer auditOutboxMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	auditOutboxWrites.Add(uint64(len(events)))
	return nil
}

// EmitAuditEvent appends in Postgres, then publishes committed outbox rows.
func EmitAuditEvent(ctx context.Context, event *AuditEvent) error {
	if err := persistAuditMetadata(ctx, event); err != nil {
		auditPostgresFailures.Add(1)
		if strings.Contains(err.Error(), "idempotency-key collision") {
			auditIdempotencyCollisions.Add(1)
		}
		log.Printf("[AUDIT] Postgres metadata persistence failed: %v", err)
		outboxAvailable, outboxErr := recoverAuditEvent(ctx, event, err)
		if outboxErr != nil {
			auditOutboxFailures.Add(1)
			log.Printf("[AUDIT] Durable outbox write failed: %v", outboxErr)
		}
		if auditFailClosedEnabled() {
			auditFailClosedFailures.Add(1)
			return &auditPersistenceError{
				cause:             fmt.Errorf("canonical audit append failed (local recovery copy available=%t): %w", outboxAvailable, err),
				recoveryAvailable: outboxAvailable,
			}
		}
		auditFailOpenLosses.Add(1)
		log.Printf("[AUDIT] class=%s provider=%s result=fail_open recovery_available=%t err=%v", event.Action, event.Provider, outboxAvailable, err)
		return nil
	}

	// Attempt transport publish first.
	if err := publishPendingAuditOutbox(ctx, event.TenantID, 100); err != nil {
		log.Printf("[AUDIT] transport publish error: %v — falling back to stdout", err)
		logToStdout(event)
		return nil
	}

	// If the configured transport is unavailable, also log to stdout as fallback.
	if !AuditTransportEnabled() {
		logToStdout(event)
	}
	return nil
}

func auditIdempotencyKey(requestID, eventClass string) string {
	if strings.TrimSpace(requestID) == "" {
		return ""
	}
	return "gateway:" + requestID + ":" + eventClass
}

func emitRequiredDecision(w http.ResponseWriter, r *http.Request, event *AuditEvent, eventClass string) bool {
	if event.IdempotencyKey == "" {
		event.IdempotencyKey = auditIdempotencyKey(event.RequestID, "decision:"+eventClass)
	}
	if err := auditEventEmitter(r.Context(), event); err != nil {
		if auditFailClosedEnabled() {
			log.Printf("[AUDIT] class=%s route=%s provider=%s result=fail_closed err=%v", eventClass, r.URL.Path, event.Provider, err)
			writeGatewayError(w, http.StatusServiceUnavailable, "AuditUnavailable", "Audit persistence is temporarily unavailable.")
			return false
		}
		auditFailOpenLosses.Add(1)
		log.Printf("[AUDIT] class=%s route=%s provider=%s result=fail_open err=%v", eventClass, r.URL.Path, event.Provider, err)
	}
	return true
}

func requireProviderAttempt(w http.ResponseWriter, r *http.Request, event *AuditEvent) bool {
	event.Action = "provider_attempt"
	event.DecisionReason = "Provider egress authorized"
	event.IdempotencyKey = auditIdempotencyKey(event.RequestID, "provider_attempt")
	if !auditFailClosedEnabled() {
		emitAuditTelemetry(r.Context(), event, "provider_attempt")
		return true
	}
	return emitRequiredDecision(w, r, event, "provider_attempt")
}

func emitAuditTelemetry(ctx context.Context, event *AuditEvent, eventClass string) {
	if event.IdempotencyKey == "" {
		event.IdempotencyKey = auditIdempotencyKey(event.RequestID, "telemetry:"+eventClass)
	}
	EmitAuditEventAsync(ctx, event)
}

func emitPostResponseOutcome(ctx context.Context, route string, event *AuditEvent) {
	event.IdempotencyKey = auditIdempotencyKey(event.RequestID, "provider_outcome")
	if !auditFailClosedEnabled() {
		EmitAuditEventAsync(ctx, event)
		return
	}
	if err := auditEventEmitter(ctx, event); err != nil {
		auditPostResponseFailures.Add(1)
		var persistenceErr *auditPersistenceError
		if !errors.As(err, &persistenceErr) || !persistenceErr.recoveryAvailable {
			if recoveryErr := writeAuditOutbox(event, err); recoveryErr != nil {
				auditOutboxFailures.Add(1)
				log.Printf("[AUDIT] class=provider_outcome route=%s provider=%s result=recovery_failed err=%v", route, event.Provider, recoveryErr)
			}
		}
		log.Printf("[AUDIT] class=provider_outcome route=%s provider=%s result=post_response_failure err=%v", route, event.Provider, err)
	}
}

const auditAsyncBacklogLimit = 64

var auditAsyncSlots = make(chan struct{}, 4)

type pendingAuditEvent struct {
	recovery  *AuditEvent
	recovered bool
	cancel    context.CancelFunc
}

type pendingAuditContextKey struct{}

var auditAsync struct {
	sync.Mutex
	pending int
	drained chan struct{}
	closing bool
	active  map[*pendingAuditEvent]struct{}
}

func startPendingAudit() {
	if auditAsync.pending == 0 {
		auditAsync.drained = make(chan struct{})
	}
	auditAsync.pending++
}

func finishPendingAudit(task *pendingAuditEvent) {
	auditAsync.Lock()
	delete(auditAsync.active, task)
	auditAsync.pending--
	if auditAsync.pending == 0 {
		close(auditAsync.drained)
	}
	auditAsync.Unlock()
	if task != nil {
		task.cancel()
	}
}

func recoverAuditEvent(ctx context.Context, event *AuditEvent, cause error) (bool, error) {
	task, _ := ctx.Value(pendingAuditContextKey{}).(*pendingAuditEvent)
	if task == nil {
		err := writeAuditOutbox(event, cause)
		return err == nil, err
	}
	auditAsync.Lock()
	defer auditAsync.Unlock()
	if task.recovered {
		return true, nil
	}
	if err := writeAuditOutbox(event, cause); err != nil {
		return false, err
	}
	task.recovered = true
	return true, nil
}

func auditOperationContext(parent context.Context) context.Context {
	if _, tracked := parent.Value(pendingAuditContextKey{}).(*pendingAuditEvent); tracked {
		return parent
	}
	return context.WithoutCancel(parent)
}

func drainAuditEvents(ctx context.Context) error {
	auditAsync.Lock()
	auditAsync.closing = true
	pending, done := auditAsync.pending, auditAsync.drained
	auditAsync.Unlock()
	if pending == 0 {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		err := fmt.Errorf("audit drain: %w", ctx.Err())
		auditAsync.Lock()
		spill := make([]*AuditEvent, 0, len(auditAsync.active))
		cancels := make([]context.CancelFunc, 0, len(auditAsync.active))
		for task := range auditAsync.active {
			if task.recovered {
				continue
			}
			task.recovered = true
			spill = append(spill, task.recovery)
			cancels = append(cancels, task.cancel)
		}
		auditAsync.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
		if len(spill) > 0 {
			if spillErr := writeAuditOutboxBatch(spill, err); spillErr != nil {
				auditOutboxFailures.Add(1)
				err = errors.Join(err, spillErr)
			}
		}
		return err
	}
}

func EmitAuditEventAsync(ctx context.Context, event *AuditEvent) {
	if event == nil {
		log.Print("[AUDIT] async emit rejected nil event")
		return
	}
	auditAsync.Lock()
	if auditAsync.closing {
		auditAsync.Unlock()
		if err := writeAuditOutbox(event, errors.New("gateway shutting down")); err != nil {
			auditOutboxFailures.Add(1)
			log.Printf("[AUDIT] shutdown recovery failed: %v", err)
		}
		return
	}
	ctx = context.WithoutCancel(ctx)
	if auditFailClosedEnabled() {
		startPendingAudit()
		auditAsync.Unlock()
		defer finishPendingAudit(nil)
		if err := EmitAuditEvent(ctx, event); err != nil {
			log.Printf("[AUDIT] fail-closed emit failed: %v", err)
		}
		return
	}
	if len(auditAsync.active) >= auditAsyncBacklogLimit {
		auditAsync.Unlock()
		if err := writeAuditOutbox(event, errors.New("asynchronous audit backlog capacity exhausted")); err != nil {
			auditOutboxFailures.Add(1)
			log.Printf("[AUDIT] overload recovery failed: %v", err)
		}
		return
	}
	recovery := *event
	recovery.FrameworksAffected = append([]string(nil), event.FrameworksAffected...)
	recovery.ExecutionTrace = append([]string(nil), event.ExecutionTrace...)
	ctx, cancel := context.WithCancel(ctx)
	task := &pendingAuditEvent{recovery: &recovery, cancel: cancel}
	ctx = context.WithValue(ctx, pendingAuditContextKey{}, task)
	if auditAsync.active == nil {
		auditAsync.active = make(map[*pendingAuditEvent]struct{})
	}
	auditAsync.active[task] = struct{}{}
	startPendingAudit()
	auditAsync.Unlock()
	go func() {
		select {
		case auditAsyncSlots <- struct{}{}:
		case <-ctx.Done():
			finishPendingAudit(task)
			return
		}
		defer func() {
			<-auditAsyncSlots
			finishPendingAudit(task)
		}()
		auditAsync.Lock()
		recovered := task.recovered
		auditAsync.Unlock()
		if recovered {
			return
		}
		if err := auditEventEmitter(ctx, event); err != nil {
			log.Printf("[AUDIT] async emit failed: %v", err)
		}
	}()
}

// logToStdout emits a structured JSON audit log to stdout.
func logToStdout(event *AuditEvent) {
	eventBytes, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal audit event: %v", err)
		return
	}
	log.Printf("[AUDIT] %s", string(eventBytes))
}

func persistAuditMetadata(parent context.Context, event *AuditEvent) error {
	if event == nil {
		return fmt.Errorf("audit event is nil")
	}
	if event.TenantID == "" || event.ID == "" {
		if !auditFailClosedEnabled() {
			return nil
		}
		return fmt.Errorf("audit event missing tenant_id or id")
	}
	if DB == nil {
		if auditFailClosedEnabled() {
			return fmt.Errorf("database is not initialized")
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(auditOperationContext(parent), 10*time.Second)
	defer cancel()

	err := RunInTenantTx(ctx, event.TenantID, func(tx *sql.Tx) error {
		// RunInTenantTx has authenticated and matched the tenant. The canonical
		// append function still checks this legacy GUC in addition to signed RLS.
		if _, err := tx.ExecContext(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", event.TenantID); err != nil {
			return err
		}
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now().UTC()
		}
		if event.IdempotencyKey == "" {
			event.IdempotencyKey = event.ID
		}
		executionTrace := "[]"
		trace := append([]string(nil), event.ExecutionTrace...)
		if correlationID, _ := parent.Value(CorrelationIDContextKey).(string); correlationID != "" && len(correlationID) <= 128 {
			trace = append(trace, "client_correlation_id:"+correlationID)
		}
		if len(trace) > 0 {
			if traceBytes, traceErr := json.Marshal(trace); traceErr == nil {
				executionTrace = string(traceBytes)
			}
		}

		var duplicate bool
		return tx.QueryRowContext(ctx, `
			SELECT record_id, tenant_sequence, prior_hash, integrity_hash,
			       canonical_payload, duplicate
			FROM append_audit_event_v2(
				$1::uuid, $2::uuid, $3, $4, NULL, 'gateway', $5, $6,
				NULLIF($7, '')::uuid, $8, $9, $10, $11, $12, $13, $14,
				$15, $16::jsonb
			)
		`,
			event.TenantID,
			event.ID,
			event.IdempotencyKey,
			event.Timestamp,
			event.Action,
			event.RequestID,
			event.PolicyID,
			event.Provider,
			event.Model,
			event.DecisionReason,
			event.PromptCount,
			event.RequestSize,
			event.ResponseStatus,
			event.DurationMs,
			pq.Array(event.FrameworksAffected),
			executionTrace,
		).Scan(
			&event.ID,
			&event.TenantSequence,
			&event.PriorHash,
			&event.IntegrityHash,
			&event.CanonicalPayload,
			&duplicate,
		)
	})
	if err != nil {
		return err
	}
	return nil
}

func publishPendingAuditOutbox(parent context.Context, tenantID string, limit int) error {
	if !AuditTransportEnabled() || DB == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(auditOperationContext(parent), 15*time.Second)
	defer cancel()
	return RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var backlog int64
		var oldestAge float64
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*),
			       COALESCE(EXTRACT(EPOCH FROM now() - min(created_at)), 0)
			FROM audit_outbox
			WHERE tenant_id = $1::uuid AND published_at IS NULL
		`, tenantID).Scan(&backlog, &oldestAge); err != nil {
			return err
		}
		auditOutboxBacklog.Store(uint64(backlog))
		auditOutboxOldestAge.Store(uint64(max(oldestAge, 0)))
		rows, err := tx.QueryContext(ctx, `
			SELECT id, event_payload
			FROM audit_outbox
			WHERE tenant_id = $1::uuid AND published_at IS NULL
			ORDER BY tenant_sequence
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		type pending struct {
			id      int64
			payload []byte
		}
		var events []pending
		for rows.Next() {
			var item pending
			if err := rows.Scan(&item.id, &item.payload); err != nil {
				return err
			}
			events = append(events, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, item := range events {
			if err := publishAuditOutboxPayloadContext(ctx, tenantID, item.payload); err != nil {
				_, _ = tx.ExecContext(ctx, `
					UPDATE audit_outbox
					SET publish_attempts = publish_attempts + 1, last_error = $2
					WHERE id = $1
				`, item.id, err.Error())
				return err
			}
			if _, err := tx.ExecContext(ctx, `
				UPDATE audit_outbox
				SET published_at = now(), publish_attempts = publish_attempts + 1,
				    last_error = NULL
				WHERE id = $1
			`, item.id); err != nil {
				return err
			}
		}
		auditOutboxBacklog.Store(uint64(max(backlog-int64(len(events)), 0)))
		if backlog <= int64(len(events)) {
			auditOutboxOldestAge.Store(0)
		}
		return nil
	})
}

func AuditMetricsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"authclaw_gateway_audit_postgres_failures_total":      auditPostgresFailures.Load(),
		"authclaw_gateway_audit_outbox_writes_total":          auditOutboxWrites.Load(),
		"authclaw_gateway_audit_outbox_failures_total":        auditOutboxFailures.Load(),
		"authclaw_gateway_audit_fail_closed_failures_total":   auditFailClosedFailures.Load(),
		"authclaw_gateway_audit_idempotency_collisions_total": auditIdempotencyCollisions.Load(),
		"authclaw_gateway_audit_outbox_backlog":               auditOutboxBacklog.Load(),
		"authclaw_gateway_audit_outbox_oldest_age_seconds":    auditOutboxOldestAge.Load(),
		"authclaw_gateway_audit_fail_open_losses_total":       auditFailOpenLosses.Load(),
		"authclaw_gateway_audit_post_response_failures_total": auditPostResponseFailures.Load(),
	}
}
