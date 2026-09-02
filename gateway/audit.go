package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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
	auditOutboxMu              sync.Mutex
)

type auditOutboxEnvelope struct {
	FailedAt    time.Time   `json:"failed_at"`
	ErrorReason string      `json:"error_reason"`
	Event       *AuditEvent `json:"event"`
}

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
	if event == nil {
		return fmt.Errorf("audit event is nil")
	}
	envelope := auditOutboxEnvelope{
		FailedAt:    time.Now().UTC(),
		ErrorReason: reason.Error(),
		Event:       event,
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
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
	if _, err := file.Write(append(payload, '\n')); err != nil {
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
	auditOutboxWrites.Add(1)
	return nil
}

// EmitAuditEvent appends in Postgres, then publishes committed outbox rows.
func EmitAuditEvent(event *AuditEvent) error {
	if err := persistAuditMetadata(event); err != nil {
		auditPostgresFailures.Add(1)
		if strings.Contains(err.Error(), "idempotency-key collision") {
			auditIdempotencyCollisions.Add(1)
		}
		log.Printf("[AUDIT] Postgres metadata persistence failed: %v", err)
		outboxAvailable := true
		if outboxErr := writeAuditOutbox(event, err); outboxErr != nil {
			outboxAvailable = false
			auditOutboxFailures.Add(1)
			log.Printf("[AUDIT] Durable outbox write failed: %v", outboxErr)
		}
		if auditFailClosedEnabled() {
			auditFailClosedFailures.Add(1)
			return fmt.Errorf(
				"canonical audit append failed (local recovery copy available=%t): %w",
				outboxAvailable,
				err,
			)
		}
		return nil
	}

	// Attempt transport publish first.
	if err := publishPendingAuditOutbox(event.TenantID, 100); err != nil {
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

var auditAsyncSlots = make(chan struct{}, 4)

func EmitAuditEventAsync(event *AuditEvent) {
	if auditFailClosedEnabled() {
		if err := EmitAuditEvent(event); err != nil {
			log.Printf("[AUDIT] fail-closed emit failed: %v", err)
		}
		return
	}
	go func() {
		// ponytail: bound background DB/Kafka work; a burst must not exhaust the request pool.
		auditAsyncSlots <- struct{}{}
		defer func() { <-auditAsyncSlots }()
		if err := EmitAuditEvent(event); err != nil {
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

func persistAuditMetadata(event *AuditEvent) error {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := RunInTenantTx(ctx, event.TenantID, func(tx *sql.Tx) error {
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now().UTC()
		}
		if event.IdempotencyKey == "" {
			event.IdempotencyKey = event.ID
		}
		executionTrace := "[]"
		if len(event.ExecutionTrace) > 0 {
			if traceBytes, traceErr := json.Marshal(event.ExecutionTrace); traceErr == nil {
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

func publishPendingAuditOutbox(tenantID string, limit int) error {
	if !AuditTransportEnabled() || DB == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
			if err := PublishAuditOutboxPayload(tenantID, item.payload); err != nil {
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
	}
}
