package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
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
	PriorHash          string    `json:"prior_hash,omitempty"`
	IntegrityHash      string    `json:"integrity_hash,omitempty"`
}

var (
	auditPostgresFailures   atomic.Uint64
	auditOutboxWrites       atomic.Uint64
	auditOutboxFailures     atomic.Uint64
	auditFailClosedFailures atomic.Uint64
	auditOutboxMu           sync.Mutex
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

// EmitAuditEvent records the event in Postgres, queues to a local outbox when
// Postgres is unavailable, then publishes to Kafka/stdout for analytics.
func EmitAuditEvent(event *AuditEvent) error {
	if err := persistAuditMetadata(event); err != nil {
		auditPostgresFailures.Add(1)
		log.Printf("[AUDIT] Postgres metadata persistence failed: %v", err)
		if outboxErr := writeAuditOutbox(event, err); outboxErr != nil {
			auditOutboxFailures.Add(1)
			log.Printf("[AUDIT] Durable outbox write failed: %v", outboxErr)
			if auditFailClosedEnabled() {
				auditFailClosedFailures.Add(1)
				return fmt.Errorf("audit persistence failed and outbox unavailable: %w", outboxErr)
			}
		}
	}

	// Attempt Kafka publish first.
	if err := PublishAuditEvent(event); err != nil {
		log.Printf("[AUDIT] Kafka serialisation error: %v — falling back to stdout", err)
		logToStdout(event)
		return nil
	}

	// If kafkaWriter is nil (not configured), also log to stdout as fallback.
	if kafkaWriter == nil {
		logToStdout(event)
	}
	return nil
}

func EmitAuditEventAsync(event *AuditEvent) {
	if auditFailClosedEnabled() {
		if err := EmitAuditEvent(event); err != nil {
			log.Printf("[AUDIT] fail-closed emit failed: %v", err)
		}
		return
	}
	go func() {
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

const auditGenesisHash = "GENESIS"

func canonicalUUID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) == 32 && !strings.Contains(value, "-") {
		return strings.ToLower(value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32])
	}
	return strings.ToLower(value)
}

func standardizeAuditTimestamp(ts time.Time) string {
	return ts.UTC().Format("2006-01-02T15:04:05.000Z")
}

func canonicalAuditJSON(event *AuditEvent) string {
	frameworks := append([]string{}, event.FrameworksAffected...)
	sort.Strings(frameworks)
	executionTrace := "[]"
	if len(event.ExecutionTrace) > 0 {
		if traceBytes, err := json.Marshal(event.ExecutionTrace); err == nil {
			executionTrace = string(traceBytes)
		}
	}
	payload := map[string]interface{}{
		"record_id":           canonicalUUID(event.ID),
		"tenant_id":           canonicalUUID(event.TenantID),
		"timestamp":           standardizeAuditTimestamp(event.Timestamp),
		"actor_id":            "",
		"actor_type":          "gateway",
		"action":              event.Action,
		"policy_id":           event.PolicyID,
		"provider":            event.Provider,
		"model":               event.Model,
		"reason":              event.DecisionReason,
		"prompt_count":        event.PromptCount,
		"request_size":        event.RequestSize,
		"response_status":     event.ResponseStatus,
		"duration_ms":         event.DurationMs,
		"frameworks_affected": frameworks,
		"execution_trace":     executionTrace,
		"request_id":          event.RequestID,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func hashAuditEvent(event *AuditEvent, priorHash string) string {
	sum := sha256.Sum256([]byte(canonicalAuditJSON(event) + priorHash))
	return hex.EncodeToString(sum[:])
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
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", event.TenantID); err != nil {
			return err
		}

		priorHash := auditGenesisHash
		var priorCreatedAt sql.NullTime
		if err := tx.QueryRowContext(ctx, `
			SELECT COALESCE(integrity_hash, ''), created_at
			FROM audit_log_metadata
			WHERE tenant_id = $1
			  AND COALESCE(integrity_hash, '') <> ''
			ORDER BY created_at DESC, record_id DESC
			LIMIT 1
		`, event.TenantID).Scan(&priorHash, &priorCreatedAt); err != nil && err != sql.ErrNoRows {
			return err
		}
		if priorHash == "" {
			priorHash = auditGenesisHash
		}
		chainTimestamp := event.Timestamp.UTC()
		if chainTimestamp.IsZero() {
			chainTimestamp = time.Now().UTC()
		}
		if priorCreatedAt.Valid && !chainTimestamp.After(priorCreatedAt.Time) {
			chainTimestamp = priorCreatedAt.Time.Add(time.Millisecond)
		}
		eventForHash := *event
		eventForHash.Timestamp = chainTimestamp
		integrityHash := hashAuditEvent(&eventForHash, priorHash)
		event.Timestamp = chainTimestamp
		event.PriorHash = priorHash
		event.IntegrityHash = integrityHash
		executionTrace := "[]"
		if len(event.ExecutionTrace) > 0 {
			if traceBytes, traceErr := json.Marshal(event.ExecutionTrace); traceErr == nil {
				executionTrace = string(traceBytes)
			}
		}

		_, err := tx.ExecContext(ctx, `
			INSERT INTO audit_log_metadata (
				id, tenant_id, record_id, actor_id, action, request_id, policy_id,
				provider, model, reason, prompt_count, request_size, response_status,
				duration_ms, frameworks_affected, created_at, prior_hash, integrity_hash,
				actor_type, execution_trace
			)
			VALUES (
				gen_random_uuid(), $1, $2::uuid, NULL, $3, $4, NULLIF($5, '')::uuid,
				$6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
			)
			ON CONFLICT (record_id) DO NOTHING
		`,
			event.TenantID,
			event.ID,
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
			chainTimestamp,
			priorHash,
			integrityHash,
			"gateway",
			executionTrace,
		)
		return err
	})
	if err != nil {
		return err
	}
	return nil
}

func AuditMetricsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"authclaw_gateway_audit_postgres_failures_total":    auditPostgresFailures.Load(),
		"authclaw_gateway_audit_outbox_writes_total":        auditOutboxWrites.Load(),
		"authclaw_gateway_audit_outbox_failures_total":      auditOutboxFailures.Load(),
		"authclaw_gateway_audit_fail_closed_failures_total": auditFailClosedFailures.Load(),
	}
}
