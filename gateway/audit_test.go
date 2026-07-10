package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestEmitAuditEvent(t *testing.T) {
	event := &AuditEvent{
		ID:             "test-id",
		Timestamp:      time.Now(),
		TenantID:       "tenant-123",
		Provider:       "openai",
		Model:          "gpt-4",
		PromptCount:    1,
		RequestSize:    100,
		ResponseStatus: 200,
		DurationMs:     50,
	}

	// Make sure it runs and serializes without errors
	EmitAuditEvent(event)
}

func TestEmitAuditEvent_WritesOutboxWhenFailClosedAndDatabaseUnavailable(t *testing.T) {
	originalDB := DB
	DB = nil
	t.Cleanup(func() { DB = originalDB })
	t.Setenv("AUTHCLAW_ENV", "production")
	t.Setenv("AUDIT_FAIL_CLOSED", "true")
	outboxPath := filepath.Join(t.TempDir(), "audit-outbox.ndjson")
	t.Setenv("AUDIT_OUTBOX_PATH", outboxPath)

	event := &AuditEvent{
		ID:             "11111111-1111-4111-8111-111111111111",
		RequestID:      "req-outbox",
		Timestamp:      time.Now(),
		TenantID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Action:         "allow",
		DecisionReason: "outbox test",
	}

	if err := EmitAuditEvent(event); err != nil {
		t.Fatalf("EmitAuditEvent returned error with durable outbox available: %v", err)
	}
	data, err := os.ReadFile(outboxPath)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	var envelope auditOutboxEnvelope
	if err := json.Unmarshal(data[:len(data)-1], &envelope); err != nil {
		t.Fatalf("unmarshal outbox envelope: %v", err)
	}
	if envelope.Event == nil || envelope.Event.RequestID != "req-outbox" {
		t.Fatalf("unexpected outbox event: %+v", envelope.Event)
	}
}

func TestEmitAuditEvent_FailClosedWhenOutboxUnavailable(t *testing.T) {
	originalDB := DB
	DB = nil
	t.Cleanup(func() { DB = originalDB })
	t.Setenv("AUTHCLAW_ENV", "production")
	t.Setenv("AUDIT_FAIL_CLOSED", "true")
	t.Setenv("AUDIT_OUTBOX_PATH", t.TempDir())

	err := EmitAuditEvent(&AuditEvent{
		ID:        "22222222-2222-4222-8222-222222222222",
		TenantID:  "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Timestamp: time.Now(),
		Action:    "allow",
	})
	if err == nil {
		t.Fatalf("expected fail-closed error when Postgres and outbox are unavailable")
	}
}

func TestAuditEventMetadataConcurrentHashChain(t *testing.T) {
	if os.Getenv("AUTHCLAW_GATEWAY_AUDIT_DB_TESTS") != "true" {
		t.Skip("set AUTHCLAW_GATEWAY_AUDIT_DB_TESTS=true to run Postgres audit-chain test")
	}

	InitDB()
	ensureAuditChainTestSchema(t)

	tenantID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	_, err := DB.Exec(
		"INSERT INTO tenants (id, name, tier, status) VALUES ($1, $2, 'starter', 'active') ON CONFLICT (id) DO NOTHING",
		tenantID,
		"Audit Chain Test Tenant",
	)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = DB.Exec("DELETE FROM audit_log_metadata WHERE tenant_id = $1", tenantID)
	})
	_, _ = DB.Exec("DELETE FROM audit_log_metadata WHERE tenant_id = $1", tenantID)

	const workers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			persistAuditMetadata(&AuditEvent{
				ID:             fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012d", i),
				RequestID:      fmt.Sprintf("req-%02d", i),
				Timestamp:      time.Unix(1700000000, 0),
				TenantID:       tenantID,
				Action:         "allow",
				DecisionReason: "concurrency audit-chain test",
				Provider:       "test",
				Model:          "mock",
				PromptCount:    1,
				RequestSize:    10 + i,
				ResponseStatus: 200,
				DurationMs:     int64(i),
			})
		}(i)
	}
	close(start)
	wg.Wait()

	rows, err := DB.Query(`
		SELECT record_id, request_id, action, provider, model, reason, prompt_count,
		       request_size, response_status, duration_ms, frameworks_affected,
		       execution_trace, created_at, prior_hash, integrity_hash
		FROM audit_log_metadata
		WHERE tenant_id = $1
		ORDER BY created_at ASC, record_id ASC
	`, tenantID)
	if err != nil {
		t.Fatalf("query audit chain: %v", err)
	}
	defer rows.Close()

	prior := auditGenesisHash
	count := 0
	for rows.Next() {
		var (
			recordID       string
			requestID      string
			action         string
			provider       string
			model          string
			reason         string
			promptCount    int
			requestSize    int
			responseStatus int
			durationMs     int64
			frameworks     pq.StringArray
			executionTrace sql.NullString
			createdAt      time.Time
			priorHash      string
			integrityHash  string
		)
		if err := rows.Scan(
			&recordID,
			&requestID,
			&action,
			&provider,
			&model,
			&reason,
			&promptCount,
			&requestSize,
			&responseStatus,
			&durationMs,
			&frameworks,
			&executionTrace,
			&createdAt,
			&priorHash,
			&integrityHash,
		); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		if priorHash != prior {
			t.Fatalf("row %d prior_hash = %q, want %q", count, priorHash, prior)
		}
		trace := []string(nil)
		if executionTrace.Valid && executionTrace.String != "" && executionTrace.String != "[]" {
			trace = []string{executionTrace.String}
		}
		event := &AuditEvent{
			ID:                 recordID,
			RequestID:          requestID,
			Timestamp:          createdAt,
			TenantID:           tenantID,
			Action:             action,
			DecisionReason:     reason,
			Provider:           provider,
			Model:              model,
			PromptCount:        promptCount,
			RequestSize:        requestSize,
			ResponseStatus:     responseStatus,
			DurationMs:         durationMs,
			FrameworksAffected: []string(frameworks),
			ExecutionTrace:     trace,
		}
		if got := hashAuditEvent(event, priorHash); got != integrityHash {
			t.Fatalf("row %d integrity_hash = %q, want %q", count, integrityHash, got)
		}
		prior = integrityHash
		count++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit rows: %v", err)
	}
	if count != workers {
		t.Fatalf("got %d audit rows, want %d", count, workers)
	}
}

func ensureAuditChainTestSchema(t *testing.T) {
	t.Helper()
	if _, err := DB.Exec(`
		CREATE TABLE IF NOT EXISTS tenants (
			id uuid PRIMARY KEY,
			name varchar(255) UNIQUE NOT NULL,
			tier varchar(50) NOT NULL DEFAULT 'starter',
			status varchar(50) NOT NULL DEFAULT 'active'
		)
	`); err != nil {
		t.Fatalf("ensure tenants table: %v", err)
	}
	if _, err := DB.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log_metadata (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id uuid NOT NULL,
			record_id uuid UNIQUE NOT NULL,
			actor_id uuid NULL,
			action varchar(255) NOT NULL,
			request_id text NULL,
			policy_id uuid NULL,
			provider text NULL,
			model text NULL,
			reason text NULL,
			prompt_count integer NULL,
			request_size integer NULL,
			response_status integer NULL,
			duration_ms bigint NULL,
			frameworks_affected text[] NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			prior_hash text NULL,
			integrity_hash text NULL,
			actor_type text NULL,
			execution_trace text NULL
		)
	`); err != nil {
		t.Fatalf("ensure audit table: %v", err)
	}
}
