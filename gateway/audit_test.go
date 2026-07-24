package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func randomTestUUID(t *testing.T) string {
	t.Helper()
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	)
}

func TestEmitAuditEvent(t *testing.T) {
	EmitAuditEvent(&AuditEvent{
		ID:             "test-id",
		Timestamp:      time.Now(),
		TenantID:       "tenant-123",
		Provider:       "openai",
		Model:          "gpt-4",
		PromptCount:    1,
		RequestSize:    100,
		ResponseStatus: 200,
		DurationMs:     50,
	})
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
	if err := EmitAuditEvent(event); err == nil {
		t.Fatal("fail-closed mode must reject a request without a canonical PostgreSQL append")
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
		t.Fatal("expected fail-closed error when Postgres and outbox are unavailable")
	}
}

func TestAuditEventMetadataConcurrentCanonicalAppend(t *testing.T) {
	if os.Getenv("AUTHCLAW_GATEWAY_AUDIT_DB_TESTS") != "true" {
		t.Skip("set AUTHCLAW_GATEWAY_AUDIT_DB_TESTS=true to run the PostgreSQL test")
	}
	InitDB()
	var functionExists bool
	if err := DB.QueryRow(`
		SELECT to_regprocedure(
			'append_audit_event_v2(uuid,uuid,text,timestamptz,uuid,text,text,text,uuid,text,text,text,integer,integer,integer,integer,text[],jsonb)'
		) IS NOT NULL
	`).Scan(&functionExists); err != nil || !functionExists {
		t.Fatalf("migration 028 must be applied before this test: %v", err)
	}

	tenantID := randomTestUUID(t)
	if _, err := DB.Exec(
		"INSERT INTO tenants (id, name, tier, status) VALUES ($1, $2, 'starter', 'active')",
		tenantID,
		"ACL-21 concurrency "+tenantID,
	); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	const workers = 100
	start := make(chan struct{})
	failures := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			event := &AuditEvent{
				ID:             randomTestUUID(t),
				IdempotencyKey: fmt.Sprintf("acl21-concurrency-%03d", i),
				RequestID:      fmt.Sprintf("req-%03d", i),
				Timestamp:      time.Unix(1700000000, int64(i)*1_000_000),
				TenantID:       tenantID,
				Action:         "allow",
				DecisionReason: "ACL-21 canonical append concurrency test",
				Provider:       "test",
				Model:          "mock",
				RequestSize:    i,
				ResponseStatus: 200,
			}
			if err := persistAuditMetadata(event); err != nil {
				failures <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("concurrent append failed: %v", err)
	}

	replayed := &AuditEvent{
		ID:             randomTestUUID(t),
		IdempotencyKey: "acl21-exact-replay",
		RequestID:      "req-exact-replay",
		Timestamp:      time.Unix(1700001000, 0),
		TenantID:       tenantID,
		Action:         "allow",
		DecisionReason: "exact duplicate replay",
		Provider:       "test",
		ResponseStatus: 200,
	}
	if err := persistAuditMetadata(replayed); err != nil {
		t.Fatalf("first replay append: %v", err)
	}
	firstSequence, firstHash := replayed.TenantSequence, replayed.IntegrityHash
	if err := persistAuditMetadata(replayed); err != nil {
		t.Fatalf("exact replay must return the existing row: %v", err)
	}
	if replayed.TenantSequence != firstSequence || replayed.IntegrityHash != firstHash {
		t.Fatal("exact replay returned different proof data")
	}
	collision := *replayed
	collision.ID = randomTestUUID(t)
	collision.Action = "block"
	if err := persistAuditMetadata(&collision); err == nil {
		t.Fatal("changed content with the same idempotency key must fail")
	}

	ctx := context.Background()
	err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT tenant_sequence, prior_hash, integrity_hash,
			       encode(
			           digest(
			               convert_to(canonical_payload || prior_hash, 'UTF8'),
			               'sha256'
			           ),
			           'hex'
			       ) AS expected_hash
			FROM audit_log_metadata
			WHERE tenant_id = $1
			ORDER BY tenant_sequence
		`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		priorHash := "GENESIS"
		count := 0
		for rows.Next() {
			var sequence int
			var previous, integrity, expected string
			if err := rows.Scan(&sequence, &previous, &integrity, &expected); err != nil {
				return err
			}
			count++
			if sequence != count {
				return fmt.Errorf("sequence %d, want %d", sequence, count)
			}
			if previous != priorHash {
				return fmt.Errorf("sequence %d prior hash mismatch", sequence)
			}
			if integrity != expected {
				return fmt.Errorf("sequence %d integrity hash mismatch", sequence)
			}
			priorHash = integrity
		}
		if count != workers+1 {
			return fmt.Errorf("got %d rows, want %d", count, workers+1)
		}
		var outboxCount int
		if err := tx.QueryRowContext(
			ctx,
			"SELECT count(*) FROM audit_outbox WHERE tenant_id = $1",
			tenantID,
		).Scan(&outboxCount); err != nil {
			return err
		}
		if outboxCount != workers+1 {
			return fmt.Errorf("got %d outbox rows, want %d", outboxCount, workers+1)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(
			ctx,
			"UPDATE audit_log_metadata SET action = 'tampered' WHERE tenant_id = $1",
			tenantID,
		)
		return err
	}); err == nil {
		t.Fatal("immutable trigger must reject UPDATE")
	}
	if err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(
			ctx,
			"DELETE FROM audit_log_metadata WHERE tenant_id = $1",
			tenantID,
		)
		return err
	}); err == nil {
		t.Fatal("immutable trigger must reject DELETE")
	}
}

func TestAuditEventMetadataConcurrentMultiTenant(t *testing.T) {
	if os.Getenv("AUTHCLAW_GATEWAY_AUDIT_DB_TESTS") != "true" {
		t.Skip("set AUTHCLAW_GATEWAY_AUDIT_DB_TESTS=true to run the PostgreSQL test")
	}
	InitDB()
	const tenantCount = 4
	const eventsPerTenant = 20
	tenants := make([]string, tenantCount)
	for index := range tenants {
		tenants[index] = randomTestUUID(t)
		if _, err := DB.Exec(
			"INSERT INTO tenants (id, name, tier, status) VALUES ($1, $2, 'starter', 'active')",
			tenants[index],
			"ACL-21 multi-tenant "+tenants[index],
		); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	failures := make(chan error, tenantCount*eventsPerTenant)
	var wg sync.WaitGroup
	for _, tenantID := range tenants {
		for index := 0; index < eventsPerTenant; index++ {
			wg.Add(1)
			go func(tenantID string, index int) {
				defer wg.Done()
				<-start
				failures <- persistAuditMetadata(&AuditEvent{
					ID:             randomTestUUID(t),
					IdempotencyKey: fmt.Sprintf("multi-%s-%d", tenantID, index),
					Timestamp:      time.Unix(1700010000, int64(index)*1_000_000),
					TenantID:       tenantID,
					Action:         "allow",
					DecisionReason: "multi-tenant concurrency",
				})
			}(tenantID, index)
		}
	}
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.Background()
	for _, tenantID := range tenants {
		err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
			var count, minimum, maximum int
			if err := tx.QueryRowContext(ctx, `
				SELECT count(*), min(tenant_sequence), max(tenant_sequence)
				FROM audit_log_metadata WHERE tenant_id = $1
			`, tenantID).Scan(&count, &minimum, &maximum); err != nil {
				return err
			}
			if count != eventsPerTenant || minimum != 1 || maximum != eventsPerTenant {
				return fmt.Errorf(
					"tenant %s sequence range count=%d min=%d max=%d",
					tenantID,
					count,
					minimum,
					maximum,
				)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
