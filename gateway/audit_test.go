package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func readAuditRecoveryData(t *testing.T) []byte {
	t.Helper()
	files, err := auditRecoveryFiles()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	var data []byte
	for _, path := range files {
		part, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, part...)
	}
	return data
}

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
	EmitAuditEvent(context.Background(), &AuditEvent{
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
	if err := EmitAuditEvent(context.Background(), event); err == nil {
		t.Fatal("fail-closed mode must reject a request without a canonical PostgreSQL append")
	}
	data := readAuditRecoveryData(t)
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
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUDIT_OUTBOX_PATH", filepath.Join(blocked, "audit.ndjson"))

	err := EmitAuditEvent(context.Background(), &AuditEvent{
		ID:        "22222222-2222-4222-8222-222222222222",
		TenantID:  "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Timestamp: time.Now(),
		Action:    "allow",
	})
	if err == nil {
		t.Fatal("expected fail-closed error when Postgres and outbox are unavailable")
	}
}

func TestAuditEvent_OutboxConcurrentProcesses(t *testing.T) {
	if path := os.Getenv("AUTHCLAW_AUDIT_OUTBOX_HELPER_PATH"); path != "" {
		t.Setenv("AUDIT_OUTBOX_PATH", path)
		if err := writeAuditOutbox(&AuditEvent{ID: os.Getenv("AUTHCLAW_AUDIT_OUTBOX_HELPER_ID"), TenantID: "tenant"}, errors.New("test")); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	t.Setenv("AUDIT_OUTBOX_PATH", path)
	const writers = 8
	commands := make([]*exec.Cmd, writers)
	for i := range commands {
		commands[i] = exec.Command(os.Args[0], "-test.run=^TestAuditEvent_OutboxConcurrentProcesses$")
		commands[i].Env = append(os.Environ(), "AUTHCLAW_AUDIT_OUTBOX_HELPER_PATH="+path, fmt.Sprintf("AUTHCLAW_AUDIT_OUTBOX_HELPER_ID=writer-%d", i))
		if err := commands[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	data := string(readAuditRecoveryData(t))
	for i := range writers {
		if strings.Count(data, fmt.Sprintf("writer-%d", i)) != 1 {
			t.Fatalf("writer %d record missing or duplicated: %s", i, data)
		}
	}
	if backlog := AuditMetricsSnapshot()["authclaw_gateway_audit_recovery_backlog"]; backlog != writers {
		t.Fatalf("recovery backlog=%d, want %d", backlog, writers)
	}
	replayed := 0
	replayAuditRecovery(context.Background(), "tenant", func(context.Context, *AuditEvent) error {
		replayed++
		return nil
	})
	if replayed != writers || len(readAuditRecoveryData(t)) != 0 {
		t.Fatalf("restart replayed=%d, want %d", replayed, writers)
	}
}

func TestAuditEvent_LegacyMigrationConcurrentProcesses(t *testing.T) {
	if path := os.Getenv("AUTHCLAW_AUDIT_LEGACY_HELPER_PATH"); path != "" {
		t.Setenv("AUDIT_OUTBOX_PATH", path)
		if _, err := auditRecoveryFiles(); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	t.Setenv("AUDIT_OUTBOX_PATH", path)
	var legacy []byte
	for _, event := range []*AuditEvent{{ID: "legacy-a", TenantID: "tenant-a"}, {ID: "legacy-b", TenantID: "tenant-b"}} {
		line, err := json.Marshal(auditOutboxEnvelope{FailedAt: time.Now().Add(-time.Minute), Event: event})
		if err != nil {
			t.Fatal(err)
		}
		legacy = append(legacy, append(line, '\n')...)
	}
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	commands := make([]*exec.Cmd, 8)
	for i := range commands {
		commands[i] = exec.Command(os.Args[0], "-test.run=^TestAuditEvent_LegacyMigrationConcurrentProcesses$")
		commands[i].Env = append(os.Environ(), "AUTHCLAW_AUDIT_LEGACY_HELPER_PATH="+path)
		commands[i].Stdout, commands[i].Stderr = os.Stdout, os.Stderr
		if err := commands[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	data := string(readAuditRecoveryData(t))
	for _, id := range []string{"legacy-a", "legacy-b"} {
		if count := strings.Count(data, id); count != 1 {
			t.Fatalf("legacy event %s count=%d, want 1: %s", id, count, data)
		}
	}
}

func TestAuditEvent_ResumesClaimedLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	t.Setenv("AUDIT_OUTBOX_PATH", path)
	var legacy []byte
	for _, event := range []*AuditEvent{{ID: "claimed-a", TenantID: "tenant-a"}, {ID: "claimed-b", TenantID: "tenant-b"}} {
		line, err := json.Marshal(auditOutboxEnvelope{Event: event})
		if err != nil {
			t.Fatal(err)
		}
		legacy = append(legacy, append(line, '\n')...)
	}
	claimed := path + ".legacy.ready"
	if err := os.WriteFile(claimed, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := auditRecoveryFiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0] == claimed || files[1] == claimed {
		t.Fatalf("claimed legacy recovery was not resumed: %v", files)
	}
	data := string(readAuditRecoveryData(t))
	if strings.Count(data, "claimed-a") != 1 || strings.Count(data, "claimed-b") != 1 {
		t.Fatalf("claimed legacy records were not split exactly once: %s", data)
	}
}

func TestAuditEvent_RecoversStaleAtomicTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.ndjson")
	t.Setenv("AUDIT_OUTBOX_PATH", path)
	failedAt := time.Now().Add(-2 * time.Minute)
	line, err := json.Marshal(auditOutboxEnvelope{FailedAt: failedAt, Event: &AuditEvent{ID: "complete-temp", TenantID: "tenant"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, payload := range map[string][]byte{".audit-recovery-complete.tmp": append(line, '\n'), ".audit-recovery-invalid.tmp": []byte("partial")} {
		temp := filepath.Join(dir, name)
		if err := os.WriteFile(temp, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(temp, failedAt, failedAt); err != nil {
			t.Fatal(err)
		}
	}
	before := auditRecoveryScanFailures.Load()
	metrics := AuditMetricsSnapshot()
	if metrics["authclaw_gateway_audit_recovery_backlog"] != 2 || auditRecoveryScanFailures.Load() != before+1 {
		t.Fatalf("stale temp metrics=%v scan_failures=%d", metrics, auditRecoveryScanFailures.Load()-before)
	}
	persisted := ""
	replayAuditRecovery(context.Background(), "tenant", func(_ context.Context, event *AuditEvent) error {
		persisted = event.ID
		return nil
	})
	if persisted != "complete-temp" {
		t.Fatalf("complete temp was not replayed: %q", persisted)
	}
	if data := string(readAuditRecoveryData(t)); !strings.Contains(data, "partial") {
		t.Fatalf("invalid temp was not retained for investigation: %s", data)
	}
}

func TestAuditEvent_RecoveryReplayIsBoundedBackgroundWork(t *testing.T) {
	t.Setenv("AUDIT_OUTBOX_PATH", filepath.Join(t.TempDir(), "audit.ndjson"))
	if err := writeAuditOutbox(&AuditEvent{ID: "background", TenantID: "tenant"}, errors.New("restart")); err != nil {
		t.Fatal(err)
	}
	oldPersist := auditRecoveryPersist
	entered := make(chan struct{})
	auditRecoveryPersist = func(ctx context.Context, _ *AuditEvent) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	t.Cleanup(func() {
		auditRecoveryPersist = oldPersist
		auditAsync.Lock()
		auditAsync.closing = false
		auditAsync.Unlock()
	})
	started := time.Now()
	scheduleAuditRecovery(context.Background(), "tenant")
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("recovery scheduling blocked request path for %v", elapsed)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("background replay did not start")
	}
	deadline, cancel := context.WithCancel(context.Background())
	cancel()
	if err := drainAuditEvents(deadline); !errors.Is(err, context.Canceled) {
		t.Fatalf("drain error=%v, want cancellation", err)
	}
	drained, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := drainAuditEvents(drained); err != nil {
		t.Fatal(err)
	}
	if data := readAuditRecoveryData(t); !strings.Contains(string(data), "background") {
		t.Fatal("canceled background replay removed uncommitted recovery")
	}
}

func TestAuditEvent_RecoveryQueueDoesNotDropTenants(t *testing.T) {
	t.Setenv("AUDIT_OUTBOX_PATH", filepath.Join(t.TempDir(), "audit.ndjson"))
	for _, event := range []*AuditEvent{{ID: "queued-a", TenantID: "tenant-a"}, {ID: "queued-b", TenantID: "tenant-b"}} {
		if err := writeAuditOutbox(event, errors.New("restart")); err != nil {
			t.Fatal(err)
		}
	}
	oldPersist := auditRecoveryPersist
	entered, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var persisted []string
	auditRecoveryPersist = func(ctx context.Context, event *AuditEvent) error {
		if event.TenantID == "tenant-a" {
			select {
			case <-entered:
			default:
				close(entered)
			}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		mu.Lock()
		persisted = append(persisted, event.TenantID)
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() {
		auditRecoveryPersist = oldPersist
		auditAsync.Lock()
		auditAsync.closing = false
		auditAsync.Unlock()
	})
	scheduleAuditRecovery(context.Background(), "tenant-a")
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first tenant recovery did not start")
	}
	scheduleAuditRecovery(context.Background(), "tenant-b")
	if err := writeAuditOutbox(&AuditEvent{ID: "queued-a-rerun", TenantID: "tenant-a"}, errors.New("restart")); err != nil {
		t.Fatal(err)
	}
	scheduleAuditRecovery(context.Background(), "tenant-a")
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := drainAuditEvents(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	sort.Strings(persisted)
	if strings.Join(persisted, ",") != "tenant-a,tenant-a,tenant-b" {
		t.Fatalf("persisted tenants=%v", persisted)
	}
}

func TestAuditEvent_RecoveryQueueBoundsDistinctTenants(t *testing.T) {
	t.Setenv("AUDIT_OUTBOX_PATH", filepath.Join(t.TempDir(), "audit.ndjson"))
	oldPersist := auditRecoveryPersist
	entered, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	persisted := 0
	auditRecoveryPersist = func(ctx context.Context, event *AuditEvent) error {
		if event.ID == "event-000" {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		mu.Lock()
		persisted++
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() {
		auditRecoveryPersist = oldPersist
		auditAsync.Lock()
		auditAsync.closing = false
		auditAsync.Unlock()
	})
	queue := func(index int) error {
		tenant := fmt.Sprintf("tenant-%03d", index)
		if err := writeAuditOutbox(&AuditEvent{ID: fmt.Sprintf("event-%03d", index), TenantID: tenant}, errors.New("restart")); err != nil {
			return err
		}
		scheduleAuditRecovery(context.Background(), tenant)
		return nil
	}
	if err := queue(0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first tenant recovery did not start")
	}
	for index := 1; index < auditRecoveryQueueLimit; index++ {
		if err := queue(index); err != nil {
			t.Fatal(err)
		}
	}
	overflowDone := make(chan error, 1)
	go func() {
		overflowDone <- queue(auditRecoveryQueueLimit)
	}()
	select {
	case <-overflowDone:
		t.Fatal("recovery scheduler exceeded its tenant bound")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-overflowDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backpressured tenant was not admitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := drainAuditEvents(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if persisted != auditRecoveryQueueLimit+1 || len(auditRecoveryAdmissions) != 0 {
		t.Fatalf("persisted=%d admissions=%d", persisted, len(auditRecoveryAdmissions))
	}
}

func TestAuditEvent_IndeterminateDirectorySyncReportsRecoveryAvailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	t.Setenv("AUDIT_OUTBOX_PATH", path)
	oldSyncDir := auditOutboxSyncDir
	auditOutboxSyncDir = func(string) error { return errors.New("forced directory sync failure") }
	t.Cleanup(func() { auditOutboxSyncDir = oldSyncDir })
	available, err := recoverAuditEvent(context.Background(), &AuditEvent{ID: "synced", TenantID: "tenant"}, errors.New("database unavailable"))
	var indeterminate *auditOutboxIndeterminateError
	if !available || !errors.As(err, &indeterminate) {
		t.Fatalf("available=%t err=%v, want indeterminate durable recovery", available, err)
	}
	files, globErr := filepath.Glob(path + ".*.ready")
	if globErr != nil || len(files) != 1 {
		t.Fatalf("ready files=%v err=%v", files, globErr)
	}
}

func TestAuditEvent_ReplaysPersistedRecoveryByTenant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	t.Setenv("AUDIT_OUTBOX_PATH", path)
	var legacy []byte
	for _, event := range []*AuditEvent{{ID: "legacy-a", TenantID: "tenant-a"}, {ID: "legacy-b", TenantID: "tenant-b"}} {
		line, err := json.Marshal(auditOutboxEnvelope{FailedAt: time.Now().Add(-time.Minute), Event: event})
		if err != nil {
			t.Fatal(err)
		}
		legacy = append(legacy, append(line, '\n')...)
	}
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, event := range []*AuditEvent{
		{ID: "recovered-a", TenantID: "tenant-a"},
		{ID: "recovered-a", TenantID: "tenant-a"},
		{ID: "recovered-b", TenantID: "tenant-b"},
	} {
		if err := writeAuditOutbox(event, errors.New("simulated restart")); err != nil {
			t.Fatal(err)
		}
	}
	persisted := make(map[string]struct{})
	replayAuditRecovery(context.Background(), "tenant-a", func(_ context.Context, event *AuditEvent) error {
		persisted[event.ID] = struct{}{}
		return nil
	})
	if _, ok := persisted["recovered-a"]; !ok || len(persisted) != 2 {
		t.Fatalf("unexpected replay set: %v", persisted)
	}
	if _, ok := persisted["legacy-a"]; !ok {
		t.Fatalf("legacy recovery was not replayed: %v", persisted)
	}
	if data := string(readAuditRecoveryData(t)); strings.Contains(data, "recovered-a") || !strings.Contains(data, "recovered-b") || !strings.Contains(data, "legacy-b") {
		t.Fatalf("tenant-isolated replay left unexpected recovery data: %s", data)
	}
	if backlog := AuditMetricsSnapshot()["authclaw_gateway_audit_recovery_backlog"]; backlog != 2 {
		t.Fatalf("recovery backlog=%d, want 2", backlog)
	}
}

func TestAuditEvent_ReplayFailureRetainsRecovery(t *testing.T) {
	t.Setenv("AUDIT_OUTBOX_PATH", filepath.Join(t.TempDir(), "audit.ndjson"))
	if err := writeAuditOutbox(&AuditEvent{ID: "retry", TenantID: "tenant"}, errors.New("simulated restart")); err != nil {
		t.Fatal(err)
	}
	before := auditRecoveryReplayFailures.Load()
	replayAuditRecovery(context.Background(), "tenant", func(context.Context, *AuditEvent) error {
		return errors.New("database unavailable")
	})
	if data := readAuditRecoveryData(t); !strings.Contains(string(data), "retry") {
		t.Fatal("failed replay removed its durable recovery record")
	}
	if auditRecoveryReplayFailures.Load() != before+1 {
		t.Fatal("failed replay was not observable")
	}
}

func TestAuditEvent_ReplayCheckpointsPartialProgress(t *testing.T) {
	t.Setenv("AUDIT_OUTBOX_PATH", filepath.Join(t.TempDir(), "audit.ndjson"))
	events := []*AuditEvent{{ID: "first", TenantID: "tenant"}, {ID: "second", TenantID: "tenant"}, {ID: "third", TenantID: "tenant"}}
	if err := writeAuditOutboxBatch(events, errors.New("restart")); err != nil {
		t.Fatal(err)
	}
	var firstPass []string
	replayAuditRecovery(context.Background(), "tenant", func(_ context.Context, event *AuditEvent) error {
		firstPass = append(firstPass, event.ID)
		if event.ID == "second" {
			return errors.New("database unavailable")
		}
		return nil
	})
	if strings.Join(firstPass, ",") != "first,second" {
		t.Fatalf("first replay=%v", firstPass)
	}
	data := string(readAuditRecoveryData(t))
	if strings.Contains(data, `"id":"first"`) || !strings.Contains(data, `"id":"second"`) || !strings.Contains(data, `"id":"third"`) {
		t.Fatalf("partial checkpoint=%s", data)
	}
	var secondPass []string
	replayAuditRecovery(context.Background(), "tenant", func(_ context.Context, event *AuditEvent) error {
		secondPass = append(secondPass, event.ID)
		return nil
	})
	if strings.Join(secondPass, ",") != "second,third" || len(readAuditRecoveryData(t)) != 0 {
		t.Fatalf("second replay=%v", secondPass)
	}
}

func TestAuditEvent_ReplayCheckpointsAtBatchLimit(t *testing.T) {
	t.Setenv("AUDIT_OUTBOX_PATH", filepath.Join(t.TempDir(), "audit.ndjson"))
	events := make([]*AuditEvent, auditRecoveryReplayLimit+1)
	for index := range events {
		events[index] = &AuditEvent{ID: fmt.Sprintf("event-%03d", index), TenantID: "tenant"}
	}
	if err := writeAuditOutboxBatch(events, errors.New("restart")); err != nil {
		t.Fatal(err)
	}
	oldPersist := auditRecoveryPersist
	var replayed []string
	auditRecoveryPersist = func(_ context.Context, event *AuditEvent) error {
		replayed = append(replayed, event.ID)
		return nil
	}
	t.Cleanup(func() {
		auditRecoveryPersist = oldPersist
		auditAsync.Lock()
		auditAsync.closing = false
		auditAsync.Unlock()
	})
	scheduleAuditRecovery(context.Background(), "tenant")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := drainAuditEvents(ctx); err != nil {
		t.Fatal(err)
	}
	if len(replayed) != auditRecoveryReplayLimit+1 || replayed[len(replayed)-1] != "event-100" || len(readAuditRecoveryData(t)) != 0 {
		t.Fatalf("replayed=%v", replayed)
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
			if err := persistAuditMetadata(context.Background(), event); err != nil {
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
	if err := persistAuditMetadata(context.Background(), replayed); err != nil {
		t.Fatalf("first replay append: %v", err)
	}
	firstSequence, firstHash := replayed.TenantSequence, replayed.IntegrityHash
	if err := persistAuditMetadata(context.Background(), replayed); err != nil {
		t.Fatalf("exact replay must return the existing row: %v", err)
	}
	if replayed.TenantSequence != firstSequence || replayed.IntegrityHash != firstHash {
		t.Fatal("exact replay returned different proof data")
	}
	collision := *replayed
	collision.ID = randomTestUUID(t)
	collision.Action = "block"
	if err := persistAuditMetadata(context.Background(), &collision); err == nil {
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
				failures <- persistAuditMetadata(context.Background(), &AuditEvent{
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
