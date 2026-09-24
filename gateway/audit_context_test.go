package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAuditAuthenticatedContextPostgres(t *testing.T) {
	ownerURL := os.Getenv("AUDIT_TEST_OWNER_DATABASE_URL")
	if ownerURL == "" {
		t.Skip("requires dedicated PostgreSQL integration environment")
	}
	parsed, err := url.Parse(ownerURL)
	if err != nil || !strings.HasSuffix(parsed.Path, "_test") {
		t.Fatal("requires disposable test database")
	}
	// The disposable CI PostgreSQL service does not enable TLS.
	query := parsed.Query()
	if query.Get("sslmode") == "" {
		query.Set("sslmode", "disable")
	}
	parsed.RawQuery = query.Encode()
	owner, err := sql.Open("postgres", parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	appURL, err := url.Parse(os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	query = appURL.Query()
	if query.Get("sslmode") == "" {
		query.Set("sslmode", "disable")
	}
	appURL.RawQuery = query.Encode()
	app, err := sql.Open("postgres", appURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	oldDB, oldSkip, oldStream, oldWriter := DB, skipDatabaseSecurityValidationForTests, activeAuditStream, kafkaWriter
	DB, skipDatabaseSecurityValidationForTests = app, false
	writer := &fakeKafkaWriter{}
	kafkaWriter = writer
	activeAuditStream = &kafkaAuditStream{topics: auditTopics{events: defaultAuditEventsTopic}}
	defer func() {
		DB, skipDatabaseSecurityValidationForTests, activeAuditStream, kafkaWriter = oldDB, oldSkip, oldStream, oldWriter
	}()
	t.Setenv("AUDIT_FAIL_CLOSED", "true")
	t.Setenv("AUDIT_OUTBOX_PATH", t.TempDir()+"/recovery.ndjson")
	tenant, user, key := randomTestUUID(t), randomTestUUID(t), randomTestUUID(t)
	rawKey := "audit-integration-" + randomTestUUID(t)
	hash := HashKey(rawKey)
	if _, err = owner.Exec(`INSERT INTO tenants(id,name,status) VALUES ($1,$2,'active')`, tenant, "audit context regression "+tenant); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Audit rows are immutable. Keep this unique fixture in the disposable
		// CI database and disable its credentials rather than bypassing triggers.
		for _, table := range []string{"api_keys", "users"} {
			if _, e := owner.Exec("UPDATE "+table+" SET is_active=false WHERE tenant_id=$1", tenant); e != nil {
				t.Error(e)
			}
		}
	}()
	if _, err = owner.Exec(`INSERT INTO users(id,tenant_id,email,role,platform_role,is_active) VALUES ($1,$2,$3,'admin','NONE',true)`, user, tenant, user+"@example.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Exec(`INSERT INTO api_keys(id,tenant_id,key_hash,name,created_by) VALUES ($1,$2,$3,'audit-regression',$4)`, key, tenant, hash, user); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), APIKeyHashContextKey, hash)
	ctx = context.WithValue(ctx, CredentialKindContextKey, "api_key")
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = owner.Exec(`INSERT INTO authn.sessions(token_hash,tenant_id,user_id,authentication_method,expires_at) VALUES ($1,$2,$3,'password',now()+interval '5 minutes')`, hash, tenant, user); err != nil {
		t.Fatal(err)
	}
	t.Run("notification retains authenticated context", func(t *testing.T) {
		queueNotification(ctx, tenant, "", "policy_violation_block", "critical", "Regression notification", "Synthetic test only", "/audit")
		sessionCtx := context.WithValue(ctx, CredentialKindContextKey, "session")
		queueNotification(sessionCtx, tenant, user, "approval_requested", "warning", "Regression notification", "Synthetic test only", "/agent")
		deadline := time.Now().Add(4 * time.Second)
		for {
			var notifications int
			if err := owner.QueryRow("SELECT count(*) FROM notifications WHERE tenant_id=$1 AND title='Regression notification'", tenant).Scan(&notifications); err != nil {
				t.Fatal(err)
			}
			if notifications == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("authenticated notification was not persisted after request cancellation")
			}
			time.Sleep(20 * time.Millisecond)
		}
		for _, badCtx := range []context.Context{context.Background(), context.WithValue(context.WithoutCancel(ctx), APIKeyHashContextKey, "invalid")} {
			if err := insertNotification(badCtx, tenant, "", "test", "info", "Denied", "", ""); err == nil {
				t.Fatal("unauthenticated notification accepted")
			}
		}
		if err := insertNotification(context.WithoutCancel(ctx), randomTestUUID(t), "", "test", "info", "Denied", "", ""); err == nil {
			t.Fatal("cross-tenant notification accepted")
		}
		if _, err := owner.Exec("UPDATE authn.sessions SET revoked_at=now() WHERE token_hash=$1", hash); err != nil {
			t.Fatal(err)
		}
		if err := insertNotification(context.WithoutCancel(sessionCtx), tenant, user, "test", "info", "Denied", "", ""); err == nil {
			t.Fatal("revoked session notification accepted")
		}
		var leaked int
		if err := owner.QueryRow("SELECT count(*) FROM notifications WHERE tenant_id=$1 AND row_to_json(notifications)::text LIKE $2", tenant, "%"+hash+"%").Scan(&leaked); err != nil || leaked != 0 {
			t.Fatalf("credential leakage check: count=%d error=%v", leaked, err)
		}
	})
	recovered := &AuditEvent{ID: randomTestUUID(t), TenantID: tenant, Timestamp: time.Now().Add(-time.Minute).UTC(), Action: "allow", RequestID: "audit-restart-recovery"}
	for range 2 {
		if err = writeAuditOutbox(recovered, errors.New("simulated shutdown")); err != nil {
			t.Fatal(err)
		}
	}
	event := &AuditEvent{ID: randomTestUUID(t), TenantID: tenant, Timestamp: time.Now().UTC(), Action: "redact", RequestID: "audit-context-regression"}
	if err = EmitAuditEvent(ctx, event); err != nil {
		t.Fatalf("authenticated append after request cancellation: %v", err)
	}
	drainCtx, stopDrain := context.WithTimeout(context.Background(), 5*time.Second)
	if err = drainAuditEvents(drainCtx); err != nil {
		stopDrain()
		t.Fatal(err)
	}
	stopDrain()
	auditAsync.Lock()
	auditAsync.closing = false
	auditAsync.Unlock()
	if len(writer.messages) != 2 {
		t.Fatalf("expected live and recovered event publication, got %d", len(writer.messages))
	}
	if files, listErr := auditRecoveryFiles(); listErr != nil || len(files) != 0 {
		t.Fatalf("restart recovery was not consumed: files=%v err=%v", files, listErr)
	}
	if strings.Contains(string(writer.messages[0].Value), hash) {
		t.Fatal("credential leaked to transport")
	}
	var count int
	if err = owner.QueryRow("SELECT count(*) FROM audit_outbox WHERE tenant_id=$1 AND published_at IS NOT NULL", tenant).Scan(&count); err != nil || count != 2 {
		t.Fatalf("published outbox count %d: %v", count, err)
	}
	if err = owner.QueryRow("SELECT count(*) FROM audit_log_metadata WHERE tenant_id=$1 AND request_id=$2", tenant, recovered.RequestID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("recovered event count %d: %v", count, err)
	}
	if err = EmitAuditEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	drainCtx, stopDrain = context.WithTimeout(context.Background(), 5*time.Second)
	if err = drainAuditEvents(drainCtx); err != nil {
		stopDrain()
		t.Fatal(err)
	}
	stopDrain()
	auditAsync.Lock()
	auditAsync.closing = false
	auditAsync.Unlock()
	if len(writer.messages) != 2 {
		t.Fatal("duplicate append was republished")
	}
	for _, badCtx := range []context.Context{context.Background(), context.WithValue(ctx, APIKeyHashContextKey, "invalid")} {
		if err = persistAuditMetadata(badCtx, &AuditEvent{ID: randomTestUUID(t), TenantID: tenant}); err == nil {
			t.Fatal("unauthenticated append accepted")
		}
	}
	if err = persistAuditMetadata(ctx, &AuditEvent{ID: randomTestUUID(t), TenantID: randomTestUUID(t)}); err == nil {
		t.Fatal("cross-tenant append accepted")
	}
	t.Run("repeated correlation persists distinct requests", func(t *testing.T) {
		t.Setenv("GATEWAY_AUTH_LAST_USED_ENABLED", "false")
		ids := map[string]bool{}
		handler := AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Context().Value(RequestIDContextKey).(string)
			if ids[id] {
				t.Fatal("caller correlation reused as audit identity")
			}
			ids[id] = true
			observed := &AuditEvent{ID: randomTestUUID(t), TenantID: tenant, RequestID: id, Action: "block", IdempotencyKey: auditIdempotencyKey(id, "decision:block")}
			if e := EmitAuditEvent(r.Context(), observed); e != nil {
				t.Fatal(e)
			}
			if e := EmitAuditEvent(r.Context(), observed); e != nil {
				t.Fatal("legitimate retry changed canonical payload", e)
			}
		}))
		for range 2 {
			r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
			r.Header.Set("Authorization", "Bearer "+rawKey)
			r.Header.Set("X-Request-ID", "connect-test-repeated")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body.String())
			}
		}
		var observed int
		if e := owner.QueryRow("SELECT count(DISTINCT request_id) FROM audit_log_metadata WHERE tenant_id=$1 AND request_id LIKE 'gw2-%'", tenant).Scan(&observed); e != nil || observed != 2 {
			t.Fatalf("canonical aggregate undercounted repeated correlation: %d %v", observed, e)
		}
		// A fail-open outcome can be absent entirely. The backend must never
		// infer end-to-end completeness from these two well-identified rows.
		t.Setenv("AUDIT_FAIL_CLOSED", "false")
		before := auditFailOpenLosses.Load()
		lost := &AuditEvent{ID: randomTestUUID(t), TenantID: tenant, RequestID: "lost-outcome", Action: "allow", IdempotencyKey: auditIdempotencyKey("lost-outcome", "provider_outcome")}
		if e := EmitAuditEvent(context.Background(), lost); e != nil || auditFailOpenLosses.Load() != before+1 {
			t.Fatalf("fail-open persistence failure not exercised: %v", e)
		}
		if e := owner.QueryRow("SELECT count(*) FROM audit_log_metadata WHERE tenant_id=$1 AND request_id='lost-outcome'", tenant).Scan(&observed); e != nil || observed != 0 {
			t.Fatalf("failed outcome unexpectedly persisted: %d %v", observed, e)
		}
	})
}
