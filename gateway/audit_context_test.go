package main

import (
	"context"
	"database/sql"
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
	hash := strings.ReplaceAll(randomTestUUID(t), "-", "") + strings.ReplaceAll(randomTestUUID(t), "-", "")
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
	event := &AuditEvent{ID: randomTestUUID(t), TenantID: tenant, Timestamp: time.Now().UTC(), Action: "redact", RequestID: "audit-context-regression"}
	if err = EmitAuditEvent(ctx, event); err != nil {
		t.Fatalf("authenticated append after request cancellation: %v", err)
	}
	if len(writer.messages) != 1 {
		t.Fatalf("expected committed event publication, got %d", len(writer.messages))
	}
	if strings.Contains(string(writer.messages[0].Value), hash) {
		t.Fatal("credential leaked to transport")
	}
	var count int
	if err = owner.QueryRow("SELECT count(*) FROM audit_outbox WHERE tenant_id=$1 AND published_at IS NOT NULL", tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("published outbox count %d: %v", count, err)
	}
	if err = EmitAuditEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	if len(writer.messages) != 1 {
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
}
