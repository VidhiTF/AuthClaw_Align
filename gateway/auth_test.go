package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lib/pq"
)

func TestAuthMiddleware(t *testing.T) {
	// 1. Initialize DB
	InitDB()

	// 2. Clean database for test
	_, err := DB.Exec("TRUNCATE TABLE audit_log_metadata, pending_approvals, redaction_tokens, gateway_configs, policies, api_keys, users, tenants CASCADE")
	if err != nil {
		t.Fatalf("Failed to truncate tables: %v", err)
	}

	// 3. Insert test tenant
	tenantID := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	_, err = DB.Exec(
		"INSERT INTO tenants (id, name, tier, status) VALUES ($1, 'Test Tenant', 'starter', 'active')",
		tenantID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test tenant: %v", err)
	}

	// 4. Insert test user
	userID := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22"
	_, err = DB.Exec(
		"INSERT INTO users (id, tenant_id, email, role, platform_role, mfa_enabled, is_active) VALUES ($1, $2, 'test@example.com', 'admin', 'NONE', false, true)",
		userID, tenantID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test user: %v", err)
	}

	// 5. Insert test API key
	apiKey := "authclaw_test_api_key_123"
	keyHash := HashKey(apiKey)
	_, err = DB.Exec(
		"INSERT INTO api_keys (id, tenant_id, key_hash, name, scopes, is_active, created_by) VALUES (gen_random_uuid(), $1, $2, 'Test Key', $3, true, $4)",
		tenantID, keyHash, pq.Array([]string{"read", "write"}), userID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test API key: %v", err)
	}

	// 6. Test middleware with valid key
	req := httptest.NewRequest("GET", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()

	handlerTested := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerTested = true
		ctxTenantID := r.Context().Value(TenantIDContextKey).(string)
		ctxScopes := r.Context().Value(ScopesContextKey).([]string)

		if ctxTenantID != tenantID {
			t.Errorf("Expected tenant ID %s, got %s", tenantID, ctxTenantID)
		}

		if len(ctxScopes) != 2 || ctxScopes[0] != "read" || ctxScopes[1] != "write" {
			t.Errorf("Expected scopes [read, write], got %v", ctxScopes)
		}
	})

	AuthMiddleware(nextHandler).ServeHTTP(w, req)

	if !handlerTested {
		t.Error("Expected next handler to be called")
	}

	// 7. Test middleware with invalid key
	reqInvalid := httptest.NewRequest("GET", "/v1/chat/completions", nil)
	reqInvalid.Header.Set("Authorization", "Bearer invalid_key")
	wInvalid := httptest.NewRecorder()

	AuthMiddleware(nextHandler).ServeHTTP(wInvalid, reqInvalid)

	if wInvalid.Code != http.StatusUnauthorized {
		t.Errorf("Expected status code %d for invalid key, got %d", http.StatusUnauthorized, wInvalid.Code)
	}
}

func TestHashKeyUsesKeyedDigest(t *testing.T) {
	t.Setenv("API_KEY_HASH_SECRET", "pepper-one")

	digest := HashKey("acl_test")

	if digest != "b3c918c53064a470e644f166936ebee72d558517581e436327197837a5a7faaf" {
		t.Fatalf("unexpected keyed digest: %s", digest)
	}
	if HashKey("acl_test") != digest {
		t.Fatal("same key and secret should produce the same digest")
	}
	t.Setenv("API_KEY_HASH_SECRET", "pepper-two")
	if HashKey("acl_test") == digest {
		t.Fatal("changing the secret should change the digest")
	}
}

func TestHashKeyKeepsStableSessionKeyDuringRotation(t *testing.T) {
	t.Setenv("API_KEY_HASH_SECRET", "")
	t.Setenv("SESSION_SECRET", "active-session-secret")
	t.Setenv("SESSION_SECRET_V1", "stable-session-secret")
	digest := HashKey("acl_test")
	t.Setenv("SESSION_SECRET", "rotated-session-secret")
	if HashKey("acl_test") != digest {
		t.Fatal("session rotation must not invalidate API key hashes")
	}
}
