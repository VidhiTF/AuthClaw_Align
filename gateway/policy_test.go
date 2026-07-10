package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestValidatePolicyYAMLRejectsInvalidSRSFields(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "require approval timeout above SRS cap",
			yaml: `
regex_rules:
  - name: medical_review
    pattern: "(?i)diagnosis"
    action: require_approval
    hitl_timeout_seconds: 1801
`,
			want: "hitl_timeout_seconds",
		},
		{
			name: "topic rule without allowed models",
			yaml: `
topic_rules:
  - topic: medical
    allowed_models: []
`,
			want: "allowed model",
		},
		{
			name: "regex rule without pattern",
			yaml: `
regex_rules:
  - name: missing_pattern
    action: block
`,
			want: "missing pattern",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePolicyYAML(tt.yaml)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestPolicyEnforcement(t *testing.T) {
	// 1. Init DB and Redis
	InitDB()
	InitRedis()

	ctx := context.Background()

	// Clear DB tables
	_, err := DB.Exec("TRUNCATE TABLE audit_log_metadata, pending_approvals, redaction_tokens, gateway_configs, policies, api_keys, users, tenants CASCADE")
	if err != nil {
		t.Fatalf("Failed to truncate tables: %v", err)
	}

	// 2. Seed test tenants
	tenantA := "a0eebc99-0000-0000-0000-bb6d6bb9bd11"
	tenantB := "b0eebc99-0000-0000-0000-bb6d6bb9bd22"

	_, _ = DB.Exec("INSERT INTO tenants (id, name, tier, status) VALUES ($1, 'Tenant A', 'enterprise', 'active')", tenantA)
	_, _ = DB.Exec("INSERT INTO tenants (id, name, tier, status) VALUES ($1, 'Tenant B', 'starter', 'active')", tenantB)

	// Seed user for Tenant A
	userA := "a0eebc99-0000-0000-0000-bb6d6bb9bd33"
	_, _ = DB.Exec("INSERT INTO users (id, tenant_id, email, role, mfa_enabled, is_active) VALUES ($1, $2, 'adminA@example.com', 'admin', false, true)", userA, tenantA)

	// Seed user for Tenant B
	userB := "b0eebc99-0000-0000-0000-bb6d6bb9bd44"
	_, _ = DB.Exec("INSERT INTO users (id, tenant_id, email, role, mfa_enabled, is_active) VALUES ($1, $2, 'adminB@example.com', 'admin', false, true)", userB, tenantB)

	// 3. Test YAML Validation & Regex check
	t.Run("YAML_Validation_Syntax_And_Regex", func(t *testing.T) {
		validYAML := `
model_rules:
  blacklist:
    - gpt-3.5-turbo
regex_rules:
  - pattern: "(?i)confidential"
    reason: "Strict confidentiality block"
`
		config, err := ValidatePolicyYAML(validYAML)
		if err != nil {
			t.Fatalf("Expected valid YAML parsing, got: %v", err)
		}
		if len(config.ModelRules.Blacklist) != 1 || config.ModelRules.Blacklist[0] != "gpt-3.5-turbo" {
			t.Errorf("Blacklist parsed incorrectly: %v", config.ModelRules.Blacklist)
		}

		invalidRegexYAML := `
regex_rules:
  - pattern: "["
    reason: "Invalid brackets pattern"
`
		_, err = ValidatePolicyYAML(invalidRegexYAML)
		if err == nil {
			t.Errorf("Expected compile error for invalid regex, but passed")
		}
	})

	// 4. Test Model Blacklist and Whitelist via OPA
	t.Run("OPA_Model_Blacklist_And_Whitelist", func(t *testing.T) {
		policyYAML := `
model_rules:
  whitelist:
    - gemini-2.5-flash-lite
    - gpt-4
  blacklist:
    - gpt-3.5-turbo
`
		// Insert policy for Tenant A
		_, err := DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Blacklist Whitelist Policy', $2, 1, true, $3)", tenantA, policyYAML, userA)
		if err != nil {
			t.Fatalf("Failed to insert policy for Tenant A: %v", err)
		}
		InvalidatePolicyCache(tenantA)

		// Test allowed model
		allow, reason, _, err := EvaluatePolicy(ctx, tenantA, "gemini-2.5-flash-lite", "/v1/chat/completions", []string{"Hello"}, nil)
		if err != nil {
			t.Fatalf("EvaluatePolicy failed: %v", err)
		}
		if !allow {
			t.Errorf("Expected allowed model to pass, got block with reason: %s", reason)
		}

		// Test blacklisted model
		allow, reason, _, _ = EvaluatePolicy(ctx, tenantA, "gpt-3.5-turbo", "/v1/chat/completions", []string{"Hello"}, nil)
		if allow {
			t.Errorf("Expected blacklisted model to be blocked")
		}
		if !strings.Contains(reason, "blacklisted") {
			t.Errorf("Expected block reason about blacklist, got: %s", reason)
		}

		// Test non-whitelisted model
		allow, reason, _, _ = EvaluatePolicy(ctx, tenantA, "claude-3-opus", "/v1/chat/completions", []string{"Hello"}, nil)
		if allow {
			t.Errorf("Expected non-whitelisted model to be blocked")
		}
		if !strings.Contains(reason, "not in whitelist") {
			t.Errorf("Expected block reason about whitelist, got: %s", reason)
		}
	})

	// 5. Test Regex-based Blocking
	t.Run("Regex_Based_Blocking_Rules", func(t *testing.T) {
		policyYAML := `
regex_rules:
  - name: confidentiality_block
    pattern: "(?i)confidential"
    reason: "Confidentiality rules block"
    action: block
`
		// Update Tenant A policy
		_, _ = DB.Exec("DELETE FROM policies WHERE tenant_id = $1", tenantA)
		_, err := DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Regex Policy', $2, 2, true, $3)", tenantA, policyYAML, userA)
		if err != nil {
			t.Fatalf("Failed to update policy: %v", err)
		}
		InvalidatePolicyCache(tenantA)

		// Test clean prompt (allowed)
		allow, _, _, _ := EvaluatePolicy(ctx, tenantA, "gemini-2.5-flash-lite", "/v1/chat/completions", []string{"Hello there"}, nil)
		if !allow {
			t.Errorf("Expected clean prompt to pass")
		}

		// Test matching prompt (blocked)
		allow, reason, _, _ := EvaluatePolicy(ctx, tenantA, "gemini-2.5-flash-lite", "/v1/chat/completions", []string{"This is CONFIDENTIAL data"}, nil)
		if allow {
			t.Errorf("Expected matching prompt to be blocked")
		}
		if !strings.Contains(reason, "confidentiality_block") {
			t.Errorf("Expected regex block reason, got: %s", reason)
		}
	})

	// 6. Test Topic-based blocking
	t.Run("Topic_Classification_Enforcement", func(t *testing.T) {
		policyYAML := `
topic_rules:
  - topic: "medical"
    allowed_models:
      - clinical-gpt
    reason: "Medical queries only allowed on clinical-gpt"
`
		_, _ = DB.Exec("DELETE FROM policies WHERE tenant_id = $1", tenantA)
		_, _ = DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Topic Policy', $2, 3, true, $3)", tenantA, policyYAML, userA)
		InvalidatePolicyCache(tenantA)

		// Test non-medical topic or allowed model
		allow, _, _, _ := EvaluatePolicy(ctx, tenantA, "clinical-gpt", "/v1/chat/completions", []string{"diagnosed"}, []string{"medical"})
		if !allow {
			t.Errorf("Expected medical topic to pass on allowed clinical model")
		}

		// Test blocked model for medical topic
		allow, reason, _, _ := EvaluatePolicy(ctx, tenantA, "gemini-2.5-flash-lite", "/v1/chat/completions", []string{"diagnosed"}, []string{"medical"})
		if allow {
			t.Errorf("Expected medical topic to block non-clinical model")
		}
		if !strings.Contains(reason, "Topic block") {
			t.Errorf("Expected topic block reason, got: %s", reason)
		}
	})

	// 7. Test Tenant-Scoped Rate Limiting & Quota Exhaustion Isolation
	t.Run("Rate_Limiting_Tenant_Isolation", func(t *testing.T) {
		// Set rate limit for Tenant A & Tenant B to 1 request per minute
		policyYAML := `
rate_limits:
  requests_per_minute: 1
`
		_, _ = DB.Exec("DELETE FROM policies")
		_, _ = DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Limit A', $2, 1, true, $3)", tenantA, policyYAML, userA)
		_, _ = DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Limit B', $2, 1, true, $3)", tenantB, policyYAML, userB)

		InvalidatePolicyCache(tenantA)
		InvalidatePolicyCache(tenantB)

		// Clear rate limits in Redis
		now := time.Now().Format("200601021504")
		RedisClient.Del(ctx, "rate_limit:"+tenantA+":/v1/chat/completions:"+now)
		RedisClient.Del(ctx, "rate_limit:"+tenantB+":/v1/chat/completions:"+now)

		// 1st request for Tenant A (Allowed)
		allow, _, _, _ := EvaluatePolicy(ctx, tenantA, "gemini-2.5-flash-lite", "/v1/chat/completions", []string{"Hi"}, nil)
		if !allow {
			t.Errorf("Expected Tenant A first request to pass")
		}

		// 2nd request for Tenant A (Blocked - quota exhausted)
		allow, reason, _, _ := EvaluatePolicy(ctx, tenantA, "gemini-2.5-flash-lite", "/v1/chat/completions", []string{"Hi"}, nil)
		if allow {
			t.Errorf("Expected Tenant A second request to be blocked by rate limiting")
		}
		if !strings.Contains(reason, "Rate limit exceeded") {
			t.Errorf("Expected rate limit exceed reason, got: %s", reason)
		}

		// 1st request for Tenant B (Allowed - should NOT be blocked by Tenant A's exhaustion!)
		allow, _, _, _ = EvaluatePolicy(ctx, tenantB, "gemini-2.5-flash-lite", "/v1/chat/completions", []string{"Hi"}, nil)
		if !allow {
			t.Errorf("Expected Tenant B request to pass. Cross-tenant quota isolation failed!")
		}
	})

	// 8. Test Caching & Invalidation (Hot Reloading)
	t.Run("Policy_Caching_And_Hot_Reload_Invalidation", func(t *testing.T) {
		policyYAML1 := `
model_rules:
  blacklist:
    - forbidden-model
`
		_, _ = DB.Exec("DELETE FROM policies WHERE tenant_id = $1", tenantA)
		_, _ = DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Cache 1', $2, 1, true, $3)", tenantA, policyYAML1, userA)
		InvalidatePolicyCache(tenantA)

		// Populate cache
		allow, _, _, _ := EvaluatePolicy(ctx, tenantA, "forbidden-model", "/v1/chat/completions", []string{"Hi"}, nil)
		if allow {
			t.Errorf("Expected forbidden-model to be blocked initially")
		}

		// Update policy in DB directly without invalidating cache (it should STILL block because cache is used!)
		policyYAML2 := `
model_rules:
  blacklist: []
`
		_, _ = DB.Exec("UPDATE policies SET policy_yaml = $1 WHERE tenant_id = $2", policyYAML2, tenantA)

		allow, _, _, _ = EvaluatePolicy(ctx, tenantA, "forbidden-model", "/v1/chat/completions", []string{"Hi"}, nil)
		if allow {
			t.Errorf("Expected cached policy to block forbidden-model before cache invalidation")
		}

		// Explicitly invalidate cache (hot reload check!)
		InvalidatePolicyCache(tenantA)

		// Should now allow the forbidden-model
		allow, _, _, _ = EvaluatePolicy(ctx, tenantA, "forbidden-model", "/v1/chat/completions", []string{"Hi"}, nil)
		if !allow {
			t.Errorf("Expected updated policy to allow forbidden-model after cache invalidation")
		}
	})

	// 9. Test Default-Deny Safety
	t.Run("Default_Deny_Safety", func(t *testing.T) {
		// A. Malformed policy validation error
		badPolicyYAML := `
regex_rules:
  - pattern: "["
    reason: "Bad regex pattern"
`
		_, _ = DB.Exec("DELETE FROM policies WHERE tenant_id = $1", tenantA)
		_, _ = DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Bad Policy', $2, 1, true, $3)", tenantA, badPolicyYAML, userA)
		InvalidatePolicyCache(tenantA)

		allow, reason, _, _ := EvaluatePolicy(ctx, tenantA, "gemini-2.5-flash-lite", "/v1/chat/completions", []string{"Hi"}, nil)
		if allow {
			t.Errorf("Expected default-deny for malformed validation policy")
		}
		if !strings.Contains(reason, "parsing error") && !strings.Contains(reason, "validation failed") {
			t.Errorf("Expected parsing/validation fail reason, got: %s", reason)
		}

		// B. OPA Service Unavailable
		// Set OPA_URL to bad port
		os.Setenv("OPA_URL", "http://localhost:9999")
		defer os.Unsetenv("OPA_URL")

		// Re-seed clean policy
		cleanPolicy := `model_rules: {blacklist: []}`
		_, _ = DB.Exec("DELETE FROM policies WHERE tenant_id = $1", tenantA)
		_, _ = DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Clean Policy', $2, 1, true, $3)", tenantA, cleanPolicy, userA)
		InvalidatePolicyCache(tenantA)

		allow, reason, _, _ = EvaluatePolicy(ctx, tenantA, "gemini-2.5-flash-lite", "/v1/chat/completions", []string{"Hi"}, nil)
		if allow {
			t.Errorf("Expected default-deny when OPA service is unavailable")
		}
		if !strings.Contains(reason, "unavailable") {
			t.Errorf("Expected service unavailable reason, got: %s", reason)
		}
	})

	// 10. Test Cross-Tenant Policy Isolation
	t.Run("Cross_Tenant_Policy_Isolation", func(t *testing.T) {
		policyA := `
model_rules:
  blacklist:
    - block-model-for-a
`
		policyB := `
model_rules:
  blacklist:
    - block-model-for-b
`
		// Insert policy for Tenant A
		_, _ = DB.Exec("DELETE FROM policies")
		_, err := DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Policy A', $2, 1, true, $3)", tenantA, policyA, userA)
		if err != nil {
			t.Fatalf("Failed to insert policy for Tenant A: %v", err)
		}
		// Insert policy for Tenant B
		_, err = DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Policy B', $2, 1, true, $3)", tenantB, policyB, userB)
		if err != nil {
			t.Fatalf("Failed to insert policy for Tenant B: %v", err)
		}

		InvalidatePolicyCache(tenantA)
		InvalidatePolicyCache(tenantB)

		// Evaluate for Tenant A: block-model-for-a should be blocked
		allowA, _, _, _ := EvaluatePolicy(ctx, tenantA, "block-model-for-a", "/v1/chat/completions", []string{"Hi"}, nil)
		if allowA {
			t.Errorf("Expected Tenant A to block block-model-for-a")
		}

		// Evaluate for Tenant B: block-model-for-a should NOT be blocked (since Tenant B doesn't block it)
		allowB, _, _, _ := EvaluatePolicy(ctx, tenantB, "block-model-for-a", "/v1/chat/completions", []string{"Hi"}, nil)
		if !allowB {
			t.Errorf("Expected Tenant B to allow block-model-for-a (isolation failed)")
		}

		// Evaluate for Tenant A: block-model-for-b should NOT be blocked (since Tenant A doesn't block it)
		allowA2, _, _, _ := EvaluatePolicy(ctx, tenantA, "block-model-for-b", "/v1/chat/completions", []string{"Hi"}, nil)
		if !allowA2 {
			t.Errorf("Expected Tenant A to allow block-model-for-b (isolation failed)")
		}

		// Evaluate for Tenant B: block-model-for-b should be blocked
		allowB2, _, _, _ := EvaluatePolicy(ctx, tenantB, "block-model-for-b", "/v1/chat/completions", []string{"Hi"}, nil)
		if allowB2 {
			t.Errorf("Expected Tenant B to block block-model-for-b")
		}
	})
}

func TestProxyIntegrationWithPolicy(t *testing.T) {
	// 1. Setup mock provider backend
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"choices":[{"message":{"content":"Allowed Response"}}]}`))
	}))
	defer targetServer.Close()

	InitDB()
	InitRedis()

	// Seed tenant, config, user, api_key
	tenantID := "c0eebc99-1111-1111-1111-bb6d6bb9bd11"
	_, _ = DB.Exec("INSERT INTO tenants (id, name, tier, status) VALUES ($1, 'Proxy Policy Tenant', 'starter', 'active')", tenantID)

	userID := "c0eebc99-1111-1111-1111-bb6d6bb9bd22"
	_, _ = DB.Exec("INSERT INTO users (id, tenant_id, email, role, mfa_enabled, is_active) VALUES ($1, $2, 'proxy@example.com', 'admin', false, true)", userID, tenantID)

	apiKey := "authclaw_proxy_policy_key_1"
	keyHash := HashKey(apiKey)
	_, _ = DB.Exec("INSERT INTO api_keys (id, tenant_id, key_hash, name, scopes, is_active, created_by) VALUES (gen_random_uuid(), $1, $2, 'Proxy Policy Key', $3, true, $4)", tenantID, keyHash, pq.Array([]string{"read"}), userID)
	encryptedProviderKey, err := EncryptSecret("sk-test-provider")
	if err != nil {
		t.Fatalf("Failed to encrypt provider key: %v", err)
	}
	_, _ = DB.Exec(
		`INSERT INTO provider_credentials (
			id, tenant_id, provider, display_name, endpoint, encrypted_secret, auth_scheme, status, created_by, version
		) VALUES (
			gen_random_uuid(), $1, 'openai', 'Policy OpenAI', $2, $3, 'api_key', 'active', $4, 1
		)`,
		tenantID, targetServer.URL, encryptedProviderKey, userID,
	)

	// Point config to mock server
	_, _ = DB.Exec("DELETE FROM gateway_configs WHERE tenant_id = $1", tenantID)
	_, _ = DB.Exec("INSERT INTO gateway_configs (id, tenant_id, name, provider, endpoint, redaction_strategy, is_active) VALUES (gen_random_uuid(), $1, 'OpenAI Policy Dev', 'openai', $2, 'mask', true)", tenantID, targetServer.URL)

	// Create reverse proxy
	proxy := NewProxyServer()
	proxy.OpenAIBaseURL = targetServer.URL

	handler := AuthMiddleware(http.HandlerFunc(proxy.ServeHTTP))

	// A. Seed allowed policy
	allowedPolicy := `
model_rules:
  blacklist:
    - gpt-3.5-turbo
`
	_, _ = DB.Exec("DELETE FROM policies WHERE tenant_id = $1", tenantID)
	_, _ = DB.Exec("INSERT INTO policies (id, tenant_id, name, policy_yaml, version, is_active, created_by) VALUES (gen_random_uuid(), $1, 'Allowed Policy', $2, 1, true, $3)", tenantID, allowedPolicy, userID)
	InvalidatePolicyCache(tenantID)

	// Make request for allowed model (gpt-4) -> Expected 200 OK
	reqBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 OK for allowed policy, got %d", resp.StatusCode)
	}

	// B. Make request for blacklisted model (gpt-3.5-turbo) -> Expected 403 Forbidden
	reqBodyBlocked := `{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"Hello"}]}`
	reqBlocked := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(reqBodyBlocked))
	reqBlocked.Header.Set("Authorization", "Bearer "+apiKey)
	wBlocked := httptest.NewRecorder()

	handler.ServeHTTP(wBlocked, reqBlocked)

	respBlocked := wBlocked.Result()
	if respBlocked.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for blacklisted model, got %d", respBlocked.StatusCode)
	}

	respBodyBytes, _ := io.ReadAll(respBlocked.Body)
	if !strings.Contains(string(respBodyBytes), "blacklisted") {
		t.Errorf("Expected block reason in body, got: %s", string(respBodyBytes))
	}
}
