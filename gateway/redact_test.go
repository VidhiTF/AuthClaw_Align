package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestNormalizeDetectedEntityTreatsPhoneLikeUkNhsAsPhoneNumber(t *testing.T) {
	entity := normalizeDetectedEntity("UK_NHS", "9876543210", []RegexRule{
		{Name: "Phone", Pattern: `(\+?[0-9]{1,3}[-. ]?)?[0-9]{10}`, Action: "require_approval"},
	})
	if entity != "PHONE_NUMBER" {
		t.Fatalf("expected PHONE_NUMBER, got %s", entity)
	}
}

type chunkedReadCloser struct {
	chunks []string
	index  int
}

func (c *chunkedReadCloser) Read(p []byte) (int, error) {
	if c.index >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(p, c.chunks[c.index])
	c.index++
	return n, nil
}

func (c *chunkedReadCloser) Close() error {
	return nil
}

func TestStaticReversalReaderReplacesAcrossReadBoundaries(t *testing.T) {
	tokenMap := map[string]string{"[REDACTED_PERSON_123]": "John Doe"}
	body := &chunkedReadCloser{
		chunks: []string{"Hello ", "[REDA", "CTED_PERSON_", "123]", "!"},
	}

	reversed, err := io.ReadAll(NewStaticReversalReader(body, tokenMap))
	if err != nil {
		t.Fatalf("read static reversal: %v", err)
	}
	if string(reversed) != "Hello John Doe!" {
		t.Fatalf("unexpected reversed body: %s", string(reversed))
	}
}

func TestStreamingReversalReaderOpenAISSEAcrossEvents(t *testing.T) {
	tokenMap := map[string]string{"[REDACTED_PERSON_123]": "John Doe"}
	body := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Hello [REDA"}}]}`,
		`data: {"choices":[{"delta":{"content":"CTED_PERSON_123]"}}]}`,
		`data: [DONE]`,
		"",
	}, "\n")

	reversed, err := io.ReadAll(NewStreamingReversalReader(io.NopCloser(strings.NewReader(body)), tokenMap, "openai"))
	if err != nil {
		t.Fatalf("read streaming reversal: %v", err)
	}
	out := string(reversed)
	if !strings.Contains(out, "John Doe") {
		t.Fatalf("stream did not reverse token across events: %s", out)
	}
	if strings.Contains(out, "[REDACTED_PERSON_123]") {
		t.Fatalf("stream still contains redacted token: %s", out)
	}
	if !strings.Contains(out, "data: [DONE]") {
		t.Fatalf("stream lost DONE sentinel: %s", out)
	}
}

func TestStreamingReversalReaderFlushesBufferedTextBeforeDone(t *testing.T) {
	tokenMap := map[string]string{"[REDACTED_PERSON_123]": "John Doe"}
	body := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Hello [REDA"}}]}`,
		`data: [DONE]`,
		"",
	}, "\n")

	reversed, err := io.ReadAll(NewStreamingReversalReader(io.NopCloser(strings.NewReader(body)), tokenMap, "openai"))
	if err != nil {
		t.Fatalf("read streaming reversal: %v", err)
	}
	out := string(reversed)
	if !strings.Contains(out, `"content":"Hello "`) {
		t.Fatalf("stream did not emit safe prefix: %s", out)
	}
	if !strings.Contains(out, `"content":"[REDA"`) {
		t.Fatalf("stream did not flush buffered suffix before DONE: %s", out)
	}
	if strings.Index(out, `"content":"[REDA"`) > strings.Index(out, "data: [DONE]") {
		t.Fatalf("buffered suffix should be emitted before DONE: %s", out)
	}
}

func TestStreamingReversalReaderAnthropicSSE(t *testing.T) {
	tokenMap := map[string]string{"[REDACTED_PERSON_123]": "John Doe"}
	body := strings.Join([]string{
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi [REDA"}}`,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"CTED_PERSON_123]"}}`,
		"",
	}, "\n")

	reversed, err := io.ReadAll(NewStreamingReversalReader(io.NopCloser(strings.NewReader(body)), tokenMap, "anthropic"))
	if err != nil {
		t.Fatalf("read anthropic stream: %v", err)
	}
	out := string(reversed)
	if !strings.Contains(out, "John Doe") || strings.Contains(out, "[REDACTED_PERSON_123]") {
		t.Fatalf("anthropic stream was not reversed correctly: %s", out)
	}
	if !strings.Contains(out, "event: content_block_delta") {
		t.Fatalf("anthropic event lines were not preserved: %s", out)
	}
}

func TestStreamingReversalReaderGeminiSSE(t *testing.T) {
	tokenMap := map[string]string{"[REDACTED_PERSON_123]": "John Doe"}
	body := strings.Join([]string{
		`data: {"candidates":[{"content":{"parts":[{"text":"Hi [REDA"}]}}]}`,
		`data: {"candidates":[{"content":{"parts":[{"text":"CTED_PERSON_123]"}]}}]}`,
		"",
	}, "\n")

	reversed, err := io.ReadAll(NewStreamingReversalReader(io.NopCloser(strings.NewReader(body)), tokenMap, "gemini"))
	if err != nil {
		t.Fatalf("read gemini stream: %v", err)
	}
	out := string(reversed)
	if !strings.Contains(out, "John Doe") || strings.Contains(out, "[REDACTED_PERSON_123]") {
		t.Fatalf("gemini stream was not reversed correctly: %s", out)
	}
}

func TestStreamingReversalReaderAzureOpenAISSE(t *testing.T) {
	tokenMap := map[string]string{"[REDACTED_EMAIL_123]": "alice@example.com"}
	body := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Email [REDA"}}]}`,
		`data: {"choices":[{"delta":{"content":"CTED_EMAIL_123]"}}]}`,
		`data: [DONE]`,
		"",
	}, "\n")

	reversed, err := io.ReadAll(NewStreamingReversalReader(io.NopCloser(strings.NewReader(body)), tokenMap, "azure_openai"))
	if err != nil {
		t.Fatalf("read azure openai stream: %v", err)
	}
	out := string(reversed)
	if !strings.Contains(out, "alice@example.com") || strings.Contains(out, "[REDACTED_EMAIL_123]") {
		t.Fatalf("azure openai stream was not reversed correctly: %s", out)
	}
	if !strings.Contains(out, "data: [DONE]") {
		t.Fatalf("azure openai stream lost DONE sentinel: %s", out)
	}
}

func TestStreamingReversalReaderCohereSSE(t *testing.T) {
	tokenMap := map[string]string{"[REDACTED_EMAIL_123]": "alice@example.com"}
	body := strings.Join([]string{
		`event: content-delta`,
		`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"Email [REDA"}}}}`,
		`event: content-delta`,
		`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"CTED_EMAIL_123]"}}}}`,
		`event: stream-end`,
		`data: {"type":"stream-end","finish_reason":"COMPLETE"}`,
		"",
	}, "\n")

	reversed, err := io.ReadAll(NewStreamingReversalReader(io.NopCloser(strings.NewReader(body)), tokenMap, "cohere"))
	if err != nil {
		t.Fatalf("read cohere stream: %v", err)
	}
	out := string(reversed)
	if !strings.Contains(out, "alice@example.com") || strings.Contains(out, "[REDACTED_EMAIL_123]") {
		t.Fatalf("cohere stream was not reversed correctly: %s", out)
	}
	if !strings.Contains(out, "event: content-delta") || !strings.Contains(out, "event: stream-end") {
		t.Fatalf("cohere event lines were not preserved: %s", out)
	}
}

func TestAnalyzePromptWithFallbackTimesOutUnderConcurrency(t *testing.T) {
	slowAnalyzer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(250 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer slowAnalyzer.Close()

	t.Setenv("PRESIDIO_ANALYZE_TIMEOUT_MS", "50")
	t.Setenv("PRESIDIO_SLOW_LOG_MS", "10000")

	client := &PresidioClient{BaseURL: slowAnalyzer.URL}
	const workers = 20
	errs := make(chan string, workers)
	var wg sync.WaitGroup

	start := time.Now()
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results := analyzePromptWithFallback(context.Background(), client, "Contact jane@example.com for support.", nil)
			for _, result := range results {
				if result.EntityType == "EMAIL_ADDRESS" {
					return
				}
			}
			errs <- "fallback did not detect EMAIL_ADDRESS"
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("fallback under concurrency took too long: %v", elapsed)
	}
}

func TestFallbackAnalyzeUsesCustomNERRecognizers(t *testing.T) {
	t.Setenv("REDACTION_CUSTOM_RECOGNIZERS_JSON", `[{
		"name":"MedicalRecordNumber",
		"entity_type":"MEDICAL_RECORD_NUMBER",
		"patterns":["\\bMRN-[0-9]{6}\\b"],
		"context_keywords":["patient"],
		"score":0.96
	}]`)

	results := fallbackAnalyze("The patient record MRN-123456 is ready.", nil)
	for _, result := range results {
		if result.EntityType == "MEDICAL_RECORD_NUMBER" {
			return
		}
	}
	t.Fatalf("expected custom NER recognizer result, got %#v", results)
}

func TestPresidioAnalyzeRequestIncludesCustomNERRecognizers(t *testing.T) {
	t.Setenv("REDACTION_CUSTOM_RECOGNIZERS_JSON", `[{
		"name":"InsuranceMemberId",
		"entity_type":"INSURANCE_MEMBER_ID",
		"patterns":["\\bINS-[A-Z0-9]{8}\\b"],
		"score":0.91
	}]`)

	seen := make(chan AnalyzeRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AnalyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode analyze request: %v", err)
		}
		seen <- req
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := &PresidioClient{BaseURL: server.URL}
	_ = analyzePromptWithFallback(context.Background(), client, "Insurance INS-ABCD1234", nil)

	req := <-seen
	foundEntity := false
	for _, entity := range req.Entities {
		if entity == "INSURANCE_MEMBER_ID" {
			foundEntity = true
			break
		}
	}
	if !foundEntity {
		t.Fatalf("custom entity was not requested from Presidio: %#v", req.Entities)
	}
	foundRecognizer := false
	for _, recognizer := range req.AdHocRecognizers {
		if recognizer.SupportedEntity == "INSURANCE_MEMBER_ID" {
			foundRecognizer = true
			break
		}
	}
	if !foundRecognizer {
		t.Fatalf("custom recognizer was not sent to Presidio: %#v", req.AdHocRecognizers)
	}
}

func TestHashStrategyIsTenantSalted(t *testing.T) {
	t.Setenv("REDACTION_HASH_SALT", "unit-test-salt")

	first, err := GenerateTokenValue(context.Background(), nil, "tenant-a", "jane@example.com", "EMAIL_ADDRESS", "hash")
	if err != nil {
		t.Fatalf("first hash token: %v", err)
	}
	second, err := GenerateTokenValue(context.Background(), nil, "tenant-b", "jane@example.com", "EMAIL_ADDRESS", "hash")
	if err != nil {
		t.Fatalf("second hash token: %v", err)
	}
	again, err := GenerateTokenValue(context.Background(), nil, "tenant-a", "jane@example.com", "EMAIL_ADDRESS", "hash")
	if err != nil {
		t.Fatalf("repeat hash token: %v", err)
	}
	if first == second {
		t.Fatalf("hash token must differ by tenant, got %q", first)
	}
	if first != again {
		t.Fatalf("hash token should be deterministic within tenant, got %q and %q", first, again)
	}
}

func seedRedactionTenant(t *testing.T, name string) string {
	t.Helper()
	InitDB()
	var tenantID string
	err := DB.QueryRow("INSERT INTO tenants (id, name, tier, status) VALUES (gen_random_uuid(), $1 || gen_random_uuid()::text, 'starter', 'active') RETURNING id::text", name).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert redaction tenant: %v", err)
	}
	t.Cleanup(func() {
		DB.Exec("DELETE FROM redaction_tokens WHERE tenant_id = $1", tenantID)
		DB.Exec("DELETE FROM tenants WHERE id = $1", tenantID)
	})
	return tenantID
}

func TestProtectProviderResponseBodyRedactsNewPIIInOpenAICompletion(t *testing.T) {
	tenantID := seedRedactionTenant(t, "Response Redaction Tenant ")
	body := []byte(`{"choices":[{"message":{"content":"Contact alice@example.com after discharge."}}]}`)

	protected, _, err := ProtectProviderResponseBody(
		context.Background(),
		tenantID,
		"openai",
		body,
		nil,
		nil,
		RedactionRuntimeConfig{Strategy: "mask", TokenRetentionDays: 90},
	)
	if err != nil {
		t.Fatalf("protect response body: %v", err)
	}
	out := string(protected)
	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("response still contains raw email: %s", out)
	}
	if !strings.Contains(out, "[REDACTED_EMAIL_ADDRESS_") {
		t.Fatalf("response did not contain redacted email token: %s", out)
	}
}

func TestStreamingProtectionReaderRedactsOutboundPIIAcrossSSEEvents(t *testing.T) {
	tenantID := seedRedactionTenant(t, "Streaming Response Redaction Tenant ")
	body := strings.Join([]string{
		`data: {"choices":[{"delta":{"content":"Email alice@"}}]}`,
		`data: {"choices":[{"delta":{"content":"example.com now"}}]}`,
		`data: [DONE]`,
		"",
	}, "\n")

	reader := NewStreamingProtectionReader(
		context.Background(),
		io.NopCloser(strings.NewReader(body)),
		nil,
		"openai",
		tenantID,
		nil,
		RedactionRuntimeConfig{Strategy: "mask", TokenRetentionDays: 90},
	)
	protected, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read protected stream: %v", err)
	}
	out := string(protected)
	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("stream still contains raw email across events: %s", out)
	}
	if !strings.Contains(out, "[REDACTED_EMAIL_ADDRESS_") {
		t.Fatalf("stream did not emit redacted email token: %s", out)
	}
	if !strings.Contains(out, "data: [DONE]") {
		t.Fatalf("stream lost DONE sentinel: %s", out)
	}
}

func TestGetOrCreateRedactionTokenIsIdempotentUnderConcurrency(t *testing.T) {
	InitDB()

	var tenantID string
	err := DB.QueryRow("INSERT INTO tenants (id, name, tier, status) VALUES (gen_random_uuid(), 'Token Race Tenant ' || gen_random_uuid()::text, 'starter', 'active') RETURNING id::text").Scan(&tenantID)
	if err != nil {
		t.Fatalf("Failed to insert test tenant: %v", err)
	}
	defer DB.Exec("DELETE FROM redaction_tokens WHERE tenant_id = $1", tenantID)
	defer DB.Exec("DELETE FROM tenants WHERE id = $1", tenantID)

	const workers = 24
	ctx := context.Background()
	tokens := make(chan string, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := GetOrCreateRedactionToken(ctx, tenantID, "jane@example.com", "EMAIL_ADDRESS", "mask")
			if err != nil {
				errs <- err
				return
			}
			tokens <- token
		}()
	}
	wg.Wait()
	close(tokens)
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	first := ""
	for token := range tokens {
		if token == "" {
			t.Fatal("expected non-empty token")
		}
		if first == "" {
			first = token
			continue
		}
		if token != first {
			t.Fatalf("expected all workers to receive the same token, got %q and %q", first, token)
		}
	}

	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM redaction_tokens WHERE tenant_id = $1", tenantID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count redaction tokens: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly one redaction token row, got %d", count)
	}
}

func TestGetOrCreateRedactionTokenAppliesRetentionAndPurgesExpired(t *testing.T) {
	InitDB()

	var tenantID string
	err := DB.QueryRow("INSERT INTO tenants (id, name, tier, status) VALUES (gen_random_uuid(), 'Retention Tenant ' || gen_random_uuid()::text, 'starter', 'active') RETURNING id::text").Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	defer DB.Exec("DELETE FROM redaction_tokens WHERE tenant_id = $1", tenantID)
	defer DB.Exec("DELETE FROM tenants WHERE id = $1", tenantID)

	ctx := context.Background()
	token, err := GetOrCreateRedactionTokenWithRetention(ctx, tenantID, "MRN-123456", "MEDICAL_RECORD_NUMBER", "mask", 30)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if token == "" {
		t.Fatal("expected token value")
	}

	var entityType string
	var useCount int
	var daysUntilExpiry float64
	err = DB.QueryRow(`
		SELECT entity_type, use_count, EXTRACT(EPOCH FROM (expires_at - NOW())) / 86400
		FROM redaction_tokens
		WHERE tenant_id = $1
	`, tenantID).Scan(&entityType, &useCount, &daysUntilExpiry)
	if err != nil {
		t.Fatalf("read token metadata: %v", err)
	}
	if entityType != "MEDICAL_RECORD_NUMBER" {
		t.Fatalf("unexpected entity type %q", entityType)
	}
	if useCount != 1 {
		t.Fatalf("expected use_count=1, got %d", useCount)
	}
	if daysUntilExpiry < 29 || daysUntilExpiry > 31 {
		t.Fatalf("expected roughly 30 days retention, got %.2f", daysUntilExpiry)
	}

	_, err = DB.Exec("UPDATE redaction_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE tenant_id = $1", tenantID)
	if err != nil {
		t.Fatalf("expire token: %v", err)
	}

	nextToken, err := GetOrCreateRedactionTokenWithRetention(ctx, tenantID, "MRN-123456", "MEDICAL_RECORD_NUMBER", "mask", 30)
	if err != nil {
		t.Fatalf("recreate expired token: %v", err)
	}
	if nextToken == "" {
		t.Fatal("expected recreated token value")
	}

	var count int
	err = DB.QueryRow("SELECT COUNT(*) FROM redaction_tokens WHERE tenant_id = $1", tenantID).Scan(&count)
	if err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected expired token to be purged before recreate, got %d rows", count)
	}
}

func TestSecretEnvelopeEncryptionIsRandomizedAndBackwardCompatible(t *testing.T) {
	t.Setenv("ENVELOPE_KEY", "test-envelope-key-material-32-bytes!!")
	t.Setenv("ENCRYPTION_KEY", "")
	t.Setenv("AUTHCLAW_SECRET_PROVIDER", "env")
	t.Setenv("AUTHCLAW_SECRET_KEY_VERSION", "v9")
	encryptionKey = nil
	defer func() { encryptionKey = nil }()

	first, err := EncryptSecret("sk-provider-secret")
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}
	second, err := EncryptSecret("sk-provider-secret")
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}
	if !strings.HasPrefix(first, secretEnvelopeV2Prefix+"env:v9:") || !strings.HasPrefix(second, secretEnvelopeV2Prefix+"env:v9:") {
		t.Fatalf("expected secret envelope prefix, got %q and %q", first, second)
	}
	if first == second {
		t.Fatal("expected randomized provider secret ciphertexts to differ")
	}
	for _, ciphertext := range []string{first, second} {
		plaintext, err := DecryptSecret(ciphertext)
		if err != nil {
			t.Fatalf("DecryptSecret failed: %v", err)
		}
		if plaintext != "sk-provider-secret" {
			t.Fatalf("unexpected plaintext %q", plaintext)
		}
	}

	legacy, err := EncryptDeterministic("legacy-provider-secret")
	if err != nil {
		t.Fatalf("EncryptDeterministic failed: %v", err)
	}
	plaintext, err := DecryptSecret(legacy)
	if err != nil {
		t.Fatalf("DecryptSecret legacy fallback failed: %v", err)
	}
	if plaintext != "legacy-provider-secret" {
		t.Fatalf("unexpected legacy plaintext %q", plaintext)
	}
}

func TestSecretEnvelopeVersionedKeyRotation(t *testing.T) {
	t.Setenv("AUTHCLAW_SECRET_PROVIDER", "env")
	t.Setenv("AUTHCLAW_SECRET_KEY_VERSION", "v2")
	t.Setenv("ENVELOPE_KEY_V1", "old-test-envelope-key-material-32!!")
	t.Setenv("ENVELOPE_KEY_V2", "new-test-envelope-key-material-32!!")
	t.Setenv("ENVELOPE_KEY", "")
	t.Setenv("ENCRYPTION_KEY", "")
	encryptionKey = nil
	defer func() { encryptionKey = nil }()

	ciphertext, err := EncryptSecret("rotated-provider-secret")
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}
	if !strings.HasPrefix(ciphertext, secretEnvelopeV2Prefix+"env:v2:") {
		t.Fatalf("expected v2 versioned envelope, got %q", ciphertext)
	}
	plaintext, err := DecryptSecret(ciphertext)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}
	if plaintext != "rotated-provider-secret" {
		t.Fatalf("unexpected plaintext %q", plaintext)
	}
}

func TestValidateEnvelopeKeyConfigRejectsDemoProductionKey(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "production")
	t.Setenv("AUTHCLAW_SECRET_KEY_VERSION", "v1")
	t.Setenv("ENVELOPE_KEY", "demo-local-envelope-key-change-me")
	t.Setenv("ENCRYPTION_KEY", "")

	if err := ValidateEnvelopeKeyConfig(); err == nil {
		t.Fatal("expected production demo envelope key to be rejected")
	}
}

func TestRedactEngine(t *testing.T) {
	// 1. Init DB
	InitDB()

	// 2. Clean database for test
	_, err := DB.Exec("TRUNCATE TABLE audit_log_metadata, pending_approvals, redaction_tokens, gateway_configs, policies, api_keys, users, tenants CASCADE")
	if err != nil {
		t.Fatalf("Failed to truncate tables: %v", err)
	}

	// 3. Seed test tenant
	tenantID := "b0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	_, err = DB.Exec(
		"INSERT INTO tenants (id, name, tier, status) VALUES ($1, 'Redact Tenant', 'starter', 'active')",
		tenantID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test tenant: %v", err)
	}

	// 4. Seed default gateway config for tenant with "mask" strategy
	_, err = DB.Exec(
		"INSERT INTO gateway_configs (id, tenant_id, name, provider, endpoint, redaction_strategy, is_active) VALUES (gen_random_uuid(), $1, 'OpenAI Gateway', 'openai', 'https://api.openai.com', 'mask', true)",
		tenantID,
	)
	if err != nil {
		t.Fatalf("Failed to insert gateway config: %v", err)
	}

	ctx := context.Background()

	// 5. Test Mask strategy
	t.Run("Redaction_Masking_Strategy", func(t *testing.T) {
		prompt := "Hello, my name is John Doe and my email is john.doe@example.com"
		redacted, tokenMap, err := RedactPrompts(ctx, tenantID, []string{prompt}, nil)
		if err != nil {
			t.Fatalf("Failed to redact prompts: %v", err)
		}

		if len(redacted) != 1 {
			t.Fatalf("Expected 1 redacted prompt, got %d", len(redacted))
		}

		redactedText := redacted[0]
		if !strings.Contains(redactedText, "[REDACTED_PERSON_") {
			t.Errorf("Expected PERSON mask, got: %s", redactedText)
		}
		if !strings.Contains(redactedText, "[REDACTED_EMAIL_ADDRESS_") {
			t.Errorf("Expected EMAIL mask, got: %s", redactedText)
		}

		// Reverse it
		reversed := ReverseStaticResponse([]byte(redactedText), tokenMap)
		if string(reversed) != prompt {
			t.Errorf("Reversal failed. Expected: %s, Got: %s", prompt, string(reversed))
		}
	})

	// 6. Test Hash strategy
	t.Run("Redaction_Hashing_Strategy", func(t *testing.T) {
		// Update strategy to hash
		_, err := DB.Exec("UPDATE gateway_configs SET redaction_strategy = 'hash' WHERE tenant_id = $1", tenantID)
		if err != nil {
			t.Fatalf("Failed to update strategy: %v", err)
		}

		prompt := "My phone number is 555-123-4567 and SSN is 211-12-3456"
		redacted, tokenMap, err := RedactPrompts(ctx, tenantID, []string{prompt}, nil)
		if err != nil {
			t.Fatalf("Failed to redact prompts: %v", err)
		}

		redactedText := redacted[0]
		if !strings.Contains(redactedText, "[HASH_PHONE_NUMBER_") {
			t.Errorf("Expected PHONE_NUMBER hash, got: %s", redactedText)
		}
		if !strings.Contains(redactedText, "[HASH_US_SSN_") {
			t.Errorf("Expected US_SSN hash, got: %s", redactedText)
		}

		// Reverse it
		reversed := ReverseStaticResponse([]byte(redactedText), tokenMap)
		if string(reversed) != prompt {
			t.Errorf("Reversal failed. Expected: %s, Got: %s", prompt, string(reversed))
		}
	})

	// 7. Test Synthetic strategy
	t.Run("Redaction_Synthetic_Strategy", func(t *testing.T) {
		// Update strategy to synthetic
		_, err := DB.Exec("UPDATE gateway_configs SET redaction_strategy = 'synthetic' WHERE tenant_id = $1", tenantID)
		if err != nil {
			t.Fatalf("Failed to update strategy: %v", err)
		}

		prompt := "Call John Doe at 555-123-4567"
		redacted, tokenMap, err := RedactPrompts(ctx, tenantID, []string{prompt}, nil)
		if err != nil {
			t.Fatalf("Failed to redact prompts: %v", err)
		}

		redactedText := redacted[0]
		// Verify original value is replaced by a fake value (no mask/hash tags)
		if strings.Contains(redactedText, "John Doe") || strings.Contains(redactedText, "555-123-4567") {
			t.Errorf("Synthetic replacement did not replace name/phone, got: %s", redactedText)
		}

		// Reverse it
		reversed := ReverseStaticResponse([]byte(redactedText), tokenMap)
		if string(reversed) != prompt {
			t.Errorf("Reversal failed. Expected: %s, Got: %s", prompt, string(reversed))
		}
	})

	// 8. Test Custom NER for Health Data
	t.Run("Health_Data_Custom_NER", func(t *testing.T) {
		_, err := DB.Exec("UPDATE gateway_configs SET redaction_strategy = 'mask' WHERE tenant_id = $1", tenantID)
		if err != nil {
			t.Fatalf("Failed to update strategy: %v", err)
		}

		prompt := "The patient was diagnosed at the clinic."
		redacted, tokenMap, err := RedactPrompts(ctx, tenantID, []string{prompt}, nil)
		if err != nil {
			t.Fatalf("Failed to redact health prompt: %v", err)
		}

		redactedText := redacted[0]
		if !strings.Contains(redactedText, "[REDACTED_HEALTH_DATA_") {
			t.Errorf("Expected HEALTH_DATA custom NER detection, got: %s", redactedText)
		}

		// Reverse it
		reversed := ReverseStaticResponse([]byte(redactedText), tokenMap)
		if string(reversed) != prompt {
			t.Errorf("Reversal failed. Expected: %s, Got: %s", prompt, string(reversed))
		}
	})

	// 9. Test DB-level RLS policy validation
	t.Run("DB_RLS_Isolation_Verification", func(t *testing.T) {
		// Assert that inserting/reading without setting app.current_tenant_id returns empty/fails under RLS app user.
		// We'll create a connection using authclaw_app (non-superuser) if possible.
		// The test environment runs RLS checks. Let's see if we can query redaction_tokens without setting context.

		dbURL := os.Getenv("DATABASE_URL")
		if dbURL == "" || strings.Contains(dbURL, "authclaw:authclaw") {
			appPassword := os.Getenv("POSTGRES_APP_PASSWORD")
			if appPassword == "" {
				appPassword = "authclaw_app"
			}
			dbURL = "postgresql://authclaw_app:" + appPassword + "@localhost:5432/authclaw?sslmode=disable"
		} else {
			appPassword := os.Getenv("POSTGRES_APP_PASSWORD")
			if appPassword == "" {
				appPassword = "authclaw_app"
			}
			dbURL = strings.Replace(dbURL, "authclaw:authclaw@", "authclaw_app:"+appPassword+"@", 1)
		}
		appDB, err := sql.Open("postgres", dbURL)
		if err != nil {
			t.Fatalf("Failed to connect to DB via authclaw_app: %v", err)
		}
		defer appDB.Close()

		// Query redaction_tokens without context. Because RLS is enabled and forced, it should return zero rows!
		var count int
		err = appDB.QueryRow("SELECT COUNT(*) FROM redaction_tokens").Scan(&count)
		if err != nil {
			t.Fatalf("Query failed: %v", err)
		}

		if count != 0 {
			t.Errorf("Expected 0 visible tokens without RLS session context, got %d", count)
		}
	})

	// 10. Test Streaming Reversal
	t.Run("Streaming_Reversal_Across_Chunk_Boundaries", func(t *testing.T) {
		tokenMap := map[string]string{
			"[REDACTED_PERSON_123]": "John Doe",
		}

		reverser := NewStreamReverser(tokenMap)

		// Simulating chunks: "[REDA", "CTED_", "PERS", "ON_123]"
		out1 := reverser.ProcessChunk("Hello ")
		if out1 != "Hello " {
			t.Errorf("Expected 'Hello ', got '%s'", out1)
		}

		out2 := reverser.ProcessChunk("[REDA")
		if out2 != "" {
			t.Errorf("Expected buffered prefix output '', got '%s'", out2)
		}

		out3 := reverser.ProcessChunk("CTED_")
		if out3 != "" {
			t.Errorf("Expected buffered prefix output '', got '%s'", out3)
		}

		out4 := reverser.ProcessChunk("PERS")
		if out4 != "" {
			t.Errorf("Expected buffered prefix output '', got '%s'", out4)
		}

		out5 := reverser.ProcessChunk("ON_123]")
		// Should resolve the token to "John Doe"
		if out5 != "John Doe" {
			t.Errorf("Expected token replacement 'John Doe', got '%s'", out5)
		}
	})

	// 11. Local fallback latency check. Official NFR p95/p99 thresholds are enforced by benchmark profiles.
	t.Run("Fallback_Latency_Under_250ms", func(t *testing.T) {
		t.Setenv("PRESIDIO_ANALYZE_TIMEOUT_MS", "80")
		t.Setenv("PRESIDIO_URL", "http://127.0.0.1:1")
		prompt := "My patient John Doe (SSN: 211-12-3456) was diagnosed at hospital today."

		// Warm-up to ensure TCP connection reuse and Gunicorn thread pool warm-up
		for i := 0; i < 3; i++ {
			_, _, _ = RedactPrompts(ctx, tenantID, []string{prompt}, nil)
		}

		duration := ProfileRedaction("RedactPrompts", func() {
			_, _, err := RedactPrompts(ctx, tenantID, []string{prompt}, nil)
			if err != nil {
				t.Fatalf("Redact prompts failed: %v", err)
			}
		})

		t.Logf("Redaction Latency: %v", duration)
		if duration > 250*time.Millisecond {
			t.Errorf("Redaction latency exceeded local developer threshold of 250ms, got: %v", duration)
		}
	})
}

func TestProxyIntegrationWithRedaction(t *testing.T) {
	// 1. Create mock backend server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read body
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)

		// Assert that incoming request is redacted!
		if strings.Contains(bodyStr, "John Doe") {
			t.Errorf("Target server received unredacted name: %s", bodyStr)
		}

		// Extract the actual token generated by the gateway
		var token string
		idx := strings.Index(bodyStr, "[REDACTED_PERSON_")
		if idx != -1 {
			endIdx := strings.Index(bodyStr[idx:], "]")
			if endIdx != -1 {
				token = bodyStr[idx : idx+endIdx+1]
			}
		}
		if token == "" {
			token = "[REDACTED_PERSON_default]"
		}

		// Return redacted response containing the token
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Echo back choices with the redacted token to verify the proxy reverses it!
		w.Write([]byte(`{"choices":[{"message":{"content":"Hello, ` + token + `"}}]}`))
	}))
	defer targetServer.Close()

	// 2. Setup DB client
	InitDB()

	// Seed tenant and config
	tenantID := "c0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	_, _ = DB.Exec("INSERT INTO tenants (id, name, tier, status) VALUES ($1, 'Proxy Integration Tenant', 'starter', 'active')", tenantID)

	// Create user
	userID := "c0eebc99-9c0b-4ef8-bb6d-6bb9bd380a22"
	_, _ = DB.Exec("INSERT INTO users (id, tenant_id, email, role, mfa_enabled, is_active) VALUES ($1, $2, 'integration@example.com', 'admin', false, true)", userID, tenantID)

	// API key
	apiKey := "authclaw_integration_key_1"
	keyHash := HashKey(apiKey)
	_, _ = DB.Exec("INSERT INTO api_keys (id, tenant_id, key_hash, name, scopes, is_active, created_by) VALUES (gen_random_uuid(), $1, $2, 'Integration Key', $3, true, $4)", tenantID, keyHash, pq.Array([]string{"read"}), userID)
	encryptedProviderKey, err := EncryptSecret("sk-test-provider")
	if err != nil {
		t.Fatalf("Failed to encrypt provider key: %v", err)
	}
	_, _ = DB.Exec(
		`INSERT INTO provider_credentials (
			id, tenant_id, provider, display_name, endpoint, encrypted_secret, auth_scheme, status, created_by, version
		) VALUES (
			gen_random_uuid(), $1, 'openai', 'Integration OpenAI', $2, $3, 'api_key', 'active', $4, 1
		)`,
		tenantID, targetServer.URL, encryptedProviderKey, userID,
	)

	// Update or insert gateway config to point to our mock target server
	_, _ = DB.Exec("DELETE FROM gateway_configs WHERE tenant_id = $1", tenantID)
	_, err = DB.Exec("INSERT INTO gateway_configs (id, tenant_id, name, provider, endpoint, redaction_strategy, is_active) VALUES (gen_random_uuid(), $1, 'OpenAI Integration', 'openai', $2, 'mask', true)", tenantID, targetServer.URL)
	if err != nil {
		t.Fatalf("Failed to seed gateway config: %v", err)
	}

	// 3. Create Gateway Reverse Proxy
	proxy := NewProxyServer()
	proxy.OpenAIBaseURL = targetServer.URL

	// 4. Construct request
	requestBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi, my name is John Doe"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(requestBody))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	w := httptest.NewRecorder()

	// 5. Build route handler with AuthMiddleware
	handler := AuthMiddleware(http.HandlerFunc(proxy.ServeHTTP))
	handler.ServeHTTP(w, req)

	// 6. Verify response is successfully reversed back to the original value!
	resp := w.Result()
	responseBody, _ := io.ReadAll(resp.Body)
	respStr := string(responseBody)

	if !strings.Contains(respStr, "John Doe") {
		t.Errorf("Response did not reverse token back to 'John Doe', got: %s", respStr)
	}
	if strings.Contains(respStr, "[REDACTED_PERSON_") {
		t.Errorf("Response still contains redacted token: %s", respStr)
	}
}
