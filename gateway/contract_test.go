package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise real admission while isolating unrelated credential/policy/audit stores.
// The context represents AuthMiddleware's verified output, never identity headers.
func authenticatedProxyContract(t *testing.T, req *http.Request, provider, apiKey string) *http.Request {
	t.Helper()
	t.Setenv("AUTHCLAW_ENV", "development")
	t.Setenv("PROVIDER_CREDENTIAL_CACHE_TTL_MS", "60000")
	t.Setenv("REDACTION_RUNTIME_CONFIG_CACHE_TTL_MS", "60000")
	t.Setenv("GATEWAY_POLICY_LOCAL_FAST_PATH", "true")
	t.Setenv("REDACTION_LOCAL_ANALYZER_ONLY", "true")
	for _, name := range []string{"AUTHCLAW_RATE_LIMIT_PER_MINUTE", "AUTHCLAW_RATE_LIMIT_USER_RPM", "AUTHCLAW_RATE_LIMIT_KEY_RPM", "AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM"} {
		t.Setenv(name, "100")
	}
	previousRedis := RedisClient
	InitRedis()
	client := RedisClient
	t.Cleanup(func() { client.Close(); RedisClient = previousRedis })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Fatalf("payload contracts require real Redis via REDIS_URL: %v", err)
	}
	tenant := "contract-" + generateID()
	setCachedProviderCredential(tenant, provider, &ProviderCredential{Provider: provider, APIKey: apiKey})
	SetCachedPolicy(tenant, &PolicyConfig{}, "contract-policy", time.Minute)
	redactionRuntimeConfigCache.Store(tenant, struct {
		config    RedactionRuntimeConfig
		expiresAt time.Time
	}{RedactionRuntimeConfig{Strategy: "mask", TokenRetentionDays: 90}, time.Now().Add(time.Minute)})
	t.Cleanup(func() {
		providerCredentialCache.Delete(providerCredentialCacheKey(tenant, provider))
		InvalidatePolicyCache(tenant)
		redactionRuntimeConfigCache.Delete(tenant)
	})
	withAuditEmitter(t, func(context.Context, *AuditEvent) error { return nil })
	requestContext := context.WithValue(req.Context(), TenantIDContextKey, tenant)
	requestContext = context.WithValue(requestContext, UserIDContextKey, "contract-user")
	requestContext = context.WithValue(requestContext, APIKeyHashContextKey, "contract-key-hash")
	if requestContext.Value(RequestIDContextKey) == nil {
		requestContext = context.WithValue(requestContext, RequestIDContextKey, generateID())
	}
	return req.WithContext(requestContext)
}

// JSON object key order may change during authenticated response protection.
// Compare the complete decoded objects, retaining every field, value and array order.
func assertJSONResponseFidelity(t *testing.T, expected string, actual []byte) {
	t.Helper()
	var want, got interface{}
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatalf("invalid expected JSON: %v", err)
	}
	if err := json.Unmarshal(actual, &got); err != nil {
		t.Fatalf("invalid provider response JSON: %v; body=%s", err, actual)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Response body corrupted. Expected: %s, Got: %s", expected, actual)
	}
}

func TestPayloadFidelityContractOpenAI(t *testing.T) {
	var providerCalls atomic.Int32
	expectedResponse := `{"id":"chatcmpl-123","object":"chat.completion","created":1677858242,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}]}`

	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		bodyBytes, _ := io.ReadAll(r.Body)
		expectedRequest := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
		if strings.TrimSpace(string(bodyBytes)) != expectedRequest {
			t.Errorf("Request body corrupted. Expected: %s, Got: %s", expectedRequest, string(bodyBytes))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedResponse))
	}))
	defer openaiServer.Close()

	proxy := NewProxyServer()
	proxy.OpenAIBaseURL = openaiServer.URL

	requestBody := `{"model":"gpt-4","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(requestBody))
	req = authenticatedProxyContract(t, req, ProviderOpenAI, "test-openai-key")
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK || providerCalls.Load() != 1 {
		t.Fatalf("expected exactly one admitted provider invocation: status=%d calls=%d body=%s", w.Code, providerCalls.Load(), w.Body.String())
	}
	resp := w.Result()
	responseBodyBytes, _ := io.ReadAll(resp.Body)
	assertJSONResponseFidelity(t, expectedResponse, responseBodyBytes)
}

func TestPayloadFidelityContractAnthropic(t *testing.T) {
	var providerCalls atomic.Int32
	expectedResponse := `{"id":"msg_123","type":"message","role":"assistant","content":[{"type":"text","text":"Hello!"}],"model":"claude-3-opus"}`

	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		bodyBytes, _ := io.ReadAll(r.Body)
		expectedRequest := `{"model":"claude-3-opus","messages":[{"role":"user","content":"Hi"}]}`
		if strings.TrimSpace(string(bodyBytes)) != expectedRequest {
			t.Errorf("Request body corrupted. Expected: %s, Got: %s", expectedRequest, string(bodyBytes))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedResponse))
	}))
	defer anthropicServer.Close()

	proxy := NewProxyServer()
	proxy.AnthropicBaseURL = anthropicServer.URL

	requestBody := `{"model":"claude-3-opus","messages":[{"role":"user","content":"Hi"}]}`
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(requestBody))
	req = authenticatedProxyContract(t, req, ProviderAnthropic, "test-anthropic-key")
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK || providerCalls.Load() != 1 {
		t.Fatalf("expected exactly one admitted provider invocation: status=%d calls=%d body=%s", w.Code, providerCalls.Load(), w.Body.String())
	}
	resp := w.Result()
	responseBodyBytes, _ := io.ReadAll(resp.Body)
	assertJSONResponseFidelity(t, expectedResponse, responseBodyBytes)
}

func TestPayloadFidelityContractGemini(t *testing.T) {
	var providerCalls atomic.Int32
	expectedResponse := `{"candidates":[{"content":{"parts":[{"text":"Hello!"}],"role":"model"}}],"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":2,"totalTokenCount":4}}`
	expectedKey := "test-gemini-api-key-999"
	t.Setenv("GEMINI_API_KEY", expectedKey)

	geminiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		// Verify API Key header
		key := r.Header.Get("x-goog-api-key")
		if key != expectedKey {
			t.Errorf("Expected x-goog-api-key header %s, Got: %s", expectedKey, key)
		}

		// Verify Authorization header is deleted
		auth := r.Header.Get("Authorization")
		if auth != "" {
			t.Errorf("Expected Authorization header to be deleted, but got: %s", auth)
		}

		bodyBytes, _ := io.ReadAll(r.Body)
		expectedRequest := `{"contents":[{"parts":[{"text":"Hi"}]}]}`
		if strings.TrimSpace(string(bodyBytes)) != expectedRequest {
			t.Errorf("Request body corrupted. Expected: %s, Got: %s", expectedRequest, string(bodyBytes))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedResponse))
	}))
	defer geminiServer.Close()

	proxy := NewProxyServer()
	proxy.GeminiBaseURL = geminiServer.URL

	requestBody := `{"contents":[{"parts":[{"text":"Hi"}]}]}`
	req := httptest.NewRequest("POST", "/v1/models/gemini-1.5-flash:generateContent", strings.NewReader(requestBody))
	req.Header.Set("Authorization", "Bearer some-gateway-key")
	req = authenticatedProxyContract(t, req, ProviderGemini, expectedKey)
	w := httptest.NewRecorder()

	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK || providerCalls.Load() != 1 {
		t.Fatalf("expected exactly one admitted provider invocation: status=%d calls=%d body=%s", w.Code, providerCalls.Load(), w.Body.String())
	}
	resp := w.Result()
	responseBodyBytes, _ := io.ReadAll(resp.Body)
	assertJSONResponseFidelity(t, expectedResponse, responseBodyBytes)
}

func TestPayloadFidelityContractCohereV2Chat(t *testing.T) {
	var providerCalls atomic.Int32
	expectedResponse := `{"id":"chat-123","message":{"role":"assistant","content":[{"type":"text","text":"Hello!"}]},"finish_reason":"COMPLETE"}`

	cohereServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		if r.URL.Path != "/v2/chat" {
			t.Errorf("Expected Cohere /v2/chat path, got %s", r.URL.Path)
		}
		bodyBytes, _ := io.ReadAll(r.Body)
		expectedRequest := `{"model":"command-r-plus","messages":[{"role":"user","content":"Hi"}]}`
		if strings.TrimSpace(string(bodyBytes)) != expectedRequest {
			t.Errorf("Request body corrupted. Expected: %s, Got: %s", expectedRequest, string(bodyBytes))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedResponse))
	}))
	defer cohereServer.Close()

	proxy := NewProxyServer()
	proxy.CohereBaseURL = cohereServer.URL

	req := httptest.NewRequest("POST", "/v2/chat", strings.NewReader(`{"model":"command-r-plus","messages":[{"role":"user","content":"Hi"}]}`))
	req = authenticatedProxyContract(t, req, ProviderCohere, "test-cohere-key")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK || providerCalls.Load() != 1 {
		t.Fatalf("expected exactly one admitted provider invocation: status=%d calls=%d body=%s", w.Code, providerCalls.Load(), w.Body.String())
	}
	resp := w.Result()
	responseBodyBytes, _ := io.ReadAll(resp.Body)
	assertJSONResponseFidelity(t, expectedResponse, responseBodyBytes)
}

func TestPayloadFidelityContractAzureOpenAIChat(t *testing.T) {
	var providerCalls atomic.Int32
	expectedResponse := `{"id":"chatcmpl-azure-123","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Hello!"},"finish_reason":"stop"}]}`

	azureServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		expectedPath := "/openai/deployments/customer-gpt4/chat/completions"
		if r.URL.Path != expectedPath {
			t.Errorf("Expected Azure path %s, got %s", expectedPath, r.URL.Path)
		}
		if r.URL.Query().Get("api-version") != "2024-10-21" {
			t.Errorf("Expected api-version query, got %q", r.URL.RawQuery)
		}
		bodyBytes, _ := io.ReadAll(r.Body)
		expectedRequest := `{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`
		if strings.TrimSpace(string(bodyBytes)) != expectedRequest {
			t.Errorf("Request body corrupted. Expected: %s, Got: %s", expectedRequest, string(bodyBytes))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(expectedResponse))
	}))
	defer azureServer.Close()

	proxy := NewProxyServer()
	proxy.AzureOpenAIBaseURL = azureServer.URL

	req := httptest.NewRequest("POST", "/openai/deployments/customer-gpt4/chat/completions?api-version=2024-10-21", strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`))
	req.Header.Set("X-Provider", "azure_openai")
	req = authenticatedProxyContract(t, req, ProviderAzureOpenAI, "test-azure-key")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, req)

	if w.Code != http.StatusOK || providerCalls.Load() != 1 {
		t.Fatalf("expected exactly one admitted provider invocation: status=%d calls=%d body=%s", w.Code, providerCalls.Load(), w.Body.String())
	}
	resp := w.Result()
	responseBodyBytes, _ := io.ReadAll(resp.Body)
	assertJSONResponseFidelity(t, expectedResponse, responseBodyBytes)
}

func TestStreamingPayloadFidelityContracts(t *testing.T) {
	cases := []struct {
		name       string
		provider   string
		body       string
		wantText   string
		wantMarker string
	}{
		{
			name:     "openai",
			provider: "openai",
			body: strings.Join([]string{
				`data: {"choices":[{"delta":{"content":"Email [REDA"}}]}`,
				`data: {"choices":[{"delta":{"content":"CTED_EMAIL_123]"}}]}`,
				`data: [DONE]`,
				"",
			}, "\n"),
			wantText:   "alice@example.com",
			wantMarker: "data: [DONE]",
		},
		{
			name:     "anthropic",
			provider: "anthropic",
			body: strings.Join([]string{
				`event: content_block_delta`,
				`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Email [REDA"}}`,
				`event: content_block_delta`,
				`data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"CTED_EMAIL_123]"}}`,
				"",
			}, "\n"),
			wantText:   "alice@example.com",
			wantMarker: "event: content_block_delta",
		},
		{
			name:     "cohere",
			provider: "cohere",
			body: strings.Join([]string{
				`event: content-delta`,
				`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"Email [REDA"}}}}`,
				`event: content-delta`,
				`data: {"type":"content-delta","delta":{"message":{"content":{"type":"text","text":"CTED_EMAIL_123]"}}}}`,
				`event: stream-end`,
				`data: {"type":"stream-end","finish_reason":"COMPLETE"}`,
				"",
			}, "\n"),
			wantText:   "alice@example.com",
			wantMarker: "event: stream-end",
		},
		{
			name:     "azure_openai",
			provider: "azure_openai",
			body: strings.Join([]string{
				`data: {"choices":[{"delta":{"content":"Email [REDA"}}]}`,
				`data: {"choices":[{"delta":{"content":"CTED_EMAIL_123]"}}]}`,
				`data: [DONE]`,
				"",
			}, "\n"),
			wantText:   "alice@example.com",
			wantMarker: "data: [DONE]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tokenMap := map[string]string{"[REDACTED_EMAIL_123]": "alice@example.com"}
			reversed, err := io.ReadAll(NewStreamingReversalReader(io.NopCloser(strings.NewReader(tc.body)), tokenMap, tc.provider))
			if err != nil {
				t.Fatalf("read %s stream: %v", tc.provider, err)
			}
			out := string(reversed)
			if !strings.Contains(out, tc.wantText) || strings.Contains(out, "[REDACTED_EMAIL_123]") {
				t.Fatalf("%s stream did not preserve provider shape while reversing token: %s", tc.provider, out)
			}
			if !strings.Contains(out, tc.wantMarker) {
				t.Fatalf("%s stream lost marker %q: %s", tc.provider, tc.wantMarker, out)
			}
		})
	}
}
