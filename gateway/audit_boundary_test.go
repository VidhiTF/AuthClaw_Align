package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func withAuditEmitter(t *testing.T, emitter func(context.Context, *AuditEvent) error) {
	t.Helper()
	previous := auditEventEmitter
	auditEventEmitter = emitter
	t.Cleanup(func() { auditEventEmitter = previous })
}

func requestWithAuditContext(method, path, body, requestID string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), RequestIDContextKey, requestID)
	return req.WithContext(ctx)
}

func TestProviderPrefixesFailClosedBeforeEgress(t *testing.T) {
	t.Setenv("AUDIT_FAIL_CLOSED", "true")
	var upstreamCalls atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxy := NewProxyServer()
	proxy.OpenAIBaseURL = upstream.URL
	proxy.AnthropicBaseURL = upstream.URL
	proxy.CohereBaseURL = upstream.URL
	proxy.AzureOpenAIBaseURL = upstream.URL
	proxy.GeminiBaseURL = upstream.URL
	proxy.BedrockBaseURL = upstream.URL

	withAuditEmitter(t, func(_ context.Context, event *AuditEvent) error {
		if event.Action == "provider_attempt" {
			return errors.New("canonical append unavailable")
		}
		return nil
	})

	tests := []struct {
		name, path, body, provider string
	}{
		{"openai", "/v1/chat/completions", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, ""},
		{"anthropic", "/v1/messages", `{"model":"claude-3-5-sonnet","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`, ""},
		{"cohere", "/v2/chat", `{"model":"command-r","messages":[{"role":"user","content":"hi"}]}`, ""},
		{"azure", "/openai/deployments/customer-gpt/chat/completions?api-version=2024-10-21", `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`, ProviderAzureOpenAI},
		{"gemini", "/v1/models/gemini-2.5-flash:generateContent", `{"contents":[{"parts":[{"text":"hi"}]}]}`, ""},
		{"bedrock", "/bedrock/model/anthropic.claude-3-sonnet/invoke", `{"prompt":"hi"}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "bedrock" {
				previousDB := DB
				DB, _ = sql.Open("postgres", "postgres://localhost:1/authclaw_test?sslmode=disable")
				t.Cleanup(func() {
					_ = DB.Close()
					DB = previousDB
				})
			}
			req := requestWithAuditContext(http.MethodPost, tc.path, tc.body, "req-"+tc.name)
			if tc.provider != "" {
				req.Header.Set("X-Provider", tc.provider)
			}
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, req)
			// Bedrock now denies absent tenant entitlement before attempting egress.
			if tc.name == "bedrock" {
				if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "BedrockNotAuthorized") {
					t.Fatalf("Bedrock entitlement failed open: %d %s", recorder.Code, recorder.Body.String())
				}
				return
			}
			if recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "AuditUnavailable") {
				t.Fatalf("unstable audit failure response: %s", recorder.Body.String())
			}
		})
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("audit gate allowed %d upstream calls", upstreamCalls.Load())
	}
}

func TestRequiredAuditFailureIsObservableInFailOpenMode(t *testing.T) {
	t.Setenv("AUDIT_FAIL_CLOSED", "false")
	before := AuditMetricsSnapshot()["authclaw_gateway_audit_fail_open_losses_total"]
	withAuditEmitter(t, func(context.Context, *AuditEvent) error {
		return errors.New("canonical append unavailable")
	})
	recorder := httptest.NewRecorder()
	req := requestWithAuditContext(http.MethodPost, "/v2/chat", `{}`, "req-fail-open")
	if !emitRequiredDecision(recorder, req, &AuditEvent{RequestID: "req-fail-open", Provider: "cohere"}, "test") {
		t.Fatal("fail-open mode blocked the request")
	}
	if recorder.Body.Len() != 0 {
		t.Fatal("fail-open mode wrote an error response")
	}
	after := AuditMetricsSnapshot()["authclaw_gateway_audit_fail_open_losses_total"]
	if after != before+1 {
		t.Fatalf("fail-open metric delta=%d", after-before)
	}
}

func TestStreamingOutcomeFailurePreservesResponseAndWritesRecovery(t *testing.T) {
	t.Setenv("AUDIT_FAIL_CLOSED", "true")
	outbox := t.TempDir() + "/audit-recovery.ndjson"
	t.Setenv("AUDIT_OUTBOX_PATH", outbox)
	streamBody := "data: {\"choices\":[{\"delta\":{\"content\":\"safe-token\"}}]}\n\n"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, streamBody)
	}))
	defer upstream.Close()
	proxy := NewProxyServer()
	proxy.OpenAIBaseURL = upstream.URL

	req := authenticatedProxyContract(t, requestWithAuditContext(
		http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`,
		"req-stream",
	), ProviderOpenAI, "contract-key")
	withAuditEmitter(t, func(_ context.Context, event *AuditEvent) error {
		if event.Action == "provider_attempt" {
			return nil
		}
		return errors.New("final canonical append unavailable")
	})
	before := AuditMetricsSnapshot()["authclaw_gateway_audit_post_response_failures_total"]
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)
	var received strings.Builder
	for _, line := range strings.Split(recorder.Body.String(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			t.Fatalf("invalid SSE frame: %q", line)
		}
		var event struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
			t.Fatal(err)
		}
		if len(event.Choices) != 1 {
			t.Fatal("stream lost choice structure")
		}
		received.WriteString(event.Choices[0].Delta.Content)
	}
	if recorder.Code != http.StatusOK || received.String() != "safe-token" {
		t.Fatalf("stream changed after final audit failure: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if AuditMetricsSnapshot()["authclaw_gateway_audit_post_response_failures_total"] != before+1 {
		t.Fatal("post-response audit failure metric was not incremented")
	}
	data, err := os.ReadFile(outbox)
	if err != nil || !strings.Contains(string(data), "req-stream") {
		t.Fatalf("missing correlated recovery artifact: data=%q err=%v", data, err)
	}
}

func TestAttemptAndOutcomeUseDistinctDeterministicKeys(t *testing.T) {
	if auditIdempotencyKey("req-1", "provider_attempt") == auditIdempotencyKey("req-1", "provider_outcome") {
		t.Fatal("attempt and outcome idempotency keys must differ")
	}
	if auditIdempotencyKey("req-1", "provider_attempt") != auditIdempotencyKey("req-1", "provider_attempt") {
		t.Fatal("attempt idempotency key is not deterministic")
	}
}
