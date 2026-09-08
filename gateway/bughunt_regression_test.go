package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRedactedRequestPreservesProviderOptions(t *testing.T) {
	for _, tc := range []struct{ provider, path, body string }{
		{"openai", "/v1/chat/completions", `{"model":"gpt-4o","stream":true,"temperature":0.2,"messages":[{"role":"user","name":"alice","content":"secret"}],"seed":9007199254740993}`},
		{"azure_openai", "/v1/chat/completions", `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"secret"}],"max_tokens":64}`},
		{"anthropic", "/v1/messages", `{"model":"claude-test","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"secret"}]}`},
		{"gemini", "/v1/models/gemini-test:generateContent", `{"generationConfig":{"maxOutputTokens":64},"contents":[{"role":"user","parts":[{"text":"secret"},{"inlineData":{"mimeType":"image/png","data":"AA=="}}]}]}`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			normalized, rebuild, err := ExtractAndNormalize(req, tc.provider)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(normalized.Prompts, []string{"secret"}) {
				t.Fatalf("unexpected prompts: %v", normalized.Prompts)
			}
			actual, err := rebuild([]string{"[REDACTED]"})
			if err != nil {
				t.Fatal(err)
			}
			decode := func(s string) interface{} {
				var v interface{}
				d := json.NewDecoder(strings.NewReader(s))
				d.UseNumber()
				if err := d.Decode(&v); err != nil {
					t.Fatal(err)
				}
				return v
			}
			want := strings.ReplaceAll(tc.body, "secret", "[REDACTED]")
			if !reflect.DeepEqual(decode(string(actual)), decode(want)) {
				t.Fatalf("rebuilt request lost provider fields:\ngot %s\nwant %s", actual, want)
			}
		})
	}
}

func TestProxyResponseWriterPreservesStreamingFlush(t *testing.T) {
	recorder := httptest.NewRecorder()
	wrapped := &responseWriter{ResponseWriter: recorder, status: http.StatusOK}
	if err := http.NewResponseController(wrapped).Flush(); err != nil {
		t.Fatalf("stream flush unavailable: %v", err)
	}
	if !recorder.Flushed {
		t.Fatal("stream did not flush to client")
	}
}

func TestPolicyDecisionCacheDoesNotSurvivePolicyReplacement(t *testing.T) {
	t.Setenv("GATEWAY_POLICY_DECISION_CACHE_TTL_MS", "60000")
	t.Setenv("GATEWAY_POLICY_LOCAL_FAST_PATH", "false")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload OPAPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			return
		}
		allow, _, _ := evaluatePolicyLocal(payload.Input.Policy, payload.Input.Model, payload.Input.Prompts, payload.Input.Topics, false)
		json.NewEncoder(w).Encode(map[string]interface{}{"result": map[string]interface{}{"allow": allow}})
	}))
	defer server.Close()
	t.Setenv("OPA_URL", server.URL)
	tenant := "cache-replacement-regression"
	defer InvalidatePolicyCache(tenant)
	SetCachedPolicy(tenant, &PolicyConfig{}, "old-policy", time.Minute)
	allow, _, _, err := EvaluatePolicy(context.Background(), tenant, "gpt-4o", "/v1/chat/completions", nil, nil)
	if err != nil || !allow {
		t.Fatalf("initial evaluation: allow=%v err=%v", allow, err)
	}
	SetCachedPolicy(tenant, &PolicyConfig{ModelRules: ModelRules{Blacklist: []string{"gpt-4o"}}}, "new-policy", time.Minute)
	allow, _, id, err := EvaluatePolicy(context.Background(), tenant, "gpt-4o", "/v1/chat/completions", nil, nil)
	if err != nil || allow || id != "new-policy" {
		t.Fatalf("stale authorization after policy replacement: allow=%v policy=%s err=%v", allow, id, err)
	}
	SetCachedPolicy(tenant, &PolicyConfig{}, "new-policy", time.Minute)
	allow, _, id, err = EvaluatePolicy(context.Background(), tenant, "gpt-4o", "/v1/chat/completions", nil, nil)
	if err != nil || !allow || id != "new-policy" {
		t.Fatalf("stale decision after same-ID content change: allow=%v policy=%s err=%v", allow, id, err)
	}
}

func TestStreamingInspectionFailureDoesNotReturnUninspectedText(t *testing.T) {
	oldDB := DB
	db, err := sql.Open("postgres", "postgres://localhost:1/authclaw_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	DB = db
	defer func() { DB = oldDB; db.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Token storage fails before opening a database connection.
	for _, text := range []string{"jane@example.com", "jane@example.com " + strings.Repeat("x", 256)} {
		payload, _ := json.Marshal(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"delta": map[string]interface{}{"content": text}}}})
		reader := NewStreamingProtectionReader(ctx, io.NopCloser(strings.NewReader("data: "+string(payload)+"\n\ndata: [DONE]\n\n")), nil, ProviderOpenAI, "tenant-regression", nil, RedactionRuntimeConfig{Strategy: "mask"})
		body, err := io.ReadAll(reader)
		reader.Close()
		if err == nil {
			t.Error("failed production inspection did not terminate stream with error")
		}
		if strings.Contains(string(body), "jane@example.com") {
			t.Errorf("uninspected sensitive text escaped: %s", body)
		}
	}
}
