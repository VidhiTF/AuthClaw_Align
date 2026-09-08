package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func markerMiddleware(header, value string) gatewayMiddleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set(header, value)
			next.ServeHTTP(w, r)
		})
	}
}

func TestMain(m *testing.M) {
	raw := os.Getenv("DATABASE_URL")
	parsed, err := url.Parse(raw)
	if err != nil || !strings.HasSuffix(strings.Trim(parsed.Path, "/"), "_test") {
		fmt.Fprintln(os.Stderr, "DATABASE_URL must explicitly target a database ending in _test")
		os.Exit(1)
	}
	skipDatabaseSecurityValidationForTests = true
	os.Exit(m.Run())
}

func TestHealthCheck(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/health", HealthHandler)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}
	if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("Expected Content-Type %q, got %q", "application/json", contentType)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid health JSON: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("Expected healthy status, got %v", body["status"])
	}
	if body["service"] != "authclaw-gateway" {
		t.Errorf("Expected service authclaw-gateway, got %v", body["service"])
	}
	if len(body) != 2 {
		t.Fatalf("public health leaked internal fields: %#v", body)
	}
}

func TestPublicGatewayRouterDoesNotExposeMetrics(t *testing.T) {
	t.Setenv("GATEWAY_HTTP_LOGGER_ENABLED", "false")
	router := NewGatewayRouter(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("public metrics status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestConfiguredProviderRoutesReachProtectedProxy(t *testing.T) {
	t.Setenv("GATEWAY_HTTP_LOGGER_ENABLED", "false")
	proxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Test-Auth") != "applied" || r.Header.Get("X-Test-Rate") != "applied" {
			t.Fatal("provider route bypassed gateway middleware")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	router := newGatewayRouter(
		proxy,
		markerMiddleware("X-Test-Auth", "applied"),
		markerMiddleware("X-Test-Rate", "applied"),
	)

	paths := []string{
		"/v1/chat/completions",
		"/v1/messages",
		"/v1/models/gemini-2.5-flash:generateContent",
		"/v2/chat",
		"/openai/deployments/customer-gpt/chat/completions",
		"/bedrock/model/anthropic.claude-3/invoke",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
			if recorder.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNoContent)
			}
		})
	}
}

func TestProviderRouterRejectsUnsupportedPathsAndMethods(t *testing.T) {
	t.Setenv("GATEWAY_HTTP_LOGGER_ENABLED", "false")
	router := newGatewayRouter(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		markerMiddleware("X-Test-Auth", "applied"),
		markerMiddleware("X-Test-Rate", "applied"),
	)

	cases := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/v2/chat", http.StatusMethodNotAllowed},
		{http.MethodGet, "/openai/deployments/customer-gpt/chat/completions", http.StatusMethodNotAllowed},
		{http.MethodGet, "/bedrock/model/anthropic.claude-3/invoke", http.StatusMethodNotAllowed},
		{http.MethodPost, "/model/anthropic.claude-3/invoke", http.StatusNotFound},
		{http.MethodPost, "/internal/admin", http.StatusNotFound},
	}
	for _, tc := range cases {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
		if recorder.Code != tc.status {
			t.Fatalf("%s %s status = %d, want %d", tc.method, tc.path, recorder.Code, tc.status)
		}
	}
}

func TestAdvertisedNonV1RoutesRequireAuthentication(t *testing.T) {
	t.Setenv("GATEWAY_HTTP_LOGGER_ENABLED", "false")
	router := NewGatewayRouter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("unauthenticated request reached proxy")
	}))

	for _, path := range []string{
		"/v2/chat",
		"/openai/deployments/customer-gpt/chat/completions",
		"/bedrock/model/anthropic.claude-3/invoke",
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("POST %s status = %d, want %d", path, recorder.Code, http.StatusUnauthorized)
		}
	}
}
