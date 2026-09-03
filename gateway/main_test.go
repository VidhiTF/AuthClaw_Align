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
