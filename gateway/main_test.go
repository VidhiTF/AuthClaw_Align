package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"
)

type closingAuditStream struct {
	auditStream
	closed chan struct{}
}

func (s *closingAuditStream) Close() { close(s.closed) }

func lifecycleClients(t *testing.T) (*sql.DB, *redis.Client, <-chan struct{}) {
	t.Helper()
	oldDB, oldRedis, oldAudit := DB, RedisClient, activeAuditStream
	db, err := sql.Open("postgres", "postgres://unused")
	if err != nil {
		t.Fatal(err)
	}
	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	DB, RedisClient = db, redisClient
	stream := &closingAuditStream{closed: make(chan struct{})}
	activeAuditStream = stream
	t.Cleanup(func() {
		DB, RedisClient, activeAuditStream = oldDB, oldRedis, oldAudit
		_ = db.Close()
		_ = redisClient.Close()
		auditAsync.Lock()
		auditAsync.closing = false
		auditAsync.Unlock()
	})
	return db, redisClient, stream.closed
}

func TestShutdownGatewayDrainsRequestsAndClosesClients(t *testing.T) {
	db, redisClient, closed := lifecycleClients(t)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseRequest := sync.OnceFunc(func() { close(release) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	defer releaseRequest()
	requestDone := make(chan error, 1)
	go func() {
		resp, err := http.Get(server.URL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				err = fmt.Errorf("status=%d", resp.StatusCode)
			}
		}
		requestDone <- err
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- shutdownGateway(ctx, server.Config) }()
	select {
	case <-closed:
		t.Fatal("audit closed before active request drained")
	case <-time.After(30 * time.Millisecond):
	}
	releaseRequest()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	if _, err := http.Get(server.URL); err == nil {
		t.Fatal("server still accepts requests")
	}
	if err := db.Ping(); err == nil || err.Error() != "sql: database is closed" {
		t.Fatalf("database close not demonstrated: %v", err)
	}
	if err := redisClient.Ping(context.Background()).Err(); !errors.Is(err, redis.ErrClosed) {
		t.Fatalf("redis close not demonstrated: %v", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("audit transport remains open")
	}
}

func TestShutdownGatewayForcesConnectionsClosedAtDeadline(t *testing.T) {
	lifecycleClients(t)
	entered, canceled := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
	}))
	defer server.Close()
	requestDone := make(chan struct{})
	go func() {
		if resp, err := http.Get(server.URL); err == nil {
			resp.Body.Close()
		}
		close(requestDone)
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := shutdownGateway(ctx, server.Config); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown error=%v", err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("request context not canceled")
	}
	<-requestDone
}

func TestShutdownGatewayDrainsBackgroundAudit(t *testing.T) {
	_, _, closed := lifecycleClients(t)
	t.Setenv("AUDIT_FAIL_CLOSED", "false")
	oldEmitter := auditEventEmitter
	t.Cleanup(func() { auditEventEmitter = oldEmitter })
	entered, release := make(chan struct{}), make(chan struct{})
	releaseAudit := sync.OnceFunc(func() { close(release) })
	defer releaseAudit()
	auditEventEmitter = func(context.Context, *AuditEvent) error { close(entered); <-release; return nil }
	EmitAuditEventAsync(context.Background(), &AuditEvent{})
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- shutdownGateway(ctx, &http.Server{}) }()
	select {
	case <-closed:
		t.Fatal("audit closed before pending event drained")
	case <-time.After(30 * time.Millisecond):
	}
	releaseAudit()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuditDrainDeadlineDurablySpillsActiveQueuedAndOverflowEvents(t *testing.T) {
	lifecycleClients(t)
	t.Setenv("AUDIT_FAIL_CLOSED", "false")
	outbox := filepath.Join(t.TempDir(), "audit.ndjson")
	t.Setenv("AUDIT_OUTBOX_PATH", outbox)
	oldEmitter := auditEventEmitter
	t.Cleanup(func() { auditEventEmitter = oldEmitter })
	entered, release := make(chan struct{}, cap(auditAsyncSlots)), make(chan struct{})
	releaseAudit := sync.OnceFunc(func() { close(release) })
	t.Cleanup(func() {
		releaseAudit()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = drainAuditEvents(ctx)
	})
	auditEventEmitter = func(context.Context, *AuditEvent) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return nil
	}

	ids := make([]string, 0, auditAsyncBacklogLimit+1)
	for i := 0; i <= auditAsyncBacklogLimit; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		ids = append(ids, id)
		EmitAuditEventAsync(context.Background(), &AuditEvent{ID: id, TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})
	}
	for range cap(auditAsyncSlots) {
		<-entered
	}
	overflow, err := os.ReadFile(outbox)
	if err != nil || !strings.Contains(string(overflow), ids[len(ids)-1]) {
		t.Fatalf("overflow event was not durably recovered: err=%v data=%s", err, overflow)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := drainAuditEvents(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("drain error=%v, want context cancellation", err)
	}
	data, err := os.ReadFile(outbox)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if count := strings.Count(string(data), id); count != 1 {
			t.Fatalf("event %s recovery count=%d, want 1", id, count)
		}
	}
	if lines := strings.Count(string(data), "\n"); lines != len(ids) {
		t.Fatalf("outbox lines=%d, want %d", lines, len(ids))
	}
	releaseAudit()
	drained, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := drainAuditEvents(drained); err != nil {
		t.Fatal(err)
	}
}

func TestAuditDrainDeadlinePreventsQueuedEmitAfterSpill(t *testing.T) {
	lifecycleClients(t)
	t.Setenv("AUDIT_FAIL_CLOSED", "false")
	outbox := filepath.Join(t.TempDir(), "audit.ndjson")
	t.Setenv("AUDIT_OUTBOX_PATH", outbox)
	oldEmitter := auditEventEmitter
	t.Cleanup(func() { auditEventEmitter = oldEmitter })
	entered := make(chan struct{}, cap(auditAsyncSlots))
	release, dependenciesClosed := make(chan struct{}), make(chan struct{})
	afterClose := make(chan string, 1)
	auditEventEmitter = func(_ context.Context, event *AuditEvent) error {
		select {
		case <-dependenciesClosed:
			afterClose <- event.ID
			return writeAuditOutbox(event, errors.New("dependencies closed"))
		default:
			entered <- struct{}{}
			<-release
			return nil
		}
	}

	for i := 0; i < cap(auditAsyncSlots); i++ {
		EmitAuditEventAsync(context.Background(), &AuditEvent{ID: fmt.Sprintf("blocker-%d", i), TenantID: "tenant"})
	}
	for range cap(auditAsyncSlots) {
		<-entered
	}
	targetID := "queued-after-spill"
	EmitAuditEventAsync(context.Background(), &AuditEvent{ID: targetID, TenantID: "tenant"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := drainAuditEvents(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("drain error=%v, want context cancellation", err)
	}
	close(dependenciesClosed)
	close(release)
	drained, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := drainAuditEvents(drained); err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-afterClose:
		t.Fatalf("event %s emitted after dependencies closed", id)
	default:
	}
	data, err := os.ReadFile(outbox)
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(string(data), targetID); count != 1 {
		t.Fatalf("queued event recovery count=%d, want 1", count)
	}
}

func TestAuditEvent_OperationContextOnlyRetainsLifecycleCancellation(t *testing.T) {
	request, cancelRequest := context.WithCancel(context.Background())
	detached := auditOperationContext(request)
	cancelRequest()
	if detached.Err() != nil {
		t.Fatal("ordinary request cancellation reached audit persistence")
	}

	tracked, cancelTask := context.WithCancel(context.WithValue(context.Background(), pendingAuditContextKey{}, &pendingAuditEvent{}))
	operation := auditOperationContext(tracked)
	cancelTask()
	if !errors.Is(operation.Err(), context.Canceled) {
		t.Fatalf("tracked lifecycle cancellation not preserved: %v", operation.Err())
	}
}

func TestShutdownGatewayAfterListenFailure(t *testing.T) {
	lifecycleClients(t)
	server := &http.Server{Addr: "invalid:port"}
	if err := server.ListenAndServe(); err == nil {
		t.Fatal("invalid listener succeeded")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := shutdownGateway(ctx, server); err != nil {
		t.Fatal(err)
	}
}

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
	metricsQuery := httptest.NewRecorder()
	r.ServeHTTP(metricsQuery, httptest.NewRequest("GET", "/health?metrics=true", nil))
	if metricsQuery.Header().Get("Content-Type") != "application/json" || strings.Contains(metricsQuery.Body.String(), "authclaw_quota_") {
		t.Fatalf("public health query leaked quota telemetry: %s", metricsQuery.Body.String())
	}
}

func TestInternalQuotaMetricsRequireDedicatedSecret(t *testing.T) {
	t.Setenv("AUTHCLAW_QUOTA_METRICS_SECRET", "")
	missing := httptest.NewRecorder()
	QuotaMetricsHandler(missing, httptest.NewRequest("GET", "/internal/metrics/quota", nil))
	if missing.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing metrics secret status=%d, want %d", missing.Code, http.StatusServiceUnavailable)
	}

	t.Setenv("AUTHCLAW_QUOTA_METRICS_SECRET", "metrics-test-secret")
	for _, tc := range []struct {
		token  string
		status int
	}{{"", http.StatusUnauthorized}, {"wrong", http.StatusUnauthorized}, {"metrics-test-secret", http.StatusOK}} {
		request := httptest.NewRequest("GET", "/internal/metrics/quota", nil)
		if tc.token != "" {
			request.Header.Set("Authorization", "Bearer "+tc.token)
		}
		response := httptest.NewRecorder()
		QuotaMetricsHandler(response, request)
		if response.Code != tc.status {
			t.Fatalf("token=%q status=%d, want %d", tc.token, response.Code, tc.status)
		}
		if tc.status == http.StatusOK && !strings.Contains(response.Body.String(), "authclaw_quota_available") {
			t.Fatal("authorized metrics response omitted quota telemetry")
		}
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
