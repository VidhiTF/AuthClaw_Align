package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

func TestQuotaStrictConfigAndIdentity(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "development")
	t.Setenv("REDIS_URL", "redis://127.0.0.1:1")
	for _, raw := range []string{"bad", "0", "-1"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("GATEWAY_RATE_LIMIT_PER_MINUTE", raw)
			if ValidateGatewayRateLimitConfig() == nil {
				t.Fatal("accepted invalid limit")
			}
		})
	}
	for _, env := range []string{"shared-test", "staging", "production", " Test "} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("AUTHCLAW_ENV", env)
			t.Setenv("REDIS_URL", "")
			if ValidateGatewayRateLimitConfig() == nil {
				t.Fatal("accepted absent Redis")
			}
		})
	}
	calls := 0
	handler := RateLimitMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("POST", "/v1/chat/completions", nil))
	if response.Code != 401 || calls != 0 {
		t.Fatalf("status=%d calls=%d", response.Code, calls)
	}
}

func TestQuotaSharedRedisRequiresTLS(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "production")
	for _, name := range []string{"AUTHCLAW_RATE_LIMIT_PER_MINUTE", "AUTHCLAW_RATE_LIMIT_USER_RPM", "AUTHCLAW_RATE_LIMIT_KEY_RPM", "AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM"} {
		t.Setenv(name, "30")
	}
	t.Setenv("REDIS_URL", "redis://redis.example:6379")
	if ValidateGatewayRateLimitConfig() == nil {
		t.Fatal("accepted remote plaintext Redis")
	}
	t.Setenv("REDIS_URL", "rediss://redis.example:6379")
	if err := ValidateGatewayRateLimitConfig(); err != nil {
		t.Fatal(err)
	}
}

func TestProviderQuotaRejectsUnknownIdentityAndModel(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "development")
	t.Setenv("REDIS_URL", "redis://127.0.0.1:1")
	request := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	for _, model := range []string{"", "gpt-4"} {
		response := httptest.NewRecorder()
		if gatewayProviderQuota(response, request, "openai", model) {
			t.Fatal("admitted invalid context")
		}
		if response.Code != 401 && response.Code != 503 {
			t.Fatalf("status=%d", response.Code)
		}
	}
}

func TestQuotaMissingConfigDeniesBeforeProvider(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "production")
	t.Setenv("AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM", "")
	ctx := context.WithValue(context.Background(), TenantIDContextKey, "tenant")
	ctx = context.WithValue(ctx, APIKeyHashContextKey, "key")
	request := httptest.NewRequest("POST", "/v1/chat/completions", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	if gatewayProviderQuota(response, request, "openai", "gpt-4") || response.Code != 503 {
		t.Fatal("missing config admitted")
	}
}

func TestQuotaRealRedisIndependentAdmission(t *testing.T) {
	if os.Getenv("QUOTA_REDIS_TEST") != "1" {
		t.Skip("requires isolated real Redis")
	}
	t.Setenv("AUTHCLAW_ENV", "development")
	InitRedis()
	defer RedisClient.Close()
	for _, dimension := range []string{"tenant", "user", "key", "expensive_model"} {
		t.Run(dimension, func(t *testing.T) {
			for _, name := range []string{"AUTHCLAW_RATE_LIMIT_PER_MINUTE", "AUTHCLAW_RATE_LIMIT_USER_RPM", "AUTHCLAW_RATE_LIMIT_KEY_RPM", "AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM"} {
				t.Setenv(name, "100")
			}
			names := map[string]string{"tenant": "AUTHCLAW_RATE_LIMIT_PER_MINUTE", "user": "AUTHCLAW_RATE_LIMIT_USER_RPM", "key": "AUTHCLAW_RATE_LIMIT_KEY_RPM", "expensive_model": "AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM"}
			t.Setenv(names[dimension], "1")
			tenant := "quota-test-" + generateID()
			request := func(tenant, user, key string) *http.Request {
				ctx := context.WithValue(context.Background(), TenantIDContextKey, tenant)
				ctx = context.WithValue(ctx, UserIDContextKey, user)
				ctx = context.WithValue(ctx, APIKeyHashContextKey, key)
				return httptest.NewRequest("POST", "/v1/chat/completions", nil).WithContext(ctx)
			}
			provider := ""
			if dimension == "expensive_model" {
				provider = "openai:alias"
			}
			if !gatewayQuota(httptest.NewRecorder(), request(tenant, "user", "key"), provider) {
				t.Fatal("first admission denied")
			}
			response := httptest.NewRecorder()
			if gatewayQuota(response, request(tenant, "user", "key"), provider) || response.Code != 429 {
				t.Fatalf("limit failed: %d", response.Code)
			}
			if !gatewayQuota(httptest.NewRecorder(), request(tenant+"other", "user", "key"), provider) {
				t.Fatal("tenant isolation failed")
			}
			if dimension == "user" && !gatewayQuota(httptest.NewRecorder(), request(tenant, "other", "other"), provider) {
				t.Fatal("other user denied")
			}
			if dimension == "key" && !gatewayQuota(httptest.NewRecorder(), request(tenant, "user", "other"), provider) {
				t.Fatal("other key denied")
			}
		})
	}
}

func TestQuotaRedisRefusalNeverAdmits(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "development")
	t.Setenv("REDIS_URL", "redis://127.0.0.1:1")
	InitRedis()
	defer func() { RedisClient.Close(); RedisClient = nil }()
	ctx := context.WithValue(context.Background(), TenantIDContextKey, "tenant")
	ctx = context.WithValue(ctx, APIKeyHashContextKey, "key")
	request := httptest.NewRequest("POST", "/v1/chat/completions", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	if gatewayQuota(response, request, "openai:model") || response.Code != 503 {
		t.Fatalf("refusal admitted: %d", response.Code)
	}
}

func TestQuotaRealRedisProviderCallsExactlyOnce(t *testing.T) {
	if os.Getenv("QUOTA_REDIS_TEST") != "1" {
		t.Skip("requires isolated real Redis")
	}
	t.Setenv("AUTHCLAW_ENV", "development")
	t.Setenv("AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM", "1")
	InitRedis()
	defer func() { RedisClient.Close(); RedisClient = nil }()
	var calls atomic.Int64
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer stub.Close()
	ctx := context.WithValue(context.Background(), TenantIDContextKey, "quota-test-"+generateID())
	ctx = context.WithValue(ctx, APIKeyHashContextKey, "verified-key")
	request := httptest.NewRequest("POST", "/v1/chat/completions", nil).WithContext(ctx)
	for i := 0; i < 2; i++ {
		response := httptest.NewRecorder()
		if gatewayProviderQuota(response, request, "openai", "resolved-model") {
			result, err := http.Get(stub.URL)
			if err != nil {
				t.Fatal(err)
			}
			result.Body.Close()
		} else if response.Code != 429 {
			t.Fatalf("unexpected denial: %d", response.Code)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls=%d", calls.Load())
	}
}

func TestQuotaHealthAndReadinessDuringRefusal(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "development")
	t.Setenv("REDIS_URL", "redis://127.0.0.1:1")
	InitRedis()
	defer func() { RedisClient.Close(); RedisClient = nil }()
	calls := 0
	router := NewGatewayRouter(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	for _, tc := range []struct {
		path   string
		status int
	}{{"/ready", 503}, {"/health", 200}, {"/health?metrics=true", 200}, {"/health/extra", 404}} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest("GET", tc.path, nil))
		if response.Code != tc.status {
			t.Fatalf("%s status=%d", tc.path, response.Code)
		}
	}
	if calls != 0 {
		t.Fatal("health check executed protected handler")
	}
}

func TestQuotaTestEnvironmentCannotUseLocalDefaults(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", " Test ")
	t.Setenv("AUTHCLAW_RATE_LIMIT_PER_MINUTE", "")
	if _, err := quotaLimit("AUTHCLAW_RATE_LIMIT_PER_MINUTE"); err == nil {
		t.Fatal("shared test accepted missing mandatory limit")
	}
}
