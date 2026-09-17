package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

var buildTarget = "unknown"

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("metrics") == "true" {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "authclaw_quota_available %d\nauthclaw_quota_admitted_total %d\nauthclaw_quota_rejected_total %d\nauthclaw_quota_decisions_total %d\nauthclaw_quota_latency_seconds_sum %f\nauthclaw_quota_unavailable_total %d\nauthclaw_quota_ambiguous_total %d\n", quotaAvailable.Load(), quotaAdmitted.Load(), quotaRejected.Load(), quotaDecisions.Load(), float64(quotaLatencyMicros.Load())/1e6, rateLimitUnavailableTotal.Load(), rateLimitAmbiguousTotal.Load())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"service": "authclaw-gateway",
	})
}

func NewGatewayRouter(proxy http.Handler) http.Handler {
	return newGatewayRouter(proxy, AuthMiddleware, RateLimitMiddleware)
}

type gatewayMiddleware func(http.Handler) http.Handler

func newGatewayRouter(proxy http.Handler, auth, rateLimit gatewayMiddleware) http.Handler {
	r := chi.NewRouter()
	if envBool("GATEWAY_HTTP_LOGGER_ENABLED", true) {
		r.Use(middleware.Logger)
	}
	r.Use(middleware.Recoverer)
	r.Get("/health", HealthHandler)
	r.Get("/ready", func(w http.ResponseWriter, r *http.Request) {
		if ValidateGatewayRateLimitConfig() != nil {
			quotaAvailable.Store(0)
			writeGatewayError(w, 503, "RateLimitUnavailable", "Invalid limiter configuration")
			return
		}
		if RedisClient == nil {
			InitRedis()
		}
		ctx, cancel := context.WithTimeout(r.Context(), 300*time.Millisecond)
		defer cancel()
		if RedisClient.Ping(ctx).Err() != nil {
			quotaAvailable.Store(0)
			writeGatewayError(w, 503, "RateLimitUnavailable", "Limiter unavailable")
			return
		}
		quotaAvailable.Store(1)
		HealthHandler(w, r)
	})
	r.Group(func(r chi.Router) {
		r.Use(auth)
		r.Use(rateLimit)
		routes, err := configuredProviderRoutes()
		if err != nil {
			panic(err)
		}
		for _, route := range routes {
			if route.Method == "*" {
				r.Handle(route.Pattern, proxy)
				continue
			}
			r.Method(route.Method, route.Pattern, proxy)
		}
	})
	return r
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("authclaw-gateway %s\n", buildTarget)
		return
	}

	// Try to load .env.local from parent directory
	_ = godotenv.Load("../.env.local")
	if len(os.Args) == 2 && os.Args[1] == "--audit-producer" {
		if err := runAuditProducer(); err != nil {
			log.Fatalf("Audit producer failed: %v", err)
		}
		return
	}

	if err := ValidateEnvelopeKeyConfig(); err != nil {
		log.Fatalf("Invalid secret management configuration: %v", err)
	}
	if err := ValidateServiceTLSConfig(); err != nil {
		log.Fatalf("Invalid service TLS configuration: %v", err)
	}
	if err := ValidateEnvironmentConfig(); err != nil {
		log.Fatalf("Invalid environment configuration: %v", err)
	}
	if err := ValidateGatewayRateLimitConfig(); err != nil {
		log.Fatalf("Invalid rate limiter configuration: %v", err)
	}
	// Initialize the shared client before concurrent handlers can reach it.
	InitRedis()
	if err := ValidateAuthCacheConfig(); err != nil {
		log.Fatalf("Invalid authentication cache configuration: %v", err)
	}
	if err := ValidateAuthSecretConfig(); err != nil {
		log.Fatalf("Invalid authentication secret configuration: %v", err)
	}
	if _, err := newClientIPResolverFromEnv(); err != nil {
		log.Fatalf("Invalid trusted proxy configuration: %v", err)
	}

	// Initialize database
	InitDB()

	// Kafka is the default audit transport; missing brokers retain the local fallback.
	if err := InitAuditTransport(); err != nil {
		log.Fatalf("Invalid audit transport configuration: %v", err)
	}
	defer CloseAuditTransport()

	r := NewGatewayRouter(NewProxyServer())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           responseWriteTimeout(r, 30*time.Second),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("Starting AuthClaw Gateway on port %s...", port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start gateway server: %v", err)
	}
}
