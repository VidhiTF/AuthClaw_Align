package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

var buildTarget = "unknown"

func shutdownHTTPServer(ctx context.Context, server *http.Server) error {
	err := server.Shutdown(ctx)
	if err != nil {
		err = errors.Join(err, server.Close())
	}
	return err
}

func shutdownGateway(ctx context.Context, server *http.Server) error {
	err := shutdownHTTPServer(ctx, server)
	err = errors.Join(err, drainAuditEvents(ctx))
	CloseAuditTransport()
	presidioClientHTTP.CloseIdleConnections()
	(&http.Client{Transport: providerProxyTransport}).CloseIdleConnections()
	http.DefaultClient.CloseIdleConnections()
	if DB != nil {
		err = errors.Join(err, DB.Close())
	}
	if RedisClient != nil {
		err = errors.Join(err, RedisClient.Close())
	}
	return err
}

func terminationSignals() (chan os.Signal, func()) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	return signals, func() { signal.Stop(signals) }
}

func serveUntilSignal(serve func() error, signals <-chan os.Signal, service string) error {
	result := make(chan error, 1)
	go func() { result <- serve() }()
	select {
	case err := <-result:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("%s server failed: %w", service, err)
		}
	case sig := <-signals:
		log.Printf("Shutting down %s after %s", service, sig)
	}
	return nil
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"service": "authclaw-gateway",
	})
}

func QuotaMetricsHandler(w http.ResponseWriter, r *http.Request) {
	expected := strings.TrimSpace(os.Getenv("AUTHCLAW_QUOTA_METRICS_SECRET"))
	if expected == "" {
		writeGatewayError(w, http.StatusServiceUnavailable, "MetricsUnavailable", "Metrics authentication is unavailable.")
		return
	}
	provided, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) != 1 {
		writeGatewayError(w, http.StatusUnauthorized, "Unauthorized", "Metrics authentication failed.")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "authclaw_quota_available %d\nauthclaw_quota_admitted_total %d\nauthclaw_quota_rejected_total %d\nauthclaw_quota_decisions_total %d\nauthclaw_quota_latency_seconds_sum %f\nauthclaw_quota_unavailable_total %d\nauthclaw_quota_ambiguous_total %d\n", quotaAvailable.Load(), quotaAdmitted.Load(), quotaRejected.Load(), quotaDecisions.Load(), float64(quotaLatencyMicros.Load())/1e6, rateLimitUnavailableTotal.Load(), rateLimitAmbiguousTotal.Load())
	KafkaMetricsHandler(w, r)
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
	r.Get("/internal/metrics/quota", QuotaMetricsHandler)
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
	if err := runGateway(); err != nil {
		log.Fatal(err)
	}
}

func runGateway() (err error) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("authclaw-gateway %s\n", buildTarget)
		return nil
	}

	// Try to load .env.local from parent directory
	_ = godotenv.Load("../.env.local")
	if len(os.Args) == 2 && os.Args[1] == "--audit-producer" {
		return runAuditProducer()
	}

	if err := ValidateEnvelopeKeyConfig(); err != nil {
		return fmt.Errorf("invalid secret management configuration: %w", err)
	}
	if err := ValidateServiceTLSConfig(); err != nil {
		return fmt.Errorf("invalid service TLS configuration: %w", err)
	}
	if err := ValidateEnvironmentConfig(); err != nil {
		return fmt.Errorf("invalid environment configuration: %w", err)
	}
	if err := ValidateGatewayRateLimitConfig(); err != nil {
		return fmt.Errorf("invalid rate limiter configuration: %w", err)
	}
	if err := ValidateAuthCacheConfig(); err != nil {
		return fmt.Errorf("invalid authentication cache configuration: %w", err)
	}
	if err := ValidateAuthSecretConfig(); err != nil {
		return fmt.Errorf("invalid authentication secret configuration: %w", err)
	}
	if _, err := newClientIPResolverFromEnv(); err != nil {
		return fmt.Errorf("invalid trusted proxy configuration: %w", err)
	}
	server := &http.Server{}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = errors.Join(err, shutdownGateway(ctx, server))
	}()
	// Initialize shared clients before concurrent handlers can reach them.
	InitRedis()

	// Initialize database
	if err := initDB(); err != nil {
		return err
	}

	// Kafka is the default audit transport; missing brokers retain the local fallback.
	if err := InitAuditTransport(); err != nil {
		return fmt.Errorf("invalid audit transport configuration: %w", err)
	}
	recoveryCtx, stopRecovery := context.WithCancel(context.Background())
	defer stopRecovery()
	go runAuditRecoveryScanner(recoveryCtx, auditRecoveryScanInterval)

	r := NewGatewayRouter(NewProxyServer())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	*server = http.Server{
		Addr:              ":" + port,
		Handler:           responseWriteTimeout(r, 30*time.Second),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("Starting AuthClaw Gateway on port %s...", port)
	signals, stopSignals := terminationSignals()
	defer stopSignals()
	return serveUntilSignal(server.ListenAndServe, signals, "AuthClaw Gateway")
}
