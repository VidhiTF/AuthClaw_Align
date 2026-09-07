package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

var buildTarget = "unknown"
var gatewayShuttingDown atomic.Bool

func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if gatewayShuttingDown.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "draining",
			"service": "authclaw-gateway",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"service": "authclaw-gateway",
	})
}

func NewGatewayRouter(proxy http.Handler) http.Handler {
	r := chi.NewRouter()
	if envBool("GATEWAY_HTTP_LOGGER_ENABLED", true) {
		r.Use(middleware.Logger)
	}
	r.Use(middleware.Recoverer)
	r.Get("/health", HealthHandler)
	r.Route("/v1", func(r chi.Router) {
		r.Use(AuthMiddleware)
		r.Use(RateLimitMiddleware)
		r.Handle("/*", proxy)
	})
	return r
}

func main() {
	configureStructuredLogging()
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("authclaw-gateway %s\n", buildTarget)
		return
	}

	// Try to load .env.local from parent directory
	_ = godotenv.Load("../.env.local")

	if err := ValidateEnvelopeKeyConfig(); err != nil {
		log.Fatalf("Invalid secret management configuration: %v", err)
	}
	if err := ValidateServiceTLSConfig(); err != nil {
		log.Fatalf("Invalid service TLS configuration: %v", err)
	}
	if err := ValidateEnvironmentConfig(); err != nil {
		log.Fatalf("Invalid environment configuration: %v", err)
	}
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
	emfStop := make(chan struct{})
	go startGatewayEMF(emfStop)
	defer close(emfStop)

	r := NewGatewayRouter(NewProxyServer())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadHeaderTimeout: boundedDuration("GATEWAY_READ_HEADER_TIMEOUT_SECONDS", 5, 1, 30),
		IdleTimeout:       boundedDuration("GATEWAY_IDLE_TIMEOUT_SECONDS", 60, 5, 120),
	}
	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("Starting AuthClaw Gateway on port %s...", port)
		serverErrors <- server.ListenAndServe()
	}()

	shutdownSignal := make(chan os.Signal, 1)
	signal.Notify(shutdownSignal, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(shutdownSignal)

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to serve gateway traffic: %v", err)
		}
	case received := <-shutdownSignal:
		gatewayShuttingDown.Store(true)
		grace := boundedDuration("GATEWAY_SHUTDOWN_TIMEOUT_SECONDS", 45, 5, 110)
		log.Printf("Gateway draining after signal=%s grace_seconds=%d", received, int(grace.Seconds()))
		ctx, cancel := context.WithTimeout(context.Background(), grace)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Gateway graceful shutdown exceeded its deadline: %v", err)
			_ = server.Close()
		}
	}

	if RedisClient != nil {
		_ = RedisClient.Close()
	}
	if DB != nil {
		_ = DB.Close()
	}
}

func boundedDuration(name string, fallback, minimum, maximum int) time.Duration {
	seconds := envInt(name, fallback)
	if seconds < minimum {
		seconds = minimum
	}
	if seconds > maximum {
		seconds = maximum
	}
	return time.Duration(seconds) * time.Second
}
