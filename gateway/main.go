package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

var buildTarget = "unknown"

func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
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

	r := NewGatewayRouter(NewProxyServer())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting AuthClaw Gateway on port %s...", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Failed to start gateway server: %v", err)
	}
}
