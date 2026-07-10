package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
)

func HealthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":            "healthy",
		"service":           "authclaw-gateway",
		"audit_fail_closed": auditFailClosedEnabled(),
		"audit_outbox_path": auditOutboxPath(),
	})
}

func main() {
	// Try to load .env.local from parent directory
	_ = godotenv.Load("../.env.local")

	if err := ValidateEnvelopeKeyConfig(); err != nil {
		log.Fatalf("Invalid secret management configuration: %v", err)
	}

	// Initialize database
	InitDB()

	// Initialize Kafka producer (non-fatal if Kafka is unavailable)
	InitKafkaProducer()
	defer CloseKafkaProducer()

	r := chi.NewRouter()

	// Standard middleware
	if envBool("GATEWAY_HTTP_LOGGER_ENABLED", true) {
		r.Use(middleware.Logger)
	}
	r.Use(middleware.Recoverer)

	// Basic health check endpoint
	r.Get("/health", HealthHandler)
	r.Get("/metrics", KafkaMetricsHandler)

	// Setup LLM provider reverse proxy
	proxy := NewProxyServer()
	r.Route("/v1", func(r chi.Router) {
		r.Use(AuthMiddleware)
		r.Use(RateLimitMiddleware)
		r.HandleFunc("/*", proxy.ServeHTTP)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting AuthClaw Gateway on port %s...", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Failed to start gateway server: %v", err)
	}
}
