package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultGatewayLimitPerMinute = 30
	defaultGatewayBurst10Seconds = 10
	defaultGatewayDailyLimit     = 1000
	defaultGatewayMaxBodyBytes   = 128 * 1024
)

type gatewayRateLimitConfig struct {
	Enabled           bool
	RequestsPerMinute int
	Burst10Seconds    int
	DailyRequests     int
	MaxBodyBytes      int64
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func loadGatewayRateLimitConfig() gatewayRateLimitConfig {
	return gatewayRateLimitConfig{
		Enabled:           envBool("GATEWAY_RATE_LIMIT_ENABLED", true),
		RequestsPerMinute: envInt("GATEWAY_RATE_LIMIT_PER_MINUTE", defaultGatewayLimitPerMinute),
		Burst10Seconds:    envInt("GATEWAY_RATE_LIMIT_BURST_10S", defaultGatewayBurst10Seconds),
		DailyRequests:     envInt("GATEWAY_RATE_LIMIT_DAILY", defaultGatewayDailyLimit),
		MaxBodyBytes:      int64(envInt("GATEWAY_MAX_BODY_BYTES", defaultGatewayMaxBodyBytes)),
	}
}

func writeRateLimitError(w http.ResponseWriter, status int, code string, message string) {
	writeGatewayError(w, status, code, message)
}

func RateLimitMiddleware(next http.Handler) http.Handler {
	config := loadGatewayRateLimitConfig()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if config.MaxBodyBytes > 0 {
			if r.ContentLength > config.MaxBodyBytes {
				writeRateLimitError(w, http.StatusRequestEntityTooLarge, "RequestTooLarge", fmt.Sprintf("Request body exceeds %d bytes", config.MaxBodyBytes))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, config.MaxBodyBytes)
		}

		if !config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		tenantID, _ := r.Context().Value(TenantIDContextKey).(string)
		apiKeyHash, _ := r.Context().Value(APIKeyHashContextKey).(string)
		requestID, _ := r.Context().Value(RequestIDContextKey).(string)
		if tenantID == "" || apiKeyHash == "" {
			next.ServeHTTP(w, r)
			return
		}

		now := time.Now().UTC()
		keyPrefix := fmt.Sprintf("authclaw:gateway-limit:v2:{%s:%s}", tenantID, apiKeyHash[:16])
		checks := []struct {
			name    string
			key     string
			limit   int
			ttl     time.Duration
			message string
		}{
			{
				name:    "burst",
				key:     fmt.Sprintf("%s:10s:%d", keyPrefix, now.Unix()/10),
				limit:   config.Burst10Seconds,
				ttl:     20 * time.Second,
				message: "Gateway burst limit exceeded. Please retry shortly.",
			},
			{
				name:    "minute",
				key:     fmt.Sprintf("%s:min:%s", keyPrefix, now.Format("200601021504")),
				limit:   config.RequestsPerMinute,
				ttl:     2 * time.Minute,
				message: "Gateway minute limit exceeded. Please retry after a minute.",
			},
			{
				name:    "day",
				key:     fmt.Sprintf("%s:day:%s", keyPrefix, now.Format("20060102")),
				limit:   config.DailyRequests,
				ttl:     26 * time.Hour,
				message: "Gateway daily limit exceeded for this tenant key.",
			},
		}

		for _, check := range checks {
			exceeded, _, err := fixedWindowRateLimit(r.Context(), check.key, check.limit, check.ttl)
			if err != nil {
				if !emitRequiredDecision(w, r, &AuditEvent{
					ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
					TenantID: tenantID, Action: "block", DecisionReason: "Rate limiter unavailable",
					ResponseStatus: http.StatusServiceUnavailable, DurationMs: 0,
				}, "rate_limiter_unavailable") {
					return
				}
				writeRateLimitError(w, http.StatusServiceUnavailable, "RateLimitUnavailable", "Rate limiter unavailable. Request blocked for safety.")
				return
			}
			if exceeded {
				if !emitRequiredDecision(w, r, &AuditEvent{
					ID: generateID(), RequestID: requestID, Timestamp: time.Now(),
					TenantID: tenantID, Action: "block", DecisionReason: "Rate limit exceeded: " + check.name,
					ResponseStatus: http.StatusTooManyRequests, DurationMs: 0,
				}, "rate_limit_exceeded:"+check.name) {
					return
				}
				writeRateLimitError(w, http.StatusTooManyRequests, "RateLimitExceeded", check.message)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
