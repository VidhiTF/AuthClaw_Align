package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
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

func ValidateGatewayRateLimitConfig() error {
	if err := ValidateEnvironmentConfig(); err != nil {
		return err
	}
	for _, name := range []string{"AUTHCLAW_RATE_LIMIT_PER_MINUTE", "AUTHCLAW_RATE_LIMIT_KEY_RPM", "AUTHCLAW_RATE_LIMIT_USER_RPM", "AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM"} {
		if _, err := quotaLimit(name); err != nil {
			return err
		}
	}
	if raw := strings.ToLower(strings.TrimSpace(os.Getenv("GATEWAY_RATE_LIMIT_ENABLED"))); raw != "" {
		switch raw {
		case "1", "true", "yes", "on", "0", "false", "no", "off":
		default:
			return fmt.Errorf("GATEWAY_RATE_LIMIT_ENABLED must be boolean")
		}
	}
	for _, name := range []string{"GATEWAY_RATE_LIMIT_PER_MINUTE", "GATEWAY_RATE_LIMIT_BURST_10S", "GATEWAY_RATE_LIMIT_DAILY", "GATEWAY_MAX_BODY_BYTES"} {
		if raw := strings.TrimSpace(os.Getenv(name)); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value <= 0 {
				return fmt.Errorf("%s must be a positive integer", name)
			}
		}
	}
	if isSharedEnv() || strings.EqualFold(strings.TrimSpace(os.Getenv("AUTHCLAW_ENV")), "test") {
		if !loadGatewayRateLimitConfig().Enabled {
			return fmt.Errorf("distributed gateway limiting is required in shared environments")
		}
	}
	raw := strings.TrimSpace(os.Getenv("REDIS_URL"))
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || (parsed.Scheme != "redis" && parsed.Scheme != "rediss") || parsed.Hostname() == "" {
		return fmt.Errorf("REDIS_URL must configure a Redis endpoint")
	}
	if (isSharedEnv() || strings.EqualFold(os.Getenv("AUTHCLAW_ENV"), "test")) && parsed.Scheme == "redis" {
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("REDIS_URL must use TLS outside loopback in shared environments")
		}
	}
	return nil
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

func recordLegacyQuotaRejection() {
	// Legacy burst/minute/day windows are still enforced quota decisions. Keep
	// them in the aggregate alert numerator and denominator even though the
	// multidimensional admission script does not run after their denial.
	quotaRejected.Add(1)
	quotaDecisions.Add(1)
}

func RateLimitMiddleware(next http.Handler) http.Handler {
	config := loadGatewayRateLimitConfig()
	configErr := ValidateGatewayRateLimitConfig()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if configErr != nil {
			quotaAvailable.Store(0)
			rateLimitUnavailableTotal.Add(1)
			writeRateLimitError(w, http.StatusServiceUnavailable, "RateLimitUnavailable", "Invalid rate limiter configuration")
			return
		}
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
			writeRateLimitError(w, http.StatusUnauthorized, "AuthenticationRequired", "Verified tenant and key identity required")
			return
		}

		now := time.Now().UTC()
		keyHashPrefix := apiKeyHash
		if len(keyHashPrefix) > 16 {
			keyHashPrefix = keyHashPrefix[:16]
		}
		keyPrefix := fmt.Sprintf("authclaw:gateway-limit:v2:{%s:%s}", tenantID, keyHashPrefix)
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
				quotaAvailable.Store(0)
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
				recordLegacyQuotaRejection()
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

		if !gatewayQuota(w, r, "") {
			return
		}
		next.ServeHTTP(w, r)
	})
}
