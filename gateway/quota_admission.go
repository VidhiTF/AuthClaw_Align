package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var quotaAvailable atomic.Int64
var quotaAdmitted atomic.Uint64
var quotaRejected atomic.Uint64
var quotaDecisions atomic.Uint64
var quotaLatencyMicros atomic.Uint64

// Same admission contract as the agent; each tenant hash tag occupies one slot.
const quotaAdmissionScript = `
local counts = {}
local ttls = {}
for i, key in ipairs(KEYS) do
 local raw = redis.call('GET', key)
 local count = tonumber(raw or '0')
 local ttl = redis.call('PTTL', key)
 if not count or count < 0 or count > 2147483647 or count ~= math.floor(count) or (raw and (tostring(count) ~= raw or ttl < 0 or ttl > 60000)) then
  return redis.error_reply('invalid quota state')
 end
 counts[i] = count
 ttls[i] = ttl
end
for i, key in ipairs(KEYS) do
 if counts[i] >= tonumber(ARGV[i]) then return {0, i, math.max(1, ttls[i]), 0} end
end
local remaining = 9007199254740991
for i, key in ipairs(KEYS) do
 if ttls[i] < 0 then redis.call('SET', key, 1, 'PX', 60000)
 else redis.call('INCR', key) end
 remaining = math.min(remaining, tonumber(ARGV[i]) - counts[i] - 1)
end
return {1, 0, 60000, remaining}
`

func quotaLimit(name string) (int, error) {
	raw := os.Getenv(name)
	environment := strings.ToLower(strings.TrimSpace(os.Getenv("AUTHCLAW_ENV")))
	if raw == "" && (environment == "" || environment == "local" || environment == "development" || environment == "dev") {
		raw = "30"
	}
	value, err := strconv.Atoi(raw)
	for _, digit := range raw {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("%s must contain decimal digits", name)
		}
	}
	if err != nil || value <= 0 || int64(value) > 2147483647 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return value, nil
}

func gatewayQuota(w http.ResponseWriter, r *http.Request, providerModel string) bool {
	started := time.Now()
	defer func() { quotaDecisions.Add(1); quotaLatencyMicros.Add(uint64(time.Since(started).Microseconds())) }()
	if ValidateGatewayRateLimitConfig() != nil {
		quotaAvailable.Store(0)
		rateLimitUnavailableTotal.Add(1)
		writeRateLimitError(w, 503, "RateLimitUnavailable", "Invalid quota configuration")
		return false
	}
	tenant, _ := r.Context().Value(TenantIDContextKey).(string)
	user, _ := r.Context().Value(UserIDContextKey).(string)
	if user == "" {
		user = "service:tenant"
	}
	key, _ := r.Context().Value(APIKeyHashContextKey).(string)
	if tenant == "" || key == "" {
		writeRateLimitError(w, 401, "AuthenticationRequired", "Verified tenant and key required")
		return false
	}
	dimensions := []string{"tenant", "key"}
	subjects := []string{tenant, key}
	names := []string{"AUTHCLAW_RATE_LIMIT_PER_MINUTE", "AUTHCLAW_RATE_LIMIT_KEY_RPM"}
	if user != "" {
		dimensions = append(dimensions, "user")
		subjects = append(subjects, user)
		names = append(names, "AUTHCLAW_RATE_LIMIT_USER_RPM")
	}
	if providerModel != "" {
		dimensions = []string{"expensive_model"}
		subjects = []string{tenant}
		names = []string{"AUTHCLAW_RATE_LIMIT_EXPENSIVE_MODEL_RPM"}
	}
	namespace := "authclaw:gateway-quota:v1"
	if providerModel != "" {
		namespace = "authclaw:quota:v1"
	}
	keys := make([]string, len(subjects))
	limits := make([]interface{}, len(subjects))
	minimumLimit := int64(2147483647)
	for i, subject := range subjects {
		limit, err := quotaLimit(names[i])
		if err != nil {
			writeRateLimitError(w, 503, "RateLimitUnavailable", "Invalid quota configuration")
			return false
		}
		limits[i] = limit
		if int64(limit) < minimumLimit {
			minimumLimit = int64(limit)
		}
		keys[i] = fmt.Sprintf("%s:{%x}:%s:%x", namespace, sha256.Sum256([]byte(tenant)), dimensions[i], sha256.Sum256([]byte(subject)))
	}
	if RedisClient == nil {
		InitRedis()
	}
	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Millisecond)
	defer cancel()
	// EVAL directly avoids any retry or script-load fallback after admission.
	rawResult, err := RedisClient.Eval(ctx, quotaAdmissionScript, keys, limits...).Result()
	result := make([]int64, 0, 4)
	if values, ok := rawResult.([]interface{}); ok {
		for _, value := range values {
			integer, valid := value.(int64)
			if !valid {
				err = fmt.Errorf("non-integer quota response")
				break
			}
			result = append(result, integer)
		}
	}
	if err != nil || len(result) != 4 || (result[0] != 0 && result[0] != 1) || result[2] <= 0 || result[2] > 60000 || result[3] < 0 || (result[0] == 1 && (result[1] != 0 || result[3] >= minimumLimit)) || (result[0] == 0 && (result[1] < 1 || result[1] > int64(len(keys)) || result[3] != 0)) {
		if err == nil {
			err = fmt.Errorf("invalid quota response")
		}
		rateLimitUnavailableTotal.Add(1)
		rateLimitAmbiguousTotal.Add(1)
		quotaAvailable.Store(0)
		w.Header().Set("Retry-After", "1")
		writeRateLimitError(w, 503, "RateLimitUnavailable", "Quota admission unavailable")
		return false
	}
	quotaAvailable.Store(1)
	if result[0] == 0 {
		quotaRejected.Add(1)
		w.Header().Set("Retry-After", strconv.FormatInt((result[2]+999)/1000, 10))
		writeRateLimitError(w, 429, "RateLimitExceeded", "Quota exhausted")
		return false
	}
	quotaAdmitted.Add(1)
	return true
}

// Unknown and alias models are conservatively charged until an approved server catalog exists.
func gatewayProviderQuota(w http.ResponseWriter, r *http.Request, provider, model string) bool {
	if strings.TrimSpace(provider) == "" || strings.TrimSpace(model) == "" {
		quotaAvailable.Store(0)
		rateLimitUnavailableTotal.Add(1)
		writeRateLimitError(w, 503, "RateLimitUnavailable", "Resolved provider and model required")
		return false
	}
	return gatewayQuota(w, r, provider+":"+model)
}
