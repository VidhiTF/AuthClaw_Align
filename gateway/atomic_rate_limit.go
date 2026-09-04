package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

var atomicFixedWindowScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return {count, redis.call('PTTL', KEYS[1])}
`)

var (
	rateLimitUnavailableTotal atomic.Uint64
	rateLimitAmbiguousTotal   atomic.Uint64
)

func AbuseControlMetricsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"authclaw_rate_limit_unavailable_total": rateLimitUnavailableTotal.Load(),
		"authclaw_rate_limit_ambiguous_total":   rateLimitAmbiguousTotal.Load(),
	}
}

func recordRateLimitError(err error) {
	var networkError net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
		rateLimitAmbiguousTotal.Add(1)
		return
	}
	rateLimitUnavailableTotal.Add(1)
}

func fixedWindowRateLimit(ctx context.Context, key string, limit int, ttl time.Duration) (bool, int64, error) {
	if limit <= 0 {
		return false, 0, nil
	}
	if ttl <= 0 {
		return false, 0, fmt.Errorf("rate-limit TTL must be positive")
	}
	if RedisClient == nil {
		InitRedis()
	}
	result, err := atomicFixedWindowScript.Run(ctx, RedisClient, []string{key}, ttl.Milliseconds()).Int64Slice()
	if err != nil {
		recordRateLimitError(err)
		return false, 0, err
	}
	if len(result) != 2 || result[0] < 1 || result[1] < 0 {
		err := fmt.Errorf("invalid rate-limit counter state")
		recordRateLimitError(err)
		return false, 0, err
	}
	count := result[0]
	return count > int64(limit), count, nil
}
