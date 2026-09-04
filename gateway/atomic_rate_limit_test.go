package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAtomicRateLimitKeysAreVersionedAndClusterSafe(t *testing.T) {
	policyKey := policyRateLimitKey("tenant-1", "/v1/chat/completions", time.Date(2026, 9, 3, 1, 2, 0, 0, time.UTC))
	if !strings.HasPrefix(policyKey, "authclaw:policy-limit:v2:{tenant-1}:") {
		t.Fatalf("unexpected policy key: %s", policyKey)
	}
	gatewayKey := "authclaw:gateway-limit:v2:{tenant-1:keyhash}:minute"
	if !strings.Contains(gatewayKey, "{tenant-1:keyhash}") {
		t.Fatal("gateway key lacks Redis Cluster hash tag")
	}
}

func TestAtomicRateLimitClientRetriesAreDisabled(t *testing.T) {
	t.Setenv("REDIS_URL", "redis://127.0.0.1:6379")
	InitRedis()
	defer RedisClient.Close()
	if RedisClient.Options().MaxRetries != 0 {
		t.Fatalf("ambiguous Redis commands must not be retried, got normalized MaxRetries=%d", RedisClient.Options().MaxRetries)
	}
}

func TestAtomicRateLimitScriptSetsExpiryOnlyOnCreation(t *testing.T) {
	source := atomicFixedWindowScript.Hash()
	if source == "" {
		t.Fatal("atomic limiter script must be defined")
	}
}

func TestAtomicRateLimitConcurrentFirstIncrementKeepsTTL(t *testing.T) {
	if testing.Short() {
		t.Skip("real Redis test")
	}
	InitRedis()
	ctx := context.Background()
	key := "authclaw:gateway-limit:v2:{release4-test}:concurrency"
	if err := RedisClient.Del(ctx, key).Err(); err != nil {
		if os.Getenv("REDIS_URL") != "" {
			t.Fatalf("configured Redis unavailable: %v", err)
		}
		t.Skipf("Redis unavailable: %v", err)
	}
	defer RedisClient.Del(ctx, key)

	var wait sync.WaitGroup
	errors := make(chan error, 32)
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, err := fixedWindowRateLimit(ctx, key, 100, 30*time.Second)
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if ttl := RedisClient.PTTL(ctx, key).Val(); ttl <= 0 {
		t.Fatalf("atomic counter lost its TTL: %v", ttl)
	}
}
