package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha3"
	"database/sql"
	"encoding/hex"
	"hash"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
)

type contextKey string

const (
	TenantIDContextKey   contextKey = "tenant_id"
	ScopesContextKey     contextKey = "scopes"
	RequestIDContextKey  contextKey = "request_id"
	UserIDContextKey     contextKey = "user_id"
	APIKeyHashContextKey contextKey = "api_key_hash"
)

type cachedAPIKeyResolution struct {
	apiKeyID  string
	tenantID  string
	userID    string
	scopes    []string
	expiresAt time.Time
}

var apiKeyResolutionCache sync.Map

func apiKeyCacheTTL() time.Duration {
	return time.Duration(envInt("GATEWAY_AUTH_CACHE_TTL_MS", 0)) * time.Millisecond
}

func getCachedAPIKeyResolution(keyHash string) (cachedAPIKeyResolution, bool) {
	raw, ok := apiKeyResolutionCache.Load(keyHash)
	if !ok {
		return cachedAPIKeyResolution{}, false
	}
	cached, ok := raw.(cachedAPIKeyResolution)
	if !ok || time.Now().After(cached.expiresAt) {
		apiKeyResolutionCache.Delete(keyHash)
		return cachedAPIKeyResolution{}, false
	}
	cached.scopes = append([]string{}, cached.scopes...)
	return cached, true
}

func setCachedAPIKeyResolution(keyHash string, cached cachedAPIKeyResolution) {
	ttl := apiKeyCacheTTL()
	if ttl <= 0 {
		return
	}
	cached.expiresAt = time.Now().Add(ttl)
	cached.scopes = append([]string{}, cached.scopes...)
	apiKeyResolutionCache.Store(keyHash, cached)
}

// generateRequestID creates a random 16-byte hex request identifier.
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

// HashKey computes a keyed digest of the API key for deterministic lookup.
func HashKey(key string) string {
	secret := os.Getenv("API_KEY_HASH_SECRET")
	if secret == "" {
		secret = os.Getenv("SESSION_SECRET_V1")
	}
	if secret == "" {
		secret = os.Getenv("SESSION_SECRET")
	}
	if secret == "" {
		secret = os.Getenv("JWT_SECRET")
	}
	if secret == "" {
		secret = "authclaw-lite-dev-secret"
	}
	mac := hmac.New(func() hash.Hash { return sha3.New256() }, []byte(secret))
	mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

// AuthMiddleware extracts the API key, validates it, and injects tenant info into context
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Extract Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Invalid Authorization format. Expected: Bearer <key>", http.StatusUnauthorized)
			return
		}

		apiKey := parts[1]
		keyHash := HashKey(apiKey)

		// 2. Query DB to validate key and retrieve tenant_id
		var apiKeyID string
		var tenantID string
		var userID string
		var scopes []string

		if cached, ok := getCachedAPIKeyResolution(keyHash); ok {
			apiKeyID = cached.apiKeyID
			tenantID = cached.tenantID
			userID = cached.userID
			scopes = cached.scopes
		} else {
			err := DB.QueryRow(
				"SELECT id, tenant_id, scopes, created_by FROM resolve_api_key($1)",
				keyHash,
			).Scan(&apiKeyID, &tenantID, pq.Array(&scopes), &userID)

			if err != nil {
				http.Error(w, "Unauthorized: Invalid or expired API Key", http.StatusUnauthorized)
				return
			}
			setCachedAPIKeyResolution(keyHash, cachedAPIKeyResolution{
				apiKeyID: apiKeyID,
				tenantID: tenantID,
				userID:   userID,
				scopes:   scopes,
			})
		}

		// 3. Inject tenant info and request_id into context
		// Honour an upstream X-Request-ID header; generate one if absent.
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRequestID()
		}
		w.Header().Set("X-Request-ID", requestID)
		userAgent := r.UserAgent()
		if len(userAgent) > 512 {
			userAgent = userAgent[:512]
		}
		remoteIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			remoteIP = strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
		if envBool("GATEWAY_AUTH_LAST_USED_ENABLED", true) {
			go func() {
				ctx := context.Background()
				if err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
					_, err := tx.ExecContext(
						ctx,
						`UPDATE api_keys
					 SET last_used = NOW(),
					     last_used_ip = $2,
					     last_used_user_agent = $3,
					     last_used_request_id = $4,
					     updated_at = NOW()
					 WHERE id = $1`,
						apiKeyID,
						remoteIP,
						userAgent,
						requestID,
					)
					return err
				}); err != nil {
					// ponytail: metadata-only update; keep auth success off the latency path unless this becomes billing-critical.
				}
			}()
		}

		ctx := context.WithValue(r.Context(), TenantIDContextKey, tenantID)
		ctx = context.WithValue(ctx, ScopesContextKey, scopes)
		ctx = context.WithValue(ctx, RequestIDContextKey, requestID)
		ctx = context.WithValue(ctx, UserIDContextKey, userID)
		ctx = context.WithValue(ctx, APIKeyHashContextKey, keyHash)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
