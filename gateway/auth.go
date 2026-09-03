package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha3"
	"database/sql"
	"encoding/hex"
	"fmt"
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
	TenantIDContextKey       contextKey = "tenant_id"
	ScopesContextKey         contextKey = "scopes"
	RequestIDContextKey      contextKey = "request_id"
	UserIDContextKey         contextKey = "user_id"
	APIKeyHashContextKey     contextKey = "api_key_hash"
	CredentialKindContextKey contextKey = "credential_kind"
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

func ValidateAuthCacheConfig() error {
	environment := strings.ToLower(strings.TrimSpace(os.Getenv("AUTHCLAW_ENV")))
	switch environment {
	case "ci", "shared-test", "staging", "stage", "production", "prod":
		if ttl := apiKeyCacheTTL(); ttl != 0 {
			return fmt.Errorf("GATEWAY_AUTH_CACHE_TTL_MS must be zero in shared test, staging, and production environments")
		}
	}
	return nil
}

func ValidateEnvironmentConfig() error {
	environment := strings.ToLower(strings.TrimSpace(os.Getenv("AUTHCLAW_ENV")))
	if environment == "" {
		environment = "local"
	}
	switch environment {
	case "local", "development", "dev", "test", "ci", "shared-test", "staging", "stage", "production", "prod":
		return nil
	default:
		return fmt.Errorf("AUTHCLAW_ENV %q is unsupported; configure an explicit local, test, staging, or production environment", environment)
	}
}

func effectiveAPIKeyHashSecret() string {
	for _, name := range []string{"API_KEY_HASH_SECRET", "SESSION_SECRET_V1", "SESSION_SECRET", "JWT_SECRET"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}

func isDemoAuthSecret(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "" || normalized == "authclaw-lite-dev-secret" ||
		normalized == "dev-secret-change-in-production" ||
		strings.Contains(normalized, "change-me") || strings.HasPrefix(normalized, "authclaw-full-local-")
}

func ValidateAuthSecretConfig() error {
	if isSharedEnv() && isDemoAuthSecret(effectiveAPIKeyHashSecret()) {
		return fmt.Errorf("API_KEY_HASH_SECRET, SESSION_SECRET_V1, SESSION_SECRET, or JWT_SECRET must provide a non-default API-key hash secret in shared environments")
	}
	return nil
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
	secret := effectiveAPIKeyHashSecret()
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
		credentialKind := "api_key"
		if strings.HasPrefix(apiKey, "acl_session_") {
			credentialKind = "session"
		}

		// 2. Query DB to validate key and retrieve tenant_id
		var apiKeyID string
		var tenantID string
		var userID string
		var scopes []string

		if credentialKind == "api_key" {
			if cached, ok := getCachedAPIKeyResolution(keyHash); ok {
				apiKeyID = cached.apiKeyID
				tenantID = cached.tenantID
				userID = cached.userID
				scopes = cached.scopes
			} else {
				err := DB.QueryRow(
					"SELECT credential_id, tenant_id, scopes, user_id FROM authn.bind_api_key_context($1)",
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
		} else {
			err := DB.QueryRow(
				"SELECT credential_id, tenant_id, scopes, user_id FROM authn.bind_session_context($1)",
				keyHash,
			).Scan(&apiKeyID, &tenantID, pq.Array(&scopes), &userID)
			if err != nil {
				http.Error(w, "Unauthorized: Invalid or expired session", http.StatusUnauthorized)
				return
			}
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
		remoteIP := resolvedClientIP(r)
		if credentialKind == "api_key" && envBool("GATEWAY_AUTH_LAST_USED_ENABLED", true) {
			go func() {
				ctx := context.Background()
				ctx = context.WithValue(ctx, APIKeyHashContextKey, keyHash)
				ctx = context.WithValue(ctx, CredentialKindContextKey, credentialKind)
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
		ctx = context.WithValue(ctx, CredentialKindContextKey, credentialKind)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
