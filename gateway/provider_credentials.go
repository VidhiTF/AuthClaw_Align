package main

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

type ProviderCredential struct {
	Provider string
	Endpoint string
	APIKey   string
}

type cachedProviderCredential struct {
	credential ProviderCredential
	expiresAt  time.Time
}

var providerCredentialCache sync.Map

func providerCredentialCacheTTL() time.Duration {
	return time.Duration(envInt("PROVIDER_CREDENTIAL_CACHE_TTL_MS", 0)) * time.Millisecond
}

func providerCredentialCacheKey(tenantID, provider string) string {
	return tenantID + ":" + provider
}

func getCachedProviderCredential(tenantID, provider string) (*ProviderCredential, bool) {
	raw, ok := providerCredentialCache.Load(providerCredentialCacheKey(tenantID, provider))
	if !ok {
		return nil, false
	}
	cached, ok := raw.(cachedProviderCredential)
	if !ok || time.Now().After(cached.expiresAt) {
		providerCredentialCache.Delete(providerCredentialCacheKey(tenantID, provider))
		return nil, false
	}
	credential := cached.credential
	return &credential, true
}

func setCachedProviderCredential(tenantID, provider string, credential *ProviderCredential) {
	ttl := providerCredentialCacheTTL()
	if ttl <= 0 || credential == nil {
		return
	}
	providerCredentialCache.Store(providerCredentialCacheKey(tenantID, provider), cachedProviderCredential{
		credential: *credential,
		expiresAt:  time.Now().Add(ttl),
	})
}

func LoadProviderCredential(ctx context.Context, tenantID, provider string) (*ProviderCredential, error) {
	if tenantID == "" || provider == "" {
		return nil, nil
	}
	if credential, ok := getCachedProviderCredential(tenantID, provider); ok {
		return credential, nil
	}

	var encryptedSecret string
	var endpoint sql.NullString

	err := RunInTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT encrypted_secret, endpoint
			FROM provider_credentials
			WHERE tenant_id = $1
			  AND provider = $2
			  AND status = 'active'
			  AND revoked_at IS NULL
			ORDER BY version DESC, created_at DESC
			LIMIT 1
		`, tenantID, provider).Scan(&encryptedSecret, &endpoint)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	apiKey, err := DecryptSecret(encryptedSecret)
	if err != nil {
		return nil, err
	}

	credential := &ProviderCredential{
		Provider: provider,
		APIKey:   apiKey,
	}
	if endpoint.Valid {
		credential.Endpoint = endpoint.String
	}
	setCachedProviderCredential(tenantID, provider, credential)
	return credential, nil
}
