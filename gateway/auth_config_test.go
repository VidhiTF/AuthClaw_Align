package main

import "testing"

func TestValidateEnvironmentConfigRejectsUnknownEnvironment(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "production-us")
	if err := ValidateEnvironmentConfig(); err == nil {
		t.Fatal("expected an unknown environment to be rejected")
	}
}

func TestValidateAuthCacheConfigRejectsSharedEnvironmentCaching(t *testing.T) {
	for _, environment := range []string{"ci", "shared-test", "staging", "production"} {
		t.Run(environment, func(t *testing.T) {
			t.Setenv("AUTHCLAW_ENV", environment)
			t.Setenv("GATEWAY_AUTH_CACHE_TTL_MS", "1000")
			if err := ValidateAuthCacheConfig(); err == nil {
				t.Fatal("expected nonzero shared-environment authentication cache TTL to be rejected")
			}
		})
	}
}

func TestValidateAuthCacheConfigAllowsDisabledProductionCache(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "production")
	t.Setenv("GATEWAY_AUTH_CACHE_TTL_MS", "0")
	if err := ValidateAuthCacheConfig(); err != nil {
		t.Fatalf("expected disabled production cache to pass: %v", err)
	}
}

func TestValidateAuthCacheConfigAllowsExplicitLocalBenchmark(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "development")
	t.Setenv("GATEWAY_AUTH_CACHE_TTL_MS", "1000")
	if err := ValidateAuthCacheConfig(); err != nil {
		t.Fatalf("expected explicit local cache to pass: %v", err)
	}
}

func TestValidateAuthSecretConfigRejectsSharedEnvironmentDefaults(t *testing.T) {
	for _, secret := range []string{"", "authclaw-lite-dev-secret", "demo-api-key-hash-change-me", "authclaw-full-local-api-key-hash-secret"} {
		t.Run(secret, func(t *testing.T) {
			t.Setenv("AUTHCLAW_ENV", "staging")
			t.Setenv("API_KEY_HASH_SECRET", secret)
			t.Setenv("SESSION_SECRET_V1", "")
			t.Setenv("SESSION_SECRET", "")
			t.Setenv("JWT_SECRET", "")
			if err := ValidateAuthSecretConfig(); err == nil {
				t.Fatal("expected a missing or default shared-environment hash secret to be rejected")
			}
		})
	}
}

func TestValidateAuthSecretConfigAllowsSharedEnvironmentSecretFallbacks(t *testing.T) {
	for _, name := range []string{"API_KEY_HASH_SECRET", "SESSION_SECRET_V1", "SESSION_SECRET", "JWT_SECRET"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("AUTHCLAW_ENV", "ci")
			for _, candidate := range []string{"API_KEY_HASH_SECRET", "SESSION_SECRET_V1", "SESSION_SECRET", "JWT_SECRET"} {
				t.Setenv(candidate, "")
			}
			t.Setenv(name, "ci-secret-with-sufficient-entropy")
			if err := ValidateAuthSecretConfig(); err != nil {
				t.Fatalf("expected %s fallback to pass: %v", name, err)
			}
		})
	}
}

func TestValidateAuthSecretConfigAllowsLocalDevelopmentDefault(t *testing.T) {
	t.Setenv("AUTHCLAW_ENV", "development")
	t.Setenv("API_KEY_HASH_SECRET", "")
	t.Setenv("SESSION_SECRET_V1", "")
	t.Setenv("SESSION_SECRET", "")
	t.Setenv("JWT_SECRET", "")
	if err := ValidateAuthSecretConfig(); err != nil {
		t.Fatalf("expected local fallback to remain available: %v", err)
	}
}
