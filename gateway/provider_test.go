package main

import (
	"net/http"
	"net/url"
	"testing"
)

func TestProviderRouteValidationRejectsHeaderPathMismatch(t *testing.T) {
	req, _ := http.NewRequest("POST", "/v1/messages", nil)
	req.Header.Set("X-Provider", "cohere")

	err := ValidateProviderRoute(ProviderCohere, req, "https://api.cohere.ai", "command-r")
	if err == nil {
		t.Fatal("expected Cohere header with Anthropic route to be rejected")
	}
}

func TestProviderRouteValidationRejectsIncompatibleModel(t *testing.T) {
	req, _ := http.NewRequest("POST", "/v2/chat", nil)
	req.Header.Set("X-Provider", "cohere")

	err := ValidateProviderRoute(ProviderCohere, req, "https://api.cohere.ai", "gpt-4o")
	if err == nil {
		t.Fatal("expected OpenAI model on Cohere route to be rejected")
	}
}

func TestProviderRouteValidationAllowsAzureOpenAICompatibleRouteWithDeploymentEndpoint(t *testing.T) {
	req, _ := http.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("X-Provider", "azure_openai")

	err := ValidateProviderRoute(
		ProviderAzureOpenAI,
		req,
		"https://example.openai.azure.com/openai/deployments/customer-gpt4/chat/completions?api-version=2024-10-21",
		"gpt-4o",
	)
	if err != nil {
		t.Fatalf("expected Azure OpenAI-compatible route to be accepted with deployment endpoint: %v", err)
	}
}

func TestProviderRouteValidationAllowsGeminiStreamingRoute(t *testing.T) {
	req, _ := http.NewRequest("POST", "/v1/models/gemini-2.5-flash-lite:streamGenerateContent?alt=sse", nil)
	req.Header.Set("X-Provider", "gemini")

	err := ValidateProviderRoute(ProviderGemini, req, "https://generativelanguage.googleapis.com", "gemini-2.5-flash-lite")
	if err != nil {
		t.Fatalf("expected Gemini streamGenerateContent route to be accepted: %v", err)
	}
}

func TestApplyProviderCredentialHeaders(t *testing.T) {
	target, _ := url.Parse("https://api.example.test")
	tests := []struct {
		name          string
		provider      string
		wantHeader    string
		wantValue     string
		rejectAuth    bool
		requiresQuery bool
	}{
		{name: "openai", provider: ProviderOpenAI, wantHeader: "Authorization", wantValue: "Bearer provider-key"},
		{name: "anthropic", provider: ProviderAnthropic, wantHeader: "x-api-key", wantValue: "provider-key", rejectAuth: true},
		{name: "cohere", provider: ProviderCohere, wantHeader: "Authorization", wantValue: "Bearer provider-key"},
		{name: "gemini", provider: ProviderGemini, wantHeader: "x-goog-api-key", wantValue: "provider-key", rejectAuth: true, requiresQuery: true},
		{name: "azure_openai", provider: ProviderAzureOpenAI, wantHeader: "api-key", wantValue: "provider-key", rejectAuth: true, requiresQuery: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/v1/chat/completions", nil)
			req.Header.Set("Authorization", "Bearer gateway-key")
			if tt.provider == ProviderAzureOpenAI {
				target, _ = url.Parse("https://resource.openai.azure.com/openai/deployments/gpt4/chat/completions?api-version=2024-10-21")
			}

			ApplyProviderCredential(req, tt.provider, &ProviderCredential{APIKey: "provider-key"}, "tenant-1", target)

			if got := req.Header.Get(tt.wantHeader); got != tt.wantValue {
				t.Fatalf("expected %s=%q, got %q", tt.wantHeader, tt.wantValue, got)
			}
			if tt.rejectAuth && req.Header.Get("Authorization") != "" {
				t.Fatalf("expected Authorization header to be stripped for %s", tt.provider)
			}
			if tt.provider == ProviderGemini && req.URL.Query().Get("key") != "provider-key" {
				t.Fatalf("expected Gemini key query injection, got %q", req.URL.RawQuery)
			}
			if tt.provider == ProviderAzureOpenAI && req.URL.Query().Get("api-version") != "2024-10-21" {
				t.Fatalf("expected Azure api-version query injection, got %q", req.URL.RawQuery)
			}
		})
	}
}

func TestAzureOpenAIRequiresTenantProviderCredential(t *testing.T) {
	if !requiresTenantProviderCredential(ProviderAzureOpenAI) {
		t.Fatal("expected Azure OpenAI to require a tenant provider credential")
	}
}
