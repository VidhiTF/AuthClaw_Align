package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	ProviderOpenAI      = "openai"
	ProviderAnthropic   = "anthropic"
	ProviderCohere      = "cohere"
	ProviderAzureOpenAI = "azure_openai"
	ProviderGemini      = "gemini"
	ProviderBedrock     = "bedrock"
)

func NormalizeProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "openai":
		return ProviderOpenAI
	case "anthropic", "claude":
		return ProviderAnthropic
	case "cohere":
		return ProviderCohere
	case "azure", "azure_openai", "azure-openai":
		return ProviderAzureOpenAI
	case "gemini", "google":
		return ProviderGemini
	case "bedrock", "aws_bedrock", "aws-bedrock":
		return ProviderBedrock
	default:
		return ""
	}
}

func inferProviderFromPath(path string) string {
	cleanPath := strings.ToLower(path)
	switch {
	case strings.HasPrefix(cleanPath, "/bedrock/"):
		return ProviderBedrock
	case strings.Contains(cleanPath, ":generatecontent") || strings.Contains(cleanPath, ":streamgeneratecontent"):
		return ProviderGemini
	case strings.Contains(cleanPath, "/openai/deployments/") && strings.Contains(cleanPath, "/chat/completions"):
		return ProviderAzureOpenAI
	case strings.HasPrefix(cleanPath, "/v1/chat/completions") || strings.HasPrefix(cleanPath, "/v1/models"):
		return ProviderOpenAI
	case strings.HasPrefix(cleanPath, "/v1/messages") || strings.HasPrefix(cleanPath, "/v1/complete"):
		return ProviderAnthropic
	case strings.HasPrefix(cleanPath, "/v2/chat") ||
		strings.HasPrefix(cleanPath, "/v1/chat") ||
		strings.HasPrefix(cleanPath, "/v1/generate") ||
		strings.HasPrefix(cleanPath, "/v1/embed"):
		return ProviderCohere
	default:
		return ""
	}
}

func ProviderForRequest(r *http.Request) string {
	if headerProvider := NormalizeProvider(r.Header.Get("X-Provider")); headerProvider != "" {
		return headerProvider
	}
	if pathProvider := inferProviderFromPath(r.URL.Path); pathProvider != "" {
		return pathProvider
	}
	return ProviderOpenAI
}

func providerBaseURL(p *ProxyServer, provider string) string {
	switch NormalizeProvider(provider) {
	case ProviderOpenAI:
		return p.OpenAIBaseURL
	case ProviderAnthropic:
		return p.AnthropicBaseURL
	case ProviderCohere:
		return p.CohereBaseURL
	case ProviderAzureOpenAI:
		return p.AzureOpenAIBaseURL
	case ProviderGemini:
		return p.GeminiBaseURL
	case ProviderBedrock:
		return p.BedrockBaseURL
	default:
		return ""
	}
}

func isOpenAICompatiblePath(path string) bool {
	cleanPath := strings.ToLower(path)
	return strings.HasPrefix(cleanPath, "/v1/chat/completions")
}

func isAzureDeploymentChatPath(path string) bool {
	cleanPath := strings.ToLower(path)
	return strings.Contains(cleanPath, "/openai/deployments/") &&
		strings.Contains(cleanPath, "/chat/completions")
}

func providerNameForModel(model string) string {
	model = strings.ToLower(strings.TrimSpace(model))
	switch {
	case model == "":
		return ""
	case strings.HasPrefix(model, "claude-"):
		return ProviderAnthropic
	case strings.HasPrefix(model, "gemini-"):
		return ProviderGemini
	case strings.HasPrefix(model, "command-") || strings.HasPrefix(model, "embed-"):
		return ProviderCohere
	case strings.HasPrefix(model, "gpt-") ||
		strings.HasPrefix(model, "o1") ||
		strings.HasPrefix(model, "o3") ||
		strings.HasPrefix(model, "o4") ||
		strings.HasPrefix(model, "text-embedding-"):
		return ProviderOpenAI
	default:
		return ""
	}
}

func isModelCompatibleWithProvider(provider, model string) bool {
	expectedProvider := providerNameForModel(model)
	if expectedProvider == "" {
		return true
	}
	provider = NormalizeProvider(provider)
	if provider == expectedProvider {
		return true
	}
	return provider == ProviderAzureOpenAI && expectedProvider == ProviderOpenAI
}

func ValidateProviderRoute(provider string, r *http.Request, targetURLStr string, model string) error {
	provider = NormalizeProvider(provider)
	if provider == "" {
		return fmt.Errorf("unsupported provider")
	}

	pathProvider := inferProviderFromPath(r.URL.Path)
	if headerProvider := NormalizeProvider(r.Header.Get("X-Provider")); headerProvider != "" &&
		pathProvider != "" &&
		pathProvider != headerProvider &&
		!(headerProvider == ProviderAzureOpenAI && pathProvider == ProviderOpenAI) {
		return fmt.Errorf("X-Provider %q is not compatible with route %q", headerProvider, r.URL.Path)
	}

	if !isModelCompatibleWithProvider(provider, model) {
		return fmt.Errorf("model %q is not compatible with provider %q", model, provider)
	}

	if r.Method != http.MethodPost {
		return nil
	}

	switch provider {
	case ProviderOpenAI:
		if !isOpenAICompatiblePath(r.URL.Path) && !strings.HasPrefix(strings.ToLower(r.URL.Path), "/v1/models") {
			return fmt.Errorf("OpenAI provider requires /v1/chat/completions or /v1/models route")
		}
	case ProviderAnthropic:
		if !strings.HasPrefix(strings.ToLower(r.URL.Path), "/v1/messages") {
			return fmt.Errorf("Anthropic provider requires /v1/messages route")
		}
	case ProviderCohere:
		cleanPath := strings.ToLower(r.URL.Path)
		if !strings.HasPrefix(cleanPath, "/v2/chat") &&
			!strings.HasPrefix(cleanPath, "/v1/chat") &&
			!strings.HasPrefix(cleanPath, "/v1/generate") &&
			!strings.HasPrefix(cleanPath, "/v1/embed") {
			return fmt.Errorf("Cohere provider requires /v2/chat, /v1/chat, /v1/generate, or /v1/embed route")
		}
	case ProviderAzureOpenAI:
		if isAzureDeploymentChatPath(r.URL.Path) || isAzureDeploymentChatPath(targetURLStr) || os.Getenv("AZURE_OPENAI_DEPLOYMENT") != "" {
			return nil
		}
		return fmt.Errorf("Azure OpenAI provider requires a deployment-scoped chat/completions route or AZURE_OPENAI_DEPLOYMENT")
	case ProviderGemini:
		cleanPath := strings.ToLower(r.URL.Path)
		if !strings.Contains(cleanPath, ":generatecontent") && !strings.Contains(cleanPath, ":streamgeneratecontent") {
			return fmt.Errorf("Gemini provider requires a :generateContent or :streamGenerateContent route")
		}
	}
	return nil
}

func ensureAzureAPIVersion(req *http.Request, target *url.URL) {
	if req.URL.Query().Get("api-version") != "" {
		return
	}
	if target != nil && target.Query().Get("api-version") != "" {
		q := req.URL.Query()
		q.Set("api-version", target.Query().Get("api-version"))
		req.URL.RawQuery = q.Encode()
		return
	}
	version := strings.TrimSpace(os.Getenv("AZURE_OPENAI_API_VERSION"))
	if version == "" {
		version = "2024-10-21"
	}
	q := req.URL.Query()
	q.Set("api-version", version)
	req.URL.RawQuery = q.Encode()
}

func ApplyProviderCredential(req *http.Request, provider string, credential *ProviderCredential, tenantID string, target *url.URL) {
	provider = NormalizeProvider(provider)
	switch provider {
	case ProviderGemini:
		req.Header.Del("Authorization")
		geminiKey := ""
		if credential != nil {
			geminiKey = credential.APIKey
		}
		if geminiKey == "" && tenantID == "" {
			geminiKey = os.Getenv("GEMINI_API_KEY")
		}
		if geminiKey != "" {
			req.Header.Set("x-goog-api-key", geminiKey)
		}
	case ProviderAnthropic:
		req.Header.Del("Authorization")
		if credential != nil && credential.APIKey != "" {
			req.Header.Set("x-api-key", credential.APIKey)
			if req.Header.Get("anthropic-version") == "" {
				req.Header.Set("anthropic-version", "2023-06-01")
			}
		}
	case ProviderCohere, ProviderOpenAI:
		req.Header.Del("Authorization")
		if credential != nil && credential.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+credential.APIKey)
		}
	case ProviderAzureOpenAI:
		req.Header.Del("Authorization")
		if credential != nil && credential.APIKey != "" {
			req.Header.Set("api-key", credential.APIKey)
		}
		ensureAzureAPIVersion(req, target)
	}
}
