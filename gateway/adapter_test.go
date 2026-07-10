package main

import (
	"net/http"
	"strings"
	"testing"
)

func assertRebuiltContains(t *testing.T, rebuilder func([]string) ([]byte, error), provider string, prompts []string, want string) {
	t.Helper()
	newBodyBytes, err := rebuilder(prompts)
	if err != nil {
		t.Fatalf("Failed to rebuild %s request: %v", provider, err)
	}
	if !strings.Contains(string(newBodyBytes), want) {
		t.Errorf("Rebuilt %s body does not contain %s: %s", provider, want, string(newBodyBytes))
	}
}

func TestExtractAndNormalizeOpenAI(t *testing.T) {
	jsonBody := `{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "Hello, my email is test@example.com"},
			{"role": "assistant", "content": "How can I help you today?"}
		]
	}`

	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(jsonBody))
	normalized, rebuilder, err := ExtractAndNormalize(req, "openai")
	if err != nil {
		t.Fatalf("Failed to normalize OpenAI request: %v", err)
	}

	if normalized.Model != "gpt-4" {
		t.Errorf("Expected model gpt-4, got %s", normalized.Model)
	}

	if len(normalized.Prompts) != 2 {
		t.Fatalf("Expected 2 prompts, got %d", len(normalized.Prompts))
	}

	if normalized.Prompts[0] != "Hello, my email is test@example.com" {
		t.Errorf("Expected first prompt content, got: %s", normalized.Prompts[0])
	}

	assertRebuiltContains(t, rebuilder, "OpenAI", []string{"Hello, my email is [REDACTED]", "How can I help you today?"}, "[REDACTED]")
}

func TestExtractAndNormalizeAnthropic(t *testing.T) {
	jsonBody := `{
		"model": "claude-3-opus",
		"system": "You are a helpful assistant.",
		"messages": [
			{"role": "user", "content": "My phone number is 123-456-7890"}
		]
	}`

	req, _ := http.NewRequest("POST", "/v1/messages", strings.NewReader(jsonBody))
	normalized, rebuilder, err := ExtractAndNormalize(req, "anthropic")
	if err != nil {
		t.Fatalf("Failed to normalize Anthropic request: %v", err)
	}

	if normalized.Model != "claude-3-opus" {
		t.Errorf("Expected model claude-3-opus, got %s", normalized.Model)
	}

	// System prompt + 1 message = 2 prompts
	if len(normalized.Prompts) != 2 {
		t.Fatalf("Expected 2 prompts, got %d", len(normalized.Prompts))
	}

	if normalized.Prompts[0] != "You are a helpful assistant." {
		t.Errorf("Expected system prompt, got: %s", normalized.Prompts[0])
	}

	assertRebuiltContains(t, rebuilder, "Anthropic", []string{"You are a helpful assistant.", "My phone number is [REDACTED]"}, "[REDACTED]")
}

func TestExtractAndNormalizeGemini(t *testing.T) {
	jsonBody := `{
		"contents": [
			{
				"role": "user",
				"parts": [
					{"text": "Hello, my phone is 555-123-4567"}
				]
			}
		]
	}`

	req, _ := http.NewRequest("POST", "/v1/models/gemini-1.5-flash:generateContent", strings.NewReader(jsonBody))
	normalized, rebuilder, err := ExtractAndNormalize(req, "gemini")
	if err != nil {
		t.Fatalf("Failed to normalize Gemini request: %v", err)
	}

	if normalized.Model != "gemini-1.5-flash" {
		t.Errorf("Expected model gemini-1.5-flash, got %s", normalized.Model)
	}

	if len(normalized.Prompts) != 1 {
		t.Fatalf("Expected 1 prompt, got %d", len(normalized.Prompts))
	}

	if normalized.Prompts[0] != "Hello, my phone is 555-123-4567" {
		t.Errorf("Expected prompt content, got: %s", normalized.Prompts[0])
	}

	assertRebuiltContains(t, rebuilder, "Gemini", []string{"Hello, my phone is [REDACTED]"}, "[REDACTED]")
}

func TestExtractAndNormalizeCohereV2Chat(t *testing.T) {
	jsonBody := `{
		"model": "command-r-plus",
		"messages": [
			{"role": "system", "content": "Keep answers concise."},
			{"role": "user", "content": [{"type": "text", "text": "My email is test@example.com"}]}
		]
	}`

	req, _ := http.NewRequest("POST", "/v2/chat", strings.NewReader(jsonBody))
	normalized, rebuilder, err := ExtractAndNormalize(req, "cohere")
	if err != nil {
		t.Fatalf("Failed to normalize Cohere request: %v", err)
	}
	if normalized.Model != "command-r-plus" {
		t.Fatalf("Expected model command-r-plus, got %s", normalized.Model)
	}
	if len(normalized.Prompts) != 2 {
		t.Fatalf("Expected 2 prompts, got %d", len(normalized.Prompts))
	}
	if normalized.Prompts[1] != "My email is test@example.com" {
		t.Fatalf("Expected Cohere text block prompt, got %q", normalized.Prompts[1])
	}

	assertRebuiltContains(t, rebuilder, "Cohere", []string{"Keep answers concise.", "My email is [REDACTED]"}, "[REDACTED]")
}

func TestExtractAndNormalizeAzureOpenAIUsesDeploymentWhenModelMissing(t *testing.T) {
	jsonBody := `{
		"messages": [
			{"role": "user", "content": "My phone number is 555-123-4567"}
		]
	}`

	req, _ := http.NewRequest("POST", "/openai/deployments/customer-gpt4/chat/completions", strings.NewReader(jsonBody))
	normalized, rebuilder, err := ExtractAndNormalize(req, "azure_openai")
	if err != nil {
		t.Fatalf("Failed to normalize Azure OpenAI request: %v", err)
	}
	if normalized.Model != "customer-gpt4" {
		t.Fatalf("Expected deployment model customer-gpt4, got %s", normalized.Model)
	}
	if len(normalized.Prompts) != 1 || normalized.Prompts[0] != "My phone number is 555-123-4567" {
		t.Fatalf("Unexpected prompts: %#v", normalized.Prompts)
	}

	assertRebuiltContains(t, rebuilder, "Azure OpenAI", []string{"My phone number is [REDACTED]"}, "[REDACTED]")
}
