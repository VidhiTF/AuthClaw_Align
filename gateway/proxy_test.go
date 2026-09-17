package main

import (
	"net/http/httptest"
	"testing"
)

// Routing characterization does not pretend an unauthenticated request may execute a model.
func TestProxyServerRouting(t *testing.T) {
	proxy := &ProxyServer{OpenAIBaseURL: "https://openai.test", AnthropicBaseURL: "https://anthropic.test", GeminiBaseURL: "https://gemini.test", CohereBaseURL: "https://cohere.test", AzureOpenAIBaseURL: "https://azure.test"}
	for _, tc := range []struct{ path, provider, want string }{
		{"/v1/chat/completions", "", "https://openai.test"},
		{"/v1/messages", "", "https://anthropic.test"},
		{"/v1/models/gemini-1.5-pro:generateContent", "", "https://gemini.test"},
		{"/v1/models/gemini-1.5-pro:generateContent", "gemini", "https://gemini.test"},
		{"/v2/chat", "", "https://cohere.test"},
		{"/openai/deployments/customer-gpt4/chat/completions?api-version=2024-10-21", "azure_openai", "https://azure.test"},
	} {
		request := httptest.NewRequest("POST", tc.path, nil)
		request.Header.Set("X-Provider", tc.provider)
		if got := proxy.RouteRequest(request); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.path, got, tc.want)
		}
	}
}
