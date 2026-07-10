package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyServerRouting(t *testing.T) {
	// 1. Create mock OpenAI server
	openaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"provider": "openai", "path": "` + r.URL.Path + `"}`))
	}))
	defer openaiServer.Close()

	// 2. Create mock Anthropic server
	anthropicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"provider": "anthropic", "path": "` + r.URL.Path + `"}`))
	}))
	defer anthropicServer.Close()

	// 3. Create mock Gemini server
	geminiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"provider": "gemini", "path": "` + r.URL.Path + `"}`))
	}))
	defer geminiServer.Close()

	cohereServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"provider": "cohere", "path": "` + r.URL.Path + `"}`))
	}))
	defer cohereServer.Close()

	azureServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"provider": "azure_openai", "path": "` + r.URL.Path + `"}`))
	}))
	defer azureServer.Close()

	// 4. Create ProxyServer pointing to mock servers
	proxy := NewProxyServer()
	proxy.OpenAIBaseURL = openaiServer.URL
	proxy.AnthropicBaseURL = anthropicServer.URL
	proxy.GeminiBaseURL = geminiServer.URL
	proxy.CohereBaseURL = cohereServer.URL
	proxy.AzureOpenAIBaseURL = azureServer.URL

	// 5. Test OpenAI routing
	reqOpenAI := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	wOpenAI := httptest.NewRecorder()
	proxy.ServeHTTP(wOpenAI, reqOpenAI)

	respOpenAI := wOpenAI.Result()
	bodyOpenAI, _ := io.ReadAll(respOpenAI.Body)
	if !strings.Contains(string(bodyOpenAI), `"provider": "openai"`) {
		t.Errorf("Expected OpenAI routing, got response: %s", string(bodyOpenAI))
	}

	// 6. Test Anthropic routing
	reqAnthropic := httptest.NewRequest("POST", "/v1/messages", strings.NewReader(`{}`))
	wAnthropic := httptest.NewRecorder()
	proxy.ServeHTTP(wAnthropic, reqAnthropic)

	respAnthropic := wAnthropic.Result()
	bodyAnthropic, _ := io.ReadAll(respAnthropic.Body)
	if !strings.Contains(string(bodyAnthropic), `"provider": "anthropic"`) {
		t.Errorf("Expected Anthropic routing, got response: %s", string(bodyAnthropic))
	}

	// 7. Test Gemini routing via path
	reqGeminiPath := httptest.NewRequest("POST", "/v1/models/gemini-1.5-pro:generateContent", strings.NewReader(`{}`))
	wGeminiPath := httptest.NewRecorder()
	proxy.ServeHTTP(wGeminiPath, reqGeminiPath)

	respGeminiPath := wGeminiPath.Result()
	bodyGeminiPath, _ := io.ReadAll(respGeminiPath.Body)
	if !strings.Contains(string(bodyGeminiPath), `"provider": "gemini"`) {
		t.Errorf("Expected Gemini routing via path, got response: %s", string(bodyGeminiPath))
	}

	// 8. Test Gemini routing via X-Provider header
	reqGeminiHeader := httptest.NewRequest("POST", "/v1/models/gemini-1.5-pro:generateContent", strings.NewReader(`{}`))
	reqGeminiHeader.Header.Set("X-Provider", "gemini")
	wGeminiHeader := httptest.NewRecorder()
	proxy.ServeHTTP(wGeminiHeader, reqGeminiHeader)

	respGeminiHeader := wGeminiHeader.Result()
	bodyGeminiHeader, _ := io.ReadAll(respGeminiHeader.Body)
	if !strings.Contains(string(bodyGeminiHeader), `"provider": "gemini"`) {
		t.Errorf("Expected Gemini routing via X-Provider header, got response: %s", string(bodyGeminiHeader))
	}

	reqCohere := httptest.NewRequest("POST", "/v2/chat", strings.NewReader(`{"model":"command-r","messages":[{"role":"user","content":"Hi"}]}`))
	wCohere := httptest.NewRecorder()
	proxy.ServeHTTP(wCohere, reqCohere)

	respCohere := wCohere.Result()
	bodyCohere, _ := io.ReadAll(respCohere.Body)
	if !strings.Contains(string(bodyCohere), `"provider": "cohere"`) {
		t.Errorf("Expected Cohere routing, got response: %s", string(bodyCohere))
	}

	reqAzure := httptest.NewRequest("POST", "/openai/deployments/customer-gpt4/chat/completions?api-version=2024-10-21", strings.NewReader(`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`))
	reqAzure.Header.Set("X-Provider", "azure_openai")
	wAzure := httptest.NewRecorder()
	proxy.ServeHTTP(wAzure, reqAzure)

	respAzure := wAzure.Result()
	bodyAzure, _ := io.ReadAll(respAzure.Body)
	if !strings.Contains(string(bodyAzure), `"provider": "azure_openai"`) {
		t.Errorf("Expected Azure OpenAI routing, got response: %s", string(bodyAzure))
	}
}
