package main

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type providerContractManifest struct {
	ContractVersion string                             `json:"contract_version"`
	Providers       map[string]providerContractDetails `json:"providers"`
}

type providerContractDetails struct {
	Status         string `json:"status"`
	LastReviewed   string `json:"last_reviewed"`
	Endpoint       string `json:"endpoint"`
	PayloadShape   string `json:"payload_shape"`
	StreamShape    string `json:"stream_shape"`
	GatewayMethod  string `json:"gateway_method"`
	GatewayPattern string `json:"gateway_pattern"`
}

func loadProviderContractManifest(t *testing.T) providerContractManifest {
	t.Helper()
	data, err := os.ReadFile("provider_contracts.json")
	if err != nil {
		t.Fatalf("read provider contract manifest: %v", err)
	}
	var manifest providerContractManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse provider contract manifest: %v", err)
	}
	return manifest
}

func TestProviderContractManifestDriftGate(t *testing.T) {
	manifest := loadProviderContractManifest(t)
	if manifest.ContractVersion == "" {
		t.Fatal("contract_version is required")
	}
	required := []string{"openai", "anthropic", "cohere", "azure_openai", "gemini", "bedrock"}
	for _, provider := range required {
		contract, ok := manifest.Providers[provider]
		if !ok {
			t.Fatalf("missing SRS provider contract %q", provider)
		}
		if contract.Status == "" {
			t.Fatalf("%s contract must declare status", provider)
		}
		if contract.Endpoint == "" || contract.PayloadShape == "" || contract.StreamShape == "" || contract.GatewayMethod == "" || contract.GatewayPattern == "" {
			t.Fatalf("%s contract must declare endpoint, payload, stream, and gateway route fields", provider)
		}
		if _, err := time.Parse(time.DateOnly, contract.LastReviewed); err != nil {
			t.Fatalf("%s last_reviewed must be YYYY-MM-DD: %v", provider, err)
		}
	}
	for _, provider := range []string{"openai", "anthropic", "cohere", "azure_openai"} {
		if manifest.Providers[provider].Status != "production-ready" {
			t.Fatalf("%s contract must remain production-ready", provider)
		}
	}
	if manifest.Providers["gemini"].Status != "validated" {
		t.Fatal("gemini contract must remain validated")
	}
	if manifest.Providers["bedrock"].Status != "feature-gated" {
		t.Fatal("bedrock contract must remain feature-gated")
	}
}
