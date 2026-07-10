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
	Status       string `json:"status"`
	LastReviewed string `json:"last_reviewed"`
	Endpoint     string `json:"endpoint"`
	PayloadShape string `json:"payload_shape"`
	StreamShape  string `json:"stream_shape"`
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
	required := []string{"openai", "anthropic", "cohere", "azure_openai"}
	for _, provider := range required {
		contract, ok := manifest.Providers[provider]
		if !ok {
			t.Fatalf("missing SRS provider contract %q", provider)
		}
		if contract.Status != "production-ready" {
			t.Fatalf("%s contract must be production-ready, got %q", provider, contract.Status)
		}
		if contract.Endpoint == "" || contract.PayloadShape == "" || contract.StreamShape == "" {
			t.Fatalf("%s contract must declare endpoint, payload_shape, and stream_shape", provider)
		}
		if _, err := time.Parse(time.DateOnly, contract.LastReviewed); err != nil {
			t.Fatalf("%s last_reviewed must be YYYY-MM-DD: %v", provider, err)
		}
	}
}
