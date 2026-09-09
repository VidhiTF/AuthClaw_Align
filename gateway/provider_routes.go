package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed provider_contracts.json
var providerContractJSON []byte

type gatewayProviderContract struct {
	Status         string `json:"status"`
	Endpoint       string `json:"endpoint"`
	GatewayMethod  string `json:"gateway_method"`
	GatewayPattern string `json:"gateway_pattern"`
}

type gatewayProviderManifest struct {
	Providers map[string]gatewayProviderContract `json:"providers"`
}

type gatewayProviderRoute struct {
	Method  string
	Pattern string
}

func configuredProviderRoutes() ([]gatewayProviderRoute, error) {
	var manifest gatewayProviderManifest
	if err := json.Unmarshal(providerContractJSON, &manifest); err != nil {
		return nil, fmt.Errorf("parse embedded provider contracts: %w", err)
	}
	if len(manifest.Providers) == 0 {
		return nil, fmt.Errorf("provider contract manifest is empty")
	}

	unique := make(map[string]gatewayProviderRoute)
	for provider, contract := range manifest.Providers {
		method := strings.ToUpper(strings.TrimSpace(contract.GatewayMethod))
		pattern := strings.TrimSpace(contract.GatewayPattern)
		if method == "" || pattern == "" || !strings.HasPrefix(pattern, "/") {
			return nil, fmt.Errorf("provider %s has an invalid gateway route", provider)
		}
		key := method + " " + pattern
		unique[key] = gatewayProviderRoute{Method: method, Pattern: pattern}
	}

	routes := make([]gatewayProviderRoute, 0, len(unique))
	for _, route := range unique {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Pattern == routes[j].Pattern {
			return routes[i].Method < routes[j].Method
		}
		return routes[i].Pattern < routes[j].Pattern
	})
	return routes, nil
}
