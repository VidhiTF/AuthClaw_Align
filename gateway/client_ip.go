package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

type clientIPResolver struct {
	trusted []*net.IPNet
	maxHops int
	mode    string
}

var trustedProxyResolutionChangedTotal atomic.Uint64
var trustedProxyComparisonTotal atomic.Uint64
var trustedProxyLegacyMismatchTotal atomic.Uint64

func newClientIPResolverFromEnv() (*clientIPResolver, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("AUTHCLAW_FORWARDED_HEADER_MODE")))
	if mode == "" {
		mode = "off"
	}
	if mode != "off" && mode != "compare" && mode != "enforce" {
		return nil, fmt.Errorf("AUTHCLAW_FORWARDED_HEADER_MODE must be off, compare, or enforce")
	}
	maxHops := 8
	if raw := strings.TrimSpace(os.Getenv("AUTHCLAW_FORWARDED_FOR_MAX_HOPS")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 32 {
			return nil, fmt.Errorf("AUTHCLAW_FORWARDED_FOR_MAX_HOPS must be between 1 and 32")
		}
		maxHops = value
	}
	trusted := make([]*net.IPNet, 0)
	for _, raw := range strings.Split(os.Getenv("AUTHCLAW_TRUSTED_PROXY_CIDRS"), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ip, network, err := net.ParseCIDR(raw)
		if err != nil || !ip.Equal(network.IP) {
			return nil, fmt.Errorf("invalid canonical trusted proxy CIDR %q", raw)
		}
		trusted = append(trusted, network)
	}
	if mode != "off" && len(trusted) == 0 {
		return nil, fmt.Errorf("trusted proxy CIDRs are required when forwarded headers are enabled")
	}
	return &clientIPResolver{trusted: trusted, maxHops: maxHops, mode: mode}, nil
}

func canonicalSocketIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return remoteAddr
	}
	return ip.String()
}

func (resolver *clientIPResolver) trustedIP(ip net.IP) bool {
	for _, network := range resolver.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (resolver *clientIPResolver) resolve(remoteAddr, forwardedFor string) string {
	peer := canonicalSocketIP(remoteAddr)
	proposed := peer
	if resolver.mode == "compare" {
		defer func() {
			legacy := peer
			if forwardedFor != "" {
				legacy = strings.TrimSpace(strings.SplitN(forwardedFor, ",", 2)[0])
			}
			trustedProxyComparisonTotal.Add(1)
			if proposed != legacy {
				trustedProxyLegacyMismatchTotal.Add(1)
			}
		}()
	}
	peerIP := net.ParseIP(peer)
	if resolver.mode == "off" || peerIP == nil || forwardedFor == "" || !resolver.trustedIP(peerIP) {
		return peer
	}
	tokens := strings.Split(forwardedFor, ",")
	if len(tokens) == 0 || len(tokens) > resolver.maxHops {
		return peer
	}
	addresses := make([]net.IP, len(tokens))
	for index, token := range tokens {
		if token == "" || strings.TrimSpace(token) == "" {
			return peer
		}
		addresses[index] = net.ParseIP(strings.TrimSpace(token))
		if addresses[index] == nil {
			return peer
		}
	}
	proposed = addresses[0].String()
	for index := len(addresses) - 1; index >= 0; index-- {
		if !resolver.trustedIP(addresses[index]) {
			proposed = addresses[index].String()
			break
		}
	}
	if proposed != peer {
		trustedProxyResolutionChangedTotal.Add(1)
	}
	if resolver.mode == "enforce" {
		return proposed
	}
	return peer
}

func resolvedClientIP(r *http.Request) string {
	resolver, err := newClientIPResolverFromEnv()
	if err != nil {
		return canonicalSocketIP(r.RemoteAddr)
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 {
		return canonicalSocketIP(r.RemoteAddr)
	}
	return resolver.resolve(r.RemoteAddr, values[0])
}
