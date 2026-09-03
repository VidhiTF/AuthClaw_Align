package main

import "testing"

func resolver(t *testing.T, mode string, maxHops int, cidrs ...string) *clientIPResolver {
	t.Helper()
	t.Setenv("AUTHCLAW_FORWARDED_HEADER_MODE", mode)
	t.Setenv("AUTHCLAW_FORWARDED_FOR_MAX_HOPS", "8")
	if maxHops == 2 {
		t.Setenv("AUTHCLAW_FORWARDED_FOR_MAX_HOPS", "2")
	}
	value := ""
	for index, cidr := range cidrs {
		if index > 0 {
			value += ","
		}
		value += cidr
	}
	t.Setenv("AUTHCLAW_TRUSTED_PROXY_CIDRS", value)
	result, err := newClientIPResolverFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestClientIPDirectPeerIgnoresForgedHeader(t *testing.T) {
	got := resolver(t, "enforce", 8, "10.0.0.0/24").resolve("203.0.113.7:443", "198.51.100.9")
	if got != "203.0.113.7" { t.Fatalf("got %q", got) }
}

func TestClientIPTrustedProxyScansRightToLeft(t *testing.T) {
	got := resolver(t, "enforce", 8, "10.0.0.0/24").resolve(
		"10.0.0.4:443", "192.0.2.66, 198.51.100.9, 10.0.0.8")
	if got != "198.51.100.9" { t.Fatalf("got %q", got) }
}

func TestClientIPMalformedAndOverlongChainsFallBack(t *testing.T) {
	for _, header := range []string{"garbage", "198.51.100.9:443", "[2001:db8::1]:443", "198.51.100.9,", "192.0.2.1,198.51.100.2,203.0.113.3"} {
		got := resolver(t, "enforce", 2, "10.0.0.0/24").resolve("10.0.0.4:443", header)
		if got != "10.0.0.4" { t.Fatalf("header %q got %q", header, got) }
	}
}

func TestClientIPSupportsCanonicalIPv6AndCompareMode(t *testing.T) {
	got := resolver(t, "enforce", 8, "2001:db8:1::/64").resolve("[2001:db8:1::1]:443", "2001:DB8:2::1")
	if got != "2001:db8:2::1" { t.Fatalf("got %q", got) }
	got = resolver(t, "compare", 8, "10.0.0.0/24").resolve("10.0.0.4:443", "198.51.100.9")
	if got != "10.0.0.4" { t.Fatalf("compare mode enforced proposed address: %q", got) }
}

func TestClientIPConfigurationRequiresCanonicalCIDRs(t *testing.T) {
	t.Setenv("AUTHCLAW_FORWARDED_HEADER_MODE", "enforce")
	t.Setenv("AUTHCLAW_TRUSTED_PROXY_CIDRS", "10.0.0.1/24")
	if _, err := newClientIPResolverFromEnv(); err == nil { t.Fatal("expected invalid non-canonical CIDR") }
}
