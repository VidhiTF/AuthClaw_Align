import ipaddress

import pytest

from app.core.client_ip import ClientIPConfig, resolve_client_ip


def config(*cidrs: str, max_hops: int = 8, mode: str = "enforce") -> ClientIPConfig:
    return ClientIPConfig(tuple(ipaddress.ip_network(cidr) for cidr in cidrs), max_hops, mode)


def test_direct_client_ignores_forwarded_header():
    assert resolve_client_ip("203.0.113.7", "198.51.100.9", config("10.0.0.0/24")) == "203.0.113.7"


def test_trusted_proxy_resolves_one_client():
    assert resolve_client_ip("10.0.0.4", "198.51.100.9", config("10.0.0.0/24")) == "198.51.100.9"


def test_right_to_left_resolution_ignores_attacker_leftmost_value():
    value = resolve_client_ip(
        "10.0.0.4", "192.0.2.66, 198.51.100.9, 10.0.0.8", config("10.0.0.0/24")
    )
    assert value == "198.51.100.9"


@pytest.mark.parametrize(
    "header",
    ["", "garbage", "198.51.100.9:443", "[2001:db8::1]:443", "198.51.100.9,", ",198.51.100.9"],
)
def test_invalid_chain_falls_back_to_peer(header):
    assert resolve_client_ip("10.0.0.4", header, config("10.0.0.0/24")) == "10.0.0.4"


def test_ipv6_is_canonicalized_and_overlong_chain_is_rejected():
    cfg = config("2001:db8:1::/64", max_hops=2)
    assert resolve_client_ip("2001:db8:1::1", "2001:DB8:2:0::1", cfg) == "2001:db8:2::1"
    assert resolve_client_ip("2001:db8:1::1", "192.0.2.1,198.51.100.2,203.0.113.3", cfg) == "2001:db8:1::1"


def test_all_trusted_hops_uses_leftmost_address():
    assert resolve_client_ip("10.0.0.4", "10.0.0.5, 10.0.0.6", config("10.0.0.0/24")) == "10.0.0.5"


def test_environment_validation_requires_explicit_cidrs(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_FORWARDED_HEADER_MODE", "enforce")
    monkeypatch.delenv("AUTHCLAW_TRUSTED_PROXY_CIDRS", raising=False)
    with pytest.raises(ValueError):
        ClientIPConfig.from_environment()
