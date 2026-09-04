"""Trusted-proxy client address resolution for ASGI requests."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Iterable

from app.services import event_backbone

_VALID_MODES = {"off", "compare", "enforce"}


@dataclass(frozen=True)
class ClientIPConfig:
    trusted_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    max_hops: int
    mode: str

    @classmethod
    def from_environment(cls) -> "ClientIPConfig":
        mode = os.getenv("AUTHCLAW_FORWARDED_HEADER_MODE", "off").strip().lower()
        if mode not in _VALID_MODES:
            raise ValueError(
                "AUTHCLAW_FORWARDED_HEADER_MODE must be off, compare, or enforce"
            )
        try:
            max_hops = int(os.getenv("AUTHCLAW_FORWARDED_FOR_MAX_HOPS", "8"))
        except ValueError as exc:
            raise ValueError(
                "AUTHCLAW_FORWARDED_FOR_MAX_HOPS must be an integer"
            ) from exc
        if not 1 <= max_hops <= 32:
            raise ValueError("AUTHCLAW_FORWARDED_FOR_MAX_HOPS must be between 1 and 32")
        networks = []
        for value in os.getenv("AUTHCLAW_TRUSTED_PROXY_CIDRS", "").split(","):
            if value.strip():
                networks.append(ipaddress.ip_network(value.strip(), strict=True))
        if mode != "off" and not networks:
            raise ValueError(
                "trusted proxy CIDRs are required when forwarded headers are enabled"
            )
        return cls(tuple(networks), max_hops, mode)


def _canonical_ip(value: str) -> str:
    if "%" in value:
        raise ValueError("scoped addresses are not forwarded identities")
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.compressed
    return address.compressed


Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _is_trusted(value: str, networks: Iterable[Network]) -> bool:
    address = ipaddress.ip_address(value)
    return any(
        address.version == network.version and address in network
        for network in networks
    )


def resolve_client_ip(peer: str, forwarded_for: str, config: ClientIPConfig) -> str:
    """Return a canonical client IP, falling back to the socket peer on any invalid chain."""
    try:
        canonical_peer = _canonical_ip(peer)
    except ValueError:
        return peer
    if config.mode == "off" or not forwarded_for:
        return canonical_peer
    try:
        if not _is_trusted(canonical_peer, config.trusted_networks):
            return canonical_peer
        tokens = forwarded_for.split(",")
        if (
            not tokens
            or len(tokens) > config.max_hops
            or any(not token.strip() for token in tokens)
        ):
            return canonical_peer
        addresses = [_canonical_ip(token) for token in tokens]
    except ValueError:
        return canonical_peer
    for address in reversed(addresses):
        if not _is_trusted(address, config.trusted_networks):
            return address
    return addresses[0]


class TrustedProxyMiddleware:
    """Resolve the client at the outer ASGI boundary before authentication and routing."""

    def __init__(self, app, config: ClientIPConfig | None = None):
        self.app = app
        self.config = config or ClientIPConfig.from_environment()

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http" and scope.get("client"):
            peer, port = scope["client"]
            forwarded_values = [
                value.decode("latin-1")
                for key, value in scope.get("headers", [])
                if key.decode("latin-1").lower() == "x-forwarded-for"
            ]
            forwarded_for = forwarded_values[0] if len(forwarded_values) == 1 else ","
            proposed = resolve_client_ip(peer, forwarded_for, self.config)
            if self.config.mode == "compare":
                legacy = (
                    forwarded_values[0].split(",", 1)[0].strip()
                    if forwarded_values and forwarded_values[0]
                    else peer
                )
                event_backbone.increment_metric("trusted_proxy_comparison_total")
                if proposed != legacy:
                    event_backbone.increment_metric(
                        "trusted_proxy_legacy_mismatch_total"
                    )
            if proposed != peer:
                event_backbone.increment_metric(
                    "trusted_proxy_resolution_changed_total"
                )
            if self.config.mode == "enforce":
                scope["client"] = (proposed, port)
        await self.app(scope, receive, send)
