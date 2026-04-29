"""URL validation for SSRF defense.

Used by webhook_url config validation (G-WEBHOOK-007, ADR-030). Returns a
string error message when the URL targets a private/loopback/metadata host,
or None when the URL is considered external.

ADR-038 / B3: hostnames are resolved via getaddrinfo and every resolved IP
is checked against the same private/loopback/link-local/metadata blacklist
applied to literal IPs. A hostname that resolves to a private IP is now
rejected, closing the gap where `evil.com` resolving to 127.0.0.1 used to
pass validation.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import time
from typing import Optional
from urllib.parse import urlparse


# Operators can widen the allowlist for LAN-attached services (e.g. a
# self-hosted webhook receiver). Comma-separated hostnames in the env var
# BULWARK_ALLOWED_HOSTS bypass the private-address block. See ADR-015.
def _allowed_hosts() -> set[str]:
    raw = os.environ.get("BULWARK_ALLOWED_HOSTS", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


# Hosts always permitted — needed for local dashboard + Docker networking.
_ALWAYS_ALLOWED = {"localhost", "host.docker.internal"}

# Cloud metadata services we always block, even if they're reachable.
_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}

# DNS resolution cache: host -> (set of IP strings, expiry epoch seconds).
# Avoids DNS amplification when the same URL is validated repeatedly.
# Validation runs at config-write AND on every blocked-event webhook fire
# (api_v1._fire_webhook), so the cache hit rate matters. With one webhook
# URL the cache stays at size <= 2 in practice.
# NOTE: Bulwark does NOT pass the validated IP into httpx — the actual
# webhook POST does its own DNS lookup at fire time. See NG-WEBHOOK-006
# for the residual TOCTOU and how operators mitigate it.
_RESOLUTION_CACHE: dict[str, tuple[set[str], float]] = {}
_RESOLUTION_TTL = 60.0


def _resolve_host(host: str) -> set[str]:
    """Return all IPs `host` resolves to, cached for 60s.

    Raises socket.gaierror on resolution failure.
    """
    now = time.time()
    cached = _RESOLUTION_CACHE.get(host)
    if cached and cached[1] > now:
        return cached[0]
    addrs = socket.getaddrinfo(host, None)
    ips = {info[4][0] for info in addrs}
    _RESOLUTION_CACHE[host] = (ips, now + _RESOLUTION_TTL)
    return ips


def _ip_is_blocked(ip: ipaddress._BaseAddress) -> Optional[str]:
    """Return a reason string if the IP is private/loopback/metadata, else None."""
    if str(ip) in _METADATA_IPS:
        return f"host {ip} is the cloud metadata service"
    if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return f"host {ip} is a private/loopback/link-local address"
    return None


def validate_external_url(url: str) -> Optional[str]:
    """Return an error string if the URL targets a private host, else None.

    - Scheme must be http or https.
    - Host must not be empty.
    - Literal private/loopback/link-local/metadata IPs are rejected.
    - Hostnames are resolved (getaddrinfo) and EVERY resolved IP is
      checked. A hostname that resolves to a private IP is rejected.
    - Hosts in _ALWAYS_ALLOWED or BULWARK_ALLOWED_HOSTS skip the resolve
      step; operators who self-host are responsible for them.
    """
    if not url:
        return None  # empty = no webhook; caller decides
    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return f"unparseable URL: {exc}"
    if parsed.scheme not in ("http", "https"):
        return f"scheme {parsed.scheme!r} not allowed (must be http or https)"
    host = (parsed.hostname or "").lower()
    if not host:
        return "no host in URL"
    if host in _ALWAYS_ALLOWED or host in _allowed_hosts():
        return None
    # Literal IP path — straight check, no resolution.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return _ip_is_blocked(ip)
    # Hostname path — resolve and check every IP. ADR-038 / B3.
    try:
        resolved = _resolve_host(host)
    except socket.gaierror as exc:
        # Unresolvable host: reject so we don't pass through to runtime
        # where a later resolution could land on a private IP.
        return f"could not resolve host {host}: {exc}"
    for ip_str in resolved:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        reason = _ip_is_blocked(ip_obj)
        if reason:
            return f"host {host} resolves to {ip_str}, which is blocked ({reason})"
    return None
