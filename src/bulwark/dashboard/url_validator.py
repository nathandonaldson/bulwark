"""URL validation for SSRF defense.

Used by webhook_url config validation (G-WEBHOOK-007, ADR-030). Returns a
string error message when the URL targets a private/loopback/metadata host,
or None when the URL is considered external.
"""
from __future__ import annotations

import ipaddress
import os
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


def validate_external_url(url: str) -> Optional[str]:
    """Return an error string if the URL targets a private host, else None.

    - Scheme must be http or https.
    - Host must not be empty.
    - Literal private/loopback/link-local/metadata IPs are rejected.
    - Private hostnames resolve via allowlist (BULWARK_ALLOWED_HOSTS + defaults).
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
    # Check literal IP
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return f"host {host} is a private/loopback/link-local address"
        # Cloud metadata service
        if str(ip) == "169.254.169.254":
            return "host 169.254.169.254 is the cloud metadata service"
    return None
