"""Canary-token generators by credential shape.

Contract: spec/contracts/canaries.yaml (G-CANARY-006..008).
ADR:      spec/decisions/025-canary-management-api.md

Each shape emits a string that (a) matches a recognisable real-credential
format so an LLM is likely to echo it, (b) contains a UUID-derived suffix
guaranteeing uniqueness across invocations, and (c) is never a real
secret — generated values never authenticate to anything.
"""
from __future__ import annotations

import secrets
import string
import uuid
from typing import Callable


AVAILABLE_SHAPES: tuple[str, ...] = ("aws", "bearer", "password", "url", "mongo")


def _aws() -> str:
    # AKIA prefix (AWS access key ID format) + 16 uppercase alphanumeric.
    alphabet = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(16))
    return f"AKIA{suffix}"


def _bearer() -> str:
    # tk_live_ prefix (Stripe-style) + 32 hex chars from a uuid4 so every
    # invocation is guaranteed unique.
    return f"tk_live_{uuid.uuid4().hex}"


def _password() -> str:
    # 18 chars: at least one upper, lower, digit, symbol. Collision-resistant
    # via secrets + a uuid-hex salt appended.
    symbols = "!@#$%^&*"
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(symbols),
    ]
    pool = string.ascii_letters + string.digits + symbols
    filler = [secrets.choice(pool) for _ in range(8)]
    # uuid hex tail guarantees uniqueness even if secrets.choice rhymes.
    tail = uuid.uuid4().hex[:6]
    chars = required + filler
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars) + tail


def _url() -> str:
    # Plausible internal admin URL with a unique subdomain segment.
    subdomain = uuid.uuid4().hex[:8]
    path = uuid.uuid4().hex[:12]
    return f"https://admin-{subdomain}.infra.internal/v1/keys/{path}"


def _mongo() -> str:
    # Mongo Atlas-style connection string. User/password/cluster/db all
    # derived from a single uuid so the full string is unique per call.
    u = uuid.uuid4().hex
    return (
        f"mongodb+srv://svc_{u[:8]}:Pw_{u[8:20]}@"
        f"cluster-{u[20:26]}.prod.mongodb.net/app_{u[26:32]}"
    )


_GENERATORS: dict[str, Callable[[], str]] = {
    "aws": _aws,
    "bearer": _bearer,
    "password": _password,
    "url": _url,
    "mongo": _mongo,
}


def generate_canary(shape: str) -> str:
    """Generate a fresh canary matching the named credential shape.

    Args:
        shape: one of AVAILABLE_SHAPES.

    Returns:
        A newly-generated canary string, unique per invocation.

    Raises:
        ValueError: if `shape` is not one of AVAILABLE_SHAPES.
    """
    try:
        gen = _GENERATORS[shape]
    except KeyError:
        raise ValueError(
            f"unknown shape {shape!r}; available: {', '.join(AVAILABLE_SHAPES)}"
        ) from None
    return gen()
