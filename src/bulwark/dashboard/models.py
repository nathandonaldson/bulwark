"""Pydantic models for the Bulwark HTTP API (v2).

Hand-written to match spec/openapi.yaml. The test_spec_compliance.py
meta-test validates they agree.

v2.0.0 (ADR-031): LLM models removed. CleanResponse slimmed (no analysis/
execution/llm_mode).
"""
from __future__ import annotations

import os
from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


# ADR-042 / G-HTTP-CLEAN-CONTENT-BYTES-001: sentinel string the
# RequestValidationError handler in app.py looks for when mapping a
# Pydantic ValueError into HTTP 413. Kept in one place so the model and
# the handler agree without importing app.py from models.py (which would
# create a cycle).
CONTENT_BYTE_LIMIT_SENTINEL = "content_exceeds_byte_limit"


# G-HTTP-GUARD-009 / ADR-030: per-entry caps for user-supplied canary tokens.
_CanarySourceName = Annotated[str, Field(min_length=1, max_length=64)]
_CanaryTokenValue = Annotated[str, Field(min_length=1, max_length=256)]


# B2 / ADR-038: default body cap is 256KB. Tunable via BULWARK_MAX_CONTENT_SIZE
# (bytes). The previous 1MB default was a defense-in-depth gap — combined with
# a slow tokenizer or judge round-trip, even authenticated callers could
# pin a worker for tens of seconds per request. 256KB covers realistic
# email/document inputs while raising the floor on resource exhaustion.
def _default_max_content_size() -> int:
    raw = os.environ.get("BULWARK_MAX_CONTENT_SIZE", "262144")
    try:
        n = int(raw)
        if n <= 0:
            return 262144
        return n
    except (TypeError, ValueError):
        return 262144


MAX_CONTENT_SIZE = _default_max_content_size()


class CleanRequest(BaseModel):
    """Request body for POST /v1/clean."""
    content: str = Field(
        ...,
        description=(
            "Untrusted text to process through the defense stack. "
            "Server enforces a UTF-8 byte cap (default 262144 bytes; see "
            "BULWARK_MAX_CONTENT_SIZE). Over-cap requests get HTTP 413 "
            "content_too_large. ADR-042 / G-HTTP-CLEAN-CONTENT-BYTES-001."
        ),
    )
    source: str = Field(
        default="external",
        description="Where the content came from. Used in the trust boundary tag name.",
    )
    label: Optional[str] = Field(
        default=None,
        description="Optional label for the trust boundary tag name.",
    )
    max_length: Optional[int] = Field(
        default=None,
        ge=1,
        description="Truncate content after sanitizing. null = no limit (default).",
    )
    format: Literal["xml", "markdown", "delimiter"] = Field(
        default="xml",
        description='Trust boundary format. "xml" (default), "markdown", or "delimiter".',
    )

    @field_validator("content")
    @classmethod
    def _content_byte_limit(cls, v: str) -> str:
        """ADR-042 / G-HTTP-CLEAN-CONTENT-BYTES-001: enforce the cap on
        UTF-8 *bytes*, not Python characters. Pydantic's ``max_length``
        measures ``len(str)`` and so a 4-byte-per-char UTF-8 payload
        could exceed ``MAX_CONTENT_SIZE`` bytes by up to 4x. The
        ``RequestValidationError`` handler in ``dashboard.app`` maps
        this sentinel-tagged ValueError into HTTP 413.
        """
        if len(v.encode("utf-8")) > MAX_CONTENT_SIZE:
            raise ValueError(CONTENT_BYTE_LIMIT_SENTINEL)
        return v


class CleanResponse(BaseModel):
    """Response body for POST /v1/clean (200 OK)."""
    result: str = Field(..., description="Sanitized content wrapped in trust boundary tags.")
    blocked: bool = Field(default=False)
    source: str = Field(...)
    format: str = Field(...)
    content_length: int = Field(...)
    result_length: int = Field(...)
    modified: bool = Field(...)
    trace: list[dict[str, Any]] = Field(default_factory=list)
    detector: Optional[dict[str, Any]] = Field(
        default=None,
        description="Detector verdict (label, score) when the model is loaded.",
    )
    mode: Optional[Literal["degraded-explicit"]] = Field(
        default=None,
        description=(
            "Set to 'degraded-explicit' when BULWARK_ALLOW_NO_DETECTORS=1 "
            "and the request was served sanitize-only with zero detectors "
            "available. Absent in normal (defended) responses. See ADR-040."
        ),
    )


class RetestRequest(BaseModel):
    """Request body for POST /api/redteam/retest."""
    filename: str = Field(..., description="Filename of the report to retest.")


class GuardRequest(BaseModel):
    """Request body for POST /v1/guard."""
    text: str = Field(
        ...,
        description=(
            "LLM output to check for injection patterns and canary leaks. "
            "Server enforces the same UTF-8 byte cap as /v1/clean "
            "(ADR-042). Over-cap requests get HTTP 413 content_too_large."
        ),
    )
    canary_tokens: Optional[dict[_CanarySourceName, _CanaryTokenValue]] = Field(
        default=None,
        max_length=64,
        description="Optional map of source_name to canary token. If null, server-configured canaries are used.",
    )

    @field_validator("text")
    @classmethod
    def _text_byte_limit(cls, v: str) -> str:
        """ADR-042: byte-cap parity with CleanRequest.content."""
        if len(v.encode("utf-8")) > MAX_CONTENT_SIZE:
            raise ValueError(CONTENT_BYTE_LIMIT_SENTINEL)
        return v


class GuardResponse(BaseModel):
    """Response body for POST /v1/guard."""
    safe: bool = Field(...)
    text: str = Field(...)
    reason: Optional[str] = Field(default=None)
    check: Optional[Literal["injection", "canary"]] = Field(default=None)


class CanaryUpsertRequest(BaseModel):
    """Request body for POST /api/canaries.

    Length bounds and cross-field rules are enforced in the handler so
    the API returns 400 per spec.
    """
    label: str = Field(..., description="Source identifier.")
    token: Optional[str] = Field(default=None, description="Literal canary string; min 8 chars.")
    shape: Optional[str] = Field(default=None, description="Generate a canary matching this credential format.")
