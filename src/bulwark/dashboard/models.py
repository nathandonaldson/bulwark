"""Pydantic models for the Bulwark HTTP API (v2).

Hand-written to match spec/openapi.yaml. The test_spec_compliance.py
meta-test validates they agree.

v2.0.0 (ADR-031): LLM models removed. CleanResponse slimmed (no analysis/
execution/llm_mode).
"""
from __future__ import annotations

from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, Field


# G-HTTP-GUARD-009 / ADR-030: per-entry caps for user-supplied canary tokens.
_CanarySourceName = Annotated[str, Field(min_length=1, max_length=64)]
_CanaryTokenValue = Annotated[str, Field(min_length=1, max_length=256)]


class CleanRequest(BaseModel):
    """Request body for POST /v1/clean."""
    content: str = Field(
        ...,
        max_length=1_000_000,
        description="Untrusted text to process through the defense stack.",
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


class RetestRequest(BaseModel):
    """Request body for POST /api/redteam/retest."""
    filename: str = Field(..., description="Filename of the report to retest.")


class GuardRequest(BaseModel):
    """Request body for POST /v1/guard."""
    text: str = Field(
        ...,
        max_length=1_000_000,
        description="LLM output to check for injection patterns and canary leaks.",
    )
    canary_tokens: Optional[dict[_CanarySourceName, _CanaryTokenValue]] = Field(
        default=None,
        max_length=64,
        description="Optional map of source_name to canary token. If null, server-configured canaries are used.",
    )


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
