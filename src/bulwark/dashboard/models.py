"""Pydantic models for the Bulwark HTTP API (v1).

These models are hand-written to match spec/openapi.yaml.
The test_spec_compliance.py meta-test validates they agree.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class CleanRequest(BaseModel):
    """Request body for POST /v1/clean."""
    content: str = Field(
        ...,
        max_length=1_000_000,
        description="Untrusted text to sanitize and wrap in trust boundary tags.",
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
        description='Trust boundary format. "xml" (default, best for Claude), "markdown", or "delimiter".',
    )


class CleanResponse(BaseModel):
    """Response body for POST /v1/clean."""
    result: str = Field(
        ...,
        description="Sanitized content wrapped in trust boundary tags.",
    )
    source: str = Field(
        ...,
        description="Echo of the source parameter used.",
    )
    format: str = Field(
        ...,
        description="Echo of the format used.",
    )
    content_length: int = Field(
        ...,
        description="Length of the original content before processing.",
    )
    result_length: int = Field(
        ...,
        description="Length of the result after processing.",
    )
    modified: bool = Field(
        ...,
        description="True if the sanitizer modified the content (stripped characters).",
    )


class LLMTestRequest(BaseModel):
    """Request body for POST /v1/llm/test."""
    mode: str = Field(
        default="none",
        description="LLM mode: none, anthropic, or openai_compatible.",
    )
    api_key: str = Field(default="", description="API key for the LLM provider.")
    base_url: str = Field(default="", description="Base URL for OpenAI-compatible endpoints.")
    analyze_model: str = Field(default="", description="Model for Phase 1 analysis.")
    execute_model: str = Field(default="", description="Model for Phase 2 execution.")


class PipelineRequest(BaseModel):
    """Request body for POST /v1/pipeline."""
    content: str = Field(
        ...,
        max_length=1_000_000,
        description="Untrusted content to process through the pipeline.",
    )
    source: str = Field(
        default="external",
        description="Source label for trust boundary tags.",
    )


class GuardRequest(BaseModel):
    """Request body for POST /v1/guard."""
    text: str = Field(
        ...,
        max_length=1_000_000,
        description="LLM output to check for injection patterns and canary token leaks.",
    )
    canary_tokens: Optional[dict[str, str]] = Field(
        default=None,
        description="Optional map of source_name to canary token string for leak detection.",
    )


class GuardResponse(BaseModel):
    """Response body for POST /v1/guard."""
    safe: bool = Field(
        ...,
        description="True if the text passed all checks. False if injection or canary leak detected.",
    )
    text: str = Field(
        ...,
        description="The input text, unchanged.",
    )
    reason: Optional[str] = Field(
        default=None,
        description="If not safe, the reason. null if safe.",
    )
    check: Optional[Literal["injection", "canary"]] = Field(
        default=None,
        description="Which check triggered the block, if any.",
    )
