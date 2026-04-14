"""Bulwark HTTP API v1 — language-agnostic endpoints for clean() and guard().

These endpoints map directly to the Python convenience functions in bulwark.shortcuts.
The spec lives at spec/openapi.yaml. Pydantic models live in dashboard/models.py.
"""
from __future__ import annotations

from fastapi import APIRouter

from dashboard.models import (
    CleanRequest, CleanResponse,
    GuardRequest, GuardResponse,
)
from bulwark.shortcuts import clean, guard
from bulwark.sanitizer import Sanitizer
from bulwark.executor import AnalysisSuspiciousError
from bulwark.canary import CanarySystem, CanaryLeakError

router = APIRouter(prefix="/v1", tags=["Bulwark API v1"])


@router.post(
    "/clean",
    response_model=CleanResponse,
    summary="Sanitize untrusted content and wrap in trust boundary tags",
    description=(
        "Maps to bulwark.clean(). Strips hidden characters, steganography, "
        "and encoding tricks, then wraps in trust boundary tags. "
        "The result is safe to interpolate into any LLM prompt.\n\n"
        "This provides input sanitization + trust boundary tagging, not full "
        "architectural defense. For two-phase execution, use the Pipeline Python API."
    ),
)
async def api_clean(req: CleanRequest) -> CleanResponse:
    result = clean(
        req.content,
        source=req.source,
        label=req.label,
        max_length=req.max_length,
        format=req.format,
    )

    # Determine whether the sanitizer modified the content.
    # Run the sanitizer independently (<1ms) rather than refactoring clean().
    sanitizer = Sanitizer(max_length=req.max_length)
    modified = sanitizer.clean(req.content) != req.content

    return CleanResponse(
        result=result,
        source=req.source,
        format=req.format,
        content_length=len(req.content),
        result_length=len(result),
        modified=modified,
    )


@router.post(
    "/guard",
    response_model=GuardResponse,
    summary="Check LLM output for injection patterns and canary leaks",
    description=(
        "Maps to bulwark.guard(). Checks text against regex-based injection "
        "patterns and optional canary token leaks. Always returns 200 — "
        "the request succeeded, the analysis result may be 'unsafe'."
    ),
)
async def api_guard(req: GuardRequest) -> GuardResponse:
    canary = None
    if req.canary_tokens:
        canary = CanarySystem.from_dict(req.canary_tokens)

    try:
        guard(req.text, canary=canary)
        return GuardResponse(safe=True, text=req.text)
    except AnalysisSuspiciousError as e:
        return GuardResponse(
            safe=False, text=req.text, reason=str(e), check="injection",
        )
    except CanaryLeakError as e:
        return GuardResponse(
            safe=False, text=req.text, reason=str(e), check="canary",
        )
