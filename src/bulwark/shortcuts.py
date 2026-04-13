"""One-call convenience functions for Bulwark.

These are the simplest entry points — zero config, zero callbacks.
Import and call.

    import bulwark
    safe = bulwark.clean(email_body, source="email")
    safe_output = bulwark.guard(llm_response)

**These provide input sanitization and output checking, not full architectural
defense.** For two-phase execution, canary tokens, and batch isolation, use
Pipeline directly.

This module must NEVER import from bulwark.integrations or any optional-dependency
module. All imports must be from core Bulwark modules only.
"""
from __future__ import annotations

import functools
from typing import Optional

from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary, BoundaryFormat
from bulwark.executor import AnalysisGuard
from bulwark.canary import CanarySystem, CanaryLeakError

# Module-level singletons — created once, reused across all calls.
# Thread-safe: Sanitizer, TrustBoundary, and AnalysisGuard are stateless
# dataclasses with no mutation after __init__.
_DEFAULT_SANITIZER = Sanitizer(max_length=None)
_DEFAULT_BOUNDARY = TrustBoundary()
_DEFAULT_GUARD = AnalysisGuard()

# Format string -> BoundaryFormat mapping
_FORMAT_MAP = {
    "xml": BoundaryFormat.XML,
    "markdown": BoundaryFormat.MARKDOWN_FENCE,
    "delimiter": BoundaryFormat.DELIMITER,
}


@functools.lru_cache(maxsize=16)
def _get_sanitizer(max_length: Optional[int]) -> Sanitizer:
    """Return a cached Sanitizer for the given max_length."""
    return Sanitizer(max_length=max_length)


@functools.lru_cache(maxsize=4)
def _get_boundary(fmt: str) -> TrustBoundary:
    """Return a cached TrustBoundary for the given format string."""
    return TrustBoundary(format=_FORMAT_MAP[fmt])


def clean(
    content: str,
    source: str = "external",
    label: Optional[str] = None,
    *,
    max_length: Optional[int] = None,
    format: str = "xml",
) -> str:
    """Sanitize untrusted content and wrap it in trust boundary tags.

    This is the simplest Bulwark integration — one function, one return value.
    The returned string is safe to interpolate into any LLM prompt.

    **This provides input sanitization + trust boundary tagging, not full
    architectural defense.** For two-phase execution (where the LLM that reads
    untrusted content cannot act), use ``Pipeline``.

    Args:
        content: The untrusted text (email body, user input, web scrape, etc.)
        source: Where the content came from. Used in the trust boundary tag.
        label: Optional label for the trust boundary tag name.
        max_length: Truncate content after sanitizing. ``None`` = no limit (default).
        format: Trust boundary format — ``"xml"`` (default, best for Claude),
            ``"markdown"``, or ``"delimiter"``. Non-Claude models may work
            better with ``"markdown"`` or ``"delimiter"``.

    Returns:
        A string containing the sanitized content wrapped in trust boundary tags.

    Example::

        import bulwark

        safe = bulwark.clean(user_input, source="email")
        prompt = f"Classify this email:\\n{safe}"
    """
    if not isinstance(content, str):
        raise TypeError(f"Expected str, got {type(content).__name__}")
    if format not in _FORMAT_MAP:
        raise ValueError(f"format must be one of {list(_FORMAT_MAP)}, got {format!r}")

    sanitizer = _DEFAULT_SANITIZER if max_length is None else _get_sanitizer(max_length)
    boundary = _DEFAULT_BOUNDARY if format == "xml" else _get_boundary(format)

    cleaned = sanitizer.clean(content)
    tagged = boundary.wrap(cleaned, source=source, label=label)
    return tagged


def guard(
    text: str,
    *,
    canary: Optional[CanarySystem] = None,
) -> str:
    """Check LLM output for injection patterns and canary token leaks.

    Use this on content coming back from an LLM before passing it to
    tools, users, or downstream systems.

    Args:
        text: The LLM output to check.
        canary: Optional ``CanarySystem`` to also check for canary token leaks.

    Returns:
        The input text, unchanged, if it passes all checks.

    Raises:
        AnalysisSuspiciousError: If injection patterns are detected in the text.
        CanaryLeakError: If canary tokens are found (only when ``canary`` is provided).

    Example::

        import bulwark

        safe_output = bulwark.guard(llm_response)
        # If we get here, the output is clean
    """
    if not isinstance(text, str):
        raise TypeError(f"Expected str, got {type(text).__name__}")

    _DEFAULT_GUARD.check(text)

    if canary is not None:
        result = canary.check(text)
        if result.leaked:
            raise CanaryLeakError(result)

    return text
