"""Output-regex guard — checks LLM output for injection patterns.

Renamed from AnalysisGuard (which guarded the Phase 1 → Phase 2 bridge) to
PatternGuard (which checks caller-produced LLM output via /v1/guard). The
semantics are identical; the framing matters: this is an *output* check.

See ADR-031.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from bulwark.events import EventEmitter, BulwarkEvent, Layer, Verdict, _now


class SuspiciousPatternError(Exception):
    """Raised when text contains a known injection pattern."""
    pass


@dataclass
class PatternGuard:
    """Regex-based injection-pattern detector for LLM output.

    Runs a list of patterns against a text blob. Length cap prevents DoS.
    Zero-dependency, zero-latency. For stronger detection, plug in
    model-based classifiers via custom_checks.
    """
    max_length: int = 5000
    block_patterns: list[str] = field(default_factory=lambda: [
        # Instruction override attempts
        r'(?i)\bignore\s+(all\s+)?previous\s+instructions?\b',
        r'(?i)\bdisregard\b.{0,100}\binstructions?\b',
        r'(?i)\bnew\s+(system\s+)?instructions?\b',
        r'(?i)\byou\s+are\s+now\b',
        r'(?i)\badmin\s+mode\b',
        # Trust boundary escape attempts
        r'(?i)</untrusted_',
        r'(?i)</?system',
        r'(?i)</?trusted',
        r'(?i)^SYSTEM\s*:', r'(?i)\nSYSTEM\s*:',
        # Tool call manipulation
        r'(?i)\btool_use\b',
        r'(?i)\bfunction_call\b',
        r'(?i)\btool_calls?\b',
        # Multilingual instruction overrides
        r'忽略.{0,100}指令', r'تجاهل.{0,100}تعليمات',
        r'(?i)\bforward\s+all\b.{0,100}\b(email|data|contact)',
        r'(?i)\bsend\s+all\b.{0,100}\b(data|email|contact)',
    ])
    custom_checks: list[Callable[[str], None]] = field(default_factory=list)
    emitter: Optional[EventEmitter] = None

    def check(self, text: str) -> None:
        """Raise SuspiciousPatternError if patterns match. No-op if clean."""
        if len(text) > self.max_length:
            if self.emitter:
                self.emitter.emit(BulwarkEvent(
                    timestamp=_now(), layer=Layer.ANALYSIS_GUARD,
                    verdict=Verdict.BLOCKED,
                    detail=f"Exceeds max length: {len(text)} > {self.max_length}",
                ))
            raise SuspiciousPatternError(
                f"Text exceeds maximum length ({len(text)} > {self.max_length})"
            )
        for pattern in self.block_patterns:
            if re.search(pattern, text):
                if self.emitter:
                    self.emitter.emit(BulwarkEvent(
                        timestamp=_now(), layer=Layer.ANALYSIS_GUARD,
                        verdict=Verdict.BLOCKED,
                        detail=f"Pattern match: {pattern}",
                        metadata={"pattern": pattern},
                    ))
                raise SuspiciousPatternError(
                    f"Suspicious pattern in text: {pattern}"
                )
        for check_fn in self.custom_checks:
            check_fn(text)

        if self.emitter:
            self.emitter.emit(BulwarkEvent(
                timestamp=_now(), layer=Layer.ANALYSIS_GUARD,
                verdict=Verdict.PASSED,
                detail=f"All {len(self.block_patterns)} patterns + {len(self.custom_checks)} custom checks passed",
            ))


