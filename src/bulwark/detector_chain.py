"""Shared detector-chain executor (ADR-048).

Both `bulwark.pipeline.Pipeline.run()` and
`bulwark.dashboard.api_v1.api_clean` delegate variant fan-out to this
module. Two prior copies of the loop drifted (dashboard short-circuited
on judge ERROR; library didn't), creating a parity gap
(G-PIPELINE-PARITY-001) and a real defense gap: an attacker who could
engineer the original variant to make the judge choke could hide the
real injection in an encoded variant — the dashboard's short-circuit
meant the judge would never see it.

`run_detector_chain(...)` is the single source of truth for chain
execution semantics. It contains zero FastAPI / dashboard imports —
pure logic, no I/O beyond calling the detector callables it was given.

Semantic (G-CLEAN-DECODE-JUDGE-ALL-VARIANTS-001):
  - For each non-skipped variant, run all detectors first, then the
    judge (if supplied).
  - First INJECTION raise (from a detector or the judge) blocks
    immediately and returns.
  - Judge ERROR / UNPARSEABLE on a variant: log + record in the
    per-judge result list. If `judge_fail_open=True`, continue to next
    variant. If `judge_fail_open=False`, treat as block on this variant.
  - Skipped variants are NOT run through detectors or the judge.
  - Detectors run in the supplied order on each variant.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional

from bulwark.decoders import DecodedVariant
from bulwark.guard import SuspiciousPatternError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DetectorResult:
    """One detector run on one variant.

    Captures everything either caller needs to build its trace entry:
    the dashboard cares about `detection_model`, `max_score`, `n_windows`,
    `window_index`, and `duration_ms`; the library cares about `passed`
    + `error_message` + `variant_label`. Both are populated.
    """
    detector_index: int
    detector_name: Optional[str]   # e.g. "detection:protectai"; None for ad-hoc
    variant_label: str
    passed: bool
    duration_ms: float
    error: Optional[SuspiciousPatternError] = None
    # Result dict from the detector when it passed (`max_score`, `n_windows`,
    # `top_label`); None when blocked.
    result: Optional[dict] = None


@dataclass(frozen=True)
class JudgeResult:
    """One judge call on one variant.

    Wraps a JudgeVerdict-like object plus the variant the call ran on,
    so the dashboard can attribute the trace entry to the correct
    variant. `verdict` / `confidence` / `latency_ms` mirror the
    `JudgeVerdict` dataclass; `raw` is intentionally NOT exposed
    (NG-JUDGE-004).
    """
    variant_label: str
    verdict: str          # "SAFE" | "INJECTION" | "ERROR" | "UNPARSEABLE"
    confidence: float
    latency_ms: float
    # When True, this judge result was the one that blocked the chain
    # (either INJECTION or fail-closed ERROR/UNPARSEABLE).
    blocked: bool = False


@dataclass
class ChainResult:
    """Aggregate result of a detector-chain run.

    Callers splice `detector_results` and `judge_results` into their
    own trace shape. `blocked`, `blocked_at_variant`,
    `blocked_detector_name`, and `blocked_reason` are the load-bearing
    decision the chain reached and what the caller's response should
    surface.
    """
    blocked: bool = False
    blocked_at_variant: Optional[str] = None
    blocked_detector_name: Optional[str] = None
    blocked_reason: Optional[str] = None
    blocked_detector_index: Optional[int] = None
    # The actual SuspiciousPatternError that fired (so the caller can
    # extract `max_score` / `n_windows` / `window_index` for its trace).
    blocked_error: Optional[SuspiciousPatternError] = None
    # Which JudgeResult triggered the block, if the judge was the cause
    # (None when an ML detector blocked first).
    blocked_judge: Optional[JudgeResult] = None
    detector_results: list[DetectorResult] = field(default_factory=list)
    judge_results: list[JudgeResult] = field(default_factory=list)


def _detector_name(detector: Callable[..., Any], index: int) -> Optional[str]:
    """Best-effort detector label. Returns the `__bulwark_name__` attr or None."""
    name = getattr(detector, "__bulwark_name__", None)
    if isinstance(name, str) and name:
        return name
    return None


def run_detector_chain(
    *,
    variants: list[DecodedVariant],
    detectors: Iterable[Callable[[str], Any]],
    judge: Optional[Callable[[str], Any]] = None,
    judge_fail_open: bool = True,
) -> ChainResult:
    """Run the detector chain across `variants`. See module docstring.

    Args:
      variants: precomputed list from `decode_rescan_variants`. Skipped
        variants are recorded in the trace by the caller but not run
        through detectors here.
      detectors: ordered iterable of detector callables. Each callable
        takes `text -> dict` and raises `SuspiciousPatternError` to
        block. Detectors run in the supplied order on each variant.
      judge: optional callable taking `text -> JudgeVerdict-like`
        (with `.verdict`, `.confidence`, `.latency_ms` attributes). The
        judge runs AFTER all detectors on each variant, so cheaper
        detectors short-circuit it.
      judge_fail_open: when True (default), judge ERROR / UNPARSEABLE
        on one variant logs + records but does NOT short-circuit.
        When False, ERROR / UNPARSEABLE blocks immediately. INJECTION
        always blocks regardless.

    Returns:
      ChainResult with the block decision and the per-variant
      detector / judge events the caller can splice into its trace.
    """
    detectors_list = list(detectors)
    result = ChainResult()

    non_skipped = [v for v in variants if not v.skipped and v.text]

    # Phase 1: detectors. For each detector, iterate variants. First
    # raise (from any variant) blocks the entire chain. The variant loop
    # is the OUTER loop conceptually but the detector loop is the loop
    # that defines short-circuit ordering — once detector `d_i` raises
    # on any variant, we stop (matching the prior dashboard + library
    # semantic where detector order = priority order). To preserve that,
    # iterate detector-major.
    for index, detector in enumerate(detectors_list):
        name = _detector_name(detector, index)
        for variant in non_skipped:
            t0 = time.time()
            try:
                det_result = detector(variant.text)
            except SuspiciousPatternError as exc:
                elapsed_ms = (time.time() - t0) * 1000
                result.detector_results.append(DetectorResult(
                    detector_index=index, detector_name=name,
                    variant_label=variant.label, passed=False,
                    duration_ms=elapsed_ms, error=exc, result=None,
                ))
                # Block.
                result.blocked = True
                result.blocked_at_variant = variant.label
                result.blocked_detector_name = name
                result.blocked_detector_index = index
                result.blocked_reason = str(exc)
                result.blocked_error = exc
                return result
            else:
                elapsed_ms = (time.time() - t0) * 1000
                result.detector_results.append(DetectorResult(
                    detector_index=index, detector_name=name,
                    variant_label=variant.label, passed=True,
                    duration_ms=elapsed_ms,
                    result=det_result if isinstance(det_result, dict) else {},
                ))

    # Phase 2: judge. Run on every non-skipped variant. INJECTION blocks
    # immediately. ERROR / UNPARSEABLE block only when fail-closed; in
    # fail-open mode they're recorded but the chain continues.
    if judge is None:
        return result

    for variant in non_skipped:
        verdict_obj = judge(variant.text)
        verdict = getattr(verdict_obj, "verdict", "UNPARSEABLE")
        confidence = float(getattr(verdict_obj, "confidence", 0.0) or 0.0)
        latency_ms = float(getattr(verdict_obj, "latency_ms", 0.0) or 0.0)

        if verdict == "INJECTION":
            jr = JudgeResult(
                variant_label=variant.label, verdict=verdict,
                confidence=confidence, latency_ms=latency_ms, blocked=True,
            )
            result.judge_results.append(jr)
            result.blocked = True
            result.blocked_at_variant = variant.label
            result.blocked_detector_name = "detection:llm_judge"
            result.blocked_reason = f"LLM judge: INJECTION ({confidence:.2f})"
            result.blocked_judge = jr
            return result

        if verdict in ("ERROR", "UNPARSEABLE"):
            if not judge_fail_open:
                jr = JudgeResult(
                    variant_label=variant.label, verdict=verdict,
                    confidence=confidence, latency_ms=latency_ms, blocked=True,
                )
                result.judge_results.append(jr)
                result.blocked = True
                result.blocked_at_variant = variant.label
                result.blocked_detector_name = "detection:llm_judge"
                label = "unreachable" if verdict == "ERROR" else "unparseable response"
                result.blocked_reason = f"LLM judge {label} (fail-closed)"
                result.blocked_judge = jr
                return result
            # Fail-open: log, record, KEEP GOING.
            # G-CLEAN-DECODE-JUDGE-ALL-VARIANTS-001 — ERROR on one variant
            # MUST NOT short-circuit the chain. The H.2 defense gap.
            logger.info(
                "LLM judge %s on variant %s (fail-open); continuing to next variant",
                verdict.lower(), variant.label,
            )
            result.judge_results.append(JudgeResult(
                variant_label=variant.label, verdict=verdict,
                confidence=confidence, latency_ms=latency_ms, blocked=False,
            ))
            continue

        # SAFE — record + continue.
        result.judge_results.append(JudgeResult(
            variant_label=variant.label, verdict=verdict,
            confidence=confidence, latency_ms=latency_ms, blocked=False,
        ))

    return result
