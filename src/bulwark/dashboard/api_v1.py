"""Bulwark HTTP API v1 — language-agnostic endpoints.

v2.0.0 (ADR-031): /v1/clean is sanitize → (optional detector) → wrap.
/v1/guard is the caller-side output check. No LLM calls. No /v1/llm/*.
"""
from __future__ import annotations

import logging
import os
import time
from fastapi import APIRouter
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


# ADR-040: Truthy values for the BULWARK_ALLOW_NO_DETECTORS opt-in.
# Mirrors the convention used by BULWARK_ALLOW_SANITIZE_ONLY (ADR-038).
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes"})


def _allow_no_detectors() -> bool:
    """Return True when BULWARK_ALLOW_NO_DETECTORS is set to a truthy value.

    "0", "false", "" (and unset) all evaluate to False — the fail-closed
    default. See ADR-040.
    """
    return os.environ.get("BULWARK_ALLOW_NO_DETECTORS", "").strip().lower() in _TRUTHY_ENV_VALUES

from bulwark.dashboard.models import (
    CleanRequest, CleanResponse,
    GuardRequest, GuardResponse,
)
from bulwark.shortcuts import guard as shortcut_guard
from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary, BoundaryFormat

_FORMAT_MAP = {
    "xml": BoundaryFormat.XML,
    "markdown": BoundaryFormat.MARKDOWN_FENCE,
    "delimiter": BoundaryFormat.DELIMITER,
}
from bulwark.guard import SuspiciousPatternError
from bulwark.canary import CanarySystem, CanaryLeakError

router = APIRouter(prefix="/v1", tags=["Bulwark API v1"])


def _emit_event(layer: str, verdict: str, source_id: str = "", detail: str = "", duration_ms: float = 0):
    """Emit a BulwarkEvent to the dashboard's EventDB + SSE + webhook."""
    from bulwark.dashboard.app import db, _subscribers, config
    import asyncio
    event = {
        "timestamp": time.time(),
        "layer": layer,
        "verdict": verdict,
        "source_id": source_id,
        "detail": detail,
        "duration_ms": duration_ms,
        "metadata": {},
    }
    db.insert_batch([event])
    for q in _subscribers:
        try:
            q.put_nowait(event)
        except (asyncio.QueueFull, Exception):
            pass
    if verdict == "blocked" and config.webhook_url:
        _fire_webhook(config.webhook_url, event)


def _fire_webhook(url: str, event: dict) -> None:
    """Dispatch a single BLOCKED event to the configured external URL."""
    try:
        from bulwark.dashboard.url_validator import validate_external_url
        if validate_external_url(url):
            return
        from bulwark.events import WebhookEmitter, BulwarkEvent, Layer, Verdict
        emitter = WebhookEmitter(url, timeout=5.0, async_send=True)
        try:
            layer_enum = Layer(event["layer"])
        except ValueError:
            layer_enum = Layer.ANALYSIS_GUARD
        try:
            verdict_enum = Verdict(event["verdict"])
        except ValueError:
            verdict_enum = Verdict.BLOCKED
        emitter.emit(BulwarkEvent(
            timestamp=event["timestamp"],
            layer=layer_enum,
            verdict=verdict_enum,
            source_id=event.get("source_id", ""),
            detail=event.get("detail", ""),
            duration_ms=event.get("duration_ms", 0.0),
            metadata=event.get("metadata", {}),
        ))
    except Exception:
        pass


@router.post(
    "/clean",
    response_model=CleanResponse,
    summary="Sanitize, detect, and wrap untrusted content",
    description=(
        "Pipeline: sanitizer (with optional encoding-decode) → DeBERTa / "
        "PromptGuard / optional LLM judge classifiers → trust boundary wrap. "
        "Returns 200 with cleaned content the caller feeds into their own "
        "LLM. Returns 422 when any classifier blocks. The LLM judge is "
        "detection-only — only verdict + confidence + latency reach the "
        "response (NG-JUDGE-004 / ADR-037). Generative judge text is never "
        "exposed to /v1/clean callers."
    ),
    responses={
        422: {"description": "Injection detected — content blocked"},
        503: {"description": "No detectors loaded and operator has not opted in (ADR-040)"},
    },
)
async def api_clean(req: CleanRequest):
    t0 = time.time()
    content = req.content
    source = req.source

    from bulwark.dashboard.app import config, _detection_checks

    # ADR-040 / G-CLEAN-DETECTOR-REQUIRED-001 / G-HTTP-CLEAN-503-NO-DETECTORS-001:
    # Fail closed when nothing can actually run a detection check. Predicate
    # matches /healthz's `degraded` definition (ADR-038): zero ML detectors
    # AND judge disabled. Operators may opt into sanitize-only mode via
    # BULWARK_ALLOW_NO_DETECTORS=1. This runs BEFORE the sanitizer so we
    # don't waste work on a request we're about to refuse.
    judge_enabled = False
    try:
        judge_enabled = bool(config.judge_backend.enabled)
    except AttributeError:
        pass
    has_any_detector = bool(_detection_checks) or judge_enabled
    degraded_explicit_opt_in = _allow_no_detectors()
    if not has_any_detector:
        if not degraded_explicit_opt_in:
            logger.warning(
                "/v1/clean refused: no detectors loaded and "
                "BULWARK_ALLOW_NO_DETECTORS is unset (ADR-040). source=%s",
                source,
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "code": "no_detectors_loaded",
                        "message": (
                            "Bulwark has zero ML detectors loaded and the LLM "
                            "judge is disabled. /v1/clean refuses to serve "
                            "sanitize-only output by default. Set "
                            "BULWARK_ALLOW_NO_DETECTORS=1 to opt in (see ADR-040)."
                        ),
                    },
                },
            )
        # Opt-in path: log every request so the operator's log volume reflects
        # the reduced-defense state. NG-CLEAN-DETECTOR-REQUIRED-001.
        logger.warning(
            "/v1/clean serving in degraded-explicit mode "
            "(BULWARK_ALLOW_NO_DETECTORS=1, no detectors loaded, judge disabled). "
            "source=%s bulwark.degraded_explicit=1",
            source,
        )

    sanitizer = Sanitizer(
        normalize_unicode=config.normalize_unicode,
        strip_emoji_smuggling=config.strip_emoji_smuggling,
        strip_bidi=config.strip_bidi,
        decode_encodings=config.encoding_resistant,
        max_length=req.max_length,
    ) if config.sanitizer_enabled else None

    trust_boundary = TrustBoundary(format=_FORMAT_MAP.get(req.format, BoundaryFormat.XML)) if config.trust_boundary_enabled else None

    trace: list[dict] = []
    step = 0

    # Step 1: sanitize
    cleaned = content
    modified = False
    if sanitizer:
        step += 1
        cleaned = sanitizer.clean(content)
        modified = cleaned != content
        trace.append({
            "step": step, "layer": "sanitizer",
            "verdict": "modified" if modified else "passed",
            "detail": f"{'Modified' if modified else 'Clean'}: {len(content)} -> {len(cleaned)} chars",
        })

    # Step 2: detectors (DeBERTa + optional PromptGuard)
    # B6 / ADR-038: trace records max_score and n_windows from the detector
    # so observability is per-window, not just SAFE/BLOCKED.
    detector_verdict = None
    if _detection_checks and cleaned:
        for model_name, check_fn in _detection_checks.items():
            step += 1
            dt0 = time.time()
            try:
                result = check_fn(cleaned)
                elapsed = (time.time() - dt0) * 1000
                # check_fn now returns a dict on pass (B6); fall back to
                # empty dict if a custom check still returns None.
                result = result or {}
                max_score = result.get("max_score")
                n_windows = result.get("n_windows")
                detail = f"{model_name}: clean"
                if max_score is not None:
                    detail += f" (max={max_score:.3f}"
                    if n_windows and n_windows > 1:
                        detail += f", {n_windows} windows"
                    detail += ")"
                detail += f" ({elapsed:.0f}ms)"
                trace_entry = {
                    "step": step, "layer": f"detection:{model_name}",
                    "verdict": "passed",
                    "detail": detail,
                    "detection_model": model_name,
                    "duration_ms": round(elapsed, 1),
                }
                if max_score is not None:
                    trace_entry["max_score"] = round(max_score, 4)
                if n_windows is not None:
                    trace_entry["n_windows"] = n_windows
                trace.append(trace_entry)
                # B6 follow-up (review): use the detector's actual top label
                # (BENIGN / SAFE / etc.) rather than hardcoding "SAFE".
                # max_score remains the INJECTION-class signal per ADR-039.
                detector_verdict = {
                    "label": result.get("top_label") or "SAFE",
                    "score": round(max_score, 4) if max_score is not None else None,
                }
            except SuspiciousPatternError as e:
                elapsed = (time.time() - dt0) * 1000
                # B6: blocked exceptions carry max_score / n_windows / window_index.
                max_score = getattr(e, "max_score", None)
                n_windows = getattr(e, "n_windows", None)
                window_index = getattr(e, "window_index", None)
                trace_entry = {
                    "step": step, "layer": f"detection:{model_name}",
                    "verdict": "blocked",
                    "detail": f"{model_name}: {e} ({elapsed:.0f}ms)",
                    "detection_model": model_name,
                    "duration_ms": round(elapsed, 1),
                }
                if max_score is not None:
                    trace_entry["max_score"] = round(max_score, 4)
                if n_windows is not None:
                    trace_entry["n_windows"] = n_windows
                if window_index is not None:
                    trace_entry["window_index"] = window_index
                trace.append(trace_entry)
                total_ms = (time.time() - t0) * 1000
                _emit_event(
                    layer="detection", verdict="blocked",
                    source_id=f"api:clean:{source}",
                    detail=f"Blocked by {model_name}: {e}",
                    duration_ms=round(total_ms, 1),
                )
                return JSONResponse(
                    status_code=422,
                    content={
                        "blocked": True,
                        "block_reason": f"Detector {model_name}: {e}",
                        "blocked_at": f"detection:{model_name}",
                        "trace": trace,
                        "content_length": len(content),
                        "modified": modified,
                    },
                )

    # Step 2b: LLM judge (opt-in, runs after DeBERTa/PromptGuard so faster
    # detectors short-circuit it). G-JUDGE-001..008.
    if config.judge_backend.enabled and cleaned:
        from bulwark.detectors.llm_judge import classify
        jcfg = config.judge_backend
        step += 1
        v = classify(jcfg, cleaned)
        trace_layer = "detection:llm_judge"
        if v.verdict == "INJECTION" and v.confidence >= jcfg.threshold:
            # NG-JUDGE-004 / ADR-037: do NOT include v.reason in trace detail.
            # Generative judge text never reaches /v1/clean callers.
            trace.append({
                "step": step, "layer": trace_layer, "verdict": "blocked",
                "detail": f"LLM judge: INJECTION ({v.confidence:.2f}) ({v.latency_ms:.0f}ms)",
                "detection_model": "llm_judge",
                "duration_ms": round(v.latency_ms, 1),
            })
            total_ms = (time.time() - t0) * 1000
            _emit_event(
                layer="detection", verdict="blocked",
                source_id=f"api:clean:{source}",
                detail=f"Blocked by llm_judge (confidence={v.confidence:.2f})",
                duration_ms=round(total_ms, 1),
            )
            return JSONResponse(
                status_code=422,
                content={
                    "blocked": True,
                    "block_reason": f"Detector llm_judge: INJECTION ({v.confidence:.2f})",
                    "blocked_at": "detection:llm_judge",
                    "trace": trace,
                    "content_length": len(content),
                    "modified": modified,
                },
            )
        # ADR-037 / G-JUDGE-005: UNPARSEABLE follows the same path as ERROR.
        # Strict mode (fail_open=False) blocks them; permissive mode lets
        # them pass with a trace annotation. UNPARSEABLE never short-
        # circuits as SAFE. Generative judge text (v.reason) is never
        # included in trace details (NG-JUDGE-004).
        if v.verdict in ("ERROR", "UNPARSEABLE"):
            label = "unreachable" if v.verdict == "ERROR" else "unparseable response"
            if not jcfg.fail_open:
                trace.append({
                    "step": step, "layer": trace_layer, "verdict": "blocked",
                    "detail": f"LLM judge {label} (fail-closed)",
                    "detection_model": "llm_judge",
                    "duration_ms": round(v.latency_ms, 1),
                })
                total_ms = (time.time() - t0) * 1000
                _emit_event(
                    layer="detection", verdict="blocked",
                    source_id=f"api:clean:{source}",
                    detail=f"Blocked by llm_judge ({label}, fail-closed)",
                    duration_ms=round(total_ms, 1),
                )
                return JSONResponse(
                    status_code=422,
                    content={
                        "blocked": True,
                        "block_reason": f"Detector llm_judge {label}",
                        "blocked_at": "detection:llm_judge",
                        "trace": trace,
                        "content_length": len(content),
                        "modified": modified,
                    },
                )
            # fail-open
            trace.append({
                "step": step, "layer": trace_layer, "verdict": "passed",
                "detail": f"LLM judge {label} (fail-open) ({v.latency_ms:.0f}ms)",
                "detection_model": "llm_judge",
                "duration_ms": round(v.latency_ms, 1),
            })
        else:
            # SAFE → pass through
            trace.append({
                "step": step, "layer": trace_layer, "verdict": "passed",
                "detail": f"LLM judge: {v.verdict} ({v.confidence:.2f}) ({v.latency_ms:.0f}ms)",
                "detection_model": "llm_judge",
                "duration_ms": round(v.latency_ms, 1),
            })
            detector_verdict = {"label": v.verdict, "score": v.confidence}

    # Step 3: trust boundary wrap
    tagged = cleaned
    if trust_boundary:
        step += 1
        tagged = trust_boundary.wrap(cleaned, source=source, label=req.label)
        trace.append({
            "step": step, "layer": "trust_boundary",
            "verdict": "passed",
            "detail": f"Wrapped with source={source}",
        })

    total_ms = (time.time() - t0) * 1000
    _emit_event(
        layer="sanitizer",
        verdict="modified" if modified else "passed",
        source_id=f"api:clean:{source}",
        detail=f"Clean {source}: {len(content)} -> {len(tagged)} chars ({total_ms:.0f}ms)",
        duration_ms=round(total_ms, 1),
    )

    return CleanResponse(
        result=tagged,
        blocked=False,
        source=req.source,
        format=req.format,
        content_length=len(content),
        result_length=len(tagged),
        modified=modified,
        trace=trace,
        detector=detector_verdict,
        # ADR-040 / NG-CLEAN-DETECTOR-REQUIRED-001: mark sanitize-only opt-in
        # responses so callers can detect they're in reduced-defense mode.
        mode="degraded-explicit" if (not has_any_detector and degraded_explicit_opt_in) else None,
    )


@router.post(
    "/guard",
    response_model=GuardResponse,
    summary="Check caller's LLM output for injection patterns and canary leaks",
    description=(
        "The caller-side output check. Run this on your own LLM's output to "
        "detect injection patterns and canary token leaks. Always returns 200 — "
        "the request succeeded, the analysis result may be 'unsafe'."
    ),
)
async def api_guard(req: GuardRequest) -> GuardResponse:
    from bulwark.dashboard.app import config as app_config

    # If caller didn't pass canary_tokens, fall back to server-configured canaries.
    tokens = req.canary_tokens
    if tokens is None and app_config.canary_tokens:
        tokens = dict(app_config.canary_tokens)

    canary = CanarySystem.from_dict(tokens) if tokens else None

    t0 = time.time()
    try:
        shortcut_guard(req.text, canary=canary)
        elapsed = (time.time() - t0) * 1000
        _emit_event(
            layer="analysis_guard",
            verdict="passed",
            source_id="api:guard",
            detail=f"Guard: {len(req.text)} chars (passed)",
            duration_ms=round(elapsed, 1),
        )
        return GuardResponse(safe=True, text=req.text)
    except SuspiciousPatternError as e:
        elapsed = (time.time() - t0) * 1000
        _emit_event(
            layer="analysis_guard",
            verdict="blocked",
            source_id="api:guard",
            detail=f"Guard: injection detected ({e})",
            duration_ms=round(elapsed, 1),
        )
        return GuardResponse(
            safe=False, text=req.text, reason=str(e), check="injection",
        )
    except CanaryLeakError as e:
        elapsed = (time.time() - t0) * 1000
        _emit_event(
            layer="analysis_guard",
            verdict="blocked",
            source_id="api:guard",
            detail=f"Guard: canary leak detected ({e})",
            duration_ms=round(elapsed, 1),
        )
        return GuardResponse(
            safe=False, text=req.text, reason=str(e), check="canary",
        )
