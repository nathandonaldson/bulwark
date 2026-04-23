"""Bulwark HTTP API v1 — language-agnostic endpoints.

v2.0.0 (ADR-031): /v1/clean is sanitize → (optional detector) → wrap.
/v1/guard is the caller-side output check. No LLM calls. No /v1/llm/*.
"""
from __future__ import annotations

import time
from fastapi import APIRouter
from fastapi.responses import JSONResponse

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
        "Pipeline: sanitizer → DeBERTa detector (if loaded) → trust boundary wrap. "
        "Returns 200 with cleaned content the caller feeds into their own LLM. "
        "Returns 422 when the detector blocks. No LLM is invoked by Bulwark."
    ),
    responses={
        422: {"description": "Injection detected — content blocked"},
    },
)
async def api_clean(req: CleanRequest):
    t0 = time.time()
    content = req.content
    source = req.source

    from bulwark.dashboard.app import config, _detection_checks

    sanitizer = Sanitizer(
        normalize_unicode=config.normalize_unicode,
        strip_emoji_smuggling=config.strip_emoji_smuggling,
        strip_bidi=config.strip_bidi,
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
    detector_verdict = None
    if _detection_checks and cleaned:
        for model_name, check_fn in _detection_checks.items():
            step += 1
            dt0 = time.time()
            try:
                check_fn(cleaned)
                elapsed = (time.time() - dt0) * 1000
                trace.append({
                    "step": step, "layer": f"detection:{model_name}",
                    "verdict": "passed",
                    "detail": f"{model_name}: clean ({elapsed:.0f}ms)",
                    "detection_model": model_name,
                    "duration_ms": round(elapsed, 1),
                })
                detector_verdict = {"label": "SAFE", "score": None}
            except SuspiciousPatternError as e:
                elapsed = (time.time() - dt0) * 1000
                trace.append({
                    "step": step, "layer": f"detection:{model_name}",
                    "verdict": "blocked",
                    "detail": f"{model_name}: {e} ({elapsed:.0f}ms)",
                    "detection_model": model_name,
                    "duration_ms": round(elapsed, 1),
                })
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
            trace.append({
                "step": step, "layer": trace_layer, "verdict": "blocked",
                "detail": f"LLM judge: INJECTION ({v.confidence:.2f}) — {v.reason} ({v.latency_ms:.0f}ms)",
                "detection_model": "llm_judge",
                "duration_ms": round(v.latency_ms, 1),
            })
            total_ms = (time.time() - t0) * 1000
            _emit_event(
                layer="detection", verdict="blocked",
                source_id=f"api:clean:{source}",
                detail=f"Blocked by llm_judge: {v.reason}",
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
        if v.verdict == "ERROR":
            if not jcfg.fail_open:
                trace.append({
                    "step": step, "layer": trace_layer, "verdict": "blocked",
                    "detail": f"LLM judge unreachable (fail-closed): {v.reason}",
                    "detection_model": "llm_judge",
                    "duration_ms": round(v.latency_ms, 1),
                })
                total_ms = (time.time() - t0) * 1000
                _emit_event(
                    layer="detection", verdict="blocked",
                    source_id=f"api:clean:{source}",
                    detail=f"Blocked by llm_judge (fail-closed): {v.reason}",
                    duration_ms=round(total_ms, 1),
                )
                return JSONResponse(
                    status_code=422,
                    content={
                        "blocked": True,
                        "block_reason": f"Detector llm_judge unreachable: {v.reason}",
                        "blocked_at": "detection:llm_judge",
                        "trace": trace,
                        "content_length": len(content),
                        "modified": modified,
                    },
                )
            # fail-open
            trace.append({
                "step": step, "layer": trace_layer, "verdict": "passed",
                "detail": f"LLM judge unreachable (fail-open): {v.reason} ({v.latency_ms:.0f}ms)",
                "detection_model": "llm_judge",
                "duration_ms": round(v.latency_ms, 1),
            })
        else:
            # SAFE or UNPARSEABLE → pass through
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
