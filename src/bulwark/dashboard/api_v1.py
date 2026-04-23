"""Bulwark HTTP API v1 — language-agnostic endpoints for defense and output checking.

/v1/clean is the primary endpoint — runs the full defense stack.
/v1/guard checks LLM output for injection patterns.
The spec lives at spec/openapi.yaml.
"""
from __future__ import annotations

import time
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from bulwark.dashboard.models import (
    CleanRequest, CleanResponse,
    GuardRequest, GuardResponse,
    LLMModelsRequest, LLMTestRequest,
)
from bulwark.shortcuts import guard
from bulwark.sanitizer import Sanitizer
from bulwark.executor import AnalysisSuspiciousError
from bulwark.canary import CanarySystem, CanaryLeakError

router = APIRouter(prefix="/v1", tags=["Bulwark API v1"])


def _resolve_llm_api_key(req_api_key: str, req_base_url: str, configured_api_key: str, configured_base_url: str) -> str:
    """Resolve API key safely for LLM test/model endpoints.

    If caller overrides base_url, never fall back to the server-stored key.
    This prevents sending stored credentials to caller-controlled endpoints.
    """
    has_explicit_key = bool(req_api_key and "..." not in req_api_key)
    if has_explicit_key:
        return req_api_key

    if req_base_url:
        requested = req_base_url.rstrip("/")
        configured = (configured_base_url or "").rstrip("/")
        if requested != configured:
            return ""

    return configured_api_key


def _emit_event(layer: str, verdict: str, source_id: str = "", detail: str = "", duration_ms: float = 0):
    """Emit a BulwarkEvent to the dashboard's EventDB, SSE subscribers, and —
    if configured — an external webhook (ADR-026, G-WEBHOOK-001..006)."""
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
    # G-WEBHOOK-002: external fan-out only on BLOCKED verdicts. G-WEBHOOK-004:
    # fire-and-forget; a dead webhook must not delay the /v1/clean response.
    if verdict == "blocked" and config.webhook_url:
        _fire_webhook(config.webhook_url, event)


def _fire_webhook(url: str, event: dict) -> None:
    """Dispatch a single BLOCKED event to the configured external URL.

    Wraps bulwark.events.WebhookEmitter (which already runs in a daemon
    thread when async_send=True). Construction can raise on an invalid URL
    scheme (G-WEBHOOK-005) — we swallow that so a misconfigured operator
    URL never crashes the primary path. The config-change path is where
    schema errors should surface; _emit_event is not the place to raise.

    G-WEBHOOK-007 / ADR-030: additionally, if somehow a webhook_url
    pointing at a private/metadata host ended up in config (e.g. loaded
    from a bulwark-config.yaml that predated the validation), do not
    POST to it. The config-write validator should have rejected these,
    but defense-in-depth prevents a stale config file from becoming an
    SSRF vector when the process restarts.
    """
    try:
        from bulwark.dashboard.llm_factory import _validate_base_url
        if _validate_base_url(url):
            return  # silently skip; config-write path surfaces the real error
        from bulwark.events import WebhookEmitter, BulwarkEvent, Layer, Verdict
        emitter = WebhookEmitter(url, timeout=5.0, async_send=True)
        # Marshal the dict back into a BulwarkEvent for consistent wire shape.
        # Unknown layer/verdict strings fall through to sensible defaults so
        # a future verdict name doesn't silently drop the webhook.
        try:
            layer_enum = Layer(event["layer"])
        except ValueError:
            layer_enum = Layer.EXECUTOR
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
        pass  # G-WEBHOOK-004: never fail the primary request


@router.post(
    "/clean",
    response_model=CleanResponse,
    summary="Run untrusted content through the full Bulwark defense stack",
    description=(
        "The primary Bulwark endpoint. Runs the complete defense pipeline: "
        "sanitizer, trust boundary, detection models, LLM two-phase execution "
        "(if configured), bridge guard, and canary check.\n\n"
        "Returns 200 with the safe result when content passes all checks. "
        "Returns 422 when injection is detected — content does not pass through."
    ),
    responses={
        422: {"description": "Injection detected — content blocked"},
    },
)
async def api_clean(req: CleanRequest):
    """Run the full defense stack. Returns 200 (safe) or 422 (blocked)."""
    import time as _time
    from pathlib import Path
    from bulwark.pipeline import Pipeline
    from bulwark.events import CollectorEmitter
    from bulwark.dashboard.llm_factory import make_analyze_fn, make_execute_fn
    from bulwark.shortcuts import clean
    from bulwark.trust_boundary import TrustBoundary as _TrustBoundary
    from bulwark.executor import AnalysisGuard as _AnalysisGuard

    from bulwark.dashboard.app import config, _detection_checks

    t0 = _time.time()
    content = req.content
    source = req.source
    collector = CollectorEmitter()

    # Build pipeline from app config (respects dashboard toggles)
    analyze_fn = make_analyze_fn(config.llm_backend)
    execute_fn = make_execute_fn(config.llm_backend)

    sanitizer = Sanitizer(
        normalize_unicode=config.normalize_unicode,
        strip_emoji_smuggling=config.strip_emoji_smuggling,
        strip_bidi=config.strip_bidi,
        max_length=req.max_length,
    ) if config.sanitizer_enabled else None

    trust_boundary = _TrustBoundary() if config.trust_boundary_enabled else None

    analysis_guard = None
    if config.guard_bridge_enabled:
        guard_kwargs = {}
        if config.guard_patterns:
            guard_kwargs["block_patterns"] = config.guard_patterns
        if config.guard_max_length:
            guard_kwargs["max_length"] = config.guard_max_length
        analysis_guard = _AnalysisGuard(**guard_kwargs)

    canary = None
    if config.canary_enabled and config.canary_file:
        cf = Path(config.canary_file)
        if cf.exists():
            canary = CanarySystem.from_file(str(cf))

    pipeline = Pipeline(
        sanitizer=sanitizer,
        trust_boundary=trust_boundary,
        analysis_guard=analysis_guard,
        canary=canary,
        analyze_fn=analyze_fn,
        execute_fn=execute_fn,
        sanitize_bridge=config.sanitize_bridge_enabled,
        guard_bridge=config.guard_bridge_enabled,
        require_json=config.require_json,
        emitter=collector,
    )

    # Determine if sanitizer modified the content
    modified = False
    if sanitizer:
        modified = sanitizer.clean(content) != content

    # Run detection models BEFORE the LLM
    detection_trace = []
    detection_blocked = False
    detection_reason = None

    if _detection_checks and content:
        sanitized_for_detection = sanitizer.clean(content) if sanitizer else content
        step_num = 3  # After sanitizer (1) and trust_boundary (2)
        for model_name, check_fn in _detection_checks.items():
            dt0 = _time.time()
            try:
                check_fn(sanitized_for_detection)
                elapsed = (_time.time() - dt0) * 1000
                detection_trace.append({
                    "step": step_num,
                    "layer": f"detection:{model_name}",
                    "verdict": "passed",
                    "detail": f"{model_name}: clean ({elapsed:.0f}ms)",
                    "detection_model": model_name,
                    "duration_ms": round(elapsed, 1),
                })
            except AnalysisSuspiciousError as e:
                elapsed = (_time.time() - dt0) * 1000
                detection_trace.append({
                    "step": step_num,
                    "layer": f"detection:{model_name}",
                    "verdict": "blocked",
                    "detail": f"{model_name}: {e} ({elapsed:.0f}ms)",
                    "detection_model": model_name,
                    "duration_ms": round(elapsed, 1),
                })
                detection_blocked = True
                detection_reason = f"Detection model {model_name}: {e}"
            step_num += 1

    if detection_blocked:
        # Run sanitizer + trust boundary for the trace, but skip LLM
        pipeline_noop = Pipeline(
            sanitizer=sanitizer,
            trust_boundary=trust_boundary,
            emitter=collector,
        )
        result = await pipeline_noop.run_async(content, source=source)
        trace = list(result.trace) + detection_trace
        for i, entry in enumerate(trace):
            entry["step"] = i + 1

        total_ms = (_time.time() - t0) * 1000
        _emit_event(
            layer="detection",
            verdict="blocked",
            source_id=f"api:clean:{source}",
            detail=f"Blocked: {detection_reason} ({total_ms:.0f}ms)",
            duration_ms=round(total_ms, 1),
        )

        return JSONResponse(
            status_code=422,
            content={
                "blocked": True,
                "block_reason": detection_reason,
                "blocked_at": detection_reason.split(":")[0].strip() if detection_reason else "detection",
                "trace": trace,
                "content_length": len(content),
                "modified": modified,
                "llm_mode": config.llm_backend.mode,
            },
        )

    # Detection passed — run full pipeline with LLM
    result = await pipeline.run_async(content, source=source)

    # Build trace with detection entries inserted after trust_boundary
    trace = list(result.trace)
    insert_idx = 0
    for i, entry in enumerate(trace):
        if entry.get("layer") in ("trust_boundary", "sanitizer"):
            insert_idx = i + 1
        if entry.get("layer") == "analyze":
            insert_idx = i
            break
    for j, det_entry in enumerate(detection_trace):
        trace.insert(insert_idx + j, det_entry)
    for i, entry in enumerate(trace):
        entry["step"] = i + 1

    # Enrich analyze step with LLM backend info
    for entry in trace:
        if entry.get("layer") == "analyze":
            mode = config.llm_backend.mode
            if mode == "anthropic":
                model = config.llm_backend.analyze_model or "claude-haiku-4-5"
                entry["detail"] = f"Phase 1 via Anthropic ({model}): {len(result.analysis)} chars"
                entry["backend"] = "anthropic"
                entry["model"] = model
            elif mode == "openai_compatible":
                model = config.llm_backend.analyze_model or "unknown"
                url = config.llm_backend.base_url or "unknown"
                entry["detail"] = f"Phase 1 via {url} ({model}): {len(result.analysis)} chars"
                entry["backend"] = "openai_compatible"
                entry["model"] = model
            elif not mode or mode == "none":
                entry["detail"] = f"Phase 1 (echo mode, no LLM): {len(result.analysis)} chars"
                entry["backend"] = "echo"

    # Check if pipeline itself blocked (bridge guard, canary, etc.)
    if result.blocked:
        total_ms = (_time.time() - t0) * 1000
        _emit_event(
            layer="pipeline",
            verdict="blocked",
            source_id=f"api:clean:{source}",
            detail=f"Blocked: {result.block_reason} ({total_ms:.0f}ms)",
            duration_ms=round(total_ms, 1),
        )
        return JSONResponse(
            status_code=422,
            content={
                "blocked": True,
                "block_reason": result.block_reason,
                "blocked_at": result.block_reason.split(":")[0].strip() if result.block_reason else "pipeline",
                "trace": trace,
                "content_length": len(content),
                "modified": modified,
                "llm_mode": config.llm_backend.mode,
            },
        )

    # All checks passed — return safe result
    # Use trust-boundary-wrapped sanitized content as the result
    safe_result = clean(
        content,
        source=req.source,
        label=req.label,
        max_length=req.max_length,
        format=req.format,
    ) if not analyze_fn else (result.analysis or "")

    total_ms = (_time.time() - t0) * 1000
    _emit_event(
        layer="sanitizer",
        verdict="modified" if modified else "passed",
        source_id=f"api:clean:{source}",
        detail=f"Clean {source}: {len(content)} -> {len(safe_result)} chars ({total_ms:.0f}ms)",
        duration_ms=round(total_ms, 1),
    )

    return CleanResponse(
        result=safe_result,
        blocked=False,
        source=req.source,
        format=req.format,
        content_length=len(content),
        result_length=len(safe_result),
        modified=modified,
        analysis=result.analysis if analyze_fn else None,
        execution=result.execution if execute_fn else None,
        trace=trace,
        llm_mode=config.llm_backend.mode,
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

    t0 = time.time()
    try:
        guard(req.text, canary=canary)
        elapsed = (time.time() - t0) * 1000
        _emit_event(
            layer="analysis_guard",
            verdict="passed",
            source_id="api:guard",
            detail=f"Guard: {len(req.text)} chars (passed)",
            duration_ms=round(elapsed, 1),
        )
        return GuardResponse(safe=True, text=req.text)
    except AnalysisSuspiciousError as e:
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


# ---------------------------------------------------------------------------
# LLM Backend Management
# ---------------------------------------------------------------------------

@router.post(
    "/llm/test",
    summary="Test the configured LLM backend connection",
)
async def test_llm_connection(req: LLMTestRequest):
    """Test connectivity to the configured LLM backend."""
    from bulwark.dashboard.config import LLMBackendConfig
    from bulwark.dashboard.llm_factory import test_connection

    from bulwark.dashboard.app import config as app_config
    cfg = LLMBackendConfig(
        mode=req.mode or app_config.llm_backend.mode,
        api_key=_resolve_llm_api_key(
            req_api_key=req.api_key,
            req_base_url=req.base_url,
            configured_api_key=app_config.llm_backend.api_key,
            configured_base_url=app_config.llm_backend.base_url,
        ),
        base_url=req.base_url or app_config.llm_backend.base_url,
        analyze_model=req.analyze_model or app_config.llm_backend.analyze_model,
        execute_model=req.execute_model or app_config.llm_backend.execute_model,
    )
    return test_connection(cfg)


@router.post(
    "/llm/models",
    summary="List available models for the configured LLM backend",
)
async def list_llm_models(req: LLMModelsRequest):
    """Return models available for the given backend configuration."""
    from bulwark.dashboard.config import LLMBackendConfig
    from bulwark.dashboard.llm_factory import list_models

    from bulwark.dashboard.app import config as app_config
    cfg = LLMBackendConfig(
        mode=req.mode or app_config.llm_backend.mode,
        api_key=_resolve_llm_api_key(
            req_api_key=req.api_key,
            req_base_url=req.base_url,
            configured_api_key=app_config.llm_backend.api_key,
            configured_base_url=app_config.llm_backend.base_url,
        ),
        base_url=req.base_url or app_config.llm_backend.base_url,
    )
    return {"models": list_models(cfg)}
