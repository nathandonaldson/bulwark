"""Bulwark HTTP API v1 — language-agnostic endpoints for clean, guard, and pipeline.

These endpoints map directly to the Python convenience functions in bulwark.shortcuts
and the Pipeline class. The spec lives at spec/openapi.yaml.
"""
from __future__ import annotations

import time
from fastapi import APIRouter

from bulwark.dashboard.models import (
    CleanRequest, CleanResponse,
    GuardRequest, GuardResponse,
    LLMModelsRequest, LLMTestRequest, PipelineRequest,
)
from bulwark.shortcuts import clean, guard
from bulwark.sanitizer import Sanitizer
from bulwark.executor import AnalysisSuspiciousError
from bulwark.canary import CanarySystem, CanaryLeakError

router = APIRouter(prefix="/v1", tags=["Bulwark API v1"])


def _emit_event(layer: str, verdict: str, source_id: str = "", detail: str = "", duration_ms: float = 0):
    """Emit a BulwarkEvent to the dashboard's EventDB and SSE subscribers."""
    from bulwark.dashboard.app import db, _subscribers
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
    t0 = time.time()
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
    elapsed = (time.time() - t0) * 1000

    verdict = "modified" if modified else "passed"
    _emit_event(
        layer="sanitizer",
        verdict=verdict,
        source_id=f"api:clean:{req.source}",
        detail=f"Clean {req.source}: {len(req.content)} -> {len(result)} chars ({verdict})",
        duration_ms=round(elapsed, 1),
    )

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

    # Fall back to env var / app config for fields not provided in the request
    from bulwark.dashboard.app import config as app_config
    cfg = LLMBackendConfig(
        mode=req.mode or app_config.llm_backend.mode,
        api_key=req.api_key if req.api_key and "..." not in req.api_key else app_config.llm_backend.api_key,
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
        api_key=req.api_key if req.api_key and "..." not in req.api_key else app_config.llm_backend.api_key,
        base_url=req.base_url or app_config.llm_backend.base_url,
    )
    return {"models": list_models(cfg)}


@router.post(
    "/pipeline",
    summary="Run content through the full Bulwark pipeline with LLM",
    description=(
        "Runs untrusted content through the complete Bulwark pipeline including "
        "LLM-backed two-phase execution (if configured), detection models "
        "(ProtectAI, PromptGuard), and canary token checks. Returns full pipeline trace."
    ),
)
async def run_pipeline(req: PipelineRequest):
    """Run the full pipeline with the configured LLM backend and detection models."""
    import time as _time
    from pathlib import Path
    from bulwark.pipeline import Pipeline
    from bulwark.events import CollectorEmitter
    from bulwark.dashboard.config import BulwarkConfig
    from bulwark.dashboard.llm_factory import make_analyze_fn, make_execute_fn

    content = req.content
    source = req.source

    from bulwark.dashboard.app import config as app_config
    config = app_config
    collector = CollectorEmitter()

    analyze_fn = make_analyze_fn(config.llm_backend)
    execute_fn = make_execute_fn(config.llm_backend)

    # Build pipeline from app config (respects dashboard toggles)
    from bulwark.sanitizer import Sanitizer as _Sanitizer
    from bulwark.trust_boundary import TrustBoundary as _TrustBoundary
    from bulwark.executor import AnalysisGuard as _AnalysisGuard

    sanitizer = _Sanitizer(
        normalize_unicode=config.normalize_unicode,
        strip_emoji_smuggling=config.strip_emoji_smuggling,
        strip_bidi=config.strip_bidi,
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

    # Run detection models on the SANITIZED INPUT before sending to LLM.
    # If detection catches injection, skip the LLM call entirely.
    from bulwark.dashboard.app import _detection_checks
    detection_trace = []
    detection_blocked = False
    detection_reason = None

    if _detection_checks and content:
        # Run detection on sanitized content (after pipeline sanitizer)
        sanitized_content = content
        if pipeline.sanitizer:
            sanitized_content = pipeline.sanitizer.clean(content)

        step_num = 3  # After sanitizer (1) and trust_boundary (2)
        for model_name, check_fn in _detection_checks.items():
            t0 = _time.time()
            try:
                check_fn(sanitized_content)
                elapsed = (_time.time() - t0) * 1000
                detection_trace.append({
                    "step": step_num,
                    "layer": f"detection:{model_name}",
                    "verdict": "passed",
                    "detail": f"{model_name}: clean ({elapsed:.0f}ms)",
                    "detection_model": model_name,
                    "duration_ms": round(elapsed, 1),
                })
            except AnalysisSuspiciousError as e:
                elapsed = (_time.time() - t0) * 1000
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
        # Detection caught it — run pipeline for sanitizer + trust boundary trace only,
        # but skip the LLM call. Reuse the config-aware pipeline (no Pipeline.default()).
        pipeline_noop = Pipeline(
            sanitizer=sanitizer,
            trust_boundary=trust_boundary,
            emitter=collector,
        )
        result = await pipeline_noop.run_async(content, source=source)
        trace = list(result.trace) + detection_trace
        # Renumber steps
        for i, entry in enumerate(trace):
            entry["step"] = i + 1
        return {
            "payload_length": len(content),
            "analysis": None,
            "execution": None,
            "blocked": True,
            "block_reason": detection_reason,
            "neutralized": result.neutralized,
            "blocked_at": detection_reason.split(":")[0].strip() if detection_reason else None,
            "neutralized_by": "Sanitizer" if result.neutralized else None,
            "trace": trace,
            "llm_mode": config.llm_backend.mode,
        }

    # Detection passed (or no detection models active) — run full pipeline with LLM
    result = await pipeline.run_async(content, source=source)

    # Build trace: pipeline steps, then insert detection entries after trust_boundary
    trace = list(result.trace)

    # Find where to insert detection entries (after trust_boundary, before analyze)
    insert_idx = 0
    for i, entry in enumerate(trace):
        if entry.get("layer") in ("trust_boundary", "sanitizer"):
            insert_idx = i + 1
        if entry.get("layer") == "analyze":
            insert_idx = i
            break

    # Insert detection trace entries
    for j, det_entry in enumerate(detection_trace):
        trace.insert(insert_idx + j, det_entry)

    # Renumber all steps
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
                entry["url"] = url
            elif not mode or mode == "none":
                entry["detail"] = f"Phase 1 (echo mode, no LLM): {len(result.analysis)} chars"
                entry["backend"] = "echo"

    return {
        "payload_length": len(content),
        "analysis": result.analysis,
        "execution": result.execution,
        "blocked": result.blocked,
        "block_reason": result.block_reason,
        "neutralized": result.neutralized,
        "blocked_at": result.block_reason.split(":")[0].strip() if result.block_reason else None,
        "neutralized_by": "Sanitizer" if result.neutralized else None,
        "trace": trace,
        "llm_mode": config.llm_backend.mode,
    }
