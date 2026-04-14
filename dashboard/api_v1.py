"""Bulwark HTTP API v1 — language-agnostic endpoints for clean, guard, and pipeline.

These endpoints map directly to the Python convenience functions in bulwark.shortcuts
and the Pipeline class. The spec lives at spec/openapi.yaml.
"""
from __future__ import annotations

from fastapi import APIRouter, Request

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


# ---------------------------------------------------------------------------
# LLM Backend Management
# ---------------------------------------------------------------------------

@router.post(
    "/llm/test",
    summary="Test the configured LLM backend connection",
)
async def test_llm_connection(request: Request):
    """Test connectivity to the configured LLM backend."""
    from dashboard.config import BulwarkConfig, LLMBackendConfig
    from dashboard.llm_factory import test_connection

    body = await request.json()
    cfg = LLMBackendConfig(
        mode=body.get("mode", "none"),
        api_key=body.get("api_key", ""),
        base_url=body.get("base_url", ""),
        analyze_model=body.get("analyze_model", ""),
        execute_model=body.get("execute_model", ""),
    )
    return test_connection(cfg)


@router.post(
    "/pipeline",
    summary="Run content through the full Bulwark pipeline with LLM",
    description=(
        "Runs untrusted content through the complete Bulwark pipeline including "
        "LLM-backed two-phase execution (if configured), detection models "
        "(ProtectAI, PromptGuard), and canary token checks. Returns full pipeline trace."
    ),
)
async def run_pipeline(request: Request):
    """Run the full pipeline with the configured LLM backend and detection models."""
    import time as _time
    from pathlib import Path
    from bulwark.pipeline import Pipeline
    from bulwark.events import CollectorEmitter
    from dashboard.config import BulwarkConfig
    from dashboard.llm_factory import make_analyze_fn, make_execute_fn

    body = await request.json()
    content = body.get("content", "")
    source = body.get("source", "external")

    config = BulwarkConfig.load()
    collector = CollectorEmitter()

    analyze_fn = make_analyze_fn(config.llm_backend)
    execute_fn = make_execute_fn(config.llm_backend)

    # Load canary tokens if available
    canary = None
    canary_file = Path(__file__).parent.parent / "knowledge" / "comms" / "canaries.json"
    if not canary_file.exists():
        canary_file = Path(__file__).parent.parent.parent / "knowledge" / "comms" / "canaries.json"
    if canary_file.exists():
        canary = CanarySystem.from_file(str(canary_file))

    config_path = Path(__file__).parent.parent / "bulwark-config.yaml"
    if config_path.exists():
        pipeline = Pipeline.from_config(str(config_path), analyze_fn=analyze_fn, execute_fn=execute_fn)
        pipeline.emitter = collector
        if canary:
            pipeline.canary = canary
    else:
        pipeline = Pipeline.default(analyze_fn=analyze_fn, execute_fn=execute_fn,
                                    canary=canary, emitter=collector)

    result = await pipeline.run_async(content, source=source)

    # Enrich trace with LLM backend info
    trace = list(result.trace)
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

    # Run detection models individually with per-model trace entries
    from dashboard.app import _detection_checks
    blocked = result.blocked
    block_reason = result.block_reason
    if _detection_checks and result.analysis and not result.blocked:
        step_num = len(trace) + 1
        for model_name, check_fn in _detection_checks.items():
            t0 = _time.time()
            try:
                check_fn(result.analysis)
                elapsed = (_time.time() - t0) * 1000
                trace.append({
                    "step": step_num,
                    "layer": f"detection:{model_name}",
                    "verdict": "passed",
                    "detail": f"{model_name}: clean ({elapsed:.0f}ms)",
                    "detection_model": model_name,
                    "duration_ms": round(elapsed, 1),
                })
            except AnalysisSuspiciousError as e:
                elapsed = (_time.time() - t0) * 1000
                trace.append({
                    "step": step_num,
                    "layer": f"detection:{model_name}",
                    "verdict": "blocked",
                    "detail": f"{model_name}: {e} ({elapsed:.0f}ms)",
                    "detection_model": model_name,
                    "duration_ms": round(elapsed, 1),
                })
                blocked = True
                block_reason = f"Detection model {model_name}: {e}"
            step_num += 1

    return {
        "payload_length": len(content),
        "analysis": result.analysis,
        "execution": result.execution,
        "blocked": blocked,
        "block_reason": block_reason,
        "neutralized": result.neutralized,
        "blocked_at": block_reason.split(":")[0].strip() if block_reason else None,
        "neutralized_by": "Sanitizer" if result.neutralized else None,
        "trace": trace,
        "llm_mode": config.llm_backend.mode,
    }
