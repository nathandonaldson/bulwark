"""Bulwark HTTP API v1 — language-agnostic endpoints.

v2.0.0 (ADR-031): /v1/clean is sanitize → (optional detector) → wrap.
/v1/guard is the caller-side output check. No LLM calls. No /v1/llm/*.
"""
from __future__ import annotations

import logging
import time
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from bulwark.dashboard.config import env_truthy
from bulwark.dashboard.models import (
    CleanRequest, CleanResponse,
    GuardRequest, GuardResponse,
)
from bulwark.shortcuts import guard as shortcut_guard
from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary, BoundaryFormat
from bulwark.guard import SuspiciousPatternError
from bulwark.canary import CanarySystem, CanaryLeakError
from bulwark.decoders import DecodedVariant, decode_rescan_variants
from bulwark.detector_chain import run_detector_chain

logger = logging.getLogger(__name__)

_FORMAT_MAP = {
    "xml": BoundaryFormat.XML,
    "markdown": BoundaryFormat.MARKDOWN_FENCE,
    "delimiter": BoundaryFormat.DELIMITER,
}

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
    degraded_explicit_opt_in = env_truthy("BULWARK_ALLOW_NO_DETECTORS")
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

    # ADR-047 / Phase H: decode-rescan fan-out. Build variant list once;
    # the detector chain runs over each non-skipped variant. Trust boundary
    # still wraps the *original* cleaned text (NG-CLEAN-DECODE-VARIANTS-
    # PRESERVED-001) — variants are a detection-only fan-out.
    decode_b64 = bool(getattr(config, "decode_base64", False))
    variants: list[DecodedVariant] = decode_rescan_variants(
        cleaned, decode_base64=decode_b64,
    ) if cleaned else []
    decoded_variants_trace: list[dict] = [
        {
            "label": v.label,
            "depth": v.depth,
            "skipped": v.skipped,
            **({"skip_reason": v.skip_reason} if v.skipped and v.skip_reason else {}),
        }
        for v in variants
    ]

    # ADR-052 / G-CLEAN-DECODE-CANDIDATE-CAP-FAIL-CLOSED-001: fail closed
    # when the base64 decode-rescan candidate cap is exhausted. The cap
    # (`_CANDIDATE_CAP` in `bulwark.decoders`) is a CPU-budget protection;
    # silently dropping work past the limit lets an attacker push their
    # malicious base64 candidate past the 16th slot and bypass detection.
    # Extends ADR-040's "fail closed when detection is impossible" semantic
    # to "fail closed when detection budget is exhausted".
    if any(v.skipped and v.skip_reason == "candidate_cap" for v in variants):
        step += 1
        trace.append({
            "step": step,
            "layer": "decoders",
            "verdict": "blocked",
            "detail": "Base64 candidate cap exceeded during decode-rescan",
        })
        total_ms = (time.time() - t0) * 1000
        _emit_event(
            layer="detection", verdict="blocked",
            source_id=f"api:clean:{source}",
            detail="Blocked by decoder: base64 candidate cap exceeded",
            duration_ms=round(total_ms, 1),
        )
        return JSONResponse(
            status_code=422,
            content={
                "blocked": True,
                "block_reason": "Decoder blocked: base64 candidate cap exceeded",
                "blocked_at": "decoders",
                "trace": trace,
                "decoded_variants": decoded_variants_trace,
                "blocked_at_variant": None,
                "content_length": len(content),
                "modified": modified,
            },
        )

    # Step 2 + 2b: detectors + LLM judge — delegated to bulwark.detector_chain
    # (G-CLEAN-DETECTOR-CHAIN-PARITY-001 / ADR-048). The shared helper runs
    # all detectors first (cheaper short-circuits the slower judge), then
    # the judge on every non-skipped variant. ERROR / UNPARSEABLE in
    # fail-open mode is logged + traced per variant but does NOT short-
    # circuit (G-CLEAN-DECODE-JUDGE-ALL-VARIANTS-001 / H.2).
    detector_verdict = None
    judge_enabled_runtime = bool(config.judge_backend.enabled)
    judge_callable = None
    jcfg = config.judge_backend
    if judge_enabled_runtime and cleaned:
        from bulwark.detectors.llm_judge import classify

        def _judge_call(text: str):
            v = classify(jcfg, text)
            # Coerce sub-threshold INJECTION to SAFE so the chain doesn't
            # block on a low-confidence verdict (existing dashboard
            # threshold semantic).
            if v.verdict == "INJECTION" and v.confidence < jcfg.threshold:
                from bulwark.detectors.llm_judge import JudgeVerdict
                return JudgeVerdict(
                    verdict="SAFE", confidence=v.confidence, reason=v.reason,
                    latency_ms=v.latency_ms, raw=None,
                )
            return v

        judge_callable = _judge_call

    # Each registered detector check carries a `__bulwark_name__`
    # attribute set at registration time (see `app.py`'s
    # `_register_detection_check`) so the helper can attribute trace
    # entries by model name. Defensive fallback if the attribute is
    # somehow missing on a check the dashboard registered another way.
    detector_callables: list = []
    if _detection_checks and cleaned:
        for model_name, check_fn in _detection_checks.items():
            if not getattr(check_fn, "__bulwark_name__", None):
                check_fn.__bulwark_name__ = f"detection:{model_name}"
            detector_callables.append(check_fn)

    chain_result = run_detector_chain(
        variants=variants if cleaned else [],
        detectors=detector_callables,
        judge=judge_callable,
        judge_fail_open=bool(jcfg.fail_open) if judge_enabled_runtime else True,
    )

    # Build per-detector trace entries from the helper's results.
    # Detector-major iteration in the helper produces one DetectorResult
    # per (detector, variant); we collapse to ONE trace entry per detector
    # (block record if any, otherwise the last pass record), preserving
    # the pre-refactor trace shape.
    detector_indices = sorted({r.detector_index for r in chain_result.detector_results})
    detector_block_record = None
    for det_index in detector_indices:
        step += 1
        results_for_detector = [
            r for r in chain_result.detector_results
            if r.detector_index == det_index
        ]
        block_record = next((r for r in results_for_detector if not r.passed), None)
        # Sum duration across all variants for this detector — operators
        # see the full per-detector cost rather than just the last variant.
        elapsed = sum(r.duration_ms for r in results_for_detector)
        # Detector name from the callable's __bulwark_name__ (set above);
        # fall back to "detection:<index>" if missing (defensive).
        layer_name = (
            results_for_detector[0].detector_name
            or f"detection:{det_index}"
        )
        model_name = layer_name.replace("detection:", "", 1)
        if block_record is None:
            # Pass record of last variant — mirrors pre-refactor "trace
            # the result of the last (or only) variant" behaviour.
            last_pass = results_for_detector[-1]
            res = last_pass.result or {}
            max_score = res.get("max_score")
            n_windows = res.get("n_windows")
            detail = f"{model_name}: clean"
            if max_score is not None:
                detail += f" (max={max_score:.3f}"
                if n_windows and n_windows > 1:
                    detail += f", {n_windows} windows"
                detail += ")"
            detail += f" ({elapsed:.0f}ms)"
            trace_entry = {
                "step": step, "layer": layer_name,
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
            detector_verdict = {
                "label": res.get("top_label") or "SAFE",
                "score": round(max_score, 4) if max_score is not None else None,
            }
        else:
            detector_block_record = block_record
            e = block_record.error
            max_score = getattr(e, "max_score", None)
            n_windows = getattr(e, "n_windows", None)
            window_index = getattr(e, "window_index", None)
            variant_suffix = (
                f" variant={block_record.variant_label}"
                if block_record.variant_label
                and block_record.variant_label != "original"
                else ""
            )
            trace_entry = {
                "step": step, "layer": layer_name,
                "verdict": "blocked",
                "detail": f"{model_name}: {e} ({elapsed:.0f}ms){variant_suffix}",
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
            # Detector blocks short-circuit — emit + return.
            total_ms = (time.time() - t0) * 1000
            _emit_event(
                layer="detection", verdict="blocked",
                source_id=f"api:clean:{source}",
                detail=f"Blocked by {model_name}: {e}{variant_suffix}",
                duration_ms=round(total_ms, 1),
            )
            return JSONResponse(
                status_code=422,
                content={
                    "blocked": True,
                    "block_reason": f"Detector {model_name}: {e}",
                    "blocked_at": layer_name,
                    "trace": trace,
                    "decoded_variants": decoded_variants_trace,
                    "blocked_at_variant": block_record.variant_label,
                    "content_length": len(content),
                    "modified": modified,
                },
            )

    # Build judge trace entries from the helper's judge_results. One trace
    # entry per variant the judge saw — replaces the pre-refactor's single
    # collapsed entry. This is the H.1 observability win: operators can
    # see exactly which variants the judge ran on, including ERROR /
    # UNPARSEABLE results that were previously hidden by the short-circuit.
    if chain_result.judge_results:
        for jr in chain_result.judge_results:
            step += 1
            trace_layer = "detection:llm_judge"
            variant_suffix = (
                f" variant={jr.variant_label}"
                if jr.variant_label and jr.variant_label != "original"
                else ""
            )
            if jr.blocked and jr.verdict == "INJECTION":
                # NG-JUDGE-004 / ADR-037: do NOT include reason in trace detail.
                trace.append({
                    "step": step, "layer": trace_layer, "verdict": "blocked",
                    "detail": f"LLM judge: INJECTION ({jr.confidence:.2f}) ({jr.latency_ms:.0f}ms){variant_suffix}",
                    "detection_model": "llm_judge",
                    "duration_ms": round(jr.latency_ms, 1),
                })
                total_ms = (time.time() - t0) * 1000
                _emit_event(
                    layer="detection", verdict="blocked",
                    source_id=f"api:clean:{source}",
                    detail=f"Blocked by llm_judge (confidence={jr.confidence:.2f}){variant_suffix}",
                    duration_ms=round(total_ms, 1),
                )
                return JSONResponse(
                    status_code=422,
                    content={
                        "blocked": True,
                        "block_reason": f"Detector llm_judge: INJECTION ({jr.confidence:.2f})",
                        "blocked_at": "detection:llm_judge",
                        "trace": trace,
                        "decoded_variants": decoded_variants_trace,
                        "blocked_at_variant": jr.variant_label,
                        "content_length": len(content),
                        "modified": modified,
                    },
                )
            if jr.blocked and jr.verdict in ("ERROR", "UNPARSEABLE"):
                # Fail-closed path.
                label = "unreachable" if jr.verdict == "ERROR" else "unparseable response"
                trace.append({
                    "step": step, "layer": trace_layer, "verdict": "blocked",
                    "detail": f"LLM judge {label} (fail-closed){variant_suffix}",
                    "detection_model": "llm_judge",
                    "duration_ms": round(jr.latency_ms, 1),
                })
                total_ms = (time.time() - t0) * 1000
                _emit_event(
                    layer="detection", verdict="blocked",
                    source_id=f"api:clean:{source}",
                    detail=f"Blocked by llm_judge ({label}, fail-closed){variant_suffix}",
                    duration_ms=round(total_ms, 1),
                )
                return JSONResponse(
                    status_code=422,
                    content={
                        "blocked": True,
                        "block_reason": f"Detector llm_judge {label}",
                        "blocked_at": "detection:llm_judge",
                        "trace": trace,
                        "decoded_variants": decoded_variants_trace,
                        "blocked_at_variant": jr.variant_label,
                        "content_length": len(content),
                        "modified": modified,
                    },
                )
            if jr.verdict in ("ERROR", "UNPARSEABLE"):
                # Fail-open path: log + record, no block.
                label = "unreachable" if jr.verdict == "ERROR" else "unparseable response"
                trace.append({
                    "step": step, "layer": trace_layer, "verdict": "passed",
                    "detail": f"LLM judge {label} (fail-open) ({jr.latency_ms:.0f}ms){variant_suffix}",
                    "detection_model": "llm_judge",
                    "duration_ms": round(jr.latency_ms, 1),
                })
            else:
                # SAFE — record per-variant trace entry.
                trace.append({
                    "step": step, "layer": trace_layer, "verdict": "passed",
                    "detail": f"LLM judge: {jr.verdict} ({jr.confidence:.2f}) ({jr.latency_ms:.0f}ms){variant_suffix}",
                    "detection_model": "llm_judge",
                    "duration_ms": round(jr.latency_ms, 1),
                })
                detector_verdict = {"label": jr.verdict, "score": jr.confidence}

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
        # ADR-047 / Phase H: surface variants and the (None on 200) blocked-at
        # label so operators can audit decode decisions on every request.
        decoded_variants=decoded_variants_trace,
        blocked_at_variant=None,
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
