"""Bulwark Dashboard — FastAPI application."""
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import json
import time
import os
from pathlib import Path
from typing import Optional

from dashboard.db import EventDB
from dashboard.config import BulwarkConfig, AVAILABLE_INTEGRATIONS, IntegrationConfig

app = FastAPI(title="Bulwark Dashboard", version="0.1.0")

from dashboard.api_v1 import router as v1_router
app.include_router(v1_router)
db = EventDB()
config = BulwarkConfig.load()

# SSE subscribers
_subscribers: list[asyncio.Queue] = []

# Serve static frontend
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    index_path = _static_dir / "index.html"
    if index_path.exists():
        return index_path.read_text()
    return "<h1>Bulwark Dashboard</h1><p>Static files not found. Place index.html in dashboard/static/</p>"


@app.post("/api/events")
async def ingest_events(request: Request):
    """Ingest events from WebhookEmitter."""
    body = await request.json()
    events = body.get("events", [])
    if not events:
        return {"ingested": 0}
    count = db.insert_batch(events)
    # Notify SSE subscribers
    for event in events:
        for q in _subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass
    return {"ingested": count}


@app.get("/api/events")
async def query_events(
    layer: Optional[str] = None,
    verdict: Optional[str] = None,
    since: Optional[float] = None,
    hours: Optional[float] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
):
    """Query stored events with filters."""
    since_ts = since
    if hours and not since:
        since_ts = time.time() - (hours * 3600)
    return db.query(layer=layer, verdict=verdict, since=since_ts, limit=limit, offset=offset)


@app.get("/api/metrics")
async def get_metrics(hours: int = Query(default=24, le=720)):
    """Aggregated metrics for dashboard widgets."""
    return db.metrics(hours=hours)


@app.get("/api/timeseries")
async def get_timeseries(
    hours: int = Query(default=24, le=720),
    buckets: int = Query(default=24, le=100),
    layer: Optional[str] = None,
):
    """Time-series event counts for sparkline charts."""
    return db.timeseries(hours=hours, buckets=buckets, layer=layer)


@app.get("/api/stream")
async def event_stream():
    """SSE endpoint for real-time event streaming."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _subscribers.append(queue)

    async def generate():
        try:
            while True:
                event = await queue.get()
                yield f"data: {json.dumps(event)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            _subscribers.remove(queue)

    return StreamingResponse(generate(), media_type="text/event-stream")


@app.post("/api/test")
async def test_pipeline(request: Request):
    """Run a payload through the Bulwark pipeline and return per-layer trace."""
    body = await request.json()
    payload = body.get("payload", "")

    from bulwark.pipeline import Pipeline
    from bulwark import CanarySystem
    from bulwark.events import CollectorEmitter

    collector = CollectorEmitter()

    # Load real canary tokens if available
    canary_file = Path(__file__).parent.parent.parent / "knowledge" / "comms" / "canaries.json"
    canary = CanarySystem.from_file(str(canary_file)) if canary_file.exists() else None

    # Build pipeline from config (respects dashboard toggles) or defaults
    config_path = Path(__file__).parent.parent / "bulwark-config.yaml"
    if config_path.exists():
        pipeline = Pipeline.from_config(
            str(config_path),
            analyze_fn=lambda prompt: payload,  # Echo payload as "analysis" to test guard
        )
        pipeline.emitter = collector
        if canary:
            pipeline.canary = canary
    else:
        pipeline = Pipeline.default(
            analyze_fn=lambda prompt: payload,
            canary=canary,
            emitter=collector,
        )

    # Attach any active detection model checks
    if _detection_checks and pipeline.analysis_guard is not None:
        pipeline.analysis_guard.custom_checks = list(_detection_checks.values())

    result = await pipeline.run_async(payload, source="test")

    return {
        "payload_length": len(payload),
        "blocked": result.blocked,
        "neutralized": result.neutralized,
        "blocked_at": result.block_reason.split(":")[0].strip() if result.block_reason else None,
        "neutralized_by": "Sanitizer" if result.neutralized else None,
        "trace": result.trace,
    }


@app.get("/api/pipeline-status")
async def pipeline_status():
    """Show what layers the pipeline would use based on current config."""
    from bulwark.pipeline import Pipeline

    try:
        pipeline = Pipeline.from_config(str(Path(__file__).parent.parent / "bulwark-config.yaml"))
        return {
            "sanitizer": pipeline.sanitizer is not None,
            "trust_boundary": pipeline.trust_boundary is not None,
            "analysis_guard": pipeline.analysis_guard is not None,
            "canary": pipeline.canary is not None,
            "guard_bridge": pipeline.guard_bridge,
            "sanitize_bridge": pipeline.sanitize_bridge,
            "require_json": pipeline.require_json,
        }
    except Exception:
        return {"error": "Failed to load pipeline configuration", "using_defaults": True}


@app.get("/api/config")
async def get_config():
    """Get current Bulwark configuration."""
    return config.to_dict()


@app.put("/api/config")
async def update_config(request: Request):
    """Update Bulwark configuration (partial update)."""
    data = await request.json()
    config.update_from_dict(data)
    config.save()
    return config.to_dict()


@app.get("/api/integrations")
async def list_integrations():
    """List available integrations with their status."""
    result = {}
    for key, info in AVAILABLE_INTEGRATIONS.items():
        int_config = config.integrations.get(key, IntegrationConfig())
        result[key] = {
            **info,
            "enabled": int_config.enabled,
            "installed": int_config.installed,
            "last_used": int_config.last_used,
        }
    return result


# Loaded detection models (kept in memory while dashboard runs)
_detection_checks: dict[str, object] = {}


@app.post("/api/integrations/{name}/activate")
async def activate_integration(name: str):
    """Load a detection model and register it as an AnalysisGuard check.

    This actually loads the model into memory (not just toggling a config flag).
    """
    import concurrent.futures

    if name == "promptguard":
        model_key = "promptguard"
        model_label = "PromptGuard-86M"
    elif name == "protectai":
        model_key = "protectai"
        model_label = "ProtectAI DeBERTa"
    elif name == "piguard":
        return {"status": "error", "message": "PIGuard integration not yet implemented"}
    elif name == "llm_guard":
        return {"status": "error", "message": "LLM Guard integration not yet implemented"}
    elif name == "nemo":
        return {"status": "error", "message": "NeMo Guardrails integration not yet implemented"}
    else:
        return {"status": "error", "message": f"Unknown integration: {name}"}

    try:
        from bulwark.integrations.promptguard import load_detector, create_check

        # Load model in thread (can take a few seconds on first download)
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            detector = await loop.run_in_executor(pool, lambda: load_detector(model_key))

        check_fn = create_check(detector)
        _detection_checks[name] = check_fn

        # Update config
        if name not in config.integrations:
            config.integrations[name] = IntegrationConfig()
        config.integrations[name].enabled = True
        config.integrations[name].installed = True
        config.integrations[name].last_used = time.time()
        config.save()

        return {
            "status": "active",
            "model": model_label,
            "message": f"{model_label} loaded and registered as bridge check",
        }
    except ImportError as e:
        return {"status": "error", "message": f"Missing dependency: {e}. Run: pip install transformers torch"}
    except OSError as e:
        msg = str(e)
        if "gated" in msg.lower() or "awaiting" in msg.lower():
            return {"status": "error", "message": f"{model_label} requires HuggingFace approval. Check https://huggingface.co/meta-llama/Prompt-Guard-86M"}
        return {"status": "error", "message": f"Failed to load model: {msg[:200]}"}
    except Exception as e:
        return {"status": "error", "message": f"Unexpected error: {type(e).__name__}: {str(e)[:200]}"}


@app.get("/api/integrations/active-checks")
async def active_checks():
    """List currently loaded detection models."""
    return {
        "active": list(_detection_checks.keys()),
        "count": len(_detection_checks),
    }


@app.put("/api/integrations/{name}")
async def update_integration(name: str, request: Request):
    """Enable/disable an integration."""
    if name not in AVAILABLE_INTEGRATIONS:
        return {"error": f"Unknown integration: {name}"}, 404
    data = await request.json()
    if name not in config.integrations:
        config.integrations[name] = IntegrationConfig()
    for k, v in data.items():
        if hasattr(config.integrations[name], k):
            setattr(config.integrations[name], k, v)
    config.save()
    int_config = config.integrations[name]
    return {
        **AVAILABLE_INTEGRATIONS[name],
        "enabled": int_config.enabled,
        "installed": int_config.installed,
        "last_used": int_config.last_used,
    }


@app.delete("/api/events")
async def prune_events(days: int = Query(default=30)):
    """Prune events older than N days."""
    count = db.prune(days=days)
    return {"pruned": count}


# Background task state (Garak and Red Team)
_garak_task: Optional[asyncio.Task] = None
_garak_result: dict = {}
_redteam_task: Optional[asyncio.Task] = None
_redteam_result: dict = {}


@app.post("/api/garak/run")
async def run_garak():
    """Start Garak probes in the background. Poll /api/garak/status for results."""
    global _garak_task, _garak_result

    if _garak_task and not _garak_task.done():
        return {"status": "running", "message": "Garak is already running"}

    _garak_result = {"status": "running"}
    _garak_start_time = time.time()

    async def _run_in_background():
        global _garak_result
        from bulwark.integrations.garak import GarakAdapter
        from bulwark.events import WebhookEmitter
        import concurrent.futures

        emitter = WebhookEmitter("http://127.0.0.1:3000/api/events")
        try:
            adapter = GarakAdapter(emitter=emitter)
            # Run blocking subprocess in a thread
            loop = asyncio.get_running_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                summary = await loop.run_in_executor(pool, adapter.run)
            if "garak" not in config.integrations:
                config.integrations["garak"] = IntegrationConfig()
            config.integrations["garak"].installed = True
            config.integrations["garak"].last_used = __import__("time").time()
            config.save()
            _garak_result = {
                "status": "complete",
                "total": summary.total,
                "passed": summary.passed,
                "failed": summary.failed,
                "pass_rate": summary.pass_rate,
                "probes_tested": summary.probes_tested,
                "duration_s": round(__import__("time").time() - _garak_start_time, 1),
                "results": [
                    {
                        "probe": r.probe,
                        "prompt": r.prompt[:200],
                        "output": r.output[:200] if r.output else "",
                        "detector": r.detector,
                        "passed": r.passed,
                        "score": r.score,
                    }
                    for r in summary.results
                ],
            }
        except Exception as e:
            _garak_result = {"status": "error", "message": str(e)}

    _garak_task = asyncio.create_task(_run_in_background())
    return {"status": "started", "message": "Garak probes started. Poll /api/garak/status for results."}


@app.get("/api/garak/status")
async def garak_status():
    """Check the status of a running Garak scan."""
    return _garak_result


def _make_emitter():
    from bulwark.events import WebhookEmitter
    return WebhookEmitter("http://127.0.0.1:3000/api/events")


@app.post("/api/redteam/run")
async def run_redteam(request: Request):
    """Start production red team in the background."""
    global _redteam_task, _redteam_result

    if _redteam_task and not _redteam_task.done():
        return {"status": "running", "message": "Red team is already running"}

    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    max_probes = body.get("max_probes", 0)

    _redteam_result = {"status": "running", "completed": 0, "total": 0}

    async def _run_in_background():
        global _redteam_result
        from bulwark.integrations.redteam import ProductionRedTeam
        import concurrent.futures

        # Find project root (parent of bulwark-ai/)
        project_dir = str(Path(__file__).parent.parent.parent)

        def on_progress(completed, total):
            _redteam_result["completed"] = completed
            _redteam_result["total"] = total

        try:
            runner = ProductionRedTeam(
                project_dir=project_dir,
                delay_ms=200,
                max_probes=max_probes,
                emitter=_make_emitter(),
                on_progress=on_progress,
            )
            loop = asyncio.get_running_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                summary = await loop.run_in_executor(pool, runner.run)

            _redteam_result = {
                "status": "complete",
                "total": summary.total,
                "defended": summary.defended,
                "vulnerable": summary.vulnerable,
                "errors": summary.errors,
                "defense_rate": summary.defense_rate,
                "duration_s": summary.duration_s,
                "by_layer": summary.by_layer,
                "by_family": summary.by_family,
                "results": [
                    {
                        "probe_family": r.probe_family,
                        "probe_class": r.probe_class,
                        "payload": r.payload[:200],
                        "llm_response": r.llm_response[:300],
                        "defended": r.defended,
                        "blocked_by": r.blocked_by,
                        "sanitizer_modified": r.sanitizer_modified,
                        "suspicious_flagged": r.suspicious_flagged,
                        "classification": r.classification,
                        "error": r.error,
                    }
                    for r in summary.results
                ],
            }
        except Exception as e:
            _redteam_result = {"status": "error", "message": str(e)}

    _redteam_task = asyncio.create_task(_run_in_background())
    return {"status": "started"}


@app.get("/api/redteam/status")
async def redteam_status():
    """Check status of running red team scan."""
    return _redteam_result


@app.get("/api/integrations/detect")
async def detect_integrations():
    """Check which testing tools are actually installed."""
    results = {}
    try:
        import garak
        results["garak"] = {"installed": True, "version": getattr(garak, "__version__", "unknown")}
    except ImportError:
        results["garak"] = {"installed": False}
    return results
