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

    # Use a mock analyze_fn that returns the input as-is (we're testing defenses, not LLM output)
    pipeline = Pipeline.default(
        analyze_fn=lambda prompt: payload,  # Echo payload as "analysis" to test guard
        canary=canary,
        emitter=collector,
    )

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


@app.post("/api/garak/run")
async def run_garak():
    """Run Garak probes and return results. Events are emitted to the dashboard."""
    from bulwark.integrations.garak import GarakAdapter
    from bulwark.events import WebhookEmitter

    emitter = WebhookEmitter("http://127.0.0.1:3000/api/events")

    try:
        adapter = GarakAdapter(emitter=emitter)
        summary = adapter.run()
        # Update integration status
        if "garak" not in config.integrations:
            config.integrations["garak"] = IntegrationConfig()
        config.integrations["garak"].installed = True
        config.integrations["garak"].last_used = __import__("time").time()
        config.save()
        return {
            "status": "complete",
            "total": summary.total,
            "passed": summary.passed,
            "failed": summary.failed,
            "pass_rate": summary.pass_rate,
            "probes_tested": summary.probes_tested,
        }
    except FileNotFoundError:
        return {"status": "error", "message": "Garak not installed. Run: pip install garak"}
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}
    except Exception as e:
        return {"status": "error", "message": f"Unexpected error: {type(e).__name__}"}
