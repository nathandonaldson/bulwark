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

    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from bulwark import Sanitizer, TrustBoundary, CanarySystem
    from bulwark.executor import AnalysisGuard, AnalysisSuspiciousError
    from bulwark.events import CollectorEmitter, Layer

    collector = CollectorEmitter()
    trace = []
    neutralized = False  # True if any layer stripped/modified malicious content

    # Step 1: Analysis Guard (check RAW input BEFORE sanitization)
    # This catches patterns that the sanitizer would strip (like </analysis_output>)
    guard = AnalysisGuard(emitter=collector)
    guard_verdict = "passed"
    guard_detail = ""
    try:
        guard.check(payload)
        guard_events = [e for e in collector.events if e.layer == Layer.ANALYSIS_GUARD]
        guard_detail = guard_events[-1].detail if guard_events else "All patterns passed"
    except AnalysisSuspiciousError as ex:
        guard_verdict = "blocked"
        guard_detail = str(ex)
    trace.append({
        "step": 1, "name": "Analysis Guard", "layer": "analysis_guard",
        "verdict": guard_verdict,
        "detail": guard_detail,
    })

    # Step 2: Sanitizer
    collector.clear()
    sanitizer = Sanitizer(emitter=collector)
    cleaned = sanitizer.clean(payload)
    san_events = [e for e in collector.events if e.layer == Layer.SANITIZER]
    san_verdict = san_events[-1].verdict.value if san_events else "passed"
    if san_verdict == "modified":
        neutralized = True
    trace.append({
        "step": 2, "name": "Sanitizer", "layer": "sanitizer",
        "verdict": san_verdict,
        "detail": san_events[-1].detail if san_events else "Clean",
        "output_preview": cleaned[:200],
    })

    # Step 3: Trust Boundary
    collector.clear()
    boundary = TrustBoundary(emitter=collector)
    wrapped = boundary.wrap(cleaned, source="test", label="input")
    tb_events = [e for e in collector.events if e.layer == Layer.TRUST_BOUNDARY]
    trace.append({
        "step": 3, "name": "Trust Boundary", "layer": "trust_boundary",
        "verdict": "passed",
        "detail": tb_events[-1].detail if tb_events else "Wrapped",
        "output_preview": wrapped[:200],
    })

    # Step 4: Canary Check (use real canary tokens if available)
    collector.clear()
    canary_file = Path(__file__).parent.parent.parent / "knowledge" / "comms" / "canaries.json"
    if canary_file.exists():
        canary = CanarySystem.from_file(str(canary_file))
    else:
        canary = CanarySystem()
        canary.generate("test_data")
    canary.emitter = collector
    result = canary.check(payload)  # Check raw input (encoding-resistant catches base64)
    if not result.leaked:
        result = canary.check(cleaned)  # Also check cleaned
    trace.append({
        "step": 4, "name": "Canary Check", "layer": "canary",
        "verdict": "blocked" if result.leaked else "passed",
        "detail": f"{'Leaked from: ' + ', '.join(result.sources) if result.leaked else 'Clean: 0/' + str(len(canary.tokens)) + ' tokens found'}",
    })

    blocked = guard_verdict == "blocked" or result.leaked

    return {
        "payload_length": len(payload),
        "blocked": blocked,
        "neutralized": neutralized and not blocked,  # Modified but not blocked
        "blocked_at": next((t["name"] for t in trace if t["verdict"] == "blocked"), None),
        "neutralized_by": "Sanitizer" if neutralized and not blocked else None,
        "trace": trace,
    }


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
