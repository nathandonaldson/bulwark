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

app = FastAPI(title="Bulwark Dashboard", version="0.1.0")
db = EventDB()

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

    # Step 1: Sanitizer
    sanitizer = Sanitizer(emitter=collector)
    cleaned = sanitizer.clean(payload)
    san_events = [e for e in collector.events if e.layer == Layer.SANITIZER]
    trace.append({
        "step": 1, "name": "Sanitizer", "layer": "sanitizer",
        "verdict": san_events[-1].verdict.value if san_events else "passed",
        "detail": san_events[-1].detail if san_events else "No emitter",
        "output_preview": cleaned[:200],
    })

    # Step 2: Trust Boundary
    collector.clear()
    boundary = TrustBoundary(emitter=collector)
    wrapped = boundary.wrap(cleaned, source="test", label="input")
    tb_events = [e for e in collector.events if e.layer == Layer.TRUST_BOUNDARY]
    trace.append({
        "step": 2, "name": "Trust Boundary", "layer": "trust_boundary",
        "verdict": "passed",
        "detail": tb_events[-1].detail if tb_events else "Wrapped",
        "output_preview": wrapped[:200],
    })

    # Step 3: Analysis Guard
    collector.clear()
    guard = AnalysisGuard(emitter=collector)
    guard_verdict = "passed"
    guard_detail = ""
    try:
        guard.check(cleaned)
        guard_events = [e for e in collector.events if e.layer == Layer.ANALYSIS_GUARD]
        guard_detail = guard_events[-1].detail if guard_events else "All patterns passed"
    except AnalysisSuspiciousError as ex:
        guard_verdict = "blocked"
        guard_detail = str(ex)
    trace.append({
        "step": 3, "name": "Analysis Guard", "layer": "analysis_guard",
        "verdict": guard_verdict,
        "detail": guard_detail,
    })

    # Step 4: Canary Check
    collector.clear()
    canary = CanarySystem(emitter=collector)
    canary.generate("test_data")
    result = canary.check(cleaned)
    trace.append({
        "step": 4, "name": "Canary Check", "layer": "canary",
        "verdict": "blocked" if result.leaked else "passed",
        "detail": f"{'Leaked from: ' + ', '.join(result.sources) if result.leaked else 'Clean: no tokens found'}",
    })

    blocked = guard_verdict == "blocked" or result.leaked

    return {
        "payload_length": len(payload),
        "blocked": blocked,
        "blocked_at": next((t["name"] for t in trace if t["verdict"] == "blocked"), None),
        "trace": trace,
    }


@app.delete("/api/events")
async def prune_events(days: int = Query(default=30)):
    """Prune events older than N days."""
    count = db.prune(days=days)
    return {"pruned": count}
