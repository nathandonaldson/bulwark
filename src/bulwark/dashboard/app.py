"""Bulwark Dashboard — FastAPI application."""
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import json
import time
import os
from pathlib import Path
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse as StarletteJSONResponse

from bulwark.dashboard.db import EventDB
from bulwark.dashboard.config import BulwarkConfig, AVAILABLE_INTEGRATIONS, IntegrationConfig, get_api_token
from bulwark.dashboard.models import RetestRequest


# Endpoints that never require authentication
_PUBLIC_PATHS = frozenset({
    "/",
    "/healthz",
    "/v1/clean",
    "/v1/guard",
    "/v1/pipeline",
    "/api/auth/login",
})


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Optional bearer token auth. Disabled when BULWARK_API_TOKEN is not set."""

    async def dispatch(self, request: Request, call_next):
        # OPTIONS requests always pass through (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        token = get_api_token()
        if not token:
            # No token configured — auth disabled
            return await call_next(request)

        # Check if this is a public path
        path = request.url.path
        if path in _PUBLIC_PATHS or path.startswith("/static/"):
            return await call_next(request)

        # Check Authorization header
        auth_header = request.headers.get("authorization", "")
        if auth_header == f"Bearer {token}":
            return await call_next(request)

        # Check cookie
        cookie_token = request.cookies.get("bulwark_token", "")
        if cookie_token == token:
            return await call_next(request)

        return StarletteJSONResponse(
            {"error": "Authentication required. Set BULWARK_API_TOKEN and use Authorization: Bearer <token>."},
            status_code=401,
        )


def _read_version() -> str:
    """Read version from VERSION file or package metadata."""
    version_file = Path(__file__).parent.parent.parent.parent / "VERSION"
    if version_file.exists():
        return version_file.read_text().strip()
    try:
        from importlib.metadata import version
        return version("bulwark-shield")
    except Exception:
        return "unknown"


app = FastAPI(title="Bulwark Dashboard", version=_read_version())

# CORS: allow localhost origins so browser-based apps on the same machine can call the API.
# Wildcard ("*") would expose /api/config (which contains API keys) to any website.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(BearerAuthMiddleware)

from bulwark.dashboard.api_v1 import router as v1_router
app.include_router(v1_router)
db = EventDB()
config = BulwarkConfig.load()


@app.get("/healthz")
async def healthz():
    """Liveness probe. Returns 200 with version info."""
    return {
        "status": "ok",
        "version": _read_version(),
        "docker": os.path.exists("/.dockerenv"),
        "env_configured": bool(os.environ.get("BULWARK_LLM_MODE")),
        "auth_required": bool(get_api_token()),
    }


@app.post("/api/auth/login")
async def auth_login(request: Request):
    """Validate token and set HttpOnly cookie for SSE/browser auth."""
    body = await request.json()
    submitted_token = body.get("token", "")
    expected_token = get_api_token()

    if not expected_token:
        return {"ok": True, "message": "Auth not configured"}

    if submitted_token != expected_token:
        return StarletteJSONResponse(
            {"ok": False, "error": "Invalid token"},
            status_code=401,
        )

    response = StarletteJSONResponse({"ok": True, "message": "Authenticated"})
    response.set_cookie(
        key="bulwark_token",
        value=expected_token,
        httponly=True,
        samesite="strict",
        max_age=86400,  # 24 hours
    )
    return response

# SSE subscribers
_subscribers: list[asyncio.Queue] = []

# Serve static frontend
_static_dir = Path(__file__).parent / "static"
if _static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    from fastapi.responses import Response
    index_path = _static_dir / "index.html"
    if index_path.exists():
        return Response(
            content=index_path.read_text(),
            media_type="text/html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )
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

    # Load canary tokens from config path (if set) or skip
    canary = None
    if config.canary_file:
        cf = Path(config.canary_file)
        if cf.exists():
            canary = CanarySystem.from_file(str(cf))

    # Build pipeline from config (respects dashboard toggles)
    # Use configured LLM backend if available, otherwise echo payload for guard testing
    from bulwark.dashboard.llm_factory import make_analyze_fn as _make_analyze
    llm_analyze = _make_analyze(config.llm_backend)
    analyze_fn = llm_analyze if llm_analyze else lambda prompt: payload

    config_path = Path(__file__).parent.parent / "bulwark-config.yaml"
    if config_path.exists():
        pipeline = Pipeline.from_config(
            str(config_path),
            analyze_fn=analyze_fn,
        )
        pipeline.emitter = collector
        if canary:
            pipeline.canary = canary
    else:
        pipeline = Pipeline.default(
            analyze_fn=analyze_fn,
            canary=canary,
            emitter=collector,
        )

    # Don't attach detection checks to the pipeline — we'll run them separately
    # so we can get per-model trace entries
    result = await pipeline.run_async(payload, source="test")

    # Enrich the trace with LLM backend info
    trace = list(result.trace)
    for entry in trace:
        if entry.get("layer") == "analyze":
            mode = config.llm_backend.mode if config.llm_backend.mode != "none" else None
            if mode == "anthropic":
                model = config.llm_backend.analyze_model or "claude-haiku-4-5-20251001"
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
            else:
                entry["detail"] = f"Phase 1 (echo mode, no LLM): {len(result.analysis)} chars"
                entry["backend"] = "echo"

    # Run detection models individually and add separate trace entries
    blocked = result.blocked
    block_reason = result.block_reason
    if _detection_checks and result.analysis and not result.blocked:
        from bulwark.executor import AnalysisSuspiciousError as _ASE
        step_num = len(trace) + 1
        for model_name, check_fn in _detection_checks.items():
            import time as _time
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
            except _ASE as e:
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
        "payload_length": len(payload),
        "blocked": blocked,
        "neutralized": result.neutralized,
        "blocked_at": block_reason.split(":")[0].strip() if block_reason else None,
        "neutralized_by": "Sanitizer" if result.neutralized else None,
        "trace": trace,
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
    error = config.update_from_dict(data)
    if error:
        return {"error": error}
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


@app.on_event("startup")
async def _auto_load_detection_models():
    """Auto-load detection models that were previously activated."""
    import concurrent.futures
    for name in ("protectai", "promptguard"):
        int_cfg = config.integrations.get(name)
        if int_cfg and int_cfg.enabled:
            try:
                from bulwark.integrations.promptguard import load_detector, create_check
                loop = asyncio.get_running_loop()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    detector = await loop.run_in_executor(pool, lambda n=name: load_detector(n))
                _detection_checks[name] = create_check(detector)
                print(f"  Auto-loaded detection model: {name}")
            except Exception as e:
                print(f"  Failed to auto-load {name}: {e}")


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


# ---------------------------------------------------------------------------
# Red Team Tiers
# ---------------------------------------------------------------------------

# Families included in each tier
_QUICK_FAMILIES = frozenset({"promptinject", "latentinjection", "dan"})

_redteam_tiers_cache: Optional[dict] = None


def _compute_redteam_tiers() -> dict:
    """Compute red team tier definitions from installed garak version. Cached.

    Counts actual payloads (not just probe classes) by instantiating each probe.
    Takes ~3s on first call, then cached for the session.
    """
    global _redteam_tiers_cache
    if _redteam_tiers_cache is not None:
        return _redteam_tiers_cache

    try:
        import garak
        from garak._plugins import enumerate_plugins
        version = getattr(garak, "__version__", "unknown")
    except ImportError:
        result = {"garak_installed": False, "garak_version": None, "tiers": []}
        _redteam_tiers_cache = result
        return result

    import importlib
    probes = list(enumerate_plugins("probes"))

    quick_families = set()
    standard_families = set()
    full_families = set()
    quick_count = 0
    standard_count = 0
    full_count = 0

    for name, active in probes:
        parts = name.split(".")
        family = parts[1]
        cls_name = parts[-1]

        # Count actual payloads by instantiating the probe
        try:
            mod = importlib.import_module(f"garak.probes.{family}")
            cls = getattr(mod, cls_name)
            probe = cls()
            n = len(probe.prompts)
        except Exception:
            n = 1  # Fallback: count the class itself

        full_count += n
        full_families.add(family)
        if active:
            standard_count += n
            standard_families.add(family)
            if family in _QUICK_FAMILIES:
                quick_count += n
                quick_families.add(family)

    result = {
        "garak_installed": True,
        "garak_version": version,
        "tiers": [
            {
                "id": "quick",
                "name": "Smoke Test",
                "description": "10 probes across core injection families — verify the pipeline is working",
                "probe_count": min(quick_count, 10),
                "families": sorted(quick_families),
            },
            {
                "id": "standard",
                "name": "Standard Scan",
                "description": "All active probes — injection, encoding, exfiltration, jailbreaks, content safety",
                "probe_count": standard_count,
                "families": sorted(standard_families),
            },
            {
                "id": "full",
                "name": "Full Sweep",
                "description": "Every probe including extended payload variants — comprehensive but slow",
                "probe_count": full_count,
                "families": sorted(full_families),
            },
        ],
    }
    _redteam_tiers_cache = result
    return result


@app.get("/api/redteam/tiers")
async def redteam_tiers():
    """Return red team scan tiers with dynamic probe counts from garak."""
    return _compute_redteam_tiers()


# Background task state (Garak and Red Team)
_garak_task: Optional[asyncio.Task] = None
_garak_result: dict = {}
_redteam_task: Optional[asyncio.Task] = None
_redteam_result: dict = {}
_redteam_runner = None  # Reference to ProductionRedTeam for cancellation


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

        emitter = WebhookEmitter(f"http://127.0.0.1:{_dashboard_port()}/api/events")
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


def _dashboard_port() -> int:
    return int(os.environ.get("BULWARK_DASHBOARD_PORT", "3000"))


def _make_emitter():
    from bulwark.events import WebhookEmitter
    return WebhookEmitter(f"http://127.0.0.1:{_dashboard_port()}/api/events")


@app.post("/api/redteam/run")
async def run_redteam(request: Request):
    """Start production red team in the background."""
    global _redteam_task, _redteam_result

    if _redteam_task and not _redteam_task.done():
        return {"status": "running", "message": "Red team is already running"}

    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    max_probes = body.get("max_probes", 0)
    tier = body.get("tier", "")
    # Smoke test: cap at 10 probes
    if tier == "quick" and max_probes == 0:
        max_probes = 10

    _redteam_result = {"status": "running", "completed": 0, "total": 0}

    async def _run_in_background():
        global _redteam_result, _redteam_runner
        from bulwark.integrations.redteam import ProductionRedTeam
        import concurrent.futures

        # Find project root. Use BULWARK_PROJECT_DIR if set (e.g. in Docker),
        # otherwise walk up from this file's location.
        project_dir = os.environ.get("BULWARK_PROJECT_DIR", str(Path(__file__).parent.parent.parent))

        def on_progress(completed, total):
            _redteam_result["completed"] = completed
            _redteam_result["total"] = total

        try:
            runner = ProductionRedTeam(
                project_dir=project_dir,
                delay_ms=200,
                max_probes=max_probes,
                tier=tier,
                emitter=_make_emitter(),
                on_progress=on_progress,
            )
            # Route through /v1/pipeline so red team uses the exact same
            # code path as manual tests (detection models, LLM, canary, etc.)
            runner.pipeline_url = f"http://127.0.0.1:{_dashboard_port()}"
            _redteam_runner = runner
            loop = asyncio.get_running_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                summary = await loop.run_in_executor(pool, runner.run)

            from datetime import datetime, timezone
            completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            _redteam_result = {
                "status": "complete",
                "tier": tier or "legacy",
                "completed_at": completed_at,
                "total": summary.total,
                "defended": summary.defended,
                "vulnerable": summary.vulnerable,
                "hijacked": summary.hijacked,
                "format_failures": summary.format_failures,
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
                        "verdict": r.verdict,
                        "blocked_by": r.blocked_by,
                        "sanitizer_modified": r.sanitizer_modified,
                        "suspicious_flagged": r.suspicious_flagged,
                        "classification": r.classification,
                        "error": r.error,
                    }
                    for r in summary.results
                ],
            }

            # Persist report to disk
            _save_redteam_report(_redteam_result)
        except Exception as e:
            _redteam_result = {"status": "error", "message": str(e)}

    _redteam_task = asyncio.create_task(_run_in_background())
    return {"status": "started"}


@app.get("/api/redteam/status")
async def redteam_status():
    """Check status of running red team scan."""
    return _redteam_result


@app.post("/api/redteam/stop")
async def redteam_stop():
    """Stop a running red team scan."""
    global _redteam_runner
    if _redteam_runner and _redteam_task and not _redteam_task.done():
        _redteam_runner.cancelled = True
        return {"status": "stopping", "message": "Red team scan will stop after the current probe finishes."}
    return {"status": "not_running", "message": "No red team scan is currently running."}


@app.post("/api/redteam/retest")
async def retest_redteam(req: RetestRequest):
    """Re-run only the non-defended probes from a previous report."""
    global _redteam_task, _redteam_result

    if _redteam_task and not _redteam_task.done():
        return {"status": "running", "message": "Red team is already running"}

    filename = req.filename

    # Load the report
    safe_name = Path(filename).name
    if not safe_name.startswith("redteam-") or not safe_name.endswith(".json"):
        return {"status": "error", "message": "Invalid filename"}
    path = _reports_dir() / safe_name
    if not path.exists():
        return {"status": "error", "message": f"Report not found: {safe_name}"}

    try:
        report = json.loads(path.read_text())
    except Exception as e:
        return {"status": "error", "message": f"Failed to parse report: {e}"}

    from bulwark.integrations.redteam import ProductionRedTeam
    failed_probes = ProductionRedTeam.extract_failed_probes(report)
    if not failed_probes:
        return {"status": "error", "message": "No failed probes to retest"}

    _redteam_result = {"status": "running", "completed": 0, "total": len(failed_probes)}

    async def _run_retest():
        global _redteam_result, _redteam_runner
        from bulwark.integrations.redteam import ProductionRedTeam
        import concurrent.futures

        project_dir = os.environ.get("BULWARK_PROJECT_DIR", str(Path(__file__).parent.parent.parent))

        def on_progress(completed, total):
            _redteam_result["completed"] = completed
            _redteam_result["total"] = total

        try:
            runner = ProductionRedTeam(
                project_dir=project_dir,
                delay_ms=200,
                emitter=_make_emitter(),
                on_progress=on_progress,
            )
            runner.pipeline_url = f"http://127.0.0.1:{_dashboard_port()}"
            _redteam_runner = runner

            # Override the probe loading to use failed probes from the report
            runner._get_probe_payloads = lambda: failed_probes

            loop = asyncio.get_running_loop()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                summary = await loop.run_in_executor(pool, runner.run)

            from datetime import datetime, timezone
            completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            _redteam_result = {
                "status": "complete",
                "tier": f"retest:{safe_name}",
                "completed_at": completed_at,
                "total": summary.total,
                "defended": summary.defended,
                "vulnerable": summary.vulnerable,
                "hijacked": summary.hijacked,
                "format_failures": summary.format_failures,
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
                        "verdict": r.verdict,
                        "blocked_by": r.blocked_by,
                        "sanitizer_modified": r.sanitizer_modified,
                        "suspicious_flagged": r.suspicious_flagged,
                        "classification": r.classification,
                        "error": r.error,
                    }
                    for r in summary.results
                ],
            }
            _save_redteam_report(_redteam_result)
        except Exception as e:
            _redteam_result = {"status": "error", "message": str(e)}

    _redteam_task = asyncio.create_task(_run_retest())
    return {"status": "started", "message": f"Retesting {len(failed_probes)} failed probes from {safe_name}"}


def _reports_dir() -> Path:
    """Directory for persisted red team reports."""
    d = Path("reports")
    d.mkdir(exist_ok=True)
    return d


def _save_redteam_report(result: dict) -> str:
    """Save a completed red team report to disk. Returns the filename."""
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    tier = result.get("tier", "unknown")
    filename = f"redteam-{tier}-{ts}.json"
    path = _reports_dir() / filename
    path.write_text(json.dumps(result, indent=2))
    return filename


@app.get("/api/redteam/reports")
async def list_redteam_reports():
    """List saved red team reports."""
    d = _reports_dir()
    reports = []
    for f in sorted(d.glob("redteam-*.json"), reverse=True):
        try:
            data = json.loads(f.read_text())
            reports.append({
                "filename": f.name,
                "tier": data.get("tier", "unknown"),
                "completed_at": data.get("completed_at", ""),
                "total": data.get("total", 0),
                "defended": data.get("defended", 0),
                "vulnerable": data.get("vulnerable", 0),
                "defense_rate": data.get("defense_rate", 0),
                "duration_s": data.get("duration_s", 0),
            })
        except Exception:
            continue
    return {"reports": reports}


@app.get("/api/redteam/reports/{filename}")
async def download_redteam_report(filename: str):
    """Download a saved red team report as JSON."""
    from fastapi.responses import JSONResponse
    # Sanitize filename to prevent path traversal
    safe_name = Path(filename).name
    if not safe_name.startswith("redteam-") or not safe_name.endswith(".json"):
        return JSONResponse({"error": "Invalid filename"}, status_code=404)
    path = _reports_dir() / safe_name
    if not path.exists():
        return JSONResponse({"error": "Report not found"}, status_code=404)
    return FileResponse(path, media_type="application/json", filename=safe_name)


_garak_latest_cache: dict = {}  # {version: str, checked_at: float}


@app.get("/api/integrations/detect")
async def detect_integrations():
    """Check which testing tools are actually installed and if updates are available."""
    results = {}
    try:
        import garak
        installed_version = getattr(garak, "__version__", "unknown")
        import sys
        info = {"installed": True, "version": installed_version, "python": f"{sys.version_info.major}.{sys.version_info.minor}"}

        # Check for newer version (cached for 1 hour)
        latest = _check_garak_latest()
        if latest and latest != installed_version:
            info["latest"] = latest
            info["update_available"] = True
            # Check if upgrade is blocked by Python version
            import subprocess
            check = subprocess.run(
                [sys.executable, "-m", "pip", "install", f"garak=={latest}", "--dry-run"],
                capture_output=True, text=True, timeout=15,
            )
            if check.returncode != 0 and "requires-python" in check.stderr.lower() or "no matching distribution" in check.stderr.lower():
                info["python_upgrade_needed"] = True
            else:
                info["python_upgrade_needed"] = False
        else:
            info["update_available"] = False

        results["garak"] = info
    except ImportError:
        results["garak"] = {"installed": False}
    return results


def _check_garak_latest() -> Optional[str]:
    """Check PyPI for latest garak version. Cached for 1 hour."""
    now = time.time()
    if _garak_latest_cache.get("checked_at", 0) > now - 3600:
        return _garak_latest_cache.get("version")
    try:
        import urllib.request
        import json as _json
        req = urllib.request.Request("https://pypi.org/pypi/garak/json", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read())
            latest = data.get("info", {}).get("version", "")
            _garak_latest_cache["version"] = latest
            _garak_latest_cache["checked_at"] = now
            return latest
    except Exception:
        return None
