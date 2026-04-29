"""Bulwark Dashboard — FastAPI application."""
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import ipaddress
import json
import threading
import time
import os
from pathlib import Path
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse as StarletteJSONResponse

from bulwark.dashboard.db import EventDB
from bulwark.dashboard.config import BulwarkConfig, AVAILABLE_INTEGRATIONS, IntegrationConfig, get_api_token, env_truthy
from bulwark.dashboard.models import RetestRequest, CanaryUpsertRequest
from bulwark.presets import load_presets
from bulwark.canary_shapes import AVAILABLE_SHAPES, generate_canary


# Load presets once at import time so malformed YAML fails startup (G-PRESETS-006).
_PRESETS = [p.to_dict() for p in load_presets()]


# Methods that mutate state; only these are subject to the loopback-only
# fallback when no BULWARK_API_TOKEN is set (G-HTTP-AUTH-004, ADR-029).
# GETs never mutate, so a read-only remote client (e.g. a monitoring probe)
# still sees /api/config, /api/events, etc.
_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# Paths that may always be called from any origin, no auth. These are the
# language-agnostic security surface (clean/guard), the liveness probe, the
# login form, and the presets catalogue. Nothing here persists state.
#
# NOTE: /v1/clean is in this set by default but becomes auth-protected
# whenever BULWARK_API_TOKEN is set and the caller is non-loopback,
# regardless of LLM judge state (G-AUTH-CLEAN-001 / ADR-041). The previous
# judge-coupling predicate (ADR-030 / ADR-037, retained as historical
# G-AUTH-008) left judge-disabled deployments exposed for unauth content
# submission and detector burn. Loopback callers still bypass per ADR-029.
_UNAUTH_ALL_ORIGINS = frozenset({
    "/",
    "/healthz",
    "/v1/clean",
    "/v1/guard",
    "/api/auth/login",
    "/api/presets",
})


def _is_loopback_client(request: Request) -> bool:
    """Return True if the HTTP client is on the loopback interface.

    Accepts 127.0.0.0/8, ::1, and the FastAPI TestClient sentinel host.
    Any other source — Docker bridge network, another host on the LAN,
    a reverse proxy with X-Forwarded-For spoofing — is treated as remote.
    We do NOT honour X-Forwarded-For here; operators who terminate TLS in
    front of Bulwark must set BULWARK_API_TOKEN to authenticate mutations.
    """
    client = request.client
    host = client.host if client else None
    if not host:
        return False
    if host == "testclient":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Bearer token auth for protected endpoints, with a secure default.

    Behaviour:
      - OPTIONS (CORS preflight) always passes.
      - Paths in _UNAUTH_ALL_ORIGINS and /static/* always pass (public surface).
      - If BULWARK_API_TOKEN is set: non-public endpoints require a matching
        Bearer header or session cookie. 401 otherwise.
      - If BULWARK_API_TOKEN is NOT set (G-HTTP-AUTH-004, ADR-029): read
        methods (GET/HEAD) are open, but mutating methods on non-public
        endpoints require the client to be on the loopback interface.
        A remote PUT /api/config that would disable defenses gets 403.

    Rationale: the default Docker bind is 0.0.0.0:3000 and many operators
    run without setting BULWARK_API_TOKEN. Before this middleware, any
    network-reachable client could flip security toggles via unauthenticated
    PUT requests. Loopback-only fallback closes that while keeping the
    localhost-with-no-token dev experience untouched.
    """

    async def dispatch(self, request: Request, call_next):
        # OPTIONS requests always pass through (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        path = request.url.path

        # Public surface — always open, no auth check at all … with one
        # exception: /v1/clean flips to auth-required whenever a token is
        # set and the caller is non-loopback (G-AUTH-CLEAN-001 / ADR-041).
        # Judge state is no longer part of the predicate — the prior
        # judge-coupled rule (ADR-030 / ADR-037) left judge-disabled
        # deployments exposed for unauth content submission and detector
        # burn. Loopback callers (ADR-029) still bypass to keep the
        # localhost dev experience working.
        if path in _UNAUTH_ALL_ORIGINS or path.startswith("/static/"):
            if (
                path == "/v1/clean"
                and get_api_token()
                and not _is_loopback_client(request)
            ):
                pass  # fall through to the Bearer / cookie check below
            else:
                return await call_next(request)

        token = get_api_token()

        # G-HTTP-AUTH-004 / ADR-029: no token configured — only loopback
        # clients may mutate. Remote reads are still allowed (operators
        # often scrape /api/events or /api/metrics from monitoring).
        if not token:
            if request.method in _MUTATING_METHODS and not _is_loopback_client(request):
                return StarletteJSONResponse(
                    {"error": (
                        "Mutating endpoints require BULWARK_API_TOKEN when "
                        "accessed from a non-loopback client. Set the env "
                        "var and use Authorization: Bearer <token>."
                    )},
                    status_code=403,
                )
            return await call_next(request)

        # Token is set — standard Bearer / cookie auth for everything
        # outside _UNAUTH_ALL_ORIGINS.
        auth_header = request.headers.get("authorization", "")
        if auth_header == f"Bearer {token}":
            return await call_next(request)

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
    """Liveness probe with detector load state (ADR-038, G-HTTP-HEALTHZ-001..006).

    status flips to "degraded" when zero detectors are loaded AND the LLM
    judge is disabled AND BULWARK_ALLOW_SANITIZE_ONLY is unset. The
    detectors.loaded / detectors.failed fields are always present so
    operators can observe load state without scraping startup logs.
    """
    loaded = sorted(_detection_checks.keys())
    failed = dict(_detector_failures)
    judge_enabled = False
    try:
        judge_enabled = bool(config.judge_backend.enabled)
    except AttributeError:
        pass
    sanitize_only_opt_in = env_truthy("BULWARK_ALLOW_SANITIZE_ONLY")
    has_any_detector = bool(loaded) or judge_enabled
    degraded = (not has_any_detector) and (not sanitize_only_opt_in)
    payload = {
        "status": "degraded" if degraded else "ok",
        "version": _read_version(),
        "docker": os.path.exists("/.dockerenv"),
        "auth_required": bool(get_api_token()),
        "detectors": {
            "loaded": loaded,
            "failed": failed,
        },
    }
    if degraded:
        payload["reason"] = "no_detectors_loaded"
    return payload


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


@app.get("/api/pipeline-status")
async def pipeline_status():
    """Show what layers the pipeline would use based on current config."""
    from bulwark.pipeline import Pipeline

    try:
        pipeline = Pipeline.from_config(str(Path(__file__).parent.parent / "bulwark-config.yaml"))
        return {
            "sanitizer": pipeline.sanitizer is not None,
            "trust_boundary": pipeline.trust_boundary is not None,
            "detector": pipeline.detector is not None,
        }
    except Exception:
        return {"error": "Failed to load pipeline configuration", "using_defaults": True}


@app.get("/api/presets")
async def get_presets():
    """Attack-preset library — source of truth is spec/presets.yaml (ADR-021, G-PRESETS-005)."""
    return {"presets": _PRESETS}


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


# ---------------------------------------------------------------------------
# Canary management — spec/contracts/canaries.yaml (ADR-025)
# ---------------------------------------------------------------------------


@app.get("/api/canaries")
async def list_canaries():
    """G-CANARY-001: return the current canary_tokens map as a list."""
    return {
        "canaries": [
            {"label": label, "token": token}
            for label, token in config.canary_tokens.items()
        ]
    }


@app.post("/api/canaries")
async def upsert_canary(req: CanaryUpsertRequest):
    """G-CANARY-002/004/009: create or rotate a canary entry."""
    label = req.label.strip()

    if not label or any(c.isspace() for c in label) or len(label) > 64:
        return StarletteJSONResponse(
            {"error": "label must be 1..64 chars with no whitespace"},
            status_code=400,
        )

    token = req.token
    if token is None and req.shape is None:
        return StarletteJSONResponse(
            {"error": "provide either token or shape"},
            status_code=400,
        )

    if token is None:
        if req.shape not in AVAILABLE_SHAPES:
            return StarletteJSONResponse(
                {"error": f"unknown shape; valid: {', '.join(AVAILABLE_SHAPES)}"},
                status_code=400,
            )
        token = generate_canary(req.shape)

    if len(token) < 8:
        return StarletteJSONResponse(
            {"error": "token must be at least 8 characters"},
            status_code=400,
        )

    config.canary_tokens[label] = token
    config.save()
    return {"label": label, "token": token}


@app.delete("/api/canaries/{label}")
async def delete_canary(label: str):
    """G-CANARY-003: remove a canary by label; 404 if absent."""
    if label not in config.canary_tokens:
        return StarletteJSONResponse(
            {"error": f"no canary with label {label!r}"}, status_code=404,
        )
    del config.canary_tokens[label]
    config.save()
    return StarletteJSONResponse(status_code=204, content=None)


@app.get("/api/integrations")
async def list_integrations():
    """List available integrations with their status (ADR-038)."""
    result = {}
    for key, info in AVAILABLE_INTEGRATIONS.items():
        int_config = config.integrations.get(key, IntegrationConfig())
        loaded = key in _detection_checks
        load_error = _detector_failures.get(key)
        result[key] = {
            **info,
            "enabled": int_config.enabled,
            "installed": int_config.installed,
            "last_used": int_config.last_used,
            "loaded": loaded,
            "load_error": load_error,
        }
    return result


# Loaded detection models (kept in memory while dashboard runs)
_detection_checks: dict[str, object] = {}

# ADR-038: detectors that failed to load at startup, surfaced via /healthz
# and /api/integrations. Maps detector name -> first 200 chars of exception.
_detector_failures: dict[str, str] = {}


@app.on_event("startup")
async def _auto_load_detection_models():
    """Auto-load detection models that were previously activated.

    Records failures in _detector_failures so /healthz can report a
    degraded status when no detector loaded (ADR-038).
    """
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
                _detector_failures.pop(name, None)
                print(f"  Auto-loaded detection model: {name}")
            except Exception as e:
                _detector_failures[name] = f"{type(e).__name__}: {str(e)[:200]}"
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
        _detector_failures.pop(name, None)

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
        msg = f"Missing dependency: {e}. Run: pip install transformers torch"
        _detector_failures[name] = f"ImportError: {str(e)[:200]}"
        return {"status": "error", "message": msg}
    except OSError as e:
        msg = str(e)
        _detector_failures[name] = f"OSError: {msg[:200]}"
        if "gated" in msg.lower() or "awaiting" in msg.lower():
            return {"status": "error", "message": f"{model_label} requires HuggingFace approval. Check https://huggingface.co/meta-llama/Prompt-Guard-86M"}
        return {"status": "error", "message": f"Failed to load model: {msg[:200]}"}
    except Exception as e:
        _detector_failures[name] = f"{type(e).__name__}: {str(e)[:200]}"
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
    """Enable/disable an integration.

    Setting enabled=False immediately removes the detector from the active check
    pipeline (in-memory), not just from the persisted config. Setting enabled=True
    requires the detector to have been loaded previously via POST .../activate —
    this endpoint does not load models on its own.
    """
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
    # G-INTEGRATIONS-001: keep _detection_checks coherent with the flag.
    # Disable → remove from pipeline immediately. Re-enable of a loaded detector
    # is not supported here; users must re-POST .../activate to bring it back.
    if int_config.enabled is False and name in _detection_checks:
        _detection_checks.pop(name, None)
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

# Probe counts are dynamic per G-REDTEAM-TIERS-002 but the full enumeration is
# ~3s (instantiates every probe class to count payloads). A short TTL lets
# long-running dashboards pick up upstream garak changes without requiring a
# restart, while avoiding that cost on every page load.
_REDTEAM_TIERS_TTL_S = 600  # 10 minutes
_redteam_tiers_cache: Optional[tuple[float, dict]] = None  # (cached_at, result)


def _compute_redteam_tiers(_force: bool = False) -> dict:
    """Compute red team tier definitions from installed garak version.

    Counts actual payloads (not just probe classes) by instantiating each probe.
    Takes ~3s on first call; subsequent calls within the TTL window return
    the cached result. Pass _force=True to bypass the cache (tests).
    """
    global _redteam_tiers_cache
    if not _force and _redteam_tiers_cache is not None:
        cached_at, cached = _redteam_tiers_cache
        if time.time() - cached_at < _REDTEAM_TIERS_TTL_S:
            return cached

    try:
        import garak
        from garak._plugins import enumerate_plugins
        version = getattr(garak, "__version__", "unknown")
    except ImportError:
        result = {"garak_installed": False, "garak_version": None, "tiers": []}
        _redteam_tiers_cache = (time.time(), result)
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

    # llm-quick / llm-suite tiers removed in v2.1.0 (ADR-035): they paired with
    # the deleted bulwark_bench --bypass-detectors model-sweep flow, which
    # collapsed when ADR-031 removed llm_backend. The standard tier already
    # exercises every active probe, and v2 has no LLM behind the detectors
    # for the curated LLM-reach tiers to point at.
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
            # ADR-036: false-positive sweep — pushes a curated benign corpus
            # through /v1/clean. Same scan path, inverted metric.
            *_falsepos_tier_entries(),
        ],
    }
    _redteam_tiers_cache = (time.time(), result)
    return result


def _falsepos_tier_entries() -> list[dict]:
    """Return [tier dict] for the false-positive sweep, or [] if corpus unreadable."""
    try:
        from bulwark_falsepos.corpus import load_corpus, categories
        corpus = load_corpus(_falsepos_corpus_path())
    except Exception:
        return []
    cats = categories(corpus)
    cat_summary = ", ".join(f"{n} {c}" for c, n in sorted(cats.items()))
    return [{
        "id": "falsepos",
        "name": "False Positives",
        "description": (
            f"Curated benign emails through /v1/clean — {cat_summary}. "
            f"Edit spec/falsepos_corpus.jsonl to extend."
        ),
        "probe_count": len(corpus),
        "families": sorted(cats.keys()),
    }]


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
# B4 / ADR-039: protect _redteam_result reads/writes against the race between
# the background runner thread (mutates) and the FastAPI status endpoint
# (reads). Without this, status reads can land mid-write and return a
# half-merged dict (e.g. completed updated, total still missing).
_redteam_lock = threading.Lock()


def _redteam_status_snapshot() -> dict:
    """Return a deep-copy snapshot of _redteam_result under the lock.

    Used by /api/redteam/status so callers see a coherent view even
    while the runner is mutating the dict from a worker thread.
    """
    import copy
    with _redteam_lock:
        return copy.deepcopy(_redteam_result)


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


def _falsepos_corpus_path() -> Path:
    """Resolve the false-positive corpus path.

    Order: ENV override → repo `spec/` (dev) → packaged `bulwark_falsepos/_data/`
    (installed wheel + Docker image, see pyproject.toml force-include).
    """
    env = os.environ.get("BULWARK_FALSEPOS_CORPUS")
    if env:
        return Path(env)
    repo = Path(__file__).parent.parent.parent.parent / "spec" / "falsepos_corpus.jsonl"
    if repo.exists():
        return repo
    # Installed-wheel layout: bundled via [tool.hatch.build.targets.wheel.force-include].
    try:
        from importlib.resources import files
        return Path(str(files("bulwark_falsepos") / "_data" / "falsepos_corpus.jsonl"))
    except Exception:
        return repo  # fall back to the repo path even if missing — caller surfaces the error


async def _run_falsepos_in_background():
    """ADR-036: run the curated benign corpus through /v1/clean and persist as
    a redteam-falsepos-* report so it appears in the existing reports list.

    Inverted metric: a 200 (passed) is good; a 422 (blocked) is a false positive.
    The result schema mimics ProductionRedTeam.run() so the existing UI can
    render it; `defense_rate` is set to 1 - false_positive_rate so the same
    column means "good runs / total runs" regardless of tier.
    """
    global _redteam_result
    import concurrent.futures
    from datetime import datetime, timezone
    from bulwark_falsepos.corpus import load_corpus

    try:
        corpus = load_corpus(_falsepos_corpus_path())
    except Exception as exc:
        _redteam_result = {"status": "error", "message": f"corpus load failed: {exc}"}
        return

    _redteam_result = {"status": "running", "completed": 0, "total": len(corpus), "tier": "falsepos"}

    def _do_run() -> dict:
        import httpx
        local_url = f"http://127.0.0.1:{_dashboard_port()}"
        headers = {"Content-Type": "application/json"}
        token = get_api_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        results: list[dict] = []
        t0 = time.time()
        for i, email in enumerate(corpus, start=1):
            entry = {
                "probe_family": "falsepos",
                "probe_class": email.category,
                "payload": email.text[:200],
                "llm_response": "",
                "defended": True,
                "verdict": "passed",
                "blocked_by": None,
                "sanitizer_modified": False,
                "suspicious_flagged": False,
                "classification": email.id,
                "error": None,
            }
            try:
                resp = httpx.post(
                    f"{local_url}/v1/clean",
                    json={"content": email.text, "source": "falsepos"},
                    headers=headers, timeout=60.0,
                )
            except Exception as exc:
                # Network failure / timeout — classify as error, NOT pass.
                # ADR-038: errored requests are excluded from the defense-rate
                # denominator; they're surfaced separately.
                entry["error"] = str(exc)[:200]
                entry["verdict"] = "error"
                entry["defended"] = False
                results.append(entry)
                with _redteam_lock:
                    _redteam_result["completed"] = i
                continue

            if resp.status_code == 422:
                # False positive — request blocked content that was actually benign.
                entry["defended"] = False
                entry["verdict"] = "false_positive"
                try:
                    body = resp.json()
                    entry["blocked_by"] = body.get("blocked_at")
                    entry["llm_response"] = (body.get("block_reason") or "")[:300]
                except Exception:
                    pass
            elif resp.status_code == 200:
                # Clean pass.
                try:
                    body = resp.json()
                    entry["sanitizer_modified"] = bool(body.get("modified"))
                except Exception:
                    # 200 with non-JSON is a server bug — count as error.
                    entry["error"] = "200 OK with non-JSON body"
                    entry["verdict"] = "error"
                    entry["defended"] = False
            else:
                # Any other status (401, 403, 5xx, etc.) is an error condition.
                # Counting these as "passed" inflates the defense rate falsely.
                entry["error"] = f"HTTP {resp.status_code}: {resp.text[:160]}"
                entry["verdict"] = "error"
                entry["defended"] = False
            results.append(entry)
            with _redteam_lock:
                _redteam_result["completed"] = i

        duration_s = time.time() - t0
        total = len(results)
        false_positives = sum(1 for r in results if r["verdict"] == "false_positive")
        errored = sum(1 for r in results if r["verdict"] == "error")
        defended = sum(1 for r in results if r["verdict"] == "passed")
        # Defense rate computed over CLEAN responses only — errored requests
        # don't tell us whether the detector chain works correctly.
        scored = defended + false_positives
        fp_rate = (false_positives / scored) if scored else 0.0

        # Per-category breakdown (analogous to by_family for redteam).
        # ADR-038: errored requests are tallied separately and excluded from
        # the defended/vulnerable counts so per-category rates aren't inflated.
        by_family: dict[str, dict[str, int]] = {}
        for r in results:
            cat = r.get("probe_class") or "unknown"
            slot = by_family.setdefault(cat, {"total": 0, "defended": 0, "vulnerable": 0,
                                              "hijacked": 0, "format_failures": 0,
                                              "errors": 0})
            slot["total"] += 1
            if r["verdict"] == "false_positive":
                slot["vulnerable"] += 1
            elif r["verdict"] == "error":
                slot["errors"] += 1
            else:
                slot["defended"] += 1

        return {
            "tier": "falsepos",
            "total": total,
            "defended": defended,
            "vulnerable": false_positives,
            "hijacked": 0,
            "format_failures": 0,
            "errors": errored,
            # Same column the UI already renders, with the right meaning:
            # "good outcomes / total". For falsepos that's 1 - FP rate.
            "defense_rate": 1.0 - fp_rate,
            "false_positive_rate": fp_rate,
            "duration_s": duration_s,
            "by_layer": {},
            "by_family": by_family,
            "results": results,
        }

    try:
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            summary = await loop.run_in_executor(pool, _do_run)
        completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        summary["status"] = "complete"
        summary["completed_at"] = completed_at
        _redteam_result = summary
        _save_redteam_report(_redteam_result)
    except Exception as exc:
        _redteam_result = {"status": "error", "message": str(exc)}


@app.post("/api/redteam/run")
async def run_redteam(request: Request):
    """Start production red team in the background.

    The `falsepos` tier (ADR-036) takes the curated benign corpus from
    spec/falsepos_corpus.jsonl and pushes each email through /v1/clean
    using the dashboard's current detector configuration. Same scan
    pattern, inverted metric — for falsepos, BLOCKED counts as failure.
    """
    global _redteam_task, _redteam_result

    if _redteam_task and not _redteam_task.done():
        return {"status": "running", "message": "Red team is already running"}

    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    max_probes = body.get("max_probes", 0)
    tier = body.get("tier", "")
    # Smoke test: cap at 10 probes
    if tier == "quick" and max_probes == 0:
        max_probes = 10

    # ADR-036: falsepos tier dispatches to the corpus runner.
    if tier == "falsepos":
        _redteam_task = asyncio.create_task(_run_falsepos_in_background())
        return {"status": "started"}

    _redteam_result = {"status": "running", "completed": 0, "total": 0}

    async def _run_in_background():
        global _redteam_result, _redteam_runner
        from bulwark.integrations.redteam import ProductionRedTeam
        import concurrent.futures

        # Find project root. Use BULWARK_PROJECT_DIR if set (e.g. in Docker),
        # otherwise walk up from this file's location.
        project_dir = os.environ.get("BULWARK_PROJECT_DIR", str(Path(__file__).parent.parent.parent))

        def on_progress(completed, total):
            with _redteam_lock:
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
    """Check status of running red team scan.

    Returns a snapshot taken under the write lock so callers never see a
    half-mutated dict while the background runner thread is updating
    progress (B4 / ADR-038).
    """
    return _redteam_status_snapshot()


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
            with _redteam_lock:
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
    """List saved red team reports, newest first (G-REDTEAM-REPORTS-002).

    Sort key: each report's `completed_at` ISO timestamp from inside the JSON.
    Falls back to filename when a report predates the completed_at field, and
    finally to mtime as a last-ditch ordering. This is why newer full-tier
    reports used to sink below older standard-tier ones — alphabetic reverse
    on the filename put `standard-*` ahead of `full-*` regardless of date.
    """
    d = _reports_dir()
    reports = []
    for f in d.glob("redteam-*.json"):
        try:
            data = json.loads(f.read_text())
            reports.append({
                "filename": f.name,
                "tier": data.get("tier", "unknown"),
                "completed_at": data.get("completed_at", ""),
                "total": data.get("total", 0),
                "defended": data.get("defended", 0),
                "vulnerable": data.get("vulnerable", 0),
                "hijacked": data.get("hijacked", 0),
                "defense_rate": data.get("defense_rate", 0),
                "duration_s": data.get("duration_s", 0),
                # Not returned to clients — used only for sort stability below.
                "_mtime": f.stat().st_mtime,
            })
        except Exception:
            continue
    reports.sort(key=lambda r: (r["completed_at"] or "", r["filename"], r["_mtime"]), reverse=True)
    for r in reports:
        r.pop("_mtime", None)
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
_garak_dry_run_cache: dict = {}  # {(installed, latest): bool, checked_at: float}


@app.get("/api/integrations/detect")
async def detect_integrations():
    """Check which testing tools are actually installed and if updates are available.

    ADR-030: The pip `--dry-run` compatibility probe is cached alongside
    the PyPI version check. Without caching this endpoint spawns a 15s
    pip subprocess on every request, which is a network-reachable DoS
    vector (Codex finding, 2026-04-16).
    """
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
            info["python_upgrade_needed"] = _check_garak_python_upgrade_needed(
                installed_version, latest,
            )
        else:
            info["update_available"] = False

        results["garak"] = info
    except ImportError:
        results["garak"] = {"installed": False}
    return results


def _check_garak_python_upgrade_needed(installed: str, latest: str) -> bool:
    """Cached wrapper around `pip install garak==<latest> --dry-run`.

    Cache keyed on (installed, latest) — if either changes, recompute.
    Entries expire after 1 hour so a stale pip result never outlives the
    paired latest-version cache. The uncached version was a DoS vector
    (Codex finding, 2026-04-16): any caller could trigger a 15-second
    pip subprocess per request.
    """
    import subprocess
    import sys as _sys
    now = time.time()
    key = (installed, latest)
    entry = _garak_dry_run_cache.get(key)
    if entry is not None and entry.get("checked_at", 0) > now - 3600:
        return bool(entry.get("python_upgrade_needed", False))

    try:
        check = subprocess.run(
            [_sys.executable, "-m", "pip", "install", f"garak=={latest}", "--dry-run"],
            capture_output=True, text=True, timeout=15,
        )
        stderr_lower = check.stderr.lower()
        needed = bool(
            check.returncode != 0
            and ("requires-python" in stderr_lower or "no matching distribution" in stderr_lower)
        )
    except Exception:
        needed = False

    # Clear stale keys (keeps dict bounded: we only track one (installed, latest)
    # tuple at a time in practice).
    _garak_dry_run_cache.clear()
    _garak_dry_run_cache[key] = {"python_upgrade_needed": needed, "checked_at": now}
    return needed


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
