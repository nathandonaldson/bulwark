# Dashboard

Interactive observability dashboard with real-time event streaming, attack testing, production red teaming, and detection model management.

## Setup

**Docker (recommended):**

```bash
docker run -p 3000:3000 ghcr.io/nathandonaldson/bulwark
```

**From source:**

```bash
pip install bulwark-shield[dashboard]
PYTHONPATH=src python -m bulwark.dashboard --port 3000
```

Binds to `127.0.0.1` (localhost only) by default. `--host 0.0.0.0` to expose on the network (no auth, be careful). In Docker, binds to `0.0.0.0` by default.

Open http://localhost:3000.

## Pages

**Shield** — concentric ring visualization of all 5 defense layers. Real-time activity feed with sparkline charts. Per-layer event counts.

**Events** — filterable event feed. Click any event to expand the full trace.

**Configure** — three sections:
- *Defense layers:* toggle sanitizer, trust boundary, guard, canary, and sub-features (emoji smuggling, bidi defense, NFKC normalization)
- *AnalysisGuard patterns:* view, add, and remove regex patterns checked at the bridge
- *Detection integrations:* activate ProtectAI DeBERTa, PromptGuard-86M, or other classifiers. Click "Activate" to download and load the model. Active models run on every Test tab payload.
- *Canary tokens:* view embedded tripwires and their sources

**Test** — two sections:
- *Manual testing:* paste any payload (or select from 8 presets), hit "Run Through Pipeline," watch the pipeline trace. If detection models are active, they run at the bridge.
- *Red teaming:* send Garak's attack probes through the real production Bulwark+LLM pipeline. Three tiers — Smoke Test (10 probes), Standard Scan (~4k probes), Full Sweep (~33k probes) — with counts pulled dynamically from garak. Reports are saved to `reports/` and downloadable as JSON. Inline report with defense score, layer breakdown, and vulnerability details.

## Detection models

In the Configure tab, click "Activate" on a detection model. The model downloads (~180MB first time) and loads into memory. Once active:

- It runs on every payload tested in the Test tab
- It appears as a custom check in the AnalysisGuard bridge
- It stays loaded while the dashboard service is running (~200MB RAM)

Available models:
- **ProtectAI DeBERTa** (recommended) — ungated, works immediately, 99.99% accuracy, ~30ms
- **PromptGuard-86M** — gated (requires HuggingFace approval from Meta), ~50ms

## Connecting your pipeline

Use `WebhookEmitter` to send events to the dashboard:

```python
from bulwark import Pipeline
from bulwark.events import WebhookEmitter

pipeline = Pipeline.default(
    analyze_fn=my_fn,
    emitter=WebhookEmitter("http://localhost:3000/api/events"),
)
```

Other emitters: `StdoutJsonEmitter`, `CollectorEmitter`, `CallbackEmitter`, `MultiEmitter`.

## Persistent service (macOS, non-Docker)

```bash
bash src/bulwark/dashboard/install-service.sh install
```

Installs as a launchd service that starts on boot. For Docker, use `docker compose up -d` with `restart: unless-stopped` instead.
