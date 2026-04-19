# Dashboard

Interactive observability dashboard with real-time event streaming, attack testing, production red teaming, and detection model management.

## Setup

**Docker (recommended):**

```bash
docker run -p 3000:3000 nathandonaldson/bulwark
```

**From source:**

```bash
pip install bulwark-shield[dashboard]
PYTHONPATH=src python -m bulwark.dashboard --port 3000
```

Binds to `127.0.0.1` (localhost only) by default. `--host 0.0.0.0` to expose on the network (no auth, be careful). In Docker, binds to `0.0.0.0` by default.

Open http://localhost:3000.

## Pages

**Shield** — concentric ring visualization of the full pipeline. Outer ring = first layer, inner ring = last. Status banner, 24h totals (items processed, attacks neutralized, canary leaks, bridge blocks), sparkline trend, and a recent activity feed.

**Events** — filterable stream of every layer event (sanitizer hits, detection verdicts, bridge blocks, canary leaks). Filter by layer, severity, source, or free-text search. Export as JSON.

**Configure** — click any pipeline stage (Sanitizer, Trust Boundary, Detection, Phase 1 Analyze, Bridge Guard, Canary Tokens, Phase 2 Execute) to open its settings on the right. Toggle the switch next to a stage to drop it from the pipeline.
- *Sanitizer:* emoji smuggling defense, bidirectional override stripping, NFKC normalization
- *Detection:* activate ProtectAI DeBERTa or PromptGuard-86M. First activation downloads the model (~180MB).
- *Bridge Guard:* view, add, remove AnalysisGuard regex patterns
- *LLM backend:* Anthropic, OpenAI-compatible (Ollama / llama.cpp / vLLM / LM Studio), or sanitize-only
- *Canary Tokens:* view embedded tripwires and their sources

**Test** — two sections:
- *Manual testing:* paste any payload (or select from 8 presets), hit "Run through pipeline," watch the pipeline trace. If detection models are active, they run at the bridge. A "cURL" button copies the exact request for scripting.
- *Red teaming:* sends Garak attack probes through the real production Bulwark+LLM pipeline. Five tiers — Smoke Test (10), LLM Quick (10 curated), LLM Suite (~200 balanced), Standard Scan (~4k), Full Sweep (~33k) — with counts pulled dynamically from your installed garak version. Reports are saved to `reports/` and downloadable as JSON with defense score, layer breakdown, and vulnerability details.

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
