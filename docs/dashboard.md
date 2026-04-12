# Dashboard

Interactive observability dashboard with real-time event streaming and an attack test page.

## Setup

```bash
pip install fastapi uvicorn
cd bulwark-ai
PYTHONPATH=src uvicorn dashboard.app:app --port 3000
```

Open http://localhost:3000.

## Pages

**Shield** — concentric ring visualization of all 5 defense layers. Real-time activity feed with sparkline charts. Per-layer event counts.

**Events** — filterable event feed. Click any event to expand the full trace.

**Configure** — toggle each defense layer, manage guard patterns, configure integrations (PromptGuard-86M, PIGuard, LLM Guard, NeMo Guardrails, Garak, Promptfoo), manage canary tokens.

**Test** — paste any attack payload (or select from 8 presets), hit "Run Through Pipeline," and watch the pipeline trace light up layer by layer.

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

## Persistent service (macOS)

```bash
bash dashboard/install-service.sh install
```

Installs as a launchd service that starts on boot.
