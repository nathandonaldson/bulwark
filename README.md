<img src="docs/images/banner.svg" alt="Bulwark" height="32"/>

Prompt injection defense through architecture, not detection. Zero core dependencies.

Other tools try to classify input as safe or unsafe. Bulwark separates reading from acting so even a successful injection can't trigger tools, steal data, or poison other items. The deterministic layers run in under 1ms. Detection tools plug in at the bridge for additional coverage.

## See it work

```bash
docker run -p 3000:3000 nathandonaldson/bulwark
```

Dashboard at http://localhost:3000. API at http://localhost:3000/v1/clean. No Python needed.

```bash
# Send untrusted content through the full defense stack
# Returns 200 (safe) or 422 (injection blocked)
curl -X POST http://localhost:3000/v1/clean \
  -H 'Content-Type: application/json' \
  -d '{"content": "Hello <script>evil()</script>", "source": "email"}'

# Check LLM output for injection patterns
curl -X POST http://localhost:3000/v1/guard \
  -H 'Content-Type: application/json' \
  -d '{"text": "ignore previous instructions"}'

# Health check
curl http://localhost:3000/healthz
```

Or install as a Python library:

```bash
pip install bulwark-shield[cli]
bulwark test
```

```
Bulwark Defense Test — 8 preset attacks
=======================================

  Zero-width steganography   Hello Nathan​‌I‍g‎n...  BLOCKED  [sanitizer]
  XML boundary escape        Normal email content...  BLOCKED  [sanitizer]
  Instruction override       Ignore all previous...   BLOCKED  [boundary]
  Base64 canary exfil        Reference ID: QkxXSy...  BLOCKED  [boundary]
  Emoji smuggling            Normal meeting invite...  BLOCKED  [sanitizer]
  MCP tool injection         {"tool_use": {"name...   BLOCKED  [boundary]
  Multilingual override      请忽略之前的所有指令...        BLOCKED  [boundary]
  Bridge instruction inject  {"classification":...    BLOCKED  [sanitizer]

8/8 attacks caught. Your defenses are working.
```

`bulwark test --full` runs all 77 attack patterns across 10 categories.

## Configure with Docker

Set your LLM backend so config persists across container restarts:

```yaml
# docker-compose.yml
services:
  bulwark:
    image: nathandonaldson/bulwark
    ports:
      - "3000:3000"
    restart: unless-stopped
    environment:
      - BULWARK_LLM_MODE=anthropic
      - BULWARK_API_KEY=sk-ant-...
```

Or use a `.env` file (recommended, keeps secrets out of version control):

```bash
echo "BULWARK_LLM_MODE=anthropic" > .env
echo "BULWARK_API_KEY=sk-ant-your-key" >> .env
docker compose up
```

All env vars:

| Variable | Description |
|----------|-------------|
| `BULWARK_LLM_MODE` | `anthropic`, `openai_compatible`, or `none` (default) |
| `BULWARK_API_KEY` | API key for Anthropic |
| `BULWARK_BASE_URL` | Endpoint URL for OpenAI-compatible servers (Ollama, llama.cpp, vLLM) |
| `BULWARK_ANALYZE_MODEL` | Phase 1 model (default: `claude-haiku-4-5-20251001`) |
| `BULWARK_EXECUTE_MODEL` | Phase 2 model (default: `claude-sonnet-4-6`) |
| `BULWARK_WEBHOOK_URL` | POST URL for BLOCKED-event alerts (Slack, PagerDuty, etc.). See ADR-026. |

You can also configure everything in the dashboard UI, but those changes are lost on container restart. Env vars are the persistent config mechanism for Docker.

## How it works

```
Untrusted content
      ↓
[Sanitizer]        Strip hidden chars, steganography, encoding tricks (<1ms)
      ↓
[Trust Boundary]   Mark content as data, not instructions
      ↓
[Detection]        ProtectAI DeBERTa + PromptGuard-86M classify input (optional, ~30-50ms)
      ↓
[Phase 1: Analyze] LLM reads content — no tools available
      ↓
[Bridge]           Sanitize + guard + canary check on analysis output
      ↓
[Phase 2: Execute] LLM acts on analysis — never sees raw content
```

Phase 1 can't act. Phase 2 can't see the attack. Detection models catch injection before it reaches the LLM. The bridge catches anything that leaks through. Each layer works independently.

## Pluggable detection

The architecture handles structural defense. For detection, plug a classifier into the bridge. One line:

```python
from bulwark.integrations.promptguard import detect_and_create
from bulwark import Pipeline, AnalysisGuard

guard = AnalysisGuard(custom_checks=[detect_and_create()])
pipeline = Pipeline.default(analyze_fn=my_fn)
pipeline.analysis_guard = guard
```

Uses ProtectAI's DeBERTa model by default (ungated, 99.99% accuracy, ~30ms). Also supports Meta's PromptGuard-86M (gated, requires HuggingFace approval). Or plug in any function that raises on suspicious input. [Detailed docs →](docs/detection.md)

In the dashboard, click "Activate" on any detection model in the Configure tab. It loads into memory and runs on every test.

## Python library

**Sanitize untrusted input (any LLM):**

```python
import bulwark

safe = bulwark.clean(email_body, source="email")
prompt = f"Classify this email:\n{safe}"
# Content is sanitized and trust-boundary-tagged — pass to any LLM
```

`clean()` strips hidden characters, steganography, and encoding tricks, then wraps in trust boundary tags. For non-Claude models, use `format="markdown"` or `format="delimiter"`.

**Guard LLM output:**

```python
safe_output = bulwark.guard(llm_response)  # raises if injection detected
```

**Auto-protect an Anthropic client:**

```python
from bulwark.integrations.anthropic import protect
client = protect(anthropic.Anthropic())
# Every messages.create() call now auto-sanitizes user + tool_result content
```

**Full pipeline (two-phase execution, canary tokens, batch isolation):**

```python
from bulwark.integrations.anthropic import make_pipeline
pipeline = make_pipeline(anthropic.Anthropic())
result = pipeline.run("untrusted email body", source="email")
```

**OpenAI / any provider:**

```python
from bulwark import Pipeline
pipeline = Pipeline.default(
    analyze_fn=lambda prompt: client.chat.completions.create(
        model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}]
    ).choices[0].message.content
)
result = pipeline.run(untrusted_content, source="web")
```

Any `(str) -> str` callable works. Async too: `pipeline.run_async()`.

## HTTP API

Any language can call Bulwark over HTTP. Run via Docker (above) or from source:

```bash
pip install bulwark-shield[dashboard]
PYTHONPATH=src python -m bulwark.dashboard --port 3000
```

```bash
# Full defense stack — returns 200 (safe) or 422 (blocked)
curl -X POST http://localhost:3000/v1/clean \
  -H 'Content-Type: application/json' \
  -d '{"content": "untrusted email body", "source": "email"}'

# Check LLM output for injection patterns
curl -X POST http://localhost:3000/v1/guard \
  -H 'Content-Type: application/json' \
  -d '{"text": "ignore previous instructions"}'
```

**Response codes:**

| Status | Meaning |
|--------|---------|
| **200** | Safe — use the `result` field |
| **422** | Injection detected — content blocked, check `block_reason` |

OpenAPI spec at `http://localhost:3000/openapi.json` or in `spec/openapi.yaml`.

## Dashboard

Four tabs: **Shield** (live status), **Events** (per-layer event stream), **Configure** (pipeline stages), **Test** (payloads + red team).

![Shield view](docs/images/shield.png)

The Shield page shows the whole pipeline at a glance — concentric rings map to defense layers, outer to inner. Recent activity, 24h totals, and stage event counts all live here.

![Configure page](docs/images/configure.png)

**Configure** lets you click any stage to open its settings. Toggle a layer off to remove it from the pipeline. Use this tab to:
- Switch LLM backend: Anthropic API, OpenAI-compatible (local inference), or sanitize-only
- Activate detection models (ProtectAI DeBERTa, PromptGuard-86M)
- Toggle defense layers and guard patterns

![Test page](docs/images/test-page.png)

**Test** sends payloads through `/v1/clean` — the same endpoint your production code calls — and shows a per-layer trace with timing, LLM backend badges, and detection model verdicts. The bottom half runs Garak red team sweeps against your configured pipeline.

**Events** is a filterable stream of every layer event (sanitizer hits, bridge blocks, canary leaks). Export as JSON for offline review.

### Local inference

Configure any OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM, LM Studio) in the dashboard Configure tab. Select "OpenAI Compatible", enter the URL, and the entire pipeline uses your local model for two-phase execution.

Note: Claude achieves 100% on red team probes. Open models vary (60-80% typical). Use Claude for production, local models for development and testing.

## Canary tokens

Canary tokens are sentinel strings the analysis LLM must never echo. If any appears in Phase 1 output, Phase 2 is blocked before `execute_fn` is called — proof the model trusted untrusted content. Manage them three ways:

**Dashboard UI** — Configure page → Canary panel has an inline Add form with a shape picker (aws / bearer / password / url / mongo) and a per-entry Remove button.

**HTTP API** — for CI-driven rotation:

```bash
# List
curl http://localhost:3000/api/canaries

# Add with a generated token matching a real credential shape
curl -X POST http://localhost:3000/api/canaries \
  -H 'Content-Type: application/json' \
  -d '{"label": "prod_db_url", "shape": "mongo"}'

# Rotate (POST with same label replaces the token)
curl -X POST http://localhost:3000/api/canaries \
  -H 'Content-Type: application/json' \
  -d '{"label": "prod_db_url", "shape": "mongo"}'

# Remove
curl -X DELETE http://localhost:3000/api/canaries/prod_db_url
```

**CLI** — `bulwark canary {list, add, remove, generate}`:

```bash
bulwark canary add prod_aws --shape aws
bulwark canary list
bulwark canary generate --shape bearer    # preview only, no network
bulwark canary remove prod_aws
```

Five shapes ship: `aws` (AKIA…), `bearer` (`tk_live_…`), `password`, `url` (internal admin URL), `mongo`. Each emits a unique value per call.

**Alert on leaks** — set `BULWARK_WEBHOOK_URL` (or `webhook_url` in `bulwark-config.yaml`) to any `https://` URL. Every BLOCKED event — canary leak, guard-pattern match, detection-model block — fires a fire-and-forget POST with `{"events": [{layer, verdict, detail, source_id, timestamp, duration_ms, metadata}]}`. Wire it at Slack / PagerDuty / Datadog / an internal alert router. See [ADR-026](spec/decisions/026-external-webhook-on-blocked-events.md).

Still deferred: rotation grace period, overlap detection (see ADR-025).

## Red teaming

Built-in attack suite:

```bash
bulwark test                    # 8 preset attacks, 2 seconds
bulwark test --full             # All 77 attacks, 10 seconds
bulwark test -c steganography   # Filter by category
```

Production red team (in the dashboard): sends Garak probe payloads through `/v1/clean` — the same endpoint production uses — and evaluates whether the LLM followed its instructions or the injection hijacked it. Five tiers — Smoke Test (10 probes), LLM Quick (10 curated), LLM Suite (~200 balanced), Standard Scan (~4k), Full Sweep (~33k) — with counts pulled dynamically from your installed garak version. Requires `pip install garak`.

For model bake-offs (efficacy × latency × cost), use the `bulwark_bench` CLI — a sibling tool that sweeps the same probe tiers across multiple LLMs and prints a comparison table.

## Integrations

**OpenClaw** — Drop-in prompt injection defense for [OpenClaw](https://openclaw.ai) agents. A Docker sidecar + plugin hooks into OpenClaw's message pipeline at infrastructure level — the agent cannot bypass sanitization. Three hooks: `message:received`, `tool_result_persist`, `before_message_write`.

```bash
cd integrations/openclaw && ./install.sh
```

See [integrations/openclaw/README.md](integrations/openclaw/README.md).

**Wintermute** — Personal agent that runs Bulwark as a local Docker sidecar on `localhost:3000` and calls `POST /v1/clean` before feeding any external content (emails, documents, web pages) to its LLM. See [docs/integrations/wintermute.md](docs/integrations/wintermute.md) for the full integration guide — request/response shape, canary handling, auth, health checks, and failure modes.

**Any HTTP client** — the `/v1/clean` endpoint is language-agnostic. Run Bulwark once via `docker compose up -d`, point your agent at `http://localhost:3000/v1/clean`, check `response.blocked` before acting on content. [HTTP API reference](docs/api-reference.md).

## Development

Bulwark follows spec-driven development. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

Short version: write the spec first (`spec/openapi.yaml` for HTTP endpoints, `spec/contracts/*.yaml` for function guarantees), then write tests referencing guarantee IDs, then implement. CI enforces that specs and tests stay in sync.

Architecture decisions are recorded in `spec/decisions/`. Contract specs define what each function guarantees and, critically, what it does NOT guarantee.

## Install

```bash
# Docker (recommended)
docker run -p 3000:3000 nathandonaldson/bulwark

# Python
pip install bulwark-shield              # Core (zero deps)
pip install bulwark-shield[cli]         # CLI tools
pip install bulwark-shield[anthropic]   # Anthropic SDK
pip install bulwark-shield[dashboard]   # Dashboard
pip install bulwark-shield[testing]     # Garak red teaming
pip install bulwark-shield[all]         # Everything
```

Python 3.11+. [Detailed docs →](docs/)

## Limitations

- **AnalysisGuard is regex-based by default.** Plug in PromptGuard-86M for paraphrased attacks.
- **Canary tokens catch encoding tricks** (base64, hex, reversed) **but not semantic paraphrasing.**
- **Trust boundaries depend on LLM training.** Claude respects XML tags well. Other models vary.
- **The bridge is a residual risk.** Sanitized and guarded, but sophisticated attacks could craft benign-looking analysis.
- **English-focused.** Multilingual attacks may have lower detection rates.

Not a silver bullet. Raises the cost of successful injection from trivial to very hard.

## License

MIT
