<img src="docs/images/banner.svg" alt="Bulwark" height="32"/>

Prompt injection defense through architecture, not detection. Zero core dependencies.

Other tools try to classify input as safe or unsafe. Bulwark separates reading from acting so even a successful injection can't trigger tools, steal data, or poison other items. The deterministic layers run in under 1ms. Detection tools plug in at the bridge for additional coverage.

## See it work

```bash
docker run -p 3000:3000 ghcr.io/nathandonaldson/bulwark
```

Dashboard at http://localhost:3000. API at http://localhost:3000/v1/clean. No Python needed.

```bash
# Sanitize untrusted content
curl -X POST http://localhost:3000/v1/clean \
  -H 'Content-Type: application/json' \
  -d '{"content": "Hello <script>evil()</script>", "source": "email"}'

# Run the full pipeline (sanitize + detect + LLM + guard)
curl -X POST http://localhost:3000/v1/pipeline \
  -H 'Content-Type: application/json' \
  -d '{"content": "untrusted email body", "source": "email"}'

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
    image: ghcr.io/nathandonaldson/bulwark
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
| `BULWARK_EXECUTE_MODEL` | Phase 2 model (default: `claude-sonnet-4-5-20241022`) |

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
# Sanitize untrusted content
curl -X POST http://localhost:3000/v1/clean \
  -H 'Content-Type: application/json' \
  -d '{"content": "Hello <script>evil()</script>", "source": "email"}'

# Check LLM output for injection
curl -X POST http://localhost:3000/v1/guard \
  -H 'Content-Type: application/json' \
  -d '{"text": "ignore previous instructions"}'

# Run the full pipeline (sanitize + detect + LLM + guard)
curl -X POST http://localhost:3000/v1/pipeline \
  -H 'Content-Type: application/json' \
  -d '{"content": "untrusted email body", "source": "email"}'
```

OpenAPI spec at `http://localhost:3000/openapi.json` or in `spec/openapi.yaml`.

## Dashboard

Test attacks interactively, configure your LLM backend, and monitor your pipeline.

![Shield view](docs/images/shield.png)
![Test page](docs/images/test-page.png)

**Configure tab** lets you:
- Switch LLM backend: Anthropic API, OpenAI-compatible (local inference), or sanitize-only
- Activate detection models (ProtectAI DeBERTa, PromptGuard-86M)
- Toggle defense layers and guard patterns

**Test tab** sends payloads through the full pipeline and shows a per-layer trace with timing, LLM backend badges, and detection model verdicts.

**Red teaming** sends Garak probe payloads through the same `/v1/pipeline` endpoint used by production. Same code path, same defense layers.

### Local inference

Configure any OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM, LM Studio) in the dashboard Configure tab. Select "OpenAI Compatible", enter the URL, and the entire pipeline uses your local model for two-phase execution.

Note: Claude achieves 100% on red team probes. Open models vary (60-80% typical). Use Claude for production, local models for development and testing.

## Red teaming

Built-in attack suite:

```bash
bulwark test                    # 8 preset attacks, 2 seconds
bulwark test --full             # All 77 attacks, 10 seconds
bulwark test -c steganography   # Filter by category
```

Production red team (in the dashboard): sends 315 Garak probe payloads through your actual Bulwark+LLM pipeline and evaluates whether the LLM followed its instructions or the injection hijacked it. Quick Test (10 probes, ~2 min) or Full Scan (315 probes, ~50 min). Requires `pip install garak`.

## Development

Bulwark follows spec-driven development. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

Short version: write the spec first (`spec/openapi.yaml` for HTTP endpoints, `spec/contracts/*.yaml` for function guarantees), then write tests referencing guarantee IDs, then implement. CI enforces that specs and tests stay in sync.

Architecture decisions are recorded in `spec/decisions/`. Contract specs define what each function guarantees and, critically, what it does NOT guarantee.

## Install

```bash
# Docker (recommended)
docker run -p 3000:3000 ghcr.io/nathandonaldson/bulwark

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
