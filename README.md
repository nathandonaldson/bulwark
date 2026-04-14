<img src="docs/images/banner.svg" alt="Bulwark" height="32"/>

Prompt injection defense through architecture, not detection. Zero core dependencies.

Other tools try to classify input as safe or unsafe. Bulwark separates reading from acting so even a successful injection can't trigger tools, steal data, or poison other items. The deterministic layers run in under 1ms. Detection tools plug in at the bridge for additional coverage.

## See it work

```bash
pip install "git+https://github.com/nathandonaldson/bulwark.git#egg=bulwark-ai[cli]"
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

## Quick start

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

## HTTP API (language-agnostic)

Run Bulwark as a standalone service. Any language can call it.

```bash
pip install bulwark-ai[dashboard]
PYTHONPATH=src python -m dashboard --port 3000
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

```bash
PYTHONPATH=src python -m dashboard --port 3000
```

Connect your pipeline: `emitter=WebhookEmitter("http://localhost:3000/api/events")`

Binds to localhost by default. `--host 0.0.0.0` to expose on the network (no auth, be careful).

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

## Comparison

| | Bulwark | Rebuff | LLM Guard | PromptGuard | LlamaFirewall |
|---|---|---|---|---|---|
| Two-phase execution | Yes | — | — | — | — |
| Cross-item isolation | Yes | — | — | — | — |
| Pluggable detection | Yes | — | — | — | — |
| HTTP API | Yes | — | — | — | — |
| Local inference | Yes | — | — | — | — |
| Production red teaming | 315 probes | — | — | — | — |
| Zero dependencies | Yes | No | No | No | No |
| Deterministic layers | <1ms | — | — | — | — |

Bulwark is the architecture. These tools are the detection. Use both.

## Development

Bulwark follows spec-driven development. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

Short version: write the spec first (`spec/openapi.yaml` for HTTP endpoints, `spec/contracts/*.yaml` for function guarantees), then write tests referencing guarantee IDs, then implement. CI enforces that specs and tests stay in sync.

Architecture decisions are recorded in `spec/decisions/`. Contract specs define what each function guarantees and, critically, what it does NOT guarantee.

## Install

```bash
pip install bulwark-ai              # Core (zero deps)
pip install bulwark-ai[cli]         # CLI tools
pip install bulwark-ai[anthropic]   # Anthropic SDK
pip install bulwark-ai[dashboard]   # Dashboard
pip install bulwark-ai[testing]     # Garak red teaming
pip install bulwark-ai[all]         # Everything
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
