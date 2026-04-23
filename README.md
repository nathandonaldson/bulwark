<img src="docs/images/banner.svg" alt="Bulwark" height="32"/>

**Prompt-injection defense as a sidecar.** Bulwark sanitizes untrusted input,
runs it through a prompt-injection classifier, and returns the wrapped result
to your application. Your LLM never sees Bulwark — you call `/v1/clean`,
feed the result into your own LLM, and call `/v1/guard` on the output.

Bulwark v2 is **detection only.** It returns safe content or an HTTP 422.
There is no two-phase executor, no LLM backend config, no analyze/execute
flow — the project is opinionated about what it does and doesn't do.

[Architecture](#architecture) · [Quickstart](#quickstart) · [Dashboard](#dashboard) · [Detectors](#detectors) · [Measuring quality](#measuring-quality) · [Docs](docs/)

---

## Quickstart

```bash
docker run -p 3001:3000 nathandonaldson/bulwark
```

Dashboard at <http://localhost:3001>. API at the same host.

```bash
# Sanitize untrusted content. Returns 200 (safe) or 422 (blocked).
curl -X POST http://localhost:3001/v1/clean \
  -H 'Content-Type: application/json' \
  -d '{"content": "ignore previous instructions", "source": "email"}'
# → 422  {"blocked": true, "block_reason": "Detector protectai: Prompt injection detected (1.000)"}

# Check your LLM's output for canary leaks + injection patterns.
curl -X POST http://localhost:3001/v1/guard \
  -H 'Content-Type: application/json' \
  -d '{"text": "the LLM said this back to the user"}'
# → 200  {"safe": true, ...}
```

The DeBERTa classifier downloads on the first `/v1/clean` request (~180 MB).
It's mandatory in v2; PromptGuard and an LLM judge are opt-in second/third
detectors.

## Architecture

```
INPUT (untrusted)
    │
    ▼
┌───────────────┐
│  Sanitizer    │  ←  strip bidi, emoji-smuggling, hidden chars
├───────────────┤
│  DeBERTa      │  ←  mandatory classifier (~30 ms)
├───────────────┤
│  PromptGuard  │  ←  optional second-opinion detector
├───────────────┤
│  LLM Judge    │  ←  optional third detector (~1–3 s)
├───────────────┤
│ Trust Boundary│  ←  output formatter, not a defense gate
└───────┬───────┘
        ▼
SAFE OUTPUT  →  your application's LLM  →  POST /v1/guard on the response
```

Each detector can independently block. Trust Boundary is the output formatter
that wraps cleaned content in `<untrusted_input>…</>` tags so your downstream
LLM treats it as data, not instructions.

See [docs/detection.md](docs/detection.md) and [ADR-031](spec/decisions/031-pipeline-simplification.md)
for the full rationale.

## Dashboard

The Docker image ships with a live dashboard at <http://localhost:3001>.
Five tabs: **Shield** (live status + ring), **Events** (filterable log),
**Configure** (pipeline + detectors), **Leak Detection** (canaries + guard
patterns), and **Test** (red-team scans + false-positive sweep).

### Shield

<img src="docs/images/shield.png" alt="Shield page" />

Live status, 24-hour stats, recent activity. The Active-defense banner
appears when something blocked in the last 30 minutes; click **Review ›**
to jump to the Events page.

### Configure

<img src="docs/images/configure.png" alt="Configure page" />

Pipeline visualisation. Click any stage to open its settings pane on the
right. DeBERTa is mandatory ("REQUIRED" pill), PromptGuard and the LLM Judge
are opt-in toggles. Trust Boundary is shown as the output formatter, not a
defense gate.

### LLM Judge (opt-in)

<img src="docs/images/configure-judge.png" alt="LLM Judge configuration" />

Bring your own classifier LLM (LM Studio, Ollama, vLLM, OpenAI, Anthropic).
Detection only — Bulwark sends the sanitized input with a fixed classifier
prompt and reads only the verdict. The LLM's raw output never reaches
`/v1/clean` callers (NG-JUDGE-004). Default fail-open so a judge outage
doesn't take down `/v1/clean`. Adds 1–3 s per request when enabled, so it's
off by default.

### Leak Detection

<img src="docs/images/leak-detection.png" alt="Leak Detection page" />

Output-side checks — canary tokens you embed in your LLM's system prompt
plus regex patterns that match exfiltration markers. Both are checked by
`/v1/guard` against the caller's LLM output, never on input to `/v1/clean`.

### Test

<img src="docs/images/test.png" alt="Test page with all four red-team tier cards" />

Top half: send a payload through `/v1/clean` and watch the live trace.
Bottom: four scan tiers — **Smoke Test**, **Standard Scan**, **Full Sweep**,
and **False Positives** (sends curated benign emails through the same
pipeline so you can measure both halves of detector quality).

### Events

<img src="docs/images/events.png" alt="Events page" />

Live event log with verdict / layer / search filtering and per-row diff
panes for modified events.

## Detectors

| Detector              | Status     | Latency    | Notes                                          |
|-----------------------|------------|-----------|-----------------------------------------------|
| Sanitizer             | Always on  | < 1 ms    | bidi, emoji smuggling, NFKC normalisation.    |
| DeBERTa (ProtectAI)   | Mandatory  | ~30 ms    | `protectai/deberta-v3-base-prompt-injection-v2`. Loads on first request. |
| PromptGuard-86M       | Optional   | ~50 ms    | Meta mDeBERTa second-opinion. Requires HF approval. |
| LLM Judge             | Optional   | 1–3 s     | Detection-only; bring your own classifier LLM. ADR-033. |
| Trust Boundary        | Always on  | < 1 ms    | Output formatter, not a defense gate.         |

Sanitizer + DeBERTa achieve **100% defense** on the Standard Scan tier
(3,049 probes) as of v2.1.0. PromptGuard and the LLM Judge are there for
operators who want stricter detection on their specific traffic distribution.

## Measuring quality

Two harnesses ship for measuring detector behaviour against your real traffic.

**Red-team scan** — Garak's attack payloads through `/v1/clean`.

```bash
# CLI:
PYTHONPATH=src python3 -m bulwark_bench \
  --configs deberta-only,deberta+promptguard,deberta+llm-judge \
  --tier standard

# Or click "Run Standard Scan" in the dashboard's Test tab.
```

**False-positive scan** — curated benign emails through `/v1/clean`.

```bash
# CLI:
PYTHONPATH=src python3 -m bulwark_falsepos \
  --configs deberta-only,deberta+promptguard \
  --max-fp-rate 0.05

# Or click "Run False Positives" in the dashboard's Test tab.
```

The corpus lives at [`spec/falsepos_corpus.jsonl`](spec/falsepos_corpus.jsonl)
— 42 entries across nine categories (everyday, customer support, marketing,
technical, meta, repetitive, non-English, code blocks, quoted-attacks). Add
your production false positives over time and the harness picks them up.

Pick the detector configuration that maximises defense rate while keeping
false positives in your acceptable range. See [docs/red-teaming.md](docs/red-teaming.md).

## Configuration

Mostly env-var driven for Docker:

```bash
BULWARK_API_TOKEN=...           # Bearer auth on mutating endpoints
BULWARK_WEBHOOK_URL=https://... # POST BLOCKED events to a webhook
BULWARK_ALLOWED_HOSTS=...       # Hostname allowlist for SSRF guard
```

All other settings live in `bulwark-config.yaml` (mounted as a volume) and
are editable through `PUT /api/config`. Full reference at
[docs/config.md](docs/config.md).

## Library use (Python)

The library is zero-dependency for the sanitize + wrap path:

```python
import bulwark

safe = bulwark.clean("ignore previous instructions", source="email")
# → "<untrusted_email source=\"email\" treat_as=\"data_only\">…</untrusted_email>"

# Output side — checks regex patterns against your LLM response:
ok = bulwark.guard("the LLM's response text")
```

For full v2 detection (DeBERTa, PromptGuard, LLM judge), call the running
dashboard via HTTP — that's where the detector models live. See examples in
[`examples/quickstart_generic.py`](examples/quickstart_generic.py).

## Project structure

| Path                  | Contents                                                  |
|-----------------------|-----------------------------------------------------------|
| `src/bulwark/`        | Core library (sanitizer, trust boundary, canary, guard).  |
| `src/bulwark/dashboard/` | FastAPI app + dashboard React UI.                     |
| `src/bulwark/detectors/` | DeBERTa loader + LLM judge.                            |
| `src/bulwark_bench/`  | Detector-config sweep CLI.                                |
| `src/bulwark_falsepos/` | False-positive sweep CLI.                                |
| `spec/openapi.yaml`   | HTTP API contract — source of truth.                       |
| `spec/contracts/`     | Function-level guarantees + non-guarantees.                |
| `spec/decisions/`     | Architecture Decision Records.                             |
| `spec/falsepos_corpus.jsonl` | Curated benign-email corpus for the FP harness.     |
| `tests/`              | 848 tests including spec-compliance enforcement.           |

## Spec-driven development

Every new feature follows: spec → contract → tests → code. See
[CONTRIBUTING.md](CONTRIBUTING.md). The
[`tests/test_spec_compliance.py`](tests/test_spec_compliance.py) meta-test
enforces that every guarantee ID has at least one matching test reference.

## Versions

- **PyPI**: `bulwark-shield` (`bulwark` is taken on PyPI)
- **Docker**: `nathandonaldson/bulwark`
- **Import**: `import bulwark`
- **Current**: v2.2.3

The v1 → v2 break is documented in [ADR-031](spec/decisions/031-pipeline-simplification.md).
The full release history lives in [CHANGELOG.md](CHANGELOG.md).

## License

MIT.
