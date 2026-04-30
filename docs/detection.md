# Detectors

Bulwark v2 ships with three detector slots. They run in order on every
`/v1/clean` request; each can independently block.

| Slot | Detector              | Status     | Latency    | Notes                                        |
|------|-----------------------|------------|-----------|---------------------------------------------|
| 1    | DeBERTa (ProtectAI)   | Mandatory  | ~30 ms    | Auto-loads at container startup. Always on. |
| 2    | PromptGuard-86M (Meta) | Optional  | ~50 ms    | Second-opinion. Requires HuggingFace approval. |
| 3    | LLM Judge             | Optional  | 1–3 s     | Detection-only — Bulwark never runs a generative LLM. ADR-033. |

The detection chain runs *after* the sanitizer (cheap, deterministic) and
*before* the trust boundary wrap. A blocking verdict from any detector
returns HTTP 422; otherwise the cleaned content gets wrapped and returned 200.

`bulwark.detector_chain.run_detector_chain` is the single source of
truth for chain execution (ADR-048) — both `Pipeline.run()` and the
HTTP `/v1/clean` route delegate to it, so library and dashboard always
behave identically.

## DeBERTa (mandatory)

`protectai/deberta-v3-base-prompt-injection-v2` — ungated, ~180 MB.
Loaded at FastAPI startup via `_auto_load_detection_models`; a fresh
container with no cache pays the ~180 MB download once on first boot
and caches the weights.

Inputs longer than ~510 tokens are chunked into overlapping 510-token
windows with 64-token overlap; up to 64 windows are batched per
inference call (ADR-032). The 512-token model ceiling minus the two
reserved `[CLS]/[SEP]` slots gives 510 usable tokens per window.

The dashboard's Configure tab shows DeBERTa's status (Loading / Ready /
Error) on its pipeline stage card.

## PromptGuard (optional)

`meta-llama/Prompt-Guard-86M` — Meta's mDeBERTa second-opinion classifier.
Requires HuggingFace approval before download.

Enable from the dashboard:

1. Configure → click the "PromptGuard (optional)" stage card
2. Click **Enable PromptGuard** in the detail pane

When enabled, PromptGuard runs alongside DeBERTa on every `/v1/clean` request
and can independently block.

## LLM Judge (optional, ADR-033)

A detector that delegates classification to an LLM. **Detection only** — the
LLM's raw output never reaches `/v1/clean` callers (NG-JUDGE-004; the
`JudgeVerdict.raw` field is held server-side and never surfaced). The
chain wraps the input between unique nonce-delimited markers
(`[INPUT_<nonce>_START]` / `[INPUT_<nonce>_END]`) before sending it to
the judge, and parses only `verdict` / `confidence` / `latency` from the
response.

Enable from the dashboard:

1. Configure → click the "LLM Judge (optional)" stage card
2. Set mode (`openai_compatible` or `anthropic`), base URL, and model
3. Click **Save settings** then **Enable judge**

Default failure mode is **fail-open**: a judge timeout or unreachable
endpoint logs the error and lets the request continue. Set `fail_open: false`
in `bulwark-config.yaml` to fail-closed (return 422 on judge error).

The classifier prompt is fixed in code (NG-JUDGE-003 / ADR-037). Editing
it would re-open the v1 jailbreak surface ADR-031 closed.

## Decode-rescan (ADR-047)

`/v1/clean` runs the detector chain over decoded variants of the input
in addition to the original cleaned text:

- **ROT13** — always on. Zero false-positive cost (the decode is a
  pure character substitution that only matches a payload-shaped
  original).
- **Base64** — opt-in via `BULWARK_DECODE_BASE64=1` (env) or
  `decode_base64: true` in `bulwark-config.yaml`. Trades a small
  false-positive uptick for base64-encoded injection coverage.

The decoder caps at 16 candidate variants per request, applies a
printable-ASCII quality gate (≥80% printable bytes, ≥10 decoded bytes)
to skip noise, and decodes nested encodings up to depth 2. Each
detector runs once per surviving variant; the trust boundary always
wraps the **original** cleaned text — variants are detection-only
fan-out, never returned to the caller (NG-CLEAN-DECODE-VARIANTS-PRESERVED-001).

The 200 response carries `decoded_variants` (the variants the chain saw)
and `blocked_at_variant` (index if a variant blocked, else `null`). Per-event
trace entries also annotate which variant produced each verdict.

## Operator opt-outs

Two env vars let an operator override the default fail-closed posture
when no detectors load. Both default to *unset*; set to `1` to opt in.

| Var                            | Effect                                                                                            | ADR |
|--------------------------------|---------------------------------------------------------------------------------------------------|-----|
| `BULWARK_ALLOW_NO_DETECTORS=1` | `/v1/clean` returns 200 with `mode: "degraded-explicit"` instead of 503 when zero detectors load. Every request in that mode is logged at WARNING. | ADR-040 |
| `BULWARK_ALLOW_SANITIZE_ONLY=1`| `/healthz` reports `status: "ok"` instead of `"degraded"` when zero detectors are loaded.         | ADR-038 |

Operators running Bulwark as a dev shim (no detectors, sanitizer only)
flip both. Production deployments leave both unset.

## Known non-guarantees

- **NG-DETECTOR-WINDOW-EVASION-001** (ADR-046) — long-range split-evasion
  with ≥~50 tokens of benign filler between the trigger and the
  instruction is out of scope for the per-window classifier; the
  dilution is a model-context limit, not a chunking artefact. If
  dilution-style attacks are in your threat model, enable the LLM Judge
  (ADR-033).
- **NG-CLEAN-DECODE-VARIANTS-PRESERVED-001** — decoded variants are
  scanned but never returned in the trust-boundary wrap. The downstream
  LLM only ever sees the original cleaned text.
- **NG-JUDGE-003** — the LLM-judge classifier prompt is fixed in code,
  not configurable.
- **NG-JUDGE-004** — the LLM-judge raw text never reaches `/v1/clean`
  callers; only `verdict` / `confidence` / `latency` are surfaced.

## Measuring detector quality

Two harnesses ship for measuring detector behaviour against your traffic:

- **Red-team scan** (Test page → Smoke / Standard / Full Sweep) — measures
  defense rate against Garak's attack probes.
- **False-positive scan** (Test page → False Positives) — measures false-positive
  rate against the curated benign corpus at `spec/falsepos_corpus.jsonl`.

Pick the detector configuration that maximises defense rate while
keeping false positives in your acceptable range. The v2.1.0 baseline
hit 100% defense on the Standard tier with `deberta-only`; run the
Standard tier in your environment to get a current number against your
installed garak version.

## Adding a custom detector

A custom detector is any callable that raises
`bulwark.guard.SuspiciousPatternError` on a block. Wire it in via the
library `Pipeline` (ADR-044):

```python
from bulwark import Pipeline
from bulwark.guard import SuspiciousPatternError

def my_check(text: str) -> None:
    if "boom" in text:
        raise SuspiciousPatternError("custom detector flagged 'boom'")

pipeline = Pipeline.from_config("bulwark-config.yaml", detectors=[my_check])
```

The dashboard exposes the same callable surface via its integrations
loader — see `src/bulwark/integrations/promptguard.py` for the
canonical example of a detector that registers itself for the dashboard
chain.
