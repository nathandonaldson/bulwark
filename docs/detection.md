# Detectors

Bulwark v2 ships with three detector slots. They run in order on every
`/v1/clean` request; each can independently block.

| Slot | Detector              | Status     | Latency    | Notes                                        |
|------|-----------------------|------------|-----------|---------------------------------------------|
| 1    | DeBERTa (ProtectAI)   | Mandatory  | ~30 ms    | Auto-loads on first request. Always on.     |
| 2    | PromptGuard-86M (Meta) | Optional  | ~50 ms    | Second-opinion. Requires HuggingFace approval. |
| 3    | LLM Judge             | Optional  | 1–3 s     | Detection-only — Bulwark never runs a generative LLM. ADR-033. |

The detection chain runs *after* the sanitizer (cheap, deterministic) and
*before* the trust boundary wrap. A blocking verdict from any detector
returns HTTP 422; otherwise the cleaned content gets wrapped and returned 200.

## DeBERTa (mandatory)

`protectai/deberta-v3-base-prompt-injection-v2` — ungated, ~180 MB. Loaded on
the first `/v1/clean` request after server start. Inputs over 512 tokens are
chunked into overlapping windows so the detector sees the entire payload
(ADR-032).

The dashboard's Configure tab shows DeBERTa's status (Loading / Ready /
Error) on its pipeline stage card.

## PromptGuard (optional)

`meta-llama/Prompt-Guard-86M` — Meta's mDeBERTa second-opinion classifier.
Requires HuggingFace approval before download.

Enable from the dashboard:

1. Configure → click the "PromptGuard (optional)" stage card
2. Click **Enable PromptGuard** in the detail pane
3. The model downloads and registers in `_detection_checks`

When enabled, PromptGuard runs alongside DeBERTa on every `/v1/clean` request
and can independently block.

## LLM Judge (optional, ADR-033)

A detector that delegates classification to an LLM. **Detection only** — the
LLM's raw output never reaches `/v1/clean` callers (NG-JUDGE-004). Bulwark
sends the sanitized input plus a fixed classifier prompt and parses the
verdict only.

Enable from the dashboard:

1. Configure → click the "LLM Judge (optional)" stage card
2. Set mode (`openai_compatible` or `anthropic`), base URL, and model
3. Click **Save settings** then **Enable judge**

Default failure mode is **fail-open**: a judge timeout or unreachable
endpoint logs the error and lets the request continue. Set `fail_open: false`
in `bulwark-config.yaml` to fail-closed (return 422 on judge error).

The classifier prompt is fixed in code (NG-JUDGE-003). Editing it would
re-open the v1 jailbreak surface ADR-031 closed.

## Measuring detector quality

Two harnesses ship for measuring detector behaviour against your traffic:

- **Red-team scan** (Test page → Smoke / Standard / Full Sweep) — measures
  defense rate against Garak's attack probes.
- **False-positive scan** (Test page → False Positives) — measures false-positive
  rate against the curated benign corpus at `spec/falsepos_corpus.jsonl`.

Pick the detector configuration that maximises defense rate while keeping
false positives in your acceptable range. The Standard tier achieves 100%
defense on `deberta-only` as of v2.1.0.

## Adding a custom detector

Any callable that raises `bulwark.guard.SuspiciousPatternError` on a block
can be registered as a detector. The dashboard's `_detection_checks` dict
maps integration name → check function:

```python
from bulwark.guard import SuspiciousPatternError

def my_check(text: str) -> None:
    if "boom" in text:
        raise SuspiciousPatternError("custom detector flagged 'boom'")
```

Wire it into the dashboard via the integration loader. See
`src/bulwark/integrations/promptguard.py` for the canonical example.
