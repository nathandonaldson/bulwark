# ADR-033: LLM judge as an opt-in detection stage

**Status:** Accepted
**Date:** 2026-04-23

## Context

v2.0.0 (ADR-031) removed the two-phase executor on the principle that
Bulwark returns safe content or an error and never invokes an LLM. That
remains the design. The detection chain is `Sanitizer → DeBERTa
(mandatory) → PromptGuard (optional)` and a Standard-tier red-team scan
of 3,112 probes produced a 100% defense rate.

There is, however, a real use case for users with a **purpose-built
prompt-injection-judge LLM** (e.g. a fine-tuned 8B model behind LM
Studio) who want a third-opinion classifier that the regex/transformer
detectors cannot replicate. The cost is significant — typical
classification latency is 1–3 seconds vs ~30 ms for DeBERTa — so this
must be opt-in and clearly labelled as a high-latency option.

Critically, the LLM judge is **detection only**:
- Bulwark sends the sanitized input to the LLM with a fixed classifier
  prompt asking for `SAFE` or `INJECTION`.
- Bulwark does not send tools, system prompts the user controls,
  conversation history, or any generative payload.
- Bulwark does not return the LLM's output to the caller. Only the
  verdict (SAFE/INJECTION) and confidence score reach `/v1/clean`.

This is structurally identical to how PromptGuard is wired — same
"third detector" slot, just running inference over the network instead
of locally.

## Decision

Add an opt-in `judge_backend` to `BulwarkConfig` and a new
`bulwark.detectors.llm_judge` module. The detection chain becomes:

```
Sanitizer → DeBERTa → PromptGuard (opt) → LLM Judge (opt) → Trust Boundary
```

### Configuration

```yaml
judge_backend:
  enabled: false                             # Default off.
  mode: openai_compatible                    # or anthropic
  base_url: http://192.168.1.78:1234/v1
  api_key: ""                                # Optional for OpenAI-compatible.
  model: prompt-injection-judge-8b
  threshold: 0.85                            # Confidence ≥ threshold blocks.
  fail_open: true                            # Network/parse failure → log + pass.
```

### Classifier prompt (fixed in code)

The judge receives a system prompt that:
- Names its role (prompt-injection classifier).
- Demands a single-line JSON object: `{"verdict": "SAFE" | "INJECTION", "confidence": 0..1}`.
- Wraps the user content in `<input>...</input>` markers so the model
  cannot mistake the user payload for system instructions.

The user prompt template is not user-editable. Letting users tweak the
classifier prompt would re-introduce all the v1 jailbreak surface we
removed in ADR-031.

### Failure mode

Default fail-open: if the judge endpoint times out, returns garbage,
or refuses TLS, the request continues to trust-boundary wrap and
returns 200. The trace records `judge: error` so the operator sees it.
DeBERTa already gated; the judge is bonus signal, not a single point
of failure.

`fail_open: false` flips this to fail-closed (return 422 on judge
error). Recommended only for users running the judge on the same host
as Bulwark, where reachability is essentially guaranteed.

### Network safety

`base_url` reuses the existing `validate_external_url()` allowlist
(ADR-030, G-WEBHOOK-007) — private/loopback/metadata hosts are
rejected at config-write time unless explicitly allowlisted via
`BULWARK_ALLOWED_HOSTS`. Same surface as the webhook URL check.

## Consequences

### Positive
- Power users with judge models get a third detector; the rest stay
  on the fast DeBERTa+PromptGuard path with no added latency.
- Adds zero dependencies — uses `httpx` (already in dashboard deps).
- Trace gains a `detection:llm_judge` entry; observability stays
  consistent with other detectors.
- Enables the `bulwark_bench` detector-config sweep
  (DeBERTa-only vs DeBERTa+PromptGuard vs DeBERTa+LLM) — see
  the upcoming bench rebuild.

### Negative
- Restores a small piece of LLM-config surface to the dashboard.
  Mitigated by scoping it to *judge* (single field set, no
  per-phase splits, no chat templates, no tools).
- 1–3 s added latency when enabled. Documented loudly in the UI.
- Network dependency on the judge endpoint. Default fail-open keeps
  this from being a soft outage trigger.

### Neutral
- Does NOT re-introduce `TwoPhaseExecutor`, `analyze_fn`, `execute_fn`,
  `bridge_sanitizer`, or any generative LLM call. ADR-031 stands.
- Bench rebuild lives in a separate ADR (ADR-034) — that work changes
  the bench harness from a model-sweep to a detector-config sweep.
