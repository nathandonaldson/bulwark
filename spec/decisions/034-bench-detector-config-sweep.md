# ADR-034: Rebuild bulwark_bench as a detector-config sweep

**Status:** Accepted
**Date:** 2026-04-23

## Context

`bulwark_bench` v1 was a model-comparison harness — it swapped
`llm_backend.analyze_model` per iteration and measured defense rate /
latency / cost. v2.0.0 (ADR-031) removed `llm_backend`; the swap target
is gone, and the bench has been silently broken since.

The natural v2 axis is **detector configuration**:

- DeBERTa only (the default)
- DeBERTa + PromptGuard
- DeBERTa + LLM judge (ADR-033)
- DeBERTa + PromptGuard + LLM judge (everything)

This answers the actual user question: "is DeBERTa enough or do I need
to layer more detectors on for *my* attack distribution?" The same
red-team-tier metric (`defense_rate`) is meaningful and comparable.

## Decision

Rebuild `bulwark_bench` to sweep detector configurations rather than
LLM models. Same harness shape (sequential, persists per-config result,
markdown + JSON report); only the swap target changes.

### Configurations

Predefined presets keyed by short slug:

| Slug                       | DeBERTa | PromptGuard | LLM judge |
|----------------------------|---------|-------------|-----------|
| `deberta-only`             | ✓       |             |           |
| `deberta+promptguard`      | ✓       | ✓           |           |
| `deberta+llm-judge`        | ✓       |             | ✓         |
| `all`                      | ✓       | ✓           | ✓         |

DeBERTa is always on — it's mandatory in v2 (ADR-031).

### CLI

```
bulwark_bench --configs deberta-only,deberta+promptguard,deberta+llm-judge \
              --tier standard \
              --bulwark http://localhost:3001
```

`--judge-base-url` and `--judge-model` are required when any selected
config includes the LLM judge.

### Bench client

`bulwark_client.swap_model()` is removed. Replaced with
`apply_detector_config(name)` that:
- ensures DeBERTa is loaded (POST `/api/integrations/protectai/activate`
  if not already active)
- enables/disables PromptGuard via `set_integration_enabled`
- toggles `judge_backend.enabled` and updates `base_url` / `model` via
  PUT `/api/config`
- returns the active configuration snapshot for the report

### Metrics

- `defense_rate`, `defended`, `hijacked`, `format_failures`, `total` —
  unchanged, lifted from the red-team result.
- `avg_latency_s` per probe — unchanged.
- `cost_usd` — drop. The config sweep doesn't pay per-token costs in any
  meaningful way (DeBERTa is local, PromptGuard is local, judge depends
  on the operator's deployment). The pricing module stays in the repo
  for reference but is unused.
- `per_family` — kept; useful for spotting which categories the LLM
  judge actually improves.

### Report

Markdown table sorted by `defense_rate desc`, then `avg_latency_s asc`.
JSON keeps the same top-level keys, with `models` renamed to
`configurations`.

## Consequences

### Positive
- Bench works again on v2.
- The output answers a question users actually have. The 100% defense
  rate on DeBERTa-only (Standard tier, 3,112 probes) is the baseline;
  the bench can quantify whether adding PromptGuard or the LLM judge
  closes any remaining gap.
- No new external dependencies — uses the same `httpx` client.

### Negative
- Existing v1 bench scripts (saved invocations, README snippets) break.
  Documented in CHANGELOG; the v1 model-sweep flow no longer makes
  sense post-ADR-031.
- Cost reporting drops out. Pricing table sits dormant — could be
  resurrected if generative LLM judging gets a price-per-call surface.

### Neutral
- Existing per-model JSON files won't be backward-compatible with the
  new report shape. Any old `report.json` in `benchmarks/` should be
  regenerated.
