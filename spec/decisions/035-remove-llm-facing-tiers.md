# ADR-035: Remove llm-quick / llm-suite red-team tiers

**Status:** Accepted
**Date:** 2026-04-23

## Context

ADR-018 introduced `llm-quick` and `llm-suite` tiers — curated probe
classes selected for high empirical "LLM-reach" rate. They paired with
`bulwark_bench --bypass-detectors`, which disabled DeBERTa/PromptGuard
so probes would actually reach the analyze LLM and the bench could
compare model responses.

Both pillars are gone:

- ADR-031 removed the analyze LLM from the pipeline entirely. There
  is nothing behind the detectors for the curated tiers to reach.
- ADR-034 rebuilt `bulwark_bench` as a detector-config sweep with no
  `--bypass-detectors` flag.

The Standard tier already exercises every active probe (3,112 probes;
100% defense as of v2.1.0). The curated LLM tiers no longer answer a
question we can ask.

## Decision

Remove `llm-quick` and `llm-suite` from `/api/redteam/tiers` and from
`ProductionRedTeam.TIER_CLASS_SELECTORS`. ADR-018 is superseded.

The dashboard's red-team UI surfaces three tiers: **Smoke Test**,
**Standard Scan**, **Full Sweep**.

## Consequences

### Positive
- One less concept to explain. Tier list reflects what `/v1/clean`
  actually does in v2.
- Removes ~50 lines of dead curation data from `redteam.py` and the
  matching meta-test.

### Negative
- Saved bench invocations referencing `--tier llm-quick` or
  `--tier llm-suite` stop working. CHANGELOG documents the removal.

### Neutral
- ADR-018 marked Superseded. Spec contract `llm_facing_tiers.yaml` and
  test `test_llm_facing_tiers.py` deleted.
- `TIER_CLASS_SELECTORS` is now an empty dict for back-compat — the
  fallback path in `_get_tier_payloads` handles unknown tiers cleanly.
