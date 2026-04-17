# ADR-018: LLM-facing red-team tiers (`llm-quick`, `llm-suite`)

**Status:** Accepted
**Date:** 2026-04-17

## Context

The existing red-team tiers — `quick` (10 probes), `standard` (4270), `full`
(32765) — don't answer the question "how well does *this LLM* defend against
prompt injection?" because the pipeline's ML detectors (ProtectAI ~30%,
PromptGuard ~63%) catch most probes before they ever reach the analyze stage.
Analysis of real reports in `reports/` shows only ~6% of `standard`-tier
probes actually reach the LLM. For model benchmarking (see ADR-017 /
`bulwark_bench`), that's not a useful signal — a broken LLM and a perfect
LLM both score 100% on `quick` because ProtectAI silently carries the load.

## Decision

Add two curated tiers that live alongside the existing ones:

- **`llm-quick`** — 10 probes across 10 attack families (latent injection,
  encoding bypass, divergence/DRA, credential extraction, adversarial suffix,
  markdown exfil, data leakage, jailbreak). One prompt per class.
- **`llm-suite`** — ~200 probes across 16 attack families, with per-class
  prompt caps (5–10) so no single family dominates.

Probe classes were selected from four historical reports (one full, three
standard) totaling 47k observations. Selection criteria: classes with the
highest *absolute* LLM-reach count across runs, then prioritized for family
diversity. Every class listed had ≥5 LLM reaches in the data, and together
they span every attack family with any historical reach.

### Reach rate vs. detector bypass

Even the best-reaching classes only hit the LLM ~40% of the time with full
detection on (latent injection tops out at 43%; encoding at ~20%). To make
these tiers "actually hit the LLM" as intended, users pair them with
`bulwark_bench --bypass-detectors protectai,promptguard`, which toggles
those integrations off for the sweep and restores them on exit
(G-BENCH-011). This is opt-in so the tiers remain valid to run against a
production stack — you just won't learn as much about LLM efficacy that
way.

### Tier selection format

`TIER_FAMILIES` stays (family-level selection for `quick`/`standard`/`full`).
New `TIER_CLASS_SELECTORS` maps tier id → list of `(family, class, max_prompts)`
tuples. `_get_tier_payloads` checks `TIER_CLASS_SELECTORS` first; falls back
to `TIER_FAMILIES` otherwise. Existing tiers unchanged.

## Consequences

### Positive
- Model-comparison benchmarks now have a signal. Pair with
  `bulwark_bench --tier llm-suite --bypass-detectors protectai,promptguard`
  and you actually measure LLM prompt-injection resilience.
- Data-driven curation — the probe list came from what garak's probes
  actually do against *this* pipeline, not a guess.
- Tier addition is additive; no breaking changes.

### Negative
- Curated list will drift when garak changes probes. The code silently
  skips unavailable classes rather than erroring, but reach rates can
  shift between garak versions. Re-curate when garak minor-bumps.
- ~200 prompts × 5 models × ~1–5s LLM latency = 15–85 minutes per sweep.
  Acceptable for benchmarking; not for a smoke test.
- Bypass is a session-level toggle. If the user Ctrl+Cs between the
  disable and the restore (rare — restore is in `finally`), they must
  re-enable detectors manually. Dashboard UI makes this easy.

### Neutral
- `quick` tier is still useful for pipeline smoke-tests (its probes mostly
  test ProtectAI, which is fine when the goal is "did my dashboard come
  up?"). We don't remove or change it.

### Explicit non-goals
- **No auto-bypass.** The tier itself never changes detector state; only
  the bench tool (via `--bypass-detectors`) does, and it's explicit.
- **No "adaptive" probe selection.** Per-model probe lists would make
  results non-comparable across models. Same probes, same order, same
  caps, every run.
