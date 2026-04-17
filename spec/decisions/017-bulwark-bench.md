# ADR-017: `bulwark_bench` — sibling CLI for LLM model benchmarking

**Status:** Accepted
**Date:** 2026-04-17

## Context

Bulwark's defense posture depends on which LLM is wired into the pipeline.
A brittle analyze model that follows injections will tank defense rate;
a slow model will make the pipeline unusable; an expensive model will
blow the budget. Today there is no structured way to compare models on
the three axes that matter — **efficacy, speed, cost** — against the
same probe suite.

Red-team reports in the dashboard answer "how defended is my current
pipeline?" but they do not sweep. To pick a model, a user has to
manually swap env vars, restart, re-run the tier, and eyeball numbers
across JSON files. That is slow, error-prone, and doesn't resume after
a crash — a 40-minute sweep is one power blip away from starting over.

## Decision

Ship a sibling Python package `bulwark_bench` (imported as
`import bulwark_bench`, invoked as `python -m bulwark_bench`) that:

1. Takes a list of up to N models and drives them sequentially through
   the same probe suite against a running Bulwark dashboard.
2. Uses the dashboard's own HTTP API to swap models (`PUT /api/config`)
   and run red-team tiers (`POST /api/redteam/start`, poll
   `GET /api/redteam/status`). Reuses the three-way scoring already
   proven in G-REDTEAM-SCORE-001..007 — the efficacy number matches
   what the dashboard reports.
3. Computes:
   - **Efficacy** — `defense_rate` + hijack count from the tier result.
   - **Speed** — `duration_s / total` = avg wall-clock per probe.
     Cold-start and steady-state are both exposed by running an
     optional warmup probe before the timed run.
   - **Cost** — `tokens_in × $/Mtok_in + tokens_out × $/Mtok_out` using
     a hardcoded pricing table. A single pre-run sample call to the
     model estimates tokens-per-probe; cost = estimate × probe count.
     Local inference pricing defaults to $0.
4. Is **resumable** — each completed model's result is persisted to
   disk as it finishes. A restarted run with `--resume` skips models
   whose result file already exists. Persist-then-continue, never
   buffer-then-dump.
5. Emits two artifacts per run: `report.json` (machine-readable,
   suitable for diffing across runs) and `report.md` (human-readable
   comparison table sorted by defense rate).

## Consequences

### Positive
- Users can empirically answer "which model for my threat model?"
  against their own prompt-injection corpus, not a synthetic benchmark.
- Reusing the dashboard API means zero new scoring code — same metrics,
  same bugs, same contracts.
- Resume turns a "start over" catastrophe into a "pick up where we left
  off" annoyance. Essential for local-GPU sweeps that take an hour+.
- Sibling package keeps `src/bulwark/` zero-dependency; bench can depend
  on httpx freely.

### Negative
- Token counting is an estimate (single-sample extrapolation). Real
  probe-by-probe variance is not captured. Acceptable for ranking
  models but not for dollar-accurate billing reconciliation.
- Pricing table goes stale when providers change rates. Documented
  cost is "$/Mtok as of the pricing table"; users can edit
  `bulwark_bench/pricing.py` or pass `--pricing custom.json` to
  override.
- A dashboard running auth-protected will need a bearer token exposed
  to the bench CLI (`--token` / `BULWARK_API_TOKEN` env). By design —
  don't paper over it.

### Neutral
- Sibling package rather than a script — future extension (leaderboard
  history, HTML report, multi-host parallel sweep) doesn't require
  repackaging. PyPI publish is opt-in; for now it lives in-repo only.

### Explicit non-goals (for v1)
- **No parallel execution across models.** Sequential by requirement;
  parallel would compete for local GPU RAM and confuse latency
  numbers.
- **No pipeline instrumentation.** `_openai_chat` is not changed;
  token accounting is done by a direct sample call from the bench
  runner, not by the pipeline. Keeps Bulwark's core unchanged.
- **No web UI.** CLI + markdown + JSON is enough.
