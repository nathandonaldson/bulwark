---
name: bulwark-bench
description: |
  Run bulwark_bench to compare LLM models on prompt-injection defense —
  efficacy (defense rate), speed (avg latency), and cost (USD from the pricing
  table). Lets the user pick from the models currently available via the
  configured LM Studio / local endpoint plus a known Anthropic list, choose a
  tier (llm-quick, llm-suite, quick, standard), and decide whether to bypass
  ML detectors so probes are guaranteed to reach the analyze LLM. Runs the
  sweep inside a subagent so the main conversation stays responsive; reports
  the markdown comparison table when done.
  Use when: "benchmark models", "compare llms", "bulwark bench", "run a model
  sweep", "which model defends best", "llm benchmark".
allowed-tools:
  - Bash
  - Read
  - Write
  - Glob
  - Agent
  - AskUserQuestion
---

# bulwark-bench

Run `bulwark_bench` end-to-end and report the comparison. Use a subagent for
the actual sweep so the main conversation stays responsive — local-GPU
standard-tier sweeps take 10+ minutes per model.

## 0. Safety / prerequisites

Before anything else, confirm:

1. **Working directory is a bulwark-shield checkout.** Run
   `test -f pyproject.toml && grep -q '"bulwark-shield"' pyproject.toml` —
   if it fails, tell the user and stop.
2. **Dashboard is up.** `curl -sf http://localhost:3001/healthz` (or the
   port the user specifies). Report the `version` field so the user knows
   which Bulwark they're running against.
3. **.venv exists and garak is installed there.** `test -x .venv/bin/python`
   — if missing, tell the user they need to create the venv (CLAUDE.md
   documents this) and stop.

If any check fails, stop with a clear message. Don't try to "fix" the user's
environment.

## 1. Discover available models

Query the LM Studio / local-inference endpoint for models the user has
loaded. The endpoint URL lives in the dashboard config:

```bash
BULWARK_URL="${BULWARK_URL:-http://localhost:3001}"
curl -s "$BULWARK_URL/api/config" \
  | python3 -c "import sys,json; b=json.load(sys.stdin)['llm_backend']; print(b.get('base_url',''))"
```

If `base_url` is set, fetch its `/models` list:

```bash
curl -s "${BASE_URL}/models" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(m['id'] for m in d.get('data',[])))"
```

Combine that list with these Anthropic models (always available if the user
has `BULWARK_API_KEY`):

```
claude-haiku-4-5
claude-sonnet-4-6
claude-opus-4-7
```

If fetch fails, fall back to asking the user to type models directly.

## 2. Ask the user what to run

Use `AskUserQuestion` with three questions:

**Q1: models** — a multi-select from the discovered list. Default to "all
local models, up to 5". Cap the selection at 5 (tell the user if they pick
more). If the user picked Anthropic models, confirm their API key will be
used from `BULWARK_API_KEY`.

**Q2: tier** — single-select. Options and guidance:
- `llm-quick` — 10 probes, 10 families, ~5 min per model. Good for smoke
  comparisons.
- `llm-suite` — ~200 probes, 16 families, 30–60 min per model. Real
  LLM-efficacy signal.
- `standard` — 4270 probes, most blocked by ML detectors, hours per model.
  Only pick this if the user explicitly wants full-stack measurement.
- `quick` — 10 dan/latentinjection probes, mostly detector-blocked. Not
  useful for model comparison; offer only if the user asks by name.

Default: `llm-quick` for the first run, `llm-suite` for comparison runs.

**Q3: bypass detectors?** — yes/no.
- Yes (default for `llm-quick`/`llm-suite`): disables protectai + promptguard
  for the sweep via `--bypass-detectors protectai,promptguard`, restores
  them on exit. All probes reach the LLM.
- No: probes run against the full stack; ML detectors will catch most. Only
  useful if measuring "which model defends best IF the detectors miss it".

## 3. Plan the command

Build the `bulwark_bench` invocation:

```bash
RUN_DIR="benchmarks/$(date +%Y-%m-%d-%H%M%S)-<tier>"
MODELS="comma,separated,list"
ARGS=(
  --models "$MODELS"
  --tier "<tier>"
  --output "$RUN_DIR"
)
[[ "$BYPASS" == "yes" ]] && ARGS+=(--bypass-detectors protectai,promptguard)
# Generous client timeout — standard tier with real LLM is slow.
ARGS+=(--redteam-timeout 7200)
```

Echo the full planned command to the user before running.

## 4. Run it — via subagent

Spawn a subagent with the Agent tool (subagent_type `general-purpose`).
Prompt template:

```
Run this bulwark_bench sweep and return the final report.md contents plus
a one-paragraph summary of the results.

Command (run from /Users/musicmac/Documents/bulwark-shield):
  PYTHONPATH=src .venv/bin/python -m bulwark_bench <ARGS>

The sweep may take <N> minutes (<tier> × <model_count> models). Wait for it
to complete; don't return early. When done, Read <RUN_DIR>/report.md and
return its contents verbatim followed by a 2-3 sentence summary naming the
winning model(s) on defense rate and any hijacks observed.

If the command fails, return the last 30 lines of stderr.
```

Use `run_in_background: true` if the expected duration is over 10 minutes;
otherwise foreground is fine. The main conversation should tell the user
the agent ID and estimated time, then wait.

## 5. Post-run

When the agent returns:

1. Print the markdown report directly (no paraphrasing).
2. Highlight interesting findings:
   - Any model with hijacks > 0 (security concern).
   - Latency outliers (>5× median).
   - Cost outliers for Anthropic models.
3. Tell the user the run dir path so they can diff `report.json` against
   future runs.
4. Ask if they want to `--resume` against the same dir to add more models,
   or start a fresh sweep.

## Error modes to handle

- **Dashboard times out during sweep.** Client timeout was increased to
  300s per poll (G-BENCH-011 + a real LLM probe on Qwen can take 30s+).
  If it still times out, suggest running with `--redteam-timeout 7200`
  and checking `/tmp/bulwark-local.log` for the dashboard log.
- **Model not in pricing table.** Bench prints a warning on stderr and
  costs default to $0. Fine for local models; surface the warning in the
  summary if the user picked an Anthropic model that's missing (means we
  need to update `src/bulwark_bench/pricing.py`).
- **Detectors left disabled after crash.** The runner restores in a
  `finally` block, but if Ctrl+C happens mid-request, re-activate by
  POSTing `/api/integrations/protectai/activate` (same for promptguard).
  Mention this in the report if the run errored.

## Output conventions

- Don't rewrite the bench's markdown report. Show it verbatim.
- Don't invent metrics the bench didn't produce (no "confidence interval",
  no "statistical significance"). Single-run numbers are what they are.
- The 10-probe llm-quick is not statistically meaningful — say so if the
  user asks whether the small difference between two models is real.

## Non-goals

- **Don't parallelize models.** Sequential execution is an explicit design
  property (NG-BENCH-003) — parallel GPU contention pollutes latency.
- **Don't modify the dashboard config beyond what bench's --bypass-detectors
  already handles.** Users who want to tweak sanitizer / trust_boundary
  toggles should do so in the dashboard UI, not through this skill.
- **Don't run `--tier full`.** 32,765 probes × multiple models is a bad
  default. If the user explicitly asks for it, confirm the multi-hour cost.
