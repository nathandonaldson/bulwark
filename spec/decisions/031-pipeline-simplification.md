# ADR-031: Pipeline simplification — detection-only, no LLM, no two-phase executor

**Status:** Accepted
**Date:** 2026-04-23

## Context

The current pipeline was designed for an agentic use case: Phase 1 reads
untrusted content (no tools), Phase 2 acts on Phase 1's scrubbed summary
(with tools). The architectural defense relied on tools existing only in
Phase 2, so an injection surviving Phase 1 would hit a tool-less Phase 2
prompt and cause no harm.

In practice, nobody is using Bulwark that way. The actual deployment
pattern — including the Wintermute integration and any user of
`/v1/clean` — is:

1. Caller has untrusted content (email, scraped page, user input).
2. Caller asks Bulwark "is this safe, and if so give me a cleaned version".
3. Caller feeds the result into *their own* LLM with *their own* tools.

In this flow Phase 2 is not a security boundary — it's a second billing
event on a tool-less endpoint. Meanwhile the layers that exist to protect
Phase 2 (`AnalysisGuard` regex on Phase 1 output, `sanitize_bridge`,
canary check between phases) are generating false positives on benign
content because they're applied as *input gates* rather than *output
sanity checks*.

Separate problems compound the noise:

- **Canaries sit on the input Config page.** Users reasonably infer that
  canaries are checked on incoming content. They're not — canaries are
  leak-detection tokens checked on LLM output. The UI placement is a
  lie.
- **Two ML detectors** (ProtectAI DeBERTa + Meta PromptGuard-86M) overlap
  heavily. PromptGuard is gated (requires HuggingFace approval), which
  adds onboarding friction for negligible marginal detection. Users
  rarely enable both.
- **`AnalysisGuard` regex runs on input.** Patterns like
  `ignore previous instructions` fire on benign text that mentions
  injection defense, tutorials, or security docs. The same patterns run
  on output, where their signal-to-noise ratio is far higher (LLMs
  rarely emit those phrases organically).

## Decision

Bulwark's job is to **return safe content or an error**. Nothing more.
The caller owns the LLM. Bulwark never calls an LLM itself.

### Pipeline (new)

```
INPUT (untrusted content)
  │
  ├─ Sanitizer (bidi, emoji smuggling, unicode)   always on
  ├─ DeBERTa classifier                            mandatory, bundled
  │     HIGH confidence → 422 BLOCKED
  │     pass            → continue
  ├─ Trust boundary wrap (<untrusted_input>…)
  │
  └─ 200 OK: cleaned, wrapped content
       caller feeds this into their own LLM

SEPARATE ENDPOINT: /v1/guard
  │
  └─ Called by the user on their OWN LLM's OUTPUT
       ├─ Output regex check
       └─ Canary leak check
       → safe: true/false
```

### Concrete changes

1. **Remove `TwoPhaseExecutor` entirely.** Delete `executor.py`. No
   Phase 1, no Phase 2, no `analyze_fn`, no `execute_fn`. Bulwark does
   not orchestrate LLM calls.

2. **Remove `AnalysisGuard`.** Its only purpose was guarding the bridge
   between Phase 1 and Phase 2. With no phases, no bridge, no guard.
   The same regex list moves to `/v1/guard` for callers to check their
   own LLM output.

3. **Remove LLM backend config.** No `llm_backend.mode`, `api_key`,
   `base_url`, `analyze_model`, `execute_model`. Remove `/v1/llm/test`
   and `/v1/llm/models`. Remove the LLM section from the dashboard
   Config page.

4. **Remove `sanitize_bridge`** (it bridged phases that no longer exist).

5. **`/v1/clean` response slims down.** Drop `analysis`, `execution`,
   `llm_mode` fields. Keeps: `result`, `blocked`, `source`, `format`,
   `content_length`, `result_length`, `modified`, `trace`.

6. **Canaries leave the Config > Pipeline page.** Move to a dedicated
   "Leak detection" surface. Canaries are *only* checked on `/v1/guard`
   (caller's LLM output). Never on input.

7. **Make DeBERTa mandatory, downloaded on first run.** DeBERTa is
   ungated, 180 MB, ~30 ms latency. The Docker image does *not* bundle
   the weights — they download from HuggingFace on first `/v1/clean`
   call and cache to a volume. Keeps the base image small; startup is
   instant when the cache is warm. First run requires internet; this
   is documented.

8. **PromptGuard stays as an opt-in second detector, surfaced as its
   own dedicated configuration step in the UI.** Not buried in an
   "Integrations" tab alongside Garak — PromptGuard is a *detector*,
   same category as DeBERTa, so it deserves first-class placement on
   the Config page: "Step 2: Enable second-opinion detector
   (optional)." Users who enable it supply a HuggingFace token; the
   weights download on first use just like DeBERTa.

## Consequences

### Positive

- Zero LLM calls in `/v1/clean`. No latency from LLM round-trips, no
  API-key config, no model-selection UI, no billing surprises.
- DeBERTa + sanitizer + trust boundary is a coherent story: "classify,
  clean, wrap." No "Phase 2 has tools" claim that our deployment can't
  back up.
- Input-side false positives drop sharply. The noisy regex layer is
  gone from the input path entirely.
- One mandatory detector removes the HuggingFace-gating onboarding step.
- Removes ~400 lines of executor + bridge + LLM-factory code and their
  tests.
- Canaries gain their own surface, making their role (output-side leak
  detection) discoverable.

### Negative

- Breaking changes:
  - `/v1/clean` response drops `analysis`, `execution`, `llm_mode`.
  - `/v1/llm/test` and `/v1/llm/models` removed.
  - `llm_backend` removed from config (YAML + env vars).
  - `from bulwark.executor import TwoPhaseExecutor` stops working.
  None of these have known external users — Bulwark ships to nobody yet.
- PromptGuard users lose the core-layer treatment. Mitigation: auto-
  disable on upgrade, surface a notice pointing at the opt-in plugin.
- Losing the LLM-based analyze step means a sophisticated injection
  that slips past DeBERTa reaches the caller unflagged. Counter: the
  caller runs their own LLM and can call `/v1/guard` on its output;
  Bulwark was never designed to be the only line of defense.

### Neutral

- Contracts affected: `http_clean.yaml` (response slim-down),
  `executor.yaml` (deleted), `http_llm_test.yaml` (deleted),
  `dashboard_ui.yaml` (LLM section removed, canaries moved),
  `canaries.yaml` (scope narrows to output-only), `webhooks.yaml`
  (BLOCKED events now only come from DeBERTa + canary, not analysis
  guard). Guarantee IDs need a sweep.
- Env vars removed: `BULWARK_LLM_MODE`, `BULWARK_API_KEY`,
  `BULWARK_BASE_URL`, `BULWARK_ANALYZE_MODEL`, `BULWARK_EXECUTE_MODEL`.
- Version bump: this is a breaking API change → v2.0.0.
