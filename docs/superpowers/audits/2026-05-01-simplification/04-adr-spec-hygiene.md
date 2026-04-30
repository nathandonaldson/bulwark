# Phase 3 Analysis 04: ADR + spec/contract hygiene

Audit of `spec/decisions/` (50 files including TEMPLATE.md) and `spec/contracts/` (28 yaml files) on `main` (post-v2.5.7, ADR-049 just landed).

## Summary up front

- **49 ADRs** (excluding TEMPLATE.md). Every ADR has a `Status:` line — that hygiene is solid.
- **4 already marked Superseded** (002, 003, 018, 028). All point at the correct successor.
- **0 ADRs are truly orphaned-and-dead** — the v1-era ADRs (004, 005, 006, 007, 009, 011, 013) still describe behaviour that's wired in code, even where the inbound-reference count looks low. They're "Live, low-touch" not orphan candidates.
- **1 ADR has a stale Status header** — ADR-019 says **Proposed** but the implementation (multi-stage Dockerfile, non-root user, healthcheck) shipped and is enforced by `tests/test_docker_hardening.py` against `spec/contracts/docker_hardening.yaml`. Should be marked **Accepted** (with a note that option C / Chainguard was deferred) or **Superseded by shipped implementation**.
- **All 28 contracts** have at least one live test reference for their first guarantee — none are orphaned.
- **CLAUDE.md ADR pointer block** (currently 029/040/041/042/044/046/047/048) is accurate. **Recommend adding ADR-031** as the foundational pointer (it's the "everything before this is v1" anchor and is referenced 59 times across 32 ADRs/docs/code). **Recommend adding ADR-033** (LLM judge architecture — 29 inbound refs, the only reason judge surface area still exists). **Optional: ADR-038** (mandatory detector visibility / `/healthz` reason field).

## ADR inventory

Inbound-ref count counts files outside the ADR's own file containing `\bADR-NNN\b`. "py/yaml/jsx/md(adr)" breaks that down: how many Python source/test files, contract yamls, dashboard JSX, and Markdown files (of which other ADRs).

| ADR | Status (declared) | Status (actual) | Inbound refs | Recommended action |
|-----|-------------------|-----------------|--------------|-------------------|
| 001 | Accepted | Live (process ADR — defines the spec-driven loop CLAUDE.md mandates) | 2 md | Keep |
| 002 | Superseded by ADR-031 | Correctly marked | 1 md | Keep |
| 003 | Superseded by ADR-031 | Correctly marked | 1 md | Keep |
| 004 | Accepted | Live — `clean()` defaults still match (`max_length=None`, `format="xml"` in `shortcuts.py`) | 0 | Keep — describes still-shipping convenience-API defaults |
| 005 | Accepted | Live — `protect()` Anthropic proxy is in `integrations/anthropic.py:28` and tested by `tests/test_protect_anthropic.py` | 0 | Keep |
| 006 | Accepted | Live — no OpenAI `protect()` is the deliberate non-decision; reaffirmed by absence | 0 | Keep |
| 007 | Accepted | Live — `/v1/guard` and `/v1/clean` still 200-on-injection-detected (200/422 only), no 4xx-on-malicious-content | 1 md | Keep |
| 008 | Accepted | Live — Docker is shipping; ADR-019/049 layer onto this | 1 md | Keep |
| 009 | Accepted | Live — `bulwark-shield` PyPI name still in use | 1 md | Keep |
| 010 | Accepted | Live — `G-REDTEAM-TIERS-001..007` all enforced in `tests/test_http_api.py` | 0 | Keep |
| 011 | Accepted (revised) | Live — `integrations/openclaw/` still ships, `tests/test_openclaw_integration.py` runs | 1 md | Keep |
| 012 | Accepted | Live — three-way scoring + retest still in dashboard. Contract `redteam_scoring.yaml` is wired | 0 | Keep |
| 013 | Accepted | Live — bearer auth via `BULWARK_API_TOKEN` is the foundation of ADR-029/030/041 | 0 | Keep |
| 014 | Accepted | Live — unified `/v1/clean` is THE primary endpoint | 1 py | Keep |
| 015 | Accepted | Live — SSRF allowlist remains for webhook URL validation (ADR-030 reuses it). Note: `llm_factory` module no longer exists in v2 (ADR-031 removed LLM backend), but the validator function moved to `dashboard/config.py`/equivalent | 1 py + 1 yaml + 3 md | Keep — verify the module path note in the ADR is still accurate |
| 016 | Accepted | Live — `.env` autoload still in dashboard startup | 1 yaml + 1 md | Keep |
| 017 | Accepted | Live, **but** ADR-034 substantially rewrote the bench (LLM-comparison → detector-config sweep). ADR-017 now describes the *original* design; ADR-034 is the current one | 1 yaml + 2 md (1 adr) | Keep but consider adding "Partially superseded by ADR-034 (rebuild as detector-config sweep)" to header |
| 018 | Superseded by ADR-035 | Correctly marked | 1 py + 3 md (1 adr) | Keep |
| 019 | **Proposed** | **Stale header** — multi-stage Dockerfile, non-root user, healthcheck all shipped. `tests/test_docker_hardening.py` + `spec/contracts/docker_hardening.yaml` enforce the contract. Option (C) Chainguard was deferred per the ADR's own Recommendation section | 0 | **Update Status to Accepted (option A+B shipped; C deferred)** |
| 020 | Accepted | Live — React+Babel-in-browser is still the dashboard model | 3 py + 1 yaml + 4 jsx + 2 md (1 adr) | Keep |
| 021 | Accepted | Live — `spec/presets.yaml` is source of truth | 2 py + 3 yaml + 5 md (4 adr) | Keep |
| 022 | Accepted | Live — env-shadowed fields editable as defaults; ADR-031 deleted the LLM-backend fields specifically but the *pattern* is still applied to remaining env-shadowed config | 1 yaml + 2 md (1 adr) | Keep — text mentions LLM-backend examples that no longer exist; minor edit could add "(LLM backend removed in ADR-031; pattern still applies to remaining env-shadowed fields)" |
| 023 | Accepted | Live — wheel bundling fix still in `pyproject.toml`/`MANIFEST.in` | 2 py + 2 yaml + 1 md | Keep |
| 024 | Accepted | Live — guarantee-ID coverage of sanitizer/isolator/validator still enforced by `tests/test_contracts.py` | 1 md | Keep |
| 025 | Accepted | Live — canary management API still in dashboard | 2 py + 2 yaml + 6 md (2 adr) | Keep |
| 026 | Accepted | Live — webhook emitter still wired | 1 py + 1 yaml + 1 md | Keep |
| 027 | Accepted | **Mostly historical** — describes a pre-ADR-031 confused-deputy bug in `/v1/llm/test`. ADR-031 removed all `/v1/llm/*` endpoints, so the bug surface is gone. The validator function was repurposed for webhook URLs (ADR-030). Inbound refs are from ADR-028 + ADR-030 cross-references only | 2 md (1 adr) | Mark **"Historical / surface removed by ADR-031; validator reused per ADR-030"**. Don't archive — security history matters |
| 028 | Superseded by ADR-031 | Correctly marked | 2 md (1 adr) | Keep |
| 029 | Accepted | **Live + load-bearing** — loopback-only mutations is core auth invariant | 3 py + 3 yaml + 12 md (3 adr) | Keep — in CLAUDE.md pointer block |
| 030 | Accepted | Live — webhook SSRF, content cap, detect-endpoint, canary-tokens caps all in code | 4 py + 3 yaml + 3 md (2 adr) | Keep |
| 031 | Accepted | **Live + foundational** — the v2 architecture | 15 py + 9 yaml + 3 jsx + 32 md (13 adr) | Keep — **add to CLAUDE.md pointer block** |
| 032 | Accepted | Live — chunking still in `integrations/promptguard.py` | 3 py + 2 yaml + 1 jsx + 12 md (4 adr) | Keep |
| 033 | Accepted | **Live + load-bearing** — defines the LLM-judge surface area, NG-JUDGE-* contracts, hardcoded system prompt | 4 py + 3 yaml + 2 jsx + 20 md (9 adr) | Keep — **add to CLAUDE.md pointer block** |
| 034 | Accepted | Live — bulwark_bench v2 detector-config sweep | 7 py + 1 yaml + 6 md (2 adr) | Keep |
| 035 | Accepted | Live — `llm-quick`/`llm-suite` tier removal (supersedes ADR-018) | 4 py + 6 md (1 adr) | Keep |
| 036 | Accepted | Live — `bulwark_falsepos` harness | 7 py + 5 md | Keep |
| 037 | Accepted | Live — three P1 fixes (auth bypass, judge reason leak, judge timeout) | 6 py + 2 yaml + 7 md (4 adr) | Keep |
| 038 | Accepted | **Live + load-bearing** — `/healthz` degraded reason, detector visibility | 12 py + 7 yaml + 1 jsx + 16 md (7 adr) | Keep — **consider adding to CLAUDE.md pointer block** |
| 039 | Accepted | Live — PR-B hardening (encoding_resistant for HTML/percent, etc.) | 3 py + 2 yaml + 1 jsx + 9 md (3 adr) | Keep |
| 040 | Accepted | **Live + load-bearing** — fail-closed when no detectors | 10 py + 4 yaml + 19 md (5 adr) | Keep — in CLAUDE.md pointer block |
| 041 | Accepted | **Live + load-bearing** — auth predicate on token+origin only | 2 py + 2 yaml + 8 md | Keep — in CLAUDE.md pointer block |
| 042 | Accepted | **Live + load-bearing** — content byte cap | 2 py + 3 yaml + 12 md | Keep — in CLAUDE.md pointer block |
| 043 | Accepted | **Housekeeping** — one-time spec/preset/compose drift cleanup | 1 py + 2 yaml + 3 md | Keep but acceptable to mark **"Housekeeping (closed)"** since it documents one-time corrections rather than ongoing invariants |
| 044 | Accepted | **Live + load-bearing** — `Pipeline.from_config()` parity | 5 py + 1 yaml + 13 md (2 adr) | Keep — in CLAUDE.md pointer block |
| 045 | Accepted | Live — e2e real-detector CI lane | 3 py + 2 yaml + 6 md (1 adr) | Keep |
| 046 | Accepted | **Live + load-bearing** — split-evasion non-guarantee | 3 py + 1 yaml + 12 md (1 adr) | Keep — in CLAUDE.md pointer block |
| 047 | Accepted (v2.5.4) | **Live + load-bearing** — encoding decoders | 6 py + 3 yaml + 2 jsx + 20 md (2 adr) | Keep — in CLAUDE.md pointer block |
| 048 | Accepted (v2.5.7) | **Live + load-bearing** — detector_chain helper | 5 py + 1 yaml + 9 md | Keep — in CLAUDE.md pointer block |
| 049 | Accepted | Live — native arm64 CI runner | 2 md | Keep |

## Superseded-but-unmarked (action: add Status line)

**None.** Every ADR carries a Status line, and the four genuine supersessions (002→031, 003→031, 018→035, 028→031) are correctly marked.

The closest cases are:

- **ADR-019 — Proposed** is *stale* rather than *superseded*. Implementation shipped (option A+B in the ADR's own Recommendation: multi-stage build, non-root, version pins, CVE scan in CI). Update to **Accepted (options A+B; C deferred)**. Optionally append "see also ADR-049" since arm64-runner work is in the same Docker-hardening lineage.
- **ADR-017** is *partially* superseded by **ADR-034**: the original "compare LLM models on the bench" framing was replaced when ADR-031 deleted `llm_backend`. ADR-034's Status correctly flags itself as a rebuild, but ADR-017's header still says plain Accepted. Suggest **"Accepted (rebuilt as detector-config sweep in ADR-034)"** for symmetry.
- **ADR-022** describes env-shadowed *LLM* fields specifically; ADR-031 removed those fields. The *pattern* (env-shadowed-as-defaults-not-locks) still applies to remaining env-shadowed config. A one-line note in ADR-022 saying "LLM-backend example removed by ADR-031; pattern still in force" prevents confusion.
- **ADR-027** is functionally historical (the `/v1/llm/*` endpoints it protects don't exist in v2) but the *validator function* it introduced was reused for webhooks per ADR-030. Could add **"Historical: original surface removed by ADR-031, but the URL validator reused per ADR-030"** to the header.

## Orphaned candidates (action: archive or mark Historical)

**No genuine orphans.** Every ADR with zero or low inbound-ref counts (004, 005, 006, 007, 010, 012, 013) describes behaviour that's still wired in code:

- **ADR-004** → defaults are in `shortcuts.py` clean() signature
- **ADR-005** → `protect()` proxy in `integrations/anthropic.py:28`, tested by `test_protect_anthropic.py`
- **ADR-006** → no-OpenAI-protect is the absence-decision; reaffirmed by `integrations/` having only `anthropic.py`
- **ADR-007** → 200-on-completed-analysis is enforced by `http_clean.yaml`/`http_guard.yaml` G-* IDs
- **ADR-010** → `G-REDTEAM-TIERS-001..007` enforced in `test_http_api.py`
- **ADR-012** → `redteam_scoring.yaml` G-REDTEAM-SCORE-001 still tested
- **ADR-013** → `BULWARK_API_TOKEN` foundation, depended on by ADR-029/030/041

Low ref counts here just mean these ADRs are **early/stable** — they introduced an invariant once, the invariant didn't need to change, and later ADRs talk about *adjacent* invariants instead. That's healthy.

## Housekeeping ADR

- **ADR-043** (spec/preset/compose drift cleanup) is the clearest housekeeping ADR — documents one-time documentation/preset corrections after the v2 cutover. It's still useful as a forensic record ("why did the XML-escape preset description change?") and is referenced from contracts. Acceptable to keep as-is, or to add **"Housekeeping (closed) — see ADR-031 for the architectural cutover"** to the Status line.

## Contract hygiene

| Contract | Live? | Notes |
|----------|-------|-------|
| bulwark_bench.yaml | Yes | v2.0.0 (ADR-034); 3 inbound test/source refs |
| bulwark_falsepos.yaml | Yes | ADR-036 |
| canaries.yaml | Yes | v2.0.0 (ADR-025) |
| clean.yaml | Yes | `bulwark.shortcuts.clean()` library function |
| cli.yaml | Yes | `bulwark.cli` |
| dashboard_layer_status.yaml | Yes | `tests/test_dashboard_layers.py` enforces G-DASH-LAYERS-001..003 |
| dashboard_ui.yaml | Yes | v2.0.0 (ADR-031) |
| docker_hardening.yaml | Yes | enforced by `tests/test_docker_hardening.py` (the ADR-019 contract) |
| docker_persistence.yaml | Yes | G-DOCKER-001 in `test_http_api.py:427` |
| e2e_ci.yaml | Yes | v2.4.8 (ADR-045) |
| env_config.yaml | Yes | v2.0.0 (ADR-031); G-ENV-001..005, 012, 013 dropped per ADR-031 |
| guard.yaml | Yes | `bulwark.shortcuts.guard()` library function |
| http_auth.yaml | Yes | ADR-013 / ADR-029 / ADR-041 |
| http_clean.yaml | Yes | THE primary endpoint contract; v2.0.0 |
| http_config.yaml | Yes | v2.0.0 (ADR-031 removed LLM-backend fields) |
| http_guard.yaml | Yes | output-side endpoint |
| http_healthz.yaml | Yes | v0.6.0 (ADR-038 added detector load state); 3 inbound refs |
| integrations_toggle.yaml | Yes | `PUT /api/integrations/{name}` |
| isolator.yaml | Yes | `MapReduceIsolator` is still in `__init__.py` exports |
| llm_judge.yaml | Yes | v1.0.0 (ADR-033/037) |
| openclaw_integration.yaml | Yes | sidecar still ships under `integrations/openclaw/` |
| presets.yaml | Yes | ADR-021 |
| redteam_reports.yaml | Yes | dashboard reports endpoint |
| redteam_scoring.yaml | Yes | ADR-012 |
| redteam_tiers.yaml | Yes | ADR-010 |
| sanitizer.yaml | Yes | ADR-024 — `bulwark.sanitizer` core defense module |
| validator.yaml | Yes | ADR-024 — `bulwark.validator` |
| webhooks.yaml | Yes | v1.1.0 (ADR-026) |

**No contracts are orphaned.** All 28 first-guarantee IDs have at least one inbound reference under `tests/` or `src/`.

**Possible mergers (low priority, could simplify the index):**

- `clean.yaml` + `guard.yaml` (the two `shortcuts.py` library functions) → merge into a single `shortcuts.yaml`. They're the same module, same audience, shipping together. Saves one file in `spec/contracts/`.
- `http_clean.yaml` + `http_guard.yaml` (the HTTP endpoints) — *don't* merge. These are the two public endpoints documented by `openapi.yaml`; keeping them parallel is a feature.
- `redteam_tiers.yaml` + `redteam_reports.yaml` + `redteam_scoring.yaml` could be folded into a single `redteam.yaml` — they all describe the dashboard's red-team subsystem. But they're small (~1.2-1.6 KB each) and have distinct audiences; the merger is taste, not need.
- `docker_hardening.yaml` + `docker_persistence.yaml` → merge into `docker.yaml`. Both describe Docker-image guarantees; together they're under 1.5 KB.

None of these are urgent. The current per-feature granularity is fine.

## CLAUDE.md pointer block

Currently lists: **029, 040, 041, 042, 044, 046, 047, 048**.

This is the curated "agent-load-bearing" set. It's reasonable but I'd suggest two adds:

**Strongly recommend adding:**

- **ADR-031** — *the* v2 architectural cutover. Without it, an agent reading the codebase has no anchor for "why did all the LLM/two-phase code disappear?" 32 markdown files reference it; 13 ADRs cite it as the supersession target. It's the single highest-traffic ADR.
- **ADR-033** — defines the LLM-judge surface area, the `_SYSTEM_PROMPT` hardcoding rule, and the NG-JUDGE-* non-guarantees. CLAUDE.md already mentions the system-prompt hardcoding rule (NG-JUDGE-003); pointing at ADR-033 makes the lineage visible.

**Optional add:**

- **ADR-038** — detector load visibility / `/healthz` degraded reason. ADR-040 (which IS in the block) builds on it. Could go either way; ADR-040 alone implies it.

**No removals needed.** Every ADR in the current block is still load-bearing.

Suggested updated block (additions in **bold**):

```
ADR-029: mutating endpoints require BULWARK_API_TOKEN when accessed from non-loopback clients...
**ADR-031**: v2 is detection-only — Sanitizer + DeBERTa (mandatory) + PromptGuard (optional) + LLM judge (optional) → trust boundary. No two-phase executor, no llm_backend, no /v1/llm/* endpoints.
**ADR-033**: LLM judge is opt-in third detector; system prompt is hardcoded (NG-JUDGE-003); judge generative output never reaches /v1/clean callers (NG-JUDGE-004).
ADR-040: /v1/clean returns HTTP 503 + error.code = "no_detectors_loaded"...
ADR-041: /v1/clean auth predicate keys on token presence + non-loopback origin alone...
ADR-042: /v1/clean.content and /v1/guard.text are byte-capped...
ADR-044: Pipeline.from_config(path) loads the same detector chain the dashboard uses...
ADR-046: long-range split-evasion is a documented non-guarantee...
ADR-047: /v1/clean decodes base64 + ROT13 substrings as detection variants...
ADR-048: bulwark.detector_chain.run_detector_chain is the single source of truth for chain execution...
```

## Summary

- **ADRs to mark Superseded:** 0 (all real supersessions already marked)
- **ADRs with stale Status header:** 1 (ADR-019: Proposed → Accepted)
- **ADRs that could use a clarifying header note:** 3 (017, 022, 027 — partial-supersession or surface-removed-but-pattern-survives)
- **ADRs to archive:** 0 (security/historical record outweighs index complexity)
- **ADRs that could be marked "Housekeeping (closed)":** 1 (ADR-043) — optional; current state is fine
- **Contracts to retire:** 0
- **Contracts that could merge for tidiness:** 2-3 pairs (clean+guard, redteam_*, docker_*) — taste, not need
- **CLAUDE.md pointer block:** add ADR-031 and ADR-033 (high-traffic foundational anchors); ADR-038 optional
- **Estimated reduction in spec/decisions/ index complexity:** ~2% — marking ADR-019 Accepted and adding the three header clarifications. The bigger lever is the **CLAUDE.md pointer additions**, not ADR pruning.

The ADR + contract corpus is in genuinely good shape. Status hygiene is consistent, supersessions are marked, and there's no dead weight to clear out — just one stale Proposed header (019) and a couple of header notes that would help future readers track the v1→v2 transition more cleanly.
