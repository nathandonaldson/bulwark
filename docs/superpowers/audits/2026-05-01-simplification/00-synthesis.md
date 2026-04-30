# Phase 3 Synthesis: Simplification Proposal

**Date:** 2026-05-01
**Inputs:** 6 parallel analyst reports (`01-deferred-code-bugs.md` through `06-dashboard-jsx.md`)
**Total estimated LOC reduction:** **~1,560 LOC** (~6% of the ~26K combined source + tests)
**Goal:** answer the user's question — "can we substantially reduce the size and complexity of the codebase while retaining all existing functionality, without introducing regressions?"

---

## TL;DR (the honest answer)

**No, not substantially.** The codebase is in genuinely good shape. The 6 analysts found **hygiene issues, not architectural bloat**. Total LOC reduction is ~6%, half of which is one zombie file (`tests/benchmark.py`, 494 LOC). The ADR corpus has zero orphans, every contract is live, the test suite has only one true duplicate pair, and the dashboard JSX bundle is cohesive (no `data.jsx` split needed). The architecture is simpler than its reputation — v2's detection-only model (ADR-031) already did the substantial pruning.

**What CAN be done:** ~1,560 LOC of cleanup, plus 4–5 architectural simplifications (status-pill state machine, sister-package merge, primitive hoists, ADR-019 flip) that improve correctness more than they reduce size. None of these introduce migration burden for external users.

---

## Cuts ranked by leverage

### Tier 1 — Free wins (no risk, immediate)

| # | Cut | LOC | Source |
|---|-----|-----|--------|
| F1 | **Delete `tests/benchmark.py`** — broken zombie, imports `bulwark.executor` (deleted), not collected by pytest, ADR-044 itself notes it's not a test | -494 | analyst 2, 5 |
| F2 | **Delete `src/bulwark_bench/pricing.py`** — 95 LOC of dead code per ADR-034 ("kept for reference but is unused") | -95 | analyst 3 |
| F3 | **Delete `Layer.EXECUTOR` enum value** — zero consumers anywhere | -1 | analyst 2 |
| F4 | **Strip `__init__.py` docstring rot** — references `make_analyze_fn` / `make_execute_fn` / `make_pipeline` (all deleted) | -5 | analyst 2 |
| F5 | **Delete `tests/attacks/`** — empty dir with only `__init__.py` | -1 | analyst 5 |
| F6 | **ADR-019 status flip** — Proposed → Accepted (A+B; C deferred); options A+B already shipped and are enforced by `tests/test_docker_hardening.py` | doc-edit | analyst 4 |

**Tier 1 total: ~600 LOC, zero risk, no test changes.** This is the no-brainer batch.

### Tier 2 — High-leverage architectural simplifications

| # | Cut | LOC | Bug class fixed | Risk |
|---|-----|-----|-----------------|------|
| A1 | **Sister-package merge** — `bulwark_bench` + `bulwark_falsepos` → `bulwark.tools.{bench,falsepos}`. The "independent packages" framing is fictional: `bulwark_falsepos` hard-imports from `bulwark_bench` (5 sites), `bulwark.dashboard.app` reaches into `bulwark_falsepos.corpus` (3 sites). One wheel, one VERSION, one CHANGELOG already. Console scripts (`bulwark-bench`, `bulwark-falsepos`) stable across the move via 30-LOC re-export shim. | -250 net | structural duplication (CHANGELOG v2.3.2 already showed cost: ADR-038 fix landed twice) | LOW |
| A2 | **H1 unified status-pill state machine** — `computeStatusPill` reads `judge.enabled` + `integrations.promptguard` + service `mode` instead of just `protectai.status`. Closes audit-05 F2 / F13 / F16 simultaneously. Status pill stops lying when `/v1/clean` is 503-ing. | +60/-30 net | three audit-05 CRITICAL findings (status pill blind to no-detectors / degraded / 503) | LOW (pure helper) |
| A3 | **H3 `<Field>` form-control primitive** — silently fixes 11 instances of `var(--text-1)` (not defined; real token is `var(--text)`) across `LLMJudgePane` and `CanaryPane`. CSS-token typo bug discovered by analyst 6. | -40 net | silent CSS bug + hard-to-spot field-styling drift | LOW |
| A4 | **Production React UMD instead of dev UMD** — ADR-020 deferred follow-up has been deferred long enough. ~600 KB script reduction, ~30% script-execution speedup. Zero JSX change. | 1-line index.html | perf | LOW |
| A5 | **Merge `test_shortcuts.py` → `test_contracts.py`** — both target `bulwark.shortcuts.{clean,guard}` with the same `G-CLEAN-*` / `G-GUARD-*` IDs. Near-duplicates. | -100 LOC, ~15 tests | n/a | LOW (consolidation, not removal) |
| A6 | **Remove `AnalysisGuard` / `AnalysisSuspiciousError` aliases** — analyst 2 confirmed every test that uses the old name does its own local rename (`from bulwark.guard import PatternGuard as AnalysisGuard`); package-level back-compat aliases hold zero call sites. | -8 | n/a | LOW |

**Tier 2 total: ~430 LOC + 3 architectural improvements + 1 perf win + 1 silent bug fix.**

### Tier 3 — Requires care (MEDIUM risk)

| # | Cut | LOC | Concerns |
|---|-----|-----|----------|
| M1 | **Remove `_bridge_exploitation_attacks()` block** in `attacks.py` — held alive by `tests/test_attacks.py:128-130`. v1 vocabulary residue ("bridge" describes an architecture that doesn't exist). | -52 | category was kept post-ADR-031 because the patterns still test general boundary-escape shapes; rename rather than remove |
| M2 | **`spec/presets.yaml` `family: bridge` entries** — held alive by `_ALLOWED_FAMILIES` validation + JSX category-pill UI. Three concerns to coordinate: spec → src → JSX. | -10 spec, -5 src, -10 JSX | needs ADR or contract update because preset family is part of the test/preset contract |
| M3 | **G-01 status-pill code bugs (12 deferred)** — analyst 1 found 8 groups, ~25 LOC net, but 3 of 12 are gated by tests/contracts that need coordinated updates (C3 unwired button; C4 Bridge filter; C14 5-step LAYERS slice). The status-pill subset (C1+C2) is handled by A2 above. | ~25 net | several need synchronized contract + test + JSX updates |
| M4 | **`page-test.jsx` v1-vocabulary cleanup** — "configured LLM backend" string (C5), Bridge filter (C4), `_normalizeTraceLayer` keys (C13), dead SVG icons (C7). Coordinated with M2. | -30 | UI contract (`spec/contracts/dashboard_ui.yaml`) needs lookup |

**Tier 3 total: ~130 LOC.** Each item needs 1 ADR-or-contract coordination touch. Not blocked, just slower.

### Tier 4 — Optional / taste-driven

| # | Cut | Notes |
|---|-----|-------|
| T1 | Add ADR-031 + ADR-033 to CLAUDE.md ADR pointer block | analyst 4 — ADR-031 has 32 inbound markdown refs (most-cited) but isn't curated in the agent-handoff list |
| T2 | Three contract-merger candidates (clean+guard, three redteam_*, docker_hardening+docker_persistence) | analyst 4 — taste, not need |
| T3 | Conftest factory for `_get_client()` (reimplemented in 4 files) | analyst 5 — useful refactor, ~30 LOC saved |
| T4 | `test_codex_prb_hardening.py` redistribution into module-aligned files | analyst 5 — quality of life |
| T5 | Tighten `test_spec_compliance.py::test_every_guarantee_has_test` to require ID in a `def test_*` docstring (currently any string match) | analyst 5 meta-finding — would let `test_v2_coverage.py` shrink |
| T6 | H6 stage metadata from `/api/integrations` (vs hardcoded JSX) | analyst 6 — closes a recurring drift class |

---

## What we're NOT proposing (and why)

- **Don't split `data.jsx`.** Analyst 6: it's cohesively the store. Splitting won't reduce coupling.
- **Don't remove the in-browser Babel JSX compilation.** Analyst 6: no CSP, no offline requirement, no operator complaints. ADR-020 still earns its keep. (Just upgrade the React UMD per A4.)
- **Don't delete superseded ADRs.** Analyst 4: ADRs are historical record. Mark Superseded; don't archive unless the trail is broken.
- **Don't dedup tests aggressively.** Analyst 5: tests are evidence of past bugs. The one true duplicate pair (`test_shortcuts.py`, `test_contracts.py`) is in A5; the rest are different angles on the same module, which is fine.
- **Don't remove `AnalysisGuard` if you intend to ship anything that imports the old name.** Analyst 2 verified zero internal call sites — but if any external user has `from bulwark import AnalysisGuard` in their code, this is a breaking change. Recommend: deprecation warning for one release, then remove. Or just remove now — semver gives you major-bump cover for v3.

---

## Risk profile across all proposed cuts

- **HIGH-risk items requiring external migration paths: 0**
- **MEDIUM-risk (needs coordinated contract/test/spec update): 4** (Tier 3)
- **LOW-risk (pure cleanup, dead code, hoist): everything else**
- **Regression guards:** every cut in tiers 1–2 has a corresponding test file that verifies the surface stays correct. Tier 3 needs new tests in 2 cases (M2, M4); flagged.

---

## Recommended sequence

If we ship this in batches:

1. **Batch 1 (Tier 1, ~600 LOC):** delete benchmark.py, pricing.py, Layer.EXECUTOR, __init__.py docstring, empty `tests/attacks/`, flip ADR-019 status. One commit. Zero risk. Single-line CHANGELOG entry.
2. **Batch 2 (A2 + A3 + A4):** unified status pill + Field primitive + production React UMD. JSX-only. Closes 3 audit findings + a silent CSS bug + nets a perf win. New ADR? Probably no — these are bug fixes, not new contracts.
3. **Batch 3 (A1 sister-package merge):** the structural one. Single ADR (~060-tools-namespace), single commit moving files + adding shim, contract-stable since console scripts don't change. ~250 LOC reduction.
4. **Batch 4 (A5 + A6 + Tier 4 cherry-picks):** test merge, alias removal, optional pointer block + conftest factory. Cleanup PR.
5. **Batch 5 (Tier 3, optional):** v1-vocabulary sweep with synchronized spec/src/JSX/contract updates. The most painful batch; defer until there's an unrelated reason to touch the test page.

Total scope across all 5 batches: **~1,560 LOC removed, 4 architectural improvements, 1 silent bug fix, 1 perf win, 1 ADR-status flip, 0 external-migration burdens**.

---

## What this means for your original question

> "I want to know if we can substantially reduce the size and complexity of the codebase while retaining all existing functionality, without introducing regressions."

The honest answer:

- **Substantial size reduction:** ~6%. Not "substantial" by most definitions. The biggest single cut is one zombie file. The architecture is already lean.
- **Substantial complexity reduction:** real, but qualitative — sister-package merge clarifies the mental model, status-pill state machine fixes a class of UI lies, primitive hoists fix silent CSS bugs. None reduce LOC much; all reduce reasoning load.
- **No regression risk:** with the suggested ordering and batching, every cut has a regression guard. The only items that need new tests are 2 of the 4 Tier 3 items (M2, M4).

The real gain is in correctness, not lines. If "complexity" to you means "things I'd have to re-derive when reading this code in 6 months," then yes — A1 + A2 + A3 + Tier 4 each remove a recurring re-derivation cost. If "complexity" means LOC, the codebase is roughly as small as it can usefully be.
