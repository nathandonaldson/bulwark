# Simplification Audit 02 — Back-Compat Aliases & v1 Architecture Leftovers (Code)

**Analyst:** 2 of 6
**Date:** 2026-05-01
**Slice:** Back-compat aliases and v1-architecture leftovers in code (not docs).
**Method:** grep across `src/`, `tests/`, `examples/`, sister packages (`bulwark_bench`, `bulwark_falsepos`); cross-checked ADR-031, ADR-044; counted call sites src vs tests separately.
**Out-of-scope:** docs/markdown/JSX strings (analyst 1's slice), `spec/decisions/*.md` historical content, `CHANGELOG.md`, archived audit notes.

---

## Executive summary

The v1 → v2 migration left two distinct strata of residue in code:

1. **`AnalysisGuard` / `AnalysisSuspiciousError`** back-compat aliases — load-bearing in `tests/` and the `bulwark.integrations.promptguard` module docstring/imports. Removable in two phases.
2. **Genuine zombies that no longer compile** — `tests/benchmark.py` imports the deleted `bulwark.executor` module and calls non-existent constructors (`Pipeline.default(analyze_fn=…)`, `Pipeline(analysis_guard=…, analyze_fn=…)`). ADR-044 explicitly notes this file is "not part of the test suite."
3. **`make_analyze_fn` / `make_execute_fn` references in module docstrings** that no longer resolve to anything — the symbols themselves are gone (audit 04 F-04-01 confirms). Pure docstring rot.
4. **Dashboard / event-system internals still keyed on `analysis_guard` / `Layer.ANALYSIS_GUARD` / `Layer.EXECUTOR` / `target="executor"` / `family: bridge`** — these are wire-level enum strings the frontend reads. They're not v2-meaningful labels but renaming them is contract-breaking work, not a delete.

Total LOC removable cleanly: **~280–340 LOC** depending on aggressiveness. Sister packages (`bulwark_bench`, `bulwark_falsepos`) are clean — no v1 aliases, only `bulwark_bench/bulwark_client.py` reads `llm_backend` from `/api/config` for token sampling and that is intentional (the dashboard still emits the field via redteam.py — separate concern).

`Pipeline(detect=callable)` is **fully gone** — confirmed zero call sites in `src/` and `tests/`. ADR-044's claim is accurate. The only old-shape kwargs left are in `tests/benchmark.py` (item 2-A below).

No HIGH-risk items: nothing in this audit is exposed to external integrators in a contract sense — `AnalysisGuard` is a public top-level export but there is no documented v2 promise that it will continue to work, and `__init__.py:14` already labels it "back-compat aliases for pre-v2 callers."

---

## Group 1 — `AnalysisGuard` / `AnalysisSuspiciousError` aliases

### 1-A `bulwark.AnalysisGuard` / `bulwark.AnalysisSuspiciousError` top-level exports

- **Path:** `src/bulwark/__init__.py:13-16, 39-40`
- **Why it's there:** Pre-v2 callers imported `from bulwark import AnalysisGuard`. Renamed to `PatternGuard` per ADR-031.
- **Usage count (src):** 0 in `src/bulwark/*.py` outside the module itself (the alias is _defined_ here and re-exported from `guard.py`; no library code consumes the alias name from the package root).
- **Usage count (tests):** 4 test files import `AnalysisGuard` — `tests/test_security_audit.py`, `tests/test_events.py`, `tests/benchmark.py`, `tests/test_v2_coverage.py` (uses `Layer.ANALYSIS_GUARD`, not the class). All four use `from bulwark.guard import PatternGuard as AnalysisGuard` — i.e. they alias **inside the test file**, not via the package-root re-export. The package-root alias is consumed by zero call sites.
- **LOC delta if removed:** −5 (lines 14-16 + two `__all__` entries on 39-40).
- **Risk:** LOW. Removal of the package-root re-export breaks no existing test (each test does its own `as AnalysisGuard` rename).
- **Migration path:** None needed — pre-v2 callers were already supposed to migrate to `PatternGuard`. Bump minor and document.

### 1-B `bulwark.guard.AnalysisGuard` / `AnalysisSuspiciousError` module-level aliases

- **Path:** `src/bulwark/guard.py:91-94`
- **Why it's there:** Aliases preserved at the module level so `from bulwark.guard import AnalysisGuard` still works for "internal modules [that] still import the old names" (per the comment on line 91).
- **Usage count (src):** 1 — `src/bulwark/integrations/promptguard.py:23` imports `from bulwark.guard import SuspiciousPatternError as AnalysisSuspiciousError`. This is using the **non-aliased** name with an `as` rename, so the alias on line 94 is **not** load-bearing for `promptguard.py`. The class alias on line 93 is consumed by zero `src/` call sites — every `src/` use of `AnalysisGuard` is a `from bulwark.guard import PatternGuard as AnalysisGuard` rename or a docstring.
- **Usage count (tests):** Same picture — test files alias `PatternGuard as AnalysisGuard` themselves; they do not import the `AnalysisGuard` symbol bound on line 93.
- **LOC delta if removed:** −4 (lines 91-94 plus one comment line).
- **Risk:** LOW. The tests' `from bulwark.guard import PatternGuard as AnalysisGuard` keeps working; only an external pre-v2 consumer doing `from bulwark.guard import AnalysisGuard` would break, and that path is undocumented in v2 docs.
- **Migration path:** Note in CHANGELOG: "Removed module-level `AnalysisGuard` / `AnalysisSuspiciousError` aliases. Use `PatternGuard` / `SuspiciousPatternError`."

### 1-C `bulwark.shortcuts` internal `AnalysisGuard` rename

- **Path:** `src/bulwark/shortcuts.py:26, 30, 34`
- **Why it's there:** `from bulwark.guard import PatternGuard as AnalysisGuard` followed by `_DEFAULT_GUARD = AnalysisGuard()`. Pure cosmetic — the local name doesn't escape the module.
- **Usage count:** Local-only. 3 references inside the module.
- **LOC delta if cleaned up:** 0 (rename `AnalysisGuard` → `PatternGuard` in 3 spots; net zero LOC).
- **Risk:** LOW. Internal only.
- **Migration path:** None.

### 1-D Test classes / docstrings still named `TestAnalysisGuard*`

- **Paths:**
  - `tests/test_events.py:106-129` — `class TestAnalysisGuardEvents` (~24 LOC test class).
  - `tests/test_security_audit.py:189-237` — `# SEC-05: AnalysisGuard ReDoS protection` block + `class TestAnalysisGuardReDoS` (~50 LOC).
  - `tests/test_shortcuts.py:113-119` — docstrings reference `AnalysisSuspiciousError`.
  - `tests/test_contracts.py:9, 146-147` — same.
  - `tests/test_v2_coverage.py:191` — comment reference only.
- **Why it's there:** Test class names + docstring guarantees still spell the old name. Tests are fully passing — these are cosmetic.
- **Usage count:** Tests-only.
- **LOC delta if renamed:** 0 (rename only).
- **Risk:** LOW. The `from bulwark.guard import PatternGuard as AnalysisGuard` aliasing inside each test means the alias-removal in 1-A/1-B does **not** break these tests — they survive even if the package-root alias is deleted, because they each do their own as-rename. No regression-guard concern.
- **Migration path:** None — removable any time.

### 1-E `spec/contracts/guard.yaml` G-GUARD-002 wording

- **Path:** `spec/contracts/guard.yaml:9`
- **Why it's there:** Contract still says "Raises **AnalysisSuspiciousError** when regex injection patterns match."
- **Usage count:** 1 contract; 2 docstring tests reference G-GUARD-002 (`tests/test_shortcuts.py:113`, `tests/test_contracts.py:146`).
- **LOC delta:** 0 (rename to `SuspiciousPatternError`).
- **Risk:** LOW. Contract guarantee text is read by humans, not by `test_spec_compliance.py` (function-name resolution only).
- **Migration path:** Edit the contract guarantee text in the same commit as 1-A/1-B and tests' `with pytest.raises()` already use the renamed class.

---

## Group 2 — Genuine v1 zombies (broken code paths)

### 2-A `tests/benchmark.py` imports a deleted module + uses removed kwargs

- **Path:** `tests/benchmark.py` (494 LOC total)
- **Why it's there:** Pre-v2 benchmark script. Imports `from bulwark.executor import AnalysisGuard` (line 19) — but `bulwark.executor` does not exist as a module in `src/bulwark/`. Calls `Pipeline.default(analyze_fn=…, execute_fn=…)` (line 249) — `analyze_fn` / `execute_fn` are not parameters of `Pipeline.default()`. Calls `Pipeline(sanitizer=…, trust_boundary=…, analysis_guard=…, analyze_fn=…)` (lines 256-261) — `analysis_guard` and `analyze_fn` are not fields on the `Pipeline` dataclass.
- **Usage count (src):** 0.
- **Usage count (tests):** Self-only. Not collected by pytest (filename does not start with `test_`); not invoked by any CI workflow (`grep` of `.github/workflows/*` and `pyproject.toml` returns no references). ADR-044's "Why no backwards-compat shim" section explicitly says "tests/benchmark.py references stale kwargs that predate ADR-031 and is not part of the test suite."
- **LOC delta if removed:** **−494** (whole file deletable).
- **Risk:** LOW. Confirmed broken — `python3 tests/benchmark.py` would `ImportError` on line 19. No regression-guard test would catch removal because nothing imports it.
- **Migration path:** None. If benchmarking is still wanted, it should be rebuilt against the v2.5+ `Pipeline.from_config()` shape — but that's a fresh-design task, not a back-compat preservation.
- **Regression guard for keeping it:** None exists — that is the smoking gun for deleting it.

### 2-B `bulwark.integrations.anthropic` docstring lists removed symbols

- **Path:** `src/bulwark/__init__.py:6` and `src/bulwark/integrations/__init__.py:6-7`
- **Why it's there:**
  ```python
  # __init__.py:6
  "    from bulwark.integrations.anthropic import make_analyze_fn, make_execute_fn, make_pipeline"
  # integrations/__init__.py:6-7
  "    from bulwark.integrations.anthropic import protect, make_pipeline"
  "    from bulwark.integrations.anthropic import make_analyze_fn, make_execute_fn"
  ```
  These docstring example imports point at symbols that **no longer exist** in `bulwark/integrations/anthropic.py` (only `protect` / `ProtectedAnthropicClient` survive — confirmed by reading the full 127-line file).
- **Usage count (src):** 0 — these are docstring strings, not `import` statements.
- **Usage count (tests):** 0.
- **LOC delta if cleaned:** −1 line in `__init__.py`, −2 lines in `integrations/__init__.py`. Net **−3 LOC** plus updating the surrounding docstring sentence.
- **Risk:** LOW. Docstring rot only.
- **Migration path:** Replace with `from bulwark.integrations.anthropic import protect`.

### 2-C `Pipeline(detect=callable)` constructor — confirmed dead

- **Path:** `src/bulwark/pipeline.py`
- **Status:** Fully removed in v2.5.0. No `detect=` kwarg, no `_two_phase_*`, no `analyze_fn` / `execute_fn`, no `analysis_guard` field. ADR-044's claim is accurate.
- **Confirmation grep:** `grep -rn "Pipeline.*detect=" src/ tests/ examples/` returns zero hits. The only legacy-shape calls are inside `tests/benchmark.py` (item 2-A) which is dead code.
- **Action:** None. Already done.

---

## Group 3 — Layer/family enum strings still spelled in v1 vocabulary

These are **not** removable without breaking the dashboard frontend's enum-mapping tables. They're listed for completeness; mark each as "preserve as wire-format" unless a wire-bump is on the table.

### 3-A `Layer.ANALYSIS_GUARD = "analysis_guard"` and `Layer.EXECUTOR = "executor"`

- **Path:** `src/bulwark/events.py:20, 22`
- **Wire consumers:**
  - `src/bulwark/dashboard/api_v1.py:71, 505, 515, 527` — `/v1/guard` emits `layer="analysis_guard"`.
  - `src/bulwark/guard.py:61, 72, 85` — `PatternGuard` emits `layer=Layer.ANALYSIS_GUARD`.
  - `src/bulwark/dashboard/static/src/page-test.jsx:159` — JSX maps `analysis_guard → 'bridge'`.
  - `src/bulwark/dashboard/static/src/data.jsx:38` — same mapping.
- **Where `Layer.EXECUTOR` is consumed:** **Nowhere active.** No `src/` or `tests/` code emits `Layer.EXECUTOR`. The string `"executor"` survives only as `Attack.target="executor"` (item 3-B).
- **LOC delta:**
  - Removing `Layer.EXECUTOR`: −1 (truly dead).
  - Renaming `Layer.ANALYSIS_GUARD` to `Layer.PATTERN_GUARD`: ~10 sites including JSX. Wire-breaking — dashboard frontends pinned to old strings would mis-render trace entries.
- **Risk:** Layer.EXECUTOR removal is **LOW**. ANALYSIS_GUARD rename is **MEDIUM** (frontend coupling).
- **Regression guard:** `tests/test_events.py:117, 125` and `tests/test_v2_coverage.py:210` would catch ANALYSIS_GUARD rename. Nothing would catch EXECUTOR removal — also a smoking gun for the deletion.
- **Migration path (EXECUTOR):** Just delete the line. No migration needed.
- **Migration path (ANALYSIS_GUARD rename):** Add new enum value, write a translation map at the trace serializer, deprecate one release later. Not in scope for a "simplification" pass.

### 3-B `Attack.target="executor"` (27 occurrences)

- **Path:** `src/bulwark/attacks.py` lines 249, 257, 297, 335, 343, 367, 397, 405, 413, 421, 647, 661, 677, 741, 779, 801, 809, 817, 825, 833, 841, 855, 863, 871, 879, 887, 895 (27 entries).
- **Why it's there:** Pre-v2, `target` indicated which defense layer was expected to block the attack — including the `executor` layer that wrapped Phase 2. v2 has no executor layer; `executor` here is now meaningless.
- **Wire consumers:** `AttackSuite.get_by_target(target)` — but no `src/` code calls `get_by_target("executor")`. Tests reference `target="boundary"` (`tests/test_attacks.py:140-ish`).
- **LOC delta if rewritten:** 0 (each is a one-word change). If the field is dropped entirely, ~27 LOC shrink across the file.
- **Risk:** LOW. The data isn't surfaced through any UI or contract — it's metadata on the attack catalog.
- **Migration path:** Pick a v2-meaningful target string per attack (most should be `"boundary"` or `"detection"`) or drop the field if no consumer exists.

### 3-C `AttackCategory.BRIDGE_EXPLOITATION` + `_bridge_exploitation_attacks()`

- **Path:** `src/bulwark/attacks.py:18, 192, 793-844` (~52 LOC for the method, plus the enum + extend call).
- **Why it's there:** v1 had a Phase 1 → Phase 2 bridge; this category exercised it. v2 has no bridge.
- **Usage count:** `tests/test_attacks.py:128-130` asserts that `get_by_category(BRIDGE_EXPLOITATION)` returns ≥2 attacks. The 6 attacks themselves (`bridge_instruction_smuggling`, `bridge_trust_escape`, `bridge_context_stuffing`, `analysis_output_formatting`, `nested_json_injection`, `template_injection`) are still useful as injection probes — they just don't test a "bridge" anymore.
- **LOC delta if removed:** **−~52 LOC** (whole `_bridge_exploitation_attacks()` method) + 1 `AttackCategory` enum value + 1 `extend` call + tests/test_attacks.py:128-130.
- **Risk:** MEDIUM. Some of these probes (especially `nested_json_injection`, `template_injection`) overlap with detection-stage tests and would need re-categorising rather than deleting outright if benchmarks rely on probe variety. The `_bridge_exploitation_attacks` docstring "Phase 1 to Phase 2 bridge" leaks v1 vocabulary into the attack catalog.
- **Migration path:** Recategorize the 6 attacks under existing categories (`INSTRUCTION_OVERRIDE` for the trust-escape ones, `DATA_EXFILTRATION` or a new `JSON_FIELD_INJECTION` for the JSON-shape ones); update `tests/test_attacks.py:128-130` to match.

### 3-D `spec/presets.yaml` `family: bridge`

- **Path:** `spec/presets.yaml:47, 80, 82` (3 presets keyed `family: bridge`: `override`, `b64`, `bridge`).
- **Wire consumers:**
  - `src/bulwark/presets.py:19` — `_ALLOWED_FAMILIES = {"sanitizer", "boundary", "bridge", "detection", "canary"}` (loader validates against this set).
  - `src/bulwark/dashboard/static/src/page-test.jsx:34` — UI category filter pill `{ id: 'bridge', label: 'Bridge' }`.
  - `src/bulwark/dashboard/static/src/page-test.jsx:36` — filters `presets.filter(p => p.family === category)`.
- **Why it's there:** v1 categories. The "Bridge" pill in the UI no longer maps to a real pipeline stage — v2 stages are sanitizer, detection, boundary, canary.
- **LOC delta if removed:** 3 lines in `presets.yaml` recategorized; `_ALLOWED_FAMILIES` shrinks by 1; JSX category list shrinks by 1; the `analysis_guard → bridge` and `guard → bridge` mappings in `_normalizeTraceLayer` (page-test.jsx:159, 164) become dead. Total ~6 LOC. Plus changing `description` text on the 3 presets that mention "Bridge" / "Phase 1" / "Phase 2" (lines 41-43, 49-51, 84-87).
- **Risk:** MEDIUM. The `family: bridge` value is a public-ish contract via `spec/contracts/presets.yaml`. Renaming may need a contract bump (see audit 05's note).
- **Regression guard:** `_ALLOWED_FAMILIES` validates the YAML at load time — `tests/test_presets.py` (if it exists) would catch removal of the `bridge` family while presets still use it. The fix order is: (1) recategorize the 3 presets, (2) drop `bridge` from `_ALLOWED_FAMILIES`, (3) drop the JSX pill.
- **Migration path:** Recategorize: `override` → `boundary`, `b64` → `canary` (it's a canary-decode test), `bridge` → `boundary` (it's a JSON action-field injection — boundary's job to wrap it opaquely). Drop the "Bridge" UI pill in the same commit. Update preset `description` text to drop "Phase 1/2".

### 3-E `Phase 1 / Phase 2` references in code comments

- **Path:**
  - `src/bulwark/guard.py:3` — module docstring mentions "Phase 1 → Phase 2 bridge". Historical context — keep as renaming history note OR delete.
  - `src/bulwark/attacks.py:794, 799` — `_bridge_exploitation_attacks` docstring + 1 attack description literally say "Phase 1 to Phase 2 bridge" / "embeds Phase 2 instructions". Same fix as 3-C.
  - `src/bulwark/detector_chain.py:142, 178` — `# Phase 1: detectors. ... # Phase 2: judge.` — these are **NOT** v1 leftovers; they refer to detector-chain phases inside the v2.5 chain executor. **KEEP.**
- **LOC delta:** ~3 (stripping the v1 historical phrases from docstrings).
- **Risk:** LOW.

---

## Ranked candidate table

| # | Item | Risk | LOC Δ | Test holding it alive | Action |
|---|------|------|-------|----------------------|--------|
| 1 | **`tests/benchmark.py` (broken zombie)** | LOW | **−494** | none | Delete file outright |
| 2 | `_bridge_exploitation_attacks()` + `AttackCategory.BRIDGE_EXPLOITATION` | MEDIUM | −52 | `tests/test_attacks.py:128-130` | Recategorize attacks; remove enum |
| 3 | `Attack.target="executor"` (27 occurrences) | LOW | −0 to −27 | none | Re-target to "boundary"/"detection" or drop field |
| 4 | `spec/presets.yaml` `family: bridge` (3 presets) + JSX pill + `_ALLOWED_FAMILIES` entry | MEDIUM | ~6 + descriptions | preset loader validation | Recategorize + drop pill |
| 5 | `bulwark.AnalysisGuard` / `AnalysisSuspiciousError` package-root re-exports | LOW | −5 | none (tests rename internally) | Delete |
| 6 | `bulwark.guard.AnalysisGuard` / `AnalysisSuspiciousError` module aliases | LOW | −4 | none (tests rename internally) | Delete |
| 7 | `make_analyze_fn` / `make_execute_fn` / `make_pipeline` docstring references in `__init__.py` files | LOW | −3 | none | Strip from docstrings |
| 8 | `Layer.EXECUTOR` enum value (zero consumers) | LOW | −1 | none | Delete |
| 9 | Test class renames (`TestAnalysisGuard*` → `TestPatternGuard*`) | LOW | 0 | self | Rename |
| 10 | `spec/contracts/guard.yaml` G-GUARD-002 text | LOW | 0 | the contract reference itself | Update wording |
| 11 | `bulwark.shortcuts` internal `as AnalysisGuard` rename | LOW | 0 | none | Drop rename, use `PatternGuard` |
| 12 | `Phase 1 / Phase 2` historical phrases in `guard.py` docstring + `attacks.py` bridge attacks | LOW | ~3 | none | Reword |
| 13 | `integrations/promptguard.py` module docstring still references `AnalysisGuard.custom_checks` | LOW | 0 | none | Reword |

**Total LOC reduction (taking everything except items 2 and 4 which are MEDIUM):** ~−507 LOC (driven almost entirely by `tests/benchmark.py`).
**Total LOC reduction (full sweep including MEDIUM with recategorization, not deletion of attack content):** ~−560 LOC.
**HIGH-risk items requiring migration paths:** **0**.

---

## Out-of-scope — looked at, decided not to flag

- **`bulwark_bench/bulwark_client.py:193-196`** reads `cfg.get("llm_backend", {})` from `/api/config`. Looks like v1 residue but `bulwark_bench` is the sidecar harness intentionally pointing at a separate LLM endpoint for token sampling — `llm_backend` here refers to **its own** LLM-judge backend, not the deleted v1 pipeline. ADR-034 + `src/bulwark_bench/__init__.py:4` make this scope clear. Keep as-is.
- **`src/bulwark/integrations/redteam.py:599-600`** reads `data.get("llm_mode", "none")` from probe response data. This is the garak-adapter pulling a field the dashboard's redteam endpoint emits — not a v1-pipeline call. Out of scope.
- **`src/bulwark/dashboard/static/src/page-test.jsx:62`** — `llm_mode: res.llm_mode || ''` — same; reads a dashboard response field. Out of scope (audit 05 / analyst 1's territory).
- **Trace-layer mappings in `data.jsx` / `page-test.jsx`** that translate `analysis_guard → bridge` and `executor → analyze`: live wire-format glue. Renaming requires a coordinated wire+frontend bump that is not what this audit is sized for.
- **`spec/decisions/002-two-phase-execution.md`, `028-bridge-sanitizer-strips-html.md`** still discuss bridge / AnalysisGuard. They are historical ADRs — keep as written; don't rewrite history.
- **`spec/contracts/guard.yaml` mention of `AnalysisSuspiciousError`** — listed in 1-E above, not deferred but bundled with the Group 1 cleanup.
- **`Pipeline.detector` (singular) back-compat shim** — ADR-044 §"Why no backwards-compat shim" explicitly chose not to ship one. Confirmed not present in `pipeline.py`. Nothing to remove.

---

## Suggested removal sequencing (one-PR-per-row, smallest blast radius first)

1. **Delete `tests/benchmark.py`** (item 1). Zero blast radius — the file imports a deleted module so it can't even be loaded. **Do this first.** −494 LOC.
2. **Strip `make_analyze_fn` / `make_execute_fn` from package docstrings** (item 7). Pure docstring rot. −3 LOC.
3. **Remove `Layer.EXECUTOR` enum value** (item 8). Confirmed zero consumers. −1 LOC.
4. **Phase 1 / Phase 2 phrase scrub in `guard.py`, `attacks.py`, `integrations/promptguard.py` docstrings** (items 12, 13). Zero behavior change.
5. **Retire `AnalysisGuard` / `AnalysisSuspiciousError` aliases — package root + module level** (items 5, 6). Two file edits + rename test classes (item 9) + update G-GUARD-002 wording (item 10) + drop the `shortcuts.py` `as AnalysisGuard` rename (item 11). One PR. ~ −12 LOC and a few renames.
6. **Recategorize `Attack.target="executor"`** (item 3). Touches 27 lines but is a sed-pass.
7. **Bridge family / category cleanup** (items 2, 4). The biggest semantic rewrite; do last so earlier cosmetic PRs don't merge-conflict with it.

Steps 1–5 are pure delete/rename and could land in a single "v2 vocabulary final pass" minor bump. Steps 6–7 deserve their own commit each because they touch test fixtures and the preset contract.
