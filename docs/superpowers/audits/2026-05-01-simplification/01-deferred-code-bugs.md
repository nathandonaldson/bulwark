# Phase 3 Analysis 01: Deferred code bugs

**Date:** 2026-05-01
**Source:** Doc audit C1–C14 (12 deferred items: C1, C2, C3, C4, C5, C6, C7, C8, C10, C11, C13, C14)
**Total estimated LOC delta:** +85 / −60 (net +25 — most groups add small amounts of correctness logic, not pure deletion)

C9 (`shortcuts.py` docstring) and C12 (`docs/cli.md` literal `​`) were already addressed in the v2.5.10 doc-rewriter pass and are excluded from this proposal.

## Verification notes

I read every cited file and confirmed line numbers. Drift caught:

- **C2** audit cites `page-events.jsx:165-166`; the empty-state copy is now at lines **161-166** of the rewriter-bumped tree (`Your pipeline is running.` is on line 165). Same string, slightly shifted.
- **C5** audit cites line 269; current `page-test.jsx:269` is exactly `"Sends Garak's attack payloads through your real Bulwark pipeline with the configured LLM backend."` Confirmed.
- **C13** audit's note about `data.jsx:38 vs page-test.jsx:159-164`: confirmed. `data.jsx:38` says `analysis_guard: 'canary'`, `page-test.jsx:159` says `analysis_guard: 'bridge'`. Two files disagree on the same backend token.
- **The `Layer` enum** (`src/bulwark/events.py:17-23`) still contains `ANALYSIS_GUARD = "analysis_guard"`, `EXECUTOR = "executor"`. So the *backend* still emits these tokens. Any normalizer cleanup must keep the inbound mapping for these even while dropping the v1 *display* values.
- **`spec/presets.yaml`** has two presets (`b64`, `bridge`) with `family: bridge` and `src/bulwark/presets.py:18-20`'s `_ALLOWED_FAMILIES` includes `bridge`. The JSX `bridge` filter button is consistent with the spec right now — this is a multi-file rename, not a unilateral JSX cut.

## Existing-test gates that block naive removal

These were the biggest surprises while cross-referencing — two of the proposed cuts have tests that *require* the v1 leftover, so the cut is more than a JSX edit:

| Code bug | Blocking test | What the test asserts |
|---|---|---|
| **C3** (`shell.jsx:50` unwired ⌘K) | `tests/test_dashboard_ui_shell.py::TestNonGuarantees::test_cmdk_is_stub` (NG-UI-SHELL-001) | `onClick={() => {}}` AND `"Search events (⌘K)"` must remain. |
| **C14** (`page-events.jsx:267-271` slice(0,5)) | `tests/test_dashboard_ui_events.py::TestRowExpansion::test_trace_fallback_when_metadata_missing` (G-UI-EXPAND-003) | Literal `LAYERS.slice(0, 5)` must be present. |
| **C4 / C13** (mapping) | `tests/test_dashboard_ui_events.py::TestFilterEvents` uses `"layer": "bridge"` in fixture data (line 45) | Test data references `bridge` as a valid layer string for filter assertions. |

For C3 and C14 the contract `spec/contracts/dashboard_ui.yaml` is also load-bearing — the cut needs a contract update, not just a JSX delete. CLAUDE.md spec-driven rule applies.

## Groups (ranked by leverage)

### G-01: Status-pill state-machine + truthful empty state — HIGH leverage / MEDIUM risk

- **Finding IDs:** C1, C2 (audit 05 F2 + F13 — flagged CRITICAL/IMPORTANT)
- **Files:**
  - `src/bulwark/dashboard/static/src/shell.jsx:6-17` — extend `computeStatusPill` to a small state machine returning `{kind, label, detail}`.
  - `src/bulwark/dashboard/static/src/page-events.jsx:161-166` — branch the no-events copy on the same state.
  - `src/bulwark/dashboard/static/src/data.jsx` — surface ADR-040 `error.code === 'no_detectors_loaded'` and ADR-038 `mode === 'degraded-explicit'` from `runClean` responses into store state. Currently `runClean` reads `res.error` but does not project a backend-mode signal anywhere reachable from the shell.
  - **New** spec entries: `spec/contracts/dashboard_ui.yaml` needs `G-UI-STATUS-006` (no-detectors → `{kind:'bad', label:'No detectors loaded'}`) and `G-UI-STATUS-008` (degraded-explicit → `{kind:'warn', label:'Sanitize-only mode'}`). Per CLAUDE.md spec-driven rule, contract additions come first.
  - **New** test: `tests/test_dashboard_ui_shell.py` — extend `TestComputeStatusPill` with two cases (no_detectors, degraded_explicit). And `tests/test_dashboard_ui_events.py::TestEmptyState` — branch on the same store fixture.
- **LOC delta:** +50 (state machine + 2 contract entries + 4 test cases) / −10 (collapse the existing 4-line `if det.status` ladder into the same `switch`). Net **+40**.
- **Risk:** **MEDIUM**. Touches the single most-rendered component on the page (status pill in every header). New state branches are pure string returns, so failure mode is "wrong label" not "broken UI". The risky edge is `runClean` plumbing — if the backend signal is misnamed in the store the pill silently goes back to lying.
- **Regression guard:**
  - Existing: `tests/test_dashboard_ui_shell.py::TestComputeStatusPill::{test_all_on_ready_returns_ok, test_one_off_returns_warn_with_count, test_detector_error_returns_bad, test_detector_loading_returns_warn}` (G-UI-STATUS-001..004) — these MUST keep passing across the refactor.
  - Existing: `tests/test_fail_closed_no_detectors.py` exercises the backend 503 path — confirms the response shape this group depends on.
  - **New** must-add: assertions that the pill returns `bad/'No detectors loaded'` when store has `lastCleanError === 'no_detectors_loaded'` and `warn/'Sanitize-only mode'` when `lastCleanMode === 'degraded-explicit'`.
- **Order:** Ship first (highest user-visible win, most-cited audit finding, blocks G-02 which extends the same component).

---

### G-02: v1 layer vocabulary sweep (`bridge`/`analyze`/`execute`/`executor`) — HIGH leverage / MEDIUM risk

- **Finding IDs:** C4, C5, C7, C13 (audit 05 F1, F4, F5; cross-referenced from synthesis theme #1)
- **Files:**
  - `src/bulwark/dashboard/static/src/page-test.jsx:34` — drop `{id:'bridge', label:'Bridge'}` from `categories`. Add `{id:'detection', label:'Detection'}` and `{id:'canary', label:'Canary'}` (matches `_ALLOWED_FAMILIES` in `presets.py:18-20` minus `bridge`).
  - `src/bulwark/dashboard/static/src/page-test.jsx:153-167` — fix `_normalizeTraceLayer`: drop `analyze`/`execute`/`executor`/`guard` keys; change `analysis_guard` mapping to `'canary'` to match `data.jsx:38`.
  - `src/bulwark/dashboard/static/src/page-test.jsx:269` — replace "configured LLM backend" string with the audit's recommended copy (sanitizer → DeBERTa / PromptGuard / optional LLM judge → trust boundary).
  - `src/bulwark/dashboard/static/src/primitives.jsx:96-105` — drop `analyze`, `bridge`, `execute` entries from `paths`. Keep `sanitizer`, `boundary`, `detection`, `canary` (the 4 real LAYERS).
  - `src/bulwark/dashboard/static/src/data.jsx:4` — update the comment that says `analyze/execute/bridge layers` (already historical-only, but redundant with the JSX cleanup).
  - `spec/presets.yaml:47, :82` — rename `family: bridge` → `family: detection` on the two affected presets (`b64`, `bridge`). The preset id `bridge` itself can stay or be renamed; the *family* is what the filter button keys on.
  - `src/bulwark/presets.py:18-20` — drop `"bridge"` from `_ALLOWED_FAMILIES` once spec/presets.yaml stops using it. Tests in `tests/test_presets.py` will catch a stale spec entry.
  - **Test fixture update**: `tests/test_dashboard_ui_events.py:45` test fixture `"layer": "bridge"` → `"layer": "detection"`.
- **LOC delta:** +15 (3 replacement category buttons, 1 preset family rename across 2 entries, the LLM-backend string swap) / −22 (mapping keys, dead SVG icons, ALLOWED_FAMILIES entry, 2 preset family lines). Net **−7**.
- **Risk:** **MEDIUM**. Pure JSX/spec rename, no runtime logic change. The risk is the *cross-file dependency*: if you change `_ALLOWED_FAMILIES` before `spec/presets.yaml` you break preset loading; if you change the JSX category list before the preset rename, the new buttons render with zero presets. Order matters.
- **Regression guard:**
  - Existing: `tests/test_presets.py` validates every preset's family is in `_ALLOWED_FAMILIES`. Catches a spec/code mismatch.
  - Existing: `tests/test_spec_compliance.py` — confirms presets.yaml schema.
  - Existing: `tests/test_dashboard_ui_test_page.py::TestPresetsSource::test_page_test_uses_store_presets` — confirms category/family wiring stays through the rename.
  - **No regression test exists** for the `_normalizeTraceLayer` mapping correctness — the function isn't covered by `tests/test_dashboard_ui_test_page.py` at all. Would need to add a Node harness similar to `_run_pill` covering: `analysis_guard → canary`, `executor → detection` (since the backend Layer enum still emits these), `trust_boundary → boundary`, unknown → unknown. **New test required**: `tests/test_dashboard_ui_test_page.py::TestNormalizeTraceLayer` (~5 cases, ~25 LOC).
  - **No regression test exists** confirming `primitives.jsx::LayerIcon` only ships ids that match LAYERS — would be a useful one-liner: `assert all(k in valid for k in LayerIcon paths)`. Add as `tests/test_dashboard_ui_shell.py::TestLayerIcon`.
- **Order:** Ship after G-01 (independent, but the audit's R1 / R2 are sister recommendations and reviewing them as one PR gives the cleanest commit). Internal order: contract/spec first (`spec/presets.yaml`, `_ALLOWED_FAMILIES`, new G-UI-NORMALIZE-001 contract entry), then JSX, then the new tests.

---

### G-03: Falsepos tier "probes" → "samples" — MEDIUM leverage / LOW risk

- **Finding IDs:** C8 (audit 05 F18)
- **Files:**
  - `src/bulwark/dashboard/static/src/page-test.jsx:286-296` — branch the unit literal on `t.id === 'falsepos'` so the card renders `{count} samples` instead of `{count} probes` for the false-positive tier. Backend already returns a custom `description`; only the unit label is the category error.
  - **No backend change needed**. `app.py:780-787` already returns enough metadata to identify the tier client-side; renaming the field would be more disruptive than the JSX branch.
- **LOC delta:** +3 / −1. Net **+2**.
- **Risk:** **LOW**. Single literal, no behaviour change.
- **Regression guard:** No specific regression test exists for the unit label. **New test needed** in `tests/test_dashboard_ui_test_page.py::TestRedTeamTiers`: asserts that for `t.id === 'falsepos'` the rendered unit is "samples", and for any other tier the unit is "probes". ~10 LOC.
- **Order:** Independent of all other groups. Ship anytime; would be a clean stand-alone PR.

---

### G-04: Test-page copy: "or generate payloads" claim removal — LOW leverage / LOW risk

- **Finding IDs:** C6 (audit 05 F11)
- **Files:**
  - `src/bulwark/dashboard/static/src/page-test.jsx:71` — change `"Paste untrusted content, select a preset, or generate payloads"` to `"Paste untrusted content or select a preset"`.
- **LOC delta:** +1 / −1. Net **0**.
- **Risk:** **LOW**. Pure copy edit.
- **Regression guard:** No regression test exists for this string. Adding one is overkill — this is a one-shot copy fix, not a recurring drift surface. *Note: "no regression test exists, would need to add one"* if user wants belt-and-braces.
- **Order:** Bundle into G-02's commit (same file, same theme — v1 vocabulary). Adds zero coordination risk.

---

### G-05: CLI help text dynamic attack count — LOW leverage / LOW risk

- **Finding IDs:** C11 (audit 05 in synthesis table)
- **Files:**
  - `src/bulwark/cli.py:181-182` — replace the static `'Run all 77 attacks (default: 8 presets)'` with a dynamic value computed from `len(AttackSuite().attacks)`.
- **LOC delta:** +3 (lazy-import + f-string) / −1. Net **+2**.
- **Risk:** **LOW**. Click decorators evaluate `help=` at module import — to interpolate a count you either:
  1. Compute at module load (`AttackSuite().attacks` is cheap; module import already pays for `attacks/` traversal elsewhere), or
  2. Fall back to a generic "all attacks" wording (zero LOC, no count drift surface).
  Option 2 is the lower-risk choice and matches the rewriter's "drop the precise numbers entirely" pattern (synthesis brief restructural lever in theme 6).
- **Regression guard:**
  - Existing: `tests/test_attacks.py` — verifies the suite count integrity, not the CLI help string.
  - **No regression test exists** for the help text. Recommend dropping the count instead of testing the interpolation. If interpolation is chosen, add a test that imports `bulwark.cli` and asserts `--help` output matches `len(AttackSuite().attacks)`.
- **Order:** Independent. Ship anytime.

---

### G-06: `LAYERS.slice(0, 5)` no-op cap removal — LOW leverage / LOW risk (but blocked by contract)

- **Finding IDs:** C14 (audit 05 F7)
- **Files:**
  - `src/bulwark/dashboard/static/src/page-events.jsx:267-271` — replace `LAYERS.slice(0, 5).map(l => ({ id: l.id }))` with `LAYERS.map(l => ({ id: l.id }))` and update the comment.
  - `tests/test_dashboard_ui_events.py:184-189` — `test_trace_fallback_when_metadata_missing` asserts the literal `LAYERS.slice(0, 5)`. Must be updated to assert `LAYERS.map`.
  - `spec/contracts/dashboard_ui.yaml::G-UI-EXPAND-003` — currently codifies "first 5 LAYERS"; reword to "all LAYERS".
- **LOC delta:** +1 / −2 (slice gone, comment shorter). Net **−1**. Plus 1-line spec edit, 1-line test edit.
- **Risk:** **LOW**. Today the slice is a no-op (LAYERS has 4, slice(0,5) returns all 4). The fix codifies what's already happening. Only risk is forgetting to update the contract; CI will fail loudly via `tests/test_spec_compliance.py`.
- **Regression guard:** The very test that gates this (`G-UI-EXPAND-003`) needs editing — by definition you cannot leave it untouched. After the edit, the test still asserts "trace synthesis covers all known layers" via `LAYERS.map`.
- **Order:** Independent. Trivial follow-up; bundle with G-02 if shipping a single "v1 vocabulary cleanup" PR.

---

### G-07: Unwired ⌘K button — LOW leverage / LOW risk (but blocked by contract)

- **Finding IDs:** C3 (audit 05 F3)
- **Files:**
  - `src/bulwark/dashboard/static/src/shell.jsx:50` — delete the `<button … data-hint="Search events (⌘K)" onClick={() => {}}>…</button>`.
  - `tests/test_dashboard_ui_shell.py::TestNonGuarantees::test_cmdk_is_stub` — currently *requires* the stub. Either delete the test or invert it to assert the button is gone.
  - `spec/contracts/dashboard_ui.yaml::NG-UI-SHELL-001` — currently codifies the stub as a non-guarantee. Either remove the entry or rephrase to "no command palette in v2".
  - `CLAUDE.md` "Don't add buttons that aren't wired up" rule — already implies removal is correct; the contract is the only thing preserving the stub.
- **LOC delta:** +0 / −10 (button + svg + test + non-guarantee). Net **−10**.
- **Risk:** **LOW**. Pure deletion, isolated to the header. The "risk" is procedural — three artefacts (JSX, test, contract) must be updated atomically or CI fails. Spec-driven rule means contract goes first.
- **Regression guard:** After the cut, `test_cmdk_is_stub` should be inverted: `assert "Search events (⌘K)" not in shell` and `assert "onClick={() => {}}" not in shell` (or scoped narrowly so it doesn't flag legitimate uses). Adds a forward-going regression guard against the stub being re-added.
- **Order:** Independent. CLAUDE.md design rule already endorses the cut. Recommend bundling into the same PR as G-01 (both touch `shell.jsx`).

---

### G-08: `quickstart_protect.py` orphan check — VERY LOW leverage / NO risk

- **Finding IDs:** C10 (audit 01 F-01-013, audit 04 F-04-13 verified clean)
- **Files:** `examples/quickstart_protect.py`
- **LOC delta:** +0 / −0. Already verified clean by the rewriter pass; the docstring (lines 1-13) already explains the v2 sanitize+boundary-only positioning. Audit's "orphaned" flag was based on the assumption `protect()` was a v1 API — `bulwark.integrations.anthropic.protect` still exists and does what the docstring says.
- **Risk:** **NONE**. No change required.
- **Regression guard:** `tests/test_protect_anthropic.py` already covers `protect()` end-to-end.
- **Order:** **Skip**. Listed for completeness; the rewriter's "user resolution #2 — keep with clarified docstring" already settled this.

---

## Summary table

| Group | Findings | LOC (net) | Risk | Guard | Order |
|---|---|---|---|---|---|
| G-01 status-pill state machine | C1, C2 | +40 | MEDIUM | Existing G-UI-STATUS-001..004 + new G-UI-STATUS-006/008 + new test | 1 (highest leverage) |
| G-02 v1 vocab sweep | C4, C5, C7, C13 | −7 | MEDIUM | tests/test_presets.py + new normalizer test + LayerIcon test | 2 |
| G-03 falsepos units | C8 | +2 | LOW | New test required | 3 (independent) |
| G-04 "or generate payloads" | C6 | 0 | LOW | None; bundle into G-02 | 4 (with G-02) |
| G-05 CLI 77 attacks | C11 | +2 | LOW | None for the literal — recommend dropping count entirely | 5 (independent) |
| G-06 LAYERS.slice(0,5) | C14 | −1 | LOW | Existing G-UI-EXPAND-003 (must be edited) | 6 (with G-02) |
| G-07 unwired ⌘K button | C3 | −10 | LOW | Existing NG-UI-SHELL-001 (must be removed/inverted) | 7 (with G-01) |
| G-08 quickstart_protect.py | C10 | 0 | NONE | tests/test_protect_anthropic.py | Skip |
| **Totals** | **11 in scope (C9, C12 done; C10 no-op)** | **+26 net** | mixed | | |

## Out-of-scope observations

Things I noticed while cross-referencing the audit citations that are NOT in the C1–C14 list. Logged for the user; not actioned per the "don't propose new features" rule.

1. **`Layer` enum dead values** — `src/bulwark/events.py:17-23` still has `EXECUTOR` and `ISOLATOR` (lines 22-23). The dashboard `_normalizeTraceLayer` and `_normalizeEventLayer` need to handle whatever the backend emits, but if `EXECUTOR`/`ISOLATOR` are never written by any current code path, the enum entries are dead. A grep across `src/bulwark/` for `Layer.EXECUTOR` / `Layer.ISOLATOR` would confirm.
2. **`page-configure.jsx:40` "512-token" wording** — audit 05 F6 (MINOR). Closely related to the v1 vocabulary cleanup but mis-bucketed by the audit (it's a doc-text drift, not v1 vocabulary). The rewriter pass fixed `docs/detection.md` to say 510; the JSX still says 512. Could be added to G-02 as a one-line edit but isn't in C1–C14.
3. **`page-shield.jsx:171` 24h window label** (audit 05 F15, F16) — copy-only, MINOR. Outside C1–C14.
4. **`page-leak-detection.jsx:39-41`** "Edit via bulwark-config.yaml" message (audit 05 F17, IA-gap) — depends on whether to ship inline pattern editor; outside the deferred-bug list.
5. **`page-configure.jsx:39-43, :281`** static latency badges (audit 05 F20). Audit 05 R4 proposes pulling them from `/api/integrations`; this is structural work, not a code-bug cut.
6. **`data.jsx:11` Sanitizer description** (audit 05 F9). Copy-only; outside C1–C14.
7. **`primitives.jsx:104` `execute` SVG** has a "play triangle" glyph distinct from the others — if `EXECUTOR` is reachable via the Layer enum, the icon may still be used by some code path. Worth a final `grep -rn "LayerIcon.*id={\"execute\"\|id={'execute'\|id=execute" src/` before the cut.

These would warrant their own simplification proposal if the user wants to extend phase 3 beyond C1–C14.
