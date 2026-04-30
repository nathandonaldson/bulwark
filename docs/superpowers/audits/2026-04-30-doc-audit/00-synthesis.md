# Doc Audit Synthesis (5 auditors → 1 brief)

**Date:** 2026-04-30
**Inputs:** `01-root-onboarding.md`, `02-interfaces-ops.md`, `03-architecture-concepts.md`, `04-integrations.md`, `05-dashboard-ui.md`
**Total findings:** 96 (12 CRITICAL, 37 IMPORTANT, 47 MINOR) + 26 restructural recommendations
**Goal:** Brief the rewriter (and inform the user before phase 2 dispatch).

---

## Cross-cutting themes (where the audits agree)

These are the patterns that show up across 3+ audits, ranked by remediation leverage.

### 1. v1-architecture vocabulary residue — biggest single concentration of bugs

The v1 two-phase / bridge / analyze-execute / "LLM backend" vocabulary is dead but scattered across the codebase:

- `src/bulwark/dashboard/static/src/page-test.jsx:269` — "configured LLM backend" prose. **CRITICAL** (audit 05 F1)
- `src/bulwark/dashboard/static/src/page-test.jsx:34, 159, 162-164` — "Bridge" filter button + `analyze/execute/executor` trace-layer mappings. **IMPORTANT** (audit 05 F4)
- `src/bulwark/dashboard/static/src/primitives.jsx:96-105` — dead `analyze`/`bridge`/`execute` SVG icons. **MINOR** (audit 05 F5)
- `docs/codex-security/bulwark-security-review.txt` — entire threat model is two-phase / `/v1/pipeline` / `make_analyze_fn` / `AnalysisGuard`. **CRITICAL** (audit 04 F-04-01)
- `src/bulwark/shortcuts.py:11-12, 68-69` — docstring still mentions "two-phase execution". **MINOR** (audit 01 F-01-014)
- `src/bulwark/__init__.py` — `AnalysisGuard` is a back-compat alias for `PatternGuard`; new docs should prefer the new name (audit 04 F-04-02)
- `examples/quickstart_protect.py` — orphaned example for the removed v1 `protect()` two-phase API (audit 01 F-01-013, audit 04 F-04-13 verified clean against v2 protect())
- `spec/presets.yaml` — two presets still use `family: bridge` (audit 05 F4 cross-ref)

**Restructural lever:** one sweep to delete every v1 token + add a CI grep guard against regressions. Audits 05 R1 and 04 R-04-01 propose this.

### 2. Port-convention chaos (3000 / 3001 / 8100) — every HTTP integration doc is wrong somewhere

| Surface | Port | Where defined |
|---|---|---|
| Docker image (`nathandonaldson/bulwark`) | **3000** | `dashboard/__main__.py:111`, `CLAUDE.md:65`, OpenAPI server URL |
| Source-tree dev | 3001 | `CLAUDE.md:62` |
| OpenClaw sidecar | 8100 | `docker-compose.bulwark.yml:12` |

Docs that disagree: `docs/dashboard.md:3`, `docs/api-reference.md:13`, `docs/batch.md:20`, `docs/config.md:119`, `docs/integrations/wintermute.md:5,42,74,94`, `examples/quickstart_anthropic.py:39`, `examples/quickstart_openai.py:15`, `examples/quickstart_generic.py:13` — all use 3001.

Project memory `project_wintermute_integration.md` says Wintermute consumes Bulwark on 3000. The docs say 3001 to Wintermute operators. They cannot both be right.

**Restructural lever:** standardize examples + integration docs on **3000** (the Docker contract). Keep 3001 explicitly labeled "dev" in CLAUDE.md. Add one paragraph titled "Which port am I on?" to `docs/README.md`. Audit 02 R-01, 04 R-04-02, 04 R-04-05.

### 3. ADR-047 / ADR-048 invisibility in user-facing docs

Phase H shipped (decode-rescan + shared chain helper) but user-facing docs barely surface it:

- `docs/detection.md` — missing decode-rescan section entirely. **CRITICAL** (audit 03 F1)
- `docs/api-reference.md:55-74` — 200 response shape missing `decoded_variants` and `blocked_at_variant`. **IMPORTANT** (audit 02 F-11)
- `docs/config.md:51-92` — file-shape config block omits `decode_base64` (env-var mentioned but YAML knob not). **IMPORTANT** (audit 02 F-12)
- `CLAUDE.md:33-38` — ADR pointer block missing 047 + 048 (the load-bearing chain semantics). **IMPORTANT** (audit 01 F-01-009)
- `src/bulwark/dashboard/static/src/page-configure.jsx:21-24` — pipeline visualization silent on the variant-fan-out stage. **MINOR** (audit 05 F14)
- `docs/red-teaming.md` — missing split-evasion (ADR-046) non-guarantee. **IMPORTANT** (audit 03 F10)

### 4. Fail-mode (`BULWARK_ALLOW_*`) underdocumentation

ADR-038 (`/healthz` degraded), ADR-040 (503 fail-closed), ADR-042 (413 byte cap) shipped — opt-out env vars (`BULWARK_ALLOW_NO_DETECTORS`, `BULWARK_ALLOW_SANITIZE_ONLY`) are operator decisions but barely documented:

- `docs/layers.md`, `docs/detection.md` — no mention. **IMPORTANT** (audit 03 F8)
- `docs/api-reference.md:159` — wording bug: claims `/healthz` returns a `mode` field, it doesn't (`mode` is on `/v1/clean` only). **MINOR** (audit 02 F-M11)
- `docs/config.md:32` — example shows `BULWARK_ALLOW_SANITIZE_ONLY=0` which suggests a default; env vars default to *unset*. **MINOR** (audit 02 F-M12)
- `docs/integrations/wintermute.md:46-48,146-151` — failure-modes table only lists 422; missing 503 and 413. **IMPORTANT** (audit 04 F-04-04)
- `docs/async.md:25-31` — async client example only handles 422. **IMPORTANT** (audit 03 F13)
- `integrations/openclaw/skills/bulwark-sanitize/SKILL.md:50-55` — rule covers "unreachable" but not 503 misconfigured. **MINOR** (audit 04 F-04-08)

### 5. Status pill blind to backend reality (CRITICAL — code bug, not doc bug)

`shell.jsx::computeStatusPill` reports "All layers active" even when `/v1/clean` is returning 503 to every request. Empty-state copy in events page (`"Your pipeline is running"`) lies in the same state. **CRITICAL** (audit 05 F2 + F13).

This is a CODE bug the audit caught — not a doc edit. The user's first-five-minutes experience is "green pill, zero events, no idea why". Restructural lever R2 in audit 05 proposes a small state machine that all UI surfaces read from.

### 6. Stale numbers everywhere — one source-of-truth fix retires several findings

- Test count: README `:243` and ROADMAP `:6` say "960+", actual is 991. **IMPORTANT** (audit 01 F-01-005, F-01-006)
- Probe counts: hardcoded "315" (`docs/red-teaming.md:78`), "3,112" (`page-configure.jsx:356`), "~3,000" (`docs/dashboard.md:57`) — actual count is dynamic from installed garak version. **IMPORTANT** (audit 02 F-06, audit 03 F5, audit 05 F8)
- Attack count: `docs/red-teaming.md:7-19` header says 77, table sums to 71 (missing `bridge_exploitation` row). **CRITICAL** (audit 03 F4)
- Latency badges in `page-configure.jsx:39-43, 281`: hardcoded "<1ms / ~30ms / ~50ms / ~1–3s" while the dashboard already has live per-event durations. **MINOR** (audit 05 F20)

**Restructural lever:** drop the precise numbers entirely (R-01 in audit 01 proposes "comprehensive test suite enforced by `tests/test_spec_compliance.py`" instead of "991 tests"). For probe counts, point readers at the live `/api/redteam/tiers` response. Audit 05 R4 proposes pulling stage badges from `/api/integrations`.

### 7. DeBERTa load timing — README is wrong in two places

- `README.md:38` and `:134` say DeBERTa "loads on first request"
- Actually loads at FastAPI startup via `_auto_load_detection_models` (`app.py:519-544`)

**CRITICAL** (audit 01 F-01-001, F-01-002).

### 8. Pipeline.from_config invisibility — ADR-044 hasn't propagated

ADR-044 made `Pipeline.from_config(path)` parity with the dashboard's `/v1/clean`, but most docs still treat HTTP as the only path to detection:

- `docs/layers.md:3` — `Pipeline.default()` for "all five" — false; default returns sanitizer + boundary, no detectors. **IMPORTANT** (audit 03 F6)
- `docs/detection.md:73-88` — "custom detector" section uses old `_detection_checks` private dict path. **MINOR** (audit 03 F16)
- `examples/quickstart_clean.py:1-7` — positions HTTP as the only detection path. **MINOR** (audit 04 F-04-16)

### 9. Auth model wording — ADR-029 reads-vs-writes misleading

- `docs/dashboard.md:69-73` implies reads gated when token is set. ADR-029 is explicit: when token unset, reads remain open; only mutating methods are gated by loopback check. **IMPORTANT** (audit 02 F-14)

### 10. Screenshots stale — Apr 23 PNGs predate v2.5.5+ JSX changes

- `docs/images/configure.png` cannot show the v2.5.5 base64-decode toggle (added Apr 30 in `page-configure.jsx`)
- All 6 PNGs are from Apr 23, multiple JSX files have changed since
- **IMPORTANT** (audit 05 F10)

**Restructural lever:** audit 05 R3 proposes a CI step that warns when `docs/images/*.png` mtime predates the JSX it depicts.

---

## Restructural recommendations (consolidated, ranked by leverage)

Q2=ii — the user picked restructural over surgical. Here are the audits' top consolidation/retirement/IA proposals, deduplicated and prioritized:

### High leverage (fix many findings at once)

1. **Retire `ROADMAP.md` "Shipped highlights"** — drifts worse than CHANGELOG and CLAUDE.md (still says Phase H deferred when it shipped in v2.5.4). Cut to one line: "Shipped: see CHANGELOG.md." Halves the file's size and removes its biggest drift surface. (audit 01 R-01-001)

2. **Standardize ports** — pick **3000** for examples + integration docs (matches Docker image). Add a "Which port am I on?" paragraph. Closes 8+ findings across 4 audits. (audit 02 R-01, audit 04 R-04-02)

3. **Triage `docs/codex-security/bulwark-security-review.txt`** — archive (rename + banner) or commission fresh. Currently misleading public-facing security artifact about a v1 architecture that no longer exists. (audit 04 R-04-01)

4. **Eliminate v1 vocabulary residue in one sweep** — `bridge`/`analyze`/`execute`/`executor`/`Phase 1`/`Phase 2`/`LLM backend` across `page-test.jsx`, `primitives.jsx`, `data.jsx`, `presets.yaml`, `shortcuts.py` docstring. Add a CI grep guard. (audit 05 R1)

5. **Single env-var canonical source** — extend `spec/contracts/env_config.yaml` (already says "canonical") to enumerate every `BULWARK_*` (currently missing `BULWARK_DECODE_BASE64`, `BULWARK_DASHBOARD_PORT`, `BULWARK_FALSEPOS_CORPUS`, `BULWARK_PROJECT_DIR`, `BULWARK_ALLOW_*`). Then `docs/config.md` and `docs/api-reference.md` link to it instead of duplicating. (audit 02 R-02)

6. **Move Configuration out of `docs/api-reference.md` into `docs/config.md`** — duplicated, drifting. Strip the Configuration section from api-reference, leave a one-line link. (audit 02 R-03)

### Medium leverage (cleaner IA)

7. **Hoist a v2 architecture overview page** — currently `detection.md` describes detectors only, `layers.md` describes the SDK, the big-picture pipeline is implied but not pictured anywhere. Either add a top-of-page diagram to `detection.md` or extract a new `docs/architecture.md`. (audit 03 R1)

8. **Add a "Known non-guarantees" section/page** — split-evasion (ADR-046), variants-not-reaching-LLM (NG-CLEAN-DECODE-VARIANTS-PRESERVED-001), judge-prompt-fixed (NG-JUDGE-003), judge-text-never-returned (NG-JUDGE-004). Currently scattered. (audit 03 R5)

9. **Tighten `protect()` / `clean()` / `/v1/clean` / `Pipeline.from_config()` hierarchy** — four entry points that look superficially similar; users can't tell which gives detection. Single comparison table closes a class of "what does this actually do" confusion. (audit 04 R-04-03)

10. **Move React library into `docs/python-library.md`** — README's library section (lines 198-228) competes for real estate; growing. Pattern matches existing Configuration → docs/config.md. (audit 01 R-01-003)

### Lower leverage (sane housekeeping)

11. **CLAUDE.md ADR pointer block** — generate from each ADR's frontmatter or move to `spec/decisions/INDEX.md`. Currently bit-rotting. (audit 01 R-01-004)

12. **CONTRIBUTING dev setup** — add a "Dev setup" section that pulls relevant rules from CLAUDE.md (test command, version bump, CHANGELOG). (audit 01 R-01-006)

13. **Async.md repositioning** — rename to `operations/concurrency.md` or fold into integration page. The "async" framing is misleading — Bulwark v2 is sync request/response. (audit 03 R4)

14. **De-emphasize `bulwark canary-generate`/`canary-check` legacy CLI** — pre-ADR-025, JSON-only, single largest concentration of doc bugs in audit 02. Either modernize or move to "Pre-ADR-025 commands" appendix. (audit 02 R-06)

---

## Code bugs the audit caught (separate from doc edits)

These are NOT for the rewriter. They become candidates for phase 3's simplification proposal or a follow-up "audit-driven code fixes" PR. Listing here so the rewriter doesn't try to fix them and so the user can scope phase 3.

| # | File | Issue | Severity |
|---|------|-------|----------|
| C1 | `src/bulwark/dashboard/static/src/shell.jsx:6-17` | `computeStatusPill` doesn't honor 503/no-detectors/degraded-explicit states | CRITICAL |
| C2 | `src/bulwark/dashboard/static/src/page-events.jsx:165-166` | Empty-state copy lies under no-detectors (consequence of C1) | IMPORTANT |
| C3 | `src/bulwark/dashboard/static/src/shell.jsx:50` | Unwired `⌘K` magnifier button (violates CLAUDE.md "no unwired buttons") | IMPORTANT |
| C4 | `src/bulwark/dashboard/static/src/page-test.jsx:34, 159, 162-164` | "Bridge" filter button + analyze/execute/executor mappings (v1 leftovers) | IMPORTANT |
| C5 | `src/bulwark/dashboard/static/src/page-test.jsx:269` | "configured LLM backend" string | CRITICAL |
| C6 | `src/bulwark/dashboard/static/src/page-test.jsx:71` | "or generate payloads" implies feature that doesn't exist | MINOR |
| C7 | `src/bulwark/dashboard/static/src/primitives.jsx:96-105` | Dead-code SVG icons for `analyze`/`bridge`/`execute` | MINOR |
| C8 | `src/bulwark/dashboard/static/src/page-test.jsx:296` | Tier card "probes" unit wrong for `falsepos` (samples, not probes) | MINOR |
| C9 | `src/bulwark/shortcuts.py:11-12, 68-69` | Docstring mentions "two-phase execution" (removed in v2) | MINOR |
| C10 | `examples/quickstart_protect.py` | Orphaned per audit 01 — but audit 04 verified the v2 `protect()` API still works in this file (sanitize+boundary-only) | MINOR |
| C11 | `src/bulwark/cli.py:182` | Help text "All 77 attacks" hardcoded; should interpolate from `len(AttackSuite().attacks)` | MINOR |
| C12 | `docs/cli.md:27` | Shell example with literal `​` chars that won't expand in default zsh/bash | IMPORTANT (this one is a doc; included for completeness — rewriter handles it) |
| C13 | `src/bulwark/dashboard/static/src/data.jsx:38` vs `page-test.jsx:159-164` | Two files disagree on what `analysis_guard` maps to (canary vs bridge) | MINOR |
| C14 | `src/bulwark/dashboard/static/src/page-events.jsx:267-271` | `LAYERS.slice(0, 5)` cap — LAYERS only has 4 entries; the "5-step" wording is v1 leftover | MINOR |

---

## Out-of-scope for the rewriter (do NOT touch)

- `spec/openapi.yaml`, `spec/contracts/*.yaml`, `spec/decisions/*.md` — auditors didn't audit these (Q1=a). The rewriter should refer TO them but not edit them. Drift from spec → impl is enforced by `tests/test_spec_compliance.py`.
- `src/` code — code bugs (C1-C14) are out of scope. The rewriter touches docs only.
- `tests/` — out of scope.
- `.github/workflows/` — out of scope.
- The graphify-related changes (`.gitignore` graphify line, `CLAUDE.md` graphify section, `.claude/settings.json`, `.mcp.json`) — uncommitted, user has decided NOT to commit. Don't touch.

---

## What the rewriter should do

1. **Read all 5 audit reports** + this synthesis brief. Read no other documentation files first — read what each audit cites as authoritative (`src/`, `spec/`).

2. **Apply the Q2=ii restructural recommendations first** (since they retire whole sections, no point editing lines you're about to delete). Top priority: ROADMAP "Shipped highlights" → 1-line link, port standardization, codex-security archival, env-var single source.

3. **Then apply doc-only findings** (CRITICAL → IMPORTANT → MINOR). For each finding, either edit the doc or note "supersedes-by-restructural" if the relevant section was already removed.

4. **Skip every code bug (C1-C14, except C12)**. Note them for phase 3 but don't touch `.jsx` / `.py` / `.html` files except for in-source docstrings (e.g., `shortcuts.py` C9 is a docstring, that's fair game).

5. **Update screenshots is out of scope** — re-shooting requires a running dashboard. Note as a follow-up; don't try.

6. **Output: a single markdown summary + the actual file edits**. The rewriter should commit the edits in one commit (or one logical commit per restructural theme). The summary lives at `docs/superpowers/audits/2026-04-30-doc-audit/06-rewriter-report.md`.

7. **Don't introduce new findings.** If something looks wrong but wasn't in any audit, flag it in the rewriter report and skip — let phase 3 catch it.

8. **VERSION + CHANGELOG**: this is a doc-only PR, so VERSION should bump to **2.5.10** and CHANGELOG should get a `## [2.5.10]` entry summarizing the restructural pass. Per CLAUDE.md "patch bump every commit".

---

## Ambiguities the user should resolve before phase 2

1. **Codex security review**: archive (rename + banner) or commission a fresh `/codex security-review`? Defaulting to archive in the brief; user can override.

2. **`examples/quickstart_protect.py`**: keep with clarified docstring (since v2 `protect()` works, it's just sanitize+boundary-only) or delete? Defaulting to KEEP + clarify.

3. **ROADMAP "Future" section** (Transparent proxy mode, CaMeL, etc.): keep, label "Aspirational", or prune? Defaulting to label.

4. **CLAUDE.md graphify section**: leave (user's stated intent — Phase 2 install uncommitted) or rephrase? Defaulting to leave untouched.

5. **CLAUDE.md ADR pointer block**: rewriter adds 047 + 048 inline (low effort), or proposes the auto-generated approach (audit 01 R-01-004) for follow-up? Defaulting to inline-add now.
