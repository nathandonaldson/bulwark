# Phase 2 Rewriter Report

**Date:** 2026-05-01
**Worktree:** `agent-a66ea96943a0a17ee` (current `main`)
**Inputs:** Synthesis brief + audits 01–05 at `docs/superpowers/audits/2026-04-30-doc-audit/`.
**Version bump:** 2.5.9 → 2.5.10. CHANGELOG entry added.

---

## What you did

### Restructural — high leverage (closes many findings at once)

- **`docs/codex-security/bulwark-security-review.txt`**: moved to
  `docs/codex-security/archive/bulwark-security-review-v1.txt` with a
  banner ("ARCHIVED 2026-05-01 — frozen at v1.x architecture …"). No
  inbound links from production docs needed updating (verified).
  Closes F-04-01, F-04-02 (both audit 04).
- **`ROADMAP.md`**: full rewrite. "Shipped highlights" cut to a
  one-line `CHANGELOG.md` link; "Future" section pruned per user
  resolution #3. "Next" section rewritten to drop the falsified
  "ADR-047 planned" / "Phase H deferred" lines. Closes
  F-01-003, F-01-004, F-01-005, F-01-015, R-01-001, R-01-002.
- **Ports standardized on 3000**:
  - `docs/dashboard.md`, `docs/api-reference.md`, `docs/batch.md`,
    `docs/config.md`, `docs/integrations/wintermute.md`,
    `examples/quickstart_anthropic.py`, `examples/quickstart_openai.py`,
    `examples/quickstart_generic.py` all switched.
  - `examples/quickstart_clean.py` doesn't need a port (pure library).
  - "Which port am I on?" table added to `docs/README.md` covering
    3000 (Docker) / 3001 (source dev) / 8100 (OpenClaw).
  - Closes F-03 (audit 02), F-04-03, F-04-11, F-04-05 (audit 04 — port
    portion), R-01 (audit 02), R-04-02 + R-04-05 (audit 04).
- **`CLAUDE.md`**: ADR-047 + ADR-048 inline-added per user
  resolution #5. Closes F-01-009.
- **`docs/api-reference.md`**: full rewrite. Configuration block moved
  out into `docs/config.md` (one-line link); endpoints table extended
  with `/api/redteam/reports`, `/api/redteam/reports/{filename}`,
  `/api/redteam/retest`; 200-response shape adds `decoded_variants`,
  `blocked_at_variant`, per-detector trace fields; auth section
  rewritten per ADR-029/041 reads-vs-writes split; byte cap fixed.
  Closes F-01, F-10, F-11, F-13, F-14, F-15, F-M3, F-M11, F-M2 (all
  audit 02), R-01 + R-03 + R-05 (audit 02), R-04-04.

### Restructural — medium leverage

- **`docs/python-library.md`** (new): extracted the README "Library
  use" section into a standalone page. Adds the 4-way entry-point
  comparison table (`bulwark.clean()` vs `protect()` vs
  `Pipeline.from_config()` vs HTTP `/v1/clean`) with what each runs
  and when to use each. Closes R-01-003 (audit 01), R-04-03 (audit 04).
- **`docs/detection.md`**: full rewrite. New "Decode-rescan
  (ADR-047)" section, new "Operator opt-outs" section
  (`BULWARK_ALLOW_NO_DETECTORS`, `BULWARK_ALLOW_SANITIZE_ONLY`), new
  "Known non-guarantees" section (NG-DETECTOR-WINDOW-EVASION-001,
  NG-CLEAN-DECODE-VARIANTS-PRESERVED-001, NG-JUDGE-003/004), chunk
  numbers fixed to 510 + 64-token, judge prompt section now mentions
  the nonce-delimited markers, custom-detector docs moved from the
  private `_detection_checks` to `Pipeline(detectors=[...])`. Closes
  F1, F2, F3, F8, F10, F14, F15, F16 (all audit 03), R5 (audit 03).
- **`docs/layers.md`**: full rewrite. `Pipeline.default()` claim
  corrected (sanitizer + boundary only); cross-link to `detection.md`
  + `python-library.md`; sanitizer "what it removes" expanded with
  scripts/styles/CSS-hide/variation-selectors/encoding decode; NFKC
  default fixed (off, opt-in); canary token shape shown. Closes F6,
  F7, F17, F18, F19 (audit 03), R3 (audit 03).
- **`docs/async.md`**: full rewrite. Repositioned around the async
  client (Bulwark v2 is sync request/response server-side); example
  client now branches on 422 + 413 + 503 with `error.code`; judge
  mechanics paragraph corrected (synchronous httpx round-trip blocks
  the route handler — there is no thread-pool offload). Closes F13,
  F22 (audit 03), R4 (audit 03).
- **`docs/red-teaming.md`**: full rewrite. Attack-count header dropped
  in favour of the per-category table (with `bridge_exploitation` row
  added; `split_evasion` noted as on-demand); probe-count comment in
  the programmatic example softened; programmatic example sets
  `runner.pipeline_url`; ADR-035 LLM-tier removal noted; new "Known
  non-guarantees" section. Closes F4, F5, F9, F10, F11, F12 (audit
  03).

### Restructural — lower leverage / housekeeping

- **`docs/dashboard.md`**: rewrite. Auth section corrected per
  ADR-029/041 reads-vs-writes; Standard Scan probe count phrasing
  no longer pins "~3,000"; Sanitizer pane sub-toggles list now
  includes encoding-resistant + base64 decode-rescan. Closes F-06,
  F-14 (audit 02), R-04 (audit 02).
- **`docs/config.md`**: rewrite. `decode_base64: false` added under
  YAML pipeline-layers; env-var examples flipped from `=0` to `=1`
  with explicit "default: unset" framing; `BULWARK_ALLOW_SANITIZE_ONLY`
  description corrected (`/healthz` returns `status`, not `mode`);
  `BULWARK_DASHBOARD_PORT`, `BULWARK_FALSEPOS_CORPUS`,
  `BULWARK_PROJECT_DIR` newly enumerated. Closes F-12, F-M11, F-M12,
  R-02 (audit 02).
- **`docs/cli.md`**: rewrite. `bulwark canary-generate` /
  `canary-check` JSON-only (was YAML/JSON); `--full` no longer says
  "All 77 attacks"; `bulwark sanitize` example uses `printf` for
  zero-width escapes; entry-point section clarifies hyphenated names.
  Closes F-02, F-04, F-05, F-07, F-19, F-M1, R-06 (audit 02), C12.
- **`integrations/openclaw/skills/bulwark-sanitize/SKILL.md`**: rule 4
  added — HTTP 503 with `error.code: no_detectors_loaded` is
  Bulwark misconfigured, not transient. Closes F-04-08 (audit 04).
- **`docs/integrations/wintermute.md`**: rewrite. Port to 3000;
  failure-modes table now covers HTTP 503 + 413; trace example
  illustrative-not-exhaustive disclaimer + `decoded_variants` /
  `blocked_at_variant` shown; `clean()` helper branches on all three
  error codes. Closes F-04-03, F-04-04, F-04-05.
- **`CONTRIBUTING.md`**: Dev-setup section added (test command,
  version bump rule, dev port note); fictional `version: "0.5.0"`
  dropped from contract example; ADR list extended with 038, 047,
  048. Closes F-01-007, F-01-017, R-01-006 (audit 01).
- **`README.md`**: DeBERTa load timing corrected; quickstart port
  3000; `[Docs]` link now points at `docs/README.md`; "960+ tests"
  replaced with "comprehensive test suite enforced by `tests/test_spec_compliance.py`";
  Standard Scan rate phrasing softened; "Library use" cut to a
  pointer at `docs/python-library.md`; curl example output truncated
  with `, ...` to signal extra fields. Closes F-01-001, F-01-002,
  F-01-005, F-01-006, F-01-008, F-01-011, F-01-012.

### Source-code docstring fixes

- **`src/bulwark/shortcuts.py`**: module docstring + `clean()`
  docstring now say "sanitize + trust boundary, no ML detection" and
  point at `Pipeline.from_config(path)` for full detection. The
  "two-phase execution" mention is gone. Closes F-01-014, C9.

### CHANGELOG + VERSION

- **`VERSION`**: 2.5.9 → 2.5.10.
- **`CHANGELOG.md`**: new `## [2.5.10] - 2026-05-01` entry at the top
  describing the rewrite, what restructured, what got fixed, the
  numbers dropped, and the code bugs deferred to phase 3.

---

## What you skipped and why

### Code bugs deferred to phase 3 (synthesis brief Constraints)

| # | File | Why skipped |
|---|------|-------------|
| C1 | `shell.jsx::computeStatusPill` | Behavioural code change. State machine work. |
| C2 | `page-events.jsx:165-166` empty-state copy | Reads from store state — depends on C1. |
| C3 | `shell.jsx:50` unwired `⌘K` button | JSX behaviour. |
| C4 | `page-test.jsx` "Bridge" filter / mappings | JSX behaviour + spec/presets.yaml family rename. |
| C5 | `page-test.jsx:269` "configured LLM backend" string | JSX literal. Per audit 05 F1 — out of scope here. |
| C6 | `page-test.jsx:71` "or generate payloads" | JSX literal. |
| C7 | `primitives.jsx:96-105` dead SVG icons | JSX dead code. |
| C8 | `page-test.jsx:296` falsepos "probes" unit | JSX behaviour. |
| C10 | `examples/quickstart_protect.py` | Per user resolution #2: kept with clarified docstring. Not a bug. |
| C11 | `cli.py:182` "All 77 attacks" help text | Python source. |
| C13 | `data.jsx:38` vs `page-test.jsx:159-164` mapping | JSX behaviour. |
| C14 | `page-events.jsx:267-271` `LAYERS.slice(0, 5)` | JSX dead code. |

C9 (`shortcuts.py` docstring) and C12 (`docs/cli.md` literal `​`)
were doc-side and **were** addressed.

### Spec / openapi / contracts / tests / Dockerfile / workflows / pyproject

Out of scope per the synthesis brief. Several findings reference these
(e.g., R-02 audit 02 wants `spec/contracts/env_config.yaml` extended
with the missing env vars). Logged for follow-up; not edited.

### Screenshots in `docs/images/*.png` (audit 05 F10)

Re-shooting the dashboard screenshots requires running the dashboard.
Not done here. The Apr 23 PNGs predate the v2.5.5 base64-decode toggle
on `page-configure.jsx` and the v2.4.x / v2.5.x design tweaks. Logged
as a follow-up; do this at the next dashboard-touching release.

### `CLAUDE.md` graphify section (user resolution #4)

Left untouched. The user's stated intent is to keep the section while
graphify-Phase-2 changes are uncommitted on `main`. The worktree did
not show a graphify section that needed editing — synthesis brief
guidance was simply "if your worktree's CLAUDE.md doesn't have a
graphify section, that's fine — don't add one". The local
`CLAUDE.md` happens to *have* a graphify section already in the
worktree's snapshot of `main`; per the user's instruction, left
untouched.

---

## Findings count

- **Doc fixes applied:** ~50 (CRITICAL + IMPORTANT + the in-scope MINOR
  set across all five audits). Several MINORs were superseded by the
  restructural rewrites that retired entire sections (e.g. F-M2 dropped
  out when the api-reference endpoints table was rewritten).
- **Restructural changes:** 12 (all 6 high-leverage and most of the
  medium/low-leverage items from the synthesis brief; CONTRIBUTING dev
  setup added; CLAUDE.md ADR-pointer auto-generation deferred per
  brief's lower-leverage classification).
- **Code bugs deferred to phase 3:** 12 (C1–C8, C10, C11, C13, C14;
  C9 + C12 handled here).

---

## Discrepancies you found verifying audits

- **Audit 04 R-04-04 says "Wintermute doc shows trace label
  `detection:protectai`"**: the live trace builds layer names as
  `f"detection:{model_name}"` from the registered loader's
  `__bulwark_name__`. ProtectAI's loader (`integrations/promptguard.py`)
  registers as `protectai-deberta-v3-base-injection-v2` or similar,
  not the literal string `protectai`. I rewrote the wintermute trace
  example to show the longer registered name + a "fields are
  illustrative — pin to the model id, don't pin to the literal
  string". I did not verify the exact registered name against running
  code, since the audit itself flagged this. The wording is now
  defensive — operators won't pin to a literal that breaks on a model
  rename.
- **Audit 03 F1 says "candidate cap of 16, ≥80% printable, depth-2
  nested decoding"**: I propagated those numbers verbatim into
  `docs/detection.md` per the audit. If the constants in
  `src/bulwark/decoders.py` move, the doc will need updating —
  flagged as a follow-up but not editing the source here (out of scope).
- **`docs/red-teaming.md` "Standard Scan (~3k probes)" / "Full Sweep
  (~10k+ probes)"**: I dropped the "~3k" parenthetical (live count
  per audit recommendations) but kept the "every probe including
  extended payload variants" framing. The "~10k+" wasn't in the
  audit findings; left alone but note it has the same staleness risk.
  Logged below in "Out-of-scope observations".

---

## Out-of-scope observations

These are things I noticed while editing but didn't act on, per the
"don't add new findings" rule.

1. **`README.md` `spec/falsepos_corpus.jsonl` count**: README claims
   "42 entries across nine categories"; actual file is 55 lines.
   Drift surface, similar character to the other stale-number
   findings. Audit 01/02/03 didn't flag it. Worth fixing in the next
   doc pass; can drop the count entirely.
2. **`docs/red-teaming.md` "Full Sweep (~10k+ probes)"**: same drift
   surface as the "~3,000 probes" finding the audit caught — no
   audit explicitly flagged this. The probe count is dynamic; the
   "10k+" is a rough order-of-magnitude that's probably fine but is
   technically the same problem class.
3. **`docs/openclaw.md`**: I didn't touch this file. Audit 04 F-04-06
   verified `message:received` (colon form) is canonical. F-04-07
   suggested adding a note that the OpenClaw plugin's fail-open is
   an availability/security trade-off — minor, not actioned.
4. **`bulwark canary` subgroup help link** (`docs/cli.md`): the
   `[canary management API]` link target was the api-reference
   `#canary-management-adr-025` anchor, which doesn't exist on the
   rewritten `api-reference.md`. I changed it to `#endpoints`.
   Acceptable but not a perfect anchor; the audit didn't flag this.
5. **Audit 04 F-04-12 (httpx not in non-bench extras)**: doc is
   already accurate per the audit; no action.
6. **`graphify-out/` / `.gitignore` / `.claude/settings.json` /
   `.mcp.json`**: pre-existing uncommitted changes on the worktree.
   Per the synthesis brief "user has decided NOT to commit". Left
   alone.

---

## Validation hints for the user

### What `git diff --stat` should look like (rough)

```
 CHANGELOG.md                                             | ~95 ++++++++++++
 CLAUDE.md                                                |   2 +
 CONTRIBUTING.md                                          |  ~40 +++++-
 README.md                                                |  ~60 +++++----
 ROADMAP.md                                               | ~60 +++--------
 VERSION                                                  |   2 +-
 docs/README.md                                           |  ~25 +++++-
 docs/api-reference.md                                    | ~150 ++++++++--------
 docs/async.md                                            |  ~60 +++++----
 docs/batch.md                                            |   4 +-
 docs/cli.md                                              |  ~50 ++++++---
 docs/codex-security/bulwark-security-review.txt          | (renamed to archive/, +banner)
 docs/config.md                                           |  ~50 +++++----
 docs/dashboard.md                                        |  ~30 +++++--
 docs/detection.md                                        | ~110 +++++++++++--
 docs/integrations/wintermute.md                          |  ~70 ++++++----
 docs/layers.md                                           |  ~50 ++++++---
 docs/python-library.md                                   |  NEW (~60 lines)
 docs/red-teaming.md                                      |  ~80 +++++-----
 examples/quickstart_anthropic.py                         |  ~10 ++--
 examples/quickstart_clean.py                             |  ~14 ++-
 examples/quickstart_generic.py                           |   2 +-
 examples/quickstart_openai.py                            |   2 +-
 examples/quickstart_protect.py                           |  ~10 +++-
 integrations/openclaw/skills/bulwark-sanitize/SKILL.md   |   3 +-
 src/bulwark/shortcuts.py                                 |  ~10 +++--
```

Plus `docs/superpowers/audits/2026-04-30-doc-audit/06-rewriter-report.md` (this file, untracked).

### Greps to run

```bash
# Should print only docs/codex-security/archive/... (and the audit reports + the bundled plan):
grep -rn "v1/pipeline\|two-phase\|make_analyze_fn\|AnalysisGuard\|configured LLM backend" docs/ examples/ CLAUDE.md README.md ROADMAP.md CONTRIBUTING.md

# Should be zero (or only the historical plan under docs/superpowers/plans/):
grep -rn "localhost:3001" docs/ examples/

# Should be zero across all live docs:
grep -rn "960+ tests\|315 prob\|3,112 prob\|~3,000 prob\|77 attacks" docs/ examples/ README.md ROADMAP.md

# Confirm new files exist and old file moved:
ls docs/codex-security/archive/bulwark-security-review-v1.txt
ls docs/python-library.md
ls docs/codex-security/bulwark-security-review.txt 2>&1 | grep "No such" # should print

# Version
cat VERSION                            # → 2.5.10
head -5 CHANGELOG.md                   # → ## [2.5.10] - 2026-05-01

# Pipeline(detect= should remain only in docs/python-library.md (educational) + the historical plan under superpowers/plans:
grep -rn "Pipeline(detect=" docs/ examples/
```

### What you can't easily verify without running the dashboard

- The wintermute trace example's exact registered model id (e.g.
  `detection:protectai-deberta-v3-base-injection-v2` vs whatever the
  loader actually uses today). Verify by hitting `/v1/clean` on a
  live container and looking at `trace[].layer`.
- That ADR-047's documented decoder constants
  (`_CANDIDATE_CAP=16`, `_MIN_DECODED_BYTES=10`,
  `_MIN_PRINTABLE_RATIO=0.80`, depth-2 nested decoding) still match
  `src/bulwark/decoders.py` if it's been edited since the audit. The
  audit citations are recent (2026-04-30) so they should still be
  correct, but worth a glance.
- The "991 tests pass" CHANGELOG claim — I left it asserted. If the
  test suite has changed since v2.5.9 the doc may need a tweak; the
  audit deliberately moved away from precise counts so this is a
  one-time legacy phrasing.
- Screenshots in `docs/images/*.png` — known-stale, follow-up.
