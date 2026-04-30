# Audit 01: Root onboarding & project metadata

**Auditor:** subagent 1/5
**Files audited:** README.md, ROADMAP.md, CONTRIBUTING.md, CLAUDE.md, CHANGELOG.md (latest 3 entries: v2.5.7, v2.5.8, v2.5.9)
**Date:** 2026-04-30

## Findings

### CRITICAL

#### F-01-001: README claims DeBERTa "downloads on the first `/v1/clean` request" — actually loads at startup
- **File:** `README.md:38`
- **Category:** STALE
- **Claim:** "The DeBERTa classifier downloads on the first `/v1/clean` request (~180 MB)."
- **Reality:** `src/bulwark/dashboard/app.py:519-544` (`_auto_load_detection_models`) — models load at FastAPI startup via the `@app.on_event("startup")` hook for any integration where `int_cfg.enabled` is True (default config has both `protectai` and `promptguard` enabled). First request behaviour: detector is already loaded; user sees no extra latency. Cold-start latency is paid on container boot, not on first request.
- **Recommended fix:** Replace with "DeBERTa loads at container startup (the first boot downloads ~180 MB of weights and caches them)." Or move the timing claim into the Detectors table where it already says "Loads on first request" — that row is also wrong.

#### F-01-002: Detectors table claims DeBERTa "Loads on first request"
- **File:** `README.md:134`
- **Category:** STALE
- **Claim:** "`protectai/deberta-v3-base-prompt-injection-v2`. Loads on first request."
- **Reality:** Same as F-01-001 — `app.py:519` registers a startup hook that auto-loads any integration whose config has `enabled=True`, before any HTTP traffic arrives.
- **Recommended fix:** Change to "Loads at container startup." Possibly add a line about how a fresh image with no cache pays the ~180 MB download once on first boot.

### IMPORTANT

#### F-01-003: ROADMAP says ADR-047 is "planned" — it's been shipped for ~24h
- **File:** `ROADMAP.md:60-62`
- **Category:** STALE
- **Claim:** "**Content fingerprinting pre-pass** — strip benign filler before classification to mitigate the long-range dilution gap documented by ADR-046 (planned ADR-047)."
- **Reality:** `spec/decisions/047-encoding-decoders.md` exists and shipped in v2.5.4 (CHANGELOG:68-79), and ADR-048 + ADR-049 have shipped on top of it. ADR-047 was reused for *encoding decoders* (base64 / ROT13), not content fingerprinting — the original placeholder was repurposed. The "Content fingerprinting" follow-up to ADR-046's long-range dilution gap is now ADR-orphaned: there's no shipped or planned ADR that covers it.
- **Recommended fix:** Remove the "(planned ADR-047)" parenthetical; either rename the bullet to point at a new placeholder ADR number (e.g., 050) or drop the ADR pointer entirely until the design firms up.

#### F-01-004: ROADMAP says Phase H is "deferred" — it shipped in v2.5.4
- **File:** `ROADMAP.md:55-59`
- **Category:** STALE / WRONG
- **Claim:** "**Semantic encoding detection (Phase H, deferred)** — base64 / ROT13 / punycode decoding pre-pass at `/v1/clean`. Deliberately punted from the Codex efficacy hardening series pending its own brainstorming session — see Phase H in [`docs/superpowers/plans/2026-04-29-codex-efficacy-hardening.md`](docs/superpowers/plans/2026-04-29-codex-efficacy-hardening.md)."
- **Reality:** v2.5.4 (CHANGELOG:68) shipped exactly this: "**`/v1/clean` now decodes base64 and ROT13 substrings as detection variants.** New `bulwark.decoders` module..." with new ADR-047. v2.5.7 shipped Phase H follow-ups (H.1 + H.2 — see CHANGELOG:32, ADR-048). Punycode is the only sub-item of the original Phase H still un-shipped.
- **Recommended fix:** Move base64 + ROT13 to "Shipped highlights" with ADR-047 reference; demote the bullet to "Phase H follow-ups: punycode decoding, additional encodings" or strike it.

#### F-01-005: ROADMAP "Current state" lists test count as "960+" — actual is 991
- **File:** `ROADMAP.md:6-12`
- **Category:** STALE
- **Claim:** "Detection-only architecture (ADR-031). Five-stage pipeline... 960+ tests."
- **Reality:** CHANGELOG.md:7,12 says "991 tests pass" as of v2.5.9. The "960+" comes from v2.5.2 era and was bumped via `+17` (v2.5.4) + `+1` (v2.5.5) + `+13` (v2.5.7) etc.
- **Recommended fix:** "990+ tests" or just "≈1000 tests" — the absolute number bumps every release and is doc-rot bait. Better to point at `tests/` and say "comprehensive test suite enforced by `tests/test_spec_compliance.py`".

#### F-01-006: README "Project structure" table also says "960+ tests"
- **File:** `README.md:243`
- **Category:** STALE
- **Claim:** "`tests/` — 960+ tests including spec-compliance enforcement."
- **Reality:** Same as F-01-005 — actual is 991 per CHANGELOG.md:7,12.
- **Recommended fix:** Same fix as F-01-005 — drop the precise number or replace with "comprehensive test suite".

#### F-01-007: CONTRIBUTING ADR list is missing the four most recent ADRs
- **File:** `CONTRIBUTING.md:75-92`
- **Category:** STALE
- **Claim:** Architecture section lists ADR-001, 008, 009, 029, 031, 032, 033, 040, 041, 042, 044, 045, 046 as "the main ones for v2".
- **Reality:** ADR-038 (mandatory detector visibility), ADR-039 (Codex PR-B hardening), ADR-043 (spec-drift cleanup), ADR-047 (encoding decoders), ADR-048 (detector chain helper), ADR-049 (native arm64 CI runner) all exist in `spec/decisions/` and are foundational v2.x decisions. ADR-038 in particular is referenced from Dockerfile/smoke test as load-bearing for `/healthz` semantics; ADR-047 + ADR-048 govern current `/v1/clean` chain semantics.
- **Recommended fix:** Add ADR-038, ADR-047, ADR-048. Optional: ADR-049 (CI infra, not really architectural). ADR-039 + ADR-043 are housekeeping ADRs and can be skipped from the curated list.

#### F-01-008: README quickstart curl example output may not match actual API
- **File:** `README.md:29`
- **Category:** WRONG (subtle — pedantic but a copy-paste check would fail)
- **Claim:** Comment shows `→ 422  {"blocked": true, "block_reason": "Detector protectai: Prompt injection detected (1.000)"}`
- **Reality:** `src/bulwark/dashboard/api_v1.py:339-345` produces a 422 body that contains `blocked`, `block_reason`, **plus** `blocked_at`, `decoded_variants`, `blocked_at_variant`, `trace`, etc. The two fields shown are correct but the response is much richer; a reader copy-pasting curl will see ~10 keys, not 2. Block reason format string `f"Detector {model_name}: {e}"` matches.
- **Recommended fix:** Add `, ...` inside the example to signal truncation: `{"blocked": true, "block_reason": "...", ...}`. Or expand to show the realistic shape briefly — a reader who follows the example shouldn't be surprised by extra fields when they actually run it.

#### F-01-009: CLAUDE.md never mentions ADR-047 or ADR-048 (current chain semantics)
- **File:** `CLAUDE.md:33-38`
- **Category:** MISSING
- **Claim:** ADR pointer block lists 029, 040, 041, 042, 044, 046 with one-line summaries — purposeful so future agentic edits "don't re-derive the rules".
- **Reality:** ADR-047 added per-variant decode-rescan to `/v1/clean` (every detector runs over every variant) and ADR-048 made `bulwark.detector_chain.run_detector_chain` the single source of truth for chain execution. Without these, an agent editing chain logic will re-derive (and likely re-break) the parity contract `G-PIPELINE-PARITY-001` + `G-CLEAN-DETECTOR-CHAIN-PARITY-001`.
- **Recommended fix:** Add two lines after the ADR-046 bullet:
  - `ADR-047`: `/v1/clean` decodes base64 + ROT13 substrings as detection variants; trust boundary still wraps the original cleaned text. `decode_base64` is opt-in.
  - `ADR-048`: `bulwark.detector_chain.run_detector_chain` is the single source of truth for chain execution shared by `Pipeline.run()` and `api_v1.api_clean`. Don't fork.

#### F-01-010: CLAUDE.md uses an em-dash that would have been the place to flag ADR-049 — also missing
- **File:** `CLAUDE.md:64-66`
- **Category:** MISSING (minor, but: this is supposed to be the spec authority for agents)
- **Claim:** Docker run example with `-p 3000:3000`. No mention anywhere of CI/build infrastructure.
- **Reality:** ADR-049 (native arm64 CI runner) just shipped this session and dropped tag-push wall-clock from ~85 min to ~15 min. CLAUDE.md doesn't claim a build time so this isn't STALE — it's just a missed integration point. Minor, but worth noting since the prompt asked us to look for ADR-049 references.
- **Recommended fix:** Optional — add a one-liner under a new "CI" subsection only if agents are expected to touch the workflow file. If not, skip.

### MINOR

#### F-01-011: README dropdown link `[Docs](docs/)` doesn't anchor to a doc index
- **File:** `README.md:12`
- **Category:** IA-GAP
- **Claim:** Top-of-doc nav row ends with `[Docs](docs/)`.
- **Reality:** `docs/README.md` exists and is the implied target; the link works because GitHub auto-resolves `docs/` to `docs/README.md`. This is fine but bare-directory link is GitHub-specific — won't render usefully on PyPI.
- **Recommended fix:** Make it `[Docs](docs/README.md)` to be portable.

#### F-01-012: README's `bulwark_bench --tier standard` example doesn't set `--harness`
- **File:** `README.md:155-162`
- **Category:** WRONG (low severity — the default is `standard` so this works, but)
- **Claim:** `python3 -m bulwark_bench --configs ... --tier standard`
- **Reality:** `src/bulwark_bench/__main__.py:36` — `--tier` defaults to `"standard"`, so passing it is redundant. The example also omits `--url` which defaults to `http://localhost:3000`; if the reader followed the README's own quickstart and ran `-p 3001:3000`, `bulwark_bench` will silently try `:3000` and fail.
- **Recommended fix:** Either add `--url http://localhost:3001` to the bench example, or change the quickstart `docker run` to `-p 3000:3000` so the ports stay consistent across the README.

#### F-01-013: `examples/quickstart_protect.py` referenced indirectly but `protect()` was removed in v2
- **File:** README.md doesn't reference it directly, but `examples/quickstart_protect.py` exists in the tree (per `ls`)
- **Category:** OBSOLETE
- **Claim:** README only references `examples/quickstart_generic.py` (line 228); the `protect.py` example is orphaned in the tree.
- **Reality:** ADR-031 removed the v1 `protect()` two-phase API. CHANGELOG history confirms `protect()` is gone. `examples/quickstart_protect.py` is stale.
- **Recommended fix:** Out of scope for this audit (file deletion), but flag for a tree-clean PR.

#### F-01-014: `shortcuts.py` docstring still mentions "two-phase execution"
- **File:** `src/bulwark/shortcuts.py:11-12,68-69`
- **Category:** OBSOLETE (this is library code, not a doc, but it ships as `import bulwark`'s docstring — surfaces in users' IDE tooltips)
- **Claim:** "**This provides input sanitization and output checking, not full architectural defense.** For two-phase execution, canary tokens, and batch isolation, use Pipeline directly."
- **Reality:** Two-phase execution was removed in v2 (ADR-031). `Pipeline` no longer offers it.
- **Recommended fix:** Out-of-strict-scope for an audit of root .md files, but worth noting because `bulwark.clean.__doc__` is the entry point a user reaches for in their REPL. Drop "two-phase execution" from both occurrences.

#### F-01-015: ROADMAP "Future" section still lists "Transparent proxy mode" with no timeline or context
- **File:** `ROADMAP.md:67-75`
- **Category:** RETIREMENT (candidate)
- **Claim:** Three bullets in "Future": Transparent proxy mode, CaMeL-style capability tracking, Community attack catalog growth, OpenClaw TypeScript plugin.
- **Reality:** None of these have shipped, no ADR has been started for any, no commit history references them. They're aspirational and have been stable text since the v2.5.3 ROADMAP rewrite. Whether they should stay is a roadmap-policy question, not an accuracy question.
- **Recommended fix:** Either prune or split into "Exploring" vs "Vague aspirations" — the four bullets currently read as commitments and may not be.

#### F-01-016: README links to images that exist (verified) — no broken-link finding here
- **File:** `README.md:79,87,96,107,115,124`
- **Category:** (no finding)
- **Reality:** All six PNG references resolve to files in `docs/images/` (banner.svg, shield.png, configure.png, configure-judge.png, leak-detection.png, test.png, events.png). No action.

#### F-01-017: CONTRIBUTING contract example version is `0.5.0`
- **File:** `CONTRIBUTING.md:33`
- **Category:** MINOR (cosmetic; example version is fictional anyway)
- **Claim:** Example contract YAML uses `version: "0.5.0"`.
- **Reality:** Project is on 2.5.9. Example doesn't have to match — it's pedagogical — but if a reader copies it as a starting point, they'll wind up with version drift on day one.
- **Recommended fix:** Either drop the `version:` field from the example, or use a placeholder like `version: "<your-version>"`.

#### F-01-018: CHANGELOG v2.5.9 entry buries the headline in a wall of text
- **File:** `CHANGELOG.md:7`
- **Category:** MINOR (style, not accuracy)
- **Claim:** v2.5.9 entry is one paragraph, ~700 words, with the "60-90 → ~15 min" punchline mid-paragraph.
- **Reality:** Reads correctly but the most actionable claim ("tag-push wall time drops from ~85 min to ~15 min") isn't easy to find.
- **Recommended fix:** Optional: lead with a bolded TL;DR ("**Tag-push wall time drops from ~85 min → ~15 min.**") then the explanation. Style issue only.

#### F-01-019: CLAUDE.md graphify section says to read `graphify-out/GRAPH_REPORT.md` — but this is dev-only
- **File:** `CLAUDE.md:85-93`
- **Category:** OVERLAP (with auditor's general instructions vs project doc separation)
- **Claim:** "This project has a graphify knowledge graph at graphify-out/. Rules: Before answering architecture or codebase questions, read graphify-out/GRAPH_REPORT.md..."
- **Reality:** `graphify-out/` exists locally with the expected files. This is per-developer state — the prompt says graphify is "not yet attempted" per `project_graphify_trial_plan` memory note. Section was likely auto-added by the graphify install.
- **Recommended fix:** Confirm with user whether this section is intentional. If `graphify-out/` is gitignored, the CLAUDE.md instruction telling agents to read it has zero effect for non-local agents (CI, fresh checkouts) and adds noise. Either commit `graphify-out/` (probably wrong — it's regenerable) or drop the section, or guard it behind "if `graphify-out/` exists".

## Restructural recommendations

The user picked Q2=ii (restructural). Here's how the root files relate and where I'd reshape:

### R-01-001: ROADMAP is mostly-redundant with CHANGELOG and CLAUDE.md ADR list
- **Overlap pair:** ROADMAP.md "Shipped highlights" vs CHANGELOG.md latest entries vs CLAUDE.md ADR pointer block.
- **Same content, three places, all drifting at different rates.** ROADMAP is the worst-drifted of the three (still says Phase H is deferred when it shipped). The "Shipped highlights" section is the most useful piece of ROADMAP for new readers, but the CHANGELOG has the same information with timestamps and CHANGELOG is the source of truth.
- **Proposal:** Cut ROADMAP "Shipped highlights" to a single sentence pointing at CHANGELOG: "Shipped: see CHANGELOG.md." Keep ROADMAP focused on what's *next* and *future*. That'd halve the file's size and remove its biggest drift surface.

### R-01-002: README "Detectors" + "Architecture" + ROADMAP "Current state" duplicate the pipeline diagram
- **Overlap trio:** README.md:42-68 (Architecture diagram + prose), README.md:131-141 (Detectors table), ROADMAP.md:6-13 (Current state pipeline list).
- **Proposal:** Cut ROADMAP's pipeline recap entirely — it's a one-line link "See README §Architecture." Don't rewrite the architecture in three voices.

### R-01-003: Library use section in README is a fast docs.md that's growing
- **File:** README.md:198-228
- README has 30 lines of Python library examples. As `Pipeline.from_config()` matures and more guarantees attach, this will keep growing. Currently inlined, it's competing for README real estate with the Quickstart curl example.
- **Proposal:** Move the library section to `docs/python-library.md` (or expand `docs/integrations/`), keep a 5-line synopsis in README + link. Same pattern README already uses for Configuration → docs/config.md.

### R-01-004: CLAUDE.md ADR pointer block is doing the work the spec/decisions/ index *should* do
- **File:** CLAUDE.md:33-38
- The ADR one-liners are gold for context handoff but they're scoped to "rules that bind future code edits", which is a narrower set than "everything in spec/decisions/". As the project grows, this list will bit-rot (already missing ADR-047/048 — see F-01-009).
- **Proposal:** Either generate the ADR-pointer block from a header line on each ADR file (machine-extractable, no drift), or move it to `spec/decisions/INDEX.md` and have CLAUDE.md link to it.

### R-01-005: IA gap — there's no "release notes" entry point for end-users
- **Pattern:** A user installing v2.5.9 from PyPI lands on the README. To know what's new, they need to find CHANGELOG.md (linked from README:257). The CHANGELOG is the right artefact but it's *operator-facing*, with internal phase labels ("Phase H.1 + H.2"), ADR cross-refs, and parity guarantees — opaque to a fresh user.
- **Proposal:** Either softly upmarket the CHANGELOG voice for end-users (one sentence per release in plain English at the top of each entry, then the operator detail below), or add a `WHATS-NEW.md` for the Twitter-thread / blog-post audience. Less critical than the staleness fixes — log it as "consider".

### R-01-006: CONTRIBUTING is half spec process, half dev-setup-by-omission
- **File:** CONTRIBUTING.md
- The doc is 93 lines, of which ~80 are spec-driven development process and ~5 are dev setup ("Run the full test suite"). It doesn't cover: how to set up a dev env, where to find pre-commit hooks, branch naming, how to bump VERSION, what to do about CHANGELOG entries (CLAUDE.md *does* cover the version bump rule but CONTRIBUTING doesn't link to it).
- **Proposal:** Add a "Dev setup" section to CONTRIBUTING that pulls the relevant rules from CLAUDE.md (test command, version bump, CHANGELOG update). CLAUDE.md is for AI agents; CONTRIBUTING is for humans; the rules overlap and duplicating them keeps both up to date.

## Summary stats
- Critical: 2
- Important: 8
- Minor: 9
- Restructural recommendations: 6
