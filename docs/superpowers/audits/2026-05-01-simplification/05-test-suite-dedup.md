# Phase 3 Analysis 05: Test suite dedup

Scope: 49 `tests/test_*.py` files, ~14k LOC, 991 collected tests (per project README claim — close enough; pytest collection numbers vary slightly with marker config). Read-only. Goal: find redundancy/overlap, frozen-snapshot tests, slow-lane candidates, dead-feature tests.

Method:
- Inventoried each file's target module via imports + class/test names.
- Cross-checked guarantee-ID overlap between unit tests and `test_spec_compliance.py`.
- Verified each candidate-for-removal against actual code paths it covers.

Important meta-finding before proceeding: `test_spec_compliance.py::test_every_guarantee_has_test` only checks that the guarantee-ID *string* appears in any `tests/test_*.py` file. It is a citation check, not a behavioural check. **Therefore, the spec-compliance meta-test is NOT a substitute for unit tests.** A unit test asserting a `G-...` behaviour cannot be removed just because the meta-test "covers" it; the meta-test would still pass with no real assertion. This neutralises the "spec-compliance vs unit duplication" axis the brief asked about — the only redundancy we can act on is unit-vs-unit.

## Inventory

| File | Target module(s) | Tests | LOC | Slow? |
|------|------------------|-------|-----|-------|
| `test_attacks.py` | `bulwark.attacks` (suite loader) | 35 | 279 | no |
| `test_auth.py` | `bulwark.dashboard.app` (auth middleware) | 41 | 477 | no |
| `test_bulwark_bench.py` | `bulwark_bench.{configs,report,runner}` | 19 | 279 | no |
| `test_bulwark_falsepos.py` | `bulwark_falsepos.{corpus,report,runner}` | 18 | 326 | no |
| `test_canary.py` | `bulwark.canary` (CanarySystem) | 54 | 495 | no |
| `test_canary_shapes.py` | `bulwark.canary_shapes` | 9 | 68 | no |
| `test_clean_decode.py` | `/v1/clean` decode-rescan integration (HTTP) | 7 | 362 | no |
| `test_cli.py` | `bulwark.cli` (Click commands) | 34 | 429 | no |
| `test_codex_prb_hardening.py` | sanitizer encoding-decode + `dashboard.url_validator` + redteam snapshot + clean-route trace + `promptguard` chain trace | 27 | 450 | no |
| `test_content_byte_limit.py` | `dashboard.models` (Pydantic byte cap) | 5 | 182 | no |
| `test_contracts.py` | `bulwark.shortcuts.{clean,guard}` | 25 | 189 | no |
| `test_dashboard_api.py` | `bulwark.dashboard.db.EventDB.timeseries` | 9 | 68 | no |
| `test_dashboard_layers.py` | `dashboard.app` layer-toggle config | 7 | 134 | no |
| `test_dashboard_ui_events.py` | `static/src/page-events.jsx` (via Node) | 19 | 201 | skips if no node |
| `test_dashboard_ui_shell.py` | `static/src/shell.jsx`, `data.jsx`, `index.html` | 11 | 179 | skips if no node |
| `test_dashboard_ui_shield.py` | `static/src/page-shield.jsx` | 12 | 168 | skips if no node |
| `test_dashboard_ui_test_page.py` | `static/src/page-test.jsx`, `data.jsx` | 21 | 233 | skips if no node |
| `test_decoders.py` | `bulwark.decoders.decode_rescan_variants` | 13 | 210 | no |
| `test_detector_chain.py` | `bulwark.detector_chain.run_detector_chain` | 11 | 291 | no |
| `test_detector_chunking.py` | `bulwark.integrations.promptguard` chunker | 9 | 144 | no |
| `test_detector_required.py` | `dashboard.app` `/healthz` detector state | 10 | 190 | no |
| `test_docker_hardening.py` | `Dockerfile` static checks | 4 | 37 | no |
| `test_e2e_real_detectors.py` | full pipeline w/ real DeBERTa weights | 3 | 343 | **yes (`@e2e_slow`)** |
| `test_env_truthy.py` | `dashboard.config.env_truthy` | 3 | 35 | no |
| `test_events.py` | `bulwark.events.CollectorEmitter` × all layers | 16 | 162 | no |
| `test_fail_closed_no_detectors.py` | `/v1/clean` 503 + opt-in (ADR-040) | 8 | 166 | no |
| `test_falsepos_error_classification.py` | `bulwark_falsepos.runner` error tagging | 8 | 168 | no |
| `test_garak_integration.py` | `bulwark.integrations.garak` + CLI flags | 33 | 584 | no |
| `test_http_api.py` | `dashboard.app` HTTP endpoints (broad) | 90 | 1167 | no |
| `test_isolator.py` | `bulwark.isolator.MapReduceIsolator` | 49 | 797 | no |
| `test_llm_judge.py` | `bulwark.detectors.llm_judge` | 32 | 404 | no |
| `test_openclaw_integration.py` | `integrations/openclaw/*` file-existence | 21 | 161 | no |
| `test_pipeline_parity.py` | `bulwark.pipeline.Pipeline.from_config` (lib↔dashboard) | 7 | 379 | no |
| `test_presets.py` | `bulwark.presets` loader + `/api/presets` | 20 | 238 | no |
| `test_protect_anthropic.py` | `bulwark.integrations.anthropic.protect` (SDK proxy) | 14 | 248 | no |
| `test_redteam_scoring.py` | `bulwark.integrations.redteam` + `/api/redteam/retest` | 16 | 220 | no |
| `test_sanitizer.py` | `bulwark.sanitizer.Sanitizer` | 91 | 698 | no |
| `test_security_audit.py` | ReDoS + scheme-only SSRF + dashboard info-leak | 32 | 318 | no |
| `test_shortcuts.py` | `bulwark.shortcuts.{clean,guard}` | 24 | 155 | no |
| `test_spec_compliance.py` | OpenAPI/contract drift meta-tests | 12 | 428 | no |
| `test_split_evasion.py` | attack generator + chunk-overlap behaviour (incl. `e2e_slow` long-range) | 13 | 397 | **partial (`e2e_slow` class)** |
| `test_trust_boundary.py` | `bulwark.trust_boundary.TrustBoundary` | 35 | 301 | no |
| `test_v2_coverage.py` | "anchor" file pinning v2 guarantee IDs | 20 | 330 | no |
| `test_validator.py` | `bulwark.validator.PipelineValidator` + CLI `bulwark test` | 29 | 439 | no |

`tests/attacks/` directory is empty — only an `__init__.py` (0 bytes). `tests/benchmark.py` is a standalone perf script, NOT a pytest module — and its first two imports (`bulwark.executor`, `from bulwark.pipeline import Pipeline` plus the deleted `bulwark.executor.AnalysisGuard`) reference modules that no longer exist.

## Overlap candidates

### Pair 1 (HIGH overlap — strong merge candidate): `test_contracts.py` ↔ `test_shortcuts.py`

Both target the exact same module: `bulwark.shortcuts.{clean, guard}`. The guarantee-ID coverage is overlapping near-1:1.

| Guarantee | `test_contracts.py` | `test_shortcuts.py` |
|-----------|---------------------|---------------------|
| G-CLEAN-001 returns string | yes | yes |
| G-CLEAN-002 zero-width strip | yes | yes |
| G-CLEAN-003 HTML script strip | yes | yes |
| G-CLEAN-004 trust-boundary wrap | yes | yes |
| G-CLEAN-005 source in tag | yes | yes |
| G-CLEAN-006 SECURITY text | yes | yes |
| G-CLEAN-007/008 truncation | yes | yes |
| G-CLEAN-009/010 markdown/delimiter | yes | yes |
| G-CLEAN-011 TypeError | yes | yes |
| G-CLEAN-012 ValueError invalid format | yes | yes |
| G-CLEAN-013 empty string | yes | yes |
| G-GUARD-001..005 | yes | yes |

Side-by-side bodies are practically identical (same fixtures, same assertions, sometimes verbatim docstrings). Unique to `test_shortcuts.py`: top-level-import smoke (`bulwark.clean`, `bulwark.guard`, `bulwark.CanaryLeakError`), a tool-call pattern test, a label-in-tag test. Unique to `test_contracts.py`: 4 `NG-CLEAN-*` and 3 `NG-GUARD-*` non-guarantee assertions.

**Proposal:** Keep `test_contracts.py` (the contract-yaml-aligned file). Move the 3 unique top-level-import smoke tests + the label-in-tag test from `test_shortcuts.py` into `test_contracts.py` (as `TestTopLevelImports` class), then delete `test_shortcuts.py`. Net: -~120 LOC, -~15 tests, **no coverage loss**.

### Pair 2 (LOWER overlap — keep separate): `test_security_audit.py` ↔ `test_codex_prb_hardening.py`

Both touch SSRF and sanitizer/regex hardening, but they hit different concerns:
- `test_security_audit.py::TestWebhookEmitterSSRF` only asserts **scheme** rejection (`file://`, `ftp://`, etc.) on `WebhookEmitter`.
- `test_codex_prb_hardening.py::TestHostnameSsrf` asserts **hostname-resolution** rejection on `dashboard.url_validator.validate_external_url` (loopback, link-local, metadata, private IPs after DNS).

`test_security_audit.py` covers ReDoS (`TestCanaryReDoS`, `TestAnalysisGuardReDoS`) and dashboard info-leak (`TestDashboardInfoLeakage`, `TestDashboardImports`) which `test_codex_prb_hardening.py` does not. `test_codex_prb_hardening.py` covers encoding-decode (`G-SANITIZER-018`), body-cap, redteam-status snapshot deep-copy, clean-route docstring, and trace observability — all unique. **Verdict: do NOT merge. Both pull weight.**

### Pair 3 (NO overlap — distinct layers): `test_dashboard_api.py` vs `test_http_api.py` vs `test_dashboard_layers.py`

- `test_dashboard_api.py` is a unit test of `EventDB.timeseries()` — bucketing math, no FastAPI.
- `test_http_api.py` is HTTP-level coverage of public endpoints — only asserts that events get inserted, never that they bucket correctly.
- `test_dashboard_layers.py` is config-layer-toggle behaviour with FastAPI client; doesn't touch EventDB.

Different layers of the stack. **Keep all three.**

### Pair 4 (NO overlap): `test_attacks.py` vs `test_redteam_scoring.py`

- `test_attacks.py` exercises the `AttackSuite` loader (categories, targets, severity, dataclass shape).
- `test_redteam_scoring.py` exercises `ProductionRedTeam` verdict classification (defended/hijacked/format-failure) and the `/api/redteam/retest` endpoint.

No shared module. **Keep both.**

### Pair 5 (NO overlap — three layers of decode): `test_clean_decode.py` ↔ `test_decoders.py` ↔ `test_pipeline_parity.py`

- `test_decoders.py` is a unit test of `bulwark.decoders.decode_rescan_variants` — pure-fn behaviour (rot13, base64 quality gate, candidate cap, replacement-char filter).
- `test_detector_chain.py` (separate file) wires variants → detector chain.
- `test_clean_decode.py` is the HTTP-level integration via `/v1/clean` proving the full pipeline matches dashboard behaviour.
- `test_pipeline_parity.py` proves `Pipeline.from_config` loads the same chain the dashboard does (ADR-044).

Each is one layer. **Keep all four.**

## Spec-compliance redundancy

(See meta-finding above.) `test_spec_compliance.py::test_every_guarantee_has_test` only checks that the ID *string appears in tests/* — not that the test verifies the behaviour. Removing the unit test would not fail the meta-test as long as the ID literal lived somewhere; conversely, keeping the unit test is the only way to actually exercise the guarantee.

So the only "spec-compliance redundancy" actionable in this analysis is the citation file `test_v2_coverage.py`:

- `test_v2_coverage.py` is explicitly described in its own docstring as: *"rather than spread one-line assertions across every test module, this file pins guarantee IDs to concrete tests or marks IDs as covered elsewhere. The spec-compliance meta-test only checks that each ID appears somewhere in tests/; these are the docstring anchors."*
- About 6–8 of its 20 tests are real assertions (webhook contract: SSRF, scheme, env override, no-probing, fire-and-forget). The other ~12 are docstring anchors that exist solely so `_find_id_in_tests(gid)` returns true for IDs that are otherwise covered by behaviour-level tests under different names.
- **Risk of removal: HIGH** — removing the file would make `test_every_guarantee_has_test` fail for many IDs (G-INTEGRATIONS-001/002, NG-INTEGRATIONS-001, G-CANARY-012, NG-HTTP-CLEAN-003, G-HTTP-CONFIG-002/004, G-HTTP-GUARD-010, G-ENV-006/009/010/011/014/015, NG-ENV-001, NG-ENV-LLM-REMOVED, G-WEBHOOK-001..007, NG-WEBHOOK-001..005, etc.).
- **Better fix (out of scope here, see Out-of-scope observations):** improve the meta-test to require a stronger anchor than "string match anywhere in tests/" — e.g. require the ID in a docstring of a `def test_*`. Then `test_v2_coverage.py` could be slimmed to only the real assertions and the docstring-only anchors moved into the actual behavioural tests under those IDs.

## Frozen-snapshot tests

| File | Line | Assertion | Drift risk |
|------|------|-----------|------------|
| `test_attacks.py:22` | `assert len(suite.attacks) >= 75` | LOW (`>=` not `==`); but the docstring says "at least 75 attacks" — drifts when corpus shrinks during dedup. F-07 in the doc audit flagged the doc-side equivalent. |
| `test_attacks.py:279` | `assert len(AttackCategory) == 11` | MEDIUM — exact match. If a category is removed/added, this breaks. Easier to assert each enum value exists by name. |
| `test_bulwark_falsepos.py:29` | `assert len(corpus) >= 30` | LOW (`>=`). Acceptable. |
| `test_redteam_scoring.py` | `display_never_rounds_up_to_100_when_hijacked` | None — behavioural |
| `test_garak_integration.py:142..397` | `assert len(results) == N` | NONE — these are in-test fixtures, not corpus snapshots |
| `test_canary.py:72,473,482` | `len(found_tokens) == 2`, `len(sent_messages) == 1` | NONE — these are fixture-driven small counts, not corpus snapshots |

Net frozen-snapshot exposure is small. The single one worth tightening is `test_attacks.py::TestAttackCategory::test_category_count` (line 279) — replace with explicit `expected_names = {...}; assert {c.name for c in AttackCategory} == expected_names` so additions/removals trigger an obvious reason rather than a drift number.

## Slow-lane candidates

The slow lane already exists and works correctly:
- `pyproject.toml` sets `addopts = "-m 'not e2e_slow'"`.
- `marker = e2e_slow` is registered.
- `test_e2e_real_detectors.py` (3 tests) and `test_split_evasion.py::TestSplitEvasionLongRange` (2 tests) opt in.
- `tests/conftest.py` contains a 60-line DX banner hook that warns when the e2e file is invoked without the marker (ADR-045 follow-up).

Other potentially slow tests that should consider opting into `e2e_slow`:
- `test_http_api.py::TestRedteamTiers::test_tier_cache_has_ttl` — sleeps to test cache expiry; non-trivial wall time. (See Out-of-scope.)

No other tests perform real network calls. `test_protect_anthropic.py` mocks the Anthropic client. `test_codex_prb_hardening.py::TestHostnameSsrf` patches `socket.getaddrinfo`. Good hygiene overall.

## Tests of removed features

- `tests/benchmark.py` (NOT a pytest module — collected by `python3 tests/benchmark.py` only) imports `bulwark.executor` (line 20) which no longer exists. Standalone perf script, broken at import. **Candidate: delete or fix.**
- `tests/attacks/` directory exists with only an empty `__init__.py`. **Candidate: delete the directory.**
- No active pytest module references `/v1/protect`, `BULWARK_LLM_MODE`, `BULWARK_API_KEY`, `BULWARK_BASE_URL`, `BULWARK_ANALYZE_MODEL`, `BULWARK_EXECUTE_MODEL`, two-phase, or `llm_backend` config in a way that *expects them to work*. References that exist (`test_v2_coverage.py:90,123,319` and `test_spec_compliance.py`) all assert the **absence** of these — i.e., they are negative-coverage tests for ADR-031 deletions. Keep.
- `test_protect_anthropic.py` is alive: `bulwark.integrations.anthropic.protect` is a SDK-side wrapper (127 LOC) — distinct from the deleted `/v1/protect` HTTP endpoint.

## Cuts ranked

| # | Cut | Files | LOC delta | Test count delta | Coverage lost? | Risk |
|---|-----|-------|-----------|------------------|----------------|------|
| 1 | Merge `test_shortcuts.py` into `test_contracts.py`; keep only top-level-import + label-in-tag tests in the merged file | `test_shortcuts.py` (delete after extracting 4 tests), `test_contracts.py` (gains 1 class) | ~ -120 | ~ -15 | NO — same module, same guarantees, kept the unique 4 | LOW |
| 2 | Delete empty `tests/attacks/` directory | `tests/attacks/__init__.py` | -1 file | 0 | NO — empty | NONE |
| 3 | Delete or fix `tests/benchmark.py` (broken — imports removed `bulwark.executor`) | `tests/benchmark.py` | -425 | 0 (not collected by pytest) | NONE — already broken at import | LOW (verify nobody runs it via README/CHANGELOG/Makefile first) |
| 4 | Replace `test_attacks.py::test_category_count` `==11` with name-set assertion | `test_attacks.py` (edit) | ~+5 | 0 | NO — strictly stronger | NONE |
| 5 | Tighten `test_spec_compliance.py::test_every_guarantee_has_test` to require ID in a `def test_*` docstring (allows step 6) | `test_spec_compliance.py` | ~+10 | 0 | NO — meta-test gets stronger | LOW (will surface IDs that are mentioned but not docstring-anchored — those need real anchors, which is the point) |
| 6 | (Depends on 5) Slim `test_v2_coverage.py` — drop ~12 docstring-only anchor functions, move their docstring IDs into real behavioural tests under those IDs | `test_v2_coverage.py`, plus a handful of HTTP/canary/env tests gain G-* docstrings | ~ -100 | ~ -12 | NO — IDs end up anchored in stronger tests | MEDIUM (touches many files; do as one atomic refactor) |
| 7 | Hoist shared `_get_client()` into `tests/conftest.py` as a fixture | 4 files (`test_http_api.py`, `test_auth.py`, `test_dashboard_layers.py`, `test_content_byte_limit.py`) | ~ -20 | 0 | NO — pure DRY | NONE |

**Headline:** ~545 LOC removable + ~27 redundant tests + 1 broken script + 1 empty dir, with zero behaviour coverage lost if cuts 1, 2, 3, 4, and 7 are taken. Cuts 5 + 6 are a more ambitious sequence that strengthens the meta-test and lets `test_v2_coverage.py` shrink — bigger payoff but more invasive.

Top recommendations in priority order:
1. **Cut 1** — pure win, mechanical merge, no risk.
2. **Cut 2 + Cut 3** — dead code, ~426 LOC.
3. **Cut 7** — one-line conftest fixture + 4 import edits.
4. **Cut 4** — single-test hardening.
5. **Cuts 5 + 6 together** — only worth doing as a paired refactor.

Out of scope of this brief: no test should be removed without first running `pytest -q` to confirm the assertion is still passing today (i.e. the test isn't already silently skipped). If a test is skipped on this machine due to FastAPI/Node/optional deps, that's not justification to cut it.

## Out-of-scope observations

1. **Conftest is under-used.** `tests/conftest.py` only provides 2 canary fixtures + a DX banner. Common patterns reimplemented in test files include:
   - `_get_client()` (4 files)
   - `client_no_detectors`, `client_with_fake_detector`, `client_with_decode_base64` — each a ~30-line fixture in its own file. These could share a parametrisable factory in `conftest.py`.
   - `monkeypatch.setenv("BULWARK_ALLOW_NO_DETECTORS", "1")` is duplicated across `test_dashboard_layers.py`, `test_v2_coverage.py`, `test_clean_decode.py`. Could be an autouse fixture or fixture parameter.

2. **Two helper files for similar UI work.** `tests/_node_helpers.py` (`run_node_eval`) is used by `test_dashboard_ui_events.py` and `test_dashboard_ui_shield.py` but `test_dashboard_ui_shell.py` and `test_dashboard_ui_test_page.py` each reimplement node-subprocess logic inline. Centralising could remove ~30 LOC.

3. **`test_spec_compliance.py::TestPresetTrustBoundaryDrift` and `TestEnvFileDrift` are not really spec-compliance tests** — they're documentation drift detectors. Long, rich, useful, but their placement in `test_spec_compliance.py` (a 428 LOC file) blurs intent. They could move to a `test_doc_drift.py` to keep `test_spec_compliance.py` focused on OpenAPI/contract-yaml drift.

4. **`test_codex_prb_hardening.py` is named after a one-time PR.** The name will become opaque as the codebase ages. Ideal would be to redistribute its 27 tests across the modules they target (sanitizer/url_validator/redteam_status/route-docstring) to make ownership obvious. Keeping the file as-is is fine for this round; flag for a future rename.

5. **Test count drift.** `tests/test_*.py` has 49 files but actual pytest-collected test count varies depending on FastAPI / Node / hatchling availability. Hardcoded "991" in README/ROADMAP is a frozen-snapshot doc claim (already noted in audit-01 F-01-005/006); the test-side equivalent doesn't exist.

6. **`test_http_api.py` is 1167 LOC and 90 tests** — it's the obvious next target for extraction (e.g. `test_http_canaries_api.py` for `TestCanariesAPI`, `test_http_redteam.py` for `TestRedteamTiers/Reports`, `test_http_detect_integrations.py` for `TestDetectIntegrationsCache`). Not a redundancy concern, but the file is hard to navigate. Out of scope for dedup.

7. **`test_attacks.py:22` "at least 75 attacks" is more cosmetic than the doc-audit suggested.** Because it's `>=` not `==`, it doesn't break when the corpus *grows*. It only breaks if someone deletes attacks below the threshold — which would also be a real signal. Lower priority than I expected going in.
