# Codex Efficacy Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the eight efficacy, security, and consistency gaps surfaced by the 2026-04-29 Codex review of Bulwark Shield, in WSJF order, using strict SSD (spec → contract → ADR → tests → implementation).

**Architecture:** Each phase is a standalone SSD-compliant change. We do not refactor the pipeline — we tighten the existing detection-only architecture so that operators cannot silently deploy a degraded version, the dashboard fails closed when detectors are absent, the library matches the dashboard, and known evasion classes are exercised in tests. No new generative paths.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic v2, transformers (DeBERTa, PromptGuard-86M), pytest, OpenAPI 3.1, Docker.

---

## WSJF Ranking

WSJF = Cost of Delay / Job Size.
Cost of Delay = User-Business Value + Time Criticality + Risk Reduction (each scored 1–13).

| Rank | Phase | Item | UBV | TC | RR | CoD | Job | **WSJF** |
|------|-------|------|-----|----|----|-----|-----|----------|
| 1 | A | Fail-closed `/v1/clean` when zero detectors loaded | 13 | 13 | 13 | 39 | 3 | **13.0** |
| 2 | B | Decouple `/v1/clean` auth from judge-enabled flag | 8 | 8 | 13 | 29 | 3 | **9.7** |
| 3 | C | Byte-count limit on `content` (currently char-count) | 5 | 5 | 8 | 18 | 2 | **9.0** |
| 4 | D | Spec/preset/compose drift cleanup | 3 | 5 | 5 | 13 | 2 | **6.5** |
| 5 | E | `Pipeline.from_config()` loads full detector chain | 8 | 5 | 8 | 21 | 5 | **4.2** |
| 6 | F | Real end-to-end detector test in CI | 5 | 3 | 13 | 21 | 5 | **4.2** |
| 7 | G | Boundary/split-evasion test coverage | 5 | 3 | 8 | 16 | 5 | **3.2** |
| 8 | H | Base64/ROT13/punycode semantic detection at `/v1/clean` | 8 | 3 | 8 | 19 | 8 | **2.4** |

**Ordering rule:** ship in WSJF order, one phase per PR. Each PR: patch-bump `VERSION`, update `CHANGELOG.md`, single commit per logical change, no auto-tagging (Nathan triggers tags).

**Per-phase SSD recipe (every phase follows this):**
1. Update `spec/openapi.yaml` if HTTP behavior changes.
2. Update or create `spec/contracts/*.yaml` with new guarantee IDs (`G-…`) and explicit non-guarantees (`NG-…`).
3. Add ADR `spec/decisions/NNN-title.md`.
4. Write failing tests referencing the guarantee IDs in docstrings.
5. Run tests, watch them fail.
6. Implement minimum code to pass.
7. Run `tests/test_spec_compliance.py` to confirm spec/impl agreement.
8. Bump `VERSION` (patch), update `CHANGELOG.md`.
9. Commit and open PR.

---

## File Structure (master)

| Path | Purpose | Phases that touch it |
|------|---------|---------------------|
| `spec/openapi.yaml` | HTTP shape of dashboard API | A, B, C, H |
| `spec/contracts/clean.yaml` | `/v1/clean` guarantees | A, B, C, H |
| `spec/contracts/http_clean.yaml` | HTTP-level guarantees for `/v1/clean` | A, B, C |
| `spec/contracts/http_auth.yaml` | Auth gating | B |
| `spec/contracts/sanitizer.yaml` | Sanitizer guarantees / non-guarantees | H |
| `spec/contracts/presets.yaml` | Presets metadata | D |
| `spec/contracts/env_config.yaml` | Environment variables | D |
| `spec/decisions/040-…` … `047-…` | One ADR per phase | A–H |
| `src/bulwark/dashboard/api_v1.py` | `/v1/clean` handler | A, C, H |
| `src/bulwark/dashboard/app.py` | Auth middleware, startup integration loading | A, B |
| `src/bulwark/dashboard/models.py` | Pydantic request/response models | C |
| `src/bulwark/pipeline.py` | Library `Pipeline` and `from_config()` | E |
| `src/bulwark/sanitizer.py` | Encoding decoders | H |
| `tests/test_*.py` | New failing tests per phase | A–H |
| `VERSION`, `CHANGELOG.md` | Released on every commit | A–H |
| `docker-compose.yml`, `spec/presets.yaml` | Drift cleanup | D |

---

## Phase A — Fail-Closed When Zero Detectors Loaded

**Why first:** Highest-ranked Codex finding. The `/v1/clean` endpoint currently returns 200 OK even when no ML detectors are loaded — operators get a false sense of security. CoD is dominated by user-business value (this is the headline efficacy claim of the project).

**Files:**
- Create: `spec/decisions/040-fail-closed-when-no-detectors.md`
- Modify: `spec/openapi.yaml` (add 503 response to `/v1/clean`)
- Modify: `spec/contracts/clean.yaml` (add `G-CLEAN-DETECTOR-REQUIRED-001`)
- Modify: `spec/contracts/http_clean.yaml` (add `G-HTTP-CLEAN-503-NO-DETECTORS-001`)
- Modify: `src/bulwark/dashboard/api_v1.py:137` (insert detector-presence guard before the `if _detection_checks and cleaned` block)
- Test: `tests/test_fail_closed_no_detectors.py` (new file)
- Modify: `VERSION`, `CHANGELOG.md`

**Guarantee proposed:**

> **G-CLEAN-DETECTOR-REQUIRED-001** — When the dashboard has zero ML detectors loaded *and* the LLM judge is disabled, `/v1/clean` MUST return HTTP 503 with `error.code = "no_detectors_loaded"`. The sanitizer-only path is never silently served.

**Non-guarantee:**

> **NG-CLEAN-DETECTOR-REQUIRED-001** — Operators MAY explicitly opt into a sanitizer-only mode by setting `BULWARK_ALLOW_NO_DETECTORS=1`; this is logged at WARNING level on every request and surfaced in `/healthz` as `mode: degraded-explicit`.

- [ ] **Step A1: Write the failing tests**

```python
# tests/test_fail_closed_no_detectors.py
def test_clean_returns_503_when_no_detectors_and_no_judge(client_no_detectors):
    """G-CLEAN-DETECTOR-REQUIRED-001"""
    r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "no_detectors_loaded"

def test_clean_serves_when_explicit_opt_in(monkeypatch, client_no_detectors):
    """NG-CLEAN-DETECTOR-REQUIRED-001"""
    monkeypatch.setenv("BULWARK_ALLOW_NO_DETECTORS", "1")
    r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
    assert r.status_code == 200
    assert r.json()["mode"] == "degraded-explicit"
```

- [ ] **Step A2: Run tests, expect FAIL**

`PYTHONPATH=src python3 -m pytest tests/test_fail_closed_no_detectors.py -v` → both fail.

- [ ] **Step A3: Write ADR-040 and contract updates**

ADR records: rationale, opt-out env var, log/observability behavior, telemetry implications, migration note for existing 0-detector deploys.

- [ ] **Step A4: Implement the guard in `api_v1.py`**

Insert before existing detector loop. Read `BULWARK_ALLOW_NO_DETECTORS` once at startup, cache. Emit structured log on every degraded-mode request.

- [ ] **Step A5: Run full suite + spec compliance**

`PYTHONPATH=src python3 -m pytest tests/ -v` → green.

- [ ] **Step A6: Bump VERSION → 2.4.2, update CHANGELOG, commit**

Commit message: `security: fail-closed /v1/clean when no detectors loaded (v2.4.2)`

---

## Phase B — Decouple `/v1/clean` Auth from Judge-Enabled

**Why second:** `/v1/clean` is currently only token-gated when the LLM judge is enabled. Public deployments without judge expose the endpoint to quota abuse and arbitrary input submission. The fix is small: a config flag plus middleware change.

**Files:**
- Create: `spec/decisions/041-clean-endpoint-auth.md`
- Modify: `spec/contracts/http_auth.yaml` (extend `G-AUTH-CLEAN-*`)
- Modify: `spec/openapi.yaml` (document 401 on `/v1/clean`)
- Modify: `src/bulwark/dashboard/app.py:88` (auth middleware predicate)
- Modify: `src/bulwark/dashboard/config.py` (new `auth.require_token_for_clean: bool` setting, default true when token set)
- Test: `tests/test_auth.py` (new test cases)
- Modify: `VERSION`, `CHANGELOG.md`

**Guarantee proposed:**

> **G-AUTH-CLEAN-001** — When `BULWARK_API_TOKEN` is set, `/v1/clean` from a non-loopback client MUST require the token, regardless of judge state. Loopback clients remain unauthenticated by ADR-029.

- [ ] **Step B1: Write failing tests** asserting 401 from non-loopback `/v1/clean` with token set + judge disabled.
- [ ] **Step B2: Run, expect FAIL.**
- [ ] **Step B3: Write ADR-041, update contract.**
- [ ] **Step B4: Update auth predicate in `app.py` to gate `/v1/clean` on token presence alone.**
- [ ] **Step B5: Run full suite.**
- [ ] **Step B6: Bump VERSION → 2.4.3, update CHANGELOG, commit.**

Commit message: `security: gate /v1/clean on token regardless of judge state (v2.4.3)`

---

## Phase C — Byte-Count Limit on `content`

**Why third:** Smallest job, real risk. `content: str = Field(..., max_length=_MAX_CONTENT_SIZE)` enforces *character* count, not bytes. A 256 KiB cap can be overrun several-fold by non-ASCII payloads, growing the attack surface and detector latency.

**Files:**
- Create: `spec/decisions/042-content-byte-limit.md`
- Modify: `spec/contracts/http_clean.yaml` (replace char-length wording with byte-length)
- Modify: `spec/openapi.yaml` (correct request schema description)
- Modify: `src/bulwark/dashboard/models.py:43` (Pydantic validator on `content`)
- Test: `tests/test_content_byte_limit.py` (new file)
- Modify: `VERSION`, `CHANGELOG.md`

**Guarantee proposed:**

> **G-HTTP-CLEAN-CONTENT-BYTES-001** — `/v1/clean` MUST reject any request whose `content` field exceeds 262,144 bytes when UTF-8 encoded with HTTP 413 and `error.code = "content_too_large"`.

- [ ] **Step C1: Write failing test** — single 4-byte UTF-8 char × 70k = 280 KiB payload should 413; current code returns 200.
- [ ] **Step C2: Run, expect FAIL.**
- [ ] **Step C3: Write ADR-042, update contracts.**
- [ ] **Step C4: Replace `max_length` with a `field_validator` that measures `len(v.encode("utf-8"))`.**
- [ ] **Step C5: Run full suite.**
- [ ] **Step C6: Bump VERSION → 2.4.4, update CHANGELOG, commit.**

Commit message: `fix(api): enforce byte-count limit on /v1/clean content (v2.4.4)`

---

## Phase D — Spec/Preset/Compose Drift Cleanup

**Why fourth:** Trivially small, removes confusion that contributed to the Codex findings. `spec/presets.yaml` claims an XML escape preset "re-escapes payload" but `tests/test_trust_boundary.py:223` proves it does not. `docker-compose.yml:22` references env vars ADR-031 deleted.

**Files:**
- Create: `spec/decisions/043-spec-drift-cleanup.md`
- Modify: `spec/presets.yaml` (correct XML preset description)
- Modify: `docker-compose.yml` (remove deleted env vars)
- Modify: `spec/contracts/presets.yaml` (mirror corrected wording)
- Test: `tests/test_spec_compliance.py` (extend to detect any preset description that contradicts trust-boundary tests)
- Modify: `VERSION`, `CHANGELOG.md`

- [ ] **Step D1: Add a spec-compliance test** that loads `presets.yaml` and asserts no preset claims behavior the trust-boundary tests disprove.
- [ ] **Step D2: Run, expect FAIL on the XML preset.**
- [ ] **Step D3: Write ADR-043 (small — "drift correction").**
- [ ] **Step D4: Edit `presets.yaml` to accurately describe what the preset does.**
- [ ] **Step D5: Edit `docker-compose.yml` to drop removed env vars.**
- [ ] **Step D6: Run full suite.**
- [ ] **Step D7: Bump VERSION → 2.4.5, update CHANGELOG, commit.**

Commit message: `docs: correct preset/compose drift from ADR-031 (v2.4.5)`

---

## Phase E — `Pipeline.from_config()` Loads Full Detector Chain

**Why fifth:** Library users (`import bulwark`) currently get sanitizer + trust boundary only — strictly weaker than the dashboard. This silently misleads embedders. Medium job because it requires plumbing detector loading into the library entry point without dragging dashboard-only deps into the lib path.

**Files:**
- Create: `spec/decisions/044-library-detector-parity.md`
- Modify: `spec/contracts/clean.yaml` (clarify library vs dashboard parity)
- Modify: `src/bulwark/pipeline.py:124` (`Pipeline.from_config()` loads detectors based on config)
- Modify: `src/bulwark/pipeline.py` (extend the single-detector field to a chain, or compose)
- Test: `tests/test_pipeline_parity.py` (new file — assert library Pipeline blocks the same canonical injection that dashboard `/v1/clean` blocks)
- Modify: `VERSION`, `CHANGELOG.md`

**Guarantee proposed:**

> **G-PIPELINE-PARITY-001** — A `Pipeline.from_config(path)` constructed from the same config the dashboard uses MUST raise `SuspiciousPatternError` for any input the dashboard `/v1/clean` blocks with HTTP 422.

- [ ] **Step E1: Write parity test** — feed a known injection through both `Pipeline.from_config()` and `/v1/clean`, assert both block.
- [ ] **Step E2: Run, expect FAIL on library side.**
- [ ] **Step E3: Write ADR-044.**
- [ ] **Step E4: Update `Pipeline` to support a detector chain; update `from_config` to load DeBERTa, PromptGuard, judge per config.**
- [ ] **Step E5: Run full suite.**
- [ ] **Step E6: Bump VERSION → 2.5.0 (minor — library API change), update CHANGELOG, commit.**

Commit message: `feat(lib): Pipeline.from_config now loads detector chain (v2.5.0)`

---

## Phase F — Real End-to-End Detector Test in CI

**Why sixth:** Today the only HTTP 422 test injects a fake detector. Nothing in CI proves a default deploy *actually* blocks known prompt injections. This is foundational for confidence in Phases A–E and for catching detector regressions.

**Files:**
- Create: `spec/decisions/045-e2e-detector-ci.md`
- Create: `tests/test_e2e_real_detectors.py`
- Modify: `pyproject.toml` or `pytest.ini` (mark slow tests, add CI lane)
- Modify: `.github/workflows/*.yml` (CI lane that downloads small DeBERTa weights and runs e2e)
- Modify: `VERSION`, `CHANGELOG.md`

**Guarantee proposed:**

> **G-E2E-DETECTOR-CI-001** — CI MUST run at least one e2e test per detector model that confirms a canonical prompt-injection sample is blocked. Failures of this lane are merge-blocking.

- [ ] **Step F1: Add a curated five-shot canonical injection list** (separate from attack catalog — picked specifically for cross-version stability).
- [ ] **Step F2: Write `test_e2e_real_detectors.py`** that boots the dashboard with real DeBERTa loaded and asserts each canonical sample returns 422.
- [ ] **Step F3: Add CI lane** marked `@pytest.mark.e2e_slow`, downloads weights, caches by hash.
- [ ] **Step F4: Write ADR-045.**
- [ ] **Step F5: Run locally end-to-end, confirm green.**
- [ ] **Step F6: Bump VERSION → 2.5.1, update CHANGELOG, commit.**

Commit message: `test: add e2e real-detector lane to CI (v2.5.1)`

---

## Phase G — Boundary/Split-Evasion Test Coverage

**Why seventh:** Surfaces a real risk class but doesn't itself close a gap — only demonstrates whether one exists. Likely uncovers Phase H work (semantic decoders), so we want it landed before H.

**Files:**
- Create: `spec/decisions/046-split-evasion-test-coverage.md`
- Create: `tests/test_split_evasion.py`
- Modify: `src/bulwark/attacks.py` (add labeled split-evasion samples to catalog)
- Modify: `VERSION`, `CHANGELOG.md`

**Guarantee proposed:**

> **G-DETECTOR-WINDOW-EVASION-001** — The detector chain MUST block a curated set of split-evasion injections where the malicious tokens straddle the 64-token chunk overlap boundary.

- [ ] **Step G1: Build curated split-evasion samples** (programmatic generator: take a known-blocked sample, pad to land instruction text precisely across the overlap).
- [ ] **Step G2: Write tests, expect FAIL** — at least some samples leak through.
- [ ] **Step G3: Write ADR-046.** Decide remediation: increase overlap stride? add deterministic re-classification at chunk boundaries? — whichever is needed.
- [ ] **Step G4: Implement remediation.**
- [ ] **Step G5: Run full suite.**
- [ ] **Step G6: Bump VERSION → 2.5.2, update CHANGELOG, commit.**

Commit message: `security: close detector chunk-boundary evasion (v2.5.2)`

---

## Phase H — Base64/ROT13/Punycode Semantic Detection

**Why last:** Biggest scope, biggest unknown. Adding semantic decoders to `/v1/clean` opens design questions (should base64 decoding be opt-in? what about nested encodings? what about FP rate explosion?). Best done after Phases A–G have hardened the foundation. Real possibility this gets split into its own brainstorming session and sub-plan.

**Files:**
- Create: `spec/decisions/047-semantic-encoding-detection.md`
- Modify: `src/bulwark/sanitizer.py` (add base64 detector + optional decode pass)
- Modify: `spec/contracts/sanitizer.yaml`
- Modify: `spec/openapi.yaml` (document new config fields)
- Test: `tests/test_semantic_encoding.py` (new file)
- Modify: `VERSION`, `CHANGELOG.md`

- [ ] **Step H1: Brainstorm scope before coding** — does this need its own plan? Likely yes.
- [ ] **Step H2: Decision recorded in ADR-047** with explicit non-guarantee list.
- [ ] **Step H3+:** Detailed steps deferred to sub-plan.

> **Note:** Phase H may spawn a separate plan file. Do not start implementation until Phases A–G have shipped and we have empirical FP-rate data from Phase F's CI lane.

---

## Self-Review Checklist

- [x] **Spec coverage:** Each Codex finding maps to a phase (A–H). Verified.
- [x] **Placeholder scan:** Phase H step H3 is a deliberate deferral, not a placeholder; flagged inline.
- [x] **Type consistency:** Guarantee IDs follow `G-{AREA}-{NAME}-NNN` pattern used elsewhere in the project.
- [x] **ADR numbering:** 040–047 reserved sequentially; latest existing is 039.
- [x] **VERSION cadence:** Phases A–D and F–G are patch bumps; E is minor (library API change). Per CLAUDE.md.
- [x] **No auto-tagging:** Every commit message ends with a version marker but no phase creates or pushes git tags. Per memory `feedback_no_auto_tag.md`.

---

## Derived Task List (for TaskCreate)

Once this plan is agreed, create eight tasks (one per phase) with the following IDs and ordering. Each task's description points back to its phase in this file.

| Task ID | Title | Blocked by |
|---------|-------|-----------|
| ce-A | Phase A — Fail-closed when no detectors | — |
| ce-B | Phase B — Decouple /v1/clean auth from judge | — (parallelizable with A) |
| ce-C | Phase C — Byte-count limit on content | — (parallelizable with A, B) |
| ce-D | Phase D — Spec/preset/compose drift cleanup | — (trivial, can ship anytime) |
| ce-E | Phase E — Pipeline.from_config detector parity | A (uses fail-closed semantics) |
| ce-F | Phase F — E2E real-detector CI lane | A (asserts the new fail-closed path too) |
| ce-G | Phase G — Split-evasion test coverage | F (needs CI lane to run real models) |
| ce-H | Phase H — Semantic encoding detection | G + F + dedicated brainstorm |

---

## Execution Handoff

Plan complete and saved. Two execution options:

1. **Subagent-Driven (recommended)** — Dispatch a fresh subagent per phase. Best parallelism for A–D which are independent.
2. **Inline Execution** — Walk phases sequentially in this session.

Phases A, B, C, D are mutually independent and can be worked in parallel (or chained if you prefer fewer concurrent PRs).
