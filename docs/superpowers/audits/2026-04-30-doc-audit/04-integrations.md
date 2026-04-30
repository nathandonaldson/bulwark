# Doc Audit 04 — Integrations and Examples

**Auditor:** subagent 4 of 5
**Date:** 2026-04-30
**Slice:** OpenClaw integration docs, Wintermute integration doc, Codex security review, all `examples/quickstart_*.py`

---

## Findings

### F-04-01 — Codex security review describes a v1 architecture that no longer exists

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/codex-security/bulwark-security-review.txt:7-11,33,67,108,134,147`
- **Category:** STALE / OBSOLETE
- **Severity:** CRITICAL
- **Claim:** Lists `/v1/pipeline` as a public endpoint (lines 8, 33, 67, 108) and the entire threat model is built around "two-phase execution," "Phase 1 / Phase 2," and `make_analyze_fn` / `make_execute_fn` (lines 11, 108, 134, 147). The "Critical" risk row literally reads "bypassing the two-phase boundary."
- **Reality:** `/v1/pipeline` is not registered. `src/bulwark/dashboard/api_v1.py:34` mounts only `/v1/clean` and `/v1/guard` (`api_v1.py:89`, `api_v1.py:480`). ADR-031 removed two-phase execution; `api_v1.py:4` says "No LLM calls. No /v1/llm/*." The integrations `__init__.py` still references `make_pipeline` etc. in its docstring but the symbols themselves are absent from `src/bulwark/integrations/anthropic.py` (only `protect` / `ProtectedAnthropicClient` remain). The threat model is auditing a code path that was deleted.
- **Recommended fix:** Either (a) move this file to a clearly labeled historical archive (rename to `bulwark-security-review-v1-2025-XX.txt` or move under `docs/archive/`) with a banner stating "Frozen at v1.x — does not reflect v2 (ADR-031) detection-only architecture," or (b) commission a fresh Codex review against current `/v1/clean` + `/v1/guard` and replace this file. Leaving it as a `.txt` with no date in `docs/codex-security/` reads as authoritative.

### F-04-02 — Codex security review references `AnalysisGuard` as the live class name

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/codex-security/bulwark-security-review.txt:7,82,97,153`
- **Category:** STALE
- **Severity:** MINOR
- **Claim:** "A Python library with `Sanitizer`, `TrustBoundary`, `AnalysisGuard`, ..." — treated as the canonical class name throughout.
- **Reality:** `src/bulwark/__init__.py:13-15` shows `PatternGuard` is the real class; `AnalysisGuard` is now an explicit back-compat alias. New v2 docs should use `PatternGuard`.
- **Recommended fix:** If F-04-01 is solved by archiving, no action needed. If kept live, replace `AnalysisGuard` with `PatternGuard` and add a single back-compat note.

### F-04-03 — Wintermute integration doc points at port 3001 while project memory and Docker default both say 3000

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/integrations/wintermute.md:5,42,74,94`
- **Category:** INCONSISTENT
- **Severity:** IMPORTANT
- **Claim:** The doc consistently uses `http://localhost:3001` for the Wintermute-facing sidecar — the leading paragraph (line 5), `safe_call` example (line 42), `guard()` example (line 74), and the canary curl (line 94).
- **Reality:** The published Docker image binds to `3000` (`CLAUDE.md:65` — `docker run -p 3000:3000 ... nathandonaldson/bulwark`) and `bulwark/dashboard/__main__.py:111` defaults `--port` to `3000`. Port 3001 is the source-tree dev port (`CLAUDE.md:62`). Project memory `project_wintermute_integration.md` explicitly says Wintermute consumes Bulwark on `localhost:3000` via the Docker image. So the doc tells Wintermute operators to hit a port that only exists if they run from source.
- **Recommended fix:** Change all four URLs to `localhost:3000` (the Docker contract Wintermute is built against). Add a single line under "Why Bulwark runs as a sidecar" noting that port 3001 is the source-tree dev port, 3000 is the Docker image port, and Wintermute should pin to 3000.

### F-04-04 — Wintermute doc claims `/v1/clean` returns 422 on block, accurate but undersells 503 path

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/integrations/wintermute.md:46-48,146-151`
- **Category:** MISSING
- **Severity:** IMPORTANT
- **Claim:** Failure-modes table only lists 422 and "sidecar unreachable." `safe_call` only branches on 422.
- **Reality:** ADR-040 introduced HTTP 503 with `error.code = "no_detectors_loaded"` (`api_v1.py:134-147`). Wintermute hitting a freshly started sidecar before models load (or one running without `BULWARK_ALLOW_NO_DETECTORS=1` and zero detectors) gets 503, not 422. ADR-042 introduced HTTP 413 `content_too_large` for payloads over 256 KiB. Neither is mentioned.
- **Recommended fix:** Add 503 + 413 rows to the failure-modes table. Update the sample `clean()` helper to surface 503 as "Bulwark is loading / misconfigured — fail closed." Cite ADR-040 and ADR-042.

### F-04-05 — Wintermute doc shows trace label `detection:protectai` — current trace uses model-name keys

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/integrations/wintermute.md:128`
- **Category:** STALE
- **Severity:** MINOR
- **Claim:** Sample 200 response shows `{"step": 2, "layer": "detection:protectai", "verdict": "passed", "detail": "..."}`.
- **Reality:** `api_v1.py:267-292` builds layer names as `f"detection:{model_name}"` from each registered check's `__bulwark_name__`. The actual layer for the ProtectAI loader is `detection:protectai-deberta-v3-base-injection-v2` or whatever model id was registered — not the literal string `protectai`. Also, every variant emits its own trace step now (ADR-047 / Phase H), and trace entries carry `detection_model`, `duration_ms`, `max_score`, `n_windows`, plus `decoded_variants` — none of which appear in the sample.
- **Recommended fix:** Regenerate the sample by hitting a live `/v1/clean` and pasting the actual JSON. Or label the existing one as "fields shown are illustrative — the live response carries additional `detection_model`, `duration_ms`, `max_score`, and `decoded_variants` fields."

### F-04-06 — `docs/openclaw.md` and `integrations/openclaw/README.md` describe the `message:received` hook with a colon — plugin code matches but ADR uses underscore form

- **File:** `/Users/musicmac/Documents/bulwark-shield/docs/openclaw.md:9,94`; `/Users/musicmac/Documents/bulwark-shield/integrations/openclaw/README.md:11,103`
- **Category:** INCONSISTENT
- **Severity:** MINOR
- **Claim:** Both docs use `message:received` (with a colon). The audit prompt for this slice references `message_received` (with an underscore).
- **Reality:** `integrations/openclaw/plugin/index.js:71` registers `api.on("message:received", ...)` (colon form). ADR-011 (`spec/decisions/011-openclaw-integration.md:25,38`) uses both forms — `message:received` in the bullet list and the same colon form for the decision. So docs and plugin agree (colon). The audit prompt's underscore form is the outlier; no action needed in the docs except confirming the colon form is canonical. Flag this so the auditor's spec stays in sync.
- **Recommended fix:** No doc change. Note in the master audit summary that `message:received` (colon) is the canonical hook name per `index.js:71` — update any internal spec / audit checklist that uses `message_received`.

### F-04-07 — OpenClaw README claims "Fail-open" without mentioning that Bulwark itself documents this as a P-low residual risk

- **File:** `/Users/musicmac/Documents/bulwark-shield/integrations/openclaw/README.md:67-69`
- **Category:** MINOR
- **Severity:** MINOR
- **Claim:** "If the Bulwark sidecar is unreachable, the plugin logs a warning and passes content through unchanged. This prevents breaking the agent when the sidecar is down."
- **Reality:** Accurate to `index.js:35-38` and `index.js:57-60`. The fail-open is genuinely an availability/security trade-off and the security review (line 122 of the codex review, line 152) explicitly classifies it as Low-priority. Worth surfacing the trade-off so an operator who wants fail-closed can know to change it.
- **Recommended fix:** Add one line: "To fail closed instead, modify `index.js` to return an error verdict when the sidecar is unreachable — there is no env switch today." Or add a `BULWARK_FAIL_CLOSED=1` env knob in `index.js` and document it.

### F-04-08 — `bulwark-sanitize/SKILL.md` is still relevant but its rule set has not been updated for ADR-040 503 path

- **File:** `/Users/musicmac/Documents/bulwark-shield/integrations/openclaw/skills/bulwark-sanitize/SKILL.md:50-55`
- **Category:** MISSING
- **Severity:** MINOR
- **Claim:** Rule 3: "If `/v1/clean` is unreachable, tell the user Bulwark is not running and refuse to process the external content."
- **Reality:** Correct for unreachable. Doesn't cover HTTP 503 (`no_detectors_loaded`) — agent would see a non-200 response and the rule doesn't tell it that this is a "Bulwark is up but its detectors aren't loaded" state distinct from "down."
- **Recommended fix:** Add: "If `/v1/clean` returns HTTP 503 with `error.code: no_detectors_loaded`, treat as Bulwark misconfigured and refuse to process — do NOT retry assuming it'll come up." The skill is otherwise still relevant.

### F-04-09 — `quickstart_protect.py` has no docstring explaining what it demonstrates (it does, but minimally)

- **File:** `/Users/musicmac/Documents/bulwark-shield/examples/quickstart_protect.py:1-7`
- **Category:** MINOR
- **Severity:** MINOR
- **Claim:** Docstring says "Auto-protect an Anthropic client with one line" and "Requires: pip install bulwark-shield[anthropic]".
- **Reality:** Functional and correct. The install line `pip install bulwark-shield[anthropic]` matches `pyproject.toml:38` `anthropic = ["anthropic>=0.39.0"]`. `protect` is the right export. The pattern is detection-only client-side proxy — matches `bulwark/integrations/anthropic.py:28-39`. One nit: the docstring doesn't say this is a *proxy* (no HTTP call, no network round-trip to Bulwark). A user reading this expecting v1-style two-phase would be confused why the script never calls Bulwark.
- **Recommended fix:** Add a sentence: "This is a client-side proxy — sanitization happens in-process before the Anthropic API call. No Bulwark sidecar required (compare `quickstart_anthropic.py` for the HTTP variant)."

### F-04-10 — `quickstart_anthropic.py` "Pattern 1" docstring claim that the SDK proxy is "detection-only" is misleading

- **File:** `/Users/musicmac/Documents/bulwark-shield/examples/quickstart_anthropic.py:9-12,24-32`
- **Category:** WRONG
- **Severity:** IMPORTANT
- **Claim:** "1. SDK proxy — `protect()` wraps the client and auto-sanitizes user message content before it leaves your process. **Detection-only**, no network call to Bulwark — uses the local sanitizer + trust boundary."
- **Reality:** `bulwark/integrations/anthropic.py:42-99` shows the proxy runs `Sanitizer.clean()` + `TrustBoundary.wrap()`. There is no detector chain — no DeBERTa, no PromptGuard, no judge. So calling it "detection-only" inverts the truth: it does *no* detection at all, only sanitization + boundary tagging. Compare to `/v1/clean` HTTP, which actually runs the three-detector chain (api_v1.py:201-247). A reader given the choice between Pattern 1 ("detection-only") and Pattern 2 ("HTTP, may return 422") would reasonably assume Pattern 1 is stricter. It is the opposite — Pattern 1 has no ML detection.
- **Recommended fix:** Rename the descriptor: "1. SDK proxy — `protect()` wraps the client and auto-sanitizes user message content. **Sanitize + trust-boundary tag only — no ML detection.** No network call to Bulwark." And on Pattern 2: "Sanitizer + DeBERTa (and optional PromptGuard / LLM judge) run in the sidecar — may return 422 if a classifier blocks."

### F-04-11 — `quickstart_anthropic.py` and `quickstart_openai.py` hardcode port 3001 — wrong for Docker users

- **File:** `/Users/musicmac/Documents/bulwark-shield/examples/quickstart_anthropic.py:39`; `/Users/musicmac/Documents/bulwark-shield/examples/quickstart_openai.py:15`; `/Users/musicmac/Documents/bulwark-shield/examples/quickstart_generic.py:13`
- **Category:** INCONSISTENT
- **Severity:** IMPORTANT
- **Claim:** All three examples hardcode `http://localhost:3001` as the Bulwark URL.
- **Reality:** Same root cause as F-04-03 — port 3001 is the source-tree dev port (`CLAUDE.md:62` `python -m bulwark.dashboard --port 3001`), but the published Docker image (which is what most users will run) binds to 3000 (`CLAUDE.md:65`, `__main__.py:111`). A user who pulled `nathandonaldson/bulwark` and ran the sample would get connection refused. The OpenClaw integration uses port 8100 (also non-default). This means we have three documented ports — 3000 (Docker), 3001 (dev), 8100 (OpenClaw sidecar) — and the examples pick the rarest one.
- **Recommended fix:** Change all three to `http://localhost:3000` (the Docker default), OR introduce a single `BULWARK = os.environ.get("BULWARK_URL", "http://localhost:3000")` pattern at the top of each example. Add a one-line comment explaining "use 3001 if you're running from source via `python -m bulwark.dashboard --port 3001`."

### F-04-12 — `quickstart_openai.py` has no `httpx` in `pyproject.toml` extras for non-bench users

- **File:** `/Users/musicmac/Documents/bulwark-shield/examples/quickstart_openai.py:8`
- **Category:** MINOR
- **Severity:** MINOR
- **Claim:** "Requirements: pip install openai httpx"
- **Reality:** Correct, but `pyproject.toml:38` only ships `httpx` under the `dashboard`, `bench`, and `all` extras. The "minimal install" path (`pip install bulwark-shield`) does not include `httpx`. The example acknowledges this by listing `httpx` in its requirements, so it's accurate — flag for awareness.
- **Recommended fix:** No fix required. Optionally add `pip install bulwark-shield openai httpx` to make the dependency on Bulwark itself explicit (right now the example just imports `httpx` and `openai` and doesn't import bulwark at all — which is correct given it talks to Bulwark over HTTP, but a user might wonder).

### F-04-13 — `quickstart_clean.py` correctly demonstrates `bulwark.clean()` with all current params

- **File:** `/Users/musicmac/Documents/bulwark-shield/examples/quickstart_clean.py`
- **Category:** (verified, no finding)
- **Severity:** —
- **Reality:** `import bulwark; bulwark.clean(content, source="email")` — works against `src/bulwark/shortcuts.py:54-100`. `format="markdown"` is one of the three supported formats (`shortcuts.py:35-39`). Verified by running `PYTHONPATH=src python3 -c "import bulwark; ... bulwark.clean(...)"` — returns the markdown-fenced trust boundary as expected. Docstring is accurate. No `Pipeline(detect=...)` usage.

### F-04-14 — `quickstart_generic.py` is correct against current `/v1/clean` + `/v1/guard` shape

- **File:** `/Users/musicmac/Documents/bulwark-shield/examples/quickstart_generic.py`
- **Category:** (verified, no finding)
- **Severity:** —
- **Reality:** Uses `httpx.post` against `/v1/clean` and `/v1/guard`. The 422 branch reads `body.get('blocked_at')` and `body.get('block_reason')` — both fields are emitted by `api_v1.py:339-347`. The 200 branch reads `r.json()["result"]` — emitted by `api_v1.py:461`. The `/v1/guard` branch reads `body["safe"]` and `body.get("reason")` — emitted by `api_v1.py:511,521,533`. All correct. Same port 3001 caveat as F-04-11.

### F-04-15 — None of the five examples reference the removed `Pipeline(detect=...)` API

- **File:** all five examples
- **Category:** (verified, no finding)
- **Severity:** —
- **Reality:** ADR-044 / v2.5.0 removed the `Pipeline(detect=callable)` constructor — `Pipeline` now takes `detectors=[...]` (a list). `grep -rn "Pipeline(detect" examples/` returns no matches. None of the examples instantiate `Pipeline` at all — they all use `bulwark.clean()`, `protect()`, or HTTP. So the v2.5.0 breaking change is not exposed in any example. Good.

### F-04-16 — `quickstart_clean.py` docstring positions `bulwark.clean()` as preferred path; reality is more nuanced

- **File:** `/Users/musicmac/Documents/bulwark-shield/examples/quickstart_clean.py:1-7`
- **Category:** INCONSISTENT
- **Severity:** MINOR
- **Claim:** "bulwark.clean() provides input sanitization + trust boundary tagging in one library call — no HTTP sidecar required. For the full v2 detection chain (DeBERTa + optional PromptGuard / LLM judge), call /v1/clean on the running dashboard instead."
- **Reality:** Accurate for the in-process variant (sanitize + boundary, no detectors). However, `Pipeline.from_config(path)` (ADR-044) now ALSO loads the same detector chain in-process — the doc treats HTTP as the only way to get detection, but the library `Pipeline.from_config` is now the parity path. A user reading this might think they have to spin up a dashboard to get DeBERTa.
- **Recommended fix:** Add a third option: "For full v2 detection in-process without HTTP, use `Pipeline.from_config('bulwark-config.yaml').run(content)` (ADR-044). For HTTP, see `quickstart_generic.py`."

---

## Restructural recommendations

### R-04-01 — Triage `docs/codex-security/bulwark-security-review.txt`

This document is the most stale piece of public-facing security documentation in the repo. It claims `/v1/pipeline`, two-phase execution, `make_analyze_fn`, `AnalysisGuard` — all v1 surfaces removed by ADR-031. Either:

1. Move to `docs/archive/codex-security-2025-XX.txt` with a banner stating "frozen at v1.x — see current security model in [link]."
2. Re-run `/codex security-review` against current code, replace the file, and date it. Existing recent commits already mention "Codex follow-up" PRs (e.g. `5725e91 hardening: PR-B Codex follow-up`), so the workflow is in place.

Severity: CRITICAL. A reader landing on `bulwark-security-review.txt` reasonably believes it documents the live system.

### R-04-02 — Pick one canonical port for examples and integrations

Three port conventions coexist with no single source of truth:

| Surface | Port | Where defined |
|---|---|---|
| Docker image (`nathandonaldson/bulwark`) | 3000 | `__main__.py:111`, `CLAUDE.md:65` |
| Source-tree dev | 3001 | `CLAUDE.md:62` |
| OpenClaw sidecar | 8100 | `docker-compose.bulwark.yml:12` |

Examples currently use 3001, the rarest. Recommend: standardize examples on 3000 (Docker default, what most external integrators use), keep 3001 explicitly labeled "dev" in CLAUDE.md, leave 8100 as the OpenClaw-sidecar-specific port. Add one paragraph to `docs/README.md` titled "Which port am I on?"

Severity: IMPORTANT.

### R-04-03 — Tighten the relationship between `protect()`, `clean()`, and HTTP `/v1/clean`

Right now there are three Bulwark entry points that look superficially similar:

- `bulwark.clean()` — sanitize + boundary, in-process, no detectors
- `protect(client)` — same sanitize + boundary, but auto-applied to Anthropic SDK calls
- `POST /v1/clean` — sanitize + boundary + the full DeBERTa/PromptGuard/judge chain
- `Pipeline.from_config()` — same detector chain as HTTP, in-process (ADR-044)

The examples and Wintermute doc don't make this hierarchy explicit. A user wondering "do I need detection?" can't easily tell which path gives it. Recommend a single comparison table (one of: in `docs/README.md`, in `docs/integrations/`, or as the top of `examples/README.md` if one were created) showing all four paths, what each runs, and when to use each. F-04-10 is one local instance of this confusion ("detection-only" applied to a no-detector path).

Severity: IMPORTANT.

### R-04-04 — Add a 503 + 413 row to every integration's failure-modes guidance

ADR-040 and ADR-042 introduced two new HTTP failure codes that aren't covered in the Wintermute doc, the OpenClaw README, the SKILL.md rules, or the quickstart examples. This is fine for the SDK proxy (which doesn't make HTTP calls), but every HTTP-using integration should know that `/v1/clean` can return 503 (no detectors loaded) and 413 (content too large) in addition to 422 (blocked). One shared table replicated to each integration doc would close the gap.

Severity: IMPORTANT.

### R-04-05 — Wintermute project memory says port 3000, doc says port 3001 — pick one and update both

The 15-day-old project memory `project_wintermute_integration.md` (which itself comes with a "memories may be outdated" reminder) says Wintermute runs on `localhost:3000`. The doc says 3001. They cannot both be right for the same integration. Confirm with the user which is canonical, then sync the doc to match.

Severity: IMPORTANT (already covered as F-04-03 + R-04-02; calling out as a memory/doc consistency concern separately).

---

## Summary stats

- **Files audited:** 11 (3 markdown docs, 1 SKILL.md, 1 plain-text security review, 5 quickstart examples, 1 plugin index.js cross-referenced)
- **Findings:** 14 (excluding the 2 "verified, no finding" entries F-04-13/14/15)
  - **CRITICAL:** 1 (F-04-01 — stale Codex security review architecture)
  - **IMPORTANT:** 4 (F-04-03 wintermute port, F-04-04 missing 503/413 in wintermute, F-04-10 wrong "detection-only" claim in quickstart_anthropic, F-04-11 example port hardcoded)
  - **MINOR:** 9 (F-04-02, F-04-05, F-04-06, F-04-07, F-04-08, F-04-09, F-04-12, F-04-16)
- **Restructural recommendations:** 5
- **Verified-clean items:** 3 (F-04-13, F-04-14, F-04-15 — quickstart_clean works, quickstart_generic matches HTTP shape, no example uses removed `Pipeline(detect=...)`)

Audit 04 written: 1 critical, 4 important, 9 minor findings, 5 restructural recommendations.
