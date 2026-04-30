# Doc Audit 03: Architecture & Defense Concepts

**Auditor:** doc-audit subagent 3 of 5
**Date:** 2026-04-30
**Scope:** `docs/detection.md`, `docs/layers.md`, `docs/red-teaming.md`, `docs/async.md`

---

## Findings

### CRITICAL

#### 1. `docs/detection.md` — Missing decode-rescan / encoding decoders entirely

- **File:** `docs/detection.md`
- **Category:** MISSING
- **Claim:** The doc describes the v2 chain as "DeBERTa → PromptGuard → LLM Judge" running once on the cleaned text. No mention that each detector is run once **per decoded variant** (ROT13 always-on, base64 opt-in), or the candidate cap of 16, the printable-ASCII quality gate, or two-pass nested decoding.
- **Reality:** ADR-047 (`spec/decisions/047-encoding-decoders.md`), `src/bulwark/decoders.py:55-180` (`decode_rescan_variants`, `_quality_gate`, `_CANDIDATE_CAP=16`, `_MIN_DECODED_BYTES=10`, `_MIN_PRINTABLE_RATIO=0.80`), `src/bulwark/pipeline.py:98-114`, `src/bulwark/dashboard/api_v1.py:183-199`. Shipped in v2.5.4. The Pipeline `decode_base64: bool = False` flag (`pipeline.py:62`) is the opt-in.
- **Recommended fix:** Add a "Decode-rescan (ADR-047)" section after the per-detector descriptions: ROT13 always-on (free FP-cost coverage), base64 opt-in via `decode_base64` (config + Pipeline kwarg), candidate cap 16, printable-ASCII quality gate ≥80%, depth-2 nested decoding. Mention that the trust boundary still wraps the **original** cleaned text — variants are detection-only fan-out (NG-CLEAN-DECODE-VARIANTS-PRESERVED-001).

#### 2. `docs/detection.md` — Wrong chunk-window numbers

- **File:** `docs/detection.md:18-21`
- **Category:** WRONG
- **Claim:** "Inputs over 512 tokens are chunked into overlapping windows so the detector sees the entire payload (ADR-032)."
- **Reality:** ADR-032 specifies **510-token windows** (model_max_length minus 2 for `[CLS]/[SEP]` reserved tokens) with **64-token stride/overlap**. See `src/bulwark/integrations/promptguard.py:78-83` (`_WINDOW_RESERVED_TOKENS = 2`, `_WINDOW_STRIDE_TOKENS = 64`, `_MAX_BATCH_WINDOWS = 64`). The 512 number is the model's input ceiling, not the window size used.
- **Recommended fix:** "Inputs longer than ~510 tokens are chunked into overlapping 510-token windows with 64-token overlap; up to 64 windows are batched per inference call (ADR-032)."

#### 3. `docs/detection.md` — LLM-judge classifier prompt section underspecified vs. NG-JUDGE-003/004

- **File:** `docs/detection.md:40-58`
- **Category:** INCONSISTENT
- **Claim:** "The classifier prompt is fixed in code (NG-JUDGE-003)." — but doc does not mention the per-request nonce-delimited markers (`[INPUT_<nonce>_START]` / `[INPUT_<nonce>_END]`) or the requirement that only `verdict` / `confidence` / `latency` reach `/v1/clean`.
- **Reality:** `src/bulwark/detectors/llm_judge.py:25-71` (the `_SYSTEM_PROMPT` constant and `_generate_nonce` / `_markers` helpers); ADR-037 fixed-prompt guarantee. NG-JUDGE-004 forbids returning generative text to callers — the `JudgeVerdict.raw` field is explicitly never surfaced (`api_v1.py` description at line 99-100, `ChainResult` JudgeResult does not include `raw`).
- **Recommended fix:** Replace the single "fixed in code (NG-JUDGE-003)" line with a short explainer: judge sees the input wrapped between unique nonce-delimited markers; only verdict + confidence + latency reach the response; raw judge text never leaves the server (NG-JUDGE-004).

#### 4. `docs/red-teaming.md` — Wrong attack count and category list

- **File:** `docs/red-teaming.md:7-19`
- **Category:** WRONG / STALE
- **Claim:** Header says "77 patterns across 10 categories" — total of breakdown rows = 71 (9+11+10+10+8+6+6+6+5). Table row order is inconsistent and `bridge_exploitation` is missing.
- **Reality:** Live count from `python3 -c "from bulwark.attacks import AttackSuite; ..."` produces **77 attacks across 10 categories** (rows total to 77 only when `bridge_exploitation: 6` is included): `instruction_override 9, social_engineering 11, encoding 10, steganography 10, data_exfiltration 8, cross_contamination 6, delimiter_escape 6, tool_manipulation 6, multi_turn 5, bridge_exploitation 6`. Plus an 11th category `SPLIT_EVASION` (`AttackCategory` enum in `src/bulwark/attacks.py:9-20`) generated on demand from `generate_split_evasion_samples` (ADR-046).
- **Recommended fix:** Replace the table with the correct numbers (matching live counts), add the `bridge_exploitation` row, and add a footnote about the on-demand `split_evasion` category (ADR-046).

#### 5. `docs/red-teaming.md` — Stale "all 315" probe count for `ProductionRedTeam`

- **File:** `docs/red-teaming.md:78`
- **Category:** STALE
- **Claim:** `max_probes=10,  # 0 for all 315`
- **Reality:** `ProductionRedTeam._get_probe_payloads` (`src/bulwark/integrations/redteam.py:271-391`) loads probes dynamically from Garak's plugin registry per tier. The actual count depends on the installed garak version — the dashboard already pulls dynamically (`src/bulwark/dashboard/app.py:736-765`) and exposes `probe_count` in the tier metadata. The 315 number is a frozen snapshot from before tiered loading (ADR-018) and is now misleading. The doc itself acknowledges this elsewhere ("probe counts pulled dynamically from your installed garak version") — the inline comment contradicts that.
- **Recommended fix:** Change the comment to `# 0 for all probes (count depends on garak version + tier)`.

---

### IMPORTANT

#### 6. `docs/layers.md` — "All five" claim does not match `Pipeline.default()`

- **File:** `docs/layers.md:3`
- **Category:** WRONG
- **Claim:** "use `Pipeline.default()` for all five."
- **Reality:** `Pipeline.default()` (`src/bulwark/pipeline.py:186-204`) returns Sanitizer + TrustBoundary + caller-supplied detectors only. It does NOT auto-load DeBERTa, PromptGuard, or the LLM judge. The detector-loading three-stage chain (DeBERTa, PromptGuard, judge) is composed by `Pipeline.from_config(path)` (`pipeline.py:206-263`), per ADR-044 (G-PIPELINE-PARITY-001). `Pipeline.default()` returns an empty detector chain unless the caller passes one.
- **Recommended fix:** Replace with: "Use `Pipeline.default()` for sanitizer + trust boundary, or `Pipeline.from_config('bulwark-config.yaml')` to compose the same DeBERTa + PromptGuard + LLM-judge chain the dashboard's `/v1/clean` runs (ADR-044, G-PIPELINE-PARITY-001)." The "five" framing is also stale — the v2 pipeline is sanitizer + 1–3 detectors + trust boundary; the count varies with config.

#### 7. `docs/layers.md` — Missing detector layer entirely; entire detector docs is in detection.md but `layers.md` describes layers as Sanitizer / TrustBoundary / Canary only

- **File:** `docs/layers.md`
- **Category:** IA-GAP / MISSING
- **Claim:** The doc describes Sanitizer, Trust Boundary, and Canary Tokens as "each Bulwark layer" — but the detector chain (DeBERTa / PromptGuard / LLM judge) is the centerpiece of v2 (ADR-031) and is omitted. There's also no cross-link to `detection.md`.
- **Reality:** ADR-031 makes the detector chain mandatory for `/v1/clean`. The v2 architecture is sanitizer → detector chain → trust boundary, plus canaries on the output side via `/v1/guard`.
- **Recommended fix:** Add a Detector section linking to `detection.md`, OR rename this doc to "Per-Layer Library Usage" and explicitly call out that the detector chain has its own page.

#### 8. `docs/layers.md` — Missing `BULWARK_ALLOW_NO_DETECTORS` / `BULWARK_ALLOW_SANITIZE_ONLY` documentation

- **File:** `docs/layers.md` (and arguably `detection.md`)
- **Category:** MISSING
- **Claim:** N/A — these env vars are not mentioned at all.
- **Reality:** ADR-040 (`BULWARK_ALLOW_NO_DETECTORS=1`) gates `/v1/clean` fail-closed-when-no-detectors behavior; ADR-038 (`BULWARK_ALLOW_SANITIZE_ONLY=1`) gates the `/healthz` degraded signal. Both are user-facing operator decisions and ship in production. References: `src/bulwark/dashboard/api_v1.py:118-152`, `src/bulwark/dashboard/app.py:235-248`, `spec/decisions/040-fail-closed-when-no-detectors.md`, `spec/decisions/038-mandatory-detector-visibility.md`.
- **Recommended fix:** Add an "Operator opt-outs" subsection to either `layers.md` or `detection.md` that lists both env vars, what they do, and links to the ADRs. The audit task spec specifically calls these out as required content.

#### 9. `docs/red-teaming.md` — Stale references to `bridge_exploitation` family in code but missing from doc table; `multi_turn` description fine

- **File:** `docs/red-teaming.md:7-19`
- **Category:** INCONSISTENT
- **Claim:** Table omits `bridge_exploitation` (6 attacks).
- **Reality:** `_bridge_exploitation_attacks()` returns 6 attacks (`src/bulwark/attacks.py:793-845`). The category was kept post-ADR-031 even though the bridge concept itself was deleted, because the attack patterns still test general boundary-escape shapes.
- **Recommended fix:** Add `| bridge_exploitation | 6 | Boundary-escape patterns retained from v1 |` to the table.

#### 10. `docs/red-teaming.md` — Missing split-evasion / ADR-046 non-guarantee

- **File:** `docs/red-teaming.md`
- **Category:** MISSING
- **Claim:** No mention of split-evasion as a known non-guarantee or of the curated attack pairs.
- **Reality:** ADR-046 documents `NG-DETECTOR-WINDOW-EVASION-001`: ≥~50 tokens of benign filler between trigger and instruction is documented as out of scope for the per-window classifier. The on-demand corpus generator is `AttackSuite.generate_split_evasion_samples` (`src/bulwark/attacks.py:204-223`); curated pairs at `attacks.py:36-49`. Defense for that regime relies on the LLM Judge (ADR-033).
- **Recommended fix:** Add a "Known non-guarantees" subsection that mentions split-evasion (ADR-046), with a one-line "use the LLM judge if dilution-style attacks are in scope for your threat model" recommendation.

#### 11. `docs/red-teaming.md` — Stale `from_dict` / batch-LLM tier hints

- **File:** `docs/red-teaming.md:33`
- **Category:** STALE / OBSOLETE
- **Claim:** Tier list shows three Garak tiers + False Positives. The framing "Smoke / Standard / Full Sweep" is correct, but the deprecated `llm-quick` and `llm-suite` tiers are not mentioned as removed.
- **Reality:** ADR-035 removed `llm-quick` and `llm-suite` (`src/bulwark/integrations/redteam.py:118-122`: "llm-quick / llm-suite removed in v2.1.0 (ADR-035)"). Anyone reading old materials might still try to invoke them; calling out the removal would help.
- **Recommended fix:** Optional — add a footnote that the legacy `llm-quick`/`llm-suite` LLM-facing tiers were removed in v2.1.0 (ADR-035) since v2's detection-only architecture has no LLM behind the detectors. (MINOR-leaning, but useful for migrators.)

#### 12. `docs/red-teaming.md` — Programmatic ProductionRedTeam example missing `pipeline_url`

- **File:** `docs/red-teaming.md:71-84`
- **Category:** INCONSISTENT
- **Claim:** Example constructs `ProductionRedTeam(project_dir=..., max_probes=10, delay_ms=200)` and calls `runner.run()`. With those args, the runner builds its own pipeline (sanitizer + trust boundary) and calls Claude CLI — it does NOT exercise `/v1/clean`.
- **Reality:** `ProductionRedTeam._evaluate_probe` (`src/bulwark/integrations/redteam.py:519-524`) routes via `pipeline_url` if set, else falls back to "evaluate_direct" — direct sanitizer + trust boundary + LLM call, no detector chain. To exercise the production detector chain (ADR-031), callers must set `runner.pipeline_url = "http://localhost:3001"`. The doc's prose at line 30 says "the production red team" sends "Garak's attack payloads through your actual `/v1/clean` pipeline" — but the programmatic example does not show how.
- **Recommended fix:** Add `runner.pipeline_url = "http://localhost:3000"` (or 3001 for source) to the example, with a comment explaining what it does.

#### 13. `docs/async.md` — "Single-process, async-capable" framing is incomplete vis-à-vis fail-modes / 503 / 413

- **File:** `docs/async.md:25-31`
- **Category:** MISSING
- **Claim:** The async client example only handles 422 (blocked).
- **Reality:** `/v1/clean` can return:
  - HTTP 200 (cleaned content),
  - HTTP 422 (detector blocked),
  - HTTP 413 (payload over `BULWARK_MAX_CONTENT_SIZE`, default 256 KiB — ADR-042),
  - HTTP 503 (`error.code = "no_detectors_loaded"` — ADR-040).
- **Recommended fix:** Update the example client to also branch on 413 and 503 with `error.code` extraction, and add a one-line note about each. (CRITICAL for any production async caller; without 503/413 handling the caller may treat them as 5xx retries.)

---

### MINOR

#### 14. `docs/detection.md` — DeBERTa size note slightly stale

- **File:** `docs/detection.md:18`
- **Category:** MINOR / STALE
- **Claim:** "ungated, ~180 MB."
- **Reality:** ADR-031 says "ungated, 180 MB". Close enough. No fix needed unless a precise number matters; the ~ already softens it.

#### 15. `docs/detection.md` — "Standard tier achieves 100% defense on `deberta-only`" claim has no version anchor

- **File:** `docs/detection.md:69-71`
- **Category:** MINOR
- **Claim:** "The Standard tier achieves 100% defense on `deberta-only` as of v2.1.0."
- **Reality:** ADR-033 references the same number ("3,112 probes produced a 100% defense rate"). Number is stable but the "as of v2.1.0" anchor is a maintenance burden. Recommend a softer phrasing that points readers at the live red-team report instead of pinning a version.
- **Recommended fix:** "Run the Standard tier on your installed garak version to get a current defense-rate number (the v2.1.0 baseline was 100% on `deberta-only`)."

#### 16. `docs/detection.md` — "Adding a custom detector" still references `_detection_checks` as the integration point

- **File:** `docs/detection.md:73-88`
- **Category:** STALE / MINOR
- **Claim:** "The dashboard's `_detection_checks` dict maps integration name → check function." Implies the user wires their own dashboard plugin.
- **Reality:** Library-side integration is now via `Pipeline(detectors=[...])` or `Pipeline.from_config(path, detectors=[my_check])` (ADR-044). `_detection_checks` is a private dashboard-internal dict (`src/bulwark/dashboard/api_v1.py:236`); the `/v1/clean` route still iterates it, but the documented public surface for adding a check is the library Pipeline `detectors=` kwarg.
- **Recommended fix:** Show `Pipeline(detectors=[my_check])` as the canonical way to wire a custom check, with a separate sentence noting that the dashboard exposes the same surface via its integrations loader (link to `bulwark/integrations/promptguard.py` for the canonical example).

#### 17. `docs/layers.md` — Sanitizer "what it removes" list missing several real items

- **File:** `docs/layers.md:16-21`
- **Category:** MINOR
- **Claim:** Lists zero-width chars, invisible HTML/CSS, control chars + bidi overrides, emoji tag sequences, NFKC normalization.
- **Reality:** The Sanitizer also strips: `<script>`/`<style>` content (`_SCRIPT_RE`, `_STYLE_RE`), CSS `display:none` / `font-size:0` / `color:white` patterns (`_CSS_*_RE`), variation selectors and supplementary variation selectors (`_VARIATION_*_RE`), and — when `decode_encodings=True` — HTML entities + percent-encoding before the strip steps (`Sanitizer.decode_encodings`, B1 / ADR-039). NFKC is **off by default** (`normalize_unicode: bool = False`, `sanitizer.py:73`); the doc implies it's on.
- **Recommended fix:** Add `<script>`/`<style>` removal, CSS hide-text patterns, and HTML-entity / percent-decoding (encoding_resistant). Correct the NFKC default (off, opt-in).

#### 18. `docs/layers.md` — Sanitizer constructor example shows kwargs that don't include `decode_encodings`, `normalize_unicode`, `strip_emoji_smuggling`, `strip_bidi`, `strip_scripts`, `strip_control_chars`

- **File:** `docs/layers.md:25-32`
- **Category:** MINOR
- **Claim:** Example shows only 4 kwargs.
- **Reality:** The Sanitizer dataclass exposes ~12 toggles plus `custom_patterns: list[str]` and `emitter: Optional[EventEmitter]` (`sanitizer.py:65-83`).
- **Recommended fix:** Either trim the example with a comment like `# (see Sanitizer's docstring for the full list of toggles)`, or expand it to cover all the toggles.

#### 19. `docs/layers.md` — Canary `prefix` default not documented

- **File:** `docs/layers.md:60-84`
- **Category:** MINOR
- **Claim:** Doc shows `CanarySystem()` with no constructor args.
- **Reality:** `CanarySystem.prefix = "BLWK-CANARY"` by default (`canary.py:42`). Tokens are emitted as `BLWK-CANARY-<TAG>-<16-hex>`. Worth showing for ops who are searching their LLM logs.
- **Recommended fix:** Add a one-line example showing the default token shape.

#### 20. `docs/async.md` — "PromptGuard ~50 ms" is suspect for second-opinion path

- **File:** `docs/async.md:34-39`
- **Category:** MINOR / UNVERIFIED
- **Claim:** "PromptGuard | ~50 ms".
- **Reality:** `meta-llama/Prompt-Guard-86M` is mDeBERTa-base-sized (similar scale to the ProtectAI DeBERTa); the ~50ms figure is plausible but I couldn't find a benchmark anchor in the codebase. Not a defect, but operators may want a per-host calibration note. Optional.

#### 21. `docs/async.md` — Stale "rate limiting between LLM calls" mention assumes red-team

- **File:** Cross-reference: `docs/red-teaming.md:50` mentions "200ms" rate limiting. `async.md` doesn't repeat this and doesn't need to. No fix.

#### 22. `docs/async.md` — Async-LLM-judge section subtly wrong about thread vs. asyncio

- **File:** `docs/async.md:44-49`
- **Category:** MINOR
- **Claim:** "The LLM judge is invoked from inside `/v1/clean` synchronously (in a thread)..."
- **Reality:** The judge call is a synchronous `httpx.Client(...)` round-trip inside the request handler (`src/bulwark/detectors/llm_judge.py:149-152, 180-181`); the FastAPI route itself is `async def api_clean` and the synchronous httpx client blocks the event-loop thread until the judge replies. There's no thread-pool offload in the code path. The sentence is approximately right at the user-perception level (request stays linear) but mechanically misleading.
- **Recommended fix:** "The LLM judge is called synchronously from within `/v1/clean`, blocking the request until the judge replies. To parallelize across many inputs, fan out from your application using `asyncio.gather` over `httpx.AsyncClient.post('/v1/clean', ...)`."

---

## Restructural Recommendations

1. **Hoist a "v2 architecture overview" page that names the five stages once.** Right now `detection.md` describes detectors only, `layers.md` describes the library SDK, and the Pipeline shape (sanitizer → detector chain → trust boundary, plus the canary side-channel via `/v1/guard`) is implied but not pictured anywhere. Either add a top-of-page diagram to `detection.md` or extract a new `docs/architecture.md` that the other pages link into. The CLAUDE.md "five stages" framing isn't reflected in user-facing docs.

2. **Pull out a single canonical "ADR cross-reference" table.** Several findings (decode-rescan, fail-closed env vars, library/dashboard parity, split-evasion non-guarantee, judge fail-open semantics) point at ADRs the user-facing docs don't mention. A small ADR-to-feature map in `docs/architecture.md` (or a sidebar in each page) would make these discoverable.

3. **Disambiguate the "five layers" terminology between `layers.md` (library SDK abstractions) and `pipeline.py` (the detection-only run).** Today `layers.md` opens with "all five layers" but the page only documents three — and v2's per-request pipeline is logically four stages (sanitizer / detector chain / trust boundary, with canary as an output-side concern). Recommend either: rename `layers.md` → `library-usage.md`, or rename the page so it matches the detection-only count and clarifies that canaries are output-side.

4. **Move `docs/async.md` content into either `interfaces/http.md` or a new `operations/concurrency.md`.** The "async" framing is misleading — Bulwark v2 is sync request/response, FastAPI is the only async surface, and the doc's real value is "how to call us from an async client". A clearer title would also retire the unanswered question of whether there's a batch API (there isn't, beyond `Sanitizer.clean_batch` and `TrustBoundary.wrap_batch`).

5. **Add a "Known non-guarantees" page or section.** ADR-046 (split-evasion), NG-CLEAN-DECODE-VARIANTS-PRESERVED-001 (variant text doesn't reach the LLM), NG-JUDGE-003/004 (judge prompt fixed, judge text never returned) are all important to operators and there's no single place to find them.

---

## Summary stats

- 4 docs audited (`detection.md`, `layers.md`, `red-teaming.md`, `async.md`)
- **5 CRITICAL** findings (1 missing decode-rescan section, 1 wrong chunk numbers, 1 underspecified judge prompt, 1 wrong attack-count table, 1 stale "315" probe count)
- **8 IMPORTANT** findings (Pipeline.default semantics, missing detector layer in layers.md, missing fail-mode env vars, missing bridge_exploitation row, missing split-evasion non-guarantee, stale removed-LLM-tier mention, ProductionRedTeam example missing pipeline_url, async client missing 413/503 handling)
- **9 MINOR** findings (DeBERTa size, version anchor, custom-detector docs, sanitizer features list, sanitizer kwargs example, canary prefix default, PromptGuard latency, async-judge mechanism wording, plus an empty entry for completeness)
- **5 restructural recommendations** (architecture overview page, ADR cross-reference, "five layers" disambiguation, async.md repositioning, non-guarantees page)
