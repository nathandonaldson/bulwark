# ADR-048: Shared detector-chain helper + judge-all-variants semantic

**Status:** Accepted (v2.5.7)
**Date:** 2026-04-30
**Related:** ADR-031 (v2 detection-only pipeline), ADR-033 (LLM Judge fail-open semantics), ADR-037 (judge prompt fixed in code), ADR-044 (library ↔ dashboard parity), ADR-047 (encoding decoders / decode-rescan architecture)
**Author:** Phase H follow-up (Codex efficacy hardening, Tasks 9 + 10)

## Context

Phase H (PR #44, v2.5.5) shipped encoding decoders for `/v1/clean`. The
detector chain now fans out across decoded variants: original, rot13,
optional base64@... candidates, plus depth-2 nested combinations
(ADR-047). Both `Pipeline.run()` (the library path) and `api_v1.api_clean`
(the dashboard HTTP handler) iterate that variant list.

Two problems with that arrangement, both surfaced by the post-Phase-H
code-quality review:

### Problem 1 — Behavioural drift (parity erosion)

`G-PIPELINE-PARITY-001` (ADR-044) says the library `Pipeline.run()` and
the dashboard `/v1/clean` handler MUST produce the same block decision
for the same input. The Phase H fan-out duplicated the chain-execution
logic in both places, and the duplicates already drifted:

- **Dashboard** `api_v1.py` (the judge block, lines 308-326 of v2.5.6):
  on the FIRST variant where the judge returned `ERROR` or `UNPARSEABLE`,
  the loop set `judge_blocked_variant = variant.label` and `break`-ed.
  Subsequent variants were never sent to the judge — even when
  `fail_open=True`.
- **Library** `pipeline.py` `_build_judge_check()`: raises a
  `SuspiciousPatternError` only on `INJECTION` (always) or on `ERROR` /
  `UNPARSEABLE` when `fail_open=False`. With the default `fail_open=True`,
  judge ERROR on one variant did NOT short-circuit — every subsequent
  variant was still scanned by the judge.

So identical inputs hitting both paths could produce different block
decisions in the judge ERROR + fail-open case. That is exactly the
parity gap `G-PIPELINE-PARITY-001` exists to prevent.

### Problem 2 — Defense gap (H.2)

The dashboard's short-circuit creates a real attack vector. With
`fail_open=True` (the default), an attacker who can engineer the
`original` variant text to make the judge endpoint choke — oversize
input, malformed structure, prompt injection in the input that breaks
the judge's parser, transient HTTP error — gets the judge to return
`ERROR` on the original variant. The dashboard's `break` then means the
encoded variants (rot13, any base64 spans) are NEVER scanned by the
judge. The attacker hides the real injection in the encoded variant and
the judge never sees it. The ML detectors might still catch it, but the
judge — the one detector that reads the full prompt with cross-attention
and is supposed to be the safety net for encoded payloads ADR-047
specifically calls out — has been bypassed.

This is a worse outcome than just the parity drift: the library path
already does the right thing here (it keeps scanning), but the
production HTTP endpoint operators actually deploy is the one with the
gap.

## Decision

### 1. Factor the variant fan-out into a single shared module

Add `bulwark/detector_chain.py` containing `run_detector_chain(...)`.
Both `Pipeline.run()` and `api_v1.api_clean` delegate to it. The helper
contains zero FastAPI / dashboard imports — pure logic, no I/O beyond
calling the detector callables it was given.

The helper accepts:

- A precomputed `variants: list[DecodedVariant]` (the caller decides
  whether to call `decode_rescan_variants` itself, since the dashboard
  may want to reuse cached variants for SSE event emission).
- An ordered iterable of detector callables (the existing
  `_detection_checks` shape: `text -> dict`, raises
  `SuspiciousPatternError` on hit).
- An optional judge callable + `judge_fail_open` flag (because the judge
  has different fail-open semantics from regular detectors and the
  helper needs to honour them).
- A trace-recording hook for callers that need per-variant trace events
  (e.g. SSE streaming).

It returns a `ChainResult` dataclass: `blocked`, `blocked_at_variant`,
`blocked_reason`, `blocked_detector`, plus the list of trace records the
caller can splice into its own response shape.

### 2. Judge runs on EVERY non-skipped variant regardless of fail-open ERROR

`G-CLEAN-DECODE-JUDGE-ALL-VARIANTS-001`: when the judge is enabled and
`fail_open=True`, judge ERROR / UNPARSEABLE on one variant is logged +
recorded in the trace but does NOT short-circuit the chain. Remaining
variants are still scanned by the judge. The chain blocks on:

- The first detector or judge `INJECTION` verdict on any variant, OR
- A judge `ERROR` / `UNPARSEABLE` on any variant when
  `fail_open=False` (the existing fail-closed semantic).

This is purely a fail-open behaviour change — fail-closed deployments
already block on the first ERROR, so they exhibit the same observable
behaviour before and after this ADR.

### 3. Why a new ADR (not an extension to ADR-047)

ADR-047 documents the decode-rescan ARCHITECTURE: which encodings to
attempt, the quality gate, the per-request candidate cap, the
trust-boundary verbatim guarantee. ADR-048 documents the chain-execution
SEMANTIC: who runs in what order across the variants, what
short-circuits, and how fail-open ERROR composes with fan-out. Different
concerns, different ADRs.

## Consequences

### Positive

- `G-PIPELINE-PARITY-001` is upheld for the judge ERROR + fail-open
  case, and a single shared helper makes future drift mechanically
  harder (you'd have to bypass the helper, not just edit one of two
  copies).
- The H.2 defense gap closes: encoded variants are always scanned by
  the judge, even when an attacker engineers the original text to
  make the judge choke.
- Both call sites shrink dramatically (the variant fan-out shrinks from
  ~80-100 lines per call site to a single helper invocation).
- The helper has zero dashboard / FastAPI imports — the library path
  no longer carries detection logic that's hard to reuse outside HTTP.

### Negative — judge cost when `fail_open=True`

This is the load-bearing operational consequence. **When the judge is
enabled and `fail_open=True`, every request now incurs N judge
round-trips** where N is the number of non-skipped decoded variants
(typically 1–~20, bounded by the candidate cap of 16 plus original +
rot13).

For metered judge endpoints this is real money. Operators on a
per-token-priced judge backend (OpenAI, Anthropic) should:

1. Monitor judge call volume after this release. The
   `bulwark.detection.llm_judge` log channel records each call.
2. Consider keeping `decode_base64=False` (the default) so N is bounded
   to ~2 (original + rot13) instead of up to ~20.
3. Or set `judge_backend.fail_open=False` if every additional judge
   round-trip on ERROR is unacceptable — fail-closed mode short-circuits
   on the first ERROR (existing pre-Phase-H semantic), at the cost of
   blocking legitimate traffic when the judge is transiently down.

The pre-Phase-H semantic (judge runs on `original` only) IS still
available — set `decode_base64=False` AND ensure the original variant
already triggers the judge — but ADR-047's whole point was that
encoded payloads are a real evasion class, so reverting to it is a
defense regression.

### Neutral

- Trust-boundary semantics are unchanged. The helper does not touch the
  trust boundary; both callers wrap the original cleaned text after the
  helper returns.
- Trace shape (`decoded_variants[]`, `blocked_at_variant`) is unchanged.
  The helper produces the same trace records the dashboard built
  inline; the dashboard splices them into its existing response.
- Skipped variants are still recorded in the trace but not run through
  detectors or the judge — same as before.

## Migration

No config migration required. No env-var changes. No HTTP surface
changes (request / response shapes unchanged).

Operators on metered judge endpoints with `fail_open=True` should
monitor judge call volume after upgrading. If the increase is
unacceptable, `decode_base64=False` (default) bounds N to 2; setting
`fail_open=False` reverts to short-circuit-on-error semantics.

## Tests

- `tests/test_detector_chain.py` — unit tests for `run_detector_chain`
  covering: SAFE on all variants, INJECTION on the original variant
  short-circuits, INJECTION on a later variant blocks (no earlier
  variant reached the judge), judge ERROR on original variant in
  fail-open mode does NOT short-circuit (the new H.2 semantic), judge
  ERROR in fail-closed mode DOES short-circuit (existing semantic).
- `tests/test_clean_decode.py` — integration coverage:
  `test_judge_error_on_original_does_not_skip_encoded_variants` (the
  H.2 regression test), `test_library_and_dashboard_block_identically_on_fake_chain`
  (the parity test exercising both call sites against the same fake
  detector chain).
- `tests/test_pipeline_parity.py` — existing Phase E tests must still
  pass; the new helper is the implementation strategy that upholds
  `G-PIPELINE-PARITY-001`, not a replacement for it.
