# ADR-047: Encoding Decoders for /v1/clean

**Status:** Accepted (v2.5.4)
**Related:** ADR-031 (v2 detection-only pipeline), ADR-032 (chunking), ADR-033 (LLM Judge), ADR-039 (Phase B1 — encoding_resistant for HTML/percent), ADR-046 (split-evasion non-guarantee)
**Author:** Phase H of Codex Efficacy Hardening

## Context

The 2026-04-29 Codex review found that `/v1/clean` does not detect prompt injections hidden in base64- or ROT13-encoded substrings. ADR-039 wired `encoding_resistant` to decode HTML entities and percent-encoding; base64 and ROT13 were left untreated. The attack catalog in `src/bulwark/attacks.py` already names `base64_instructions`, `base64_canary_bypass`, and `rot13_instructions` as known evasions.

Modern LLMs natively decode base64 and follow instructions inside, which makes encoded payloads a real-world threat in detection-only deployments — even if our DeBERTa detector classifies the *encoded* text as SAFE, the downstream LLM is happy to act on the *decoded* meaning.

## Decision

Add a `bulwark.decoders` module exposing `decode_rescan_variants(text, *, decode_base64) -> list[DecodedVariant]` that returns the original sanitized text plus zero or more decoded variants. `Pipeline.run()` runs the existing detector chain once per variant. Block on first detector hit on any variant. Trust boundary wraps the original cleaned text — variants exist only for detection.

**ROT13 is always on.** Rotated normal English is gibberish; detectors classify gibberish as SAFE; FP cost is effectively zero. The added cost is one detector chain pass on the rotated text per request.

**Base64 is opt-in via `decode_base64: bool = False`.** Substring scan with regex `[A-Za-z0-9+/_-]{20,}={0,2}` (covers standard + base64url; MIME-line-broken inputs handled by stripping whitespace before decode). Each candidate decodes; printable-ASCII quality gate (≥80% printable, ≥10 bytes) filters binary garbage like data-URI image bytes, OAuth tokens, and JWT signatures. Failed gates record a trace entry with the skip reason.

**Two-pass nested decoding.** A decoded variant is rescanned for further candidates; depth-2 covers `base64(rot13(...))` and `rot13(base64(...))`. Deeper nesting is documented as a non-guarantee.

**Per-request candidate cap of 16** prevents adversarial fan-out DoS. Beyond 16, candidates are logged + skipped with `skipped: candidate_cap`.

### Why decode-and-detect-parallel, not decode-and-substitute

Decode-and-substitute would replace base64 spans with decoded text, breaking the trust-boundary verbatim guarantee — legitimate base64 (images, JWTs, OAuth tokens) would be replaced with garbage and the downstream LLM would see corrupted content. Parallel detection preserves the original verbatim and adds detection coverage as a fan-out.

### Why a separate flag, not extend `encoding_resistant`

Existing operators opted into `encoding_resistant` for HTML/percent decoding. Silently extending its scope to include base64 (the highest-FP-risk decoder) would be a backwards-incompatible surprise. New flag keeps the operator decision in one place per concern.

### Why dashboard toggle parity

The existing `encoding_resistant` toggle is on the dashboard config page; operators looking for the base64 toggle will look in the same place. Adding it next to `encoding_resistant` is the discoverable choice. Default off; tooltip warns about FP risk in email/data-URI use cases.

## Consequences

### Positive

- Closes a real evasion class (base64-encoded injections).
- ROT13 always-on is free coverage.
- Trust boundary semantics preserved — original text reaches the downstream LLM verbatim.
- FP risk is gated by an explicit operator decision (`decode_base64` flag).
- Two-pass depth covers realistic threat without unbounded recursion.

### Negative

- Per-request cost: +1 detector chain pass for ROT13 (always); +N for base64 candidates (when enabled).
- Adversarial inputs with many base64-shaped substrings can hit the candidate cap and skip detection on the rest. Cap is logged.
- Base64 false positives are real — operators in email-heavy environments should leave `decode_base64=False` and rely on the LLM Judge.
- Decoded variants visible in the trace's `decoded_variants` field — operators can see what was tried.

### Neutral

- The current `encoding_resistant` flag keeps its existing scope (HTML entities + percent encoding); no behaviour change.
- Punycode, hex, and unicode-escape decoders are explicitly out of scope for this ADR. If real attacks emerge, future ADR.

## Migration

No migration needed. Default `decode_base64=False` matches prior behaviour. Operators who want the new coverage flip the flag in config or env.

## Tests

- Unit tests in `tests/test_decoders.py` cover `decode_rescan_variants` semantics, quality gate, candidate cap, base64 variants (standard + url-safe + MIME-line-broken), nested decoding.
- Integration tests in `tests/test_clean_decode.py` exercise `/v1/clean` with the existing attack catalog (`base64_instructions`, `rot13_instructions`).
- E2E tests in `tests/test_e2e_real_detectors.py` add 2 canonical encoded samples under `@pytest.mark.e2e_slow`.
- False-positive corpus (`spec/falsepos_corpus.jsonl`) gains benign base64 samples for empirical FP measurement.
