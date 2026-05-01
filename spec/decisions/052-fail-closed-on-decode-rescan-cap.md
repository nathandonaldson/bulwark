# ADR-052: Fail closed when base64 decode-rescan candidate cap is exhausted

**Status:** Accepted
**Date:** 2026-05-01

## Context

ADR-047 introduced base64 + ROT13 decode-rescan in `/v1/clean` (v2.5.4). To bound CPU work per request, `bulwark.decoders` enforced a per-request candidate cap (`_CANDIDATE_CAP = 16`). When the cap was reached, later base64 candidates were emitted as `DecodedVariant(skipped=True, skip_reason='candidate_cap')` and processing continued. Both `Pipeline.run` (library) and `api_v1.api_clean` (dashboard) skipped variants marked `skipped=True` before running detectors.

An OpenAI Codex Cloud security scan (commit `c8157cf`) validated a high-severity bypass: an attacker who prepends 16 harmless base64 spans before a malicious base64-encoded prompt injection causes the malicious 17th candidate to be skipped by the cap. The detectors never see it; the trust boundary wraps the original encoded payload; the downstream LLM receives the injection. The bypass is reliable, low-complexity, and works whenever `decode_base64=True` is enabled.

The cap was correct as a CPU-budget protection but wrong as a security primitive: silently dropping work that would otherwise be classified is incompatible with detection-as-a-security-boundary.

## Decision

Fail closed when the candidate cap is exhausted. Specifically, if any variant in the decoded fan-out is `skipped=True` with `skip_reason='candidate_cap'`, the request blocks before the detector chain runs:

- `/v1/clean`: HTTP 422, `blocked_at = "decoders"`, `block_reason = "Decoder blocked: base64 candidate cap exceeded"`. New guarantee `G-CLEAN-DECODE-CANDIDATE-CAP-FAIL-CLOSED-001`.
- `Pipeline.run()`: returns `PipelineResult(blocked=True, block_reason="Decoder blocked: base64 candidate cap exceeded")`. Same guarantee covers both paths (parity with ADR-044/048).

This extends the fail-closed pattern from ADR-040 ("fail closed when detection is impossible because no detectors are loaded") to a related case ("fail closed when detection is incomplete because the budget was exhausted before the work was done").

The cap value itself is unchanged in this ADR (still `_CANDIDATE_CAP = 16`). Operators who see legitimate emails blocked because they contain >16 base64 fragments can either raise the cap (recompile) or accept the block.

## Consequences

### Positive
- Closes the validated bypass. An attacker can no longer pad the request with harmless base64 to push their malicious payload past the cap.
- Architectural consistency with ADR-040: budget-exhausted detection is detection-impossible by another name.
- Behavior is the same for the library and the dashboard — preserves ADR-044/048 parity.

### Negative
- False-positive risk: any legitimate request with >16 base64-shaped substrings now blocks. Forwarded message chains, attachment-heavy emails, and base64-rich technical docs are the most likely false-positive sources.
- The cap is now a security-relevant primitive, not just a CPU-budget one. Future increases need to balance attacker work-factor against false-positive rate.

### Neutral
- The cap is only active when `decode_base64=True` (opt-in, default off). Operators not using base64 decode-rescan are unaffected.
- ROT13 decode-rescan does not have a candidate cap (always-on, single-pass), so this fix does not apply to it.
- Trust boundary continues to wrap the original cleaned text — this fix only blocks the request before that wrap, it doesn't change what reaches the boundary in passing requests.

## Alternatives considered

- **Decode the over-cap candidates anyway** — rejected: defeats the CPU-budget purpose. An attacker could submit a request with thousands of base64 candidates and tie up the worker.
- **Decode only the LAST cap candidates (FILO instead of FIFO)** — rejected: the bypass becomes "prepend N+1 harmless base64 spans" instead of "prepend N", which doesn't fix anything.
- **Random sampling of cap candidates** — rejected: probabilistic security is unacceptable here.
- **Raise the cap to a much higher value (e.g. 1024)** — rejected as a sole fix: still bypassable with enough padding, just at a higher attack cost. Could be combined with fail-closed for defense in depth, but isn't part of this ADR.

## Related
- ADR-040 (fail closed when no detectors loaded) — the architectural pattern this extends.
- ADR-044 / ADR-048 (library/dashboard parity) — the requirement that drove fixing both paths.
- ADR-047 (decode-rescan introduction) — the original architectural decision being patched.
- Codex Cloud finding `2e18f268a58c8191af3f4d6dfa05c385` (the source).
