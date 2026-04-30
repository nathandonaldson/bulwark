# Phase H — Encoding Decoders Design Spec

**Date:** 2026-04-30
**Author:** brainstorm session, claude-code
**Status:** Draft — awaiting Nathan's review before plan

## Goal

`/v1/clean` blocks prompt injections hidden inside **base64**-encoded or **ROT13**-rotated text, without breaking the trust boundary's verbatim-content guarantee or producing false positives on legitimate base64 (images, JWTs, OAuth tokens, hashes).

## Architecture (locked during brainstorm)

New `bulwark.decoders` module exposes `decode_rescan_variants(text, *, decode_base64) -> list[DecodedVariant]` that returns the original sanitized text plus zero or more decoded variants. The `Pipeline` runs the existing detector chain (DeBERTa + PromptGuard + optional judge) **once per variant**. If any variant trips `SuspiciousPatternError`, the pipeline blocks. Trust boundary wraps the original cleaned text — variants exist only for detection, never for output.

Decode-rescan is a fan-out around the detector chain, not a step in it.

**Key invariants:**
- Original (sanitized) text is what reaches the trust boundary — always.
- Decoded variants never appear in any response body.
- ROT13 is always attempted (zero FP cost; rotated normal English is gibberish that detectors classify SAFE).
- Base64 is opt-in via `decode_base64` flag (default off).
- When `decode_base64=False`, the only added cost is one ROT13 pass + one detector run per request.
- Two-pass nested decoding is supported (`base64(rot13(...))`, `rot13(base64(...))`); deeper nesting is a non-guarantee.

## Public API

```python
# bulwark/decoders.py

from dataclasses import dataclass

@dataclass(frozen=True)
class DecodedVariant:
    """A candidate text for detection. Original or decoded."""
    label: str          # "original" | "rot13" | "base64@<start>:<end>" | nested labels e.g. "base64@10:42/rot13"
    text: str           # the candidate text to feed detectors
    depth: int          # 0 = original, 1 = first-pass decoded, 2 = second-pass decoded


def decode_rescan_variants(
    text: str,
    *,
    decode_base64: bool,
    max_depth: int = 2,
) -> list[DecodedVariant]:
    """Return original + decoded variants for detection.

    The original text is always the first variant.

    ROT13 is always attempted (one variant added if the rotated text
    differs meaningfully from the original — which it always does for
    non-empty text).

    Base64 is attempted only when decode_base64=True. Substring scan
    with regex r'[A-Za-z0-9+/]{20,}={0,2}'. Each match becomes a
    candidate. Each candidate is decoded; the result must pass the
    quality gate (>=80% printable ASCII, length >= 10) to become a
    variant. Failed decodes are silently dropped (logged at DEBUG).

    Nested decoding: if a decoded variant itself contains base64-shaped
    spans, those are decoded recursively up to max_depth=2.
    """
```

**Why a list of variants instead of a generator:** the detector chain may parallelize across variants in a future pass; explicit list is cheaper to reason about. Variant count is bounded by candidate count × decoders × depth, which is small in practice.

**Why a frozen dataclass instead of a tuple:** trace records reference variant labels; named fields are clearer than tuple indices.

## Pipeline integration

`src/bulwark/pipeline.py`:

```python
def run(self, text: str) -> PipelineResult:
    cleaned = self.sanitizer(text) if self.sanitizer else text

    variants = decode_rescan_variants(
        cleaned,
        decode_base64=self._decode_base64,
    )

    # Each variant runs through the full detector chain.
    # First variant that trips raises; trace records which.
    for variant in variants:
        for detector in self.detectors:
            try:
                detector(variant.text)
            except SuspiciousPatternError as exc:
                exc.detail = f"variant={variant.label}: {exc.detail}"
                raise

    return PipelineResult(text=self.trust_boundary(cleaned), ...)
```

The existing detector chain remains untouched. Decode-rescan is a new outer loop. Pipelines without `decode_base64=True` and without ROT13-shaped input still pay the cost of one ROT13 pass through the chain (cheap; one DeBERTa inference).

## Configuration

`src/bulwark/dashboard/config.py`:

```python
@dataclass
class BulwarkConfig:
    # ... existing fields ...
    decode_base64: bool = False  # ADR-047
```

Env override: `BULWARK_DECODE_BASE64=1` (uses existing `env_truthy()` helper from Phase A). Phase A's `env_truthy()` parser handles all opt-in env vars consistently.

Dashboard toggle on the existing config page, alongside `encoding_resistant`. Tooltip:
> "When on, /v1/clean detects prompt injections hidden in base64-encoded substrings. May increase false positives in content with legitimate base64 (data URIs, JWTs, OAuth tokens). Off by default. See ADR-047."

`Pipeline.from_config()` (Phase E) reads `cfg.decode_base64` and passes it to the decode-rescan step.

## Trace shape

The detector trace gains a `decoded_variants` field listing all variants tried:

```json
{
  "blocked": true,
  "block_reason": "Detector protectai: variant=base64@45:81: ...",
  "trace": {
    "decoded_variants": [
      {"label": "original", "depth": 0, "skipped": false},
      {"label": "rot13", "depth": 1, "skipped": false},
      {"label": "base64@45:81", "depth": 1, "skipped": false},
      {"label": "base64@110:142", "depth": 1, "skipped": true, "skip_reason": "low_printable_ratio:0.42"}
    ],
    "blocked_at_variant": "base64@45:81",
    ...
  }
}
```

Trace lets operators audit decode decisions (was the binary-looking span correctly skipped? was the rotated text checked?). Skipped reasons are documented in the contract.

## Quality gate

```python
def _quality_gate(decoded: bytes) -> tuple[bool, str | None]:
    """Return (accept, skip_reason). skip_reason populated only on rejection."""
    if len(decoded) < 10:
        return False, "too_short"
    try:
        text = decoded.decode("utf-8", errors="replace")
    except Exception:
        return False, "not_utf8"
    printable = sum(1 for c in text if c.isprintable() or c in ("\n", "\r", "\t"))
    ratio = printable / len(text)
    if ratio < 0.8:
        return False, f"low_printable_ratio:{ratio:.2f}"
    return True, None
```

## SSD artifacts to ship

**ADR-047:** Phase H encoding decoders. Covers:
- Empirical motivation: Codex review found base64-encoded injections evade today's detector chain.
- Architecture choice (decode-and-detect-parallel; rejected substitute and inline-concat).
- ROT13 always-on rationale.
- Base64 opt-in rationale (FP risk in email/data-URI use cases).
- Two-pass depth bound (covers realistic threat; deeper bounded by judge).
- Quality gate (printable-ASCII ratio).
- Dashboard toggle parity with `encoding_resistant`.

**New guarantees** (in `spec/contracts/clean.yaml`):
- `G-CLEAN-DECODE-ROT13-001`: `/v1/clean` MUST attempt ROT13 decoding on every request and run the detector chain on the decoded text. Always on.
- `G-CLEAN-DECODE-BASE64-001`: When `decode_base64=True`, `/v1/clean` MUST scan for base64-shaped substrings, decode those that pass the quality gate, and run the detector chain on each. Substring regex: `[A-Za-z0-9+/]{20,}={0,2}`. Quality gate: ≥80% printable ASCII, ≥10 decoded bytes.

**New non-guarantees** (same file):
- `NG-CLEAN-DECODE-NESTED-001`: Encoding nesting beyond depth 2 is NOT guaranteed to be detected. Operators relying on defense against deeply nested encodings should enable the LLM Judge.
- `NG-CLEAN-DECODE-BASE64-FP-001`: When `decode_base64=True`, requests containing legitimate base64 substrings (images, OAuth tokens, hashes) may produce false positives. Quality gate mitigates but does not eliminate. Mitigation: keep `decode_base64=False` for email/attachment-heavy use cases and rely on the LLM Judge.
- `NG-CLEAN-DECODE-VARIANTS-PRESERVED-001`: Decoded variants are NEVER returned in `/v1/clean` response bodies. Trust boundary wraps the original cleaned text. The trace records variant labels but not decoded content.

**OpenAPI:** no surface change. `/v1/clean` still returns 200 / 422 / 503 / 401 / 413 with the same envelope shapes. The trace's `decoded_variants` field is documented as an optional addition to the existing trace schema.

## Testing strategy

**Unit tests** (`tests/test_decoders.py`):
- `decode_rescan_variants` returns just `original + rot13` when `decode_base64=False`.
- Returns `original + rot13 + base64@…` when `decode_base64=True` and a base64-shaped span is present.
- Quality gate rejects short decodes, non-UTF-8, low-printable-ratio decodes.
- Nested decoding: `base64(rot13("ignore previous instructions"))` produces both layers.
- Substring scan regex handles MIME line-broken base64 (CRLF + 76-char wraps); whitespace stripped before decoding.
- base64url variant (`-_` instead of `+/`) is also accepted.
- Empty/short input returns just `original`.

**Integration tests** (`tests/test_clean_decode.py`):
- Existing attacks from `src/bulwark/attacks.py` actually block: `base64_instructions`, `base64_canary_bypass`, `rot13_instructions`.
- `decode_base64=False` (default): base64 attacks pass through (regression-prevention test that the flag actually gates).
- ROT13 attacks block regardless of `decode_base64` flag.
- Trace contains `decoded_variants` and `blocked_at_variant`.

**E2E tests** (`tests/test_e2e_real_detectors.py`, `@pytest.mark.e2e_slow`):
- Add 2 new canonical samples to ADR-045's e2e suite: one base64-encoded "ignore all previous instructions" and one ROT13-encoded equivalent. With real ProtectAI DeBERTa weights they should both block.

**False-positive corpus** (`spec/falsepos_corpus.jsonl`):
- Add benign base64 samples: data URI fragment, JWT header, sample OAuth token, MIME-encoded text. Ensure they pass with `decode_base64=True`. (May not — that's the point: measure FP rate empirically.)

## File layout

| Path | Action |
|------|--------|
| `src/bulwark/decoders.py` | Create — new module with `decode_rescan_variants` + helpers |
| `src/bulwark/pipeline.py` | Modify — add decode-rescan loop in `Pipeline.run()` |
| `src/bulwark/dashboard/config.py` | Modify — add `decode_base64: bool = False` field |
| `src/bulwark/dashboard/static/src/page-config.jsx` (or wherever the toggle lives) | Modify — add toggle UI |
| `spec/decisions/047-encoding-decoders.md` | Create — ADR |
| `spec/contracts/clean.yaml` | Modify — add 2 G + 3 NG entries |
| `spec/openapi.yaml` | Modify — document `decoded_variants` trace field |
| `tests/test_decoders.py` | Create — unit tests |
| `tests/test_clean_decode.py` | Create — integration tests |
| `tests/test_e2e_real_detectors.py` | Modify — add 2 canonical samples |
| `spec/falsepos_corpus.jsonl` | Modify — add benign base64 samples |
| `VERSION` | Bump 2.5.3 → 2.5.4 (patch — feature behind opt-in flag, default off) |
| `CHANGELOG.md` | Add v2.5.4 entry |

## Performance notes

**Cost when `decode_base64=False`:** one ROT13 string transform (microseconds) + one extra detector chain pass on the rotated text. For a typical request with 2 detectors at ~20ms each, this is +40ms. **Acceptable.**

**Cost when `decode_base64=True`:**
- Substring scan: regex over input, microseconds.
- Per candidate: base64 decode (microseconds) + quality gate (microseconds) + detector chain pass (~40ms).
- Two-pass nested: at most one additional pass per candidate.
- Real-world: most requests have 0 base64 candidates and pay only the substring-scan cost (microseconds).

**Worst case:** an adversarial input full of base64-shaped substrings could trigger many candidates. ADR-047 will document the per-request candidate cap (proposed: 16 candidates max; beyond that, log + skip the rest with a `skipped: candidate_cap` trace entry).

## Out of scope

- Hex / unicode-escape / punycode — explicitly not included (Question 1 picked option b: base64 + ROT13). Future ADR if real attacks emerge.
- base64-decoding inside the LLM Judge prompt construction — the judge sees the original text and is smart enough to suspect base64 itself.
- Sanitizer integration of base64 (decode-and-substitute path) — explicitly rejected (Question 3 option a). Trust boundary verbatim guarantee preserved.
- Modifying `Sanitizer.decode_encodings` semantics — separate flag, separate concern.

## Self-review checklist

- [x] All Question 1–6 decisions reflected.
- [x] No placeholder text.
- [x] Public API signature is concrete.
- [x] Pipeline integration shown in code, not prose.
- [x] Trace shape is shown by example.
- [x] Quality gate is implementable from spec alone.
- [x] SSD artifact list is complete (ADR + 2 G + 3 NG).
- [x] Testing strategy covers unit + integration + e2e + FP corpus.
- [x] File layout maps every change to a path.
- [x] Performance section quantifies worst case.
- [x] VERSION bump rule (patch, opt-in feature) follows project convention.
