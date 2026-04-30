"""Decode-rescan helpers for /v1/clean.

Returns variant texts for the detector chain to evaluate. ROT13 is always
attempted; base64 is opt-in via the decode_base64 parameter. Two-pass nested
decoding bounds depth. Per-request candidate cap of 16 prevents adversarial
fan-out.

See ADR-047 for the architectural rationale and
docs/superpowers/specs/2026-04-30-phase-h-encoding-decoders-design.md for
the design doc.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Standard + url-safe base64 alphabet, length >=20 chars, optional padding.
# Whitespace inside is tolerated by stripping before decode (handles MIME
# line-broken base64); the regex itself does not match whitespace because
# we want to bound the candidate span to a contiguous run of base64 chars.
_BASE64_RE = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")

_CANDIDATE_CAP = 16
_MIN_DECODED_BYTES = 10
_MIN_PRINTABLE_RATIO = 0.80


@dataclass(frozen=True)
class DecodedVariant:
    """A candidate text for the detector chain.

    Original input is always returned as the first variant with
    label='original' and depth=0. Decoded variants get labels identifying
    their source span (e.g. 'rot13', 'base64@45:81', or nested
    'base64@45:81/rot13').

    Variants flagged with skipped=True were rejected by the quality gate
    or candidate cap and should NOT be fed to detectors. They are returned
    so the trace can record what was tried.
    """
    label: str
    text: str
    depth: int
    skipped: bool = False
    skip_reason: Optional[str] = None


def decode_rescan_variants(
    text: str,
    *,
    decode_base64: bool,
    max_depth: int = 2,
) -> list[DecodedVariant]:
    """Return original + decoded variants for the detector chain.

    See ADR-047 for the architecture. ROT13 is always attempted (zero-FP
    cost). Base64 is attempted only when decode_base64=True. Substring
    scan finds candidates; printable-ASCII quality gate filters binary
    garbage. Nested decoding bounded at max_depth=2.
    """
    variants: list[DecodedVariant] = []
    seen_texts: set[str] = set()

    def _add(variant: DecodedVariant) -> None:
        # Skipped variants always recorded (so trace can audit). Non-skipped
        # variants deduplicate on text — a depth-2 ROT13 of the rot13 variant
        # would round-trip back to the original; no need to send the same
        # string through the detectors twice.
        if not variant.skipped:
            if variant.text in seen_texts:
                return
            seen_texts.add(variant.text)
        variants.append(variant)

    # Original always first. Track its text so a downstream pass that produces
    # the same string won't queue a redundant detector run.
    original = DecodedVariant(label="original", text=text, depth=0)
    seen_texts.add(text)
    variants.append(original)

    if not text:
        return variants

    # Per-request candidate cap is enforced inside _decode_one_pass via the
    # mutable counter below. Cap is on base64 candidates encountered across
    # both passes — the worst-case adversarial fan-out vector.
    state = {"candidate_count": 0}

    def _decode_one_pass(
        in_text: str,
        parent_label: Optional[str],
        depth: int,
    ) -> list[DecodedVariant]:
        """Run one decoding pass over in_text. Returns new variants discovered."""
        new_variants: list[DecodedVariant] = []

        # ROT13 is always attempted at every depth.
        if isinstance(in_text, str) and in_text:
            rot13_text = codecs.encode(in_text, "rot_13")
            if rot13_text != in_text:
                label = "rot13" if parent_label is None else f"{parent_label}/rot13"
                new_variants.append(DecodedVariant(label=label, text=rot13_text, depth=depth))

        # Base64 candidates (opt-in).
        if decode_base64:
            for match in _BASE64_RE.finditer(in_text):
                if state["candidate_count"] >= _CANDIDATE_CAP:
                    label = (
                        f"base64@{match.start()}:{match.end()}"
                        if parent_label is None
                        else f"{parent_label}/base64@{match.start()}:{match.end()}"
                    )
                    new_variants.append(DecodedVariant(
                        label=label,
                        text="",
                        depth=depth,
                        skipped=True,
                        skip_reason="candidate_cap",
                    ))
                    continue
                state["candidate_count"] += 1

                span = match.group(0)
                start, end = match.start(), match.end()
                label_base = f"base64@{start}:{end}"
                label = label_base if parent_label is None else f"{parent_label}/{label_base}"

                decoded_bytes = _try_decode_base64(span)
                if decoded_bytes is None:
                    new_variants.append(DecodedVariant(
                        label=label,
                        text="",
                        depth=depth,
                        skipped=True,
                        skip_reason="decode_failed",
                    ))
                    continue

                accept, reason = _quality_gate(decoded_bytes)
                if not accept:
                    new_variants.append(DecodedVariant(
                        label=label,
                        text="",
                        depth=depth,
                        skipped=True,
                        skip_reason=reason,
                    ))
                    continue

                decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                new_variants.append(DecodedVariant(
                    label=label,
                    text=decoded_text,
                    depth=depth,
                ))

        return new_variants

    # Pass 1: decode from original.
    pass_1_variants = _decode_one_pass(text, parent_label=None, depth=1)
    for v in pass_1_variants:
        _add(v)

    # Pass 2: decode from each non-skipped pass-1 variant (bounded by max_depth).
    if max_depth >= 2:
        for v in pass_1_variants:
            if v.skipped or not v.text:
                continue
            pass_2_variants = _decode_one_pass(v.text, parent_label=v.label, depth=2)
            for v2 in pass_2_variants:
                _add(v2)

    return variants


def _try_decode_base64(span: str) -> Optional[bytes]:
    """Attempt to decode a base64 span. Returns None on failure.

    Tolerates url-safe alphabet, missing padding, and embedded whitespace.
    """
    cleaned = "".join(span.split())  # strip any embedded whitespace
    # Pad to multiple of 4 if missing.
    pad = (-len(cleaned)) % 4
    if pad:
        cleaned = cleaned + ("=" * pad)
    # Try url-safe first if the span has - or _; else standard.
    try:
        if "-" in cleaned or "_" in cleaned:
            return base64.urlsafe_b64decode(cleaned)
        return base64.b64decode(cleaned, validate=False)
    except (binascii.Error, ValueError) as exc:
        logger.debug("base64 decode failed for span len=%d: %s", len(cleaned), exc)
        return None


def _quality_gate(decoded: bytes) -> tuple[bool, Optional[str]]:
    """Return (accept, skip_reason). skip_reason is populated only on rejection.

    Gates:
      - Length >= 10 bytes (filters tiny / nonsensical decodes).
      - Decodes as UTF-8 (replace mode tolerates a few invalid bytes).
      - Printable-ASCII ratio >= 0.80 across the decoded text.
    """
    if len(decoded) < _MIN_DECODED_BYTES:
        return False, "too_short"
    text = decoded.decode("utf-8", errors="replace")
    if not text:
        return False, "not_utf8"
    printable = sum(1 for c in text if c.isprintable() or c in ("\n", "\r", "\t"))
    ratio = printable / len(text)
    if ratio < _MIN_PRINTABLE_RATIO:
        return False, f"low_printable_ratio:{ratio:.2f}"
    return True, None
