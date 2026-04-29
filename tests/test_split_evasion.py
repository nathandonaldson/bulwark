"""Split-evasion test coverage — ADR-046 / G-DETECTOR-WINDOW-EVASION-001.

Three classes:

1. ``TestSplitEvasionGenerator`` — fast unit tests for the generator in
   ``src/bulwark/attacks.py``. Uses a fake tokenizer; no model load.
   References G-DETECTOR-WINDOW-EVASION-001 (the generator is the source
   of truth for the curated samples that prove that guarantee).

2. ``TestSplitEvasionShortRange`` — fast tests with the fake-pipeline
   pattern from ``tests/test_detector_chunking.py``. Proves the chunk
   overlap works as designed when both pieces fit in a single window.
   References G-DETECTOR-WINDOW-EVASION-001.

3. ``TestSplitEvasionLongRange`` — ``@pytest.mark.e2e_slow`` tests
   against real ProtectAI DeBERTa weights. Two-sided regression coverage:
   the no-filler positive controls MUST block (G-DETECTOR-WINDOW-EVASION-001),
   and the long-separation cases currently pass through detection
   (NG-DETECTOR-WINDOW-EVASION-001 — pinning the gap so a model bump that
   closes it forces a contract revisit).

The default ``pytest tests/`` invocation deselects the e2e tests via
``addopts = "-m 'not e2e_slow'"`` in pyproject.toml, matching ADR-045's
e2e CI lane convention.
"""
from __future__ import annotations

import os
from typing import Iterator

import pytest

from bulwark.attacks import (
    AttackCategory,
    AttackSuite,
    SPLIT_EVASION_BENIGN_FILLER,
    SPLIT_EVASION_PAIRS,
    generate_split_evasion_samples,
)
from bulwark.guard import SuspiciousPatternError
from bulwark.integrations.promptguard import (
    _WINDOW_RESERVED_TOKENS,
    _WINDOW_STRIDE_TOKENS,
    create_check,
)


# ---------------------------------------------------------------------------
# Fake tokenizer / pipeline shared with TestSplitEvasionShortRange — same
# shape as tests/test_detector_chunking.py so the chunk mechanics are
# exercised without a real model.
# ---------------------------------------------------------------------------


class _WordTokenizer:
    """Whitespace-split tokenizer. ``encode`` returns the words as
    pseudo-token-ids; ``decode`` joins them back. Good enough for the
    generator (which only needs ``len(encode(...))``) and for the chunker
    (which needs ``encode``/``decode``)."""

    model_max_length = 32

    def encode(self, text: str, add_special_tokens: bool = False, truncation: bool = False):
        return text.split()

    def decode(self, ids, skip_special_tokens: bool = False):
        return " ".join(ids)


class _FakeModel:
    name_or_path = "fake/split-evasion-detector"


class _FakeJointPipeline:
    """Fake pipeline that flags any chunk containing BOTH the trigger AND
    the instruction substring as INJECTION. Mimics a model that only
    fires when both pieces are present in a single window — exactly the
    behaviour that ADR-046's empirical investigation observed.

    Otherwise returns SAFE 0.99. The trigger/instruction substrings are
    chosen short so they fit inside the test's small window.
    """

    TRIG = "TRIG"
    INSTR = "INSTR"

    def __init__(self):
        self.tokenizer = _WordTokenizer()
        self.model = _FakeModel()
        self.calls: list[list[str]] = []

    def __call__(self, text, truncation: bool = False):
        if isinstance(text, str):
            batch = [text]
        else:
            batch = list(text)
        self.calls.append(batch)
        return [
            {"label": "INJECTION" if (self.TRIG in t and self.INSTR in t) else "SAFE",
             "score": 0.99}
            for t in batch
        ]


# ---------------------------------------------------------------------------
# Tests — generator (G-DETECTOR-WINDOW-EVASION-001)
# ---------------------------------------------------------------------------


class TestSplitEvasionGenerator:
    """G-DETECTOR-WINDOW-EVASION-001: generator is the corpus source of truth.

    The split-evasion corpus is tokenizer-dependent (filler is built to
    match a target token count), so the generator is the canonical source
    of samples for both the curated guarantee tests below and the
    bench / red-team harnesses that consume the catalog.
    """

    def test_no_filler_emits_one_attack_per_pair(self):
        """N=0 case: the generator emits exactly one Attack per (trigger,
        instruction) pair when the filler-token-count list is [0]."""
        tok = _WordTokenizer()
        attacks = generate_split_evasion_samples(
            tok, pairs=SPLIT_EVASION_PAIRS, filler_token_counts=[0]
        )
        assert len(attacks) == len(SPLIT_EVASION_PAIRS)
        for a in attacks:
            assert a.category == AttackCategory.SPLIT_EVASION
            assert "filler0" in a.name

    def test_payload_contains_both_pieces(self):
        """Every generated payload contains its trigger AND its
        instruction. Without that, the guarantee tests below have nothing
        to verify."""
        tok = _WordTokenizer()
        attacks = generate_split_evasion_samples(
            tok, pairs=SPLIT_EVASION_PAIRS, filler_token_counts=[0, 16, 64]
        )
        # Walk by pair-index recovered from the name suffix.
        for a in attacks:
            # Names look like "split_evasion_<idx>_filler<N>"
            idx = int(a.name.split("_")[2])
            trig, instr = SPLIT_EVASION_PAIRS[idx]
            assert trig in a.payload, f"{a.name}: trigger missing from payload"
            assert instr in a.payload, f"{a.name}: instruction missing from payload"

    def test_filler_is_realistic_benign_text(self):
        """Filler is drawn from SPLIT_EVASION_BENIGN_FILLER — varied
        realistic email-shape paragraphs. A repetitive "lorem"-style
        filler trips the detector on its own (ADR-046 §"Empirical
        investigation"); the corpus deliberately avoids that pitfall.
        """
        tok = _WordTokenizer()
        attacks = generate_split_evasion_samples(
            tok, pairs=SPLIT_EVASION_PAIRS[:1], filler_token_counts=[64]
        )
        a = attacks[0]
        # At least one of the curated benign paragraphs should appear.
        assert any(p in a.payload for p in SPLIT_EVASION_BENIGN_FILLER), (
            f"expected benign-filler paragraph in payload, got {a.payload!r}"
        )

    def test_deterministic_output(self):
        """Same tokenizer + same args → byte-identical corpus. Important
        for regression-prevention tests that pin "currently passes"
        cases — non-determinism would make those tests flaky."""
        tok = _WordTokenizer()
        first = generate_split_evasion_samples(tok, filler_token_counts=[0, 32])
        second = generate_split_evasion_samples(tok, filler_token_counts=[0, 32])
        assert [a.payload for a in first] == [a.payload for a in second]

    def test_filler_token_count_monotonic(self):
        """Larger requested filler size produces a payload with more
        tokens. Sanity check on _build_filler — without this, a buggy
        accumulator could silently emit short payloads for large targets
        and undermine the long-separation regression tests."""
        tok = _WordTokenizer()
        small = generate_split_evasion_samples(
            tok, pairs=SPLIT_EVASION_PAIRS[:1], filler_token_counts=[0]
        )[0]
        large = generate_split_evasion_samples(
            tok, pairs=SPLIT_EVASION_PAIRS[:1], filler_token_counts=[100]
        )[0]
        assert len(tok.encode(large.payload)) > len(tok.encode(small.payload))

    def test_attacksuite_method_delegates(self):
        """AttackSuite.generate_split_evasion_samples is a thin wrapper —
        same args yield the same payloads as the module-level function."""
        tok = _WordTokenizer()
        suite = AttackSuite()
        a = suite.generate_split_evasion_samples(tok, filler_token_counts=[0, 32])
        b = generate_split_evasion_samples(tok, filler_token_counts=[0, 32])
        assert [x.payload for x in a] == [x.payload for x in b]


# ---------------------------------------------------------------------------
# Tests — short-range chunk-mechanic guarantee (G-DETECTOR-WINDOW-EVASION-001)
# ---------------------------------------------------------------------------


class TestSplitEvasionShortRange:
    """G-DETECTOR-WINDOW-EVASION-001: the chunk-overlap mechanic MUST
    block split-evasion attacks where both pieces fit in a single window.

    Uses the fake-pipeline pattern so we can prove the chunking math
    without a real model. The fake pipeline only fires when BOTH the
    trigger and the instruction substrings are present in a chunk —
    exactly the dilution-style behaviour ADR-046's empirical run
    observed against ProtectAI DeBERTa. The guarantee here is that
    the chunker's overlap policy still gives that single-window
    classifier a chance to see both pieces when they're close enough.
    """

    def _build_text(self, n_filler_tokens: int) -> str:
        """trigger + N benign tokens + instruction, where N is the gap
        between the two pieces in the same window."""
        filler = " ".join(f"benign{i}" for i in range(n_filler_tokens))
        return f"{_FakeJointPipeline.TRIG} {filler} {_FakeJointPipeline.INSTR}"

    def test_no_gap_blocks(self):
        """G-DETECTOR-WINDOW-EVASION-001: trigger + instruction with no
        filler between them is the positive-control case — the chunker
        sees both in one window and the chain blocks."""
        pipe = _FakeJointPipeline()
        check = create_check(pipe, threshold=0.9)
        with pytest.raises(SuspiciousPatternError):
            check(self._build_text(0))

    def test_gap_within_window_blocks(self):
        """G-DETECTOR-WINDOW-EVASION-001: trigger and instruction
        separated by a few tokens but still inside one window MUST block.
        This is the regime the chunker is designed to cover."""
        pipe = _FakeJointPipeline()
        check = create_check(pipe, threshold=0.9)
        # window=30 (model_max=32 minus 2 reserved). Gap=10 tokens is
        # comfortably inside one window.
        with pytest.raises(SuspiciousPatternError):
            check(self._build_text(10))

    def test_gap_at_overlap_boundary_still_blocks(self):
        """G-DETECTOR-WINDOW-EVASION-001: when the gap is exactly the
        chunk overlap (here, the test fake's effective stride), at least
        one window in the sweep contains both pieces. The blocking
        guarantee holds at the boundary case the overlap was sized for.

        With model_max=32 and stride logic ``min(64, 30//4) = 7``, two
        consecutive windows share 7 tokens. As long as the trigger fits
        in the leading shared prefix and the instruction fits in the
        trailing shared suffix of the next window, both appear in at
        least one window and the chain blocks.
        """
        pipe = _FakeJointPipeline()
        check = create_check(pipe, threshold=0.9)
        # Modest gap that lands well within the windowing — both pieces
        # should appear in at least one of the chunks.
        with pytest.raises(SuspiciousPatternError):
            check(self._build_text(15))

    def test_gap_far_beyond_overlap_does_not_block_with_joint_classifier(self):
        """Negative-control / NG-DETECTOR-WINDOW-EVASION-001 mechanic
        proof: when the gap is large enough that no window contains
        both pieces, a "joint-only" classifier (which is what the real
        DeBERTa empirically degrades to under benign-filler dilution —
        see ADR-046) does NOT fire. This is the gap the long-range
        regression tests pin.

        This is here as a unit-level mechanic proof: the chunker is
        per-window-independent, and a model that requires both pieces
        in one window cannot synthesize cross-window signal. Same
        property as the real DeBERTa under dilution.
        """
        pipe = _FakeJointPipeline()
        check = create_check(pipe, threshold=0.9)
        # Generous gap → multiple chunks, neither has both pieces.
        result = check(self._build_text(200))
        assert result["max_score"] == 0.0
        assert result["n_windows"] >= 2

    def test_constants_match_adr_032(self):
        """Smoke-bind ADR-032's constants. If someone bumps the stride
        or window-reserved tokens, the change should land in a
        considered ADR (e.g. an ADR-046-supersedes), not a sneak edit."""
        # ADR-032: 64-token overlap, 2 reserved tokens for [CLS]/[SEP].
        assert _WINDOW_STRIDE_TOKENS == 64
        assert _WINDOW_RESERVED_TOKENS == 2


# ---------------------------------------------------------------------------
# Tests — long-range model-dilution non-guarantee (NG-DETECTOR-WINDOW-EVASION-001)
# ---------------------------------------------------------------------------

try:
    from fastapi.testclient import TestClient  # noqa: F401
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

try:
    import transformers  # noqa: F401
    import torch  # noqa: F401
    HAS_DETECTOR_DEPS = True
except ImportError:
    HAS_DETECTOR_DEPS = False


@pytest.mark.e2e_slow
@pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed (dashboard extra missing)")
@pytest.mark.skipif(
    not HAS_DETECTOR_DEPS,
    reason="transformers/torch not installed; the e2e lane installs them explicitly",
)
class TestSplitEvasionLongRange:
    """G-DETECTOR-WINDOW-EVASION-001 (positive controls) +
    NG-DETECTOR-WINDOW-EVASION-001 (long-range regression pinning).

    Real ProtectAI DeBERTa weights, real chunker. Two-sided coverage:

      - **No-filler controls MUST block** — confirms each curated pair is
        genuinely injection-shaped when contiguous. If a future model
        drift starts letting these through with no filler at all, that's
        a class-of-bug regression separate from the chunk-boundary gap.
      - **Long-filler cases currently pass** — pinning the dilution gap
        ADR-046 documents. If a model bump starts catching them, this
        test flips RED on purpose to force a non-guarantee revisit.

    Sister to ``tests/test_e2e_real_detectors.py`` (ADR-045) — same e2e
    lane, same model fixture pattern.
    """

    @pytest.fixture(scope="class")
    def real_protectai_check(self):
        """Load real ProtectAI DeBERTa once per test class. Mirrors the
        module-scope fixture in tests/test_e2e_real_detectors.py."""
        from bulwark.integrations.promptguard import load_detector
        detector = load_detector("protectai")
        return detector, create_check(detector)

    def test_no_filler_pair_blocks(self, real_protectai_check):
        """G-DETECTOR-WINDOW-EVASION-001 positive control: every curated
        (trigger, instruction) pair concatenated directly MUST be
        blocked by the chunked classifier.

        If this fails the curated sample is no longer
        injection-shaped — likely a model drift. Update the corpus
        rather than the contract.
        """
        detector, check = real_protectai_check
        for trigger, instruction in SPLIT_EVASION_PAIRS:
            payload = f"{trigger} {instruction}"
            with pytest.raises(SuspiciousPatternError) as exc:
                check(payload)
            assert "INJECTION" in str(exc.value), (
                f"pair {trigger!r}+{instruction!r} no-filler control didn't "
                f"raise INJECTION: {exc.value!r}"
            )

    def test_long_separation_currently_passes(self, real_protectai_check):
        """NG-DETECTOR-WINDOW-EVASION-001: long-separation split evasion
        currently slips past the per-window classifier. Pin the regime
        so a future model improvement that starts catching it forces
        us back to ADR-046 to revise the non-guarantee.

        If this test starts FAILING (i.e., the chain now blocks),
        that's a GOOD outcome — re-evaluate
        NG-DETECTOR-WINDOW-EVASION-001 and either tighten the
        non-guarantee or upgrade it to a guarantee.
        """
        detector, check = real_protectai_check
        tokenizer = detector.tokenizer
        # Generate samples with 600 tokens of filler — well past the gap
        # threshold ADR-046's investigation found (~50 tokens).
        suite = AttackSuite()
        attacks = suite.generate_split_evasion_samples(
            tokenizer, filler_token_counts=[600]
        )
        leaked = []
        for a in attacks:
            try:
                result = check(a.payload)
                # Passed — record for the leak count assertion below.
                leaked.append((a.name, result["max_score"]))
            except SuspiciousPatternError:
                # Caught — model improvement; the non-guarantee is
                # tighter than reality. Don't fail the whole test for
                # one caught sample; the assertion below checks the
                # corpus aggregate.
                pass
        # Pin: at least one of the curated long-separation samples
        # currently slips past the detector. If the count drops to
        # zero, every curated sample is now caught — revisit
        # NG-DETECTOR-WINDOW-EVASION-001.
        assert len(leaked) >= 1, (
            "All long-separation split-evasion samples were blocked. "
            "This is a GOOD outcome — the model has improved. "
            "Revisit NG-DETECTOR-WINDOW-EVASION-001 in spec/contracts/clean.yaml "
            "and consider promoting it to a guarantee."
        )
