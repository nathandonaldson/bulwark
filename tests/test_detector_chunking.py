"""Tests for ADR-032 detector chunking.

Uses a fake transformers pipeline so we don't need the real model weights.
Covers G-HTTP-CLEAN-010 (chunked classification) and NG-HTTP-CLEAN-004
(O(n) latency).
"""
from __future__ import annotations

import pytest

from bulwark.integrations.promptguard import create_check, _tokenize_windows
from bulwark.guard import SuspiciousPatternError


class _FakeTokenizer:
    """Word-level tokenizer good enough to exercise the chunker."""
    model_max_length = 10  # Tiny window so short strings in tests still chunk.

    def encode(self, text: str, add_special_tokens: bool = False, truncation: bool = False):
        return text.split()

    def decode(self, ids, skip_special_tokens: bool = False):
        return " ".join(ids)


class _FakeModel:
    name_or_path = "fake/detector"


class _FakePipeline:
    """Mimics the transformers text-classification pipeline shape.

    Flags any chunk containing the trigger word 'PWNED' as INJECTION.
    Tracks calls so tests can assert chunking happened.
    """

    def __init__(self, trigger: str = "PWNED"):
        self.tokenizer = _FakeTokenizer()
        self.model = _FakeModel()
        self.calls: list[list[str]] = []
        self.trigger = trigger

    def __call__(self, text, truncation: bool = False):
        if isinstance(text, str):
            batch = [text]
        else:
            batch = list(text)
        self.calls.append(batch)
        return [
            {"label": "INJECTION" if self.trigger in t else "SAFE",
             "score": 0.99 if self.trigger in t else 0.01}
            for t in batch
        ]


def test_short_input_single_window():
    """G-HTTP-CLEAN-010: inputs under the window behave as before — one call."""
    pipe = _FakePipeline()
    check = create_check(pipe, threshold=0.9)
    check("five short tokens here please")
    assert len(pipe.calls) == 1
    # One window → batch of length 1.
    assert len(pipe.calls[0]) == 1


def test_long_input_is_chunked():
    """G-HTTP-CLEAN-010: input larger than the window splits into multiple chunks."""
    pipe = _FakePipeline()
    check = create_check(pipe, threshold=0.9)
    text = " ".join(f"tok{i}" for i in range(40))  # 40 tokens, window=8, stride=2
    check(text)
    all_inputs = [item for batch in pipe.calls for item in batch]
    assert len(all_inputs) > 1, "Long input should produce multiple windows"


def test_injection_in_tail_is_caught():
    """The whole point of ADR-032: an injection past the first window blocks."""
    pipe = _FakePipeline(trigger="PWNED")
    check = create_check(pipe, threshold=0.9)
    # First ~30 tokens benign, last chunk contains PWNED.
    benign = " ".join(f"safe{i}" for i in range(30))
    text = benign + " PWNED"
    with pytest.raises(SuspiciousPatternError) as exc:
        check(text)
    assert "INJECTION" in str(exc.value)


def test_injection_in_head_short_circuits_or_flags():
    """Injection in the first window still flags (common-case regression guard)."""
    pipe = _FakePipeline(trigger="PWNED")
    check = create_check(pipe, threshold=0.9)
    with pytest.raises(SuspiciousPatternError):
        check("PWNED " + " ".join(f"tail{i}" for i in range(20)))


def test_below_threshold_passes():
    """Below-threshold detector scores should not raise."""
    pipe = _FakePipeline(trigger="__never__")
    check = create_check(pipe, threshold=0.9)
    check(" ".join(f"tok{i}" for i in range(40)))  # always-SAFE pipeline


def test_chunker_has_stride_overlap():
    """_tokenize_windows overlaps consecutive chunks by the stride."""
    tok = _FakeTokenizer()
    chunks = _tokenize_windows(" ".join(f"t{i}" for i in range(30)), tok, model_max=tok.model_max_length)
    assert len(chunks) >= 3
    # Overlap: last few tokens of chunk[0] should reappear at the start of chunk[1].
    tail_0 = chunks[0].split()[-2:]
    head_1 = chunks[1].split()[:2]
    assert tail_0 == head_1, f"Expected stride overlap; got {tail_0!r} vs {head_1!r}"


def test_batching_cap():
    """NG-HTTP-CLEAN-004: batched inference honours the 32-window cap."""
    from bulwark.integrations.promptguard import _MAX_BATCH_WINDOWS
    pipe = _FakePipeline(trigger="__never__")
    check = create_check(pipe, threshold=0.9)
    # Build ~50 windows: model_max=10, stride=2, effective advance=8 tokens.
    text = " ".join(f"tok{i}" for i in range(50 * 8))
    check(text)
    # Each pipeline call batch is <= _MAX_BATCH_WINDOWS.
    for batch in pipe.calls:
        assert len(batch) <= _MAX_BATCH_WINDOWS


def test_empty_input_is_noop():
    pipe = _FakePipeline()
    check = create_check(pipe, threshold=0.9)
    check("")
    assert pipe.calls == []


def test_no_tokenizer_fallback():
    """Pipelines that don't expose a tokenizer still run (degraded mode)."""
    class NoTokPipe(_FakePipeline):
        def __init__(self):
            super().__init__()
            self.tokenizer = None

    pipe = NoTokPipe()
    check = create_check(pipe, threshold=0.9)
    check("some text")
    assert len(pipe.calls) == 1
