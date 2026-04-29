"""Prompt injection detection models for Bulwark's AnalysisGuard bridge.

Loads a transformer-based classifier and creates a check function
compatible with AnalysisGuard.custom_checks. Two models supported:

- ProtectAI deberta-v3 (default, ungated, works immediately)
- Meta PromptGuard-86M (gated, requires HuggingFace approval)

Usage:
    from bulwark.integrations.promptguard import load_detector, create_check

    detector = load_detector()  # loads default model
    check_fn = create_check(detector, threshold=0.9)

    guard = AnalysisGuard(custom_checks=[check_fn])
    pipeline = Pipeline.default(analyze_fn=my_fn)
    pipeline.analysis_guard = guard
"""
from __future__ import annotations

from typing import Optional, Callable

from bulwark.guard import SuspiciousPatternError as AnalysisSuspiciousError


# Available models (name -> HuggingFace model ID)
MODELS = {
    "protectai": "protectai/deberta-v3-base-prompt-injection-v2",
    "promptguard": "meta-llama/Prompt-Guard-86M",
}

DEFAULT_MODEL = "protectai"
DEFAULT_THRESHOLD = 0.9

# Cache loaded detectors so we don't reload on every call
_loaded_detectors: dict[str, object] = {}


def load_detector(
    model_name: str = DEFAULT_MODEL,
    device: Optional[str] = None,
) -> object:
    """Load a prompt injection detection model.

    Args:
        model_name: "protectai" (default, ungated) or "promptguard" (Meta, gated).
        device: Device to run on. None = auto-detect (MPS on Mac, CUDA if available).

    Returns:
        A transformers pipeline object.

    Raises:
        ImportError: If transformers is not installed.
        OSError: If model can't be downloaded (gated, no auth, network).
    """
    if model_name in _loaded_detectors:
        return _loaded_detectors[model_name]

    try:
        from transformers import pipeline
    except ImportError:
        raise ImportError(
            "transformers is required for prompt injection detection. "
            "Install with: pip install transformers torch"
        )

    model_id = MODELS.get(model_name, model_name)

    kwargs = {"model": model_id}
    if device is not None:
        kwargs["device"] = device

    detector = pipeline("text-classification", **kwargs)
    _loaded_detectors[model_name] = detector
    return detector


# ADR-032: Chunking parameters. 512-token model window minus 2 reserved tokens
# for [CLS]/[SEP]. Stride of 64 means an injection phrase can straddle a
# window boundary and still land wholly inside at least one neighbour.
_WINDOW_RESERVED_TOKENS = 2
_WINDOW_STRIDE_TOKENS = 64
_MAX_BATCH_WINDOWS = 64  # Cap per-call inference: 64 × 510 tokens ≈ 128 KB of input.


def _tokenize_windows(text: str, tokenizer, model_max: int) -> list[str]:
    """Split text into overlapping token windows, return decoded strings.

    Returns one element when the text fits in a single window — in that
    case the output equals the input (modulo tokenizer roundtrip).
    """
    window = max(8, model_max - _WINDOW_RESERVED_TOKENS)
    stride = min(_WINDOW_STRIDE_TOKENS, window // 4)
    # add_special_tokens=False — we decode back to a string and let the
    # downstream pipeline add [CLS]/[SEP] per window during inference.
    ids = tokenizer.encode(text, add_special_tokens=False, truncation=False)
    if len(ids) <= window:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(ids):
        end = min(start + window, len(ids))
        chunks.append(tokenizer.decode(ids[start:end], skip_special_tokens=True))
        if end == len(ids):
            break
        start = end - stride
    return chunks


def create_check(
    detector: object,
    threshold: float = DEFAULT_THRESHOLD,
    injection_labels: tuple[str, ...] = ("INJECTION", "JAILBREAK"),
) -> Callable[[str], None]:
    """Create a PatternGuard-compatible check function from a loaded detector.

    Args:
        detector: A transformers text-classification pipeline.
        threshold: Minimum confidence score to flag as injection. Default 0.9.
        injection_labels: Labels that indicate injection. Default ("INJECTION", "JAILBREAK").
            PromptGuard-86M uses three labels: BENIGN, INJECTION, JAILBREAK.
            ProtectAI DeBERTa uses: SAFE, INJECTION.

    Returns:
        A callable that raises SuspiciousPatternError if injection detected.
        Long inputs are chunked across the model's token window so nothing
        past the first 512 tokens is silently invisible (ADR-032).
    """
    tokenizer = getattr(detector, "tokenizer", None)
    model_max = getattr(tokenizer, "model_max_length", None) if tokenizer else None
    # Guard against tokenizers reporting a sentinel value (e.g. 10**30 for
    # "effectively unbounded"). Fall back to the DeBERTa default.
    if not isinstance(model_max, int) or model_max > 4096 or model_max < 8:
        model_max = 512

    def _classify(chunks: list[str]) -> list[dict]:
        """Run the pipeline over chunks, capped at _MAX_BATCH_WINDOWS per call."""
        out: list[dict] = []
        for i in range(0, len(chunks), _MAX_BATCH_WINDOWS):
            batch = chunks[i:i + _MAX_BATCH_WINDOWS]
            results = detector(batch, truncation=True)
            # pipeline returns a list for batch input, even of length 1.
            if results and isinstance(results[0], dict):
                out.extend(results)
            elif results and isinstance(results[0], list):
                out.extend(r[0] for r in results if r)
        return out

    def check(analysis: str) -> dict:
        """Run the detector on `analysis`.

        Returns a result dict on pass with `max_score` (highest detector
        score across windows whose label is in injection_labels — 0.0 if
        no window classified as injection), `n_windows`, and `top_label`
        (the highest-scoring window's label, regardless of class). Raises
        SuspiciousPatternError on block, with the same fields attached
        as exception attributes (B6 / ADR-038): max_score, n_windows,
        window_index, label.

        max_score is reported AS injection signal: 0.0 means "no window
        called this injection". A high max_score means the detector
        flagged the content but the score didn't cross the threshold.
        Operators see "almost-blocked" cases without confusing them with
        SAFE-class confidence scores.
        """
        if not analysis:
            return {"max_score": 0.0, "n_windows": 0, "top_label": None}
        if tokenizer is None:
            # Fallback path — no tokenizer exposed. Single call, accept the
            # pipeline's own truncation. Better than refusing to run at all.
            result = detector(analysis)
            if not result:
                return {"max_score": 0.0, "n_windows": 1, "top_label": None}
            top = result[0]
            score = float(top.get("score", 0.0) or 0.0)
            label = top.get("label")
            if label in injection_labels and score >= threshold:
                err = AnalysisSuspiciousError(
                    f"Prompt injection detected ({score:.3f}, {label}) by {detector.model.name_or_path}"
                )
                err.max_score = score
                err.n_windows = 1
                err.window_index = 1
                err.label = label
                raise err
            inj_score = score if label in injection_labels else 0.0
            return {"max_score": inj_score, "n_windows": 1, "top_label": label}

        chunks = _tokenize_windows(analysis, tokenizer, model_max)
        results = _classify(chunks)
        injection_scores = [
            float(r.get("score", 0.0) or 0.0)
            for r in results
            if r.get("label") in injection_labels
        ]
        for i, top in enumerate(results):
            score = float(top.get("score", 0.0) or 0.0)
            label = top.get("label")
            if label in injection_labels and score >= threshold:
                err = AnalysisSuspiciousError(
                    f"Prompt injection detected ({score:.3f}, {label}) by {detector.model.name_or_path}"
                    + (f" in window {i + 1}/{len(results)}" if len(chunks) > 1 else "")
                )
                err.max_score = score
                err.n_windows = len(chunks)
                err.window_index = i + 1
                err.label = label
                raise err
        # Pass path: max_score is the strongest INJECTION-class score (0.0 if
        # no window flagged injection). top_label is the strongest result's
        # label, useful for "the model was very confident SAFE" observability.
        max_inj = max(injection_scores) if injection_scores else 0.0
        if results:
            best = max(results, key=lambda r: float(r.get("score", 0.0) or 0.0))
            top_label = best.get("label")
        else:
            top_label = None
        return {"max_score": max_inj, "n_windows": len(chunks), "top_label": top_label}

    return check


def detect_and_create(
    model_name: str = DEFAULT_MODEL,
    threshold: float = DEFAULT_THRESHOLD,
) -> Callable[[str], None]:
    """One-step: load model and return a check function.

    Usage:
        guard = AnalysisGuard(custom_checks=[detect_and_create()])
    """
    detector = load_detector(model_name)
    return create_check(detector, threshold)
