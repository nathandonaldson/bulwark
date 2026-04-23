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
_MAX_BATCH_WINDOWS = 32  # Cap batched inference to bound VRAM/MPS footprint.


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

    def check(analysis: str) -> None:
        if not analysis:
            return
        if tokenizer is None:
            # Fallback path — no tokenizer exposed. Single call, accept the
            # pipeline's own truncation. Better than refusing to run at all.
            result = detector(analysis)
            if not result:
                return
            top = result[0]
            if top["label"] in injection_labels and top["score"] >= threshold:
                raise AnalysisSuspiciousError(
                    f"Prompt injection detected ({top['score']:.3f}, {top['label']}) by {detector.model.name_or_path}"
                )
            return

        chunks = _tokenize_windows(analysis, tokenizer, model_max)
        results = _classify(chunks)
        for top in results:
            if top["label"] in injection_labels and top["score"] >= threshold:
                raise AnalysisSuspiciousError(
                    f"Prompt injection detected ({top['score']:.3f}, {top['label']}) by {detector.model.name_or_path}"
                    + (f" in window {results.index(top) + 1}/{len(results)}" if len(chunks) > 1 else "")
                )

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
