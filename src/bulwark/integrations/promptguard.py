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

from bulwark.executor import AnalysisSuspiciousError


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


def create_check(
    detector: object,
    threshold: float = DEFAULT_THRESHOLD,
    injection_label: str = "INJECTION",
) -> Callable[[str], None]:
    """Create an AnalysisGuard check function from a loaded detector.

    Args:
        detector: A transformers text-classification pipeline.
        threshold: Minimum confidence score to flag as injection. Default 0.9.
        injection_label: The label that indicates injection. Default "INJECTION".

    Returns:
        A callable that raises AnalysisSuspiciousError if injection detected.
    """
    def check(analysis: str) -> None:
        result = detector(analysis)
        if not result:
            return
        top = result[0]
        if top["label"] == injection_label and top["score"] >= threshold:
            raise AnalysisSuspiciousError(
                f"Prompt injection detected ({top['score']:.3f}) by {detector.model.name_or_path}"
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
