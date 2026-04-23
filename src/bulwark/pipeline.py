"""Pipeline: sanitize → (optional detect) → trust-boundary wrap.

v2.0.0 (ADR-031): Bulwark returns safe content or an error. No LLM calls,
no two-phase execution. The caller owns the LLM.

Canaries are NOT checked here — they're an output-side concern surfaced
through /v1/guard (and bulwark.guard()).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary
from bulwark.events import EventEmitter


@dataclass
class PipelineResult:
    """Result from running content through the pipeline."""
    result: str                       # Sanitized + trust-boundary-wrapped content
    blocked: bool = False
    block_reason: Optional[str] = None
    neutralized: bool = False         # True if sanitizer modified content
    trace: list = field(default_factory=list)


@dataclass
class Pipeline:
    """Chain Bulwark defense layers into one run() call.

    v2.0.0 pipeline: sanitize → trust-boundary wrap. A detector can be
    injected (callable that raises SuspiciousPatternError to block).
    """
    sanitizer: Optional[Sanitizer] = None
    trust_boundary: Optional[TrustBoundary] = None
    detector: Optional[callable] = None  # callable(text) -> raises to block
    emitter: Optional[EventEmitter] = None

    def run(self, content: str, source: str = "external",
            label: Optional[str] = None) -> PipelineResult:
        if not isinstance(content, str):
            raise TypeError(f"Expected str, got {type(content).__name__}")

        self._propagate_emitter()
        trace: list[dict] = []
        step = 0
        neutralized = False

        cleaned = content
        if self.sanitizer is not None:
            step += 1
            cleaned = self.sanitizer.clean(content)
            was_modified = cleaned != content
            neutralized = was_modified
            trace.append({
                "step": step,
                "layer": "sanitizer",
                "verdict": "modified" if was_modified else "passed",
                "detail": f"{'Modified' if was_modified else 'Clean'}: {len(content)} -> {len(cleaned)} chars",
            })

        if self.detector is not None:
            step += 1
            try:
                self.detector(cleaned)
                trace.append({
                    "step": step,
                    "layer": "detection",
                    "verdict": "passed",
                    "detail": "Detector passed",
                })
            except Exception as exc:
                trace.append({
                    "step": step,
                    "layer": "detection",
                    "verdict": "blocked",
                    "detail": str(exc),
                })
                return PipelineResult(
                    result="",
                    blocked=True,
                    block_reason=f"Detector blocked: {exc}",
                    neutralized=neutralized,
                    trace=trace,
                )

        tagged = cleaned
        if self.trust_boundary is not None:
            step += 1
            tagged = self.trust_boundary.wrap(cleaned, source=source, label=label)
            trace.append({
                "step": step,
                "layer": "trust_boundary",
                "verdict": "passed",
                "detail": f"Wrapped with source={source}",
            })

        return PipelineResult(
            result=tagged,
            neutralized=neutralized,
            trace=trace,
        )

    def _propagate_emitter(self) -> None:
        if self.emitter is None:
            return
        for layer in (self.sanitizer, self.trust_boundary):
            if layer is not None and hasattr(layer, "emitter") and layer.emitter is None:
                layer.emitter = self.emitter

    @classmethod
    def default(cls, detector=None, emitter=None) -> "Pipeline":
        return cls(
            sanitizer=Sanitizer(emitter=emitter),
            trust_boundary=TrustBoundary(emitter=emitter),
            detector=detector,
            emitter=emitter,
        )

    @classmethod
    def from_config(cls, path: str, detector=None) -> "Pipeline":
        """Load pipeline configuration from a YAML file."""
        config_data = _load_config(path)

        sanitizer = None
        if config_data.get("sanitizer_enabled", True):
            sanitizer = Sanitizer(
                normalize_unicode=config_data.get("normalize_unicode", False),
                strip_emoji_smuggling=config_data.get("strip_emoji_smuggling", True),
                strip_bidi=config_data.get("strip_bidi", True),
            )

        trust_boundary = None
        if config_data.get("trust_boundary_enabled", True):
            trust_boundary = TrustBoundary()

        return cls(
            sanitizer=sanitizer,
            trust_boundary=trust_boundary,
            detector=detector,
        )


def _load_config(path: str) -> dict:
    import warnings
    p = Path(path)
    if not p.exists():
        return {}
    try:
        from bulwark.dashboard.config import BulwarkConfig
        config = BulwarkConfig.load(path)
        return config.to_dict()
    except ImportError:
        pass
    except Exception as e:
        warnings.warn(f"Bulwark config load failed ({p}): {e}. Using defaults.", stacklevel=2)
        return {}
    try:
        import yaml
        data = yaml.safe_load(p.read_text()) or {}
        return data
    except ImportError:
        warnings.warn(f"PyYAML not installed. Cannot load {p}. Using defaults.", stacklevel=2)
        return {}
    except Exception as e:
        warnings.warn(f"Bulwark YAML parse failed ({p}): {e}. Using defaults.", stacklevel=2)
        return {}
