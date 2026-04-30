"""Pipeline: sanitize → detector chain → trust-boundary wrap.

v2.5.0 (ADR-044): library Pipeline reaches dashboard parity.
`Pipeline.from_config(path)` now reads the same `bulwark-config.yaml`
the dashboard reads and composes the same three-detector chain
(`integrations.protectai`, `integrations.promptguard`,
`judge_backend.enabled`). Library callers get the same defense the
dashboard `/v1/clean` delivers from the same config (G-PIPELINE-PARITY-001).

v2.0.0 (ADR-031): Bulwark returns safe content or an error. No LLM calls,
no two-phase execution. The caller owns the LLM.

Canaries are NOT checked here — they're an output-side concern surfaced
through /v1/guard (and bulwark.guard()).
"""
from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary
from bulwark.events import EventEmitter

logger = logging.getLogger(__name__)


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

    v2.5.0 pipeline (ADR-044): sanitize → detector chain → trust-boundary
    wrap. `detectors` is a list of callables; each is invoked in order,
    and any callable raising SuspiciousPatternError blocks the pipeline
    with the exception message in `block_reason`. This mirrors the
    dashboard's iteration over `_detection_checks` plus the optional LLM
    judge — see G-PIPELINE-PARITY-001.

    v2.5.4 (ADR-047 / Phase H): each detector runs once per decoded
    variant of the cleaned text. ROT13 always-on; base64 opt-in via
    `decode_base64`. Trust boundary still wraps the original cleaned
    text — variants are a detection-only fan-out
    (NG-CLEAN-DECODE-VARIANTS-PRESERVED-001).
    """
    sanitizer: Optional[Sanitizer] = None
    trust_boundary: Optional[TrustBoundary] = None
    detectors: List[Callable[[str], object]] = field(default_factory=list)
    emitter: Optional[EventEmitter] = None
    decode_base64: bool = False

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

        # ADR-047 / Phase H: build decoded variants once; each detector runs
        # over every non-skipped variant. Block on first hit on any variant.
        from bulwark.decoders import decode_rescan_variants
        variants = decode_rescan_variants(
            cleaned, decode_base64=self.decode_base64,
        ) if cleaned else []

        # Detector chain (G-PIPELINE-PARITY-001). Each detector is a
        # callable that raises SuspiciousPatternError to block. Order is
        # the order the chain was constructed — for from_config() this is
        # protectai → promptguard → judge, matching the dashboard.
        for index, detector in enumerate(self.detectors):
            step += 1
            layer_name = _detector_layer_name(detector, index)
            blocked_exc: Optional[Exception] = None
            blocked_variant_label: Optional[str] = None
            for variant in variants or [None]:
                # variants is empty when content is empty — fall back to
                # running the detector on the cleaned text as before.
                target = variant.text if variant is not None else cleaned
                if variant is not None and (variant.skipped or not variant.text):
                    continue
                try:
                    detector(target)
                except Exception as exc:
                    blocked_exc = exc
                    blocked_variant_label = (
                        variant.label if variant is not None else "original"
                    )
                    break
            if blocked_exc is None:
                trace.append({
                    "step": step,
                    "layer": layer_name,
                    "verdict": "passed",
                    "detail": "Detector passed",
                })
            else:
                variant_suffix = (
                    f" variant={blocked_variant_label}"
                    if blocked_variant_label and blocked_variant_label != "original"
                    else ""
                )
                trace.append({
                    "step": step,
                    "layer": layer_name,
                    "verdict": "blocked",
                    "detail": f"{blocked_exc}{variant_suffix}",
                })
                return PipelineResult(
                    result="",
                    blocked=True,
                    block_reason=f"Detector blocked: {blocked_exc}",
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
    def default(
        cls,
        detectors: Optional[List[Callable[[str], object]]] = None,
        emitter: Optional[EventEmitter] = None,
    ) -> "Pipeline":
        """Default pipeline: sanitizer + trust boundary + caller-supplied detectors.

        For the dashboard-parity chain (DeBERTa + PromptGuard + judge,
        wired from a YAML config), use `Pipeline.from_config(path)`
        instead — that's where the integration loaders and judge config
        get read.
        """
        return cls(
            sanitizer=Sanitizer(emitter=emitter),
            trust_boundary=TrustBoundary(emitter=emitter),
            detectors=list(detectors) if detectors else [],
            emitter=emitter,
        )

    @classmethod
    def from_config(
        cls,
        path: str,
        detectors: Optional[List[Callable[[str], object]]] = None,
    ) -> "Pipeline":
        """Load a Pipeline from a YAML config — dashboard parity (ADR-044).

        Reads `integrations.protectai.enabled`, `integrations.promptguard.enabled`,
        and `judge_backend.enabled` from the same config the dashboard
        reads, and composes the same detector chain (G-PIPELINE-PARITY-001).

        Detector order in the resulting chain:
          1. ProtectAI / DeBERTa (when enabled)
          2. PromptGuard-86M (when enabled)
          3. LLM judge (when enabled)

        The optional `detectors` parameter is appended AFTER the
        config-derived chain so callers can stack their own checks on
        top of the dashboard-equivalent defense.
        """
        bulwark_config = _load_bulwark_config(path)

        # Read every layer toggle from the same `BulwarkConfig` dataclass
        # the dashboard uses (ADR-044). When the load fails (file missing,
        # malformed YAML, validation failure), `_load_bulwark_config`
        # logs a single WARNING and returns None — we then fall back to
        # the documented sanitizer + trust-boundary defaults so the
        # library doesn't crash on a missing config file.
        if bulwark_config is None:
            sanitizer = Sanitizer()
            trust_boundary = TrustBoundary()
            chain: List[Callable[[str], object]] = []
            decode_base64 = False
        else:
            sanitizer = None
            if bulwark_config.sanitizer_enabled:
                sanitizer = Sanitizer(
                    normalize_unicode=bulwark_config.normalize_unicode,
                    strip_emoji_smuggling=bulwark_config.strip_emoji_smuggling,
                    strip_bidi=bulwark_config.strip_bidi,
                )
            trust_boundary = (
                TrustBoundary() if bulwark_config.trust_boundary_enabled else None
            )
            chain = _build_detector_chain(bulwark_config)
            # ADR-047: dashboard parity for the decode-rescan opt-in flag.
            decode_base64 = bool(getattr(bulwark_config, "decode_base64", False))

        if detectors:
            chain.extend(detectors)

        return cls(
            sanitizer=sanitizer,
            trust_boundary=trust_boundary,
            detectors=chain,
            decode_base64=decode_base64,
        )


def _detector_layer_name(detector: Callable[[str], object], index: int) -> str:
    """Best-effort label for a detector callable in the trace.

    Detectors built via `_build_detector_chain` carry a `__bulwark_name__`
    attribute (e.g. "detection:protectai"). Callers attaching ad-hoc
    detectors get a positional fallback ("detection[0]") rather than the
    bare "detection" label, so the trace remains self-describing for any
    chain length.
    """
    name = getattr(detector, "__bulwark_name__", None)
    if isinstance(name, str) and name:
        return name
    return f"detection[{index}]"


def _build_detector_chain(bulwark_config) -> List[Callable[[str], object]]:
    """Compose the detector chain matching the dashboard's startup hook.

    Mirrors `bulwark.dashboard.app._auto_load_detection_models` (for the
    integrations) plus `bulwark.dashboard.api_v1.api_clean`'s judge
    wire-up. Loader / classifier failures are logged at WARNING and
    omitted from the chain, NOT raised — matches the dashboard's
    behaviour where a detector that fails to load is recorded in
    `_detector_failures` but doesn't stop the dashboard from booting.
    Callers that need fail-closed-on-load can inspect
    `pipeline.detectors` themselves.
    """
    chain: List[Callable[[str], object]] = []

    # 1. ProtectAI / DeBERTa, then PromptGuard. Same loader, same
    # create_check; the dashboard iterates the integrations dict in the
    # tuple ("protectai", "promptguard") order — we replicate that.
    integrations = getattr(bulwark_config, "integrations", None) or {}
    for name in ("protectai", "promptguard"):
        int_cfg = integrations.get(name)
        if not int_cfg or not getattr(int_cfg, "enabled", False):
            continue
        check = _try_load_promptguard_detector(name)
        if check is not None:
            check.__bulwark_name__ = f"detection:{name}"
            chain.append(check)

    # 2. LLM judge (ADR-033) — opt-in, runs after the ML detectors so
    # they short-circuit it.
    judge_cfg = getattr(bulwark_config, "judge_backend", None)
    if judge_cfg is not None and getattr(judge_cfg, "enabled", False):
        judge_check = _build_judge_check(judge_cfg)
        if judge_check is not None:
            judge_check.__bulwark_name__ = "detection:llm_judge"
            chain.append(judge_check)

    return chain


def _try_load_promptguard_detector(name: str) -> Optional[Callable[[str], object]]:
    """Load `name` via bulwark.integrations.promptguard, or None on failure.

    `transformers` / `torch` are heavy imports — we keep them inside this
    function so library callers with no integrations enabled never pay
    the cost. ImportError and OSError are the two expected failure
    classes (transformers missing, model gated / network out); we log
    and degrade rather than crash.
    """
    try:
        from bulwark.integrations.promptguard import load_detector, create_check
    except ImportError as exc:  # pragma: no cover — transformers absent
        logger.warning(
            "Pipeline.from_config: integrations.%s enabled but transformers "
            "not importable (%s). Skipping detector.", name, exc,
        )
        return None
    try:
        detector = load_detector(name)
        return create_check(detector)
    except Exception as exc:
        logger.warning(
            "Pipeline.from_config: failed to load detector %s: %s. "
            "Pipeline.detectors will not include it. Inspect the chain "
            "to enforce a require-detectors policy.", name, exc,
        )
        return None


def _build_judge_check(judge_cfg) -> Optional[Callable[[str], object]]:
    """Wrap the LLM judge as a SuspiciousPatternError-raising callable.

    Mirrors `bulwark.dashboard.api_v1.api_clean`'s judge handling:
    INJECTION at confidence ≥ threshold → block. ERROR / UNPARSEABLE
    follow the fail_open flag (block when False, pass when True).
    Generative judge text never reaches the trace (NG-JUDGE-004 /
    ADR-037).
    """
    try:
        from bulwark.detectors.llm_judge import classify
    except ImportError as exc:  # pragma: no cover
        logger.warning(
            "Pipeline.from_config: judge_backend.enabled=True but llm_judge "
            "module not importable (%s). Skipping judge.", exc,
        )
        return None
    from bulwark.guard import SuspiciousPatternError

    def judge_check(text: str) -> None:
        verdict = classify(judge_cfg, text)
        if verdict.verdict == "INJECTION" and verdict.confidence >= getattr(
            judge_cfg, "threshold", 0.85,
        ):
            raise SuspiciousPatternError(
                f"LLM judge: INJECTION ({verdict.confidence:.2f})"
            )
        if verdict.verdict in ("ERROR", "UNPARSEABLE") and not getattr(
            judge_cfg, "fail_open", True,
        ):
            raise SuspiciousPatternError(
                f"LLM judge {verdict.verdict.lower()} (fail-closed)"
            )
        return None

    return judge_check


def _load_bulwark_config(path: str):
    """Return a `BulwarkConfig` for the YAML at `path`, or None on failure.

    Sole loader for `Pipeline.from_config()` (ADR-044). The library
    Pipeline reaches the dashboard config dataclass without pulling in
    FastAPI: `bulwark.dashboard.config` is a pure-Python module that
    imports `yaml` only. We catch `ImportError` defensively in case a
    downstream packager strips the dashboard package.

    Failure modes — file missing, YAML malformed, or `BulwarkConfig`
    validation rejects the parsed dict — all return None and emit a
    single WARNING so a malformed config produces ONE warning per call,
    not two. Callers (i.e. `from_config`) fall back to sanitizer +
    trust-boundary defaults with an empty detector chain.
    """
    try:
        from bulwark.dashboard.config import BulwarkConfig
    except ImportError:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return BulwarkConfig.load(str(p))
    except Exception as exc:
        warnings.warn(
            f"Failed to load Bulwark config at {p}: {exc}; "
            "library Pipeline will use sanitizer + trust boundary "
            "defaults with an empty detector chain.",
            stacklevel=3,
        )
        return None
