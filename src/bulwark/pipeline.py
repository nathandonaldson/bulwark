"""Pipeline: chain all Bulwark defense layers into one run() call."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary
from bulwark.canary import CanarySystem
from bulwark.executor import (
    AnalysisGuard, AnalysisSuspiciousError, SECURE_EXECUTE_TEMPLATE,
)
from bulwark.events import EventEmitter


@dataclass
class PipelineResult:
    """Result from running content through the full defense pipeline."""
    analysis: str  # Phase 1 output (or cleaned input if no analyze_fn)
    execution: Optional[str] = None  # Phase 2 output
    blocked: bool = False
    block_reason: Optional[str] = None
    neutralized: bool = False  # True if sanitizer modified content
    trace: list = field(default_factory=list)
    # Each trace entry: {"step": N, "layer": "name", "verdict": "passed|blocked|modified", "detail": "..."}


@dataclass
class Pipeline:
    """Chain all Bulwark defense layers into one run() call.

    Usage:
        pipeline = Pipeline.default(
            analyze_fn=my_classifier,
            execute_fn=my_actor,
            canary=CanarySystem.from_file("canaries.json"),
            emitter=WebhookEmitter("http://localhost:3000/api/events"),
        )
        result = pipeline.run("untrusted email body", source="email")
    """
    # Layer instances (None = skip that layer)
    sanitizer: Optional[Sanitizer] = None
    trust_boundary: Optional[TrustBoundary] = None
    analysis_guard: Optional[AnalysisGuard] = None
    canary: Optional[CanarySystem] = None
    analyze_fn: Optional[Callable[[str], str]] = None
    execute_fn: Optional[Callable[[str], str]] = None

    # Bridge configuration
    sanitize_bridge: bool = True
    guard_bridge: bool = True
    require_json: bool = False
    execute_prompt_template: str = SECURE_EXECUTE_TEMPLATE

    # Observability
    emitter: Optional[EventEmitter] = None

    def run(self, content: str, source: str = "external",
            label: Optional[str] = None) -> PipelineResult:
        """Run content through all configured defense layers.

        Args:
            content: The untrusted input text.
            source: Where the content came from (e.g. "email", "calendar").
            label: Optional label for trust boundary tagging.

        Returns:
            PipelineResult with analysis, optional execution, and trace.
        """
        trace: list[dict] = []
        step = 0
        neutralized = False

        # Propagate emitter to layers that don't have one
        self._propagate_emitter()

        # -- Step 1: Sanitize input --
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

        # -- Step 2: Trust boundary --
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

        # -- Step 3: Phase 1 (analyze) --
        if self.analyze_fn is None:
            # No analyze_fn — return cleaned text as analysis
            return PipelineResult(
                analysis=cleaned,
                neutralized=neutralized,
                trace=trace,
            )

        step += 1
        analysis = self.analyze_fn(tagged)
        trace.append({
            "step": step,
            "layer": "analyze",
            "verdict": "passed",
            "detail": f"Phase 1 produced {len(analysis)} chars",
        })

        # -- Step 4: Guard bridge --
        if self.guard_bridge and self.analysis_guard is not None:
            step += 1
            try:
                self.analysis_guard.check(analysis)
                trace.append({
                    "step": step,
                    "layer": "analysis_guard",
                    "verdict": "passed",
                    "detail": "Analysis passed guard checks",
                })
            except AnalysisSuspiciousError as e:
                trace.append({
                    "step": step,
                    "layer": "analysis_guard",
                    "verdict": "blocked",
                    "detail": str(e),
                })
                return PipelineResult(
                    analysis=analysis,
                    blocked=True,
                    block_reason=f"Analysis guard blocked: {e}",
                    neutralized=neutralized,
                    trace=trace,
                )

        # -- Step 5: Require JSON --
        if self.require_json:
            step += 1
            try:
                json.loads(analysis)
                trace.append({
                    "step": step,
                    "layer": "require_json",
                    "verdict": "passed",
                    "detail": "Valid JSON",
                })
            except (json.JSONDecodeError, TypeError) as e:
                trace.append({
                    "step": step,
                    "layer": "require_json",
                    "verdict": "blocked",
                    "detail": f"Invalid JSON: {e}",
                })
                return PipelineResult(
                    analysis=analysis,
                    blocked=True,
                    block_reason=f"JSON validation failed: {e}",
                    neutralized=neutralized,
                    trace=trace,
                )

        # -- Step 6: Sanitize bridge --
        if self.sanitize_bridge:
            step += 1
            bridge_sanitizer = Sanitizer(
                strip_html=False,
                strip_scripts=False,
                strip_css_hidden=False,
                collapse_whitespace=False,
                max_length=None,
            )
            sanitized_analysis = bridge_sanitizer.clean(analysis)
            bridge_modified = sanitized_analysis != analysis
            analysis = sanitized_analysis
            trace.append({
                "step": step,
                "layer": "sanitize_bridge",
                "verdict": "modified" if bridge_modified else "passed",
                "detail": f"{'Modified' if bridge_modified else 'Clean'}: bridge sanitization",
            })

        # -- Step 7: Canary check --
        if self.canary is not None:
            step += 1
            check_result = self.canary.check(analysis)
            if check_result.leaked:
                trace.append({
                    "step": step,
                    "layer": "canary",
                    "verdict": "blocked",
                    "detail": f"Canary token leaked from: {', '.join(check_result.sources)}",
                })
                return PipelineResult(
                    analysis=analysis,
                    blocked=True,
                    block_reason=f"Canary token leaked from: {', '.join(check_result.sources)}",
                    neutralized=neutralized,
                    trace=trace,
                )
            else:
                trace.append({
                    "step": step,
                    "layer": "canary",
                    "verdict": "passed",
                    "detail": f"Clean: 0/{len(self.canary.tokens)} tokens found",
                })

        # -- Step 8: Phase 2 (execute) --
        if self.execute_fn is not None:
            step += 1
            execute_prompt = self.execute_prompt_template.format(analysis=analysis)
            execution = self.execute_fn(execute_prompt)
            trace.append({
                "step": step,
                "layer": "execute",
                "verdict": "passed",
                "detail": f"Phase 2 produced {len(execution)} chars",
            })
            return PipelineResult(
                analysis=analysis,
                execution=execution,
                neutralized=neutralized,
                trace=trace,
            )

        return PipelineResult(
            analysis=analysis,
            neutralized=neutralized,
            trace=trace,
        )

    def _propagate_emitter(self) -> None:
        """Set pipeline emitter on layers that don't already have one."""
        if self.emitter is None:
            return
        for layer in (self.sanitizer, self.trust_boundary, self.analysis_guard, self.canary):
            if layer is not None and hasattr(layer, "emitter") and layer.emitter is None:
                layer.emitter = self.emitter

    @classmethod
    def default(cls, analyze_fn=None, execute_fn=None, canary=None,
                emitter=None) -> "Pipeline":
        """Create a pipeline with all layers enabled using sensible defaults."""
        return cls(
            sanitizer=Sanitizer(emitter=emitter),
            trust_boundary=TrustBoundary(emitter=emitter),
            analysis_guard=AnalysisGuard(emitter=emitter),
            canary=canary,
            analyze_fn=analyze_fn,
            execute_fn=execute_fn,
            emitter=emitter,
        )

    @classmethod
    def from_config(cls, path: str, analyze_fn=None, execute_fn=None) -> "Pipeline":
        """Load pipeline configuration from a YAML file.

        The YAML maps to BulwarkConfig fields. analyze_fn and execute_fn
        must still be provided as code -- can't serialize callables.
        """
        config_data = _load_config(path)

        # Build layer instances based on config
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

        guard_bridge_enabled = config_data.get("guard_bridge_enabled", True)
        analysis_guard = None
        if guard_bridge_enabled:
            guard_kwargs = {}
            if "guard_patterns" in config_data:
                guard_kwargs["block_patterns"] = config_data["guard_patterns"]
            if "guard_max_length" in config_data:
                guard_kwargs["max_length"] = config_data["guard_max_length"]
            analysis_guard = AnalysisGuard(**guard_kwargs)

        canary = None
        if config_data.get("canary_enabled", True):
            canary_tokens = config_data.get("canary_tokens", {})
            canary_file = config_data.get("canary_file", "")
            encoding_resistant = config_data.get("encoding_resistant", True)
            if canary_file and Path(canary_file).exists():
                canary = CanarySystem.from_file(canary_file)
                canary.encoding_resistant = encoding_resistant
            elif canary_tokens:
                canary = CanarySystem(
                    tokens=canary_tokens,
                    encoding_resistant=encoding_resistant,
                )
            else:
                canary = CanarySystem(encoding_resistant=encoding_resistant)

        return cls(
            sanitizer=sanitizer,
            trust_boundary=trust_boundary,
            analysis_guard=analysis_guard,
            canary=canary,
            analyze_fn=analyze_fn,
            execute_fn=execute_fn,
            sanitize_bridge=config_data.get("sanitize_bridge_enabled", True),
            guard_bridge=guard_bridge_enabled,
            require_json=config_data.get("require_json", False),
        )


def _load_config(path: str) -> dict:
    """Load config from YAML, trying BulwarkConfig first, then manual parsing."""
    p = Path(path)
    if not p.exists():
        # Return defaults (empty dict triggers all defaults)
        return {}

    try:
        from dashboard.config import BulwarkConfig
        config = BulwarkConfig.load(path)
        return config.to_dict()
    except (ImportError, Exception):
        pass

    # Manual YAML parsing fallback
    try:
        import yaml
        data = yaml.safe_load(p.read_text()) or {}
        return data
    except Exception:
        return {}
