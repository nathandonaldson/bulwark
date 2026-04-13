"""Bulwark: Architectural defense against prompt injection.

LLM provider integrations are available as separate submodules
(they require their respective SDKs):

    from bulwark.integrations.anthropic import make_analyze_fn, make_execute_fn, make_pipeline
"""
from __future__ import annotations

from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary
from bulwark.canary import CanarySystem
from bulwark.executor import (
    TwoPhaseExecutor, ExecutorResult, LLMCallFn,
    AnalysisGuard, AnalysisSuspiciousError, SECURE_EXECUTE_TEMPLATE,
)
from bulwark.isolator import MapReduceIsolator, IsolatorResult, ItemResult
from bulwark.events import (
    BulwarkEvent, Layer, Verdict, EventEmitter,
    NullEmitter, CollectorEmitter, CallbackEmitter,
    StdoutJsonEmitter, WebhookEmitter, MultiEmitter,
)
from bulwark.attacks import AttackSuite
from bulwark.validator import PipelineValidator, ValidationReport
from bulwark.pipeline import Pipeline, PipelineResult

from pathlib import Path as _Path
__version__ = (_Path(__file__).parent.parent.parent / "VERSION").read_text().strip() if (_Path(__file__).parent.parent.parent / "VERSION").exists() else "0.1.0"
__all__ = [
    "Sanitizer",
    "TrustBoundary",
    "CanarySystem",
    "TwoPhaseExecutor",
    "ExecutorResult",
    "LLMCallFn",
    "AnalysisGuard",
    "AnalysisSuspiciousError",
    "SECURE_EXECUTE_TEMPLATE",
    "MapReduceIsolator",
    "IsolatorResult",
    "ItemResult",
    "BulwarkEvent",
    "Layer",
    "Verdict",
    "EventEmitter",
    "NullEmitter",
    "CollectorEmitter",
    "CallbackEmitter",
    "StdoutJsonEmitter",
    "WebhookEmitter",
    "MultiEmitter",
    "AttackSuite",
    "PipelineValidator",
    "ValidationReport",
    "Pipeline",
    "PipelineResult",
]
