"""Bulwark: Architectural defense against prompt injection."""
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

__version__ = "0.1.0"
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
