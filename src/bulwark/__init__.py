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
from bulwark.attacks import AttackSuite
from bulwark.validator import PipelineValidator, ValidationReport

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
    "AttackSuite",
    "PipelineValidator",
    "ValidationReport",
]
