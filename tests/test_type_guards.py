"""Tests that every public entry point raises TypeError for non-string inputs."""
from __future__ import annotations

import pytest

from bulwark.pipeline import Pipeline
from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary
from bulwark.canary import CanarySystem
from bulwark.executor import TwoPhaseExecutor
from bulwark.isolator import MapReduceIsolator


# ---------------------------------------------------------------------------
# Bad inputs shared across all str-parameter tests
# ---------------------------------------------------------------------------
BAD_INPUTS = [
    pytest.param(None, id="None"),
    pytest.param(42, id="int"),
    pytest.param({"key": "value"}, id="dict"),
]

# Bad inputs for list-parameter tests (Isolator)
BAD_LIST_INPUTS = [
    pytest.param(None, id="None"),
    pytest.param(42, id="int"),
    pytest.param({"key": "value"}, id="dict"),
    pytest.param("not a list", id="str"),
]


# ---------------------------------------------------------------------------
# Pipeline._run_impl (via .run())
# ---------------------------------------------------------------------------
class TestPipelineTypeGuard:
    @pytest.mark.parametrize("bad", BAD_INPUTS)
    def test_run_rejects_non_str(self, bad):
        pipeline = Pipeline()
        with pytest.raises(TypeError, match="Expected str, got"):
            pipeline.run(bad)

    @pytest.mark.parametrize("bad", BAD_INPUTS)
    def test_run_async_rejects_non_str(self, bad):
        import asyncio

        async def _test():
            pipeline = Pipeline()
            with pytest.raises(TypeError, match="Expected str, got"):
                await pipeline.run_async(bad)

        asyncio.run(_test())


# ---------------------------------------------------------------------------
# Sanitizer.clean()
# ---------------------------------------------------------------------------
class TestSanitizerTypeGuard:
    @pytest.mark.parametrize("bad", BAD_INPUTS)
    def test_clean_rejects_non_str(self, bad):
        s = Sanitizer()
        with pytest.raises(TypeError, match="Expected str, got"):
            s.clean(bad)


# ---------------------------------------------------------------------------
# TrustBoundary.wrap()
# ---------------------------------------------------------------------------
class TestTrustBoundaryTypeGuard:
    @pytest.mark.parametrize("bad", BAD_INPUTS)
    def test_wrap_rejects_non_str(self, bad):
        tb = TrustBoundary()
        with pytest.raises(TypeError, match="Expected str, got"):
            tb.wrap(bad)


# ---------------------------------------------------------------------------
# CanarySystem.check()
# ---------------------------------------------------------------------------
class TestCanaryTypeGuard:
    @pytest.mark.parametrize("bad", BAD_INPUTS)
    def test_check_rejects_non_str(self, bad):
        cs = CanarySystem()
        with pytest.raises(TypeError, match="Expected str, got"):
            cs.check(bad)


# ---------------------------------------------------------------------------
# TwoPhaseExecutor.run()
# ---------------------------------------------------------------------------
class TestExecutorTypeGuard:
    @pytest.mark.parametrize("bad", BAD_INPUTS)
    def test_run_rejects_non_str(self, bad):
        executor = TwoPhaseExecutor(analyze_fn=lambda x: x)
        with pytest.raises(TypeError, match="Expected str, got"):
            executor.run(bad)


# ---------------------------------------------------------------------------
# MapReduceIsolator.process()
# ---------------------------------------------------------------------------
class TestIsolatorTypeGuard:
    @pytest.mark.parametrize("bad", BAD_LIST_INPUTS)
    def test_process_rejects_non_list(self, bad):
        isolator = MapReduceIsolator(map_fn=lambda x: x)
        with pytest.raises(TypeError, match="Expected list, got"):
            isolator.process(bad)
