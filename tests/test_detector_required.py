"""ADR-038 — /healthz reports detector load state and degraded status.

Covers G-HTTP-HEALTHZ-001..006 and NG-HTTP-HEALTHZ-002 (no "loading" state).
"""
from __future__ import annotations

import pytest

try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


def _client():
    from bulwark.dashboard.app import app
    return TestClient(app)


class TestHealthzDetectorState:
    """G-HTTP-HEALTHZ-004: /healthz exposes detectors.loaded and detectors.failed."""

    def test_healthz_includes_detectors_field(self, monkeypatch):
        monkeypatch.delenv("BULWARK_ALLOW_SANITIZE_ONLY", raising=False)
        body = _client().get("/healthz").json()
        assert "detectors" in body
        assert "loaded" in body["detectors"]
        assert "failed" in body["detectors"]
        assert isinstance(body["detectors"]["loaded"], list)
        assert isinstance(body["detectors"]["failed"], dict)

    def test_healthz_reports_loaded_detector(self, monkeypatch):
        """detectors.loaded reflects what's in _detection_checks."""
        import bulwark.dashboard.app as app_mod
        # Snapshot+swap so we don't pollute the global state.
        saved_checks = dict(app_mod._detection_checks)
        saved_failures = dict(app_mod._detector_failures)
        try:
            app_mod._detection_checks.clear()
            app_mod._detector_failures.clear()
            app_mod._detection_checks["protectai"] = lambda _: None
            body = _client().get("/healthz").json()
            assert "protectai" in body["detectors"]["loaded"]
            assert body["detectors"]["failed"] == {}
        finally:
            app_mod._detection_checks.clear()
            app_mod._detection_checks.update(saved_checks)
            app_mod._detector_failures.clear()
            app_mod._detector_failures.update(saved_failures)

    def test_healthz_reports_failed_detector(self, monkeypatch):
        """detectors.failed maps name -> error string."""
        import bulwark.dashboard.app as app_mod
        saved_checks = dict(app_mod._detection_checks)
        saved_failures = dict(app_mod._detector_failures)
        try:
            app_mod._detection_checks.clear()
            app_mod._detector_failures.clear()
            app_mod._detector_failures["promptguard"] = "OSError: gated model"
            body = _client().get("/healthz").json()
            assert body["detectors"]["failed"]["promptguard"] == "OSError: gated model"
        finally:
            app_mod._detection_checks.clear()
            app_mod._detection_checks.update(saved_checks)
            app_mod._detector_failures.clear()
            app_mod._detector_failures.update(saved_failures)


class TestHealthzDegradedStatus:
    """G-HTTP-HEALTHZ-005: status=degraded when no detection is active."""

    def _swap(self, *, judge_enabled: bool = False, has_detector: bool = False):
        import bulwark.dashboard.app as app_mod
        from bulwark.dashboard.config import BulwarkConfig, JudgeBackendConfig
        saved_cfg = app_mod.config
        saved_checks = dict(app_mod._detection_checks)
        saved_failures = dict(app_mod._detector_failures)
        cfg = BulwarkConfig()
        if judge_enabled:
            cfg.judge_backend = JudgeBackendConfig(
                enabled=True, base_url="http://x/v1", model="m",
                threshold=0.85, fail_open=True,
            )
        app_mod.config = cfg
        app_mod._detection_checks.clear()
        app_mod._detector_failures.clear()
        if has_detector:
            app_mod._detection_checks["protectai"] = lambda _: None
        return app_mod, (saved_cfg, saved_checks, saved_failures)

    def _restore(self, app_mod, saved):
        saved_cfg, saved_checks, saved_failures = saved
        app_mod.config = saved_cfg
        app_mod._detection_checks.clear()
        app_mod._detection_checks.update(saved_checks)
        app_mod._detector_failures.clear()
        app_mod._detector_failures.update(saved_failures)

    def test_no_detectors_no_judge_is_degraded(self, monkeypatch):
        monkeypatch.delenv("BULWARK_ALLOW_SANITIZE_ONLY", raising=False)
        app_mod, saved = self._swap(judge_enabled=False, has_detector=False)
        try:
            body = _client().get("/healthz").json()
            assert body["status"] == "degraded"
            assert body["reason"] == "no_detectors_loaded"
        finally:
            self._restore(app_mod, saved)

    def test_loaded_detector_is_ok(self, monkeypatch):
        monkeypatch.delenv("BULWARK_ALLOW_SANITIZE_ONLY", raising=False)
        app_mod, saved = self._swap(has_detector=True)
        try:
            body = _client().get("/healthz").json()
            assert body["status"] == "ok"
            assert "reason" not in body
        finally:
            self._restore(app_mod, saved)

    def test_judge_only_is_ok(self, monkeypatch):
        """ADR-038: judge counts as a detector for the degraded check."""
        monkeypatch.delenv("BULWARK_ALLOW_SANITIZE_ONLY", raising=False)
        app_mod, saved = self._swap(judge_enabled=True, has_detector=False)
        try:
            body = _client().get("/healthz").json()
            assert body["status"] == "ok"
        finally:
            self._restore(app_mod, saved)

    def test_sanitize_only_opt_out(self, monkeypatch):
        """G-HTTP-HEALTHZ-006: BULWARK_ALLOW_SANITIZE_ONLY suppresses degraded."""
        monkeypatch.setenv("BULWARK_ALLOW_SANITIZE_ONLY", "1")
        app_mod, saved = self._swap(has_detector=False, judge_enabled=False)
        try:
            body = _client().get("/healthz").json()
            assert body["status"] == "ok"
            # detectors fields still report the truth.
            assert body["detectors"]["loaded"] == []
        finally:
            self._restore(app_mod, saved)


class TestIntegrationsLoadStatus:
    """G-HTTP-HEALTHZ-004 (linked): /api/integrations exposes load_error per detector."""

    def test_integrations_endpoint_includes_load_error(self):
        import bulwark.dashboard.app as app_mod
        saved_failures = dict(app_mod._detector_failures)
        try:
            app_mod._detector_failures["promptguard"] = "OSError: HuggingFace approval pending"
            body = _client().get("/api/integrations").json()
            assert body["promptguard"]["load_error"] == "OSError: HuggingFace approval pending"
            assert body["promptguard"]["loaded"] is False
        finally:
            app_mod._detector_failures.clear()
            app_mod._detector_failures.update(saved_failures)

    def test_no_loading_intermediate_state(self):
        """NG-HTTP-HEALTHZ-002: detectors are either loaded or failed.

        There is no "loading" status — load happens synchronously during
        the FastAPI startup hook. /healthz only sees the post-load state.
        Any detector key under detectors.failed will not also be under
        detectors.loaded, and vice versa.
        """
        import bulwark.dashboard.app as app_mod
        loaded = set(app_mod._detection_checks.keys())
        failed = set(app_mod._detector_failures.keys())
        # A detector may be in neither (not configured), but never in both.
        assert not (loaded & failed), \
            f"detector cannot be loaded and failed simultaneously: {loaded & failed}"

    def test_integrations_endpoint_load_error_none_when_clean(self):
        import bulwark.dashboard.app as app_mod
        saved_checks = dict(app_mod._detection_checks)
        saved_failures = dict(app_mod._detector_failures)
        try:
            app_mod._detection_checks.clear()
            app_mod._detector_failures.clear()
            app_mod._detection_checks["protectai"] = lambda _: None
            body = _client().get("/api/integrations").json()
            assert body["protectai"]["load_error"] is None
            assert body["protectai"]["loaded"] is True
        finally:
            app_mod._detection_checks.clear()
            app_mod._detection_checks.update(saved_checks)
            app_mod._detector_failures.clear()
            app_mod._detector_failures.update(saved_failures)
