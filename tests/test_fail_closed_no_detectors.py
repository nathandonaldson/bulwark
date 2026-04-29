"""ADR-040 — /v1/clean fails closed when zero detectors are loaded.

Covers G-CLEAN-DETECTOR-REQUIRED-001, NG-CLEAN-DETECTOR-REQUIRED-001,
and G-HTTP-CLEAN-503-NO-DETECTORS-001.

Until v2.4.2 a default-configured deployment booted with `_detection_checks
== {}` and judge disabled, yet `/v1/clean` happily returned 200 OK with
sanitize-only output. /healthz reported `degraded` (ADR-038) but the API
still served traffic — operators got a false sense of security. This phase
makes /v1/clean fail closed unless the operator explicitly opts in via
BULWARK_ALLOW_NO_DETECTORS=1.
"""
from __future__ import annotations

import logging

import pytest

try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


@pytest.fixture
def client_no_detectors(monkeypatch):
    """TestClient bound to a dashboard that has zero detectors and no judge.

    Snapshots+swaps the module-level _detection_checks / config so the
    surrounding test session is unaffected. By default the opt-in env var
    is cleared so the fail-closed guard fires; tests that want the
    sanitizer-only path explicitly setenv BULWARK_ALLOW_NO_DETECTORS.
    """
    import bulwark.dashboard.app as app_mod
    from bulwark.dashboard.config import BulwarkConfig

    monkeypatch.delenv("BULWARK_ALLOW_NO_DETECTORS", raising=False)
    monkeypatch.delenv("BULWARK_ALLOW_SANITIZE_ONLY", raising=False)

    saved_cfg = app_mod.config
    saved_checks = dict(app_mod._detection_checks)
    saved_failures = dict(app_mod._detector_failures)

    app_mod.config = BulwarkConfig()  # defaults: no judge, no integrations
    app_mod._detection_checks.clear()
    app_mod._detector_failures.clear()

    try:
        yield TestClient(app_mod.app)
    finally:
        app_mod.config = saved_cfg
        app_mod._detection_checks.clear()
        app_mod._detection_checks.update(saved_checks)
        app_mod._detector_failures.clear()
        app_mod._detector_failures.update(saved_failures)


class TestFailClosedNoDetectors:
    """G-CLEAN-DETECTOR-REQUIRED-001 / G-HTTP-CLEAN-503-NO-DETECTORS-001."""

    def test_clean_returns_503_when_no_detectors_and_no_judge(self, client_no_detectors):
        """G-CLEAN-DETECTOR-REQUIRED-001 / G-HTTP-CLEAN-503-NO-DETECTORS-001.

        Zero detectors loaded + judge disabled + opt-in unset → 503 with
        a structured error envelope. The sanitizer-only path is never
        silently served.
        """
        r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
        assert r.status_code == 503
        body = r.json()
        assert body["error"]["code"] == "no_detectors_loaded"

    def test_clean_503_body_is_advisory(self, client_no_detectors):
        """G-HTTP-CLEAN-503-NO-DETECTORS-001: error envelope explains the opt-in."""
        r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
        assert r.status_code == 503
        body = r.json()
        # The envelope MUST point at the env var so operators can self-serve.
        assert "BULWARK_ALLOW_NO_DETECTORS" in body["error"].get("message", "")

    def test_judge_enabled_still_serves(self, client_no_detectors):
        """G-CLEAN-DETECTOR-REQUIRED-001: judge counts as a detector for the guard.

        Same predicate as ADR-038's healthz check — a judge-only deployment
        is healthy (the judge IS the detector). The 503 only fires when
        BOTH the ML detectors and the judge are absent.
        """
        import bulwark.dashboard.app as app_mod
        from bulwark.dashboard.config import JudgeBackendConfig
        # Enable the judge but mock-out classify so the test stays hermetic.
        app_mod.config.judge_backend = JudgeBackendConfig(
            enabled=True, base_url="http://x/v1", model="m",
            threshold=0.85, fail_open=True,
        )
        from bulwark.detectors import llm_judge as judge_mod

        class _SafeVerdict:
            verdict = "SAFE"
            confidence = 0.99
            latency_ms = 1.0
            reason = ""

        original = judge_mod.classify
        judge_mod.classify = lambda cfg, content: _SafeVerdict()
        try:
            r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
            assert r.status_code == 200
        finally:
            judge_mod.classify = original

    def test_loaded_detector_still_serves(self, client_no_detectors):
        """G-CLEAN-DETECTOR-REQUIRED-001: a single loaded detector is enough."""
        import bulwark.dashboard.app as app_mod
        app_mod._detection_checks["protectai"] = lambda _: {
            "max_score": 0.01,
            "n_windows": 1,
            "top_label": "SAFE",
        }
        r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
        assert r.status_code == 200


class TestExplicitOptIn:
    """NG-CLEAN-DETECTOR-REQUIRED-001 — operators may opt into sanitize-only."""

    def test_clean_serves_when_explicit_opt_in(self, monkeypatch, client_no_detectors):
        """NG-CLEAN-DETECTOR-REQUIRED-001: opt-in unblocks the sanitizer-only path."""
        monkeypatch.setenv("BULWARK_ALLOW_NO_DETECTORS", "1")
        r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
        assert r.status_code == 200
        assert r.json()["mode"] == "degraded-explicit"

    def test_opt_in_logs_warning(self, monkeypatch, caplog, client_no_detectors):
        """NG-CLEAN-DETECTOR-REQUIRED-001: every degraded request logs WARNING."""
        monkeypatch.setenv("BULWARK_ALLOW_NO_DETECTORS", "1")
        with caplog.at_level(logging.WARNING, logger="bulwark.dashboard.api_v1"):
            r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
        assert r.status_code == 200
        warning_records = [
            rec for rec in caplog.records
            if rec.levelno == logging.WARNING
            and "degraded" in rec.getMessage().lower()
        ]
        assert warning_records, "expected a WARNING log on degraded-mode request"

    def test_falsy_opt_in_values_fail_closed(self, monkeypatch, client_no_detectors):
        """NG-CLEAN-DETECTOR-REQUIRED-001: '0' / 'false' / '' do NOT opt in."""
        for value in ("0", "false", "False", ""):
            monkeypatch.setenv("BULWARK_ALLOW_NO_DETECTORS", value)
            r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
            assert r.status_code == 503, f"value={value!r} should not opt in"

    def test_opt_in_does_not_modify_safe_response_shape(
        self, monkeypatch, client_no_detectors,
    ):
        """NG-CLEAN-DETECTOR-REQUIRED-001: existing CleanResponse fields still present."""
        monkeypatch.setenv("BULWARK_ALLOW_NO_DETECTORS", "1")
        r = client_no_detectors.post("/v1/clean", json={"content": "hello"})
        assert r.status_code == 200
        body = r.json()
        for k in ("result", "blocked", "source", "format",
                  "content_length", "result_length", "modified", "trace"):
            assert k in body, f"degraded-explicit response missing field {k!r}"
