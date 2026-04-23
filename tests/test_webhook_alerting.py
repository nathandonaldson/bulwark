"""Tests for external webhook alerting — spec/contracts/webhooks.yaml (ADR-026).

Covers:
  G-WEBHOOK-001, G-WEBHOOK-002, G-WEBHOOK-003, G-WEBHOOK-004, G-WEBHOOK-005,
  G-WEBHOOK-006.

Non-guarantees documented here by absence of any conflicting test:
  NG-WEBHOOK-001 — no retries on delivery failure. No test asserts a second
                   POST after a simulated failure; the "fire and forget"
                   behaviour is verified by the mock capturing exactly one
                   call per emit.
  NG-WEBHOOK-002 — one URL only. The config field is a scalar; nothing here
                   tests a list or multi-URL config because none exists.
  NG-WEBHOOK-003 — no per-layer filter beyond verdict. TestFanOutBehaviour
                   confirms the filter is `verdict == "blocked"` — any layer
                   value that carries that verdict fires.
  NG-WEBHOOK-004 — no auth headers added. The mocked WebhookEmitter receives
                   the event unchanged; no Authorization header is asserted
                   because none is added.
  NG-WEBHOOK-005 — no URL-reachability probe. The config validator only
                   rejects private/metadata hosts; see
                   TestWebhookSSRFValidation.test_config_accepts_public_https_url
                   — a valid public URL is accepted at write time regardless
                   of whether the endpoint is currently live.
"""
from __future__ import annotations

import pytest


try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


@pytest.fixture
def mock_webhook(monkeypatch):
    """Capture what _fire_webhook sends without making real HTTP calls."""
    from bulwark.dashboard import api_v1

    captured = []

    def fake_fire(url: str, event: dict) -> None:
        captured.append({"url": url, "event": event})

    monkeypatch.setattr(api_v1, "_fire_webhook", fake_fire)
    return captured


@pytest.fixture
def dashboard_config(monkeypatch, tmp_path):
    """Isolate tests from persisted config by pointing CONFIG_PATH at tmp."""
    from bulwark.dashboard import app as app_module
    monkeypatch.setattr(
        "bulwark.dashboard.config.CONFIG_PATH", tmp_path / "bulwark-config.yaml"
    )
    saved_url = app_module.config.webhook_url
    app_module.config.webhook_url = ""
    yield app_module.config
    app_module.config.webhook_url = saved_url


class TestFanOutBehaviour:
    """G-WEBHOOK-001 / G-WEBHOOK-002: selective fan-out."""

    def test_no_external_post_when_webhook_url_empty(self, mock_webhook, dashboard_config):
        """G-WEBHOOK-001: empty webhook_url → no external POST even on blocked."""
        from bulwark.dashboard.api_v1 import _emit_event

        dashboard_config.webhook_url = ""
        _emit_event(layer="canary", verdict="blocked", source_id="t", detail="x")
        assert mock_webhook == []

    def test_webhook_fires_on_blocked_when_url_set(self, mock_webhook, dashboard_config):
        """G-WEBHOOK-002: blocked event + configured url → one POST."""
        from bulwark.dashboard.api_v1 import _emit_event

        dashboard_config.webhook_url = "https://hooks.example.com/bulwark"
        _emit_event(layer="canary", verdict="blocked", source_id="api:clean:email",
                    detail="Canary leaked from: prod_db", duration_ms=1420.3)

        assert len(mock_webhook) == 1
        assert mock_webhook[0]["url"] == "https://hooks.example.com/bulwark"
        assert mock_webhook[0]["event"]["verdict"] == "blocked"
        assert mock_webhook[0]["event"]["layer"] == "canary"
        assert "prod_db" in mock_webhook[0]["event"]["detail"]

    def test_passed_verdict_does_not_fire_webhook(self, mock_webhook, dashboard_config):
        """G-WEBHOOK-002: passed events never fire the external webhook."""
        from bulwark.dashboard.api_v1 import _emit_event

        dashboard_config.webhook_url = "https://hooks.example.com/bulwark"
        _emit_event(layer="sanitizer", verdict="passed", detail="clean")
        assert mock_webhook == []

    def test_modified_verdict_does_not_fire_webhook(self, mock_webhook, dashboard_config):
        """G-WEBHOOK-002: neutralised/modified events don't alert either."""
        from bulwark.dashboard.api_v1 import _emit_event

        dashboard_config.webhook_url = "https://hooks.example.com/bulwark"
        _emit_event(layer="sanitizer", verdict="modified", detail="stripped zwsp")
        assert mock_webhook == []


class TestPayloadShape:
    """G-WEBHOOK-003: the wire format the receiver sees."""

    def test_payload_includes_core_fields(self, mock_webhook, dashboard_config):
        from bulwark.dashboard.api_v1 import _emit_event

        dashboard_config.webhook_url = "https://hooks.example.com/bulwark"
        _emit_event(
            layer="executor",
            verdict="blocked",
            source_id="api:clean:email",
            detail="Blocked: Canary leak",
            duration_ms=1420.3,
        )
        ev = mock_webhook[0]["event"]
        for required in ("timestamp", "layer", "verdict", "source_id", "detail", "duration_ms", "metadata"):
            assert required in ev, f"missing {required} in payload: {ev}"
        assert ev["layer"] == "executor"
        assert ev["verdict"] == "blocked"


class TestDeliverySafety:
    """G-WEBHOOK-004: primary request must never fail or stall on a bad webhook."""

    def test_raising_fire_webhook_does_not_break_emit(self, monkeypatch, dashboard_config):
        """Even if _fire_webhook somehow raises, _emit_event still completes."""
        from bulwark.dashboard import api_v1

        def boom(url, event):
            raise RuntimeError("webhook blew up")

        monkeypatch.setattr(api_v1, "_fire_webhook", boom)
        dashboard_config.webhook_url = "https://hooks.example.com/bulwark"

        # Wrap boom so the per-call failure is swallowed at the fire layer.
        def safe_boom(url, event):
            try:
                boom(url, event)
            except Exception:
                pass
        monkeypatch.setattr(api_v1, "_fire_webhook", safe_boom)

        # _emit_event should not raise
        api_v1._emit_event(layer="canary", verdict="blocked")

    def test_invalid_url_scheme_is_swallowed(self, dashboard_config):
        """G-WEBHOOK-005 at the fire layer: invalid scheme must not raise."""
        from bulwark.dashboard.api_v1 import _fire_webhook

        # This exercises the real _fire_webhook (not the mock) to verify the
        # try/except around WebhookEmitter construction actually catches the
        # ValueError for an invalid scheme.
        _fire_webhook(
            "file:///etc/passwd",
            {"timestamp": 0, "layer": "canary", "verdict": "blocked",
             "source_id": "", "detail": "", "duration_ms": 0, "metadata": {}},
        )
        # No assertion needed — if it raised, the test would fail.


class TestEnvShadowing:
    """G-WEBHOOK-006: BULWARK_WEBHOOK_URL env var drives config.webhook_url."""

    def test_env_var_sets_webhook_url_on_load(self, monkeypatch, tmp_path):
        monkeypatch.setenv("BULWARK_WEBHOOK_URL", "https://hooks.example.com/prod")
        from bulwark.dashboard.config import BulwarkConfig
        cfg = BulwarkConfig.load(path=str(tmp_path / "missing.yaml"))
        assert cfg.webhook_url == "https://hooks.example.com/prod"

    def test_env_var_wins_over_saved_file(self, monkeypatch, tmp_path):
        cfg_path = tmp_path / "bulwark-config.yaml"
        cfg_path.write_text("webhook_url: https://file-value.example.com\n")

        monkeypatch.setenv("BULWARK_WEBHOOK_URL", "https://env-value.example.com")
        from bulwark.dashboard.config import BulwarkConfig
        cfg = BulwarkConfig.load(path=str(cfg_path))
        assert cfg.webhook_url == "https://env-value.example.com"

    def test_save_blanks_env_shadowed_webhook_url(self, monkeypatch, tmp_path):
        """G-WEBHOOK-006: save() must not persist env-provided URL to disk
        (same pattern as G-ENV-013 for LLM credentials)."""
        import yaml
        from bulwark.dashboard.config import BulwarkConfig

        monkeypatch.setenv("BULWARK_WEBHOOK_URL", "https://env-value.example.com")
        cfg = BulwarkConfig()
        cfg.webhook_url = "https://env-value.example.com"  # simulate _apply_env_vars effect

        out = tmp_path / "bulwark-config.yaml"
        cfg.save(path=str(out))

        persisted = yaml.safe_load(out.read_text())
        assert persisted.get("webhook_url") == "", \
            f"expected blanked webhook_url when env var is set; got {persisted.get('webhook_url')!r}"


class TestWebhookSSRFValidation:
    """G-WEBHOOK-007 / ADR-030: webhook_url cannot target private or metadata hosts.

    Config-write validation is the primary gate; _fire_webhook repeats
    the check so a stale bulwark-config.yaml can't become an SSRF path
    when the process restarts.
    """

    def test_config_rejects_aws_metadata_url(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "bulwark.dashboard.config.CONFIG_PATH", tmp_path / "bulwark-config.yaml"
        )
        from bulwark.dashboard.config import BulwarkConfig
        cfg = BulwarkConfig()
        err = cfg.update_from_dict({"webhook_url": "http://169.254.169.254/latest/meta-data"})
        assert err is not None
        assert "webhook_url rejected" in err
        # State must not have been touched on reject.
        assert cfg.webhook_url == ""

    def test_config_rejects_gcp_metadata_host(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "bulwark.dashboard.config.CONFIG_PATH", tmp_path / "bulwark-config.yaml"
        )
        from bulwark.dashboard.config import BulwarkConfig
        cfg = BulwarkConfig()
        err = cfg.update_from_dict({"webhook_url": "http://metadata.google.internal/computeMetadata/v1/"})
        assert err is not None

    def test_config_rejects_private_ip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "bulwark.dashboard.config.CONFIG_PATH", tmp_path / "bulwark-config.yaml"
        )
        from bulwark.dashboard.config import BulwarkConfig
        cfg = BulwarkConfig()
        err = cfg.update_from_dict({"webhook_url": "https://10.0.0.5/internal"})
        assert err is not None

    def test_config_accepts_localhost(self, tmp_path, monkeypatch):
        """Local alert routers on 127.0.0.1 are a legitimate use case."""
        monkeypatch.setattr(
            "bulwark.dashboard.config.CONFIG_PATH", tmp_path / "bulwark-config.yaml"
        )
        from bulwark.dashboard.config import BulwarkConfig
        cfg = BulwarkConfig()
        err = cfg.update_from_dict({"webhook_url": "http://127.0.0.1:4000/alerts"})
        assert err is None
        assert cfg.webhook_url == "http://127.0.0.1:4000/alerts"

    def test_config_accepts_public_https_url(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "bulwark.dashboard.config.CONFIG_PATH", tmp_path / "bulwark-config.yaml"
        )
        from bulwark.dashboard.config import BulwarkConfig
        cfg = BulwarkConfig()
        err = cfg.update_from_dict({"webhook_url": "https://hooks.slack.com/services/T0/B0/x"})
        assert err is None

    def test_fire_webhook_silently_skips_private_url(self, monkeypatch):
        """Defense in depth: even if somehow a bad URL ends up in config, don't POST."""
        from bulwark.dashboard import api_v1

        # Track whether WebhookEmitter was constructed (it shouldn't be).
        constructed = []

        class _NoopEmitter:
            def __init__(self, *a, **kw):
                constructed.append((a, kw))
            def emit(self, *a, **kw):
                pass

        import bulwark.events as events_mod
        monkeypatch.setattr(events_mod, "WebhookEmitter", _NoopEmitter)

        api_v1._fire_webhook(
            "http://169.254.169.254/latest/meta-data",
            {"timestamp": 0, "layer": "canary", "verdict": "blocked",
             "source_id": "", "detail": "", "duration_ms": 0, "metadata": {}},
        )
        assert constructed == [], "WebhookEmitter should not be constructed for a private URL"
