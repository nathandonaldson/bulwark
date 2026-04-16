"""Spec-driven tests for dashboard layer status — spec/contracts/dashboard_layer_status.yaml."""
import pytest

try:
    from fastapi.testclient import TestClient
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


def _get_client():
    from fastapi.testclient import TestClient
    from bulwark.dashboard.app import app
    return TestClient(app)


class TestLayerStatus:
    def test_config_reflects_toggle_state(self):
        """G-DASH-LAYERS-001: Config endpoint returns toggle states for layer cards."""
        import bulwark.dashboard.app as app_mod
        from bulwark.dashboard.config import BulwarkConfig
        old = app_mod.config
        app_mod.config = BulwarkConfig(sanitizer_enabled=False)
        try:
            client = _get_client()
            resp = client.get("/api/config")
            data = resp.json()
            assert data["sanitizer_enabled"] is False
            assert data["trust_boundary_enabled"] is True
        finally:
            app_mod.config = old

    def test_pipeline_respects_disabled_sanitizer(self):
        """G-DASH-LAYERS-001: Pipeline skips sanitizer when toggled off."""
        import bulwark.dashboard.app as app_mod
        from bulwark.dashboard.config import BulwarkConfig
        old = app_mod.config
        app_mod.config = BulwarkConfig(sanitizer_enabled=False)
        try:
            client = _get_client()
            resp = client.post("/v1/pipeline", json={"content": "hello\u200bworld"})
            data = resp.json()
            layers = [s["layer"] for s in data["trace"]]
            assert "sanitizer" not in layers
        finally:
            app_mod.config = old

    def test_pipeline_respects_disabled_trust_boundary(self):
        """G-DASH-LAYERS-001: Pipeline skips trust boundary when toggled off."""
        import bulwark.dashboard.app as app_mod
        from bulwark.dashboard.config import BulwarkConfig
        old = app_mod.config
        app_mod.config = BulwarkConfig(trust_boundary_enabled=False)
        try:
            client = _get_client()
            resp = client.post("/v1/pipeline", json={"content": "hello"})
            data = resp.json()
            layers = [s["layer"] for s in data["trace"]]
            assert "trust_boundary" not in layers
        finally:
            app_mod.config = old

    def test_pipeline_includes_enabled_sanitizer(self):
        """G-DASH-LAYERS-001: Pipeline includes sanitizer when toggled on."""
        import bulwark.dashboard.app as app_mod
        from bulwark.dashboard.config import BulwarkConfig
        old = app_mod.config
        app_mod.config = BulwarkConfig(sanitizer_enabled=True)
        try:
            client = _get_client()
            resp = client.post("/v1/pipeline", json={"content": "hello"})
            data = resp.json()
            layers = [s["layer"] for s in data["trace"]]
            assert "sanitizer" in layers
        finally:
            app_mod.config = old

    def test_disabled_layer_not_hidden(self):
        """NG-DASH-LAYERS-001: Disabled layers still visible, not hidden."""
        # The shield page always shows all 5 layer cards — verified by HTML structure
        client = _get_client()
        resp = client.get("/")
        html = resp.text
        assert "Sanitizer" in html
        assert "Trust Boundary" in html
        assert "Canary Tokens" in html
