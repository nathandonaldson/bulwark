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
            resp = client.post("/v1/clean", json={"content": "hello\u200bworld"})
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
            resp = client.post("/v1/clean", json={"content": "hello"})
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
            resp = client.post("/v1/clean", json={"content": "hello"})
            data = resp.json()
            layers = [s["layer"] for s in data["trace"]]
            assert "sanitizer" in layers
        finally:
            app_mod.config = old

    def test_disabled_layer_shows_off_indicator(self):
        """G-DASH-LAYERS-002: Disabled layers show grey dot / off indicator.

        Post-ADR-020: Shield's LayerRow renders a Dot with kind=on?'ok':'off' and
        reduces opacity to 0.5 when the layer is off. Primitives.Dot uses
        var(--text-faint) for kind='off'.
        """
        from pathlib import Path
        src = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src"
        page_shield = (src / "page-shield.jsx").read_text()
        primitives = (src / "primitives.jsx").read_text()
        # LayerRow dims and off-dots disabled layers:
        assert "kind={on ? 'ok' : 'off'}" in page_shield
        assert "opacity: on ? 1 : 0.5" in page_shield
        # Dot primitive maps 'off' to var(--text-faint) (grey):
        assert "off: 'var(--text-faint)'" in primitives

    def test_layer_status_updates_on_toggle(self):
        """G-DASH-LAYERS-003: Layer status updates when config toggles change.

        Post-ADR-020: the React store (BulwarkStore.toggleLayer) mutates layerConfig
        and emits, which re-renders every subscriber via useStore(). Configure
        page's FlowNode onToggle calls BulwarkStore.toggleLayer(stage.id).
        """
        from pathlib import Path
        src = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src"
        data = (src / "data.jsx").read_text()
        configure = (src / "page-configure.jsx").read_text()
        # Store exposes toggleLayer and emits on change:
        assert "toggleLayer(id)" in data and "emit()" in data
        # Configure wires the toggle to the store:
        assert "BulwarkStore.toggleLayer(stage.id)" in configure

    def test_disabled_layer_not_hidden(self):
        """NG-DASH-LAYERS-001: Disabled layers still visible, not hidden.

        Post-ADR-020: all LAYERS render unconditionally; the opacity/dot state
        changes but the row is still in the DOM. Source: page-shield.jsx maps
        over LAYERS without filtering by on/off.
        """
        from pathlib import Path
        src = Path(__file__).parent.parent / "src" / "bulwark" / "dashboard" / "static" / "src"
        data = (src / "data.jsx").read_text()
        page_shield = (src / "page-shield.jsx").read_text()
        # LAYERS list contains every layer with a display name:
        for name in ("Sanitizer", "Trust Boundary", "Canary Tokens"):
            assert name in data, f"{name!r} missing from LAYERS in data.jsx"
        # Shield maps over LAYERS with no filter:
        assert "LAYERS.map(layer =>" in page_shield
